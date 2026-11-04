"""Agent Readiness Audit — Vercel serverless function (Python runtime).

POST /api/audit  with JSON body {"url": "https://example.com"}
-> 200 with the same JSON report the CLI (audit/audit.py) produces:
   {tool, url, fetched_at, score, checks[], fixes[], errors[]}

Optional lead fields in the same body — {"first_name": ..., "email": ...} —
make the function email the visitor a copy of their results from
hello@agentreadinesshq.com (see send_results_email below) and record the
completed scan as a lead in the same inbox (see send_scan_lead_notice
below). That replaces the old FormSubmit _autoresponse, which never
delivered, and the later browser-side FormSubmit lead post, which could
fail silently after the results email had already been sent. The send only
happens when the RESULTS_SMTP_PASSWORD env var is configured; without it
no email goes out (responses to lead-carrying requests report
"email_sent": false, and all other responses are unchanged). A body field
"suppress_email": true (sent by the post-payment intake-149 details step)
skips the results email while still returning the full report.

Checks and weights are IDENTICAL to audit/scoring.md (7 checks, total 100).

Serverless adaptations vs the CLI:
- 4 independent fetches (homepage, robots.txt, llms.txt, sitemap.xml) run in
  parallel threads; deep page follows sequentially.
- TIMEOUT=5s per fetch (Vercel Hobby kills functions at 10s). Worst case
  ~5s (parallel batch) + 4s (deep page) = ~9s.
- SSRF guard: the target hostname is resolved and private/loopback/link-local
  IPs are rejected (documented limitation: DNS-rebinding TOCTOU not covered;
  for a public endpoint consider an egress proxy later).
- 2 MB response cap per fetch; max 5 redirects; http(s) only; URL length cap.
- Naive in-memory per-IP rate limit (10 audits/hour). This is per function
  instance — fine for launch; use Upstash Redis if abuse appears.
- Never raises: every failure lands in the report's "errors" list.

Local test: python3 - <<'EOF'
import sys; sys.path.insert(0, 'api')
from audit import run_audit
import json
print(json.dumps(run_audit('https://example.com'), indent=2)[:2000])
EOF
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import smtplib
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, urljoin, urlencode

import requests

VERSION = "6.0-api"
SCORING_VERSION = "v6"   # scoring rules version; stamped on every
                         # report so scores from different scoring
                         # versions are never mixed
UA = "AgentReadinessAudit/1.0 (machine-readability audit; single fetch)"
TIMEOUT = 4          # per-fetch timeout (seconds) — tight for serverless
LLMS_RETRY_TIMEOUT = 12   # llms.txt second attempt after a first-fetch
                          # timeout (scoring v6); a file that still
                          # cannot be fetched is UNVERIFIED
                          # (uncertain), never a measured absence
TIMEOUT_DEEP = 3     # deep-page fetch gets a shorter budget
TIME_BUDGET = 5.5    # skip the deep page once this many seconds have elapsed
SCHEMA_MAX_PAGES = 4        # homepage + at most 3 inner pages (schema)
SCHEMA_TIME_BUDGET = 6.5    # start schema inner fetches only before this
MAX_BYTES = 2_000_000
SPEED_READINGS = 3                  # homepage timings per scan (v4)
SPEED_PROBE_TIMEOUT = 7             # per-probe timeout, seconds - sits ABOVE the
                                    # 6s total-time scoring threshold so a response
                                    # completing inside the scoring window is measured
SPEED_PROBE_MAX_BYTES = 2_000_000   # probe body cap (v4)
MAX_URL_LEN = 2048

# ---------------------------------------------------------------- weights ---
# MUST match audit/scoring.md exactly. Total = 100.
WEIGHTS = {
    "robots_ai_posture": 20,
    "llms_txt": 10,
    "sitemap": 10,
    "schema_jsonld": 20,
    "pricing_html": 15,
    "bot_wall": 15,
    "page_speed": 10,
}
assert sum(WEIGHTS.values()) == 100, "weights must total 100"

AI_CRAWLERS = [
    "GPTBot", "ChatGPT-User", "OAI-SearchBot",
    "ClaudeBot", "Claude-SearchBot", "anthropic-ai",
    "CCBot", "Bytespider", "PerplexityBot",
    "Google-Extended", "Meta-ExternalAgent", "Applebot-Extended",
    "cohere-ai", "DuckAssistBot",
]

# Scoring v5 bot-wall semantics: a page fails only when it IS a
# challenge - an interstitial carrying scant usable content. HARD
# markers are challenge-vendor or challenge-flow signatures; SOFT
# markers are challenge phrases. Either kind is evidence only on a
# near-empty page: a hard marker embedded in a usable content page
# (a Turnstile form widget, say) is form protection, not a wall, and
# does not fail the check. NEUTRAL markers appear in ordinary
# embedded form code (e.g. Squarespace serves reCAPTCHA machinery
# with its forms) and never fail a page by themselves - the v1 rule
# zeroed 15 points on the bare string "captcha" for exactly that.
BOT_WALL_HARD_MARKERS = [
    "cf-chl", "challenge-platform", "cf_clearance", "cf-turnstile",
    "datadome", "perimeterx", "incapsula", "distil_r_captcha",
]
BOT_WALL_SOFT_MARKERS = [
    "verify you are human", "please verify you are a human",
    "are you a robot", "human verification",
    "checking your browser", "just a moment",
]
BOT_WALL_NEUTRAL_MARKERS = ["captcha"]
BOT_WALL_MARKERS = (BOT_WALL_HARD_MARKERS + BOT_WALL_SOFT_MARKERS
                    + BOT_WALL_NEUTRAL_MARKERS)
BOT_WALL_MIN_CONTENT_CHARS = 2000  # below this, soft markers = interstitial

PRICE_RE = re.compile(r"\$\s?\d[\d,]*(?:\.\d{1,2})?")
PRICE_WORD_RE = re.compile(r"\b(price|pricing|cost|rates?|from\s+\$)", re.I)
JS_SHELL_RE = re.compile(r'<(div|main)[^>]*(id="(root|app|__next)"|data-reactroot)', re.I)

LOCAL_BUSINESS_TYPES = {
    "localbusiness", "plumber", "electrician", "roofer", "hvacbusiness",
    "dentist", "physician", "restaurant", "store", "automotiverepair",
    "homeandconstructionbusiness", "professionalservice", "medicalbusiness",
    "foodestablishment", "lodgingbusiness", "automotivebusiness",
    "healthandbeautybusiness", "sportsactivitylocation", "drycleaningorlaundry",
}

# Scoring v2: the business-identity third of the schema check is earned by
# a LocalBusiness-family record OR a plain Organization record (the
# standards-preferred generic business identity; v1 deliberately did not
# credit it, which zeroed the check for most non-trade businesses).
IDENTITY_TYPES = LOCAL_BUSINESS_TYPES | {"organization"}

FIX_TEXT = {
    "robots_ai_posture": "Allow major AI crawlers in robots.txt (or add explicit Allow lines); blocking them hides the site from shopping/research agents.",
    "llms_txt": "Add a concise /llms.txt summarizing offerings, pricing, service area, and contact info for LLM consumers.",
    "sitemap": "Publish /sitemap.xml listing key pages so agents can discover the site without guessing URLs.",
    "schema_jsonld": "Add schema.org JSON-LD: Product with price/offers, a business record (Organization or LocalBusiness with name and contact facts), and FAQPage for common questions - on the homepage or the relevant service/FAQ pages.",
    "pricing_html": "Render at least headline pricing in the raw HTML of the homepage or a key service/pricing page (server-side or pre-rendered); JS-only prices are invisible to non-JS agents.",
    "bot_wall": "Move bot protection behind real abuse signals instead of the front door; challenge pages block legitimate agent traffic.",
    "page_speed": "Server response timing is set by your hosting platform and plan, not by page content, so it may cap this part of your score no matter what else is fixed. If it's slow, the change that helps is a hosting change, and we'll note what to ask your host.",
}

# Plain-English layer shown with every check result, on the scan page
# and in the results email (Caleb directive 2026-10-20): a short
# "what this means" line per check — what the check measures, what it
# means, and what it does for a machine reader. Per-check "Fixable:"
# lines and per-check platform-limit lines were removed by Caleb
# ruling 2026-10-22: each check now shows only its finding and this
# meaning line. Platform disclosure lives solely in the platform box
# (and the results email's platform section), never per check.
CHECK_COPY = {
    "robots_ai_posture": {
        "meaning": "This file tells AI crawlers whether they may look at your site at all. The crawlers we check do different jobs: some power search and AI answers, some collect training data, and some fetch a page for a user who asked. Blocking a training crawler is not the same as blocking customer discovery.",
    },
    "llms_txt": {
        "meaning": "An optional file, following an emerging convention whose adoption varies by AI system, that introduces your business in a plain format written for AI agents. It supplements your pages. It is not a substitute for clear content, crawlability, structured data, or accurate facts.",
    },
    "sitemap": {
        "meaning": "The map of your site, so an agent can find every page that matters instead of just a corner of it.",
    },
    "schema_jsonld": {
        "meaning": "Machine-readable labels for your services, prices, and business facts, in the form an agent can quote accurately.",
    },
    "pricing_html": {
        "meaning": "Prices stated in the page itself, where an agent can read them. When pricing isn't clearly stated, an agent may be unable to confidently present it to a customer.",
    },
    "bot_wall": {
        "meaning": "Whether anything stops an agent at the door before it learns a single thing about your business.",
    },
    "page_speed": {
        "meaning": "How fast your pages answer. Slow pages can make it harder for automated systems to retrieve information reliably.",
    },
}

# Companion disclosure rendered beside a check's meaning line on the
# results page and in the results email (language pack items D-4 and
# D-12, Caleb direction 2026-11-02): page speed varies from scan to
# scan, so this note travels with the speed check wherever its meaning
# line is shown. It is a disclosure, not a fix: nothing in the $149 or
# $449 scope changes a host's response timing.
CHECK_NOTES = {
    "page_speed": ("Page speed is one of the seven checks, and it can "
                   "move your score on its own. Your server's response "
                   "speed varies from scan to scan, so this check may "
                   "reduce or improve your score even when nothing on "
                   "your website has changed."),
}


# ------------------------------------------------------- platform rules ---
# Platform feasibility (Caleb ruling 2026-10-21, controlling): platform
# limits are a qualification and disclosure issue, identified during
# the free scan wherever detection is reliable, and always before a
# $449 purchase when material. The scan distinguishes, per check:
# fixable / platform-limited / uncertain (platform not identified).
# Eligibility outcomes: A = eligible; B = eligible with platform or
# plan limitations, disclosed before purchase; C = $449 unavailable
# (the platform blocks core implementation; the $149 DIY Audit is the
# offer instead). Capability facts mirror access-guides/INDEX.md
# (vendor-documentation sourced, 2026-10-21) and are keyed on current
# capabilities, not on platform names alone: only the checks whose
# implementation depends on the platform vary (llms.txt, JSON-LD).
# Every other check is implementable on every platform we know.
#
# Capability values: "implementable", "limited" (possible, but depends
# on the plan or on a specific access path), "not_implementable"
# (the platform cannot do it in the required form at all), and
# "auto_only" (the component can exist only because the platform
# generates it itself; nobody, customer or us, can implement, edit,
# or replace it — unscored points on such a check are still lost,
# but the component's possible presence means the platform does not
# block BOTH core components the way a strict not_implementable
# pair does).
PLATFORM_CAPABILITY = {
    "WordPress": {},
    "Wix": {},
    "Shopify": {},
    "Webflow": {},
    "Duda": {},
    "Kajabi": {
        "llms_txt": (
            "not_implementable",
            "Kajabi does not let a site place a file at its domain root, "
            "so an llms.txt file cannot be added in the required form. "
            "The AI Information Page covers much of the same ground in "
            "page form."),
        "schema_jsonld": (
            "limited",
            "Structured data can be added on Kajabi only through the "
            "site-wide scripts setting, which needs an Administrator "
            "login. It is part of Done For You when that access is "
            "provided."),
    },
    "Squarespace": {
        "llms_txt": (
            "not_implementable",
            "Squarespace cannot place an llms.txt file at the domain "
            "root in the required form. An upload-and-redirect "
            "workaround exists, but AI tools may not honour it, so we "
            "do not count it as implemented."),
        "schema_jsonld": (
            "limited",
            "Structured data on Squarespace is added through Code "
            "Injection, a premium-plan feature (Core, Plus, or "
            "Advanced). On a Basic plan this fix cannot be implemented "
            "until the plan changes."),
    },
    "GoDaddy Website Builder": {
        # llms.txt: GoDaddy now generates one itself on builder sites
        # (verified live 2026-10-21 on five sites), so the file can
        # be present, but it is builder-controlled: it cannot be
        # edited, replaced, or (where absent) added by anyone.
        "llms_txt": (
            "auto_only",
            "GoDaddy Website Builder generates an llms.txt file "
            "itself, but neither you nor we can edit or replace what "
            "it says, so its content cannot be improved. If your "
            "site does not have one, it cannot be added in the "
            "required form either."),
        "schema_jsonld": (
            "not_implementable",
            "GoDaddy Website Builder has no site-wide code area, and "
            "its embed sections are isolated from the page itself, so "
            "structured data cannot be added in a form AI tools can "
            "read."),
    },
}
_PLATFORM_VARYING_CHECKS = ("llms_txt", "schema_jsonld")

# Host suffixes that identify the platform outright (the site is
# served from the platform's own subdomain space).
_HOST_PLATFORM = [
    ("myshopify.com", "Shopify"),
    ("mykajabi.com", "Kajabi"),
    ("wixsite.com", "Wix"),
    ("squarespace.com", "Squarespace"),
    ("godaddysites.com", "GoDaddy Website Builder"),
    ("webflow.io", "Webflow"),
    ("dudaone.com", "Duda"),
    ("wordpress.com", "WordPress"),
]

# Strong in-page signals per platform: platform asset hosts, runtime
# globals, and markup attributes a site only carries when it is built
# on that platform. Matched against the lowercased homepage HTML.
_HTML_PLATFORM_MARKERS = [
    ("Shopify", ["cdn.shopify.com", "shopify.theme",
                 "myshopify.com", "shopify-section"]),
    ("Kajabi", ["kajabi-cdn.com", "kajabiapp.com", "mykajabi.com"]),
    ("Wix", ["wixstatic.com", "wix.com website builder"]),
    ("Squarespace", ["squarespace-cdn.com", "static1.squarespace.com",
                     "assets.squarespace.com"]),
    ("GoDaddy Website Builder", ["wsimg.com"]),
    ("Webflow", ["website-files.com", "data-wf-page", "webflow.js",
                 "w-mod-"]),
    ("Duda", ["dudaone.com", "cdn-website.com"]),
    ("WordPress", ["/wp-content/", "/wp-includes/",
                   'generator" content="wordpress']),
]

CONFIRM_PLATFORM_LINE = (
    "We could not identify your website platform from the scan. Your "
    "platform decides part of what can be implemented, so we confirm "
    "it with you before any Done For You ($449) purchase: platform "
    "limitations, where they exist, are identified before you buy, "
    "not after. Your intake form asks for the platform as well.")


def detect_platform(host, html):
    """Identify the website platform from the site address and the
    homepage HTML. Conservative by design: returns (name, evidence)
    only on a strong signal, otherwise (None, None) and the results
    ask the prospect to confirm. Conflicting in-page signals with no
    clear winner also return (None, None) rather than a guess.
    """
    host = (host or "").lower()
    for suffix, name in _HOST_PLATFORM:
        if host == suffix or host.endswith("." + suffix):
            return name, f"the site is served from a {suffix} address"
    low = (html or "").lower()
    hits = {}
    for name, markers in _HTML_PLATFORM_MARKERS:
        found = [m for m in markers if m in low]
        if found:
            hits[name] = found
    if not hits:
        return None, None
    if len(hits) == 1:
        name = next(iter(hits))
        return name, f"the page code references {hits[name][0]}"
    ranked = sorted(hits.items(), key=lambda kv: -len(kv[1]))
    if len(ranked[0][1]) > len(ranked[1][1]):
        name, found = ranked[0]
        return name, f"the page code references {found[0]}"
    return None, None


def assess_platform(platform_name, raw_checks):
    """Apply the capability rules for a detected platform.
    raw_checks: list of (check_id, name, score, status, detail).
    Returns per-check capability, eligibility (A/B/C, or "unknown"
    when no platform was detected), the customer's own score ceiling
    when the platform makes one calculable, the ceiling line in the
    ruling's framing, and the list of affected failed checks.
    Category C is a platform-level outcome per the ruling: when both
    core components (llms.txt and effective JSON-LD) cannot be
    implemented at all, $449 is unavailable for that configuration.
    GoDaddy Website Builder no longer qualifies (Caleb ruling
    2026-10-21): its llms.txt is platform-generated ("auto_only"),
    so only the schema component is strictly not implementable and
    the outcome is B, sell with the limits disclosed beforehand.
    """
    if not platform_name:
        return {"eligibility": "unknown", "ceiling": None,
                "ceiling_line": None, "limitations": [],
                "per_check": {}}
    rules = PLATFORM_CAPABILITY.get(platform_name, {})
    per_check = {}
    limitations = []
    # Strict test on purpose: an "auto_only" component (GoDaddy's
    # generated llms.txt) does not count toward core_blocked, so a
    # platform needs BOTH components strictly not implementable
    # before the outcome is C.
    core_blocked = all(
        rules.get(cid, ("implementable", None))[0] == "not_implementable"
        for cid in _PLATFORM_VARYING_CHECKS)
    scores = {cid: sc for cid, _n, sc, _s, _d in raw_checks}
    # Unearnable points: what a not-implementable (or auto-only)
    # check has not already scored. A check the site somehow passes
    # (e.g. an llms.txt redirect workaround that resolves, or a
    # platform-generated file) blocks only its unscored remainder.
    blocked_checks = []
    blocked_points = 0
    for cid in _PLATFORM_VARYING_CHECKS:
        if rules.get(cid, ("implementable", None))[0] in (
                "not_implementable", "auto_only"):
            lost = WEIGHTS[cid] - scores.get(cid, 0)
            if lost > 0:
                blocked_checks.append(cid)
                blocked_points += lost
    for cid, name, sc, _st, _d in raw_checks:
        cap, reason = rules.get(cid, ("implementable", None))
        per_check[cid] = cap
        if sc < WEIGHTS[cid] and cap != "implementable":
            limitations.append({
                "check_id": cid, "check_name": name,
                "capability": cap, "reason": reason,
                "points": WEIGHTS[cid]})
    if core_blocked:
        eligibility = "C"
    elif limitations:
        eligibility = "B"
    else:
        eligibility = "A"
    ceiling_line = None
    if blocked_points:
        n = len(blocked_checks)
        # Caleb ruling 2026-10-21 (evening): a platform ceiling is
        # always phrased as a "may cap at", never a hard permanent
        # fact; platform features change over time.
        ceiling_line = (
            f"Platform limit: on its current platform, this site's "
            f"score may cap at {_fmt_num(100 - blocked_points)}/100, "
            f"because {platform_name} does not currently allow {n} "
            f"of the checks in this scan ({_fmt_num(blocked_points)} "
            f"points) to be implemented in the required way. Platform "
            f"providers update their features over time, so what a "
            f"platform allows may change; we work to what it allows "
            f"today.")
        # Language pack item D-12 (2026-11-02): fold response timing
        # into the ceiling story in words. Timing is set by the
        # hosting platform and plan, not by page content, so when the
        # speed check lost points the staged disclosure sentence
        # travels with the ceiling line (no numeric cap is invented
        # for timing).
        if scores.get("page_speed", WEIGHTS["page_speed"]) \
                < WEIGHTS["page_speed"]:
            ceiling_line += (
                " Server response timing is set by your hosting "
                "platform and plan, not by page content, so it may "
                "cap this part of your score no matter what else is "
                "fixed. If it's slow, the change that helps is a "
                "hosting change, and we'll note what to ask your "
                "host.")
    ceiling_val = 100 - blocked_points
    if float(ceiling_val).is_integer():
        ceiling_val = int(ceiling_val)
    return {"eligibility": eligibility,
            "ceiling": ceiling_val if blocked_points else None,
            "ceiling_line": ceiling_line,
            "limitations": limitations, "per_check": per_check}


def platform_offer_line(platform_name, assessment):
    """The pre-purchase disclosure line for the results page and the
    results email. A: nothing to add (no known limits). B: name the
    limitations beside the offer. C: $449 is not offered for this
    configuration; the $149 DIY Audit is the offer. Unknown: the
    confirm-platform line instead (see CONFIRM_PLATFORM_LINE).
    """
    eligibility = assessment.get("eligibility")
    if eligibility == "B":
        if platform_name == "GoDaddy Website Builder":
            # Caleb refinement 2026-10-21: do not stack the specific
            # limits into the offer notice for GoDaddy. One short
            # plain line here; the specifics (schema cannot be
            # implemented; the generated llms.txt cannot be edited)
            # live in the per-check platform labels and the report.
            return (
                "Note: GoDaddy may limit some of the technical fixes "
                "we can implement; anything it prevents is flagged "
                "in your scan and report.")
        items = "; ".join(
            f"{lim['check_name']} ({lim['reason']})"
            for lim in assessment["limitations"])
        return (
            "Done For You ($449) is available for your site, with "
            "platform limitations we are disclosing before any "
            f"purchase: {items} Everything else in your results can "
            "be implemented as usual, and your report will state "
            "these limits plainly.")
    if eligibility == "C":
        return (
            "Done For You ($449) is not available for this platform "
            "configuration: the platform itself prevents core parts "
            "of the implementation, and we will not sell work we "
            "cannot deliver. The DIY Audit ($149) is the right option "
            "here: it covers everything that can be done on your "
            "platform, explains these limits in full, and gives you "
            "the materials to use yourself or hand to a developer.")
    return None


def platform_short_line(platform_name, assessment):
    """The one plain-language sentence shown at the conversion point
    (results page caveat + results email), Caleb ruling 2026-10-22:
    universal "limits" wording for B; for C, the sentence explains
    Done For You is unavailable on this platform. The full technical
    disclosure stays available verbatim (page: the caveat's expanded
    state; email: the Platform details section). Returns None for A
    and unknown, where no limitation sentence applies. Single source:
    the results page reads this from the scan JSON (platform block),
    the email composes it with the same function.
    """
    eligibility = assessment.get("eligibility")
    if eligibility == "B":
        n = len(assessment.get("limitations") or [])
        return (
            f"{platform_name} limits {n} of the seven scan "
            "improvements. You can still address the others, and "
            "we\u2019ll show you the best available alternative.")
    if eligibility == "C":
        return (
            f"{platform_name} prevents the core parts of Done For "
            "You, so that option is not available for your site. The "
            "DIY Audit covers everything that can be done on your "
            "platform.")
    return None


# ------------------------------------------------------------------ fetch ---
def make_session():
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "text/html,*/*"})
    s.max_redirects = 5
    return s


def fetch(session, url, timeout=TIMEOUT, max_bytes=MAX_BYTES):
    """Single GET with byte cap. Returns (ok, status, text, elapsed, ttfb, err)."""
    t0 = time.perf_counter()
    try:
        r = session.get(url, timeout=timeout, stream=True, allow_redirects=True)
        ttfb = r.elapsed.total_seconds()
        size, chunks = 0, []
        for chunk in r.iter_content(chunk_size=65536):
            if chunk:
                size += len(chunk)
                if size > max_bytes:
                    break
                chunks.append(chunk)
        raw = b"".join(chunks)
        try:
            text = raw.decode(r.encoding or "utf-8", errors="replace")
        except (LookupError, UnicodeDecodeError):
            text = raw.decode("utf-8", errors="replace")
        total = time.perf_counter() - t0
        return True, r.status_code, text, total, ttfb, None
    except requests.exceptions.Timeout:
        return False, None, "", time.perf_counter() - t0, None, f"timeout after {timeout}s"
    except requests.exceptions.TooManyRedirects:
        return False, None, "", time.perf_counter() - t0, None, "too many redirects"
    except requests.exceptions.SSLError as e:
        return False, None, "", time.perf_counter() - t0, None, f"TLS error: {e}"
    except requests.exceptions.RequestException as e:
        return False, None, "", time.perf_counter() - t0, None, f"fetch error: {e}"


# --------------------------------------------------------------- SSRF guard ---
# Reason returned when a hostname cannot be resolved at all. A named
# constant because run_audit treats this one failure differently: an
# unresolvable host is not a rejected request, it is a scan that could
# not start, and it gets the normal report shape with complete: false
# (build 4.1.1; before this fix, resolver failures surfaced as HTTP 400
# - or, when the resolver raised a plain OSError instead of gaierror,
# as a raw "internal error" body).
DNS_FAIL_REASON = "hostname does not resolve"


def host_is_public(hostname):
    """Reject hostnames resolving to non-public IPs. Returns (ok, reason)."""
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        # gaierror is the usual failure mode, but it is not the only
        # one: a sandboxed resolver can raise a plain OSError (EBUSY was
        # observed in production) and an unencodable name raises
        # UnicodeError. Every resolver failure means the same thing
        # here: the name does not resolve.
        return False, DNS_FAIL_REASON
    for _fam, _type, _proto, _canon, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return False, "unparseable resolved address"
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return False, f"resolves to non-public IP ({ip})"
    return True, ""


def normalize_url(raw):
    """Returns (base, url, error). On success error is None. On a hard
    rejection (missing/invalid URL, non-http scheme, non-public IP)
    base and url are None and error carries the message. One soft
    failure differs: when the hostname does not resolve, base and url
    ARE returned with error == DNS_FAIL_REASON and the caller proceeds
    with the scan - every fetch then fails on DNS and the report
    degrades exactly like the resolvable-but-dead case (complete:
    false, per-check could-not-fetch reasons) instead of an HTTP 400
    rejection (build 4.1.1)."""
    url = (raw or "").strip()[:MAX_URL_LEN]
    if not url:
        return None, None, "missing 'url' in request body"
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    p = urlparse(url)
    if p.scheme.lower() not in ("http", "https"):
        return None, None, "only http(s) URLs are allowed"
    if not p.hostname:
        return None, None, "invalid URL"
    ok, reason = host_is_public(p.hostname)
    base = f"{p.scheme}://{p.netloc}".rstrip("/")
    if not ok:
        if reason == DNS_FAIL_REASON:
            return base, url, DNS_FAIL_REASON
        return None, None, f"URL rejected: {reason}"
    return base, url, None


# ------------------------------------------------------------ robots.txt ---
def parse_robots_groups(text):
    groups = []
    cur = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field, value = field.strip().lower(), value.strip()
        if field == "user-agent":
            if cur is None or cur["saw_rule"]:
                cur = {"agents": [], "rules": [], "saw_rule": False}
                groups.append(cur)
            cur["agents"].append(value.lower())
        elif field in ("disallow", "allow") and cur is not None:
            cur["rules"].append((field, value))
            cur["saw_rule"] = True
    return groups


def group_for_crawler(crawler, groups):
    """The merged rule group that applies to a crawler (scoring v5).
    Every group naming the crawler at the winning specificity tier
    (exact token, then substring, then '*') contributes its rules -
    the union - so the verdict never depends on the order the groups
    appear in the file. (The v4 rule returned the FIRST matching
    group only, so identical rule content could block or allow the
    same crawler depending purely on file order.)"""
    ua = crawler.lower()
    tiers = (
        [g for g in groups if ua in g["agents"]],
        [g for g in groups
         if any(a != "*" and (a in ua or ua in a) for a in g["agents"])],
        [g for g in groups if "*" in g["agents"]],
    )
    for tier in tiers:
        if tier:
            rules = []
            for g in tier:
                rules.extend(g["rules"])
            return {"agents": [ua], "rules": rules}
    return None


def crawler_access(group):
    """(state, exceptions) for one crawler's merged group (v5).
    "open": no site-wide Disallow, or an Allow: / overrides it.
    "partial": a Disallow: / tempered by Allow rules for specific
    paths - the crawler is locked out of the site EXCEPT the allowed
    paths (the common real-world pattern of opening the content that
    matters), so it is not a total lockout and is not scored as one.
    "blocked": Disallow: / with no Allow relief at all."""
    if group is None:
        return "open", []
    rules = group["rules"]
    root_disallow = any(r == "disallow" and p.rstrip() in ("/", "/*")
                        for r, p in rules)
    if not root_disallow:
        return "open", []
    allows = [p for r, p in rules if r == "allow" and p.strip()]
    if any(p.rstrip() in ("/", "/*") for p in allows):
        return "open", []
    if allows:
        return "partial", allows
    return "blocked", []


def blocked_sitewide(group):
    """True only for a TOTAL lockout - a site-wide Disallow with no
    Allow relief (see crawler_access). Kept for callers that need
    the binary answer."""
    return crawler_access(group)[0] == "blocked"


def check_robots(result):
    """Robots posture (scoring v5). Retrieval outcomes are kept
    distinct: 404/410 or an empty 200 = genuinely no robots.txt
    (allow-all, full pass); any other status or a fetch failure =
    COULD NOT VERIFY - status "uncertain", no credit, and run_audit
    flags the scan incomplete rather than silently treating an
    unmeasured posture as 'nothing blocked' (or as a measured fail).
    A crawler under a blanket Disallow with Allow exceptions for
    relevant paths is "partial" (half credit), not a total lockout;
    the exceptions are named in the detail."""
    w = WEIGHTS["robots_ai_posture"]
    ok, status, text, _t, _ttfb, err = result
    if not ok:
        return 0.0, "uncertain", (f"could not fetch robots.txt ({err}); "
                                  "crawler posture could not be verified")
    if status in (404, 410) or (status == 200 and not text.strip()):
        return w * 1.0, "pass", "no robots.txt (defaults to allow-all for every crawler)"
    if status != 200:
        return 0.0, "uncertain", (f"robots.txt returned HTTP {status}; "
                                  "crawler posture could not be verified")
    groups = parse_robots_groups(text)
    access = {c: crawler_access(group_for_crawler(c, groups))
              for c in AI_CRAWLERS}
    blocked = [c for c in AI_CRAWLERS if access[c][0] == "blocked"]
    partial = [c for c in AI_CRAWLERS if access[c][0] == "partial"]
    allowed_frac = ((len(AI_CRAWLERS) - len(blocked) - 0.5 * len(partial))
                    / len(AI_CRAWLERS))
    if not blocked and not partial:
        return w, "pass", f"all {len(AI_CRAWLERS)} known AI crawlers allowed"
    parts = []
    if blocked:
        parts.append(f"{len(blocked)}/{len(AI_CRAWLERS)} AI crawlers "
                     f"disallowed site-wide: {', '.join(blocked)}")
    if partial:
        exc = "; ".join(f"{c} (allowed: {', '.join(access[c][1])})"
                        for c in partial)
        parts.append(f"{len(partial)} partially disallowed - site-wide "
                     f"except specific Allow paths: {exc}")
    return (w * allowed_frac,
            ("partial" if allowed_frac > 0 else "fail"),
            "; ".join(parts))


# ----------------------------------------------------------------- llms.txt ---
def check_llms_txt(result):
    """llms.txt presence (scoring v6). Retrieval outcomes are kept
    distinct, matching the robots rule: an HTTP response is a
    measured result (a non-200 status is a genuinely absent file and
    fails; a 200 body is scored on its content), but a fetch that
    never completed proves nothing about the file - status
    "uncertain", no credit, and run_audit flags the scan incomplete.
    The timeout retry itself happens in run_audit, which re-fetches
    at LLMS_RETRY_TIMEOUT before this check sees the result (the v5
    rule scored a transient timeout on a file that exists as a
    fail, flipping a complete scan by the check's full weight)."""
    w = WEIGHTS["llms_txt"]
    ok, status, text, _t, _ttfb, err = result
    if not ok:
        return 0.0, "uncertain", (f"could not fetch /llms.txt ({err}); "
                                  "llms.txt presence could not be verified")
    if status != 200:
        return 0.0, "fail", f"/llms.txt returned HTTP {status}"
    if _is_html_document(text):
        return 0.0, "fail", ("/llms.txt returned an HTML page, not a "
                             "plain-text llms.txt - a fallback or error "
                             "page earns no credit")
    chars = len(text.strip())
    if chars >= 200:
        return w, "pass", f"/llms.txt present ({chars} chars)"
    if chars >= 50:
        return w * 0.5, "partial", f"/llms.txt present but thin ({chars} chars; add real content)"
    return 0.0, "fail", f"/llms.txt present but near-empty ({chars} chars)"


# ------------------------------------------------------------------ sitemap ---
def check_sitemap(result):
    w = WEIGHTS["sitemap"]
    ok, status, text, _t, _ttfb, err = result
    if not ok:
        return 0.0, "fail", f"could not fetch /sitemap.xml ({err})"
    if status != 200:
        return 0.0, "fail", f"/sitemap.xml returned HTTP {status}"
    if "<urlset" in text or "<sitemapindex" in text:
        urls = len(re.findall(r"<loc>", text))
        return w, "pass", f"/sitemap.xml present (~{urls} URLs listed)"
    if _is_html_document(text):
        return 0.0, "fail", ("/sitemap.xml returned an HTML page, not "
                             "sitemap XML - an error page earns no credit")
    stripped = text.lstrip("\ufeff \t\r\n")
    if stripped.startswith("<?xml") or stripped.startswith("<"):
        return w * 0.5, "partial", "/sitemap.xml returned 200 but content is not a recognizable sitemap"
    return 0.0, "fail", "/sitemap.xml returned 200 but the content is not XML"


# -------------------------------------------------------------- JSON-LD -----
def extract_jsonld_blocks(html):
    blocks = []
    for m in re.finditer(
        r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
        html, re.I | re.S,
    ):
        raw = m.group(1).strip()
        if not raw:
            continue
        try:
            blocks.append(json.loads(raw))
        except (json.JSONDecodeError, ValueError):
            continue
    return blocks


def derive_business_name(html):
    """Best-effort business name from the homepage the audit already
    fetched: JSON-LD Organization/LocalBusiness/WebSite name, else
    og:site_name, else the <title> stem before a separator. Returns
    "" when nothing trustworthy is present - the intake door then
    simply leaves the field for the customer, as today. Never used
    for scoring."""
    try:
        for block in extract_jsonld_blocks(html or ""):
            stack = [block]
            while stack:
                node = stack.pop()
                if isinstance(node, dict):
                    t = node.get("@type")
                    types = ({str(x).lower() for x in t}
                             if isinstance(t, list)
                             else {str(t).lower()} if t else set())
                    if types & {"organization", "localbusiness",
                                "store", "restaurant", "website",
                                "professionalservice", "dentist",
                                "attorney", "medicalbusiness"}:
                        nm = str(node.get("name") or "").strip()
                        if 2 <= len(nm) <= 80:
                            return nm
                    stack.extend(v for v in node.values()
                                 if isinstance(v, (dict, list)))
                elif isinstance(node, list):
                    stack.extend(node)
        m = re.search(r'property=["\']og:site_name["\'][^>]*'
                      r'content=["\']([^"\']{2,80})["\']', html or "", re.I)
        if m:
            return m.group(1).strip()
        m = re.search(r"<title[^>]*>([^<]{2,120})</title>",
                      html or "", re.I)
        if m:
            stem = re.split(r"\s*[|\u2013\u2014\u00b7]\s*|\s+-\s+",
                            m.group(1).strip())[0].strip()
            if 2 <= len(stem) <= 80:
                return stem
    except Exception:
        pass
    return ""


def flatten_types(node, out):
    if isinstance(node, dict):
        t = node.get("@type")
        if isinstance(t, list):
            out.update(str(x).lower() for x in t)
        elif t:
            out.add(str(t).lower())
        g = node.get("@graph")
        if g:
            flatten_types(g, out)
        for key in ("offers", "hasOfferCatalog", "itemListElement"):
            if key in node:
                flatten_types(node[key], out)
    elif isinstance(node, list):
        for item in node:
            flatten_types(item, out)


# ------------------------------------------- schema credit (final v4) ---
# Strengthened per the adopted final review (section 5):
# - the business-identity record must describe the SCANNED business,
#   not an unrelated publisher or embedded vendor record;
# - the offering third accepts a valid Product OR Service whose linked
#   Offer carries a real price (and a plausible currency when stated),
#   and whose price or name is corroborated by VISIBLE page content -
#   a price that exists solely in hidden JSON-LD earns nothing;
# - the FAQ third requires real questions with nonempty accepted
#   answers whose question text is visible in the page content;
# - @graph containers, @type arrays, and @id references resolvable
#   within the fetched page set are all handled. Empty records and
#   empty offers earn nothing.

def _node_types(node):
    t = node.get("@type")
    if isinstance(t, list):
        return {str(x).lower() for x in t}
    if t:
        return {str(t).lower()}
    return set()


def _iter_nodes(node, out):
    """Every dict node in a parsed JSON-LD structure, @graph included."""
    if isinstance(node, dict):
        out.append(node)
        for v in node.values():
            _iter_nodes(v, out)
    elif isinstance(node, list):
        for item in node:
            _iter_nodes(item, out)
    return out


def _norm_text(s):
    return re.sub(r"\s+", " ", str(s or "")).strip().lower()


def _name_tokens(name):
    stop = {"the", "and", "of", "llc", "inc", "co", "company", "group",
            "www", "com", "http", "https"}
    return {t for t in re.split(r"[^a-z0-9]+", _norm_text(name))
            if len(t) >= 3 and t not in stop}


def _site_identity_signals(homepage_html, host):
    """Identity signals for the scanned business itself: name tokens
    from the homepage <title>, og:site_name, and any WebSite /
    Organization names in the homepage JSON-LD. Used to tell the
    business's own identity record from an unrelated publisher or
    vendor record embedded on the page."""
    names = set()
    html = homepage_html or ""
    m = re.search(r'property=["\']og:site_name["\'][^>]*'
                  r'content=["\']([^"\']{2,80})["\']', html, re.I)
    if m:
        names |= _name_tokens(m.group(1))
    m = re.search(r"<title[^>]*>([^<]{2,120})</title>", html, re.I)
    if m:
        stem = re.split(r"\s*[|\u2013\u2014\u00b7]\s*|\s+-\s+",
                        m.group(1).strip())[0]
        names |= _name_tokens(stem)
    for b in extract_jsonld_blocks(html):
        for n in _iter_nodes(b, []):
            # WebSite names only: harvesting Organization names here
            # would be circular (an embedded vendor's own record would
            # certify itself as the site's identity).
            if _node_types(n) & {"website"}:
                nm = n.get("name")
                if isinstance(nm, str) and nm.strip():
                    names |= _name_tokens(nm)
    return names


def _url_host(u):
    try:
        return (urlparse(str(u)).netloc or "").lower()
    except Exception:
        return ""


def _identity_coherent(node, host, site_names):
    """True when an Organization/LocalBusiness-family record plausibly
    describes the scanned business: its url/@id host is the site's own
    host, or its name overlaps the site's own identity signals. A
    record pointing at a foreign host with an unrelated name is an
    embedded vendor/publisher record, not the business's identity."""
    name = node.get("name")
    name = name if isinstance(name, str) else ""
    url = node.get("url") or node.get("@id") or ""
    nhost = _url_host(url) if url else ""
    if nhost and host and nhost == host:
        return True
    if name and site_names and (_name_tokens(name) & site_names):
        return True
    if nhost and host and nhost != host:
        return False  # points at a different organization
    if name and site_names:
        return False  # named, but not this business
    # No usable cross-check exists (nothing points elsewhere, and the
    # site offered no name signals to contradict): accept a named
    # record, reject an anonymous one.
    return bool(name.strip())


def _parse_price(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        m = re.search(r"\d[\d,]*(?:\.\d{1,2})?", v)
        if m:
            try:
                return float(m.group(0).replace(",", ""))
            except ValueError:
                return None
    return None


def _offer_price(offer):
    """The meaningful price of an Offer node, or None. Requires a
    numeric price > 0 (directly or via priceSpecification / lowPrice)
    and, when a currency is stated, a plausible 3-letter code. Empty
    offers and price-less shells return None."""
    if not isinstance(offer, dict):
        return None
    price = _parse_price(offer.get("price"))
    if price is None:
        price = _parse_price(offer.get("lowPrice"))  # AggregateOffer
    if price is None:
        spec = offer.get("priceSpecification")
        specs = spec if isinstance(spec, list) else [spec]
        for s in specs:
            if isinstance(s, dict):
                price = _parse_price(s.get("price"))
                if price is not None:
                    break
    if price is None or price <= 0:
        return None
    cur = offer.get("priceCurrency")
    if cur is not None and not re.fullmatch(r"[A-Za-z]{3}",
                                            str(cur).strip()):
        return None
    return price


def _resolve_ref(node, id_index):
    """Resolve an @id reference (a bare string, or a dict carrying
    little besides @id) against nodes indexed across the page set."""
    if isinstance(node, str):
        return id_index.get(node, node)
    if isinstance(node, dict) and node.get("@id"):
        extra = {k for k in node if k not in ("@id", "@type")}
        if not extra:
            return id_index.get(node["@id"], node)
    return node


# ------------------------------------------- v5 credit helpers ---
# Shared by the schema and pricing checks (scoring v5, per the
# adopted ChatGPT review of the v4 methodology):
# - an offering's price must itself be visible AND associated with
#   the offering on the same page (no name-only corroboration, no
#   unassociated set membership);
# - an FAQ's published answer must correspond to its structured
#   answer (token-overlap correspondence);
# - HTML documents served at plain-format URLs earn nothing.

def _is_html_document(text):
    """True when a response body is an HTML document rather than the
    plain format expected at the URL - the signature of a fallback
    or error page served with HTTP 200 (a CMS returning its 404
    page, a SPA shell). Only the opening bytes are examined: a
    doctype or an <html>/<head> root."""
    t = (text or "").lstrip("\ufeff \t\r\n").lower()
    return (t.startswith("<!doctype") or t.startswith("<html")
            or t.startswith("<head"))


_CONTENT_STOP = {"the", "and", "for", "with", "are", "you", "your",
                 "our", "this", "that", "from", "will", "can", "all",
                 "any", "its", "it", "is", "in", "on", "of", "to",
                 "a", "an", "we", "us", "or", "as", "at", "by", "per"}


def _content_tokens(text):
    """Content words of a text: lowercase alphanumeric tokens of
    length >= 3, minus common function words. Used by the overlap
    correspondence tests (FAQ answers, offering names)."""
    return {t for t in re.split(r"[^a-z0-9]+", _norm_text(text))
            if len(t) >= 3 and t not in _CONTENT_STOP}


def _text_corresponds(structured, published):
    """Meaningful correspondence between a structured-data text and
    published page text: True when the structured text's opening
    appears verbatim in the published text, or at least half of its
    content tokens appear there. A structured text with fewer than
    3 content tokens must appear verbatim - there is too little of
    it to overlap-test."""
    n = _norm_text(structured)
    if not n:
        return False
    if n[:80] in published:
        return True
    toks = _content_tokens(n)
    if len(toks) < 3:
        return n in published
    present = sum(1 for t in toks
                  if re.search(r"\b" + re.escape(t) + r"\b", published))
    return present / len(toks) >= 0.5


def _name_anchor_positions(name, text):
    """Positions in a page's normalized visible text where an
    offering's name is anchored: exact occurrences of the full
    normalized name, or - when the full name never appears intact -
    positions from which at least 60% of the name's content tokens
    occur within the following 400 chars."""
    nname = _norm_text(name) if isinstance(name, str) else ""
    if len(nname) < 4:
        return []
    pos, start = [], 0
    while True:
        i = text.find(nname, start)
        if i < 0:
            break
        pos.append(i)
        start = i + 1
    if pos:
        return pos
    toks = sorted(_content_tokens(nname))
    if not toks:
        return []
    occ = {t: [m.start() for m in
               re.finditer(r"\b" + re.escape(t) + r"\b", text)]
           for t in toks}
    starts = sorted(p for ps in occ.values() for p in ps)
    anchors = []
    for p in starts:
        covered = sum(1 for t in toks
                      if any(p <= q <= p + 400 for q in occ[t]))
        if covered / len(toks) >= 0.6:
            anchors.append(p)
    return anchors


_PRICE_ASSOC_WINDOW = 600  # chars between an offering's name anchor
                           # and a visible occurrence of its price
                           # for the two to count as associated


def _price_corroborated(price_hits, price, name, text):
    """True when the offer's OWN price appears in the page's visible
    text AND is associated with the offering: a visible occurrence
    of the same amount within _PRICE_ASSOC_WINDOW chars of an
    occurrence of the offering's name. (The v4 tests credited two
    weaker things, both removed in v5: a visible offering NAME
    corroborating a price that existed only in JSON-LD, and any
    visible amount anywhere in the scanned set that merely equalled
    the price numerically, whatever it referred to.)"""
    spots = [pos for val, pos in price_hits if val == round(price, 2)]
    if not spots:
        return False
    anchors = _name_anchor_positions(name, text)
    if not anchors:
        return False
    return any(abs(s - a) <= _PRICE_ASSOC_WINDOW
               for s in spots for a in anchors)


_OFFER_CONTEXT_RE = re.compile(
    r"\b(prices?|pricing|costs?|fees?|rates?|tuition|enrol|packages?|"
    r"plans?|sessions?|payments?|paid|buy|book|purchase|order|from|"
    r"monthly|weekly|hourly|nightly|per)\b", re.I)
_PRICING_CONTEXT_WINDOW = 250  # chars either side of a $ figure in
                               # which offering language qualifies it


def _page_structured_prices(html):
    """Prices carried by Product/Service Offers in a page's own
    JSON-LD - one of the contexts that can qualify a visible $ figure
    as an offering's published price in the pricing check."""
    prices = set()
    for b in extract_jsonld_blocks(html or ""):
        for n in _iter_nodes(b, []):
            if _node_types(n) & {"product", "service"}:
                offers = n.get("offers")
                offer_list = offers if isinstance(offers, list) else [offers]
                for off in offer_list:
                    if isinstance(off, dict):
                        p = _offer_price(off)
                        if p is not None:
                            prices.add(round(p, 2))
    return prices


def check_jsonld_pages(pages, site_host="", site_names=None):
    """Schema check: aggregate JSON-LD across the homepage plus key
    inner pages. Three credited thirds, 20 pts total:
    (1) an offering - a Product OR Service with a meaningful linked
        Offer whose OWN price is published in visible content on the
        same page, associated with the offering (scoring v5: a
        visible offering name no longer corroborates a hidden price,
        and an unrelated visible amount that merely equals the price
        numerically does not corroborate it either);
    (2) a business-identity record (Organization or LocalBusiness
        family) that describes the scanned business;
    (3) an FAQPage whose published questions AND answers correspond
        to its structured data (v5: the visible answer must
        correspond to the structured answer, not merely be nonempty
        in JSON-LD while the question appears). FAQ structured data
        detected without corresponding page content is recorded in
        the detail as an informational finding, whether or not
        another FAQ on the scan earned the third - no silent skips.
    Misses are reported as 'not found within the scanned pages' -
    never as proof the markup is absent from the website."""
    w = WEIGHTS["schema_jsonld"]
    host = (site_host or "").lower()
    per_page = []
    id_index = {}
    for label, html in pages:
        html = html or ""
        blocks = extract_jsonld_blocks(html)
        nodes = []
        for b in blocks:
            nodes.extend(_iter_nodes(b, []))
        for n in nodes:
            nid = n.get("@id")
            if isinstance(nid, str) and nid:
                # A pure reference stub ({"@id": ...} and nothing
                # else) must not claim the index ahead of the real
                # node it points at - stubs appear earlier in the
                # tree than their targets.
                stub = not {k for k in n if k not in ("@id", "@type")}
                existing = id_index.get(nid)
                if existing is None or (
                        not stub
                        and not {k for k in existing
                                 if k not in ("@id", "@type")}):
                    id_index[nid] = n
        per_page.append((label, html, blocks, nodes))
    total_blocks = sum(len(b) for _l, _h, b, _n in per_page)
    if not total_blocks:
        return 0.0, "fail", (f"no parseable application/ld+json blocks found "
                             f"within the scanned pages ({len(pages)} page(s) scanned)")
    if site_names is None:
        site_names = _site_identity_signals(pages[0][1] if pages else "", host)
    visible_norm = {label: _norm_text(strip_to_text(h))
                    for label, h, _b, _n in per_page}
    # Every visible $ amount per page, with its position - the raw
    # material for the associated-price corroboration test.
    price_hits = {}
    for label, _h, _b, _n in per_page:
        hits = []
        for m in PRICE_RE.finditer(visible_norm[label]):
            v = _parse_price(m.group(0))
            if v is not None:
                hits.append((round(v, 2), m.start()))
        price_hits[label] = hits

    offering_ok, offering_where = False, ""
    offering_seen, offering_hidden, offering_unpriced = False, False, False
    identity_ok, identity_where = False, ""
    identity_foreign_seen, identity_empty_seen = False, False
    faq_ok, faq_where = False, ""
    faq_structured_seen, faq_unseen_seen = False, False
    faq_mismatch_seen = False
    for label, _h, _b, nodes in per_page:
        for n in nodes:
            types = _node_types(n)
            if types & IDENTITY_TYPES:
                if _identity_coherent(n, host, site_names):
                    if not identity_ok:
                        identity_ok, identity_where = True, label
                else:
                    # Classify the rejection for the detail: the
                    # record positively points at / names a different
                    # organization, or it is an empty stub carrying
                    # no identifying content at all.
                    _nhost = _url_host(n.get("url") or n.get("@id") or "")
                    _nm = n.get("name") if isinstance(n.get("name"), str) else ""
                    if ((_nhost and host and _nhost != host)
                            or (_nm and site_names
                                and not (_name_tokens(_nm) & site_names))):
                        identity_foreign_seen = True
                    else:
                        identity_empty_seen = True
            if types & {"product", "service"}:
                offering_seen = True
                offers = n.get("offers")
                offer_list = offers if isinstance(offers, list) else [offers]
                for off in offer_list:
                    off = _resolve_ref(off, id_index)
                    price = _offer_price(off)
                    if price is None:
                        offering_unpriced = True
                        continue
                    if _price_corroborated(price_hits.get(label, []),
                                           price, n.get("name"),
                                           visible_norm.get(label, "")):
                        if not offering_ok:
                            offering_ok, offering_where = True, label
                    else:
                        offering_hidden = True
            if "faqpage" in types:
                me = n.get("mainEntity")
                items = me if isinstance(me, list) else ([me] if me else [])
                for q in items:
                    q = _resolve_ref(q, id_index)
                    if not isinstance(q, dict) or "question" not in _node_types(q):
                        continue
                    qtext = _norm_text(q.get("name") or q.get("text"))
                    if not qtext:
                        continue
                    faq_structured_seen = True
                    ans = _resolve_ref(q.get("acceptedAnswer"), id_index)
                    atext = (_norm_text(ans.get("text"))
                             if isinstance(ans, dict) else "")
                    page_text = visible_norm.get(label, "")
                    qpos = page_text.find(qtext[:80])
                    if qpos < 0:
                        # The question itself is not published on the
                        # page - structured data without content.
                        faq_unseen_seen = True
                    elif atext and _text_corresponds(
                            atext, page_text[qpos:qpos + 1500]):
                        if not faq_ok:
                            faq_ok, faq_where = True, label
                    else:
                        # The question is published, but the published
                        # answer does not correspond to the structured
                        # answer (or the structured answer is empty).
                        faq_mismatch_seen = True
    hits = sum([offering_ok, identity_ok, faq_ok])
    parts = []
    if offering_ok:
        parts.append("Product/Service with visibly-priced offer")
    else:
        s = ("no Product or Service with a meaningful, visibly-corroborated "
             "offer found within the scanned pages")
        if offering_hidden:
            s += (" (an offer's price appears only in JSON-LD, not in "
                  "visible page content associated with the offering)")
        elif offering_unpriced:
            s += " (offering found, but its offer carries no valid price)"
        elif offering_seen:
            s += " (offering found, offer not creditable)"
        parts.append(s)
    if identity_ok:
        parts.append("Organization/LocalBusiness describing this business")
    else:
        s = ("no Organization or LocalBusiness record describing this "
             "business found within the scanned pages")
        if identity_foreign_seen:
            s += " (a record for a different organization was ignored)"
        if identity_empty_seen:
            s += " (an identity record with no name or identifying content was ignored)"
        parts.append(s)
    if faq_ok:
        parts.append("FAQPage with visible questions and corresponding answers")
    else:
        s = ("no FAQPage with visible questions and corresponding "
             "answers found within the scanned pages")
        if faq_unseen_seen:
            s += " (FAQ markup found, but its questions are not visible in page content)"
        elif faq_mismatch_seen:
            s += (" (FAQ questions are visible, but the published answers "
                  "do not correspond to the structured answers)")
        parts.append(s)
    detail = (f"{hits}/3 target types \u2014 " + "; ".join(parts)
              + f" ({total_blocks} ld+json block(s) parsed across {len(pages)} page(s))")
    found = []
    if offering_ok:
        found.append(f"{offering_where}: offering")
    if identity_ok:
        found.append(f"{identity_where}: identity")
    if faq_ok:
        found.append(f"{faq_where}: FAQ")
    if found:
        detail += " \u2014 found on " + "; ".join(found)
    if faq_structured_seen and (faq_unseen_seen or faq_mismatch_seen):
        # Review item 1: the informational finding is recorded
        # whenever FAQ structured data lacks corresponding page
        # content - including when another FAQ earned the third.
        detail += (" \u2014 informational finding: FAQ structured data "
                   "detected; corresponding page content not found")
    score = w * hits / 3
    status = "pass" if hits == 3 else ("partial" if hits > 0 else "fail")
    return score, status, detail


def check_jsonld(html):
    """Single-page form (homepage only) - kept for parity with v1 callers."""
    return check_jsonld_pages([("homepage", html)])


# ------------------------------------------------- schema page discovery ---
_AI_INFO_PATHS = ("/ai-information", "/ai-info", "/pages/ai-information")
# Scoring v6: when no AI Information page is discovered in the
# sitemap or homepage links, these paths are probed directly, in
# order - the canonical path, Shopify's /pages/ prefix, and the
# short form. (v5 probed only /ai-information, which 404s on
# Shopify stores, so a correctly published page earned no credit
# until the sitemap caught up with the publish.)
_AI_INFO_PROBE_PATHS = ("/ai-information", "/pages/ai-information",
                        "/ai-info")
_PRICING_PATH_WORDS = ("pricing", "price", "plans", "packages", "rates",
                       "services", "service", "work-with", "workwith",
                       "book", "offers", "shop", "store", "products",
                       "collections")
_FAQ_PATH_WORDS = ("faq", "faqs")
_FAQ_TEXT_WORDS = ("faq", "frequently asked")
_PRICING_TEXT_WORDS = ("pricing", "prices", "services", "our services",
                       "plans", "packages", "book", "shop", "store",
                       "products")
# Deterministic bucket priority for filling the inner-page slots.
_BUCKET_ORDER = ("ai", "faq", "pricing")


def _classify_schema_candidate(path):
    """Bucket an inner-page path: 'ai' (AI Information page), 'faq',
    'pricing' (service/pricing/offer page), or None."""
    p = (path or "").lower()
    if any(p.rstrip("/").endswith(a) for a in _AI_INFO_PATHS):
        return "ai"
    seg = p.strip("/")
    if any(w in seg for w in _FAQ_PATH_WORDS):
        return "faq"
    if any(w in p for w in _PRICING_PATH_WORDS):
        return "pricing"
    return None


def _classify_link_text(text):
    """Bucket an anchor's visible text when its path is uninformative."""
    t = _norm_text(text)
    if not t:
        return None
    if any(w in t for w in _FAQ_TEXT_WORDS):
        return "faq"
    if any(w in t for w in _PRICING_TEXT_WORDS):
        return "pricing"
    return None


def _schema_candidates(base, homepage_html, sitemap_text=""):
    """All classifiable inner-page candidates as (bucket, path, url),
    gathered from the sitemap and from homepage links (URL + anchor
    text). Deterministic: sorted within each bucket by path."""
    netloc = urlparse(base).netloc.lower()
    by_path = {}

    def consider(raw_url, link_text=""):
        try:
            absu = urljoin(base + "/", (raw_url or "").strip())
            p = urlparse(absu)
        except Exception:
            return
        if p.netloc.lower() != netloc or p.scheme not in ("http", "https"):
            return
        path = p.path or "/"
        if path == "/" or path.lower().endswith((".xml", ".txt", ".pdf")):
            return
        bucket = _classify_schema_candidate(path) or _classify_link_text(link_text)
        if bucket:
            by_path.setdefault(path, (bucket, f"{p.scheme}://{p.netloc}{path}"))

    for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", sitemap_text or ""):
        consider(m.group(1))
    for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                         homepage_html or "", re.I | re.S):
        consider(m.group(1), strip_to_text(m.group(2)))
    return by_path


def discover_schema_pages(base, homepage_html, sitemap_text=""):
    """Up to SCHEMA_MAX_PAGES - 1 inner-page URLs worth scanning:
    the AI Information page first, then FAQ and service/pricing
    coverage, selected DETERMINISTICALLY (bucket priority, then path)
    from the sitemap and homepage links. When no AI page is linked,
    the _AI_INFO_PROBE_PATHS are probed directly - it is the page
    this audit's own fixes install, and sitemaps can lag a fresh
    publish. Probe misses are recorded not_found and do not consume
    content-page slots (the return cap grows by the number of extra
    probe paths). Remaining slots are filled by the next-best
    candidates in bucket order rather than left empty."""
    by_path = _schema_candidates(base, homepage_html, sitemap_text)
    per_bucket = {b: [] for b in _BUCKET_ORDER}
    for path in sorted(by_path, key=lambda p: p.lower()):
        bucket, url = by_path[path]
        per_bucket[bucket].append(url)
    picked = []
    probing = False
    if per_bucket["ai"]:
        picked.append(per_bucket["ai"].pop(0))
    else:
        probing = True
        picked.extend(base + p for p in _AI_INFO_PROBE_PATHS)
    for bucket in ("faq", "pricing"):
        if per_bucket[bucket]:
            picked.append(per_bucket[bucket].pop(0))
    # Fill any remaining slots deterministically from leftovers.
    leftovers = []
    for bucket in _BUCKET_ORDER:
        leftovers.extend(per_bucket[bucket])
    picked.extend(leftovers)
    out, seen = [], set()
    for u in picked:
        key = urlparse(u).path.rstrip("/").lower()
        if key not in seen:
            seen.add(key)
            out.append(u)
    cap = SCHEMA_MAX_PAGES - 1
    if probing:
        cap += len(_AI_INFO_PROBE_PATHS) - 1
    return out[:cap]


def ai_info_link_status(base, homepage_html, sitemap_text=""):
    """Whether the AI Information page is DISCOVERABLE - linked from
    the homepage and/or listed in the sitemap. Direct probing (how the
    schema check finds an unlinked AI page) does not by itself prove
    discoverability, so the two facts are recorded separately."""
    netloc = urlparse(base).netloc.lower()

    def is_ai(raw_url):
        try:
            p = urlparse(urljoin(base + "/", (raw_url or "").strip()))
        except Exception:
            return False
        return (p.netloc.lower() == netloc
                and _classify_schema_candidate(p.path or "/") == "ai")

    in_sitemap = any(is_ai(m.group(1)) for m in
                     re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", sitemap_text or ""))
    in_links = any(is_ai(m.group(1)) for m in
                   re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']',
                               homepage_html or "", re.I))
    if in_links and in_sitemap:
        return "linked from homepage and listed in sitemap"
    if in_links:
        return "linked from homepage"
    if in_sitemap:
        return "listed in sitemap"
    return "not linked from homepage or sitemap (direct probe only)"


_SOFT404_TITLE_RE = re.compile(
    r"<title[^>]*>[^<]*(404|page not found|not found|doesn'?t exist)"
    r"[^<]*</title>", re.I)


def _is_soft_404(html):
    """A 200 response that is really an error page: a 'not found'
    title, or a very short page whose text leads with not-found
    language. Soft-404s are rejected as scan candidates - they are
    absences, not content pages."""
    if not html:
        return False
    if _SOFT404_TITLE_RE.search(html):
        return True
    text = _norm_text(strip_to_text(html))
    if len(text) < 1500 and ("page not found" in text or "404" in text[:200]):
        return True
    return False


# ------------------------------------------------------------------- pricing ---
def strip_to_text(html):
    no_script = re.sub(r"<script.*?</script>", " ", html, flags=re.I | re.S)
    no_style = re.sub(r"<style.*?</style>", " ", no_script, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", no_style)
    return re.sub(r"\s+", " ", text).strip()


def check_pricing_pages(pages):
    """Pricing check: aggregate across the homepage plus the same
    key inner pages the schema check scans (the v2/v3 page set - no
    additional fetches). pages = [(label, html), ...].

    Scoring v5 (false-positive correction): a $ figure earns full
    credit only when it is presented as an OFFERING's price, shown
    by any one of: (a) it appears on a pricing/services/offering
    page; (b) offering language (price, fee, per, from, book, ...)
    appears within _PRICING_CONTEXT_WINDOW chars of it; or (c) it
    matches the price of a Product/Service Offer in the same page's
    structured data. An incidental amount - a testimonial's 'saved
    $500', a donation total, a savings claim - establishes nothing
    on its own. Half credit when pricing words appear but no
    qualifying $ figure does. The JS-shell rule stays
    homepage-driven, exactly as v1 evaluated it, and keeps its v1
    precedence over the pricing-words partial."""
    w = WEIGHTS["pricing_html"]
    evals = []
    for label, html in pages:
        text = strip_to_text(html or "")
        structured = _page_structured_prices(html)
        page_ctx = _classify_schema_candidate(label) == "pricing"
        found, qualified = [], []
        for m in PRICE_RE.finditer(text):
            val = _parse_price(m.group(0))
            if val is None:
                continue
            found.append(m.group(0))
            window = text[max(0, m.start() - _PRICING_CONTEXT_WINDOW):
                          m.start() + _PRICING_CONTEXT_WINDOW]
            if (page_ctx or round(val, 2) in structured
                    or _OFFER_CONTEXT_RE.search(window)):
                qualified.append(m.group(0))
        evals.append((label, text, found, qualified))
    hit_pages = [(label, q) for label, _t, _f, q in evals if q]
    if hit_pages:
        total = sum(len(q) for _label, q in hit_pages)
        found_desc = []
        for label, q in hit_pages:
            sample = ", ".join(list(dict.fromkeys(q))[:5])
            found_desc.append(f"{label}: e.g. {sample}")
        detail = (f"{total} offering price(s) in raw HTML "
                  f"({len(pages)} page(s) scanned) \u2014 found on "
                  + "; ".join(found_desc))
        return w, "pass", detail
    home_text = evals[0][1]
    js_shell = bool(JS_SHELL_RE.search(pages[0][1] or "")) and len(home_text) < 500
    if js_shell:
        return 0.0, "fail", ("page looks like a JS shell (SPA root node, "
                             f"{len(home_text)} chars of visible text, no prices) \u2014 agents without JS see nothing")
    any_amounts = any(f for _l, _t, f, _q in evals)
    word_pages = [label for label, text, _f, _q in evals
                  if PRICE_WORD_RE.search(text)]
    if word_pages:
        detail = ("pricing words found but no $ price presented as an "
                  f"offering's price in raw HTML ({len(pages)} page(s) scanned) \u2014 "
                  "pricing words on " + "; ".join(word_pages))
        if any_amounts:
            detail += ("; dollar amounts were found, but none is presented "
                       "as an offering's price (incidental amounts do not "
                       "establish published pricing)")
        return w * 0.5, "partial", detail
    if any_amounts:
        return 0.0, "fail", ("dollar amounts found in raw HTML, but none is "
                             "presented as an offering's price \u2014 incidental "
                             "amounts (testimonials, savings claims, donations) "
                             f"do not establish published pricing ({len(pages)} page(s) scanned)")
    return 0.0, "fail", (f"no price patterns and no pricing language found in raw HTML "
                         f"({len(pages)} page(s) scanned)")


def check_pricing(html):
    """Single-page form (homepage only) - kept for parity with v1 callers."""
    return check_pricing_pages([("homepage", html)])


# ------------------------------------------------------------------ bot wall ---
def check_bot_wall(pages):
    """Scoring v5: a page fails only when it IS a challenge - an
    interstitial that replaces the content a visitor (or agent)
    came for. Challenge evidence = challenge markers (hard
    vendor/flow signatures or soft challenge phrases) on a page
    carrying scant usable content (< BOT_WALL_MIN_CONTENT_CHARS
    visible chars). A hard marker embedded in an otherwise usable
    content page - the standard pattern of a Turnstile, DataDome or
    similar form-protection widget sitting inside real content -
    does NOT fail the check: the vendor code is present, but nobody
    is actually walled, and the detail says so. (The v2-v4 rule
    failed ANY page containing a hard marker, which contradicted
    the documented embedded-code behaviour and failed ordinary
    form pages; the v1 rule additionally failed the bare string
    'captcha', which remains neutral and never fails a page.)"""
    w = WEIGHTS["bot_wall"]
    hits = {}
    embedded = []
    for label, html in pages:
        html = html or ""
        low = html.lower()
        hard = sorted({m for m in BOT_WALL_HARD_MARKERS if m in low})
        soft = sorted({m for m in BOT_WALL_SOFT_MARKERS if m in low})
        markers = hard + [s for s in soft if s not in hard]
        if not markers:
            continue
        if len(strip_to_text(html)) < BOT_WALL_MIN_CONTENT_CHARS:
            hits[label] = markers
        elif hard:
            embedded.append(label)
    if not hits:
        detail = (f"no bot-wall/CAPTCHA challenge on {len(pages)} "
                  f"page(s) scanned")
        if embedded:
            detail += ("; challenge-vendor code is embedded on "
                       + ", ".join(embedded)
                       + ", but those pages carry usable content "
                         "(form protection, not a wall)")
        return w, "pass", detail
    detail = "; ".join(f"{label}: {', '.join(m)}" for label, m in hits.items())
    return 0.0, "fail", f"bot-wall/CAPTCHA challenge detected \u2014 {detail}"


# --------------------------------------------------------------------- speed ---
def _median3(values):
    """Median of the speed readings; None counts as no response and
    sorts slowest. A single failed reading CAN change the median (it
    replaces a real value), but it cannot by itself force the median
    to failure: with three readings, the median is a failure only
    when at least two readings are slow or absent."""
    vals = sorted(float("inf") if v is None else v for v in values)
    mid = vals[len(vals) // 2]
    return None if mid == float("inf") else mid


def _classify_probe_result(ok, status, text, err):
    """Distinct diagnostic reason for a failed speed reading, kept
    distinct end-to-end (review section 3): a timeout is not a
    network error is not a rate limit is not a challenge response."""
    if ok and status == 200:
        return None
    if status == 429:
        return "rate limit (HTTP 429)"
    if ok and text and any(m in text.lower() for m in BOT_WALL_HARD_MARKERS):
        return "challenge response"
    if status is not None:
        return f"HTTP {status}"
    if err and "timeout" in err.lower():
        return "timeout"
    if err:
        return "network error"
    return "no response"


def speed_readings(session, url, first):
    """Three homepage speed readings: the scan's own homepage fetch
    plus two probes of the same URL. All three readings use the same
    URL, the same session headers, the same redirect handling, and
    the same timing definitions. Reading 1 is the scan's homepage
    fetch itself: in the production copy all three readings share
    the 2 MB body cap, but reading 1 runs at the scan fetch timeout
    (4s production / 10s local) rather than the probe timeout, and
    the local engine reads reading 1's body uncapped - so the local
    copy approximates, but does not exactly replicate, production
    sampling (documented in scoring.md g). The probes cap the body
    at SPEED_PROBE_MAX_BYTES and run at SPEED_PROBE_TIMEOUT, which
    sits ABOVE the 6s total-time scoring threshold, so a response
    completing inside the scoring window (e.g. 5s) is measured,
    never misclassified as a failure for stopping early. A failed
    probe is recorded as a slow reading WITH its diagnostic reason
    (timeout / network error / rate limit / challenge / HTTP
    status); it is not a scan failure - the homepage itself was
    already read."""
    readings = [(first[0], first[1], None)]
    for _ in range(SPEED_READINGS - 1):
        ok, status, text, total, ttfb, err = fetch(
            session, url, max_bytes=SPEED_PROBE_MAX_BYTES,
            timeout=SPEED_PROBE_TIMEOUT)
        if ok and status == 200:
            readings.append((ttfb, total, None))
        else:
            readings.append((None, None,
                             _classify_probe_result(ok, status, text, err)))
    return readings


def check_speed(readings):
    """Score SERVER RESPONSE TIMING from the MEDIAN of SPEED_READINGS
    homepage readings. This measures how fast the server answers our
    scanner; it is not a full browser page-load measurement. The
    bands are deliberately wide - three steps per component - so
    ordinary timing jitter cannot swing the score; a genuinely slow
    site still lands at the bottom."""
    w = WEIGHTS["page_speed"]

    def band(v, good, ok):
        if v is None:
            return 0.0
        if v <= good:
            return 1.0
        if v <= ok:
            return 0.5
        return 0.0

    triples = [(r[0], r[1], r[2] if len(r) > 2 else None) for r in readings]
    ttfbs = [r[0] for r in triples]
    totals = [r[1] for r in triples]
    med_ttfb = _median3(ttfbs)
    med_total = _median3(totals)
    ttfb_s = band(med_ttfb, 1.0, 3.0)
    total_s = band(med_total, 2.5, 6.0)
    score = w * 0.5 * (ttfb_s + total_s)

    def fmt(v):
        return f"{v:.2f}s" if v is not None else "no response"

    detail = (f"TTFB median {fmt(med_ttfb)} (readings: "
              + ", ".join(fmt(v) for v in ttfbs)
              + f"); total median {fmt(med_total)} (readings: "
              + ", ".join(fmt(v) for v in totals)
              + ") \u2014 median of 3 readings")
    fails = [f"reading {i + 1}: {reason}"
             for i, (_t, _tt, reason) in enumerate(triples) if reason]
    if fails:
        detail += "; failed readings \u2014 " + ", ".join(fails)
    detail += (" \u2014 server response timing measured by our scanner; "
               "not a full browser page-load measure")
    status = "pass" if score >= w else ("partial" if score >= w * 0.5 else "fail")
    return score, status, detail


# --------------------------------------------------------------- deep page ---
def pick_deep_page(base, html):
    netloc = urlparse(base).netloc.lower()
    for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']', html, re.I):
        href = m.group(1).strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        absu = urljoin(base + "/", href)
        p = urlparse(absu)
        if p.netloc.lower() != netloc or not p.path or p.path == "/":
            continue
        return absu
    return base + "/contact"


# --------------------------------------------------------------------- core ---
def grade(score):
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    return "F"  # anything under 60 is failing — no D grade


def run_audit(raw_url):
    """Full audit. Never raises — failures are reported in the dict."""
    t_start = time.perf_counter()
    try:
        base, url, norm_error = normalize_url(raw_url)
        if base is None:
            return {"url": (raw_url or "")[:200], "error": norm_error, "score": 0.0,
                    "checks": [], "fixes": [], "errors": [norm_error]}
        # Build 4.1.1: an unresolvable host proceeds through the scan
        # (all fetches fail on DNS) so it earns the standard incomplete
        # report instead of the pre-4.1.1 HTTP 400 / internal-error body.
        dns_unresolvable = norm_error == DNS_FAIL_REASON

        errors = []
        if dns_unresolvable:
            errors.append(
                f"could not resolve host: {urlparse(url).hostname}")
        session = make_session()

        # 4 independent fetches in parallel
        with ThreadPoolExecutor(max_workers=4) as ex:
            f_home = ex.submit(fetch, session, base + "/")
            f_robots = ex.submit(fetch, session, base + "/robots.txt")
            f_llms = ex.submit(fetch, session, base + "/llms.txt")
            f_sitemap = ex.submit(fetch, session, base + "/sitemap.xml")
            home = f_home.result()
            robots_r, llms_r, sitemap_r = f_robots.result(), f_llms.result(), f_sitemap.result()

        if not llms_r[0] and llms_r[5] and "timeout" in llms_r[5]:
            # Scoring v6: one longer-timeout retry for llms.txt, so
            # a transient timeout on a slow host is not scored as a
            # confirmed absence (the robots rule, extended to llms).
            llms_r = fetch(session, base + "/llms.txt",
                           timeout=LLMS_RETRY_TIMEOUT)

        ok_h, st_h, html, total, ttfb, err_h = home
        homepage_ok = bool(ok_h and st_h == 200 and html and html.strip())
        incomplete_reasons = []
        if dns_unresolvable:
            incomplete_reasons.append("could not resolve host")
        if not ok_h:
            errors.append(f"homepage fetch failed: {err_h}")
            html, st_h = "", None
        elif st_h != 200:
            errors.append(f"homepage returned HTTP {st_h}")
            html = ""
        if not homepage_ok:
            # Scoring v2 / scanner fix queue: a scan that could not read
            # the homepage is explicitly INCOMPLETE - the content-driven
            # checks fail with that stated, instead of silently scoring
            # an empty page (the v1 mechanism behind a 16.5 for an
            # unmeasured homepage).
            incomplete_reasons.append(
                "homepage could not be fetched or returned no content")

        # Scoring v2: schema is aggregated over the homepage plus key
        # inner pages (the AI Information page + sitemap/homepage-
        # discovered service, pricing and FAQ pages), fetched in
        # parallel at the deep-page timeout while the clock allows.
        sitemap_text = sitemap_r[2] if (sitemap_r[0] and sitemap_r[1] == 200) else ""
        schema_pages = [("homepage", html)]
        # Final v4: per-page status is recorded for every selected page
        # (ok / not_found / soft_404 / duplicate / truncated / failed /
        # skipped); a selected page that failed or was truncated makes
        # the affected checks UNCERTAIN via incomplete_reasons - never
        # silently scored as a verified absence.
        scanned_pages = [{"url": base + "/",
                          "status": "ok" if homepage_ok else "failed"}]
        ai_status = (ai_info_link_status(base, html, sitemap_text)
                     if homepage_ok else "unknown (homepage unreadable)")
        inner_fetched = []
        if homepage_ok:
            candidates = discover_schema_pages(base, html, sitemap_text)
            if candidates and (time.perf_counter() - t_start) < SCHEMA_TIME_BUDGET:
                with ThreadPoolExecutor(max_workers=min(3, len(candidates))) as ex2:
                    futs = {ex2.submit(fetch, session, u, timeout=TIMEOUT_DEEP): u
                            for u in candidates}
                    inner_results = {u: f.result() for f, u in futs.items()}
                uncertain = 0
                seen_hashes = {hashlib.sha256(
                    html.encode("utf-8", "replace")).hexdigest()}
                for cand in candidates:
                    cok, cstatus, chtml, _ct, _cttfb, cerr = inner_results[cand]
                    if cok and cstatus == 200 and chtml and chtml.strip():
                        if _is_soft_404(chtml):
                            scanned_pages.append({"url": cand, "status": "soft_404"})
                            continue
                        digest = hashlib.sha256(
                            chtml.encode("utf-8", "replace")).hexdigest()
                        if digest in seen_hashes:
                            # A redirect landed on an already-scanned page.
                            scanned_pages.append({"url": cand, "status": "duplicate"})
                            continue
                        seen_hashes.add(digest)
                        label = urlparse(cand).path or cand
                        schema_pages.append((label, chtml))
                        inner_fetched.append((label, chtml))
                        truncated = (len(chtml.encode("utf-8", "replace"))
                                     >= MAX_BYTES - 1024)
                        scanned_pages.append(
                            {"url": cand,
                             "status": "truncated" if truncated else "ok"})
                        if truncated:
                            uncertain += 1
                    elif cok and cstatus == 404:
                        # Page does not exist - negative result, not a gap.
                        scanned_pages.append({"url": cand, "status": "not_found"})
                    else:
                        uncertain += 1
                        scanned_pages.append({"url": cand, "status": "failed"})
                        errors.append(f"schema page fetch failed ({cand}): "
                                      f"{cerr or 'HTTP ' + str(cstatus)}")
                if uncertain:
                    incomplete_reasons.append(
                        "schema/pricing checks: selected inner page(s) failed "
                        "or were truncated - findings are 'within the "
                        "scanned pages' only")
            elif candidates:
                errors.append("schema inner pages skipped (time budget \u2014 homepage only)")
                for cand in candidates:
                    scanned_pages.append({"url": cand, "status": "skipped"})
                incomplete_reasons.append(
                    "schema/pricing checks: selected inner page(s) not "
                    "scanned (time budget) - findings are 'within the "
                    "scanned pages' only")

        checks = []
        s, st, d = check_robots(robots_r)
        if st == "uncertain":
            # Scoring v5: an unverifiable robots.txt flags the scan
            # incomplete - never silently a pass, never a measured fail.
            incomplete_reasons.append(
                "robots.txt could not be verified - crawler posture unmeasured")
        checks.append(("robots_ai_posture", "robots.txt AI-crawler posture", s, st, d))
        s, st, d = check_llms_txt(llms_r)
        if st == "uncertain":
            # Scoring v6: an unverifiable llms.txt flags the scan
            # incomplete - never silently a pass, never a measured fail.
            incomplete_reasons.append(
                "llms.txt could not be verified - presence unmeasured")
        checks.append(("llms_txt", "llms.txt present", s, st, d))
        s, st, d = check_sitemap(sitemap_r)
        checks.append(("sitemap", "sitemap.xml present", s, st, d))
        if homepage_ok:
            s, st, d = check_jsonld_pages(
                schema_pages, site_host=urlparse(base).netloc)
        else:
            s, st, d = 0.0, "fail", "homepage content unavailable \u2014 schema check incomplete"
        checks.append(("schema_jsonld", "schema.org JSON-LD", s, st, d))
        # Pricing: homepage plus the same key inner pages the schema
        # check scanned (v3; no additional fetches).
        if homepage_ok:
            s, st, d = check_pricing_pages(schema_pages)
        else:
            s, st, d = 0.0, "fail", "homepage content unavailable \u2014 pricing check incomplete"
        checks.append(("pricing_html", "pricing in raw HTML", s, st, d))

        # Bot wall: homepage + one inner page. Empty content never earns
        # these points - no readable homepage = incomplete, not a pass.
        if not homepage_ok:
            s, st, d = 0.0, "fail", ("no page content fetched \u2014 cannot verify "
                                     "bot-wall posture (scan incomplete)")
            checks.append(("bot_wall", "no bot-wall / CAPTCHA", s, st, d))
        else:
            pages = [("homepage", html)]
            if inner_fetched:
                pages.append(("deep page " + inner_fetched[0][0], inner_fetched[0][1]))
            elif (time.perf_counter() - t_start) < TIME_BUDGET:
                deep_url = pick_deep_page(base, html)
                dok, dstatus, dhtml, _t, _ttfb, derr = fetch(session, deep_url, timeout=TIMEOUT_DEEP)
                if dok and dstatus == 200:
                    pages.append(("deep page " + urlparse(deep_url).path, dhtml))
                else:
                    errors.append(f"deep page fetch failed ({deep_url}): {derr or 'HTTP ' + str(dstatus)}")
            else:
                errors.append("deep page skipped (time budget \u2014 homepage only)")
            s, st, d = check_bot_wall(pages)
            checks.append(("bot_wall", "no bot-wall / CAPTCHA", s, st, d))
        if homepage_ok:
            readings = speed_readings(session, base + "/", (ttfb, total))
            s, st, d = check_speed(readings)
        else:
            s, st, d = 0.0, "fail", "homepage did not load \u2014 no speed measurement (scan incomplete)"
        checks.append(("page_speed", "server response timing", s, st, d))

        # Platform feasibility (Caleb ruling 2026-10-21): detect the
        # platform and compute the $449 eligibility outcome for the
        # platform box below. Runs on the already-fetched homepage;
        # detection failure never affects the score, it only leaves
        # the platform unconfirmed. Per-check fixable / platform-
        # limit labels were removed from the results by Caleb ruling
        # 2026-10-22; eligibility still drives the platform box and
        # the $449 offer wording, exactly as before.
        platform_name, platform_evidence = detect_platform(
            urlparse(base).hostname or "", html)
        assessment = assess_platform(platform_name, checks)
        business_name = derive_business_name(html)

        total_score = round(sum(c[2] for c in checks), 1)
        results = []
        for cid, name, sc, st, detail in checks:
            entry = {
                "id": cid, "name": name, "weight": WEIGHTS[cid],
                "status": st, "score": round(sc, 1), "detail": detail,
                "meaning": CHECK_COPY[cid]["meaning"]}
            if cid in CHECK_NOTES:
                entry["note"] = CHECK_NOTES[cid]
            results.append(entry)
        platform_block = {
            "detected": bool(platform_name),
            "name": platform_name,
            "evidence": platform_evidence,
            "eligibility": assessment["eligibility"],
            "ceiling": assessment["ceiling"],
            "ceiling_line": assessment["ceiling_line"],
            "limitations": assessment["limitations"],
            "offer_line": platform_offer_line(platform_name, assessment),
            "short_line": platform_short_line(platform_name, assessment),
            "confirm_line": (None if platform_name
                             else CONFIRM_PLATFORM_LINE),
        }
        lost = [(WEIGHTS[cid] - sc, WEIGHTS[cid], FIX_TEXT[cid], cid)
                for cid, _n, sc, _s, _d in checks if sc < WEIGHTS[cid]]
        lost.sort(key=lambda x: (-x[1], -x[0]))
        fixes = [f"{text} (up to {w} pts)" for _l, w, text, cid in lost]

        return {
            "tool": f"agent-readiness-audit/{VERSION}",
            "scoring_version": SCORING_VERSION,
            "url": url,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "score": total_score,
            # Scoring v5: no letter grade is emitted for an incomplete
            # scan - the numeric partial score stays in the report for
            # internal use, but a grade computed from unmeasured
            # checks would mislead (an unreadable homepage caps the
            # measurable total at 40, an automatic 'F').
            "grade": grade(total_score) if not incomplete_reasons else None,
            "business_name": business_name,
            "checks": results,
            "platform": platform_block,
            "checkout_urls": {
                "audit_149": STRIPE_149_CHECKOUT_URL,
                "done_for_you_449": STRIPE_449_CHECKOUT_URL,
            },
            "fixes": fixes,
            "errors": errors,
            "complete": not incomplete_reasons,
            "incomplete_reasons": incomplete_reasons,
            "ai_info_discoverable": ai_status,
            "scanned_pages": scanned_pages,
            "duration_s": round(time.perf_counter() - t_start, 2),
        }
    except Exception as e:  # absolute last resort — never 500
        return {"url": (raw_url or "")[:200], "error": f"internal error: {e}",
                "score": 0.0, "checks": [], "fixes": [],
                "errors": [f"internal error: {e}"]}


# --------------------------------------------------------------- rate limit ---
# NOTE: in-memory = per function instance. Fine for launch; if abuse appears,
# move this to Upstash Redis (one env var + a few lines).
_RATE = {}
_RATE_LIMIT = 10          # audits
_RATE_WINDOW = 3600       # per hour, per IP


def rate_ok(ip):
    now = time.time()
    window = [t for t in _RATE.get(ip, []) if now - t < _RATE_WINDOW]
    if len(window) >= _RATE_LIMIT:
        return False
    window.append(now)
    # opportunistic cleanup so the dict can't grow forever
    if len(_RATE) > 10000:
        _RATE.clear()
    _RATE[ip] = window
    return True


# ------------------------------------------------------- results email ---
# The scan page promises visitors "we email your results to you." From
# 2026-10-16 to 2026-10-19 that promise rode on FormSubmit's _autoresponse,
# which never delivered a single copy (FormSubmit's own API answers that
# the Autoresponse Plugin must be turned ON for the account; it is off).
# The reliable path is ours: after a successful audit, this function sends
# the result summary itself, from the business inbox, over Google
# Workspace SMTP. Credential = a Google app password for
# hello@agentreadinesshq.com, stored ONLY as the Vercel env var
# RESULTS_SMTP_PASSWORD. Unset -> no send, audit unaffected.
RESULTS_FROM = "hello@agentreadinesshq.com"
RESULTS_SMTP_HOST = "smtp.gmail.com"
RESULTS_SMTP_PORT = 587
RESULTS_SMTP_SSL_PORT = 465
# Explicit EHLO identity: serverless containers often have a broken
# default FQDN, and a malformed EHLO can get the connection dropped.
RESULTS_SMTP_LOCAL_HOSTNAME = "agentreadinesshq.com"
_STATUS_MARK = {"pass": "\u2713", "partial": "~", "fail": "\u2717"}
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _fmt_num(x):
    """Match the on-page JS number rendering (65.0 shows as 65)."""
    try:
        s = str(float(x))
    except (TypeError, ValueError):
        return "?"
    return s[:-2] if s.endswith(".0") else s


def _esc_html(s):
    """Minimal HTML escaping for values interpolated into the email."""
    return (str(s if s is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


# Score-pill colors by check status, mirroring the scan-email mock-up
# approved 2026-10-20 (green = full marks, amber = partial, rose = zero
# or low).
_PILL_STYLE = {
    "pass": ("#e3f4ea", "#146c43", "#1f9d63"),
    "partial": ("#fdf1d7", "#8a5a00", "#e8a13d"),
    "fail": ("#ffe0e7", "#c21847", "#ff4d6d"),
}
_GRADE_CHIP_STYLE = {
    "A": ("#e3f4ea", "#146c43"),
    "B": ("#e3f4ea", "#146c43"),
    "C": ("#fdf1d7", "#8a5a00"),
    "F": ("#ffe0e7", "#c21847"),
}


def _email_button_html(url, label):
    """The site's standard rose pill button, email-safe (table cell
    carries the background; the anchor carries the padding)."""
    return (
        '<table role="presentation" cellpadding="0" cellspacing="0" '
        'style="margin-top:16px;"><tr>'
        '<td style="background-color:#ff4d6d; border-radius:99px;">'
        '<a href="%s" style="display:inline-block; padding:13px 32px; '
        'font-size:16px; font-weight:700; color:#ffffff; '
        'text-decoration:none;">%s</a></td></tr></table>'
        % (_esc_html(url), _esc_html(label)))


def _results_email_html(first_name, site, score, grade, checks, platform=None,
                        email=None, incomplete=False):
    """HTML version of the results email, mirroring the on-page results:
    score/grade header, then per check the technical name + score pill,
    the finding line, and the plain-English meaning line. (Per-check
    fixable / platform-limit lines were removed by Caleb ruling
    2026-10-22; each check renders exactly those two parts.)
    After the checks comes the conversion block (Caleb ruling
    2026-10-22): headline + subline, for B/C the short platform
    limitation sentence, then the two purchase options as stacked
    cards with rose pill buttons linking straight to the Stripe
    checkouts (for C the $449 card is muted, carries no button, and
    only the $149 button appears). The full technical platform
    disclosure is preserved verbatim at the end, under a small
    "Platform details" subhead. Table layout + inline styles for
    email-client compatibility; visual language follows the
    2026-10-20 scan-email mock-up Caleb reviewed.
    """
    chip_bg, chip_fg = _GRADE_CHIP_STYLE.get(grade, ("#fdf1d7", "#8a5a00"))
    try:
        pct = max(0.0, min(100.0, float(score)))
    except (TypeError, ValueError):
        pct = 0.0
    pct_txt = ("%.1f" % pct).rstrip("0").rstrip(".")
    blocks = []
    for c in checks:
        bg, fg, dot = _PILL_STYLE.get(c.get("status"),
                                      ("#fdf1d7", "#8a5a00", "#e8a13d"))
        pill = (
            '<span style="display:inline-block; background-color:%s; '
            'color:%s; font-size:13.5px; font-weight:700; padding:5px 13px; '
            'border-radius:99px;"><span style="color:%s;">&#9679;</span>'
            "&nbsp; %s / %s</span>"
            % (bg, fg, dot, _esc_html(_fmt_num(c.get("score"))),
               _esc_html(_fmt_num(c.get("weight")))))
        block = [
            '<div style="border-top:1px solid #f0e6e8; margin-top:22px; '
            'padding-top:22px;">',
            '<table role="presentation" width="100%" cellpadding="0" '
            'cellspacing="0"><tr>',
            '<td style="vertical-align:top;"><span style="font-size:16.5px; '
            'font-weight:700; color:#1d1d1f;">%s</span></td>'
            % _esc_html(c.get("name", "")),
            '<td align="right" style="vertical-align:top; '
            'white-space:nowrap;">%s</td>' % pill,
            "</tr></table>",
        ]
        detail = (c.get("detail") or "").strip()
        if detail:
            block.append(
                '<p style="font-size:14px; line-height:1.55; color:#6e6e73; '
                'margin-top:7px; padding-left:20px;">%s</p>'
                % _esc_html(detail))
        meaning = (c.get("meaning") or "").strip()
        if meaning:
            block.append(
                '<p style="font-size:15px; line-height:1.6; color:#333336; '
                'margin-top:8px; padding-left:20px;">%s</p>'
                % _esc_html(meaning))
        note = (c.get("note") or "").strip()
        if note:
            block.append(
                '<p style="font-size:15px; line-height:1.6; color:#333336; '
                'margin-top:8px; padding-left:20px;">%s</p>'
                % _esc_html(note))
        block.append("</div>")
        blocks.append("".join(block))
    # Conversion block (Caleb ruling 2026-10-22), mirroring the
    # on-page conversion box: headline + subline; for B/C the short
    # platform limitation sentence before the purchase choices (email
    # cannot collapse, so it is a static strip); then the two options
    # as stacked cards with rose pill buttons to the Stripe checkouts.
    # For C the $449 card is muted with no button. For an
    # unidentified platform the confirmation note follows the cards.
    platform = platform or {}
    eligibility = platform.get("eligibility")
    short_line = platform_short_line(
        platform.get("name"),
        {"eligibility": eligibility,
         "limitations": platform.get("limitations") or []})
    conv = [
        '<div style="border-top:1px solid #f0e6e8; margin-top:22px; '
        'padding-top:22px;">',
        '<h2 style="font-size:21px; line-height:1.3; font-weight:800; '
        'letter-spacing:-0.01em; color:#1d1d1f; margin:0;">We\u2019ll '
        'help you fix your score.</h2>',
        '<p style="font-size:15.5px; line-height:1.6; color:#333336; '
        'margin-top:10px;">Most of these issues sound more technical '
        "than they are. We turn your results into simple, "
        "plain-English fixes.</p>",
    ]
    if eligibility in ("B", "C") and short_line:
        conv.append(
            '<div style="margin-top:18px; background-color:#fff7f8; '
            'border:1px solid #ffd9e1; border-radius:12px; '
            'padding:16px 20px;">'
            '<p style="font-size:15.5px; font-weight:700; '
            'color:#1d1d1f; margin:0;">&#9888; Your website platform '
            "has a limitation</p>"
            '<p style="font-size:15px; line-height:1.55; '
            'color:#333336; margin-top:6px;">%s</p></div>'
            % _esc_html(short_line))
    conv.append(
        '<table role="presentation" width="100%" cellpadding="0" '
        'cellspacing="0" style="margin-top:18px; background-color:'
        '#ffffff; border:2px solid #ffd9e1; border-radius:12px;">'
        '<tr><td style="padding:22px 26px;">'
        '<div style="font-size:30px; font-weight:800; '
        'letter-spacing:-0.02em; color:#1d1d1f;">$149</div>'
        '<div style="font-size:17px; font-weight:700; '
        'color:#1d1d1f; margin-top:4px;">Show me how</div>'
        '<p style="font-size:15px; line-height:1.55; color:#6e6e73; '
        'margin-top:8px;">Step-by-step instructions + ready-to-use '
        "content: copy, paste, publish.</p>"
        + _email_button_html(STRIPE_149_CHECKOUT_URL, "Show me how")
        + "</td></tr></table>")
    if eligibility == "C":
        conv.append(
            '<table role="presentation" width="100%" cellpadding="0" '
            'cellspacing="0" style="margin-top:14px; background-color:'
            '#f4f4f5; border:2px solid #e4e4e7; border-radius:12px;">'
            '<tr><td style="padding:22px 26px;">'
            '<div style="font-size:30px; font-weight:800; '
            'color:#8e8e93;">$449</div>'
            '<div style="font-size:17px; font-weight:700; '
            'color:#8e8e93; margin-top:4px;">Do it for me</div>'
            '<p style="font-size:15px; line-height:1.55; '
            'color:#8e8e93; margin-top:8px;">Not available on your '
            "website platform.</p>"
            "</td></tr></table>")
    else:
        conv.append(
            '<table role="presentation" width="100%" cellpadding="0" '
            'cellspacing="0" style="margin-top:14px; background-color:'
            '#ffffff; border:2px solid #ffd9e1; border-radius:12px;">'
            '<tr><td style="padding:22px 26px;">'
            '<div style="font-size:30px; font-weight:800; '
            'letter-spacing:-0.02em; color:#1d1d1f;">$449</div>'
            '<div style="font-size:17px; font-weight:700; '
            'color:#1d1d1f; margin-top:4px;">Do it for me</div>'
            '<p style="font-size:15px; line-height:1.55; '
            'color:#6e6e73; margin-top:8px;">We make the approved '
            "improvements for you.</p>"
            + _email_button_html(STRIPE_449_CHECKOUT_URL,
                                 "Do it for me")
            + "</td></tr></table>")
    confirm = (platform.get("confirm_line") or "").strip()
    if confirm:
        conv.append(
            '<p style="font-size:14px; line-height:1.55; '
            'color:#6e6e73; margin-top:16px;">%s</p>'
            % _esc_html(confirm))
    conv.append(
        '<p style="font-size:15.5px; line-height:1.6; color:#333336; '
        'margin-top:22px;">Your full results are on the page where '
        "you ran the scan.</p>")
    conv.append(
        '<p style="font-size:15.5px; line-height:1.6; color:#333336; '
        'margin-top:10px;">Or just reply to this email with any '
        "questions.</p>")
    conv.append("</div>")
    conversion_html = "".join(conv)
    # Platform details: the full technical disclosure, preserved
    # verbatim (detected line, ceiling paragraph, eligibility
    # paragraph), at the end of the email under a small subhead in
    # muted type.
    detail_parts = []
    if platform.get("detected"):
        detail_parts.append(
            '<p style="font-size:13.5px; line-height:1.55; '
            'color:#6e6e73; margin-top:10px;">Website platform: '
            "<strong>%s</strong> (detected automatically).</p>"
            % _esc_html(platform.get("name") or ""))
    for key in ("ceiling_line", "offer_line"):
        text = (platform.get(key) or "").strip()
        if text:
            detail_parts.append(
                '<p style="font-size:13.5px; line-height:1.55; '
                'color:#6e6e73; margin-top:8px;">%s</p>'
                % _esc_html(text))
    details_html = ""
    if detail_parts:
        details_html = (
            '<div style="margin-top:26px;">'
            '<p style="font-size:13px; font-weight:700; '
            'letter-spacing:0.05em; color:#8e8e93; margin:0;">'
            "Platform details</p>" + "".join(detail_parts) + "</div>")
    # Header block: score + grade chip for a complete scan; for an
    # incomplete scan (scoring v5) an explicit Incomplete result with
    # NO score and NO grade - a partial number computed from
    # unmeasured checks would mislead.
    framing_line = ""
    if incomplete:
        header_block = (
            '<table role="presentation" width="100%" cellpadding="0" '
            'cellspacing="0" style="margin-top:22px; background-color:'
            '#fdf6ec; border:1px solid #ecd9ae; border-radius:12px;">'
            '<tr><td style="padding:22px 26px; vertical-align:middle;">'
            '<div style="font-size:12px; font-weight:700; '
            'letter-spacing:0.09em; color:#8a5a00;">SCAN RESULT</div>'
            '<div style="margin-top:6px; font-size:30px; font-weight:800; '
            'letter-spacing:-0.02em; color:#1d1d1f;">Incomplete scan</div>'
            '<p style="font-size:15px; line-height:1.55; color:#333336; '
            'margin-top:8px;">We could not read everything on this '
            'site, so no score or grade is issued for this scan.</p>'
            "</td></tr></table>")
        scored_line = (
            '<p style="font-size:15.5px; line-height:1.6; color:#333336; '
            'margin-top:20px;">Here is what the scan could measure on '
            + _esc_html(site) + ", and what it could not:</p>")
    else:
        header_block = (
            '<table role="presentation" width="100%" cellpadding="0" '
            'cellspacing="0" style="margin-top:22px; background-color:'
            '#fff7f8; border:1px solid #ffd9e1; border-radius:12px;">'
            "<tr>"
            '<td style="padding:22px 26px; vertical-align:middle;">'
            '<div style="font-size:12px; font-weight:700; '
            'letter-spacing:0.09em; color:#c21847;">YOUR AI READINESS '
            "SCORE</div>"
            '<div style="margin-top:6px;"><span style="font-size:46px; '
            'font-weight:800; letter-spacing:-0.02em; color:#1d1d1f;">'
            + _esc_html(score) + '</span><span style="font-size:19px; '
            'font-weight:600; color:#6e6e73;"> / 100</span></div>'
            '<table role="presentation" width="100%" cellpadding="0" '
            'cellspacing="0" style="margin-top:12px;"><tr><td style="'
            'background-color:#f6dde2; border-radius:99px; height:9px;">'
            '<div style="width:' + pct_txt + '%; height:9px; '
            'border-radius:99px; background-color:#ff4d6d; font-size:0; '
            'line-height:0;">&nbsp;</div></td></tr></table>'
            "</td>"
            '<td width="118" align="center" style="padding:22px 10px; '
            'vertical-align:middle;">'
            '<div style="font-size:12px; font-weight:700; '
            'letter-spacing:0.09em; color:#8a5a00;">GRADE</div>'
            '<div style="display:inline-block; margin-top:8px; '
            "background-color:" + chip_bg + "; color:" + chip_fg + "; "
            'font-size:34px; font-weight:800; line-height:1; '
            'padding:12px 22px; border-radius:12px;">'
            + _esc_html(grade) + "</div>"
            "</td>"
            "</tr>"
            "</table>")
        scored_line = (
            '<p style="font-size:15.5px; line-height:1.6; color:#333336; '
            'margin-top:20px;">' + _esc_html(site) + " scored "
            + _esc_html(score) + "/100 (grade " + _esc_html(grade)
            + "). Here is how the seven checks came out:</p>")
        # Language pack item S-4 (2026-11-02): Caleb's prescribed
        # grade-framing sentence, directly under the grade block, the
        # same sentence the results page shows under the grade.
        framing_line = (
            '<p style="font-size:14.5px; line-height:1.6; color:#6e6e73; '
            'margin-top:12px;">Based on seven automated technical '
            "checks using our proprietary methodology. This assesses "
            "website accessibility and machine-readability, not "
            "business quality or whether AI recommends your "
            "business.</p>")
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Your free scan results</title></head>
<body style="margin:0; padding:0; background-color:#f7f2f0; font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif; color:#1d1d1f;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background-color:#f7f2f0;">
<tr><td align="center" style="padding:28px 12px 36px 12px;">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="width:640px; max-width:640px; background-color:#ffffff; border:1px solid #f0dfe3; border-radius:16px;">
<tr><td style="padding:36px 44px 40px 44px;">
<span style="font-size:20px; font-weight:800; letter-spacing:-0.02em; color:#1d1d1f;">Agent Readiness <span style="color:#ff4d6d;">HQ</span></span>
<div style="border-bottom:2px solid #ff4d6d; margin:20px 0 26px 0; font-size:0; line-height:0;">&nbsp;</div>
<h1 style="font-size:27px; line-height:1.25; font-weight:800; letter-spacing:-0.01em; color:#1d1d1f; margin:0;">Your free scan results</h1>
<p style="font-size:16px; line-height:1.6; color:#333336; margin-top:16px;">Hi %(first)s, thanks for running your free AI Readiness Scan with Agent Readiness HQ!</p>
%(header_block)s
%(framing)s
%(scored_line)s
%(checks)s
%(conversion)s
%(details)s
<p style="font-size:16px; line-height:1.6; color:#333336; margin-top:26px;">Thanks,<br><br><strong>Agent Readiness HQ</strong><br><span style="color:#5c5c60;">hello@agentreadinesshq.com</span></p>
<p style="font-size:13px; line-height:1.55; color:#8e8e93; text-align:center; margin-top:30px;">You are receiving this because you requested your results at agentreadinesshq.com.</p>
%(footer)s
</td></tr>
</table>
</td></tr>
</table>
</body></html>""" % {
        "first": _esc_html(first_name),
        "site": _esc_html(site),
        "score": _esc_html(score),
        "grade": _esc_html(grade),
        "pct": pct_txt,
        "chip_bg": chip_bg,
        "chip_fg": chip_fg,
        "header_block": header_block,
        "framing": framing_line,
        "scored_line": scored_line,
        "checks": "".join(blocks),
        "conversion": conversion_html,
        "details": details_html,
        "footer": _footer_html(email) if email else "",
    }


def compose_results_email(first_name, email, report):
    """Build the visitor's copy of their free scan results.

    Multipart (plain text + HTML) since 2026-10-20. Both parts carry
    the same structure the visitor sees on the results page: score
    and grade, then each of the seven checks with its status mark,
    points, finding line, and plain-English meaning line. (The former
    third layer — per-check fixable / platform-limit lines — was
    removed by Caleb ruling 2026-10-22.) Signed with the business
    name only (2026-10-22 ruling). The free results are never called
    a "report" or an "Audit" — those words belong to the paid
    products.
    """
    site = report.get("url") or ""
    score = _fmt_num(report.get("score"))
    grade = report.get("grade") or "?"
    incomplete = report.get("complete") is False
    checks = report.get("checks") or []
    platform = report.get("platform") or {}
    eligibility = platform.get("eligibility")
    if incomplete:
        # Scoring v5: an incomplete scan carries no grade anywhere in
        # the email - subject or body. The per-check findings still
        # show what could and could not be measured.
        lines = [
            f"Hi {first_name}, thanks for running your free AI Readiness Scan "
            "with Agent Readiness HQ!",
            "",
            f"We could not read everything on {site}, so this scan is "
            "incomplete and no grade is issued. Here is what the scan "
            "could measure, and what it could not:",
            "",
        ]
    else:
        lines = [
            f"Hi {first_name}, thanks for running your free AI Readiness Scan "
            "with Agent Readiness HQ!",
            "",
            f"{site} scored {score}/100 (grade {grade}). "
            "Here is how the seven checks came out:",
            "Based on seven automated technical checks using our "
            "proprietary methodology. This assesses website "
            "accessibility and machine-readability, not business "
            "quality or whether AI recommends your business.",
            "",
        ]
    for c in checks:
        mark = _STATUS_MARK.get(c.get("status"), "?")
        lines.append(
            f"{mark} {c.get('name', '')} \u2014 "
            f"{_fmt_num(c.get('score'))}/{_fmt_num(c.get('weight'))}"
        )
        detail = (c.get("detail") or "").strip()
        if detail:
            lines.append(f"   {detail}")
        meaning = (c.get("meaning") or "").strip()
        if meaning:
            lines.append(f"   {meaning}")
        note = (c.get("note") or "").strip()
        if note:
            lines.append(f"   {note}")
    # Conversion block (Caleb ruling 2026-10-22), mirroring the
    # results page and the HTML part: headline + subline; for B/C the
    # short platform limitation sentence before the choices; the two
    # options with their checkout links as plain URLs (for C, Done
    # For You is named unavailable and carries no link); for an
    # unidentified platform, the confirm line as a note after the
    # choices. The full technical disclosure follows at the end
    # under "Platform details:", preserved verbatim.
    short_line = platform_short_line(
        platform.get("name"),
        {"eligibility": eligibility,
         "limitations": platform.get("limitations") or []})
    lines += [
        "",
        "We\u2019ll help you fix your score.",
        "Most of these issues sound more technical than they are. "
        "We turn your results into simple, plain-English fixes.",
        "",
    ]
    if eligibility in ("B", "C") and short_line:
        lines += [
            "\u26a0 Your website platform has a limitation",
            short_line,
            "",
        ]
    lines += [
        "$149",
        "Show me how",
        "Step-by-step instructions + ready-to-use content: copy, "
        "paste, publish.",
        f"Get it here: {STRIPE_149_CHECKOUT_URL}",
        "",
        "$449",
        "Do it for me",
    ]
    if eligibility == "C":
        lines.append("Not available on your website platform.")
    else:
        lines += [
            "We make the approved improvements for you.",
            f"Get it here: {STRIPE_449_CHECKOUT_URL}",
        ]
    confirm = (platform.get("confirm_line") or "").strip()
    if confirm:
        lines += ["", confirm]
    lines += [
        "",
        "Your full results are on the page where you ran the scan.",
        "",
        "Or just reply to this email with any questions.",
    ]
    detail_lines = []
    if platform.get("detected"):
        detail_lines.append(
            f"Website platform: {platform.get('name')} "
            "(detected automatically).")
    for key in ("ceiling_line", "offer_line"):
        text = (platform.get(key) or "").strip()
        if text:
            detail_lines.append(text)
    if detail_lines:
        lines += ["", "Platform details:"] + detail_lines
    lines += [
        "",
        "Thanks,",
        "",
        "Agent Readiness HQ",
        "hello@agentreadinesshq.com",
        "",
        "You are receiving this because you requested your results at "
        "agentreadinesshq.com.",
        "",
    ] + _footer_text_lines(email)
    msg = EmailMessage()
    msg["From"] = f"Agent Readiness HQ <{RESULTS_FROM}>"
    msg["To"] = email
    msg["Subject"] = (f"Your free scan results for {site}: incomplete scan"
                      if incomplete else
                      f"Your free scan results for {site}: {score}/100 (grade {grade})")
    msg.set_content("\n".join(lines))
    _set_unsubscribe_headers(msg, email)
    msg.add_alternative(
        _results_email_html(first_name, site, score, grade, checks,
                            platform, email=email, incomplete=incomplete),
        subtype="html")
    return msg


def _deliver_results(msg, password, transport, label="results email"):
    """One delivery attempt over a single transport. Logs each stage so
    the function logs name exactly where a failure occurs, and raises the
    original exception so the caller can decide on retry / fallback.

    transport is "587-starttls" or "465-ssl". label prefixes the log
    lines ("results email" for the scan results copy; other business
    mail sent from this function passes its own label).
    """
    stage = "connect"
    print(f"{label}: {transport} stage=connect")
    try:
        if transport == "465-ssl":
            smtp_cm = smtplib.SMTP_SSL(
                RESULTS_SMTP_HOST, RESULTS_SMTP_SSL_PORT, timeout=20,
                local_hostname=RESULTS_SMTP_LOCAL_HOSTNAME)
        else:
            smtp_cm = smtplib.SMTP(
                RESULTS_SMTP_HOST, RESULTS_SMTP_PORT, timeout=20,
                local_hostname=RESULTS_SMTP_LOCAL_HOSTNAME)
        with smtp_cm as smtp:
            stage = "ehlo"
            print(f"{label}: {transport} stage=ehlo")
            smtp.ehlo()
            if transport == "587-starttls":
                stage = "starttls"
                print(f"{label}: {transport} stage=starttls")
                smtp.starttls()
                stage = "ehlo"
                print(f"{label}: {transport} stage=ehlo-after-starttls")
                smtp.ehlo()
            stage = "login"
            print(f"{label}: {transport} stage=login")
            smtp.login(RESULTS_FROM, password)
            stage = "send"
            print(f"{label}: {transport} stage=send")
            smtp.send_message(msg)
    except Exception as exc:
        # Never swallow the cause: stage, transport, exception name and
        # message land in the Vercel function logs, where the next
        # verification run can read exactly why the send failed.
        print(
            f"{label} send failed: transport={transport} "
            f"stage={stage}: {type(exc).__name__}: {exc}")
        raise
    print(f"{label} sent via {transport}")
    return True



_PACKET_PDF_B64_URL = "https://agentreadinesshq.com/information-packet.b64"
_PACKET_PDF_CACHE = {}


def _packet_pdf_bytes():
    """Decode the information packet PDF (base64 copy served from the
    site root), cached per warm instance. None when unavailable."""
    if "pdf" in _PACKET_PDF_CACHE:
        return _PACKET_PDF_CACHE["pdf"]
    try:
        resp = requests.get(_PACKET_PDF_B64_URL, timeout=15)
        resp.raise_for_status()
        pdf = base64.b64decode(resp.content)
        if not pdf.startswith(b"%PDF"):
            raise ValueError("packet payload is not a PDF")
    except Exception as exc:
        print(f"packet pdf fetch failed: {type(exc).__name__}: {exc}")
        return None
    _PACKET_PDF_CACHE["pdf"] = pdf
    return pdf


def _packet_html(email):
    """HTML part for the packet email (added 2026-10-28): mirrors
    the plain-text body in the shared shell, with the standard
    footer in its hyperlink form. The text part stays as the
    fallback and keeps the raw unsubscribe URL on its own line,
    as plain text must."""
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Your Agent Readiness HQ information packet</title></head>
<body style="margin:0; padding:0; background-color:#f7f2f0; font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif; color:#1d1d1f;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f7f2f0;">
<tr><td align="center" style="padding:28px 12px 36px 12px;">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="width:640px; max-width:640px; background-color:#ffffff; border:1px solid #f0dfe3; border-radius:16px;">
<tr><td style="padding:36px 44px 40px 44px;">
<span style="font-size:20px; font-weight:800; letter-spacing:-0.02em; color:#1d1d1f;">Agent Readiness <span style="color:#ff4d6d;">HQ</span></span>
<div style="border-bottom:2px solid #ff4d6d; margin:20px 0 26px 0; font-size:0; line-height:0;">&nbsp;</div>
<p style="font-size:15.5px; line-height:1.6; color:#333336; margin:0;">Thanks for your interest in Agent Readiness HQ.</p>
<p style="font-size:15.5px; line-height:1.6; color:#333336; margin-top:14px;">Your information packet is attached as a PDF: how the free scan works, what each plan includes, and what everything costs.</p>
<p style="font-size:15.5px; line-height:1.6; color:#333336; margin-top:14px;">When you are ready, run the free scan and see how AI systems read your site:<br><a href="https://agentreadinesshq.com/" style="color:#c21847;">https://agentreadinesshq.com/</a></p>
<p style="font-size:15.5px; line-height:1.6; color:#333336; margin-top:14px;">You are receiving this because you requested the packet on our website.</p>
<p style="font-size:15.5px; line-height:1.6; color:#333336; margin-top:24px;">Thanks,<br><br>Agent Readiness HQ<br>hello@agentreadinesshq.com</p>
""" + _footer_html(email) + """</td></tr>
</table>
</td></tr>
</table>
</body></html>"""


def _packet_message(email, pdf_bytes):
    msg = EmailMessage()
    msg["From"] = RESULTS_FROM
    msg["To"] = email
    msg["Subject"] = "Your Agent Readiness HQ information packet"
    _set_unsubscribe_headers(msg, email)
    msg.set_content(
        "Thanks for your interest in Agent Readiness HQ.\n\n"
        "Your information packet is attached as a PDF: how the free scan "
        "works, what each plan includes, and what everything costs.\n\n"
        "When you are ready, run the free scan and see how AI systems "
        "read your site:\nhttps://agentreadinesshq.com/\n\n"
        "You are receiving this because you requested the packet on our "
        "website.\n\n"
        "Thanks,\n\n"
        "Agent Readiness HQ\n"
        "hello@agentreadinesshq.com\n\n"
        + "\n".join(_footer_text_lines(email)))
    msg.add_alternative(_packet_html(email), subtype="html")
    msg.add_attachment(pdf_bytes, maintype="application", subtype="pdf",
                       filename="Agent-Readiness-HQ-Information-Packet.pdf")
    return msg


def _packet_lead_message(email):
    msg = EmailMessage()
    msg["From"] = RESULTS_FROM
    msg["To"] = RESULTS_FROM
    msg["Subject"] = "Information packet request"
    msg.set_content(
        "A visitor requested the information packet; the PDF was emailed "
        "to them automatically.\n\n"
        f"Email: {email}\n"
        f"When: {datetime.now(timezone.utc).isoformat()}\n"
        "Source: website information form")
    return msg


def _scan_lead_message(first_name, email, report):
    """Internal lead record for a completed free scan.

    Sent from hello@ to hello@ by the scan function itself, in the
    same request that emails the visitor their results. Until
    2026-11-03 the only hello@ lead notice came from a separate
    fire-and-forget FormSubmit post in the visitor's browser after
    the scan returned; when that post failed or never ran, the lead
    existed nowhere in the inbox even though the server-side results
    email had been sent (Joey Paynter, 2026-11-03). The subject keeps
    the established "New free scan: <site>" form the signup watch
    already searches for, and the body keeps the same field names
    the FormSubmit table carried (name, email, website, score,
    grade), so the watch needs no change.
    """
    site = report.get("url") or ""
    score = _fmt_num(report.get("score"))
    grade = ("Incomplete scan" if report.get("complete") is False
             else (report.get("grade") or "?"))
    msg = EmailMessage()
    msg["From"] = RESULTS_FROM
    msg["To"] = RESULTS_FROM
    msg["Subject"] = f"New free scan: {site}"
    msg.set_content(
        "name: " + first_name + "\n"
        "email: " + email + "\n"
        "website: " + site + "\n"
        "score: " + score + "\n"
        "grade: " + grade + "\n\n"
        f"message: {first_name} ({email}) ran a free scan on {site}: "
        f"score {score}/100, grade {grade}.\n"
        f"When: {datetime.now(timezone.utc).isoformat()}\n"
        "Source: website free scan (server-side lead notice)")
    return msg


def _smtp_password():
    """The hello@ app password from the environment, whitespace-stripped.

    Google shows app passwords in spaced groups ("abcd efgh ..."); SMTP
    login needs the bare 16 characters, so strip all whitespace from the
    stored value instead of asking for the credential again.
    """
    return "".join((os.environ.get("RESULTS_SMTP_PASSWORD") or "").split())


def _deliver_with_fallback(msg_factory, password, label):
    """Deliver a message built by msg_factory over the transport ladder:
    port 587 with STARTTLS first; a dropped connection earns one full
    retry on a fresh connection; then port 465 (implicit TLS). Never
    raises: returns True only when the server accepted the message.
    msg_factory is called per attempt because a failed send can leave a
    message object in a partially-consumed state.
    """
    for attempt in (1, 2):
        try:
            return _deliver_results(
                msg_factory(), password, "587-starttls", label)
        except (smtplib.SMTPServerDisconnected, OSError) as exc:
            if attempt == 1:
                print(
                    f"{label}: retrying 587-starttls on a fresh "
                    f"connection after {type(exc).__name__}")
                continue
            print(f"{label}: 587-starttls retries exhausted, "
                  "falling back to 465-ssl")
        except Exception:
            # The stage log inside _deliver_results already named the
            # failure; a non-connection error is not retried, but the
            # fallback transport still gets its chance below.
            print(f"{label}: 587-starttls failed, "
                  "falling back to 465-ssl")
            break
    try:
        return _deliver_results(msg_factory(), password, "465-ssl", label)
    except Exception:
        return False


def send_results_email(first_name, email, report):
    """Send the results copy via Google Workspace SMTP. Never raises:
    returns True only when the server accepted the message. Delivery
    path (587/STARTTLS, one retry on a dropped connection, then the
    465/SSL fallback) lives in _deliver_with_fallback.
    """
    password = _smtp_password()
    if not password:
        print("results email: RESULTS_SMTP_PASSWORD not visible to this function")
        return False
    return _deliver_with_fallback(
        lambda: compose_results_email(first_name, email, report),
        password, "results email")


def send_scan_lead_notice(first_name, email, report):
    """Record a completed free scan as a lead in hello@. Never raises:
    returns True only when the server accepted the notice. Uses the
    same SMTP ladder as the results email (send_business_email)."""
    return send_business_email(
        lambda: _scan_lead_message(first_name, email, report),
        "scan lead notice")


def send_business_email(msg_factory, label):
    """Send any other business email from hello@ over the same SMTP
    ladder as the results email. Never raises."""
    password = _smtp_password()
    if not password:
        print(f"{label}: RESULTS_SMTP_PASSWORD not visible to this function")
        return False
    return _deliver_with_fallback(msg_factory, password, label)


# ------------------------------------------------- Stripe webhook / day 0 ---
# Intake journey rebuild (spec: intake-journey-build-spec-2026-10-19).
# Stripe fires checkout.session.completed the moment a payment lands.
# The webhook handler below sends the day-0 purchase confirmation
# (Template 7, pre-launch-package/09-email-templates.md) automatically,
# with a personalized link to the scan-first intake door, and records
# the order two ways: a structured ORDER line in the function logs and
# an internal notification email to hello@ carrying the tracker fields
# (20-order-tracker.md). Previously no Stripe notification reached
# hello@ at all and the confirmation was sent by hand.
#
# FAIL-CLOSED: the endpoint does nothing (HTTP 503) until the
# STRIPE_WEBHOOK_SECRET env var is configured in Vercel, and every
# event's Stripe-Signature header is verified against it (HMAC-SHA256
# over "<timestamp>.<raw body>", 5-minute tolerance) before any
# processing. An unsigned or badly signed POST can therefore never
# trigger an email or an order record.
SITE_BASE = "https://agentreadinesshq.com"
INTAKE_DOOR_PATH = "/intake-149.html"
INTAKE_DOOR_PATH_449 = "/intake-449.html"
STRIPE_149_PAYMENT_LINK = "plink_1UUtFNPwXi6zE7gEQlTrvvsU"
STRIPE_449_PAYMENT_LINK = "plink_1UUtFXPwXi6zE7gE3k18hI47"
STRIPE_UPGRADE_PAYMENT_LINK = "plink_1UUtFuPwXi6zE7gEzydOqNXl"
STRIPE_MONITORING_PAYMENT_LINK = "plink_1UVICVPwXi6zE7gEu9icxIad"
# Legacy monitoring link (the pre-change price; deactivated 2026-10-27
# when the price changed to $19.99, Caleb ruling): kept in the webhook
# match below so a
# straggler checkout on the old link still records correctly.
STRIPE_MONITORING_PAYMENT_LINK_LEGACY = "plink_1UUtG6PwXi6zE7gEmmN7Nzpf"
# Stripe checkout (payment link) URLs for the free-scan conversion
# box (Caleb ruling 2026-10-22). These are the same links the pricing
# section buttons use. Both are ACTIVE sandbox/test-mode links today;
# at Stripe live activation they swap to the live URLs, the same swap
# as the pricing buttons. Single config spot for the results
# surfaces: the results page reads them from the scan JSON
# (checkout_urls, built from these constants) and the results email
# uses them directly.
STRIPE_149_CHECKOUT_URL = "https://buy.stripe.com/5kQ14p9WhbAR4zd66e5AQ00"
STRIPE_449_CHECKOUT_URL = "https://buy.stripe.com/5kQ14p8Sd9sJe9NeCK5AQ01"
# Permanent Stripe customer-portal login link (Caleb retrieved it
# from the Stripe Dashboard 2026-10-27): a customer enters their
# email at this link to manage or cancel their monitoring
# subscription. Wired into the monitoring confirmation email as
# the manage/cancel route, replacing the original reply-to-manage
# line; the Oct 26 journey-test cancellation used a one-off portal
# session link because no permanent link existed yet.
STRIPE_CUSTOMER_PORTAL_LOGIN_LINK = "https://billing.stripe.com/p/login/5kQ14p9WhbAR4zd66e5AQ00"
_WEBHOOK_TOLERANCE_S = 300
_PROCESSED_SESSIONS = set()  # per-instance idempotency; Stripe also dedupes
_PAID_EMAILS = set()  # buyer emails (lowercased) from processed checkouts;
# per-instance, like _PROCESSED_SESSIONS — consulted by do_POST (D-1 fix)

# --- Durable paid-buyer store (D-1 durability upgrade, 2026-10-22) -------
# _PAID_EMAILS is only a per-instance cache: a cold instance has never
# seen the checkout, so without a durable record it would send a paid
# buyer the free-scan results (sales) email again. The durable record
# lives in the private Vercel Blob store "agent-readiness-paid-buyers"
# (BLOB_READ_WRITE_TOKEN is injected into the project env by the store
# connection): one tiny JSON blob per buyer, pathname keyed by the
# normalized email, value {"session": ..., "ts": ...}. Checkout writes
# it; do_POST consults it on a cache miss and warms the cache on a hit.
# EVERY store call is failure-isolated: any error (including "token not
# configured") falls back to the in-memory behavior and is logged — the
# store can never break a scan or a checkout.
_BLOB_API = "https://vercel.com/api/blob"
_PAID_PATH_PREFIX = "paid-buyers/v1/"


def _blob_token():
    return (os.environ.get("BLOB_READ_WRITE_TOKEN") or "").strip()


def _paid_pathname(email):
    return _PAID_PATH_PREFIX + email + ".json"


def _paid_store_write(email, session_id):
    """Persist the paid record for email (already lowercased)."""
    token = _blob_token()
    if not token:
        return
    body = json.dumps({"session": session_id or "",
                       "ts": datetime.now(timezone.utc).isoformat()})
    try:
        resp = requests.put(
            _BLOB_API + "/",
            params={"pathname": _paid_pathname(email)},
            data=body.encode("utf-8"),
            headers={"Authorization": f"Bearer {token}",
                     "x-api-version": "12",
                     "x-vercel-blob-access": "private",
                     "x-add-random-suffix": "0",
                     "x-allow-overwrite": "1",
                     "x-content-type": "application/json"},
            timeout=3)
        if resp.status_code != 200:
            print(f"paid-store: write for {email} returned "
                  f"HTTP {resp.status_code}; memory-only record kept")
    except Exception as exc:  # never break checkout processing
        print(f"paid-store: write for {email} failed ({exc!r}); "
              "memory-only record kept")


def _paid_store_has(email):
    """True only on a confirmed durable record for email."""
    token = _blob_token()
    if not token:
        return False
    try:
        resp = requests.get(
            _BLOB_API + "/",
            params={"url": _paid_pathname(email)},
            headers={"Authorization": f"Bearer {token}",
                     "x-api-version": "12"},
            timeout=3)
    except Exception as exc:  # store trouble must never break a scan
        print(f"paid-store: read for {email} failed ({exc!r}); "
              "falling back to memory-only suppression")
        return False
    if resp.status_code == 200:
        return True
    if resp.status_code != 404:
        print(f"paid-store: read for {email} returned "
              f"HTTP {resp.status_code}; treating as not-paid")
    return False


# Intake prefill records (2026-10-22): two more failure-isolated
# stores in the same pattern, so the post-payment intake door can
# re-supply what the journey already collected. A scan with lead
# fields writes scan-leads/v1/<email>.json {url, business}; the
# checkout webhook writes orders/v1/<session_id>.json {name, email,
# tier}. GET /api/intake-prefill joins them by the session id the
# door already carries. Same rule as the paid store: any failure is
# logged and the flow falls back to today's behavior.
_SCAN_LEAD_PREFIX = "scan-leads/v1/"
_ORDER_PREFIX = "orders/v1/"


def _blob_put_json(pathname, obj):
    """PUT one JSON object to the private Blob store. Never raises.
    Returns True only when the store accepted the write (HTTP 200)."""
    token = _blob_token()
    if not token:
        return False
    body = json.dumps(obj)
    try:
        resp = requests.put(
            _BLOB_API + "/",
            params={"pathname": pathname},
            data=body.encode("utf-8"),
            headers={"Authorization": f"Bearer {token}",
                     "x-api-version": "12",
                     "x-vercel-blob-access": "private",
                     "x-add-random-suffix": "0",
                     "x-allow-overwrite": "1",
                     "x-content-type": "application/json"},
            timeout=3)
        if resp.status_code != 200:
            print(f"blob-store: write of {pathname} returned "
                  f"HTTP {resp.status_code}; record skipped")
            return False
    except Exception as exc:  # never break the caller's flow
        print(f"blob-store: write of {pathname} failed ({exc!r}); "
              "record skipped")
        return False
    return True


def _blob_get_json(pathname):
    """GET and parse one JSON object from the private Blob store.
    Returns None on any miss or error. Never raises."""
    token = _blob_token()
    if not token:
        return None
    try:
        resp = requests.get(
            _BLOB_API + "/",
            params={"url": pathname},
            headers={"Authorization": f"Bearer {token}",
                     "x-api-version": "12"},
            timeout=3)
    except Exception as exc:  # store trouble must never break a page
        print(f"blob-store: read of {pathname} failed ({exc!r}); "
              "treating as missing")
        return None
    if resp.status_code != 200:
        if resp.status_code != 404:
            print(f"blob-store: read of {pathname} returned "
                  f"HTTP {resp.status_code}; treating as missing")
        return None
    try:
        obj = resp.json()
    except ValueError:
        print(f"blob-store: read of {pathname} was not JSON; "
              "treating as missing")
        return None
    return obj if isinstance(obj, dict) else None


def _scan_lead_write(email, url, business):
    _blob_put_json(_SCAN_LEAD_PREFIX + email + ".json",
                   {"url": url or "", "business": business or "",
                    "ts": datetime.now(timezone.utc).isoformat()})


def _order_write(session_id, name, email, tier, arhq_number=None):
    record = {"name": name or "", "email": email or "",
              "tier": str(tier),
              "ts": datetime.now(timezone.utc).isoformat()}
    if arhq_number:
        record["arhq_number"] = arhq_number
    _blob_put_json(_ORDER_PREFIX + session_id + ".json", record)


# --- One-click unsubscribe (2026-10-28) --------------------------------
# Every customer-facing email this function sends carries the same
# footer: a one-click Unsubscribe link, the reply option, and the
# business postal address (footer mock-up approved by Caleb
# 2026-10-28). The link is per-recipient: /api/unsubscribe?e=<email>
# &t=<token>, the token an HMAC of the normalized email. Following
# it records the opt-out in the same private Blob store as every
# other durable record here, under unsubscribed/v1/<email>.json,
# reusing _blob_put_json / _blob_get_json. Recording is the
# mechanism: any future campaign send must check _is_unsubscribed
# before mailing. The per-request sends in this file (a scan result
# or packet the visitor just asked for, an order receipt) are the
# request itself and are not gated on the store.
#
# Token secret: UNSUBSCRIBE_SECRET when configured, else the
# Stripe webhook secret (already provisioned wherever the webhook
# processes payments), domain-separated by the "unsubscribe:"
# message prefix so a token can never be mistaken for a Stripe
# signature input. With NO secret configured the footer renders
# WITHOUT the one-click line (reply + address only) rather than
# printing a link the endpoint would reject, and the endpoint
# fails closed.
BUSINESS_POSTAL_ADDRESS = (
    "Agent Readiness HQ, 1500 N Grant St, Suite #12205, "
    "Denver, CO 80203")
_UNSUB_PREFIX = "unsubscribed/v1/"


def _unsubscribe_secret():
    return (os.environ.get("UNSUBSCRIBE_SECRET")
            or os.environ.get("STRIPE_WEBHOOK_SECRET") or "").strip()


def _unsubscribe_token(email):
    """HMAC token binding an unsubscribe link to one email address.
    Empty string when no secret is configured (links are then not
    minted at all; see _footer_text_lines)."""
    secret = _unsubscribe_secret()
    if not secret:
        return ""
    mac = hmac.new(secret.encode("utf-8"),
                   ("unsubscribe:" + email).encode("utf-8"),
                   hashlib.sha256)
    return mac.hexdigest()[:32]


def _unsubscribe_url(email):
    return (SITE_BASE + "/api/unsubscribe?" + urlencode(
        {"e": email, "t": _unsubscribe_token(email)}))


def _unsubscribe_record(email):
    """Persist one opt-out. True only when the store accepted it."""
    return _blob_put_json(
        _UNSUB_PREFIX + email + ".json",
        {"email": email,
         "ts": datetime.now(timezone.utc).isoformat(),
         "source": "unsubscribe-link"})


def _is_unsubscribed(email):
    """True only on a confirmed durable opt-out record. Any store
    trouble reads as not-unsubscribed (fail open, the rule for
    every store in this file); the write is the step the endpoint
    confirms to the visitor."""
    if not email:
        return False
    return _blob_get_json(_UNSUB_PREFIX + email + ".json") is not None


def _footer_text_lines(email):
    """The standard footer, plain-text part: the one-click line
    (present only when a token can be minted; the link itself
    rides on its own line because plain text has no anchors), the
    reply option, and the postal address."""
    lines = []
    if _unsubscribe_token(email):
        lines += [
            "Don't want emails from us? Unsubscribe with one click, "
            "and you are off the list:",
            _unsubscribe_url(email),
        ]
    lines += [
        "Or just reply to this email with \"unsubscribe\" and we "
        "will take you off our list.",
        BUSINESS_POSTAL_ADDRESS,
    ]
    return lines


def _footer_html(email):
    """The standard footer, HTML part: the ruled-off centered block
    from the 2026-10-28 approved mock-up, with the word Unsubscribe
    carrying the per-recipient link as a plain hyperlink (Caleb
    correction 2026-10-28: a simple underlined link, not a styled
    element; the raw token URL never prints in the HTML part).
    Without a mintable token the click line is omitted, exactly as
    in the text part."""
    click = ""
    if _unsubscribe_token(email):
        click = (
            '<p style="font-size:14.5px; line-height:1.55; '
            'color:#6e6e73; margin:0;">Don&#8217;t want emails from '
            'us? <a href="%s" style="color:#c21847; '
            'text-decoration:underline;">Unsubscribe</a> with one '
            'click, and you are off the list.</p>'
            % _esc_html(_unsubscribe_url(email)))
    return (
        '<div style="border-top:1px solid #f0e6e8; margin-top:22px; '
        'padding-top:20px; text-align:center;">' + click +
        '<p style="font-size:13px; line-height:1.55; color:#8e8e93; '
        'margin-top:9px;">Or just reply to this email with '
        '&#8220;unsubscribe&#8221; and we will take you off our '
        'list.</p>'
        '<p style="font-size:13px; line-height:1.55; color:#8e8e93; '
        'margin-top:9px;">' + BUSINESS_POSTAL_ADDRESS + "</p></div>")


def _set_unsubscribe_headers(msg, email):
    """RFC 2369 List-Unsubscribe + RFC 8058 one-click POST headers.
    The send path is smtplib send_message over EmailMessage, which
    serializes every header set on the message, so no transport
    change is needed. Set only when a token can be minted."""
    if _unsubscribe_token(email):
        msg["List-Unsubscribe"] = "<%s>" % _unsubscribe_url(email)
        msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"


def _unsubscribe_page(heading, body_text):
    """The plain confirmation page behind /api/unsubscribe."""
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title></head>
<body style="margin:0; padding:0; background-color:#f7f2f0; font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif; color:#1d1d1f;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background-color:#f7f2f0;">
<tr><td align="center" style="padding:40px 12px;">
<table role="presentation" width="560" cellpadding="0" cellspacing="0" style="width:560px; max-width:560px; background-color:#ffffff; border:1px solid #f0dfe3; border-radius:16px;">
<tr><td style="padding:36px 40px 40px 40px;">
<span style="font-size:20px; font-weight:800; letter-spacing:-0.02em; color:#1d1d1f;">Agent Readiness <span style="color:#ff4d6d;">HQ</span></span>
<div style="border-bottom:2px solid #ff4d6d; margin:20px 0 26px 0; font-size:0; line-height:0;">&nbsp;</div>
<h1 style="font-size:24px; line-height:1.3; font-weight:800; color:#1d1d1f; margin:0;">%s</h1>
<p style="font-size:15.5px; line-height:1.65; color:#333336; margin-top:16px;">%s</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>""" % (_esc_html(heading), _esc_html(heading),
                     _esc_html(body_text))


# --- Order numbering (2026-10-22) --------------------------------------
# ARHQ order numbers used to be assigned by hand in the order tracker
# after payment, so the day-0 email (fired by this webhook at
# checkout) had no number to print and carried the raw Stripe session
# id as its order reference (ARHQ-2026-0004's confirmation did
# exactly that). Numbering now happens here, at purchase time: a
# sequence record in the same private Blob store holds the next
# integer, and each checkout claims its number BEFORE the order
# record is written, so the number rides on orders/v1/<session_id>
# (arhq_number) where the intake-prefill join and the production
# queue can find it. Format: ARHQ-<purchase year>-<sequence, zero-
# padded to 4>; the sequence never resets, so a January order takes
# the new year's prefix with the next integer in line. The seed is 5:
# 0001 (Ten Talents), 0002 (walkthrough), 0003 (upgrade) and 0004
# (Happy Whole Way) were assigned by hand in 20-order-tracker.md.
# Idempotency: Stripe retries a webhook, and a retry that reaches a
# fresh instance finds the number already on the session's order
# record and reuses it instead of burning a second number. Failure
# isolation, same rule as every store here: a claim is only handed
# out once the incremented sequence has been read back as durable;
# if that cannot be confirmed, the webhook falls back to sending the
# day-0 email with NO order reference rather than not sending it,
# and logs the failure. No customer email ever prints a session id
# as an order reference.
# 2026-10-27 fail-closed revision: on 2026-10-26 all three live
# journey-test checkouts were stamped ARHQ-2026-0005, colliding with
# the real 0005. Given this code, the only path to that outcome was
# a sequence read that came back missing or unreadable at claim
# time, and the claim then treated the unreadable sequence as a
# first claim and re-seeded at 5. The seed now applies ONLY to the
# store's first-ever claim, proven by a one-time marker record
# (order-sequence/v1/initialized.json); every other read failure,
# and any write whose read-back never confirms, fails closed to NO
# number. A burned number leaves a harmless gap in the sequence; a
# re-issued number corrupts the ledger.
_ORDER_SEQ_PATHNAME = "order-sequence/v1/next.json"
_ORDER_SEQ_MARKER = "order-sequence/v1/initialized.json"
_ORDER_SEQ_SEED = 5


def _blob_get_json_status(pathname):
    """Status-aware sibling of _blob_get_json, for order numbering.

    Returns (obj, "ok") for a parsed JSON object, (None, "missing")
    on a 404, and (None, "error") on anything else: no token,
    transport error, non-200 status, unparseable body. _blob_get_json
    deliberately folds all of those into None, which suits its other
    stores; numbering must tell "never existed" apart from "could
    not be read", so it uses this. Never raises.
    """
    token = _blob_token()
    if not token:
        return None, "error"
    try:
        resp = requests.get(
            _BLOB_API + "/",
            params={"url": pathname},
            headers={"Authorization": f"Bearer {token}",
                     "x-api-version": "12"},
            timeout=3)
    except Exception as exc:  # store trouble must never break checkout
        print(f"order-numbering: read of {pathname} failed ({exc!r})")
        return None, "error"
    if resp.status_code == 404:
        return None, "missing"
    if resp.status_code != 200:
        print(f"order-numbering: read of {pathname} returned "
              f"HTTP {resp.status_code}")
        return None, "error"
    try:
        obj = resp.json()
    except ValueError:
        print(f"order-numbering: read of {pathname} was not JSON")
        return None, "error"
    if not isinstance(obj, dict):
        return None, "error"
    return obj, "ok"


def _seq_readback_confirms(pathname, key, value):
    """Read pathname back until it shows key == value, retrying
    briefly: a just-written blob can read back stale for a moment."""
    for delay in (0.0, 0.5, 1.0, 2.0):
        if delay:
            time.sleep(delay)
        obj, status = _blob_get_json_status(pathname)
        if status == "ok" and obj.get(key) == value:
            return True
    return False


def _claim_arhq_number(session_id):
    """This order's ARHQ number, or None if numbering failed.

    Reuses the number stored on the session's existing order record
    when one is there; otherwise claims the next sequence value
    (persist the increment first, verify by read-back, then hand the
    number out). Fail-closed since 2026-10-27: a sequence read that
    fails, a sequence record that is missing after the store's first
    claim, or a write whose read-back never confirms all return None
    (the day-0 email goes out with no order reference) rather than
    re-seeding. Never raises.
    """
    existing = _blob_get_json(_ORDER_PREFIX + session_id + ".json")
    if existing and existing.get("arhq_number"):
        return str(existing["arhq_number"])
    seq_obj, seq_status = _blob_get_json_status(_ORDER_SEQ_PATHNAME)
    if seq_status == "error":
        # One retry after a short pause (2026-10-28 hardening): a
        # single transient read error otherwise costs an order its
        # number even when the store answers fine a moment later,
        # as happened to the 2026-10-28 test order. A persistent
        # error still fails closed just below, unchanged.
        time.sleep(1)
        seq_obj, seq_status = _blob_get_json_status(_ORDER_SEQ_PATHNAME)
    if seq_status == "error":
        print(f"order-numbering: sequence unreadable for session "
              f"{session_id}; day-0 email will carry no order "
              "reference")
        return None
    year = datetime.now(timezone.utc).year
    if seq_status == "missing":
        return _claim_seed_number(session_id, year)
    try:
        nxt = int(seq_obj.get("next"))
    except (TypeError, ValueError):
        nxt = None
    if nxt is None or nxt < _ORDER_SEQ_SEED:
        print(f"order-numbering: sequence record for session "
              f"{session_id} holds an unusable value; day-0 email "
              "will carry no order reference")
        return None
    # The one-time marker is what licenses the seed path in
    # _claim_seed_number; keep it alongside any live sequence record
    # (records claimed before 2026-10-27 predate it). If it cannot
    # be read or written, fail closed: without it, a later missing
    # read of the sequence could be mistaken for a first claim.
    _marker, marker_status = _blob_get_json_status(_ORDER_SEQ_MARKER)
    if marker_status == "error":
        print(f"order-numbering: marker unreadable for session "
              f"{session_id}; day-0 email will carry no order "
              "reference")
        return None
    if marker_status == "missing":
        if not _blob_put_json(
                _ORDER_SEQ_MARKER,
                {"initialized": True,
                 "ts": datetime.now(timezone.utc).isoformat()}):
            print(f"order-numbering: marker write for session "
                  f"{session_id} was not accepted; day-0 email will "
                  "carry no order reference")
            return None
    if not _blob_put_json(_ORDER_SEQ_PATHNAME,
                          {"next": nxt + 1,
                           "ts": datetime.now(timezone.utc).isoformat()}):
        print(f"order-numbering: sequence write for session "
              f"{session_id} was not accepted; day-0 email will "
              "carry no order reference")
        return None
    if not _seq_readback_confirms(_ORDER_SEQ_PATHNAME, "next", nxt + 1):
        print(f"order-numbering: read-back for session {session_id} "
              "never confirmed the increment; day-0 email will carry "
              "no order reference")
        return None
    return f"ARHQ-{year}-{nxt:04d}"


def _claim_seed_number(session_id, year):
    """The store's first-ever claim: the ONLY path that may hand out
    the seed. Reached when the sequence record reads as missing; the
    seed is issued only when the one-time marker also reads as
    missing (the sequence has never existed). A marker that is
    present or unreadable fails closed, because the sequence existed
    before and its absence now is a store problem, not a first
    claim. Writes the marker first, then the sequence at seed + 1,
    and hands the seed out only once both have read back."""
    _marker, marker_status = _blob_get_json_status(_ORDER_SEQ_MARKER)
    if marker_status != "missing":
        print(f"order-numbering: sequence missing but marker state "
              f"is {marker_status} for session {session_id}; day-0 "
              "email will carry no order reference")
        return None
    ts = datetime.now(timezone.utc).isoformat()
    if not _blob_put_json(_ORDER_SEQ_MARKER,
                          {"initialized": True, "ts": ts}):
        print(f"order-numbering: seed marker write for session "
              f"{session_id} was not accepted; day-0 email will "
              "carry no order reference")
        return None
    if not _blob_put_json(_ORDER_SEQ_PATHNAME,
                          {"next": _ORDER_SEQ_SEED + 1, "ts": ts}):
        print(f"order-numbering: seed sequence write for session "
              f"{session_id} was not accepted; day-0 email will "
              "carry no order reference")
        return None
    if not _seq_readback_confirms(_ORDER_SEQ_MARKER, "initialized", True):
        print(f"order-numbering: seed marker for session {session_id} "
              "never confirmed by read-back; day-0 email will carry "
              "no order reference")
        return None
    if not _seq_readback_confirms(_ORDER_SEQ_PATHNAME, "next",
                                  _ORDER_SEQ_SEED + 1):
        print(f"order-numbering: seed sequence for session "
              f"{session_id} never confirmed by read-back; day-0 "
              "email will carry no order reference")
        return None
    return f"ARHQ-{year}-{_ORDER_SEQ_SEED:04d}"


# --- Prior-audit safeguard for monitoring (2026-10-27) ----------------
# Monitoring maintains the AI Information Page an audit created, so
# it can only run for a business with a paid $149/$449 audit behind
# it. The monitoring payment link is public, though, and nothing in
# Stripe checks for a prior purchase: a stranger could subscribe and
# be owed a service that cannot start (found by Caleb reviewing the
# new pricing-page add-on section). When a monitoring checkout
# completes, the webhook therefore looks the buyer up in the order
# records (orders/v1/, the same store the numbering claim and the
# intake-prefill join read) and matches by email, the same key the
# operator uses to file the monitoring notice by hand. Tri-state:
#   "yes"   a paid audit order (tier 149, 449, or upgrade; an
#           upgrade record is itself proof of a $149 order) matches
#           the buyer's email. Both emails go out exactly as before.
#   "no"    the store read cleanly and no audit order matches. The
#           customer confirmation gains one sentence (activation
#           waits for the audit; this payment counts as the first
#           month) and the internal notice is flagged NO PRIOR
#           AUDIT so the operator contacts the customer.
#   "error" the lookup could not be completed. The customer still
#           gets the standard confirmation (fail open, the rule
#           everywhere in this file) and the internal notice is
#           flagged PRIOR-AUDIT CHECK FAILED for a manual check.
# The subscription record itself is never blocked by this lookup.
_AUDIT_TIERS = ("149", "449", "upgrade")


def _blob_list_pathnames(prefix):
    """List every pathname under prefix in the private Blob store,
    following cursors. Returns (pathnames, "ok") or (None, "error")
    on anything else: no token, transport error, non-200 status,
    unparseable body. Never raises."""
    token = _blob_token()
    if not token:
        return None, "error"
    pathnames = []
    cursor = None
    for _page in range(50):  # defensive bound; the store is small
        params = {"prefix": prefix, "limit": 1000}
        if cursor:
            params["cursor"] = cursor
        try:
            resp = requests.get(
                _BLOB_API + "/",
                params=params,
                headers={"Authorization": f"Bearer {token}",
                         "x-api-version": "12"},
                timeout=5)
        except Exception as exc:  # store trouble must never break checkout
            print(f"prior-audit: list of {prefix} failed ({exc!r})")
            return None, "error"
        if resp.status_code != 200:
            print(f"prior-audit: list of {prefix} returned "
                  f"HTTP {resp.status_code}")
            return None, "error"
        try:
            payload = resp.json()
        except ValueError:
            print(f"prior-audit: list of {prefix} was not JSON")
            return None, "error"
        blobs = payload.get("blobs") if isinstance(payload, dict) else None
        if not isinstance(blobs, list):
            print(f"prior-audit: list of {prefix} had no blob list")
            return None, "error"
        for blob in blobs:
            if isinstance(blob, dict) and blob.get("pathname"):
                pathnames.append(str(blob["pathname"]))
        cursor = payload.get("cursor")
        if not payload.get("hasMore") or not cursor:
            return pathnames, "ok"
    print(f"prior-audit: list of {prefix} never finished paging")
    return None, "error"


def _prior_audit_status(email, exclude_session_id=None):
    """Tri-state prior-audit lookup for a monitoring buyer: "yes"
    when a paid audit order record carries this email, "no" when the
    order store read cleanly with no match, "error" when the lookup
    could not be completed. email arrives lowercased from the
    webhook; record emails are compared case-insensitively anyway.
    The buyer's own just-written order record is skipped (its tier
    is "monitoring", so the tier filter alone would exclude it too).
    Never raises."""
    pathnames, status = _blob_list_pathnames(_ORDER_PREFIX)
    if status != "ok":
        return "error"
    own = (_ORDER_PREFIX + exclude_session_id + ".json"
           if exclude_session_id else None)
    for pathname in pathnames:
        if pathname == own or not pathname.endswith(".json"):
            continue
        record, rec_status = _blob_get_json_status(pathname)
        if rec_status == "error":
            return "error"
        if rec_status != "ok" or record is None:
            continue  # listed a moment ago, gone now: no evidence
        if str(record.get("tier") or "") not in _AUDIT_TIERS:
            continue
        if str(record.get("email") or "").strip().lower() == email:
            return "yes"
    return "no"


def _is_paid_buyer(email):
    """Suppression lookup: in-memory cache first, durable store second;
    a durable hit warms the cache for the rest of this instance's life."""
    if email in _PAID_EMAILS:
        return True
    if _paid_store_has(email):
        _PAID_EMAILS.add(email)
        return True
    return False


def _intake_door_link(name, email, session_id, door_path=INTAKE_DOOR_PATH):
    """Personalized link to the scan-first intake door. Carries exactly
    what the webhook knows (name, email, payment reference); the door
    collects the website, runs the scan, and pre-fills the intake form.
    """
    params = {"payment_ref": session_id or ""}
    if name:
        params["name"] = name
    if email:
        params["email"] = email
    return SITE_BASE + door_path + "?" + urlencode(params)


def _day0_p(inner_html):
    """One body paragraph in a day-0 HTML part, styled like the
    results email's body copy."""
    return ('<p style="font-size:15.5px; line-height:1.6; '
            'color:#333336; margin-top:14px;">%s</p>' % inner_html)


def _day0_step_html(lead, body):
    return _day0_p("<strong>%s</strong> %s"
                   % (_esc_html(lead), _esc_html(body)))


def _day0_intake_step_html(lead, body, door_link):
    """Step 1 of a day-0 email, HTML part: the lead line, then the
    personalized intake link rendered as the email's primary button
    (anchor text "Complete your intake form"; the raw URL, prefill
    params included, lives only in the href and is never displayed),
    then the explanatory paragraph."""
    return "".join([
        _day0_p("<strong>%s</strong> Use this link whenever you are "
                "ready:" % _esc_html(lead)),
        '<p style="margin-top:16px;"><a href="%s" '
        'style="display:inline-block; background-color:#ff4d6d; '
        'color:#ffffff; font-size:16px; font-weight:700; '
        'padding:13px 28px; border-radius:99px; '
        'text-decoration:none;">Complete your intake form</a></p>'
        % _esc_html(door_link),
        _day0_p(_esc_html(body)),
    ])


def _day0_tail_html(paras):
    """Closing paragraphs of a day-0 email (spam note, refunds,
    administrator note, platform note, questions line). The Refunds
    label is bolded, matching the template doc's markdown."""
    out = []
    for para in paras:
        if para.startswith("Refunds: "):
            out.append(_day0_p("<strong>Refunds:</strong>%s"
                               % _esc_html(para[len("Refunds:"):])))
        else:
            out.append(_day0_p(_esc_html(para)))
    return "".join(out)


def _day0_email_html(heading, first_name, payment_line, blocks_html,
                     show_next=True, footer_html=""):
    """HTML part for the day-0 purchase confirmations (Templates 7
    and 12), added 2026-10-21 so the personalized intake link renders
    as a hyperlink instead of a giant raw URL. Same shell as the
    results email (table layout, inline styles, warm rose palette):
    brand header, heading, greeting, payment line, the numbered next
    steps, the closing paragraphs, and the text part's sign-off.
    blocks_html is the steps + tail HTML built by the caller, so both
    parts carry identical wording.
    """
    next_html = (
        '<p style="font-size:15.5px; line-height:1.6; color:#333336; '
        'margin-top:18px;"><strong>Here is what happens next:</strong></p>'
        if show_next else "")
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(heading)s</title></head>
<body style="margin:0; padding:0; background-color:#f7f2f0; font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif; color:#1d1d1f;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background-color:#f7f2f0;">
<tr><td align="center" style="padding:28px 12px 36px 12px;">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="width:640px; max-width:640px; background-color:#ffffff; border:1px solid #f0dfe3; border-radius:16px;">
<tr><td style="padding:36px 44px 40px 44px;">
<span style="font-size:20px; font-weight:800; letter-spacing:-0.02em; color:#1d1d1f;">Agent Readiness <span style="color:#ff4d6d;">HQ</span></span>
<div style="border-bottom:2px solid #ff4d6d; margin:20px 0 26px 0; font-size:0; line-height:0;">&nbsp;</div>
<h1 style="font-size:27px; line-height:1.25; font-weight:800; letter-spacing:-0.01em; color:#1d1d1f; margin:0;">%(heading)s</h1>
<p style="font-size:16px; line-height:1.6; color:#333336; margin-top:16px;">Hi %(first)s,</p>
<p style="font-size:15.5px; line-height:1.6; color:#333336; margin-top:14px;">%(payment)s</p>
%(next)s%(blocks)s
<p style="font-size:15.5px; line-height:1.6; color:#333336; margin-top:24px;">Thanks,<br><br>Agent Readiness HQ<br>hello@agentreadinesshq.com</p>
%(footer)s</td></tr>
</table>
</td></tr>
</table>
</body></html>""" % {
        "heading": _esc_html(heading),
        "first": _esc_html(first_name),
        "payment": _esc_html(payment_line),
        "next": next_html,
        "blocks": blocks_html,
        "footer": footer_html,
    }


def compose_day0_email(first_name, email, order_ref, door_link):
    """Template 7 ($149 purchase confirmation), automated. Shortened
    2026-10-22 (journey simplification, spec section 2): the email is
    now a recovery receipt, not a journey explainer. It carries only
    the payment confirmation, ONE next action (the personalized
    intake-door button/link), a one-line note that report work begins
    after intake (delivery clock starts at completed intake), the
    one-line spam-folder note, the refunds paragraph (kept verbatim:
    it is the durable legal record), and the reply-for-help line. The
    numbered three-step journey explanation, the SEND TO ADMINISTRATOR
    block, and the platform note were removed; the journey explanation
    now lives on the post-payment thanks page only. The intake link
    still points at the scan-first door, which is also the order's
    secure resume link (payment_ref rides in its parameters).

    Multipart: the HTML part renders the personalized intake link as
    a "Complete your intake form" button; the text part keeps the
    raw URL on its own line under the action lead line. The wording
    lives in the shared lists below so both parts cannot drift apart.

    order_ref is the order's ARHQ number (assigned by the webhook,
    2026-10-22), or None when numbering failed; the payment line
    then carries no order reference at all. A Stripe session id is
    never printed here.
    """
    subject = "Payment confirmed. Now the intake form, then your report."
    ref = f" (order {order_ref})" if order_ref else ""
    payment_line = (
        f"Thank you. Your payment of $149 has been received{ref}.")
    action_lead = "Complete your intake form."
    action_body = (
        "It takes about 5 minutes, and most of it is already filled "
        "in for you.")
    tail = [
        "Your report is delivered within 5 business days after we receive the information we need from you. The clock starts when your completed intake arrives. If we’re waiting on required information, the delivery clock pauses until we receive it.",
        "Your report will come from this same email address. If it does not appear, please check your spam or junk folder, and mark our messages Not Junk so they reach your inbox.",
        "Refunds: If you cancel before we start work, you get a full refund. Once your customized report is delivered, the $149 fee is non-refundable.",
        "Questions in the meantime? Just reply to this email.",
    ]
    lines = [
        f"Hi {first_name},",
        "",
        payment_line,
        "",
        f"{action_lead} Use this link whenever you are ready:",
        door_link,
        action_body,
        "",
    ]
    for para in tail:
        lines += [para, ""]
    lines += [
        "Thanks,",
        "",
        "Agent Readiness HQ",
        "hello@agentreadinesshq.com",
        "",
    ] + _footer_text_lines(email)
    blocks_html = "".join(
        [_day0_intake_step_html(action_lead, action_body, door_link)]
        + [_day0_tail_html(tail)])
    msg = EmailMessage()
    msg["From"] = f"Agent Readiness HQ <{RESULTS_FROM}>"
    msg["To"] = email
    msg["Subject"] = subject
    _set_unsubscribe_headers(msg, email)
    msg.set_content("\n".join(lines))
    msg.add_alternative(
        _day0_email_html(subject, first_name, payment_line,
                         blocks_html, show_next=False,
                         footer_html=_footer_html(email)),
        subtype="html")
    return msg


def compose_order_notice(name, email, session_id, amount_paid, day0_sent,
                         arhq_number=None):
    """Internal order record to hello@, fields per 20-order-tracker.md.
    Business name and website are not known at payment time; the intake
    supplies them (the door runs the scan), so the row completes when
    the intake notification arrives. order_id stays the Stripe session
    id (the operator's join key); arhq_number is the customer-facing
    number the webhook assigned at purchase (2026-10-22).
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = [
        "A $149 payment was confirmed by Stripe (webhook). Day-0 confirmation email "
        + ("sent to the customer." if day0_sent else "FAILED to send; send Template 7 by hand."),
        "",
        f"order_id: {session_id}",
        f"arhq_number: {arhq_number or '(unassigned - numbering failed; see function logs)'}",
        f"order_date: {today}",
        f"customer_name: {name or ''}",
        "business_name: (pending intake)",
        "website: (pending intake)",
        f"email: {email or ''}",
        "product: 149",
        f"amount_paid: {amount_paid}",
        "payment_status: paid",
        "status: INTAKE_PENDING",
        "notes: Order recorded automatically by the Stripe webhook. "
        "Reminders at day 3 and day 14 after payment if intake is still missing.",
    ]
    msg = EmailMessage()
    msg["From"] = f"Agent Readiness HQ <{RESULTS_FROM}>"
    msg["To"] = RESULTS_FROM
    msg["Subject"] = f"New $149 order (webhook): {name or email or session_id}"
    msg.set_content("\n".join(lines))
    return msg


def compose_day0_email_449(first_name, email, order_ref, door_link):
    """Template 12 ($449 purchase confirmation), automated. Shortened
    2026-10-22 (journey simplification, spec section 5): the email is
    now a recovery receipt, not a journey explainer. It carries only
    the payment confirmation, ONE next action (the personalized
    intake-door button/link, intake-449 door), a one-line note that
    work on the report and proposed changes begins after intake plus
    the short section-10 clock sentence, the refunds paragraph (kept
    verbatim: it is the durable legal record), and the reply-for-help
    line. Removed: the numbered four-step journey explanation
    (authorization / access / implementation steps) and the long
    four-prerequisite clock paragraph; the journey explanation now
    lives on the post-payment thanks page only. The intake link is
    also the order's secure resume link (payment_ref rides in its
    parameters).

    Multipart: the HTML part renders the personalized intake link as
    a "Complete your intake form" button; the text part keeps the
    raw URL on its own line under the action lead line. The wording
    lives in the shared lists below so both parts cannot drift apart.

    order_ref is the order's ARHQ number (assigned by the webhook,
    2026-10-22), or None when numbering failed; the payment line
    then carries no order reference at all. A Stripe session id is
    never printed here.
    """
    subject = "Your $449 Done-for-You is confirmed"
    ref = f" (order {order_ref})" if order_ref else ""
    payment_line = (
        f"Thank you. Your payment of $449 has been received{ref}.")
    action_lead = "Complete your intake form."
    action_body = (
        "It takes about 5 minutes, and most of it is already filled "
        "in for you.")
    tail = [
        "We start on your report and proposed changes once your intake is complete. Implementation is completed within 10 business days after we have your signed authorization, required information, and the site access needed to perform the approved work. If we’re waiting on something from you, the delivery clock pauses until we receive it.",
        "Refunds: If you cancel before we begin work, you get a full refund. If you cancel after we start analysis but before implementation begins, we refund the portion of the work not performed. Once implementation begins, the fee is non-refundable.",
        "Questions in the meantime? Just reply to this email.",
    ]
    lines = [
        f"Hi {first_name},",
        "",
        payment_line,
        "",
        f"{action_lead} Use this link whenever you are ready:",
        door_link,
        action_body,
        "",
    ]
    for para in tail:
        lines += [para, ""]
    lines += [
        "Thanks,",
        "",
        "Agent Readiness HQ",
        "hello@agentreadinesshq.com",
        "",
    ] + _footer_text_lines(email)
    blocks_html = "".join(
        [_day0_intake_step_html(action_lead, action_body, door_link)]
        + [_day0_tail_html(tail)])
    msg = EmailMessage()
    msg["From"] = f"Agent Readiness HQ <{RESULTS_FROM}>"
    msg["To"] = email
    msg["Subject"] = subject
    _set_unsubscribe_headers(msg, email)
    msg.set_content("\n".join(lines))
    msg.add_alternative(
        _day0_email_html(subject, first_name, payment_line,
                         blocks_html, show_next=False,
                         footer_html=_footer_html(email)),
        subtype="html")
    return msg


def compose_order_notice_449(name, email, session_id, amount_paid, day0_sent,
                             arhq_number=None):
    """Internal $449 order record to hello@, fields per
    20-order-tracker.md. Business name and website are not known at
    payment time; the intake supplies them (the door runs the scan),
    so the row completes when the intake notification arrives.
    order_id stays the Stripe session id (the operator's join key);
    arhq_number is the customer-facing number the webhook assigned
    at purchase (2026-10-22).
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = [
        "A $449 payment was confirmed by Stripe (webhook). Day-0 confirmation email "
        + ("sent to the customer." if day0_sent else "FAILED to send; send Template 12 by hand."),
        "",
        f"order_id: {session_id}",
        f"arhq_number: {arhq_number or '(unassigned - numbering failed; see function logs)'}",
        f"order_date: {today}",
        f"customer_name: {name or ''}",
        "business_name: (pending intake)",
        "website: (pending intake)",
        f"email: {email or ''}",
        "product: 449",
        f"amount_paid: {amount_paid}",
        "payment_status: paid",
        "status: INTAKE_PENDING",
        "notes: Order recorded automatically by the Stripe webhook. "
        "Reminders at day 3 and day 14 after payment if intake is still missing. "
        "The 10 business day fulfillment clock starts only when completed intake, "
        "signed authorization, written approval of the change list, and confirmed "
        "working access are all in hand.",
    ]
    msg = EmailMessage()
    msg["From"] = f"Agent Readiness HQ <{RESULTS_FROM}>"
    msg["To"] = RESULTS_FROM
    msg["Subject"] = f"New $449 order (webhook): {name or email or session_id}"
    msg.set_content("\n".join(lines))
    return msg


def compose_upgrade_email(first_name, email, order_ref):
    """Template 20 (post-upgrade confirmation, $149 to $449),
    automated. Rewritten 2026-10-22 (journey simplification, spec
    section 14): a SHORT RECEIPT ONLY. The old version carried a
    partially prefilled Form 3 authorization link plus a four-step
    authorization/access/implementation explainer, and the operator
    then sent Template 19 with a second, fully prefilled Form 3 link:
    two authorization asks for one signature. That double
    authorization is eliminated. This receipt carries no form link
    and no step list: payment confirmed, the $149 credit and
    intake-facts carry-over, the line that the approval and access
    step comes next, and the reply-for-help line. The single proper
    approval/access interaction follows separately: once the $449
    report and change list are reviewed, the operator sends the
    merged Template 18 delivery email containing the proposed
    changes and the combined "Approve changes & set up access" form
    link (see compose_order_notice_upgrade). Implemented per spec
    section 14; Workstream B's documentation of the new flow in
    pre-launch-package/09 and /10 was not yet present when this was
    written (files still dated 2026-10-21).

    order_ref is the upgrade order's ARHQ number (assigned by the
    webhook, 2026-10-22), or None when numbering failed; the payment
    line then carries no order reference at all. A Stripe session id
    is never printed here.
    """
    subject = "Your Done For You upgrade is confirmed"
    ref = f" (order {order_ref})" if order_ref else ""
    payment_line = (
        f"Thank you. Your upgrade payment of $300 has been received"
        f"{ref}. Your original $149 is credited in "
        f"full, and your audit and intake facts carry over.")
    paras = [
        "We'll send your approval and access step next.",
        "That email will include the proposed changes from your report, with one form to approve them and set up temporary website access.",
        "Questions in the meantime? Just reply to this email.",
    ]
    lines = [
        f"Hi {first_name},",
        "",
        payment_line,
        "",
    ]
    for para in paras:
        lines += [para, ""]
    lines += [
        "Thanks,",
        "",
        "Agent Readiness HQ",
        "hello@agentreadinesshq.com",
        "",
    ] + _footer_text_lines(email)
    blocks_html = _day0_tail_html(paras)
    msg = EmailMessage()
    msg["From"] = f"Agent Readiness HQ <{RESULTS_FROM}>"
    msg["To"] = email
    msg["Subject"] = subject
    _set_unsubscribe_headers(msg, email)
    msg.set_content("\n".join(lines))
    msg.add_alternative(
        _day0_email_html(subject, first_name, payment_line,
                         blocks_html, show_next=False,
                         footer_html=_footer_html(email)),
        subtype="html")
    return msg


def compose_monitoring_email(first_name, email, order_ref,
                             prior_audit="yes"):
    """Monitoring subscription confirmation (added 2026-10-26):
    the monitoring payment link previously matched NO webhook
    branch, so subscribers received no confirmation email at all
    (found in Caleb's live journey test). Short receipt in the
    Template 20 pattern: payment confirmed, what the monthly
    re-scan covers, the approval-before-any-change rule, and the
    Stripe customer-portal manage/cancel link (the permanent
    portal login link, wired in 2026-10-27, replacing the
    original reply-to-manage route). order_ref is the
    subscription order's ARHQ number, or None when numbering
    failed. prior_audit is the safeguard lookup (2026-10-27,
    _prior_audit_status): only the definitive "no" changes this
    email, adding one sentence after the payment line (activation
    waits for the audit; this payment counts as the first month).
    "yes" and "error" both render exactly the pre-safeguard email.
    """
    subject = "Your AI Page Monitoring is confirmed"
    ref = f" (order {order_ref})" if order_ref else ""
    payment_line = (
        f"Thank you. Your monitoring payment of $19.99 has been "
        f"received{ref}. Your AI Page Monitoring is now active at "
        f"$19.99/month.")
    no_audit_note = (
        "One note: monitoring runs on the AI Information Page "
        "created by your audit, so yours will activate as soon as "
        "your audit is complete, and this payment counts as your "
        "first month.")
    paras = [
        "Each month, we re-scan your AI Information Page to confirm it is still live, readable, and accurate.",
        "If a scan suggests an update, we email you the proposed change first. Nothing is applied without your approval, and we never keep standing access to your site.",
        "To change your payment method or cancel, use your subscription portal: "
        + STRIPE_CUSTOMER_PORTAL_LOGIN_LINK,
    ]
    lines = [
        f"Hi {first_name},",
        "",
        payment_line,
        "",
    ]
    if prior_audit == "no":
        lines += [no_audit_note, ""]
    for para in paras:
        lines += [para, ""]
    lines += [
        "Thanks,",
        "",
        "Agent Readiness HQ",
        "hello@agentreadinesshq.com",
        "",
    ] + _footer_text_lines(email)
    blocks_html = (
        (_day0_p(_esc_html(no_audit_note))
         if prior_audit == "no" else "")
        + _day0_tail_html(paras[:2])
        + _day0_p("To change your payment method or cancel, use your "
                  "subscription portal:")
        + _email_button_html(STRIPE_CUSTOMER_PORTAL_LOGIN_LINK,
                             "Manage or cancel your subscription"))
    msg = EmailMessage()
    msg["From"] = f"Agent Readiness HQ <{RESULTS_FROM}>"
    msg["To"] = email
    msg["Subject"] = subject
    _set_unsubscribe_headers(msg, email)
    msg.set_content("\n".join(lines))
    msg.add_alternative(
        _day0_email_html(subject, first_name, payment_line,
                         blocks_html, show_next=False,
                         footer_html=_footer_html(email)),
        subtype="html")
    return msg


def compose_order_notice_upgrade(name, email, session_id, amount_paid,
                                 day0_sent, arhq_number=None):
    """Internal upgrade order record to hello@, fields per
    20-order-tracker.md. Rule 4 of the tracker: an upgrade is filed
    as its own row (product 449, amount_paid 300.00) with a note
    linking back to the original $149 order_id. This webhook is
    stateless, so the match to the original order is made by the
    operator from this notice, by customer email (and name); the
    notice carries everything needed to make that match.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = [
        "A $300 upgrade payment ($149 to $449) was confirmed by Stripe (webhook). Short Template 20 receipt "
        + ("sent to the customer." if day0_sent else "FAILED to send; send the Template 20 receipt by hand."),
        "",
        f"order_id: {session_id}",
        f"arhq_number: {arhq_number or '(unassigned - numbering failed; see function logs)'}",
        f"order_date: {today}",
        f"customer_name: {name or ''}",
        "business_name: (from the original $149 order; match by email)",
        "website: (from the original $149 order; match by email)",
        f"email: {email or ''}",
        "product: 449",
        f"amount_paid: {amount_paid}",
        "payment_status: paid",
        "status: NEW",
        "notes: UPGRADE of the customer's $149 order. File as its own tracker row "
        "(product 449, amount_paid 300.00) with a note linking back to the original "
        "order_id, matched by customer email. Intake facts carry over; no new intake; "
        "confirm the intake facts are still current if needed. "
        "The customer received a short receipt only: no authorization link, no step "
        "list. Next step: once the $449 report and change list are reviewed (Caleb "
        "review gate), send the merged Template 18 delivery email with the combined "
        "'Approve changes & set up access' form link, so the customer gets ONE "
        "approval/access interaction containing the actual change list. The "
        "10-business-day implementation period begins once we have the approved "
        "changes and working website access.",]
    msg = EmailMessage()
    msg["From"] = f"Agent Readiness HQ <{RESULTS_FROM}>"
    msg["To"] = RESULTS_FROM
    msg["Subject"] = f"New upgrade order (webhook): {name or email or session_id}"
    msg.set_content("\n".join(lines))
    return msg


def compose_order_notice_monitoring(name, email, session_id,
                                    amount_paid, day0_sent,
                                    arhq_number=None,
                                    subscription_id=None,
                                    prior_audit="yes"):
    """Internal monitoring-subscription record to hello@, fields
    per 20-order-tracker.md. Filed as its own tracker row
    (product: monitoring). Business and website are matched by
    the operator from the customer's earlier $149/$449 order by
    email, as with upgrades. prior_audit is the safeguard lookup
    (2026-10-27, _prior_audit_status): the definitive "no" flags
    this notice NO PRIOR AUDIT in the subject and in a first body
    line (monitoring cannot start; contact the customer), and an
    "error" flags it PRIOR-AUDIT CHECK FAILED for a manual check.
    "yes" renders exactly the pre-safeguard notice.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    flag_line = None
    if prior_audit == "no":
        flag_line = (
            "NO PRIOR AUDIT: no paid $149/$449 audit order is on "
            "record for this email, so monitoring cannot start "
            "(there is no AI Information Page to monitor). Contact "
            "the customer: hold this payment as their first month "
            "once an audit is completed, or refund it on request.")
    elif prior_audit == "error":
        flag_line = (
            "PRIOR-AUDIT CHECK FAILED: the order store could not "
            "be read, so a prior audit could neither be confirmed "
            "nor ruled out. Check for the customer's earlier "
            "$149/$449 order by hand before starting monitoring.")
    lines = [
        "A $19.99/month AI Page Monitoring subscription was confirmed by Stripe (webhook). Confirmation email "
        + ("sent to the customer." if day0_sent else "FAILED to send; send the monitoring confirmation by hand."),
        "",
        f"order_id: {session_id}",
        f"arhq_number: {arhq_number or '(unassigned - numbering failed; see function logs)'}",
        f"order_date: {today}",
        f"customer_name: {name or ''}",
        "business_name: (from the customer's earlier order; match by email)",
        "website: (from the customer's earlier order; match by email)",
        f"email: {email or ''}",
        "product: monitoring",
        f"amount_paid: {amount_paid}",
        "payment_status: paid",
        f"subscription_id: {subscription_id or ''}",
        "status: ACTIVE",
        "notes: Monthly re-scan of the customer's AI Information Page only. "
        "Proposed updates are emailed to the customer for approval before "
        "anything is applied; no standing site access is kept. Cancellation "
        "arrives by customer reply or the Stripe customer portal and is "
        "actioned by the operator.",]
    if flag_line is not None:
        lines = [flag_line, ""] + lines
    subject = (f"New monitoring subscription (webhook): "
               f"{name or email or session_id}")
    if prior_audit == "no":
        subject += " — NO PRIOR AUDIT"
    elif prior_audit == "error":
        subject += " — PRIOR-AUDIT CHECK FAILED"
    msg = EmailMessage()
    msg["From"] = f"Agent Readiness HQ <{RESULTS_FROM}>"
    msg["To"] = RESULTS_FROM
    msg["Subject"] = subject
    msg.set_content("\n".join(lines))
    return msg


def _stripe_signature_ok(payload, sig_header, secret):
    """Verify a Stripe-Signature header: HMAC-SHA256 keyed with the
    endpoint secret over "<t>.<raw payload>", with timestamp tolerance.
    """
    if not sig_header or not secret:
        return False
    try:
        fields = {}
        signatures = []
        for part in sig_header.split(","):
            key, _, value = part.strip().partition("=")
            if key == "t":
                fields["t"] = value
            elif key == "v1":
                signatures.append(value)
        timestamp = int(fields.get("t") or 0)
    except (ValueError, AttributeError):
        return False
    if not timestamp or not signatures:
        return False
    if abs(time.time() - timestamp) > _WEBHOOK_TOLERANCE_S:
        return False
    signed = str(timestamp).encode("utf-8") + b"." + payload
    expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, sig) for sig in signatures)


def process_checkout_completed(session):
    """Handle one checkout.session.completed session object: send the
    day-0 email and record the order. Returns a summary dict. Never
    raises; send failures are reported in the summary, not hidden.
    """
    session_id = str(session.get("id") or "")
    if session.get("payment_status") not in ("paid", None):
        print(f"stripe webhook: session {session_id} payment_status="
              f"{session.get('payment_status')}; not processed")
        return {"processed": False, "reason": "not paid"}
    link = session.get("payment_link")
    if link == STRIPE_149_PAYMENT_LINK:
        tier = 149
    elif link == STRIPE_449_PAYMENT_LINK:
        tier = 449
    elif link == STRIPE_UPGRADE_PAYMENT_LINK:
        tier = "upgrade"
    elif link in (STRIPE_MONITORING_PAYMENT_LINK,
                      STRIPE_MONITORING_PAYMENT_LINK_LEGACY):
        tier = "monitoring"
    else:
        print(f"stripe webhook: session {session_id} is for payment link "
              f"{link}, not a known product link; recorded only")
        return {"processed": False, "reason": "not a known payment link"}
    if session_id in _PROCESSED_SESSIONS:
        print(f"stripe webhook: duplicate delivery for {session_id}; skipped")
        return {"processed": False, "reason": "duplicate"}
    _PROCESSED_SESSIONS.add(session_id)

    details = session.get("customer_details") or {}
    email = str(details.get("email") or session.get("customer_email") or "").strip()
    name = str(details.get("name") or "").strip()
    arhq_number = None
    if email and _EMAIL_RE.match(email):
        # Remember the buyer so a later public re-scan does not send
        # them the free-scan results (sales) email again (defect D-1).
        # Lowercased to match _clean_lead's normalization scan-side.
        _PAID_EMAILS.add(email.lower())
        # Durable copy in the Blob paid-buyer store, so suppression
        # survives cold instances and restarts (D-1 durability).
        _paid_store_write(email.lower(), session_id)
        # Assign the order's ARHQ number at purchase time
        # (2026-10-22), so the day-0 email can print it and the
        # order record below carries it. Failure-isolated: None
        # means the emails go out with no order reference.
        arhq_number = _claim_arhq_number(session_id)
        # Intake prefill record, keyed by the session id the intake
        # door carries as payment_ref (intake prefill fix, 2026-10-22).
        _order_write(session_id, name, email.lower(), tier, arhq_number)
    first_name = name.split()[0] if name else "there"
    default_cents = {149: 14900, 449: 44900, "upgrade": 30000, "monitoring": 1999}[tier]
    try:
        amount_paid = f"{(session.get('amount_total') or default_cents) / 100:.2f}"
    except (TypeError, ValueError):
        amount_paid = {149: "149.00", 449: "449.00",
                       "upgrade": "300.00", "monitoring": "19.99"}[tier]
    if tier == 149:
        door_link = _intake_door_link(name, email, session_id)
        day0_factory = lambda: compose_day0_email(  # noqa: E731
            first_name, email, arhq_number, door_link)
        notice_factory = lambda: compose_order_notice(  # noqa: E731
            name, email, session_id, amount_paid, day0_sent, arhq_number)
    elif tier == 449:
        door_link = _intake_door_link(
            name, email, session_id, INTAKE_DOOR_PATH_449)
        day0_factory = lambda: compose_day0_email_449(  # noqa: E731
            first_name, email, arhq_number, door_link)
        notice_factory = lambda: compose_order_notice_449(  # noqa: E731
            name, email, session_id, amount_paid, day0_sent, arhq_number)
    elif tier == "upgrade":  # short receipt only; approval+access
        # follows in the merged Template 18 delivery (spec 14)
        day0_factory = lambda: compose_upgrade_email(  # noqa: E731
            first_name, email, arhq_number)
        notice_factory = lambda: compose_order_notice_upgrade(  # noqa: E731
            name, email, session_id, amount_paid, day0_sent, arhq_number)
    else:  # monitoring: confirmation receipt + internal notice
        sub_id = str(session.get("subscription") or "")
        # Prior-audit safeguard (2026-10-27): monitoring maintains
        # an AI Information Page, which only an audit creates, so
        # look the buyer up in the order records before composing
        # either email and thread the tri-state result into both
        # (see _prior_audit_status). The subscription is recorded
        # either way; only the emails change.
        prior_audit = _prior_audit_status(email.lower(), session_id)
        day0_factory = lambda: compose_monitoring_email(  # noqa: E731
            first_name, email, arhq_number, prior_audit)
        notice_factory = lambda: compose_order_notice_monitoring(  # noqa: E731
            name, email, session_id, amount_paid, day0_sent,
            arhq_number, sub_id, prior_audit)

    day0_sent = False
    if email and _EMAIL_RE.match(email):
        day0_sent = send_business_email(day0_factory, "day-0 email")
    else:
        print(f"stripe webhook: no usable customer email on {session_id}; "
              "day-0 email not sent")
    notice_sent = send_business_email(notice_factory, "order notice")

    record = {
        "order_id": session_id,
        "arhq_number": arhq_number,
        "order_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "customer_name": name,
        "email": email,
        "product": 449 if tier == "upgrade" else tier,
        "tier": tier,
        "amount_paid": amount_paid,
        "payment_status": "paid",
        "status": "NEW" if tier in ("upgrade", "monitoring") else "INTAKE_PENDING",
        "day0_email_sent": day0_sent,
        "order_notice_sent": notice_sent,
    }
    print("ORDER " + json.dumps(record))
    return {"processed": True, **record}


def _clean_lead(data):
    """Validate the optional lead fields on an audit request. Returns
    (first_name, email) or (None, None) when absent/invalid."""
    if not isinstance(data, dict):
        return None, None
    name = str(data.get("first_name") or "")
    name = "".join(ch for ch in name if ch.isprintable()).strip()[:60]
    email = str(data.get("email") or "").strip().lower()[:254]
    if not name or not _EMAIL_RE.match(email):
        return None, None
    return name, email


# ------------------------------------------------------------------ handler ---
class handler(BaseHTTPRequestHandler):
    server_version = "AgentReadinessAudit/1.0"

    def _send_html(self, code, html):
        body = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _handle_unsubscribe(self):
        """GET or POST /api/unsubscribe?e=<email>&t=<token>: the
        one-click opt-out behind every customer email's footer.
        The HMAC token is the only credential, so a link works
        only for the address it was minted for. A valid request
        records the opt-out in the Blob store and answers with a
        plain confirmation page; an invalid one changes nothing
        and says so, with the reply route as the fallback. Mail
        clients performing an RFC 8058 one-click POST land here
        too and get the same handling."""
        qs = parse_qs(urlparse(self.path).query)
        email = (qs.get("e") or [""])[0].strip().lower()[:254]
        token = (qs.get("t") or [""])[0].strip()
        ok = (bool(email) and bool(_EMAIL_RE.match(email))
              and bool(token)
              and hmac.compare_digest(token,
                                      _unsubscribe_token(email)))
        if not ok:
            self._send_html(400, _unsubscribe_page(
                "That link did not check out",
                "The unsubscribe link was not valid for this "
                "address, so nothing was changed. To stop these "
                "emails, just reply to any of them with "
                "\"unsubscribe\" and we will take you off our list."))
            return
        if not _unsubscribe_record(email):
            self._send_html(503, _unsubscribe_page(
                "We could not record that just now",
                "Something on our side kept the opt-out from being "
                "saved. Please reply to any of our emails with "
                "\"unsubscribe\" and we will take you off our list "
                "by hand."))
            return
        print(f"unsubscribe: recorded opt-out for {email}")
        self._send_html(200, _unsubscribe_page(
            "You are unsubscribed",
            "Your opt-out is recorded, and you will not receive "
            "marketing emails from Agent Readiness HQ at this "
            "address. Receipts and anything you specifically "
            "request from us can still be emailed to you. This "
            "does not cancel a paid subscription; the portal link "
            "in your confirmation email manages that."))

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


    def _handle_packet(self):
        """POST /api/packet {email}: email the information packet PDF.

        Oct 24 ruling (Option A): the packet is a public Information
        page; the capture form's offer is the packet as a PDF, emailed
        to the visitor. Sends the PDF from the business inbox and a
        lead notice to the same inbox (the lead record). Reuses the
        results-email SMTP transport and credential.
        """
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        if length > 4096:
            self._send(413, {"error": "request body too large"})
            return
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, ValueError):
            self._send(400, {"error": "invalid JSON body"})
            return
        if not rate_ok(self._client_ip()):
            self._send(429, {"error": "rate limit exceeded. Try again later."})
            return
        email = (data.get("email") or "").strip() if isinstance(data, dict) else ""
        if len(email) > 254 or not _EMAIL_RE.match(email):
            self._send(400, {"error": "a valid email address is required"})
            return
        password = _smtp_password()
        if not password:
            self._send(503, {"error": "packet email is unavailable right now"})
            return
        pdf = _packet_pdf_bytes()
        if pdf is None:
            self._send(503, {"error": "packet email is unavailable right now"})
            return
        if not _deliver_with_fallback(
                lambda: _packet_message(email, pdf), password, "packet email"):
            self._send(502, {"error": "could not send the packet email"})
            return
        _deliver_with_fallback(
            lambda: _packet_lead_message(email), password,
            "packet lead notice")
        self._send(200, {"ok": True})

    def _handle_subscribe(self):
        """POST /api/subscribe — forwards the signup email to Caleb's inbox
        via FormSubmit (no account, no API key). First-ever submission
        triggers a FormSubmit activation email he must click once."""
        import re as _re
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 4096:
            self._send(400, {"error": "bad request"})
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
        except Exception:
            self._send(400, {"error": "invalid JSON"})
            return
        email = (body.get("email") or "").strip().lower()[:254]
        source = str(body.get("source") or "site")[:64]
        if not _re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            self._send(400, {"error": "invalid email"})
            return
        if not rate_ok("sub:" + self._client_ip()):
            self._send(429, {"error": "too many signups — try again later"})
            return
        try:
            resp = requests.post(
                "https://formsubmit.co/ajax/c171c3e0d3fb9d3525cb0945982c5d2b",
                headers={"Content-Type": "application/json",
                         "Accept": "application/json",
                         # FormSubmit requires a browser-like referer; the
                         # function posts on behalf of agentreadinesshq.com.
                         "Referer": "https://agentreadinesshq.com/",
                         "Origin": "https://agentreadinesshq.com"},
                json={"email": email,
                      "_subject": "New Agent Readiness HQ signup",
                      "message": f"New signup from {source}: {email}",
                      "_template": "table",
                      "_autoresponse": (
                          "Thanks for your interest in Agent Readiness HQ! "
                          "We'll be in touch soon with your fix-it report and "
                          "practical tips for making your business easy for AI "
                          "agents to find, understand, and buy from. "
                          "— Agent Readiness HQ"
                      )},
                timeout=8,
            )
            ok = False
            try:
                ok = resp.json().get("success") == "true"
            except Exception:
                ok = False
            if resp.status_code in (200, 201) and ok:
                self._send(200, {"ok": True})
            else:
                self._send(502, {"error": "email service error"})
        except Exception:
            self._send(502, {"error": "email service unreachable"})

    def _handle_stripe_webhook(self):
        """POST /api/stripe-webhook — Stripe checkout.session.completed.

        Fail-closed: until STRIPE_WEBHOOK_SECRET is configured in the
        environment this returns 503 and processes nothing, so a forged
        POST can never trigger the day-0 email or an order record. With
        the secret set, the Stripe-Signature header must verify before
        anything is read from the event.
        """
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > 262144:
            self._send(400, {"error": "bad request"})
            return
        raw = self.rfile.read(length)
        secret = os.environ.get("STRIPE_WEBHOOK_SECRET") or ""
        if not secret:
            print("stripe webhook: STRIPE_WEBHOOK_SECRET not configured; "
                  "event rejected unprocessed")
            self._send(503, {"error": "webhook not configured"})
            return
        if not _stripe_signature_ok(raw, self.headers.get("Stripe-Signature"), secret):
            print("stripe webhook: signature verification failed; event rejected")
            self._send(400, {"error": "invalid signature"})
            return
        try:
            event = json.loads(raw.decode("utf-8", "replace"))
        except (json.JSONDecodeError, ValueError):
            self._send(400, {"error": "invalid JSON"})
            return
        if event.get("type") != "checkout.session.completed":
            self._send(200, {"received": True, "ignored": event.get("type")})
            return
        session = (event.get("data") or {}).get("object") or {}
        summary = process_checkout_completed(session)
        self._send(200, {"received": True, "processed": summary.get("processed", False)})

    def _client_ip(self):
        fwd = self.headers.get("x-forwarded-for", "")
        return fwd.split(",")[0].strip() if fwd else self.client_address[0]

    def _handle_intake_prefill(self):
        """GET /api/intake-prefill?payment_ref=cs_... -> the four
        intake-door values the journey already collected: name +
        email from the Stripe session (stored by the webhook),
        website + business name from the scan (joined by email).
        The session id is the same unguessable credential the
        existing door/resume links already carry. Any miss returns
        {} and the door behaves exactly as it does today."""
        qs = parse_qs(urlparse(self.path).query)
        ref = (qs.get("payment_ref") or [""])[0].strip()
        out = {}
        if re.match(r"^cs_(test_|live_)?[A-Za-z0-9_]+$", ref) and \
                rate_ok("prefill:" + self._client_ip()):
            order = _blob_get_json(_ORDER_PREFIX + ref + ".json")
            if order and order.get("email"):
                out = {"name": order.get("name") or "",
                       "email": order.get("email") or ""}
                lead = _blob_get_json(
                    _SCAN_LEAD_PREFIX
                    + str(order["email"]).lower() + ".json")
                if lead:
                    out["website"] = lead.get("url") or ""
                    out["business"] = lead.get("business") or ""
        body = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Serve the landing page + static assets (Vercel routes every path
        # through this entrypoint, so the function doubles as the web server).
        path = self.path.split("?", 1)[0]
        if path == "/api/intake-prefill":
            self._handle_intake_prefill()
            return
        if path == "/api/unsubscribe":
            self._handle_unsubscribe()
            return
        if path == "/":
            path = "/index.html"
        if path == "/packet":
            path = "/packet.html"
        name = path.lstrip("/")
        allowed = {
            "index.html": "text/html; charset=utf-8",
            "styles.css": "text/css; charset=utf-8",
            "styles.v2.css": "text/css; charset=utf-8",
            "styles.v3.css": "text/css; charset=utf-8",
            "styles.v4.css": "text/css; charset=utf-8",
            "styles.v5.css": "text/css; charset=utf-8",
            "styles.v6.css": "text/css; charset=utf-8",
            "app.js": "application/javascript; charset=utf-8",
            "app.v2.js": "application/javascript; charset=utf-8",
            "app.v3.js": "application/javascript; charset=utf-8",
            "app.v4.js": "application/javascript; charset=utf-8",
            "thanks-149.html": "text/html; charset=utf-8",
            "intake-149.html": "text/html; charset=utf-8",
            "thanks-449.html": "text/html; charset=utf-8",
            "intake-449.html": "text/html; charset=utf-8",
            "intake-thanks.html": "text/html; charset=utf-8",
            "thanks-upgrade.html": "text/html; charset=utf-8",
            "packet.html": "text/html; charset=utf-8",
            "ai-info.html": "text/html; charset=utf-8",
            "widget-test.html": "text/html; charset=utf-8",
        "information.html": "text/html; charset=utf-8",
        "information-packet.b64": "text/plain; charset=utf-8",
            "blog.html": "text/html; charset=utf-8",
            "support.html": "text/html; charset=utf-8",
            "pricing-faq.html": "text/html; charset=utf-8",
            "blog-captcha.html": "text/html; charset=utf-8",
            "blog-free-ai-tools-platforms.html": "text/html; charset=utf-8",
            "blog-ai-answers-change.html": "text/html; charset=utf-8",
            "blog-ai-information-drift.html": "text/html; charset=utf-8",
            "blog-agent-economy.html": "text/html; charset=utf-8",
            "blog-servicetitan-website-ai-agent-readiness.html": "text/html; charset=utf-8",
            "blog-seo-vs-aeo.html": "text/html; charset=utf-8",
            "blog-yelp-agent-access.html": "text/html; charset=utf-8",
            "blog-musk-agent-first-amazon.html": "text/html; charset=utf-8",
            "blog-benioff-digital-labor.html": "text/html; charset=utf-8",
            "blog-altman-agents-workforce.html": "text/html; charset=utf-8",
            "blog-nadella-agent-era.html": "text/html; charset=utf-8",
            "blog-llms-txt.html": "text/html; charset=utf-8",
            "blog-ai-agents-find-business.html": "text/html; charset=utf-8",
            "blog-blocking-ai-crawlers.html": "text/html; charset=utf-8",
            "blog-google-gemini-agent.html": "text/html; charset=utf-8",
            "blog-ai-in-your-business.html": "text/html; charset=utf-8",
            "blog-superintelligence.html": "text/html; charset=utf-8",
            "robots.txt": "text/plain; charset=utf-8",
            "sitemap.xml": "application/xml; charset=utf-8",
            "llms.txt": "text/plain; charset=utf-8",
        }
        if name not in allowed:
            self._send(404, {"error": "not found"})
            return
        fpath = os.path.join(os.path.dirname(__file__), "..", "site", name)
        try:
            with open(fpath, "rb") as f:
                data = f.read()
        except OSError:
            self._send(404, {"error": "not found"})
            return
        self.send_response(200)
        self.send_header("Content-Type", allowed[name])
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/unsubscribe":
            self._handle_unsubscribe()
            return
        if path == "/api/subscribe":
            self._handle_subscribe()
            return
        if path == "/api/stripe-webhook":
            self._handle_stripe_webhook()
            return
        if path == "/api/packet":
            self._handle_packet()
            return
        if path != "/api/audit":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        if length > 4096:
            self._send(413, {"error": "request body too large"})
            return
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, ValueError):
            self._send(400, {"error": "invalid JSON body"})
            return
        if not rate_ok(self._client_ip()):
            self._send(429, {"error": "rate limit exceeded (10 audits/hour). Try again later."})
            return
        url = data.get("url", "") if isinstance(data, dict) else ""
        report = run_audit(url)
        if report.get("error") and not report.get("checks"):
            self._send(400, report)
            return
        # Optional lead capture: when the scan form's first name + email
        # ride along, email the visitor their results copy from hello@.
        # Best effort only — a mail failure never fails the scan.
        # Callers that only need the facts (the post-payment intake-149
        # initial-details step, whose scan prefills the intake form) pass
        # "suppress_email": true so the buyer is NOT also sent the
        # free-scan results email. Absent/false = default behavior.
        first_name, lead_email = _clean_lead(data)
        suppress_email = isinstance(data, dict) and bool(
            data.get("suppress_email"))
        # Paid buyers re-running the public scan DO get the results
        # email (Caleb ruling 2026-10-26, reversing D-1): re-scanning
        # after implementing fixes is the natural verification loop,
        # and a silently missing email reads as a malfunction. Only
        # the explicit suppress_email flag (the post-payment intake
        # step re-running the audit internally) still skips the send.
        if first_name and lead_email:
            # Intake prefill record (2026-10-22): remember which site
            # this email scanned, so a later checkout's intake door
            # can re-supply website + business name on any device.
            # Latest scan for an email wins; every field stays
            # editable at the door. Failure-isolated like all stores.
            _scan_lead_write(lead_email, report.get("url") or url,
                             report.get("business_name") or "")
        if first_name and lead_email and not suppress_email:
            # The lead record is created here, server-side, in the
            # same request as the results email, so it cannot be lost
            # to a failed browser post after a successful scan. The
            # browser no longer posts a duplicate notice to
            # FormSubmit (see app.v4.js).
            report["lead_notice_sent"] = send_scan_lead_notice(
                first_name, lead_email, report)
            report["email_sent"] = send_results_email(
                first_name, lead_email, report)
        self._send(200, report)

    def log_message(self, *args):  # keep Vercel logs quiet
        pass
