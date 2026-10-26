"""Agent Readiness Audit — Vercel serverless function (Python runtime).

POST /api/audit  with JSON body {"url": "https://example.com"}
-> 200 with the same JSON report the CLI (audit/audit.py) produces:
   {tool, url, fetched_at, score, checks[], fixes[], errors[]}

Optional lead fields in the same body — {"first_name": ..., "email": ...} —
make the function email the visitor a copy of their results from
hello@agentreadinesshq.com (see send_results_email below). That replaces
the old FormSubmit _autoresponse, which never delivered. The send only
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

VERSION = "1.0-api"
UA = "AgentReadinessAudit/1.0 (machine-readability audit; single fetch)"
TIMEOUT = 4          # per-fetch timeout (seconds) — tight for serverless
TIMEOUT_DEEP = 3     # deep-page fetch gets a shorter budget
TIME_BUDGET = 5.5    # skip the deep page once this many seconds have elapsed
MAX_BYTES = 2_000_000
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

BOT_WALL_MARKERS = [
    "cf-chl", "challenge-platform", "verify you are human",
    "captcha", "cf_clearance", "cf-turnstile", "just a moment",
    "checking your browser", "datadome", "perimeterx",
    "please verify you are a human", "are you a robot",
    "incapsula", "distil_r_captcha", "human verification",
]

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

FIX_TEXT = {
    "robots_ai_posture": "Allow major AI crawlers in robots.txt (or add explicit Allow lines); blocking them hides the site from shopping/research agents.",
    "llms_txt": "Add a concise /llms.txt summarizing offerings, pricing, service area, and contact info for LLM consumers.",
    "sitemap": "Publish /sitemap.xml listing key pages so agents can discover the site without guessing URLs.",
    "schema_jsonld": "Add schema.org JSON-LD: Product with price/offers, LocalBusiness (name, address, phone, hours), and FAQPage for common questions.",
    "pricing_html": "Render at least headline pricing in the raw HTML (server-side or pre-rendered); JS-only prices are invisible to non-JS agents.",
    "bot_wall": "Move bot protection behind real abuse signals instead of the front door; challenge pages block legitimate agent traffic.",
    "page_speed": "Speed up the homepage: cache aggressively, shrink payload, and fix slow TTFB — agents time out faster than humans.",
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
        "meaning": "This file tells AI crawlers whether they may look at your site at all.",
    },
    "llms_txt": {
        "meaning": "An optional file that introduces your business in a plain format written for AI agents. It supplements your pages. It is not a substitute for clear content, crawlability, structured data, or accurate facts.",
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


def fetch(session, url, timeout=TIMEOUT):
    """Single GET with byte cap. Returns (ok, status, text, elapsed, ttfb, err)."""
    t0 = time.perf_counter()
    try:
        r = session.get(url, timeout=timeout, stream=True, allow_redirects=True)
        ttfb = r.elapsed.total_seconds()
        size, chunks = 0, []
        for chunk in r.iter_content(chunk_size=65536):
            if chunk:
                size += len(chunk)
                if size > MAX_BYTES:
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
def host_is_public(hostname):
    """Reject hostnames resolving to non-public IPs. Returns (ok, reason)."""
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False, "hostname does not resolve"
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
    """Returns (base, url) or (None, error_message)."""
    url = (raw or "").strip()[:MAX_URL_LEN]
    if not url:
        return None, "missing 'url' in request body"
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    p = urlparse(url)
    if p.scheme.lower() not in ("http", "https"):
        return None, "only http(s) URLs are allowed"
    if not p.hostname:
        return None, "invalid URL"
    ok, reason = host_is_public(p.hostname)
    if not ok:
        return None, f"URL rejected: {reason}"
    base = f"{p.scheme}://{p.netloc}".rstrip("/")
    return base, url


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
    ua = crawler.lower()
    for g in groups:
        if ua in g["agents"]:
            return g
    for g in groups:
        for a in g["agents"]:
            if a != "*" and (a in ua or ua in a):
                return g
    for g in groups:
        if "*" in g["agents"]:
            return g
    return None


def blocked_sitewide(group):
    if group is None:
        return False
    for rule, path in group["rules"]:
        if rule == "disallow" and path.rstrip() in ("/", "/*"):
            allows_root = any(r == "allow" and p.rstrip() in ("/", "/*")
                              for r, p in group["rules"])
            if not allows_root:
                return True
    return False


def check_robots(result):
    w = WEIGHTS["robots_ai_posture"]
    ok, status, text, _t, _ttfb, err = result
    if not ok:
        return w * 0.0, "fail", f"could not fetch robots.txt ({err}); cannot verify crawler posture"
    if status != 200 or not text.strip():
        return w * 1.0, "pass", "no robots.txt (defaults to allow-all for every crawler)"
    groups = parse_robots_groups(text)
    blocked = [c for c in AI_CRAWLERS if blocked_sitewide(group_for_crawler(c, groups))]
    allowed_frac = (len(AI_CRAWLERS) - len(blocked)) / len(AI_CRAWLERS)
    if not blocked:
        return w, "pass", f"all {len(AI_CRAWLERS)} known AI crawlers allowed"
    detail = (f"{len(blocked)}/{len(AI_CRAWLERS)} AI crawlers disallowed site-wide: "
              f"{', '.join(blocked)}")
    return w * allowed_frac, ("partial" if allowed_frac > 0 else "fail"), detail


# ----------------------------------------------------------------- llms.txt ---
def check_llms_txt(result):
    w = WEIGHTS["llms_txt"]
    ok, status, text, _t, _ttfb, err = result
    if not ok:
        return 0.0, "fail", f"could not fetch /llms.txt ({err})"
    if status != 200:
        return 0.0, "fail", f"/llms.txt returned HTTP {status}"
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
    return w * 0.5, "partial", "/sitemap.xml returned 200 but content is not a recognizable sitemap"


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


def jsonld_has_product_price(blocks):
    found_product = found_price = False

    def walk(node):
        nonlocal found_product, found_price
        if isinstance(node, dict):
            t = node.get("@type")
            types = {str(x).lower() for x in t} if isinstance(t, list) else {str(t).lower()} if t else set()
            if "product" in types:
                found_product = True
            for k in ("price", "offers", "priceSpecification"):
                if k in node and node[k]:
                    found_price = True
            g = node.get("@graph")
            if g:
                walk(g)
            for v in node.values():
                if isinstance(v, (dict, list)):
                    walk(v)
        elif isinstance(node, list):
            for i in node:
                walk(i)

    for b in blocks:
        walk(b)
    return found_product, found_price


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


def check_jsonld(html):
    w = WEIGHTS["schema_jsonld"]
    blocks = extract_jsonld_blocks(html)
    if not blocks:
        return 0.0, "fail", "no parseable application/ld+json blocks found"
    types = set()
    for b in blocks:
        flatten_types(b, types)
    has_product, has_price = jsonld_has_product_price(blocks)
    product_ok = has_product and has_price
    local_ok = bool(types & LOCAL_BUSINESS_TYPES)
    faq_ok = "faqpage" in types
    hits = sum([product_ok, local_ok, faq_ok])
    parts = []
    parts.append("Product+price/offers" if product_ok else "no Product with price/offers"
                 + (" (Product found, price missing)" if has_product and not has_price else ""))
    parts.append("LocalBusiness" if local_ok else "no LocalBusiness type")
    parts.append("FAQPage" if faq_ok else "no FAQPage")
    detail = f"{hits}/3 target types — " + "; ".join(parts) + f" ({len(blocks)} ld+json block(s) parsed)"
    score = w * hits / 3
    status = "pass" if hits == 3 else ("partial" if hits > 0 else "fail")
    return score, status, detail


# ------------------------------------------------------------------- pricing ---
def strip_to_text(html):
    no_script = re.sub(r"<script.*?</script>", " ", html, flags=re.I | re.S)
    no_style = re.sub(r"<style.*?</style>", " ", no_script, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", no_style)
    return re.sub(r"\s+", " ", text).strip()


def check_pricing(html):
    w = WEIGHTS["pricing_html"]
    text = strip_to_text(html)
    prices = PRICE_RE.findall(text)
    js_shell = bool(JS_SHELL_RE.search(html)) and len(text) < 500
    if prices:
        sample = ", ".join(list(dict.fromkeys(prices))[:5])
        return w, "pass", f"{len(prices)} price-like pattern(s) in raw HTML (e.g. {sample})"
    if js_shell:
        return 0.0, "fail", ("page looks like a JS shell (SPA root node, "
                             f"{len(text)} chars of visible text, no prices) — agents without JS see nothing")
    if PRICE_WORD_RE.search(text):
        return w * 0.5, "partial", "pricing words found but no parseable $ price pattern in raw HTML"
    return 0.0, "fail", "no price patterns and no pricing language found in raw HTML"


# ------------------------------------------------------------------ bot wall ---
def check_bot_wall(pages):
    w = WEIGHTS["bot_wall"]
    hits = {}
    for label, html in pages:
        low = html.lower()
        found = sorted({m for m in BOT_WALL_MARKERS if m in low})
        if found:
            hits[label] = found
    if not hits:
        return w, "pass", f"no bot-wall/CAPTCHA markers on {len(pages)} page(s) scanned"
    detail = "; ".join(f"{label}: {', '.join(m)}" for label, m in hits.items())
    return 0.0, "fail", f"bot-wall/CAPTCHA markers detected — {detail}"


# --------------------------------------------------------------------- speed ---
def check_speed(ttfb, total):
    w = WEIGHTS["page_speed"]

    def band(v, good, ok, bad):
        if v is None:
            return 0.0
        if v <= good:
            return 1.0
        if v <= ok:
            return 0.6
        if v <= bad:
            return 0.3
        return 0.0

    ttfb_s = band(ttfb, 0.6, 1.2, 2.5)
    total_s = band(total, 1.5, 3.0, 6.0)
    score = w * 0.5 * (ttfb_s + total_s)
    ttfb_str = f"{ttfb:.2f}s" if ttfb is not None else "n/a"
    detail = f"TTFB {ttfb_str}, total fetch {total:.2f}s"
    status = "pass" if (ttfb_s == 1.0 and total_s == 1.0) else ("partial" if score >= w * 0.5 else "fail")
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
        norm = normalize_url(raw_url)
        if norm[0] is None:
            return {"url": (raw_url or "")[:200], "error": norm[1], "score": 0.0,
                    "checks": [], "fixes": [], "errors": [norm[1]]}
        base, url = norm

        errors = []
        session = make_session()

        # 4 independent fetches in parallel
        with ThreadPoolExecutor(max_workers=4) as ex:
            f_home = ex.submit(fetch, session, base + "/")
            f_robots = ex.submit(fetch, session, base + "/robots.txt")
            f_llms = ex.submit(fetch, session, base + "/llms.txt")
            f_sitemap = ex.submit(fetch, session, base + "/sitemap.xml")
            home = f_home.result()
            robots_r, llms_r, sitemap_r = f_robots.result(), f_llms.result(), f_sitemap.result()

        ok_h, st_h, html, total, ttfb, err_h = home
        if not ok_h:
            errors.append(f"homepage fetch failed: {err_h}")
            html, st_h = "", None
        elif st_h != 200:
            errors.append(f"homepage returned HTTP {st_h}")
            html = ""

        checks = []
        s, st, d = check_robots(robots_r)
        checks.append(("robots_ai_posture", "robots.txt AI-crawler posture", s, st, d))
        s, st, d = check_llms_txt(llms_r)
        checks.append(("llms_txt", "llms.txt present", s, st, d))
        s, st, d = check_sitemap(sitemap_r)
        checks.append(("sitemap", "sitemap.xml present", s, st, d))
        s, st, d = check_jsonld(html)
        checks.append(("schema_jsonld", "schema.org JSON-LD", s, st, d))
        s, st, d = check_pricing(html)
        checks.append(("pricing_html", "pricing in raw HTML", s, st, d))

        pages = [("homepage", html)]
        if html and (time.perf_counter() - t_start) < TIME_BUDGET:
            deep_url = pick_deep_page(base, html)
            dok, dstatus, dhtml, _t, _ttfb, derr = fetch(session, deep_url, timeout=TIMEOUT_DEEP)
            if dok and dstatus == 200:
                pages.append(("deep page " + urlparse(deep_url).path, dhtml))
            else:
                errors.append(f"deep page fetch failed ({deep_url}): {derr or 'HTTP ' + str(dstatus)}")
        elif html:
            errors.append("deep page skipped (time budget — homepage only)")
        s, st, d = check_bot_wall(pages)
        checks.append(("bot_wall", "no bot-wall / CAPTCHA", s, st, d))
        s, st, d = check_speed(ttfb, total)
        checks.append(("page_speed", "page speed (TTFB + total)", s, st, d))

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
            "url": url,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "score": total_score,
            "grade": grade(total_score),
            "business_name": business_name,
            "checks": results,
            "platform": platform_block,
            "checkout_urls": {
                "audit_149": STRIPE_149_CHECKOUT_URL,
                "done_for_you_449": STRIPE_449_CHECKOUT_URL,
            },
            "fixes": fixes,
            "errors": errors,
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


def _results_email_html(first_name, site, score, grade, checks, platform=None):
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
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="margin-top:22px; background-color:#fff7f8; border:1px solid #ffd9e1; border-radius:12px;">
<tr>
<td style="padding:22px 26px; vertical-align:middle;">
<div style="font-size:12px; font-weight:700; letter-spacing:0.09em; color:#c21847;">YOUR AI READINESS SCORE</div>
<div style="margin-top:6px;"><span style="font-size:46px; font-weight:800; letter-spacing:-0.02em; color:#1d1d1f;">%(score)s</span><span style="font-size:19px; font-weight:600; color:#6e6e73;"> / 100</span></div>
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="margin-top:12px;"><tr><td style="background-color:#f6dde2; border-radius:99px; height:9px;"><div style="width:%(pct)s%%; height:9px; border-radius:99px; background-color:#ff4d6d; font-size:0; line-height:0;">&nbsp;</div></td></tr></table>
</td>
<td width="118" align="center" style="padding:22px 10px; vertical-align:middle;">
<div style="font-size:12px; font-weight:700; letter-spacing:0.09em; color:#8a5a00;">GRADE</div>
<div style="display:inline-block; margin-top:8px; background-color:%(chip_bg)s; color:%(chip_fg)s; font-size:34px; font-weight:800; line-height:1; padding:12px 22px; border-radius:12px;">%(grade)s</div>
</td>
</tr>
</table>
<p style="font-size:15.5px; line-height:1.6; color:#333336; margin-top:20px;">%(site)s scored %(score)s/100 (grade %(grade)s). Here is how the seven checks came out:</p>
%(checks)s
%(conversion)s
%(details)s
<p style="font-size:16px; line-height:1.6; color:#333336; margin-top:26px;">Thanks,<br><br><strong>Agent Readiness HQ</strong><br><span style="color:#5c5c60;">hello@agentreadinesshq.com</span></p>
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
        "checks": "".join(blocks),
        "conversion": conversion_html,
        "details": details_html,
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
    checks = report.get("checks") or []
    platform = report.get("platform") or {}
    eligibility = platform.get("eligibility")
    lines = [
        f"Hi {first_name}, thanks for running your free AI Readiness Scan "
        "with Agent Readiness HQ!",
        "",
        f"{site} scored {score}/100 (grade {grade}). "
        "Here is how the seven checks came out:",
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
    ]
    msg = EmailMessage()
    msg["From"] = f"Agent Readiness HQ <{RESULTS_FROM}>"
    msg["To"] = email
    msg["Subject"] = f"Your free scan results for {site}: {score}/100 (grade {grade})"
    msg.set_content("\n".join(lines))
    msg.add_alternative(
        _results_email_html(first_name, site, score, grade, checks, platform),
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


def _packet_message(email, pdf_bytes):
    msg = EmailMessage()
    msg["From"] = RESULTS_FROM
    msg["To"] = email
    msg["Subject"] = "Your Agent Readiness HQ information packet"
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
        "hello@agentreadinesshq.com")
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
_ORDER_SEQ_PATHNAME = "order-sequence/v1/next.json"
_ORDER_SEQ_SEED = 5


def _claim_arhq_number(session_id):
    """This order's ARHQ number, or None if numbering failed.

    Reuses the number stored on the session's existing order record
    when one is there; otherwise claims the next sequence value
    (persist the increment first, verify by read-back, then hand the
    number out). Never raises.
    """
    existing = _blob_get_json(_ORDER_PREFIX + session_id + ".json")
    if existing and existing.get("arhq_number"):
        return str(existing["arhq_number"])
    seq_obj = _blob_get_json(_ORDER_SEQ_PATHNAME)
    nxt = None
    if isinstance(seq_obj, dict):
        try:
            nxt = int(seq_obj.get("next"))
        except (TypeError, ValueError):
            nxt = None
    if nxt is None or nxt < _ORDER_SEQ_SEED:
        nxt = _ORDER_SEQ_SEED
    if not _blob_put_json(_ORDER_SEQ_PATHNAME,
                          {"next": nxt + 1,
                           "ts": datetime.now(timezone.utc).isoformat()}):
        print(f"order-numbering: sequence write for session "
              f"{session_id} was not accepted; day-0 email will "
              "carry no order reference")
        return None
    # Confirm by read-back, retrying briefly: a just-written blob can
    # read back stale for a moment (the 2026-10-23 live failure, where
    # the first real claim's instant read-back missed and the order
    # went out numberless). If no read-back confirms but the store
    # accepted the write (HTTP 200 above), hand the number out anyway
    # and log it: an accepted write is durable, and a numberless
    # order email is the worse failure.
    confirmed = False
    for delay in (0.5, 1.0, 2.0):
        confirm = _blob_get_json(_ORDER_SEQ_PATHNAME)
        if isinstance(confirm, dict) and confirm.get("next") == nxt + 1:
            confirmed = True
            break
        time.sleep(delay)
    if not confirmed:
        print(f"order-numbering: read-back for session {session_id} "
              "never confirmed the increment; handing out the number "
              "on the accepted write")
    year = datetime.now(timezone.utc).year
    return f"ARHQ-{year}-{nxt:04d}"


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
                     show_next=True):
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
</td></tr>
</table>
</td></tr>
</table>
</body></html>""" % {
        "heading": _esc_html(heading),
        "first": _esc_html(first_name),
        "payment": _esc_html(payment_line),
        "next": next_html,
        "blocks": blocks_html,
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
    ]
    blocks_html = "".join(
        [_day0_intake_step_html(action_lead, action_body, door_link)]
        + [_day0_tail_html(tail)])
    msg = EmailMessage()
    msg["From"] = f"Agent Readiness HQ <{RESULTS_FROM}>"
    msg["To"] = email
    msg["Subject"] = subject
    msg.set_content("\n".join(lines))
    msg.add_alternative(
        _day0_email_html(subject, first_name, payment_line,
                         blocks_html, show_next=False),
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
    ]
    blocks_html = "".join(
        [_day0_intake_step_html(action_lead, action_body, door_link)]
        + [_day0_tail_html(tail)])
    msg = EmailMessage()
    msg["From"] = f"Agent Readiness HQ <{RESULTS_FROM}>"
    msg["To"] = email
    msg["Subject"] = subject
    msg.set_content("\n".join(lines))
    msg.add_alternative(
        _day0_email_html(subject, first_name, payment_line,
                         blocks_html, show_next=False),
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
    ]
    blocks_html = _day0_tail_html(paras)
    msg = EmailMessage()
    msg["From"] = f"Agent Readiness HQ <{RESULTS_FROM}>"
    msg["To"] = email
    msg["Subject"] = subject
    msg.set_content("\n".join(lines))
    msg.add_alternative(
        _day0_email_html(subject, first_name, payment_line,
                         blocks_html, show_next=False),
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
    default_cents = {149: 14900, 449: 44900, "upgrade": 30000}[tier]
    try:
        amount_paid = f"{(session.get('amount_total') or default_cents) / 100:.2f}"
    except (TypeError, ValueError):
        amount_paid = {149: "149.00", 449: "449.00",
                       "upgrade": "300.00"}[tier]
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
    else:  # upgrade: short receipt only; approval+access follows in
        # the merged Template 18 delivery (spec section 14, 2026-10-22)
        day0_factory = lambda: compose_upgrade_email(  # noqa: E731
            first_name, email, arhq_number)
        notice_factory = lambda: compose_order_notice_upgrade(  # noqa: E731
            name, email, session_id, amount_paid, day0_sent, arhq_number)

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
        "status": "NEW" if tier == "upgrade" else "INTAKE_PENDING",
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
        "information.html": "text/html; charset=utf-8",
        "information-packet.b64": "text/plain; charset=utf-8",
            "blog.html": "text/html; charset=utf-8",
            "support.html": "text/html; charset=utf-8",
            "pricing-faq.html": "text/html; charset=utf-8",
            "blog-captcha.html": "text/html; charset=utf-8",
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
            report["email_sent"] = send_results_email(
                first_name, lead_email, report)
        self._send(200, report)

    def log_message(self, *args):  # keep Vercel logs quiet
        pass
