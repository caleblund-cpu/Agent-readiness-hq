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
from urllib.parse import urlparse, urljoin, urlencode

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
# "what this means" line per check, plus a high-level "Fixable:" line
# shown only when the check is not at full marks. The fixable lines
# deliberately say a fix exists without describing it — the how is
# what the paid products provide (same rule as the hidden top-fixes
# list on the scan page).
CHECK_COPY = {
    "robots_ai_posture": {
        "meaning": "This file tells AI crawlers whether they may look at your site at all.",
        "fixable": "Fixable: usually a small settings change.",
    },
    "llms_txt": {
        "meaning": "An optional file that introduces your business in a plain format written for AI agents. It supplements your pages. It is not a substitute for clear content, crawlability, structured data, or accurate facts.",
        "fixable": "Fixable: a standard addition to your site.",
    },
    "sitemap": {
        "meaning": "The map of your site, so an agent can find every page that matters instead of just a corner of it.",
        "fixable": "Fixable: a standard addition to your site.",
    },
    "schema_jsonld": {
        "meaning": "Machine-readable labels for your services, prices, and business facts, in the form an agent can quote accurately.",
        "fixable": "Fixable: structured facts can be added without redesigning your site.",
    },
    "pricing_html": {
        "meaning": "Prices stated in the page itself, where an agent can read them. When pricing isn't clearly stated, an agent may be unable to confidently present it to a customer.",
        "fixable": "Fixable: your prices can be presented in a form agents can quote.",
    },
    "bot_wall": {
        "meaning": "Whether anything stops an agent at the door before it learns a single thing about your business.",
        "fixable": "Fixable: in most cases the blocking element can be adjusted.",
    },
    "page_speed": {
        "meaning": "How fast your pages answer. Slow pages can make it harder for automated systems to retrieve information reliably.",
        "fixable": "Fixable: speed usually improves with a few standard adjustments.",
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
# (the platform cannot do it in the required form at all).
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
        "llms_txt": (
            "not_implementable",
            "GoDaddy Website Builder has no way to place a file at the "
            "domain root, so an llms.txt file cannot be added."),
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
    """
    if not platform_name:
        return {"eligibility": "unknown", "ceiling": None,
                "ceiling_line": None, "limitations": [],
                "per_check": {}}
    rules = PLATFORM_CAPABILITY.get(platform_name, {})
    per_check = {}
    limitations = []
    core_blocked = all(
        rules.get(cid, ("implementable", None))[0] == "not_implementable"
        for cid in _PLATFORM_VARYING_CHECKS)
    scores = {cid: sc for cid, _n, sc, _s, _d in raw_checks}
    # Unearnable points: what a not-implementable check has not
    # already scored. A check the site somehow passes (e.g. an
    # llms.txt redirect workaround that resolves) blocks nothing.
    blocked_checks = []
    blocked_points = 0
    for cid in _PLATFORM_VARYING_CHECKS:
        if rules.get(cid, ("implementable", None))[0] == "not_implementable":
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
        if n == 1:
            checks_phrase = ("1 of the checks in this scan to be "
                             "implemented in the required way. That "
                             "check accounts for")
        else:
            checks_phrase = (f"{n} of the checks in this scan to be "
                             "implemented in the required way. Those "
                             "checks account for")
        ceiling_line = (
            f"Platform limit: {platform_name} does not currently allow "
            f"{checks_phrase} {_fmt_num(blocked_points)} points, so "
            f"this site's maximum score on its current platform is "
            f"{_fmt_num(100 - blocked_points)}/100. That is a limit of "
            f"the platform, not of your site or of the work you have "
            f"done on it.")
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
        # platform, mark each short check as fixable or platform-
        # limited, and compute the $449 eligibility outcome. Runs on
        # the already-fetched homepage; detection failure never
        # affects the score, it only leaves the platform unconfirmed.
        platform_name, platform_evidence = detect_platform(
            urlparse(base).hostname or "", html)
        assessment = assess_platform(platform_name, checks)

        total_score = round(sum(c[2] for c in checks), 1)
        results = []
        for cid, name, sc, st, detail in checks:
            entry = {
                "id": cid, "name": name, "weight": WEIGHTS[cid],
                "status": st, "score": round(sc, 1), "detail": detail,
                "meaning": CHECK_COPY[cid]["meaning"],
                "fixable": (CHECK_COPY[cid]["fixable"]
                            if sc < WEIGHTS[cid] else None)}
            cap = assessment["per_check"].get(cid, "implementable")
            if platform_name and sc < WEIGHTS[cid] and cap != "implementable":
                _cap, reason = PLATFORM_CAPABILITY[platform_name][cid]
                head = ("Platform limit" if cap == "not_implementable"
                        else "Platform-dependent")
                entry["platform_status"] = "platform_limited"
                entry["platform_note"] = f"{head}: {reason}"
                entry["fixable"] = None
            elif sc < WEIGHTS[cid]:
                entry["platform_status"] = "fixable"
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
            "checks": results,
            "platform": platform_block,
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


def _results_email_html(first_name, site, score, grade, checks, platform=None):
    """HTML version of the results email, mirroring the on-page results:
    score/grade header, then per check the technical name + score pill,
    the finding line, the plain-English meaning line, and the fixable
    line when the check is not at full marks (or the platform-limit
    line when the platform, not the site, is what blocks the fix).
    When the scan identified the platform, a platform section follows
    the checks: the customer's own score ceiling where the platform
    makes one calculable, and the $449 eligibility disclosure (B) or
    unavailability statement (C) before any purchase. Table layout +
    inline styles for email-client compatibility; visual language
    follows the 2026-10-20 scan-email mock-up Caleb reviewed.
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
        fixable = (c.get("fixable") or "").strip()
        if fixable:
            head, _, rest = fixable.partition(":")
            block.append(
                '<p style="font-size:15px; line-height:1.6; color:#454548; '
                'margin-top:10px; margin-left:20px; padding:10px 14px; '
                'background-color:#fff7f8; border-left:3px solid #ff4d6d; '
                'border-radius:0 8px 8px 0;"><strong style="color:#c21847;">'
                "%s:</strong>%s</p>"
                % (_esc_html(head), _esc_html(rest)))
        pnote = (c.get("platform_note") or "").strip()
        if pnote:
            head, _, rest = pnote.partition(":")
            block.append(
                '<p style="font-size:15px; line-height:1.6; color:#454548; '
                'margin-top:10px; margin-left:20px; padding:10px 14px; '
                'background-color:#fdf6ec; border-left:3px solid #e8a13d; '
                'border-radius:0 8px 8px 0;"><strong style="color:#8a5a00;">'
                "%s:</strong>%s</p>"
                % (_esc_html(head), _esc_html(rest)))
        block.append("</div>")
        blocks.append("".join(block))
    # Platform section + offer wording follow the eligibility outcome
    # computed by the scan (Caleb ruling 2026-10-21). C sites are not
    # pitched Done For You at all; B sites get the limitation named
    # beside the offer; unconfirmed platforms get the confirm line.
    platform = platform or {}
    eligibility = platform.get("eligibility")
    platform_parts = []
    if platform.get("detected"):
        platform_parts.append(
            '<p style="font-size:15.5px; line-height:1.6; color:#333336; '
            'margin:0;">Website platform: <strong>%s</strong> '
            "(detected automatically).</p>"
            % _esc_html(platform.get("name") or ""))
    for key in ("ceiling_line", "offer_line", "confirm_line"):
        text = (platform.get(key) or "").strip()
        if text:
            platform_parts.append(
                '<p style="font-size:15.5px; line-height:1.6; '
                'color:#333336; margin-top:10px;">%s</p>'
                % _esc_html(text))
    platform_html = ""
    if platform_parts:
        platform_html = (
            '<div style="border-top:1px solid #f0e6e8; margin-top:22px; '
            'padding-top:22px;">' + "".join(platform_parts) + "</div>")
    if eligibility == "C":
        offer_html = (
            "As noted above, Done For You is not available for your "
            "site's current platform, so the option that fits is the "
            "DIY Audit ($149): the full picture, everything that can "
            "be done on your platform, and the materials to do it "
            "yourself or hand to a developer. You can see it here: "
            '<a href="https://agentreadinesshq.com/#pricing" '
            'style="color:#c21847;">https://agentreadinesshq.com/'
            "#pricing</a>")
    elif eligibility == "B":
        offer_html = (
            "If you'd like help with the fixes, you have two options. "
            "The DIY Audit ($149) gives you the full picture and the "
            "materials to fix things yourself. With Done For You "
            "($449), we make the approved improvements for you, "
            "within the platform limitations noted above, which we "
            "disclose before any purchase. You can see both here: "
            '<a href="https://agentreadinesshq.com/#pricing" '
            'style="color:#c21847;">https://agentreadinesshq.com/'
            "#pricing</a>")
    else:
        offer_html = (
            "If you'd like help with the fixes, you have two options. "
            "The DIY Audit ($149) gives you the full picture and the "
            "materials to fix things yourself. With Done For You "
            "($449), we make the approved improvements for you. You "
            "can see both here: "
            '<a href="https://agentreadinesshq.com/#pricing" '
            'style="color:#c21847;">https://agentreadinesshq.com/'
            "#pricing</a>")
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
%(platform)s
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="margin-top:30px; background-color:#fff7f8; border:1px solid #ffd9e1; border-radius:12px;">
<tr><td style="padding:24px 26px;">
<p style="font-size:15.5px; line-height:1.6; color:#333336; margin:0;">Your full results are on the page where you ran the scan.</p>
<p style="font-size:15.5px; line-height:1.6; color:#333336; margin-top:12px;">%(offer)s</p>
<p style="font-size:15.5px; line-height:1.6; color:#333336; margin-top:12px;">Or just reply to this email with any questions.</p>
</td></tr>
</table>
<p style="font-size:16px; line-height:1.6; color:#333336; margin-top:26px;">Thanks,<br><strong>Rachael Lund</strong><br><span style="color:#5c5c60;">Founder, Agent Readiness HQ</span></p>
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
        "platform": platform_html,
        "offer": offer_html,
    }


def compose_results_email(first_name, email, report):
    """Build the visitor's copy of their free scan results.

    Multipart (plain text + HTML) since 2026-10-20. Both parts carry
    the same three-layer structure the visitor sees on the results
    page: score and grade, then each of the seven checks with its
    status mark, points, finding line, plain-English meaning line,
    and (when the check is not at full marks) the high-level fixable
    line. Signed Rachael Lund, Founder (2026-10-16 ruling). The free
    results are never called a "report" or an "Audit" — those words
    belong to the paid products.
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
        fixable = (c.get("fixable") or "").strip()
        if fixable:
            lines.append(f"   {fixable}")
        pnote = (c.get("platform_note") or "").strip()
        if pnote:
            lines.append(f"   {pnote}")
    # Platform section (Caleb ruling 2026-10-21): the detected
    # platform, the customer's own ceiling where calculable, the
    # eligibility disclosure, and the confirm line when the platform
    # could not be identified.
    platform_lines = []
    if platform.get("detected"):
        platform_lines.append(
            f"Website platform: {platform.get('name')} "
            "(detected automatically).")
    for key in ("ceiling_line", "offer_line", "confirm_line"):
        text = (platform.get(key) or "").strip()
        if text:
            platform_lines.append(text)
    if platform_lines:
        lines += [""] + platform_lines
    lines += [
        "",
        "Your full results are on the page where you ran the scan.",
        "",
    ]
    if eligibility == "C":
        lines.append(
            "As noted above, Done For You is not available for your "
            "site's current platform, so the option that fits is the "
            "DIY Audit ($149): the full picture, everything that can "
            "be done on your platform, and the materials to do it "
            "yourself or hand to a developer. You can see it here: "
            "https://agentreadinesshq.com/#pricing")
    elif eligibility == "B":
        lines.append(
            "If you'd like help with the fixes, you have two options. "
            "The DIY Audit ($149) gives you the full picture and the "
            "materials to fix things yourself. With Done For You "
            "($449), we make the approved improvements for you, within "
            "the platform limitations noted above, which we disclose "
            "before any purchase. You can see both here: "
            "https://agentreadinesshq.com/#pricing")
    else:
        lines.append(
            "If you'd like help with the fixes, you have two options. The DIY Audit ($149) gives you the full picture and the materials to fix things yourself. With Done For You ($449), we make the approved improvements for you. You can see both here: https://agentreadinesshq.com/#pricing")
    lines += [
        "",
        "Or just reply to this email with any questions.",
        "",
        "Thanks,",
        "Rachael Lund, Founder, Agent Readiness HQ",
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
STRIPE_149_PAYMENT_LINK = "plink_1UQtKCLHicydTGP1aeNJjxNF"
STRIPE_449_PAYMENT_LINK = "plink_1UQtKaLHicydTGP1LHr3CtWE"
_WEBHOOK_TOLERANCE_S = 300
_PROCESSED_SESSIONS = set()  # per-instance idempotency; Stripe also dedupes


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


def compose_day0_email(first_name, email, session_id, door_link):
    """Template 7 ($149 purchase confirmation), automated. Adaptations
    for the new journey, flagged for Caleb's copy review: the intake
    link points at the scan-first door; step 2 no longer names a domain
    (the webhook does not know it yet; the door collects it); the
    template's markdown bold is dropped for plain-text sending.
    """
    lines = [
        f"Hi {first_name},",
        "",
        f"Thank you. Your payment of $149 has been received (order {session_id}).",
        "",
        "Here is what happens next:",
        "",
        f"1. Intake form. Use this link whenever you are ready: {door_link}",
        "It takes about 5 minutes. The first step runs a fresh scan of your website, and most of the form is then already filled in for you. The key step is confirming your business facts. We build your AI Information Page from verified facts only. We never guess at your services, prices, hours, or service areas.",
        "",
        "2. The audit. Once your intake is complete (payment received, intake form submitted, and any follow-up information we asked for to verify your business facts), we run the full audit on your website. This takes up to 5 business days. If we need information from you, the clock pauses until we receive it.",
        "",
        "3. Your report. You receive the full audit, your Agent Readiness HQ score, the prioritized fix list with exact copy and code, your custom AI Information Page, publishing instructions, and a developer handoff.",
        "",
        "Your report will come from this same email address. If it does not appear by the delivery date, please check your spam or junk folder, and mark our messages Not Junk so they reach your inbox.",
        "",
        "Refunds: If you cancel before we start work, you get a full refund. Once your customized report is delivered, the $149 fee is non-refundable.",
        "",
        "SEND TO ADMINISTRATOR: If your web person handles your site, forward them this email and the report when it arrives. The report includes a dedicated developer handoff section with everything technical in one place.",
        "",
        "Note: if your site runs on a hosted platform (WordPress, Wix, Squarespace, Kajabi), some fixes have platform limits. We check your platform as part of the audit, and we disclose any ceiling on your score honestly. If Kajabi or similar is your platform, we will tell you what is and is not possible.",
        "",
        "Questions in the meantime? Just reply to this email.",
        "",
        "-- Rachael",
        "Agent Readiness HQ",
        "agentreadinesshq.com",
    ]
    msg = EmailMessage()
    msg["From"] = f"Agent Readiness HQ <{RESULTS_FROM}>"
    msg["To"] = email
    msg["Subject"] = "Your $149 AI Readiness Report is on its way"
    msg.set_content("\n".join(lines))
    return msg


def compose_order_notice(name, email, session_id, amount_paid, day0_sent):
    """Internal order record to hello@, fields per 20-order-tracker.md.
    Business name and website are not known at payment time; the intake
    supplies them (the door runs the scan), so the row completes when
    the intake notification arrives.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = [
        "A $149 payment was confirmed by Stripe (webhook). Day-0 confirmation email "
        + ("sent to the customer." if day0_sent else "FAILED to send; send Template 7 by hand."),
        "",
        f"order_id: {session_id}",
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
        "Reminders at day 3, day 7, day 14 after payment if intake is still missing.",
    ]
    msg = EmailMessage()
    msg["From"] = f"Agent Readiness HQ <{RESULTS_FROM}>"
    msg["To"] = RESULTS_FROM
    msg["Subject"] = f"New $149 order (webhook): {name or email or session_id}"
    msg.set_content("\n".join(lines))
    return msg


def compose_day0_email_449(first_name, email, session_id, door_link):
    """Template 12 ($449 purchase confirmation), automated. Adaptations
    for the pay-first journey, flagged for Caleb's copy review: the
    intake link points at the scan-first door (intake-449); step 1 no
    longer names a domain (the webhook does not know it yet; the door
    collects it); the template's markdown bold is dropped for
    plain-text sending. Payment is not authorization, and the
    10-business-day clock starts only when all four prerequisites are
    complete: completed intake, signed authorization, written approval
    of the specific change list, and confirmed working website access.
    """
    lines = [
        f"Hi {first_name},",
        "",
        f"Thank you. Your payment of $449 has been received (order {session_id}).",
        "",
        "Here is what happens next:",
        "",
        f"1. Intake form. Use this link whenever you are ready: {door_link}",
        "It takes about 5 minutes. The first step gathers a few initial details about your business and your website, and most of the form is then already filled in for you. The key step is confirming your business facts. We build your AI Information Page from verified facts only. We never guess at your services, prices, hours, or service areas.",
        "",
        "2. Authorization. After your intake, we analyze your website and prepare a specific list of proposed changes. We email you that list with a short authorization form covering exactly those changes. Your payment does not authorize changes by itself; nothing is changed on your website until you review the list and sign.",
        "",
        "3. Temporary access. After you sign, we send step by step instructions for creating temporary website access for us, with the minimum permissions needed (or a platform invitation). You create the login yourself; we never ask for your password. Access is removed when the work is done.",
        "",
        "4. Implementation. Within 10 business days after all of the following are complete: (1) completed intake, (2) signed authorization, (3) written approval of the specific change list, and (4) confirmed working website access. The clock does not start until all four are received. If we are waiting on information, access, approval, or a decision from you, the clock pauses until we receive it. Implementation covers the approved improvements from your report. What can be implemented depends on your website platform and the access you provide; if a platform cannot support an approved change, we will tell you plainly and document the alternative in your report. You get a before-and-after report documenting every change, with undo instructions.",
        "",
        "Your report will come from this same email address. If it does not appear by the delivery date, please check your spam or junk folder, and mark our messages Not Junk so they reach your inbox.",
        "",
        "Refunds: If you cancel before we begin work, you get a full refund. If you cancel after we start analysis but before implementation begins, we refund the portion of the work not performed. Once implementation begins, the fee is non-refundable.",
        "",
        "SEND TO ADMINISTRATOR: If someone else manages your website, forward them this email. The access instructions will need their help, and the authorization form may need the site owner's signature.",
        "",
        "Questions in the meantime? Just reply to this email.",
        "",
        "-- Rachael",
        "Agent Readiness HQ",
        "agentreadinesshq.com",
    ]
    msg = EmailMessage()
    msg["From"] = f"Agent Readiness HQ <{RESULTS_FROM}>"
    msg["To"] = email
    msg["Subject"] = "Your $449 Done-for-You is confirmed"
    msg.set_content("\n".join(lines))
    return msg


def compose_order_notice_449(name, email, session_id, amount_paid, day0_sent):
    """Internal $449 order record to hello@, fields per
    20-order-tracker.md. Business name and website are not known at
    payment time; the intake supplies them (the door runs the scan),
    so the row completes when the intake notification arrives.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = [
        "A $449 payment was confirmed by Stripe (webhook). Day-0 confirmation email "
        + ("sent to the customer." if day0_sent else "FAILED to send; send Template 12 by hand."),
        "",
        f"order_id: {session_id}",
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
        "Reminders at day 3, day 7, day 14 after payment if intake is still missing. "
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
    first_name = name.split()[0] if name else "there"
    default_cents = 14900 if tier == 149 else 44900
    try:
        amount_paid = f"{(session.get('amount_total') or default_cents) / 100:.2f}"
    except (TypeError, ValueError):
        amount_paid = "149.00" if tier == 149 else "449.00"
    if tier == 149:
        door_link = _intake_door_link(name, email, session_id)
        day0_factory = lambda: compose_day0_email(  # noqa: E731
            first_name, email, session_id, door_link)
        notice_factory = lambda: compose_order_notice(  # noqa: E731
            name, email, session_id, amount_paid, day0_sent)
    else:
        door_link = _intake_door_link(
            name, email, session_id, INTAKE_DOOR_PATH_449)
        day0_factory = lambda: compose_day0_email_449(  # noqa: E731
            first_name, email, session_id, door_link)
        notice_factory = lambda: compose_order_notice_449(  # noqa: E731
            name, email, session_id, amount_paid, day0_sent)

    day0_sent = False
    if email and _EMAIL_RE.match(email):
        day0_sent = send_business_email(day0_factory, "day-0 email")
    else:
        print(f"stripe webhook: no usable customer email on {session_id}; "
              "day-0 email not sent")
    notice_sent = send_business_email(notice_factory, "order notice")

    record = {
        "order_id": session_id,
        "order_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "customer_name": name,
        "email": email,
        "product": tier,
        "amount_paid": amount_paid,
        "payment_status": "paid",
        "status": "INTAKE_PENDING",
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
                          "— Caleb, Agent Readiness HQ"
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

    def do_GET(self):
        # Serve the landing page + static assets (Vercel routes every path
        # through this entrypoint, so the function doubles as the web server).
        path = self.path.split("?", 1)[0]
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
            "packet.html": "text/html; charset=utf-8",
            "blog.html": "text/html; charset=utf-8",
            "support.html": "text/html; charset=utf-8",
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
        if first_name and lead_email and not suppress_email:
            report["email_sent"] = send_results_email(
                first_name, lead_email, report)
        self._send(200, report)

    def log_message(self, *args):  # keep Vercel logs quiet
        pass
