"""
PhishGuard — FastAPI Backend
Email Phishing Detection Engine

Run with:  uvicorn main:app --reload --port 8000
"""

import os
import re
import math
from urllib.parse import urlparse
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

# ─────────────────────────────────────────────────────────────
#  App Init
# ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="PhishGuard API",
    description="AI-powered email phishing detection engine",
    version="1.0.0",
)

# Allow all origins for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────
#  Request / Response Models
# ─────────────────────────────────────────────────────────────
class EmailRequest(BaseModel):
    sender:  Optional[str] = ""
    subject: Optional[str] = ""
    body:    Optional[str] = ""


class UrlFlag(BaseModel):
    label: str
    level: str   # "danger" | "warning" | "safe"


class UrlAnalysis(BaseModel):
    url:   str
    flags: list[UrlFlag]


class Indicator(BaseModel):
    severity:    str   # "HIGH" | "MEDIUM" | "LOW" | "INFO"
    description: str


class Recommendation(BaseModel):
    icon: str
    text: str


class Breakdown(BaseModel):
    url_risk:      float
    sender_risk:   float
    content_risk:  float
    urgency_score: float
    legitimacy:    float


class AnalysisResponse(BaseModel):
    verdict:         str         # "PHISHING" | "SUSPICIOUS" | "LEGITIMATE"
    risk_score:      int         # 0-100
    breakdown:       Breakdown
    indicators:      list[Indicator]
    url_analysis:    list[UrlAnalysis]
    recommendations: list[Recommendation]


# ─────────────────────────────────────────────────────────────
#  Threat Intelligence Data
# ─────────────────────────────────────────────────────────────

# Suspicious TLDs often abused in phishing
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ".click", ".download", ".loan", ".win", ".work",
    ".zip", ".review", ".country", ".stream", ".gdn",
    ".racing", ".science", ".party", ".date",
}

# Legitimate domains that phishers often spoof
TRUSTED_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple",
    "facebook", "netflix", "instagram", "twitter", "dropbox",
    "linkedin", "ebay", "chase", "bankofamerica", "wellsfargo",
    "dhl", "fedex", "ups", "irs", "usps",
]

# Urgency / threat keywords
URGENCY_KEYWORDS = [
    r"\burgent\b", r"\bimmediately\b", r"\bact now\b",
    r"\bwithin 24 hours\b", r"\bwithin 48 hours\b",
    r"\bexpires?\b", r"\bsuspended\b", r"\bdisabled\b",
    r"\bverif(y|ied|ication)\b", r"\bconfirm\b",
    r"\bunusual activity\b", r"\bunauthorized\b",
    r"\blimited time\b", r"\bfinal (notice|warning)\b",
    r"\baction required\b", r"\byour account\b.*\b(blocked|frozen|limited)\b",
    r"\b(permanently|will be) (closed|deleted|terminated)\b",
    r"\bdo not (ignore|delay)\b",
]

# Password / credential harvesting keywords
CREDENTIAL_KEYWORDS = [
    r"\bpassword\b", r"\bsocial security\b", r"\bssn\b",
    r"\bcredit card\b", r"\bcard number\b", r"\bcvv\b",
    r"\bbank account\b", r"\brouting number\b",
    r"\bpersonal information\b", r"\bdate of birth\b",
    r"\blogin\b.*\bdetails\b", r"\bsign in\b.*\bbelow\b",
    r"\benter your\b",
]

# URL shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "buff.ly", "short.io", "rb.gy", "cutt.ly", "is.gd",
    "v.gd", "tiny.cc", "0.gp", "adf.ly",
}

# Impersonation patterns in email addresses
IMPERSONATION_PATTERNS = [
    r"payp[a4]l", r"g[o0]{2}gle", r"amaz[o0]n",
    r"micros[o0]ft", r"[a4]pple", r"netfl[i1]x",
    r"faceb[o0]{2}k", r"supp[o0]rt.+(?:paypal|google|amazon)",
    r"(?:security|alert|noreply)\@.+\.(xyz|tk|ml|ga|cf|pw|click)",
]


# ─────────────────────────────────────────────────────────────
#  URL Extraction
# ─────────────────────────────────────────────────────────────
URL_REGEX = re.compile(
    r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
    re.IGNORECASE
)

def extract_urls(text: str) -> list[str]:
    """Extract all URLs from text."""
    found = URL_REGEX.findall(text or "")
    cleaned = []
    for url in found:
        url = url.rstrip(".,;:!?)")
        if not url.startswith("http"):
            url = "http://" + url
        cleaned.append(url)
    return list(dict.fromkeys(cleaned))   # deduplicate preserving order


# ─────────────────────────────────────────────────────────────
#  URL Analysis
# ─────────────────────────────────────────────────────────────
def analyze_url(url: str) -> tuple[UrlAnalysis, float]:
    """
    Analyze a single URL for phishing indicators.
    Returns (UrlAnalysis, risk_contribution 0.0-1.0)
    """
    flags: list[UrlFlag] = []
    risk = 0.0

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path     = parsed.path or ""
        full_url = url.lower()
    except Exception:
        return UrlAnalysis(url=url, flags=[UrlFlag(label="Parse Error", level="warning")]), 0.2

    # 1. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            flags.append(UrlFlag(label=f"Suspicious TLD ({tld})", level="danger"))
            risk += 0.35
            break

    # 2. URL Shortener
    for shortener in URL_SHORTENERS:
        if hostname == shortener or hostname.endswith("." + shortener):
            flags.append(UrlFlag(label="URL Shortener", level="warning"))
            risk += 0.2
            break

    # 3. Brand impersonation via typosquatting
    for brand in TRUSTED_BRANDS:
        if brand in hostname and not hostname.endswith(f"{brand}.com"):
            flags.append(UrlFlag(label=f"Brand Spoofing ({brand})", level="danger"))
            risk += 0.5
            break

    # 4. IP address instead of domain
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        flags.append(UrlFlag(label="IP Address URL (no domain)", level="danger"))
        risk += 0.45

    # 5. Excessive subdomains (>3)
    parts = hostname.split(".")
    if len(parts) > 4:
        flags.append(UrlFlag(label="Excessive Subdomains", level="warning"))
        risk += 0.2

    # 6. Login/verify/secure in path
    sensitive_paths = ["login", "signin", "verify", "secure", "account", "update", "confirm", "restore"]
    for sp in sensitive_paths:
        if sp in path.lower():
            flags.append(UrlFlag(label=f"Sensitive Path: /{sp}", level="warning"))
            risk += 0.15
            break

    # 7. Very long URL
    if len(url) > 100:
        flags.append(UrlFlag(label="Unusually Long URL", level="warning"))
        risk += 0.1

    # 8. @ symbol in URL (obfuscation)
    if "@" in url:
        flags.append(UrlFlag(label="@ Symbol in URL (obfuscation)", level="danger"))
        risk += 0.4

    # 9. Double slash redirect
    if "//" in path:
        flags.append(UrlFlag(label="Double-slash Redirect", level="warning"))
        risk += 0.15

    # 10. HTTP (not HTTPS)
    if url.startswith("http://"):
        flags.append(UrlFlag(label="No HTTPS Encryption", level="warning"))
        risk += 0.1

    # No flags = looks clean
    if not flags:
        flags.append(UrlFlag(label="No obvious threats", level="safe"))

    return UrlAnalysis(url=url, flags=flags), min(risk, 1.0)


# ─────────────────────────────────────────────────────────────
#  Sender Analysis
# ─────────────────────────────────────────────────────────────
def analyze_sender(sender: str) -> tuple[list[Indicator], float]:
    indicators: list[Indicator] = []
    risk = 0.0
    sender_lower = sender.lower()

    if not sender:
        return indicators, 0.0

    # Check impersonation patterns
    for pattern in IMPERSONATION_PATTERNS:
        if re.search(pattern, sender_lower):
            indicators.append(Indicator(
                severity="HIGH",
                description=f"Sender address matches known impersonation pattern: '{sender}'"
            ))
            risk += 0.6
            break

    # Mismatch: display name suggests brand but domain doesn't match
    domain_match = re.search(r"@([a-z0-9.\-]+)$", sender_lower)
    if domain_match:
        domain = domain_match.group(1)
        for brand in TRUSTED_BRANDS:
            if brand in sender_lower and not domain.startswith(brand):
                indicators.append(Indicator(
                    severity="HIGH",
                    description=f"Sender claims to be '{brand}' but email domain is '{domain}'"
                ))
                risk += 0.55
                break

        # Suspicious TLD in sender domain
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld.lstrip(".")):
                indicators.append(Indicator(
                    severity="HIGH",
                    description=f"Sender domain uses suspicious TLD: .{domain.split('.')[-1]}"
                ))
                risk += 0.4
                break

    # Numeric-heavy local part (spam indicator)
    local = sender_lower.split("@")[0] if "@" in sender_lower else sender_lower
    digits = sum(c.isdigit() for c in local)
    if len(local) > 0 and digits / len(local) > 0.5:
        indicators.append(Indicator(
            severity="MEDIUM",
            description=f"Sender local part contains excessive digits (spam pattern): '{local}'"
        ))
        risk += 0.2

    return indicators, min(risk, 1.0)


# ─────────────────────────────────────────────────────────────
#  Content Analysis
# ─────────────────────────────────────────────────────────────
def analyze_content(subject: str, body: str) -> tuple[list[Indicator], float, float]:
    """
    Returns (indicators, content_risk, urgency_score)
    """
    indicators: list[Indicator] = []
    content_risk = 0.0
    urgency_score = 0.0

    full_text = f"{subject} {body}".lower()

    # Urgency keyword hits
    urgency_hits = 0
    for kw in URGENCY_KEYWORDS:
        if re.search(kw, full_text, re.IGNORECASE):
            urgency_hits += 1

    if urgency_hits >= 4:
        indicators.append(Indicator(
            severity="HIGH",
            description=f"Extreme urgency language detected ({urgency_hits} urgency phrases found)"
        ))
        urgency_score = min(urgency_hits / 6, 1.0)
        content_risk += 0.4
    elif urgency_hits >= 2:
        indicators.append(Indicator(
            severity="MEDIUM",
            description=f"Urgency language detected ({urgency_hits} phrases like 'act now', 'verify immediately')"
        ))
        urgency_score = urgency_hits / 6
        content_risk += 0.2
    elif urgency_hits == 1:
        indicators.append(Indicator(
            severity="LOW",
            description="Mild urgency language detected"
        ))
        urgency_score = 0.1
        content_risk += 0.05

    # Credential harvesting
    cred_hits = sum(1 for kw in CREDENTIAL_KEYWORDS if re.search(kw, full_text, re.IGNORECASE))
    if cred_hits >= 2:
        indicators.append(Indicator(
            severity="HIGH",
            description=f"Multiple credential-harvesting keywords detected (password, card number, etc.)"
        ))
        content_risk += 0.45
    elif cred_hits == 1:
        indicators.append(Indicator(
            severity="MEDIUM",
            description="Credential-related keywords found in email content"
        ))
        content_risk += 0.2

    # Threatening language
    threats = [r"\bwill be\b.*\b(suspended|deleted|closed|banned)\b",
               r"\b(permanent|legal|liable|lawsuit|penalt)\b",
               r"\bhold you responsible\b"]
    threat_hits = sum(1 for t in threats if re.search(t, full_text, re.IGNORECASE))
    if threat_hits:
        indicators.append(Indicator(
            severity="HIGH",
            description="Threatening language detected (legal threats, account suspension warnings)"
        ))
        content_risk += 0.3

    # Grammar / quality check (very short body for what claims to be important)
    words = len(body.split()) if body else 0
    if words < 20 and (urgency_hits > 0 or cred_hits > 0):
        indicators.append(Indicator(
            severity="MEDIUM",
            description="Very short body with urgent/sensitive content — common in phishing templates"
        ))
        content_risk += 0.15

    # ALL CAPS subject
    if subject and subject == subject.upper() and len(subject) > 5:
        indicators.append(Indicator(
            severity="MEDIUM",
            description=f"Subject line in ALL CAPS — common social engineering tactic"
        ))
        content_risk += 0.15

    # Subject has urgent words
    for kw in [r"\burgent\b", r"\baction required\b", r"\bsuspended\b", r"\bimportant\b", r"\bwarning\b"]:
        if re.search(kw, (subject or ""), re.IGNORECASE):
            indicators.append(Indicator(
                severity="MEDIUM",
                description=f"Subject line contains high-urgency keyword"
            ))
            content_risk += 0.1
            break

    # Greetings: generic vs personalized
    generic_greetings = [r"\bdear\s+(valued\s+)?(customer|user|member|client|sir|ma'am)\b",
                         r"\bhello\s+user\b", r"\bdear\s+account\s+holder\b"]
    for g in generic_greetings:
        if re.search(g, full_text, re.IGNORECASE):
            indicators.append(Indicator(
                severity="LOW",
                description="Generic greeting used (e.g. 'Dear Customer') — legitimate emails usually address you by name"
            ))
            content_risk += 0.1
            break

    # "Click here" language
    if re.search(r"\bclick\s+here\b", full_text, re.IGNORECASE):
        indicators.append(Indicator(
            severity="LOW",
            description="Vague 'click here' call-to-action — phishers avoid showing real URLs"
        ))
        content_risk += 0.1

    return indicators, min(content_risk, 1.0), min(urgency_score, 1.0)


# ─────────────────────────────────────────────────────────────
#  Legitimacy Signals (positive indicators)
# ─────────────────────────────────────────────────────────────
def compute_legitimacy(sender: str, body: str, urls: list[str]) -> tuple[list[Indicator], float]:
    """
    Score positive signals. Higher score = more legitimate.
    """
    indicators: list[Indicator] = []
    score = 0.0

    sender_lower = (sender or "").lower()
    body_lower   = (body or "").lower()

    # Sender from known domain
    known_domains = [".com", ".org", ".edu", ".gov", ".io"]
    domain_match = re.search(r"@([a-z0-9.\-]+)$", sender_lower)
    if domain_match:
        domain = domain_match.group(1)
        for kd in known_domains:
            if domain.endswith(kd.lstrip(".")):
                score += 0.1
                break

    # Has unsubscribe link
    if re.search(r"unsubscribe", body_lower):
        indicators.append(Indicator(severity="INFO", description="Email contains unsubscribe link (legitimate newsletter pattern)"))
        score += 0.2

    # Has physical address
    if re.search(r"\d+\s+\w+\s+(street|st\b|avenue|ave\b|road|rd\b|blvd)", body_lower):
        indicators.append(Indicator(severity="INFO", description="Email contains a physical address (common in legitimate business emails)"))
        score += 0.15

    # All URLs are HTTPS
    if urls and all(u.startswith("https://") for u in urls):
        indicators.append(Indicator(severity="INFO", description="All URLs use HTTPS encryption"))
        score += 0.15

    # URLs from well-known domains
    legit_url_domains = ["github.com", "google.com", "microsoft.com", "apple.com", "amazon.com"]
    for url in urls:
        try:
            parsed_host = urlparse(url).hostname or ""
            for ld in legit_url_domains:
                if parsed_host.endswith(ld):
                    indicators.append(Indicator(severity="INFO", description=f"URL points to trusted domain: {ld}"))
                    score += 0.2
                    break
        except Exception:
            pass

    return indicators, min(score, 1.0)


# ─────────────────────────────────────────────────────────────
#  Recommendations Builder
# ─────────────────────────────────────────────────────────────
def build_recommendations(verdict: str, indicators: list[Indicator], urls: list[UrlAnalysis]) -> list[Recommendation]:
    recs: list[Recommendation] = []

    if verdict == "PHISHING":
        recs += [
            Recommendation(icon="🚫", text="Do NOT click any links in this email."),
            Recommendation(icon="🗑️", text="Delete this email immediately from your inbox."),
            Recommendation(icon="⚠️", text="Do not reply or provide any personal information."),
            Recommendation(icon="🔒", text="If you may have clicked a link, change your passwords immediately."),
            Recommendation(icon="📧", text="Report this email as phishing to your email provider."),
            Recommendation(icon="🏦", text="If financial info was shared, contact your bank immediately."),
        ]
    elif verdict == "SUSPICIOUS":
        recs += [
            Recommendation(icon="⚠️", text="Exercise extreme caution with this email."),
            Recommendation(icon="🔗", text="Verify any links by hovering over them before clicking."),
            Recommendation(icon="📞", text="Contact the sender through official channels to verify the email."),
            Recommendation(icon="🔍", text="Do not download attachments from this email."),
        ]
    else:
        recs += [
            Recommendation(icon="✅", text="This email appears legitimate, but always stay cautious."),
            Recommendation(icon="🔗", text="Verify links by checking the destination URL before clicking."),
            Recommendation(icon="🔒", text="Keep your account credentials secure and never share them via email."),
        ]

    # Add URL-specific rec
    has_shortener = any(
        any(f.label == "URL Shortener" for f in u.flags) for u in urls
    )
    if has_shortener:
        recs.append(Recommendation(icon="🔗", text="Shortened URLs were detected — use a URL expander to preview destinations."))

    return recs


# ─────────────────────────────────────────────────────────────
#  Risk Score Computation
# ─────────────────────────────────────────────────────────────
def compute_risk_score(
    url_risk: float,
    sender_risk: float,
    content_risk: float,
    urgency_score: float,
    legitimacy: float,
) -> int:
    """
    Weighted combination of risk factors.
    """
    raw = (
        url_risk      * 0.35 +
        sender_risk   * 0.25 +
        content_risk  * 0.25 +
        urgency_score * 0.15
    ) - legitimacy * 0.15

    score = max(0.0, min(raw, 1.0))
    return int(round(score * 100))


def get_verdict(score: int) -> str:
    if score >= 60:
        return "PHISHING"
    elif score >= 30:
        return "SUSPICIOUS"
    return "LEGITIMATE"


# ─────────────────────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────────────────────
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

@app.get("/")
def serve_index():
    """Serve main web UI."""
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"status": "ok", "message": "PhishGuard API is running. Visit /docs for API documentation."}

@app.get("/style.css")
def serve_css():
    """Serve CSS stylesheet."""
    css_path = os.path.join(FRONTEND_DIR, "style.css")
    if os.path.exists(css_path):
        return FileResponse(css_path, media_type="text/css")
    raise HTTPException(status_code=404, detail="style.css not found")

@app.get("/app.js")
def serve_js():
    """Serve frontend JavaScript."""
    js_path = os.path.join(FRONTEND_DIR, "app.js")
    if os.path.exists(js_path):
        return FileResponse(js_path, media_type="application/javascript")
    raise HTTPException(status_code=404, detail="app.js not found")

@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "PhishGuard API", "version": "1.0.0"}


@app.post("/analyze", response_model=AnalysisResponse)
def analyze_email(req: EmailRequest):
    """
    Analyze an email for phishing indicators.
    Accepts sender, subject, and body; returns full analysis report.
    """
    sender  = (req.sender  or "").strip()
    subject = (req.subject or "").strip()
    body    = (req.body    or "").strip()

    if not sender and not subject and not body:
        raise HTTPException(status_code=422, detail="Please provide at least one field (sender, subject, or body).")

    # --- URL Analysis ---
    all_text = f"{sender} {subject} {body}"
    raw_urls = extract_urls(all_text)
    url_analyses: list[UrlAnalysis] = []
    url_risks: list[float] = []

    for raw_url in raw_urls[:15]:  # cap at 15 URLs
        analysis, risk = analyze_url(raw_url)
        url_analyses.append(analysis)
        url_risks.append(risk)

    url_risk_score = max(url_risks) if url_risks else 0.0

    # --- Sender Analysis ---
    sender_indicators, sender_risk = analyze_sender(sender)

    # --- Content Analysis ---
    content_indicators, content_risk, urgency_score = analyze_content(subject, body)

    # --- Legitimacy ---
    legit_indicators, legitimacy_score = compute_legitimacy(sender, body, raw_urls)

    # --- Final Score ---
    risk_score = compute_risk_score(
        url_risk_score, sender_risk, content_risk,
        urgency_score, legitimacy_score
    )
    verdict = get_verdict(risk_score)

    # --- Combine all indicators ---
    all_indicators = sender_indicators + content_indicators + legit_indicators

    # Sort: HIGH → MEDIUM → LOW → INFO
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    all_indicators.sort(key=lambda x: severity_order.get(x.severity, 4))

    # --- Recommendations ---
    recommendations = build_recommendations(verdict, all_indicators, url_analyses)

    return AnalysisResponse(
        verdict=verdict,
        risk_score=risk_score,
        breakdown=Breakdown(
            url_risk=round(url_risk_score, 3),
            sender_risk=round(sender_risk, 3),
            content_risk=round(content_risk, 3),
            urgency_score=round(urgency_score, 3),
            legitimacy=round(legitimacy_score, 3),
        ),
        indicators=all_indicators,
        url_analysis=url_analyses,
        recommendations=recommendations,
    )


# ─────────────────────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
