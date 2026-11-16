from datetime import date
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx

from flowsint_enrichers import osint_http as oh
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.finding import Finding
from flowsint_types.website import Website

# header, severity if missing, why it matters
EXPECTED = [
    ("strict-transport-security", "Medium", "no HSTS: browsers may be downgraded to plain HTTP"),
    ("content-security-policy", "Low", "no Content-Security-Policy: no browser-side limit on injected scripts"),
    ("x-content-type-options", "Low", "no X-Content-Type-Options: nosniff"),
    ("referrer-policy", "Info", "no Referrer-Policy"),
    ("permissions-policy", "Info", "no Permissions-Policy"),
]


@flowsint_enricher
class WebsiteToSecurityHeaders(FetchEnricher):
    """[HTTP] Reads a page's response headers and reports missing security headers, version disclosure and unsafe cookies. One ordinary GET request."""

    InputType = Website
    OutputType = Finding
    RELATIONSHIP = "HAS_FINDING"
    SOURCE = "security headers"

    @classmethod
    def name(cls) -> str:
        return "website_to_security_headers"

    @classmethod
    def category(cls) -> str:
        return "Website"

    @classmethod
    def key(cls) -> str:
        return "url"

    def label_of(self, item) -> str:
        return str(item.url)

    async def fetch(self, item) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True, headers={"User-Agent": oh.USER_AGENT}) as c:
            r = await c.get(str(item.url))
        return {"final_url": str(r.url), "status": r.status_code, "headers": {k.lower(): v for k, v in r.headers.items()}, "cookies": r.headers.get_list("set-cookie")}

    def build(self, item, data: Dict[str, Any]) -> List[Finding]:
        host = urlparse(data["final_url"]).hostname or str(item.url)
        h = data["headers"]
        today = date.today().isoformat()
        out: List[Finding] = []

        def add(check: str, severity: str, title: str, detail: str = "") -> None:
            out.append(Finding(finding_id=f"hdr-{host}-{check}", title=f"{host}: {title}", severity=severity, status="Open" if severity != "Info" else "Info", component=detail or None, date=today, source="security headers", url=data["final_url"]))

        https = data["final_url"].startswith("https://")
        for header, sev, why in EXPECTED:
            if header == "strict-transport-security" and not https:
                continue
            if header not in h:
                add(f"missing-{header}", sev, why)
        if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
            add("missing-clickjacking", "Low", "no clickjacking protection (X-Frame-Options or frame-ancestors)")
        for disclosing in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            v = h.get(disclosing, "")
            if v and any(ch.isdigit() for ch in v):
                add(f"discloses-{disclosing}", "Low", f"{disclosing} header discloses a version", v)
        for cookie in data["cookies"]:
            name = cookie.split("=", 1)[0]
            low = cookie.lower()
            flaws = [f for f, bad in (("Secure", "secure" not in low), ("HttpOnly", "httponly" not in low)) if bad]
            if flaws:
                add(f"cookie-{name}", "Low", f"cookie {name} lacks {' and '.join(flaws)}")
        return out


InputType = WebsiteToSecurityHeaders.InputType
OutputType = WebsiteToSecurityHeaders.OutputType
