import xml.etree.ElementTree as ET
from datetime import date, datetime
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from flowsint_enrichers import cli
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.finding import Finding
from flowsint_types.website import Website

WEAK_WORDS = ("NULL", "EXPORT", "RC4", "DES-CBC", "3DES", "anon", "MD5")


def _host_port(url: str) -> Tuple[str, int]:
    p = urlparse(url if "://" in url else "https://" + url)
    return p.hostname or "", p.port or (80 if p.scheme == "http" else 443)


@flowsint_enricher
class WebsiteToTlsSslScan(FetchEnricher):
    """[sslscan] Checks a site's TLS setup: old protocol versions, weak ciphers, certificate expiry. Makes a few TLS handshakes, no attack traffic."""

    InputType = Website
    OutputType = Finding
    RELATIONSHIP = "HAS_FINDING"
    SOURCE = "sslscan"

    @classmethod
    def name(cls) -> str:
        return "website_to_tls_sslscan"

    @classmethod
    def category(cls) -> str:
        return "Website"

    @classmethod
    def key(cls) -> str:
        return "url"

    def label_of(self, item) -> str:
        return str(item.url)

    async def fetch(self, item) -> str:
        host, port = _host_port(str(item.url))
        rc, out, err = await cli.run(["sslscan", "--xml=-", "--no-colour", "--no-heartbleed", f"{host}:{port}"], timeout=180)
        if "<document" not in out:
            raise cli.ToolFailed(f"sslscan returned no XML (exit {rc}): {(err or out)[:160]}")
        return out

    def build(self, item, data: str) -> List[Finding]:
        host, port = _host_port(str(item.url))
        root = ET.fromstring(data)
        today = date.today().isoformat()
        out: List[Finding] = []

        def add(check: str, severity: str, title: str, detail: str = "") -> None:
            out.append(Finding(finding_id=f"tls-{host}:{port}-{check}", title=f"{host}:{port}: {title}", severity=severity, status="Open", component=detail or None, date=today, source="sslscan"))

        enabled = {}
        for p in root.iter("protocol"):
            enabled[f"{p.get('type', '').upper()} {p.get('version', '')}".strip()] = p.get("enabled") == "1"
        for name in ("SSLv2", "SSLv3"):
            key = f"SSL {name[-1]}"
            if enabled.get(key):
                add(name.lower(), "High", f"{name} is enabled")
        for ver in ("1.0", "1.1"):
            if enabled.get(f"TLS {ver}"):
                add(f"tls{ver.replace('.', '')}", "Medium", f"TLS {ver} is enabled (deprecated)")
        if enabled and not enabled.get("TLS 1.3"):
            add("no-tls13", "Info", "TLS 1.3 is not supported")

        weak = sorted({c.get("cipher", "") for c in root.iter("cipher") if c.get("status") == "accepted" and any(w in c.get("cipher", "") for w in WEAK_WORDS)})
        if weak:
            add("weak-ciphers", "Medium", f"{len(weak)} weak cipher(s) accepted", ", ".join(weak[:8]))

        for cert in root.iter("certificate"):
            if (cert.findtext("expired") or "").lower() == "true":
                add("cert-expired", "High", "certificate has expired", cert.findtext("not-valid-after") or "")
            if (cert.findtext("self-signed") or "").lower() == "true":
                add("cert-self-signed", "Medium", "certificate is self-signed", cert.findtext("subject") or "")
            nva = cert.findtext("not-valid-after")
            if nva:
                try:
                    days = (datetime.strptime(nva.strip(), "%b %d %H:%M:%S %Y GMT") - datetime.utcnow()).days
                    if 0 <= days < 30:
                        add("cert-expiring", "Low", f"certificate expires in {days} day(s)", nva)
                except ValueError:
                    pass
            break  # first certificate is the server's; the rest are the chain
        return out


InputType = WebsiteToTlsSslScan.InputType
OutputType = WebsiteToTlsSslScan.OutputType
