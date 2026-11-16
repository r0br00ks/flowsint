import re
from datetime import date
from typing import Any, Dict, List, Optional

from flowsint_enrichers import dns_doh
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.finding import Finding


def _txt(records: List[Dict[str, Any]]) -> List[str]:
    return [dns_doh.unquote_txt(r["data"]) for r in records if r["type"] == "TXT"]


@flowsint_enricher
class DomainToEmailSecurity(FetchEnricher):
    """[DNS] Checks SPF, DMARC, CAA and DNSSEC of a domain and reports the weak spots as findings."""

    InputType = Domain
    OutputType = Finding
    RELATIONSHIP = "HAS_FINDING"
    SOURCE = "DNS check"

    @classmethod
    def name(cls) -> str:
        return "domain_to_email_security"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    def label_of(self, item) -> str:
        return item.domain

    async def fetch(self, item) -> Dict[str, Any]:
        d = item.domain
        apex, _ = await dns_doh.query(d, "TXT")
        dmarc, _ = await dns_doh.query(f"_dmarc.{d}", "TXT")
        mx, _ = await dns_doh.query(d, "MX")
        caa, _ = await dns_doh.query(d, "CAA")
        _, ad = await dns_doh.query(d, "DNSKEY", dnssec=True)
        return {
            "spf": [t for t in _txt(apex) if t.lower().startswith("v=spf1")],
            "dmarc": [t for t in _txt(dmarc) if t.lower().startswith("v=dmarc1")],
            "has_mx": bool(mx),
            "caa": [r for r in caa if r["type"] == "CAA"],
            "dnssec": ad,
        }

    def build(self, item, data: Dict[str, Any]) -> List[Finding]:
        d = item.domain
        today = date.today().isoformat()
        out: List[Finding] = []

        def add(check: str, severity: str, title: str, detail: Optional[str] = None) -> None:
            out.append(
                Finding(
                    finding_id=f"dns-{d}-{check}",
                    title=title,
                    severity=severity,
                    status="Open" if severity != "Info" else "Info",
                    component=detail,
                    date=today,
                    source="DNS check",
                )
            )

        spf = data["spf"]
        if not spf:
            add("spf-missing", "Medium" if data["has_mx"] else "Low", f"{d}: no SPF record")
        elif len(spf) > 1:
            add("spf-multiple", "Medium", f"{d}: more than one SPF record (SPF fails when there are several)", " | ".join(spf))
        else:
            m = re.search(r"([+\-~?]?)all\b", spf[0])
            q = m.group(1) if m else ""
            if q == "+" or (m and q == ""):
                add("spf-allow-all", "High", f"{d}: SPF allows any sender (+all)", spf[0])
            elif q == "?":
                add("spf-neutral", "Medium", f"{d}: SPF ends in ?all, so it gives no protection", spf[0])
            elif q == "~":
                add("spf-softfail", "Low", f"{d}: SPF ends in ~all (soft fail); -all rejects spoofed mail", spf[0])
            elif q == "-":
                add("spf-ok", "Info", f"{d}: SPF ends in -all", spf[0])
            if len(re.findall(r"\b(?:include|a|mx|ptr|exists|redirect)[:=]", spf[0])) > 10:
                add("spf-lookups", "Low", f"{d}: SPF may exceed the 10 DNS lookup limit", spf[0])

        dm = data["dmarc"]
        if not dm:
            add("dmarc-missing", "Medium" if data["has_mx"] else "Low", f"{d}: no DMARC record")
        else:
            tags = dict(
                (k.strip().lower(), v.strip()) for k, _, v in (p.partition("=") for p in dm[0].split(";")) if k.strip()
            )
            pol = tags.get("p", "").lower()
            if pol == "none":
                add("dmarc-none", "Medium", f"{d}: DMARC policy is none (monitoring only, spoofed mail still delivered)", dm[0])
            elif pol == "quarantine":
                add("dmarc-quarantine", "Info", f"{d}: DMARC policy is quarantine", dm[0])
            elif pol == "reject":
                add("dmarc-reject", "Info", f"{d}: DMARC policy is reject", dm[0])
            if pol in ("quarantine", "reject") and tags.get("pct", "100") != "100":
                add("dmarc-pct", "Low", f"{d}: DMARC applies to only {tags['pct']}% of mail", dm[0])
            if "rua" not in tags:
                add("dmarc-no-rua", "Low", f"{d}: DMARC has no aggregate report address (rua)", dm[0])

        if not data["caa"]:
            add("caa-missing", "Low", f"{d}: no CAA record, so any certificate authority may issue certificates")
        if not data["dnssec"]:
            add("dnssec-off", "Info", f"{d}: DNSSEC is not validating")
        return out


InputType = DomainToEmailSecurity.InputType
OutputType = DomainToEmailSecurity.OutputType
