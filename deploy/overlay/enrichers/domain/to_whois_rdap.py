from typing import Any, Dict, List, Optional

from flowsint_enrichers import osint_http as oh
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.whois import Whois


def _vcard(entity: Dict[str, Any], field: str) -> Optional[str]:
    for row in (entity.get("vcardArray") or [None, []])[1]:
        if row and row[0] == field:
            return str(row[3])
    return None


@flowsint_enricher
class DomainToWhoisRdap(FetchEnricher):
    """[RDAP] Registration data of a domain from its registry: registrar, dates, status, name servers. Works for privacy-protected domains, where the classic WHOIS enricher fails."""

    InputType = Domain
    OutputType = Whois
    RELATIONSHIP = "HAS_REGISTRATION"
    SOURCE = "RDAP"

    @classmethod
    def name(cls) -> str:
        return "domain_to_whois_rdap"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    def label_of(self, item) -> str:
        return item.domain

    async def fetch(self, item) -> Dict[str, Any]:
        return await oh.get_json(f"https://rdap.org/domain/{item.domain}")

    def build(self, item, data: Dict[str, Any]) -> List[Whois]:
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events") or []}
        registrar = None
        for e in data.get("entities") or []:
            if "registrar" in (e.get("roles") or []):
                registrar = _vcard(e, "fn")
        ns = [n.get("ldhName", "").lower() for n in data.get("nameservers") or []]
        return [
            Whois(
                domain=Domain(domain=item.domain),
                registry_domain_id=data.get("handle"),
                registrar=registrar,
                creation_date=events.get("registration"),
                expiration_date=events.get("expiration"),
                last_changed=events.get("last changed"),
                status=", ".join(data.get("status") or []) or None,
                nameservers=", ".join(n for n in ns if n) or None,
                source="RDAP",
            )
        ]


InputType = DomainToWhoisRdap.InputType
OutputType = DomainToWhoisRdap.OutputType
