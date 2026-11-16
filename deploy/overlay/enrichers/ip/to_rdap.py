from typing import Any, Dict, List, Optional

from flowsint_enrichers import osint_http as oh
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ip import Ip
from flowsint_types.organization import Organization


def _vcard(entity: Dict[str, Any], field: str) -> Optional[str]:
    for row in (entity.get("vcardArray") or [None, []])[1]:
        if row and row[0] == field:
            return str(row[3])
    return None


@flowsint_enricher
class IpToOrganizationRdap(FetchEnricher):
    """[RDAP] Who the regional registry says owns the network an IP belongs to, with the netblock and abuse contact."""

    InputType = Ip
    OutputType = Organization
    RELATIONSHIP = "OWNED_BY"
    SOURCE = "RDAP"

    @classmethod
    def name(cls) -> str:
        return "ip_to_organization_rdap"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def key(cls) -> str:
        return "address"

    def label_of(self, item) -> str:
        return item.address

    async def fetch(self, item) -> Dict[str, Any]:
        return await oh.get_json(f"https://rdap.org/ip/{item.address}")

    def build(self, item, data: Dict[str, Any]) -> List[Organization]:
        owner = None
        abuse = None
        stack = list(data.get("entities") or [])
        while stack:
            e = stack.pop()
            roles = e.get("roles") or []
            if "registrant" in roles or ("administrative" in roles and not owner):
                owner = owner or _vcard(e, "fn")
            if "abuse" in roles:
                abuse = abuse or _vcard(e, "email")
            stack.extend(e.get("entities") or [])
        name = owner or data.get("name") or ""
        if not name:
            return []
        cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in data.get("cidr0_cidrs") or []]
        return [
            Organization(
                name=name,
                netname=data.get("name"),
                handle=data.get("handle"),
                network=", ".join(cidrs) or None,
                country=data.get("country"),
                abuse_email=abuse,
                source="RDAP",
            )
        ]


InputType = IpToOrganizationRdap.InputType
OutputType = IpToOrganizationRdap.OutputType
