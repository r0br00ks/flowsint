from typing import Any, Dict, List

from flowsint_enrichers import osint_http as oh
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.asn import ASN
from flowsint_types.cidr import CIDR
from flowsint_types.ip import Ip


@flowsint_enricher
class IpToAsnRipeStat(FetchEnricher):
    """[RIPEstat] The autonomous system (ASN) that announces an IP address. No key needed."""

    InputType = Ip
    OutputType = ASN
    RELATIONSHIP = "ANNOUNCED_BY"
    SOURCE = "RIPEstat"

    @classmethod
    def name(cls) -> str:
        return "ip_to_asn_ripestat"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def key(cls) -> str:
        return "address"

    def label_of(self, item) -> str:
        return item.address

    async def fetch(self, item) -> Dict[str, Any]:
        j = await oh.get_json("https://stat.ripe.net/data/prefix-overview/data.json", params={"resource": item.address})
        return j.get("data", {})

    def build(self, item, data: Dict[str, Any]) -> List[ASN]:
        prefix = data.get("resource") or data.get("block", {}).get("resource")
        out = []
        for a in data.get("asns") or []:
            n = int(a["asn"])
            out.append(ASN(asn_str=f"AS{n}", number=n, name=(a.get("holder") or "").strip() or None, cidrs=[CIDR(network=prefix)] if prefix else None))
        return out


InputType = IpToAsnRipeStat.InputType
OutputType = IpToAsnRipeStat.OutputType
