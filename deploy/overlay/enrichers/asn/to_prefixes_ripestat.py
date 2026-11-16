from typing import Any, Dict, List

from flowsint_enrichers import osint_http as oh
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.asn import ASN
from flowsint_types.cidr import CIDR


@flowsint_enricher
class AsnToPrefixesRipeStat(FetchEnricher):
    """[RIPEstat] The IP prefixes an autonomous system announces. No key needed."""

    InputType = ASN
    OutputType = CIDR
    RELATIONSHIP = "ANNOUNCES"
    SOURCE = "RIPEstat"

    @classmethod
    def name(cls) -> str:
        return "asn_to_prefixes_ripestat"

    @classmethod
    def category(cls) -> str:
        return "ASN"

    @classmethod
    def key(cls) -> str:
        return "asn_str"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [{"name": "max_results", "type": "string", "description": "Return at most this many prefixes.", "required": False, "default": "200"}]

    def label_of(self, item) -> str:
        return item.asn_str

    async def fetch(self, item) -> List[str]:
        j = await oh.get_json("https://stat.ripe.net/data/announced-prefixes/data.json", params={"resource": item.asn_str})
        return [p["prefix"] for p in j.get("data", {}).get("prefixes", [])]

    def build(self, item, data: List[str]) -> List[CIDR]:
        limit = int(float(self.params.get("max_results") or 200))
        return [CIDR(network=p) for p in data[:limit]]


InputType = AsnToPrefixesRipeStat.InputType
OutputType = AsnToPrefixesRipeStat.OutputType
