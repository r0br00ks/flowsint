from typing import Any, Dict, List

from flowsint_enrichers import osint_http as oh
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.otx_base import OtxEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ip import Ip
from flowsint_types.reputation_score import ReputationScore


@flowsint_enricher
class IpToOtx(OtxEnricher):
    """[AlienVault OTX] Whether an IP address appears in threat-intelligence pulses. No key needed."""

    InputType = Ip
    OutputType = ReputationScore
    INDICATOR_KIND = "IPv4"
    ENTITY_TYPE = "ip"

    @classmethod
    def name(cls) -> str:
        return "ip_to_otx"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def key(cls) -> str:
        return "address"

    def indicator_of(self, item) -> str:
        return item.address


@flowsint_enricher
class IpToGreyNoise(FetchEnricher):
    """[GreyNoise community] Whether an IP is mass-scanning the internet (noise) or a known benign service (RIOT). No key, low rate limit."""

    InputType = Ip
    OutputType = ReputationScore
    RELATIONSHIP = "HAS_REPUTATION"
    SOURCE = "GreyNoise"

    @classmethod
    def name(cls) -> str:
        return "ip_to_greynoise"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def key(cls) -> str:
        return "address"

    def label_of(self, item) -> str:
        return item.address

    async def fetch(self, item) -> Dict[str, Any]:
        r = await oh.get(f"https://api.greynoise.io/v3/community/{item.address}", ok=(200, 404))
        return r.json()

    def build(self, item, data: Dict[str, Any]) -> List[ReputationScore]:
        cls = data.get("classification")
        if data.get("riot"):
            score, factors = 100.0, [f"known benign service: {data.get('name') or 'RIOT'}"]
        elif data.get("noise"):
            score = {"malicious": 10.0, "benign": 80.0}.get(cls, 50.0)
            factors = [f"scanning the internet, classified {cls or 'unknown'}"] + ([data["name"]] if data.get("name") else [])
        else:
            score, factors = None, [data.get("message") or "not observed scanning the internet"]
        return [
            ReputationScore(
                entity_id=item.address,
                entity_type="ip",
                score=score,
                score_type="greynoise",
                provider="GreyNoise community",
                last_updated=data.get("last_seen"),
                factors=factors,
                category=cls,
            )
        ]


InputType = Ip
OutputType = ReputationScore
