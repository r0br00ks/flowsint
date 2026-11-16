"""AlienVault OTX threat-intelligence reputation (the anonymous 'general' endpoint, no key)."""

from typing import Any, Dict, List

from flowsint_enrichers import osint_http as oh
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_types.reputation_score import ReputationScore


class OtxEnricher(FetchEnricher):
    """Not registered itself; concrete enrichers subclass it and add @flowsint_enricher."""

    RELATIONSHIP = "HAS_REPUTATION"
    SOURCE = "AlienVault OTX"
    INDICATOR_KIND = "domain"  # OTX path segment: domain or IPv4
    ENTITY_TYPE = "domain"

    def indicator_of(self, item: Any) -> str:
        raise NotImplementedError

    def label_of(self, item: Any) -> str:
        return self.indicator_of(item)

    async def fetch(self, item: Any) -> Dict[str, Any]:
        ind = self.indicator_of(item)
        return await oh.get_json(f"https://otx.alienvault.com/api/v1/indicators/{self.INDICATOR_KIND}/{ind}/general")

    def build(self, item: Any, data: Dict[str, Any]) -> List[ReputationScore]:
        info = data.get("pulse_info") or {}
        count = int(info.get("count") or 0)
        names = [p.get("name", "") for p in (info.get("pulses") or [])][:10]
        return [
            ReputationScore(
                entity_id=self.indicator_of(item),
                entity_type=self.ENTITY_TYPE,
                score=float(max(0, 100 - 10 * count)),
                score_type="otx-pulses",
                provider="AlienVault OTX",
                factors=[f"in {count} OTX pulse(s)"] + names if count else ["not in any OTX pulse"],
                category="threat-intel",
            )
        ]
