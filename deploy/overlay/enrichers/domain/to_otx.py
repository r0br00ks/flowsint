from flowsint_enrichers.otx_base import OtxEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.reputation_score import ReputationScore


@flowsint_enricher
class DomainToOtx(OtxEnricher):
    """[AlienVault OTX] Whether a domain appears in threat-intelligence pulses. No key needed."""

    InputType = Domain
    OutputType = ReputationScore
    INDICATOR_KIND = "domain"
    ENTITY_TYPE = "domain"

    @classmethod
    def name(cls) -> str:
        return "domain_to_otx"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    def indicator_of(self, item) -> str:
        return item.domain


InputType = DomainToOtx.InputType
OutputType = DomainToOtx.OutputType
