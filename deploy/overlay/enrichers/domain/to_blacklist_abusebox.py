from flowsint_enrichers.abusebox_base import AbuseBoxEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.reputation_score import ReputationScore


@flowsint_enricher
class DomainToBlacklistAbuseBox(AbuseBoxEnricher):
    """[AbuseBox] Blocklist (DNSBL) reputation of a domain, from the dockerops AbuseBox."""

    InputType = Domain
    OutputType = ReputationScore
    ENTITY_TYPE = "domain"

    @classmethod
    def name(cls) -> str:
        return "domain_to_blacklist_abusebox"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    def target_of(self, item) -> str:
        return item.domain


InputType = DomainToBlacklistAbuseBox.InputType
OutputType = DomainToBlacklistAbuseBox.OutputType
