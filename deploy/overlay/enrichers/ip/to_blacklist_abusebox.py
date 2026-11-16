from flowsint_enrichers.abusebox_base import AbuseBoxEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ip import Ip
from flowsint_types.reputation_score import ReputationScore


@flowsint_enricher
class IpToBlacklistAbuseBox(AbuseBoxEnricher):
    """[AbuseBox] Blocklist (DNSBL) reputation of an IP address, from the dockerops AbuseBox."""

    InputType = Ip
    OutputType = ReputationScore
    ENTITY_TYPE = "ip"

    @classmethod
    def name(cls) -> str:
        return "ip_to_blacklist_abusebox"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def key(cls) -> str:
        return "address"

    def target_of(self, item) -> str:
        return item.address


InputType = IpToBlacklistAbuseBox.InputType
OutputType = IpToBlacklistAbuseBox.OutputType
