import ipaddress
from typing import Optional

from flowsint_enrichers.registry import flowsint_enricher
from flowsint_enrichers.spiderfoot_base import SpiderFootEnricher
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip


@flowsint_enricher
class DomainToIpsSpiderFoot(SpiderFootEnricher):
    """[SpiderFoot] IP addresses linked to a domain, from the dockerops SpiderFoot."""

    InputType = Domain
    OutputType = Ip
    EVENT_TYPES = ["IP_ADDRESS", "IPV6_ADDRESS"]
    RELATIONSHIP = "RESOLVES_TO"

    @classmethod
    def name(cls) -> str:
        return "domain_to_ips_spiderfoot"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    def target_of(self, item) -> str:
        return item.domain

    def make_output(self, value: str) -> Optional[Ip]:
        try:
            ipaddress.ip_address(value.strip())
        except ValueError:
            return None
        return Ip(address=value.strip())


InputType = DomainToIpsSpiderFoot.InputType
OutputType = DomainToIpsSpiderFoot.OutputType
