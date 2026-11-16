from typing import Optional

from flowsint_core.utils import is_valid_domain
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_enrichers.spiderfoot_base import SpiderFootEnricher
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip


@flowsint_enricher
class IpToDomainsSpiderFoot(SpiderFootEnricher):
    """[SpiderFoot] Domains and sites hosted on an IP address, from the dockerops SpiderFoot."""

    InputType = Ip
    OutputType = Domain
    EVENT_TYPES = ["CO_HOSTED_SITE", "INTERNET_NAME"]
    RELATIONSHIP = "HOSTS_DOMAIN"

    @classmethod
    def name(cls) -> str:
        return "ip_to_domains_spiderfoot"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def key(cls) -> str:
        return "address"

    def target_of(self, item) -> str:
        return item.address

    def make_output(self, value: str) -> Optional[Domain]:
        v = value.strip().lower().rstrip(".")
        return Domain(domain=v) if is_valid_domain(v) else None


InputType = IpToDomainsSpiderFoot.InputType
OutputType = IpToDomainsSpiderFoot.OutputType
