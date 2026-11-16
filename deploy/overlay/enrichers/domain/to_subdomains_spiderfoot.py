from typing import Optional

from flowsint_core.utils import is_valid_domain
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_enrichers.spiderfoot_base import SpiderFootEnricher
from flowsint_types.domain import Domain


@flowsint_enricher
class DomainToSubdomainsSpiderFoot(SpiderFootEnricher):
    """[SpiderFoot] Subdomains and related host names of a domain, from the dockerops SpiderFoot."""

    InputType = Domain
    OutputType = Domain
    EVENT_TYPES = ["INTERNET_NAME"]
    RELATIONSHIP = "HAS_SUBDOMAIN"

    @classmethod
    def name(cls) -> str:
        return "domain_to_subdomains_spiderfoot"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    def target_of(self, item) -> str:
        return item.domain

    def make_output(self, value: str) -> Optional[Domain]:
        v = value.strip().lower().rstrip(".")
        return Domain(domain=v) if is_valid_domain(v) else None


InputType = DomainToSubdomainsSpiderFoot.InputType
OutputType = DomainToSubdomainsSpiderFoot.OutputType
