from typing import Optional

from flowsint_enrichers.registry import flowsint_enricher
from flowsint_enrichers.spiderfoot_base import SpiderFootEnricher
from flowsint_types.domain import Domain
from flowsint_types.email import Email


@flowsint_enricher
class DomainToEmailsSpiderFoot(SpiderFootEnricher):
    """[SpiderFoot] Email addresses found for a domain, from the dockerops SpiderFoot."""

    InputType = Domain
    OutputType = Email
    EVENT_TYPES = ["EMAILADDR", "EMAILADDR_GENERIC"]
    RELATIONSHIP = "HAS_EMAIL"

    @classmethod
    def name(cls) -> str:
        return "domain_to_emails_spiderfoot"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    def target_of(self, item) -> str:
        return item.domain

    def make_output(self, value: str) -> Optional[Email]:
        try:
            return Email(email=value.strip().lower())
        except Exception:
            return None


InputType = DomainToEmailsSpiderFoot.InputType
OutputType = DomainToEmailsSpiderFoot.OutputType
