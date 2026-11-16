from typing import Any, Dict, List

from flowsint_enrichers.machine_base import SHARED_RULES, MachineEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain


@flowsint_enricher
class MachineDomainRecon(MachineEnricher):
    """[Machine] Full passive recon of a domain: DNS, email security, subdomains, reputation, WHOIS, archived URLs, code mentions, then the IPs, websites, technologies, CVEs and your own findings that follow from them. Active scanners are never run."""

    InputType = Domain
    OutputType = Domain
    ROOT_STEPS = [
        "domain_to_dns_records_doh", "domain_to_ip", "domain_to_email_security", "domain_to_subdomains_passive",
        "domain_to_otx", "domain_to_blacklist_abusebox", "domain_to_whois", "domain_to_website",
        "domain_to_wayback_urls", "domain_to_github_code",
    ]
    RULES = dict(SHARED_RULES, Domain=["domain_to_ip"])

    @classmethod
    def name(cls) -> str:
        return "machine_domain_recon"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return super().get_params_schema() + [
            {
                "name": "include_spiderfoot",
                "type": "select",
                "description": "Also run the SpiderFoot passive scan (reuses a finished scan under a week old; a new one takes many minutes).",
                "required": False,
                "default": "no",
                "options": [{"label": "No", "value": "no"}, {"label": "Yes", "value": "yes"}],
            }
        ]

    def root_steps(self) -> List[str]:
        steps = list(self.ROOT_STEPS)
        if str(self.params.get("include_spiderfoot") or "no") == "yes":
            steps += ["domain_to_subdomains_spiderfoot", "domain_to_ips_spiderfoot", "domain_to_emails_spiderfoot"]
        return steps


InputType = MachineDomainRecon.InputType
OutputType = MachineDomainRecon.OutputType
