from flowsint_enrichers.machine_base import MachineEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.email import Email


@flowsint_enricher
class MachineEmailRecon(MachineEnricher):
    """[Machine] Recon of an email address: its domain, Gravatar, GitHub accounts, infostealer exposure, then the domain's DNS, email security and reputation."""

    InputType = Email
    OutputType = Email
    ROOT_STEPS = ["email_to_domain", "email_to_gravatar", "email_to_github_accounts", "email_to_device_hudsonrock"]
    RULES = {"Domain": ["domain_to_dns_records_doh", "domain_to_email_security", "domain_to_otx"]}

    @classmethod
    def name(cls) -> str:
        return "machine_email_recon"

    @classmethod
    def category(cls) -> str:
        return "Email"

    @classmethod
    def key(cls) -> str:
        return "email"


InputType = MachineEmailRecon.InputType
OutputType = MachineEmailRecon.OutputType
