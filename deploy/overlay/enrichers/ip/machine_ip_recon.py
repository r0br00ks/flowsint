from flowsint_enrichers.machine_base import IP_STEPS, SHARED_RULES, MachineEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ip import Ip


@flowsint_enricher
class MachineIpRecon(MachineEnricher):
    """[Machine] Full passive recon of an IP address: network owner, ASN, open ports, software, CVEs, host names, reputation and blocklists, then the CVEs' matches in your own findings. Active scanners are never run."""

    InputType = Ip
    OutputType = Ip
    ROOT_STEPS = IP_STEPS
    RULES = dict(SHARED_RULES, Domain=["domain_to_otx", "domain_to_blacklist_abusebox"])

    @classmethod
    def name(cls) -> str:
        return "machine_ip_recon"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def key(cls) -> str:
        return "address"


InputType = MachineIpRecon.InputType
OutputType = MachineIpRecon.OutputType
