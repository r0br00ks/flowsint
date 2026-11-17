"""Maltego's "Run All Transforms": run every eligible enricher for a node's type, then for the type of each result.

The list is built from the enricher registry when the machine starts, so a newly added enricher is included without
editing anything. Left out on purpose: active scanners (they need `authorized=yes` and a human decision), other machines,
the n8n connector, slow third-party site searches (Maigret, Sherlock), SpiderFoot (starts a long scan), and paid-key sources
that would only log a failure.
"""

from typing import Any, Dict, List

from flowsint_enrichers.machine_base import MachineEnricher
from flowsint_enrichers.osint_base import ActiveEnricher
from flowsint_enrichers.registry import ENRICHER_REGISTRY, flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.email import Email
from flowsint_types.ip import Ip
from flowsint_types.username import Username
from flowsint_types.website import Website

SKIP_WORDS = ("dummy", "spiderfoot", "dehashed", "whois_history", "domain_to_history", "socials_maigret", "socials_sherlock", "xalgorix")
# ip_to_ports is a naabu port scan (active, though upstream does not mark it so); cidr_to_ips would fan a network range out
# into unrelated addresses; the crawler follows links across a whole site.
SKIP_NAMES = {"n8n_connector", "ip_to_ports", "cidr_to_ips", "website_to_crawler"}


def eligible_by_type() -> Dict[str, List[str]]:
    reg = getattr(ENRICHER_REGISTRY, "enrichers", None) or getattr(ENRICHER_REGISTRY, "_enrichers", None) or {}
    out: Dict[str, List[str]] = {}
    for name, cls in sorted(reg.items()):
        if name.startswith("machine_") or name in SKIP_NAMES or any(w in name for w in SKIP_WORDS):
            continue
        if isinstance(cls, type) and issubclass(cls, ActiveEnricher):
            continue
        t = getattr(getattr(cls, "InputType", None), "__name__", None)
        if t and t not in ("Any", "?"):
            out.setdefault(t, []).append(name)
    return out


class _RunAll(MachineEnricher):
    ROOT_TYPE = ""

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        schema = [dict(p) for p in super().get_params_schema()]
        for p in schema:
            if p["name"] == "max_depth":
                p["default"] = "2"
                p["description"] = "How many levels to follow. 1 is Maltego's Run All on this one node; 2 also enriches what that finds."
        return schema

    def root_steps(self) -> List[str]:
        return eligible_by_type().get(self.ROOT_TYPE, [])

    def rules(self) -> Dict[str, List[str]]:
        return eligible_by_type()


@flowsint_enricher
class RunAllDomain(_RunAll):
    """[Machine] Run all: every eligible passive enricher on a domain, then on what they find (IPs, websites, emails, wallets, technologies, CVEs ...). Same idea as Maltego's Run All Transforms."""

    InputType = Domain
    OutputType = Domain
    ROOT_TYPE = "Domain"

    @classmethod
    def name(cls) -> str:
        return "machine_run_all_domain"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"


@flowsint_enricher
class RunAllIp(_RunAll):
    """[Machine] Run all: every eligible passive enricher on an IP address, then on what they find."""

    InputType = Ip
    OutputType = Ip
    ROOT_TYPE = "Ip"

    @classmethod
    def name(cls) -> str:
        return "machine_run_all_ip"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def key(cls) -> str:
        return "address"


@flowsint_enricher
class RunAllEmail(_RunAll):
    """[Machine] Run all: every eligible passive enricher on an email address (domain, Gravatar, GitHub, username, breach and infostealer exposure), then on what they find."""

    InputType = Email
    OutputType = Email
    ROOT_TYPE = "Email"

    @classmethod
    def name(cls) -> str:
        return "machine_run_all_email"

    @classmethod
    def category(cls) -> str:
        return "Email"

    @classmethod
    def key(cls) -> str:
        return "email"


@flowsint_enricher
class RunAllWebsite(_RunAll):
    """[Machine] Run all: every eligible passive enricher on a website (headers, technologies, TLS, links, wallets, emails, phones), then on what they find."""

    InputType = Website
    OutputType = Website
    ROOT_TYPE = "Website"

    @classmethod
    def name(cls) -> str:
        return "machine_run_all_website"

    @classmethod
    def category(cls) -> str:
        return "Website"

    @classmethod
    def key(cls) -> str:
        return "url"


@flowsint_enricher
class RunAllUsername(_RunAll):
    """[Machine] Run all: every eligible enricher on a username. Maigret and Sherlock site searches stay in machine_username_recon, which has an explicit switch for them."""

    InputType = Username
    OutputType = Username
    ROOT_TYPE = "Username"

    @classmethod
    def name(cls) -> str:
        return "machine_run_all_username"

    @classmethod
    def category(cls) -> str:
        return "Username"

    @classmethod
    def key(cls) -> str:
        return "value"


InputType = RunAllDomain.InputType
OutputType = RunAllDomain.OutputType
