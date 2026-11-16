import re
from typing import Any, Dict, List

from flowsint_core.utils import is_valid_domain
from flowsint_enrichers.internetdb_base import InternetDbEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.cve import Cve
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip
from flowsint_types.open_port import OpenPort
from flowsint_types.technology import Technology


def _cat() -> str:
    return "Ip"


@flowsint_enricher
class IpToPortsInternetDb(InternetDbEnricher):
    """[Shodan InternetDB] Open ports Shodan has seen on an IP. No key, and it does not touch the IP."""

    InputType = Ip
    OutputType = OpenPort
    RELATIONSHIP = "HAS_OPEN_PORT"

    @classmethod
    def name(cls) -> str:
        return "ip_to_ports_internetdb"

    @classmethod
    def category(cls) -> str:
        return _cat()

    @classmethod
    def key(cls) -> str:
        return "address"

    def build(self, item, data: Dict[str, Any]) -> List[OpenPort]:
        return [
            OpenPort(endpoint=f"{item.address}:{p}/tcp", host=item.address, number=int(p), protocol="tcp", source="Shodan InternetDB")
            for p in sorted(data.get("ports") or [])
        ]


@flowsint_enricher
class IpToVulnsInternetDb(InternetDbEnricher):
    """[Shodan InternetDB] CVEs Shodan associates with the services on an IP. Feed them to the HexBrain and DefectDojo enrichers."""

    InputType = Ip
    OutputType = Cve
    RELATIONSHIP = "MAY_BE_AFFECTED_BY"

    @classmethod
    def name(cls) -> str:
        return "ip_to_vulns_internetdb"

    @classmethod
    def category(cls) -> str:
        return _cat()

    @classmethod
    def key(cls) -> str:
        return "address"

    def build(self, item, data: Dict[str, Any]) -> List[Cve]:
        return [Cve(cve_id=v.upper(), source="Shodan InternetDB") for v in sorted(data.get("vulns") or [])]


@flowsint_enricher
class IpToTechnologiesInternetDb(InternetDbEnricher):
    """[Shodan InternetDB] Software (CPE) Shodan fingerprinted on an IP. Feed the result to technology_to_cves_hexbrain."""

    InputType = Ip
    OutputType = Technology
    RELATIONSHIP = "RUNS"

    @classmethod
    def name(cls) -> str:
        return "ip_to_technologies_internetdb"

    @classmethod
    def category(cls) -> str:
        return _cat()

    @classmethod
    def key(cls) -> str:
        return "address"

    def build(self, item, data: Dict[str, Any]) -> List[Technology]:
        out, seen = [], set()
        for cpe in data.get("cpes") or []:
            m = re.match(r"cpe:/([aho]):([^:]+):([^:]+)(?::([^:]+))?", cpe)
            if not m:
                continue
            kind, vendor, product, version = m.groups()
            name = product.replace("_", " ")
            if (name, version) in seen:
                continue
            seen.add((name, version))
            out.append(Technology(name=name, version=version, category={"a": "application", "o": "os", "h": "hardware"}[kind], source="Shodan InternetDB"))
        return out


@flowsint_enricher
class IpToHostnamesInternetDb(InternetDbEnricher):
    """[Shodan InternetDB] Host names Shodan has linked to an IP."""

    InputType = Ip
    OutputType = Domain
    RELATIONSHIP = "HAS_HOSTNAME"

    @classmethod
    def name(cls) -> str:
        return "ip_to_hostnames_internetdb"

    @classmethod
    def category(cls) -> str:
        return _cat()

    @classmethod
    def key(cls) -> str:
        return "address"

    def build(self, item, data: Dict[str, Any]) -> List[Domain]:
        return [Domain(domain=h.lower()) for h in sorted(set(data.get("hostnames") or [])) if is_valid_domain(h.lower())]


InputType = Ip
OutputType = OpenPort
