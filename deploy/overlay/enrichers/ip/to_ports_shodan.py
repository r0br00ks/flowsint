from typing import Any, Dict, List

from flowsint_enrichers import osint_http as oh
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ip import Ip
from flowsint_types.open_port import OpenPort


@flowsint_enricher
class IpToPortsShodan(FetchEnricher):
    """[Shodan] Open ports with the product and version Shodan saw behind each, from its stored scans (needs SHODAN_API_KEY on the container; does not touch the IP)."""

    InputType = Ip
    OutputType = OpenPort
    RELATIONSHIP = "HAS_OPEN_PORT"
    SOURCE = "Shodan"

    @classmethod
    def name(cls) -> str:
        return "ip_to_ports_shodan"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def key(cls) -> str:
        return "address"

    def label_of(self, item) -> str:
        return item.address

    async def fetch(self, item) -> Dict[str, Any]:
        key = oh.env("SHODAN_API_KEY")
        if not key:
            raise oh.SourceError("SHODAN_API_KEY is not set on this container")
        r = await oh.get(f"https://api.shodan.io/shodan/host/{item.address}", params={"key": key}, ok=(200, 404))
        return {} if r.status_code == 404 else r.json()

    def build(self, item, data: Dict[str, Any]) -> List[OpenPort]:
        out, seen = [], set()
        for svc in data.get("data") or []:
            proto = (svc.get("transport") or "tcp").lower()
            key = (svc["port"], proto)
            if key in seen:
                continue
            seen.add(key)
            product = svc.get("product")
            version = svc.get("version")
            banner = " ".join(x for x in (product, version) if x) or None
            out.append(
                OpenPort(
                    endpoint=f"{item.address}:{svc['port']}/{proto}",
                    host=item.address,
                    number=int(svc["port"]),
                    protocol=proto,
                    service=(svc.get("_shodan") or {}).get("module") or product,
                    banner=banner,
                    source="Shodan",
                )
            )
        return sorted(out, key=lambda p: p.number or 0)


InputType = IpToPortsShodan.InputType
OutputType = IpToPortsShodan.OutputType
