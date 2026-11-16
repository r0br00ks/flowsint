import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from flowsint_enrichers import cli
from flowsint_enrichers.osint_base import ActiveEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ip import Ip
from flowsint_types.open_port import OpenPort


@flowsint_enricher
class IpToPortsNmap(ActiveEnricher):
    """[nmap] Scans an IP for open ports (TCP connect scan, no root needed). ACTIVE: it sends traffic to the target, so it only runs when authorized is set to yes."""

    InputType = Ip
    OutputType = OpenPort
    RELATIONSHIP = "HAS_OPEN_PORT"
    SOURCE = "nmap"

    @classmethod
    def name(cls) -> str:
        return "ip_to_ports_nmap"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def key(cls) -> str:
        return "address"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            cls.authorized_param(),
            {"name": "top_ports", "type": "string", "description": "Scan the N most common TCP ports.", "required": False, "default": "100"},
            {
                "name": "service_detection",
                "type": "select",
                "description": "Also identify the service and version behind each open port (slower, more traffic).",
                "required": False,
                "default": "no",
                "options": [{"label": "No", "value": "no"}, {"label": "Yes", "value": "yes"}],
            },
            {"name": "timeout_seconds", "type": "string", "description": "Stop the scan after this many seconds.", "required": False, "default": "300"},
        ]

    def label_of(self, item) -> str:
        return item.address

    async def fetch(self, item) -> str:
        self.require_authorized()
        top = str(int(float(self.params.get("top_ports") or 100)))
        argv = ["nmap", "-sT", "-Pn", "-n", "-T3", "--top-ports", top, "--open", "-oX", "-"]
        if str(self.params.get("service_detection") or "no") == "yes":
            argv.insert(1, "-sV")
        argv.append(item.address)
        rc, out, err = await cli.run(argv, timeout=float(self.params.get("timeout_seconds") or 300))
        if rc != 0 and "<nmaprun" not in out:
            raise cli.ToolFailed(f"nmap exit {rc}: {err[:200]}")
        return out

    def build(self, item, data: str) -> List[OpenPort]:
        out = []
        for port in ET.fromstring(data).iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            proto = port.get("protocol", "tcp")
            number = int(port.get("portid"))
            product = " ".join(x for x in ((svc.get("product") if svc is not None else None), (svc.get("version") if svc is not None else None)) if x) or None
            out.append(
                OpenPort(
                    endpoint=f"{item.address}:{number}/{proto}",
                    host=item.address,
                    number=number,
                    protocol=proto,
                    service=svc.get("name") if svc is not None else None,
                    banner=product,
                    source="nmap",
                )
            )
        return out


InputType = IpToPortsNmap.InputType
OutputType = IpToPortsNmap.OutputType
