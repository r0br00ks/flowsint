"""Shared base for the SpiderFoot enrichers (the SpiderFoot instance on dockerops).

A scan is started with one of SpiderFoot's built-in use cases. The default, "passive", only queries
third-party data sources about the target and does not touch the target itself. "footprint" and
"investigate" probe the target directly, so they are opt-in per run.
A finished scan of the same target is reused for `reuse_hours` so repeated clicks do not start new scans.
"""

from typing import Any, Dict, List, Optional

from flowsint_core.core.logger import Logger
from flowsint_enrichers import dockerops_clients as dc
from flowsint_enrichers.osint_base import ParamsEnricher


class SpiderFootEnricher(ParamsEnricher):
    """Not registered itself; concrete enrichers subclass it and add @flowsint_enricher."""

    EVENT_TYPES: List[str] = []
    RELATIONSHIP = "RELATED_TO"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "scan_mode",
                "type": "select",
                "description": "passive only asks third-party sources. footprint and investigate also probe the target directly.",
                "required": False,
                "default": "passive",
                "options": [
                    {"label": "Passive (does not touch the target)", "value": "passive"},
                    {"label": "Footprint (probes the target)", "value": "footprint"},
                    {"label": "Investigate (probes the target)", "value": "investigate"},
                ],
            },
            {
                "name": "reuse_hours",
                "type": "string",
                "description": "Reuse a finished SpiderFoot scan of the same target newer than this many hours. 0 always scans.",
                "required": False,
                "default": "168",
            },
            {
                "name": "timeout_seconds",
                "type": "string",
                "description": "How long to wait for a new scan before returning what it has found so far.",
                "required": False,
                "default": "600",
            },
        ]

    # Subclasses say how to read the target from the input and how to build outputs.
    def target_of(self, item: Any) -> str:
        raise NotImplementedError

    def make_output(self, value: str) -> Optional[Any]:
        raise NotImplementedError

    def source_object(self, item: Any) -> Any:
        return item

    async def scan(self, data: List[Any]) -> List[Dict[str, Any]]:
        mode = str(self.params.get("scan_mode") or "passive")
        reuse = float(self.params.get("reuse_hours") or 168)
        timeout = float(self.params.get("timeout_seconds") or 600)
        out: List[Dict[str, Any]] = []
        for item in data:
            target = self.target_of(item)
            try:
                scan_id, status, reused = await dc.sf_run(target, mode, reuse, timeout)
                values = await dc.sf_results(scan_id, self.EVENT_TYPES)
                how = "reused scan" if reused else f"new {mode} scan"
                note = "" if status == "FINISHED" else f" (scan not finished: {status}, partial results)"
                Logger.info(self.sketch_id, {"message": f"[SpiderFoot] {target}: {len(values)} value(s) from {how} {scan_id}{note}"})
                out.append({"item": item, "values": values})
            except Exception as e:  # one failing target must not kill the batch
                Logger.error(self.sketch_id, {"message": f"[SpiderFoot] {target} failed: {e}"})
                out.append({"item": item, "values": []})
        return out

    def postprocess(self, results: List[Dict[str, Any]], input_data: Optional[List[Any]] = None) -> List[Any]:
        output: List[Any] = []
        for r in results:
            src = self.source_object(r["item"])
            made = 0
            for value in r["values"]:
                obj = self.make_output(value)
                if obj is None:
                    continue
                self.create_node(src)
                self.create_node(obj)
                self.create_relationship(src, obj, self.RELATIONSHIP)
                output.append(obj)
                made += 1
            self.log_graph_message(f"{self.target_of(r['item'])} -> {made} result(s) from SpiderFoot.")
        return output
