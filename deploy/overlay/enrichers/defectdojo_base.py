"""Shared base for the DefectDojo enrichers: pull findings that are already recorded in your own estate.

Reads findings through the DefectDojo REST API with the importer token (DEFECTDOJO_API_TOKEN on the
container). Only active, non-duplicate findings are returned by default.
"""

from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers import dockerops_clients as dc
from flowsint_types.finding import Finding

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class DefectDojoEnricher(Enricher):
    """Not registered itself; concrete enrichers subclass it and add @flowsint_enricher."""

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "max_results",
                "type": "string",
                "description": "Keep at most this many findings per input, most severe first.",
                "required": False,
                "default": "50",
            },
            {
                "name": "include_inactive",
                "type": "select",
                "description": "Also return mitigated, inactive and duplicate findings.",
                "required": False,
                "default": "false",
                "options": [{"label": "Active only", "value": "false"}, {"label": "Include all", "value": "true"}],
            },
        ]

    def query_for(self, item: Any) -> Dict[str, Any]:
        raise NotImplementedError

    def label_of(self, item: Any) -> str:
        raise NotImplementedError

    async def scan(self, data: List[Any]) -> List[Dict[str, Any]]:
        limit = int(float(self.params.get("max_results") or 50))
        everything = str(self.params.get("include_inactive") or "false") == "true"
        out: List[Dict[str, Any]] = []
        for item in data:
            try:
                q = self.query_for(item)
                if not everything:
                    q.update({"active": "true", "duplicate": "false"})
                rows = await dc.defectdojo_findings(q, 200)
                rows.sort(key=lambda r: SEVERITY_RANK.get(str(r.get("severity", "")).lower(), 9))
                out.append({"item": item, "rows": rows[:limit], "total_seen": len(rows)})
            except Exception as e:  # one failing input must not kill the batch
                Logger.error(self.sketch_id, {"message": f"[DefectDojo] {self.label_of(item)} failed: {e}"})
                out.append({"item": item, "rows": [], "total_seen": 0})
        return out

    def postprocess(self, results: List[Dict[str, Any]], input_data: Optional[List[Any]] = None) -> List[Finding]:
        base = dc.defectdojo_url()
        output: List[Finding] = []
        for r in results:
            for row in r["rows"]:
                vids = [v.get("vulnerability_id") for v in (row.get("vulnerability_ids") or []) if isinstance(v, dict)]
                fid = row.get("id")
                finding = Finding(
                    finding_id=f"dojo-{fid}",
                    title=row.get("title"),
                    severity=row.get("severity"),
                    status=row.get("display_status"),
                    cve=vids[0] if vids else None,
                    component=row.get("component_name"),
                    component_version=row.get("component_version"),
                    date=row.get("date"),
                    url=f"{base}/finding/{fid}",
                    source="DefectDojo",
                )
                self.create_node(r["item"])
                self.create_node(finding)
                self.create_relationship(r["item"], finding, "HAS_FINDING")
                output.append(finding)
            more = f" (showing {len(r['rows'])} of at least {r['total_seen']})" if r["total_seen"] > len(r["rows"]) else ""
            self.log_graph_message(f"{self.label_of(r['item'])} -> {len(r['rows'])} DefectDojo finding(s){more}.")
        return output
