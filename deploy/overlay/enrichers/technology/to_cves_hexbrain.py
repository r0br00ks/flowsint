from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers import dockerops_clients as dc
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.cve import Cve
from flowsint_types.technology import Technology


def _cve_dicts(node: Any) -> List[Dict[str, Any]]:
    """Collect every CVE record in a HexBrain find_cves result, whichever list it sits in."""
    found: List[Dict[str, Any]] = []
    if isinstance(node, dict):
        cid = node.get("id")
        if isinstance(cid, str) and cid.upper().startswith("CVE-"):
            found.append(node)
        else:
            for v in node.values():
                found.extend(_cve_dicts(v))
    elif isinstance(node, list):
        for v in node:
            found.extend(_cve_dicts(v))
    return found


@flowsint_enricher
class TechnologyToCvesHexBrain(Enricher):
    """[HexBrain] Known CVEs for a technology and version, from the dockerops HexBrain (needs HEXBRAIN_API_KEY on the container)."""

    InputType = Technology
    OutputType = Cve

    @classmethod
    def name(cls) -> str:
        return "technology_to_cves_hexbrain"

    @classmethod
    def category(cls) -> str:
        return "Technology"

    @classmethod
    def key(cls) -> str:
        return "name"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "only_exploited",
                "type": "select",
                "description": "Only CVEs known to be exploited in the wild.",
                "required": False,
                "default": "false",
                "options": [{"label": "All CVEs", "value": "false"}, {"label": "Exploited only", "value": "true"}],
            },
            {
                "name": "max_results",
                "type": "string",
                "description": "Keep at most this many CVEs per technology, highest CVSS first.",
                "required": False,
                "default": "25",
            },
        ]

    async def scan(self, data: List[Technology]) -> List[Dict[str, Any]]:
        only_exploited = str(self.params.get("only_exploited") or "false") == "true"
        limit = int(float(self.params.get("max_results") or 25))
        out: List[Dict[str, Any]] = []
        for tech in data:
            label = f"{tech.name} {tech.version}".strip() if tech.version else tech.name
            try:
                body: Dict[str, Any] = {"technologies": [label]}
                if only_exploited:
                    body["only_exploited"] = True
                resp = await dc.hexbrain_call("find_cves", body)
                seen: Dict[str, Dict[str, Any]] = {}
                for rec in _cve_dicts(resp):
                    seen.setdefault(rec["id"].upper(), rec)
                recs = sorted(seen.values(), key=lambda r: r.get("cvss") or 0, reverse=True)[:limit]
                out.append({"item": tech, "label": label, "cves": recs})
            except Exception as e:  # one failing technology must not kill the batch
                Logger.error(self.sketch_id, {"message": f"[HexBrain] {label} failed: {e}"})
                out.append({"item": tech, "label": label, "cves": []})
        return out

    def postprocess(self, results: List[Dict[str, Any]], input_data: Optional[List[Any]] = None) -> List[Cve]:
        output: List[Cve] = []
        for r in results:
            for rec in r["cves"]:
                cvss = rec.get("cvss")
                cve = Cve(
                    cve_id=rec["id"].upper(),
                    name=rec.get("name"),
                    cvss=float(cvss) if isinstance(cvss, (int, float)) else None,
                    severity=rec.get("severity"),
                    product=rec.get("product"),
                    fixed_in=rec.get("fixed_in"),
                    exploited_in_the_wild=rec.get("exploited_in_the_wild"),
                    published=rec.get("published"),
                    url=rec.get("url"),
                    source="HexBrain",
                )
                self.create_node(r["item"])
                self.create_node(cve)
                self.create_relationship(r["item"], cve, "AFFECTED_BY")
                output.append(cve)
            self.log_graph_message(f"{r['label']} -> {len(r['cves'])} CVE(s) from HexBrain.")
        return output


InputType = TechnologyToCvesHexBrain.InputType
OutputType = TechnologyToCvesHexBrain.OutputType
