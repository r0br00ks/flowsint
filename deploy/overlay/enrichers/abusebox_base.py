"""Shared base for the AbuseBox enrichers (DNSBL reputation of an IP or domain).

Uses AbuseBox's public quick-check, which asks its own recursive resolver about 24 blocklists.
No key is needed. The score is a trust score: 100 when no list reports the target, lower in proportion
to the share of lists that do, and empty when the check was inconclusive.
"""

from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers import dockerops_clients as dc
from flowsint_types.reputation_score import ReputationScore


class AbuseBoxEnricher(Enricher):
    """Not registered itself; concrete enrichers subclass it and add @flowsint_enricher."""

    ENTITY_TYPE = "ip"

    def target_of(self, item: Any) -> str:
        raise NotImplementedError

    async def scan(self, data: List[Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for item in data:
            target = self.target_of(item)
            try:
                result = await dc.abusebox_quick_check(target)
                out.append({"item": item, "target": target, "result": result})
            except Exception as e:  # one failing target must not kill the batch
                Logger.error(self.sketch_id, {"message": f"[AbuseBox] {target} failed: {e}"})
                out.append({"item": item, "target": target, "result": None})
        return out

    def postprocess(self, results: List[Dict[str, Any]], input_data: Optional[List[Any]] = None) -> List[Any]:
        output: List[Any] = []
        for r in results:
            res = r["result"]
            if not res:
                continue
            providers = res.get("providers") or []
            listed = res.get("detected_on") or []
            inconclusive = bool(res.get("is_inconclusive"))
            score: Optional[float] = None
            if providers and not inconclusive:
                score = round(100.0 * (1 - len(listed) / len(providers)), 1)
            rep = ReputationScore(
                entity_id=r["target"],
                entity_type=self.ENTITY_TYPE,
                score=score,
                score_type="dnsbl",
                provider=f"AbuseBox DNSBL ({len(providers)} lists)",
                factors=[f"listed on {x}" for x in listed] or None,
                category=res.get("severity"),
            )
            self.create_node(self.source_object(r["item"]))
            self.create_node(rep)
            self.create_relationship(self.source_object(r["item"]), rep, "HAS_REPUTATION")
            output.append(rep)
            verdict = "inconclusive" if inconclusive else (f"listed on {len(listed)}" if listed else "not listed")
            self.log_graph_message(f"{r['target']}: {verdict} ({len(providers)} blocklists checked).")
        return output

    def source_object(self, item: Any) -> Any:
        return item
