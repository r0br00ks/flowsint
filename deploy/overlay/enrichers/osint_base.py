"""Base classes that keep each new data-source enricher down to its fetch and its mapping.

FetchEnricher: for each input, `fetch()` gets raw data (one failing input never kills the batch) and `build()`
turns it into typed entities. An entity may be returned alone or as an (entity, relationship_label) pair.

ActiveEnricher: for tools that send traffic to the target. Refuses to run unless the run's `authorized`
parameter is set to "yes", so a stray click cannot start a scan.
"""

from typing import Any, Dict, List, Optional, Tuple

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_core.core.vault import VaultProtocol


class ParamsEnricher(Enricher):
    """Hands get_params_schema() to the base class.

    Flowsint keeps only the run parameters named in the schema given to Enricher.__init__ and drops the rest.
    An enricher that declares parameters but does not pass the schema silently ignores every value set in the UI.
    """

    def __init__(
        self,
        sketch_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        vault: Optional[VaultProtocol] = None,
        params: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ):
        super().__init__(sketch_id=sketch_id, scan_id=scan_id, params_schema=self.get_params_schema(), vault=vault, params=params, **kwargs)


class FetchEnricher(ParamsEnricher):
    """Not registered itself; concrete enrichers subclass it and add @flowsint_enricher."""

    RELATIONSHIP = "RELATED_TO"
    SOURCE = "source"

    def label_of(self, item: Any) -> str:
        raise NotImplementedError

    async def fetch(self, item: Any) -> Any:
        raise NotImplementedError

    def build(self, item: Any, data: Any) -> List[Any]:
        raise NotImplementedError

    async def scan(self, data: List[Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for item in data:
            try:
                raw = await self.fetch(item)
                out.append({"item": item, "data": raw, "ok": True})
            except Exception as e:  # one failing input must not kill the batch
                Logger.error(self.sketch_id, {"message": f"[{self.SOURCE}] {self.label_of(item)} failed: {e}"})
                out.append({"item": item, "data": None, "ok": False})
        return out

    def postprocess(self, results: List[Dict[str, Any]], input_data: Optional[List[Any]] = None) -> List[Any]:
        output: List[Any] = []
        for r in results:
            if not r["ok"]:
                continue
            made = 0
            for entry in self.build(r["item"], r["data"]):
                obj, rel = entry if isinstance(entry, tuple) else (entry, self.RELATIONSHIP)
                self.create_node(r["item"])
                self.create_node(obj)
                self.create_relationship(r["item"], obj, rel)
                output.append(obj)
                made += 1
            self.log_graph_message(f"{self.label_of(r['item'])} -> {made} result(s) from {self.SOURCE}.")
        return output


class ActiveEnricher(FetchEnricher):
    """Adds the authorization gate. Subclasses call `self.require_authorized()` at the top of fetch()."""

    @classmethod
    def authorized_param(cls) -> Dict[str, Any]:
        return {
            "name": "authorized",
            "type": "select",
            "description": "This sends traffic to the target. Set to yes only if you are authorised to test it.",
            "required": False,
            "default": "no",
            "options": [
                {"label": "No (will not run)", "value": "no"},
                {"label": "Yes, I am authorised to test this target", "value": "yes"},
            ],
        }

    def require_authorized(self) -> None:
        if str(self.params.get("authorized") or "no") != "yes":
            raise PermissionError("not run: set the 'authorized' parameter to yes to send traffic to this target")
