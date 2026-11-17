from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from flowsint_core.core.logger import Logger
from flowsint_enrichers import llm_extract as lx
from flowsint_enrichers import page_extract as pe
from flowsint_enrichers.domain.to_entities_in_properties import SKIP_KEYS, _texts, _type_name_of
from flowsint_enrichers.osint_base import FetchEnricher, ParamsEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.individual import Individual
from flowsint_types.organization import Organization
from flowsint_types.website import Website

# Node types whose contents must never be sent to an outside model.
NEVER_SEND = {"Credential", "CreditCard", "BankAccount", "Session", "Breach", "Leak", "Message", "Script"}


def _people(found: Dict[str, List[Dict[str, str]]], where: str) -> List[Any]:
    out: List[Any] = []
    for p in found["people"]:
        first, _, last = p["name"].partition(" ")
        out.append(Individual(full_name=p["name"], first_name=first, last_name=last, job_title=p["role"] or None, source=f"LLM extraction: {where}", notes="Named in the text; the match is by name only, so it may be a different person with the same name."))
    return out


def _orgs(found: Dict[str, List[Dict[str, str]]]) -> List[Any]:
    return [Organization(name=o["name"]) for o in found["organizations"]]


@flowsint_enricher
class WebsiteToEntitiesLlm(FetchEnricher):
    """[LLM] People and organizations named on a website (home page plus its contact, about and team pages), found by asking the configured model. The page text is sent to that model (MiniMax here). Every returned name is checked against the page text and dropped if it does not appear there."""

    InputType = Website
    OutputType = Individual
    RELATIONSHIP = "MENTIONS"
    SOURCE = "LLM"

    @classmethod
    def name(cls) -> str:
        return "website_to_entities_llm"

    @classmethod
    def category(cls) -> str:
        return "Website"

    @classmethod
    def key(cls) -> str:
        return "url"

    def label_of(self, item) -> str:
        return str(item.url)

    async def fetch(self, item) -> Dict[str, List[Dict[str, str]]]:
        pages = await pe.fetch_pages(str(item.url), deep=True)
        text = "\n\n".join(f"[{u}]\n{lx.html_to_text(h)}" for u, h in pages.items())
        return await lx.extract(text)

    def build(self, item, data) -> List[Any]:
        return _people(data, str(item.url)) + _orgs(data)


@flowsint_enricher
class EntitiesInPropertiesLlm(ParamsEnricher):
    """[LLM] People and organizations named in any node's own text (a finding, a WHOIS record, notes, page content), found by asking the configured model. The text is SENT to that model (MiniMax here), so you must set send_to_llm to yes. Never runs on credential, card, bank, session, breach, leak or message nodes."""

    InputType = Any
    OutputType = Any

    @classmethod
    def name(cls) -> str:
        return "entities_in_properties_llm"

    @classmethod
    def category(cls) -> str:
        return "Generic"

    @classmethod
    def key(cls) -> str:
        return "nodeLabel"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "send_to_llm",
                "type": "select",
                "description": "This sends the node's text to the configured LLM provider. Choose Yes to confirm that text is fine to send.",
                "required": True,
                "default": "no",
                "options": [{"label": "No", "value": "no"}, {"label": "Yes", "value": "yes"}],
            }
        ]

    def preprocess(self, values: List) -> List:
        return [v for v in values if isinstance(v, dict)]

    async def scan(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        for d in data:
            label = str(d.get("nodeLabel") or "")
            tname = d.get("nodeType") or _type_name_of(d)
            if str(self.params.get("send_to_llm") or "no") != "yes":
                Logger.warn(self.sketch_id, {"message": f"[entities_in_properties_llm] {label}: skipped, send_to_llm is not set to yes."})
                out.append({"item": d, "type": tname, "found": None})
                continue
            if tname in NEVER_SEND:
                Logger.warn(self.sketch_id, {"message": f"[entities_in_properties_llm] {label}: skipped, {tname} nodes are never sent to an outside model."})
                out.append({"item": d, "type": tname, "found": None})
                continue
            text = "\n".join(_texts(d))
            try:
                out.append({"item": d, "type": tname, "found": await lx.extract(text) if len(text) >= 20 else {"people": [], "organizations": []}})
            except Exception as e:
                Logger.error(self.sketch_id, {"message": f"[entities_in_properties_llm] {label} failed: {e}"})
                out.append({"item": d, "type": tname, "found": None})
        return out

    def postprocess(self, results: List[Dict[str, Any]], input_data: Optional[List[Any]] = None) -> List[Any]:
        out: List[Any] = []
        for r in results:
            if r["found"] is None:
                continue
            label = str(r["item"].get("nodeLabel") or "")
            src = SimpleNamespace(nodeType=str(r["type"]).lower(), nodeLabel=label) if r["type"] and label else None
            made = [(o, "MENTIONS_PERSON") for o in _people(r["found"], label)] + [(o, "MENTIONS_ORGANIZATION") for o in _orgs(r["found"])]
            for obj, rel in made:
                self.create_node(obj)
                if src is not None:
                    self.create_relationship(src, obj, rel)
                out.append(obj)
            self.log_graph_message(f"{label or 'node'} -> {len(made)} named people and organizations (LLM, names checked against the text).")
        return out


InputType = WebsiteToEntitiesLlm.InputType
OutputType = WebsiteToEntitiesLlm.OutputType
