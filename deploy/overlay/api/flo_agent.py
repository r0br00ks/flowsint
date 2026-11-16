"""Flo with hands: tool calls so the assistant can look up enrichers and start investigations.

Used by the chat route when FLO_TOOLS=1 and the LLM provider is the OpenAI-compatible one. The model gets three
tools. Everything they start is passive: enrichers that declare an `authorized` parameter (nmap, wafw00f) are
refused here, so an AI reply can never start a scan. Work is launched as the same Celery task the UI uses, into
the newest sketch of the chat's investigation, with the same permission check as the launch route.
"""

import json
import os
import re
from typing import Any, AsyncIterator, Dict, List, Optional

from sqlalchemy import desc

from flowsint_core.core.celery import celery
from flowsint_core.core.models import Sketch
from flowsint_core.core.services import create_enricher_service
from flowsint_core.core.services.type_registry_service import create_type_registry_service
from flowsint_enrichers import ENRICHER_REGISTRY, load_all_enrichers

load_all_enrichers()

MACHINE_BY_TYPE = {
    "Domain": "machine_domain_recon",
    "Ip": "machine_ip_recon",
    "Email": "machine_email_recon",
    "Username": "machine_username_recon",
}
MAX_ROUNDS = 4

SYSTEM_ADDENDUM = (
    "You can act in this investigation with three tools: list_enrichers (what can be run on an entity type), "
    "run_enricher (run one enricher on a value) and run_machine (run the whole automated investigation on a domain, "
    "IP, email or username). Results are written to the graph a little later, not returned to you, so say what you "
    "started and tell the user to watch the console and graph. Everything you start is passive and uses public "
    "sources; you cannot start scans of a target. Only investigate targets the user named or that are already in "
    "the investigation context. Be brief."
)

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_enrichers",
            "description": "List the enrichers that can run on an entity type, with a one-line description each.",
            "parameters": {
                "type": "object",
                "properties": {"input_type": {"type": "string", "description": "Entity type, e.g. Domain, Ip, Email, Username, Website, Technology, Cve, ASN"}},
                "required": ["input_type"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_enricher",
            "description": "Run one enricher on a value. The result appears on the graph shortly after.",
            "parameters": {
                "type": "object",
                "properties": {
                    "enricher": {"type": "string", "description": "Enricher name from list_enrichers"},
                    "value": {"type": "string", "description": "The domain, IP, email, username, URL, technology or CVE id to run it on"},
                },
                "required": ["enricher", "value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_machine",
            "description": "Run the full automated passive investigation on a domain, IP address, email address or username. It chains many enrichers and writes everything to the graph.",
            "parameters": {
                "type": "object",
                "properties": {"target": {"type": "string", "description": "The domain, IP, email or username"}},
                "required": ["target"],
            },
        },
    },
]


def strip_think(text: str) -> str:
    return re.sub(r"<think>.*?</think>\s*", "", text or "", flags=re.S).strip()


class TextProvider:
    """Hands an already-written answer to the chat service's streaming code, so it is saved and sent like any reply."""

    def __init__(self, text: str):
        self._text = text

    async def stream(self, messages: Any) -> AsyncIterator[str]:
        for i in range(0, len(self._text), 40):
            yield self._text[i : i + 40]

    async def complete(self, messages: Any) -> str:
        return self._text


def _sketch_for(db: Any, user: Any, chat: Any) -> Sketch:
    if not chat.investigation_id:
        raise ValueError("this chat is not attached to an investigation")
    sk = db.query(Sketch).filter(Sketch.investigation_id == chat.investigation_id).order_by(desc(Sketch.last_updated_at)).first()
    if sk is None:
        raise ValueError("the investigation has no sketch to write results into; create one first")
    create_enricher_service(db).get_sketch_for_launch(str(sk.id), user.id)  # same permission check as the launch route
    return sk


def _entity_for(enricher_cls: Any, value: str) -> Dict[str, Any]:
    return {enricher_cls.key(): value.strip()}


def _launch(db: Any, user: Any, chat: Any, name: str, value: str) -> Dict[str, Any]:
    if not ENRICHER_REGISTRY.enricher_exists(name):
        return {"error": f"no enricher named {name}"}
    cls = ENRICHER_REGISTRY._enrichers[name]
    if any(p.get("name") == "authorized" for p in cls.get_params_schema()):
        return {"error": f"{name} sends traffic to the target, so it is not run from chat. Launch it from the Enrich menu with authorized set to yes."}
    sk = _sketch_for(db, user, chat)
    task = celery.send_task("run_enricher", args=[name, [_entity_for(cls, value)], str(sk.id), str(user.id)], kwargs={"params": {}})
    return {"started": name, "on": value, "sketch": sk.title, "task_id": task.id}


async def run_tool(db: Any, user: Any, chat: Any, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    try:
        if name == "list_enrichers":
            want = str(args.get("input_type", "")).lower()
            rows = []
            for n, cls in sorted(ENRICHER_REGISTRY._enrichers.items()):
                if getattr(cls, "InputType", None) is not None and cls.InputType.__name__.lower() == want:
                    doc = (cls.__doc__ or "").strip().splitlines()[0][:110] if cls.__doc__ else ""
                    active = any(p.get("name") == "authorized" for p in cls.get_params_schema())
                    rows.append({"name": n, "what": doc, **({"note": "active, not runnable from chat"} if active else {})})
            return {"input_type": args.get("input_type"), "enrichers": rows[:60]}
        if name == "run_enricher":
            return _launch(db, user, chat, str(args.get("enricher", "")), str(args.get("value", "")))
        if name == "run_machine":
            target = str(args.get("target", "")).strip()
            detected = create_type_registry_service(db).detect_type(target).get("type", "Phrase")
            machine = MACHINE_BY_TYPE.get(detected)
            if not machine:
                return {"error": f"'{target}' looks like a {detected}; there is no machine for that. Use list_enrichers."}
            out = _launch(db, user, chat, machine, target)
            out["detected_type"] = detected
            return out
        return {"error": f"unknown tool {name}"}
    except Exception as e:  # a tool failure goes back to the model as text, never crashes the chat
        return {"error": str(e)[:300]}


async def answer_with_tools(db: Any, user: Any, chat: Any, llm_messages: List[Any]) -> Optional[str]:
    """Run the tool loop and return the final reply, or None to let the caller use the plain chat path."""
    from openai import AsyncOpenAI

    client = AsyncOpenAI()  # reads OPENAI_API_KEY and OPENAI_BASE_URL from the environment
    msgs: List[Dict[str, Any]] = [{"role": m.role.value, "content": m.content} for m in llm_messages]
    msgs.insert(1 if msgs and msgs[0]["role"] == "system" else 0, {"role": "system", "content": SYSTEM_ADDENDUM})
    model = os.environ.get("LLM_MODEL", "gpt-4o-mini")
    for _ in range(MAX_ROUNDS):
        resp = await client.chat.completions.create(model=model, messages=msgs, tools=TOOLS, tool_choice="auto", max_tokens=1500)
        msg = resp.choices[0].message
        if not msg.tool_calls:
            return strip_think(msg.content or "") or None
        msgs.append({"role": "assistant", "content": msg.content or "", "tool_calls": [tc.model_dump() for tc in msg.tool_calls]})
        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except ValueError:
                args = {}
            result = await run_tool(db, user, chat, tc.function.name, args)
            msgs.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(result)[:3000]})
    return "I started what I could but ran out of steps for this request. Check the console for what is running."
