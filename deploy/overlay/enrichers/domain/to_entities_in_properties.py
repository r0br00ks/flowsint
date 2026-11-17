"""Maltego's "To Domains / Email Addresses / IP Addresses / URLs [within Properties]", as one enricher that works on any node.

Reads every text value a node carries (a WHOIS record, a finding's description, a website's content, a note) and turns
the domains, email addresses, IP addresses, URLs and crypto wallets found there into new nodes linked to it.
"""

import ipaddress
import re
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

from flowsint_core.core.logger import Logger
from flowsint_enrichers import page_extract as pe
from flowsint_enrichers.osint_base import ParamsEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.email import Email
from flowsint_types.ip import Ip
from flowsint_types.wallet import CryptoWallet
from flowsint_types.website import Website

# Bookkeeping fields of a node, not content.
SKIP_KEYS = {"nodeLabel", "nodeType", "id", "sketch_id", "x", "y", "created_at", "nodeShape", "node_id"}
# Looks like a domain but is a file name. Includes a few real TLDs (md, sh, rs, py) that appear far more often as file extensions.
FILE_EXT = set(
    "js ts tsx jsx py json css html htm php png jpg jpeg gif svg ico txt md yml yaml xml pdf zip gz tgz sh rb go rs java class "
    "log ini cfg conf toml lock map exe dll so bin csv doc docx xls xlsx pptx woff woff2 ttf mp3 mp4 avi mov wasm pyc".split()
)

URL_RE = re.compile(r"https?://[^\s<>\"'`)\]}]+", re.I)
DOMAIN_RE = re.compile(r"(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-])", re.I)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def _texts(value: Any, key: str = "") -> List[str]:
    if key in SKIP_KEYS:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: List[str] = []
        for k, v in value.items():
            out += _texts(v, str(k))
        return out
    if isinstance(value, (list, tuple, set)):
        out = []
        for v in value:
            out += _texts(v, key)
        return out
    return []


def _type_name_of(item: Dict[str, Any]) -> Optional[str]:
    """The node dict carries no type name; find the type whose field set matches the dict's keys exactly."""
    from flowsint_types.registry import TYPE_REGISTRY

    keys = set(item) - {"nodeLabel", "nodeType"}
    reg = getattr(TYPE_REGISTRY, "_types", None) or {}
    hits = [n for n, c in reg.items() if set(getattr(c, "model_fields", {})) - {"nodeLabel"} == keys]
    return hits[0] if len(hits) == 1 else None


def extract(text: str) -> Dict[str, List[str]]:
    found: Dict[str, List[str]] = {"emails": [], "urls": [], "ips": [], "wallets": [], "domains": []}
    seen: set = set()

    def add(kind: str, v: str) -> None:
        if (kind, v) not in seen:
            seen.add((kind, v))
            found[kind].append(v)

    for e in sorted(pe.emails_in(text)):
        add("emails", e)
    for u in URL_RE.findall(text):
        add("urls", u.rstrip(".,;:!?"))
    for a in pe.wallets_in(text):
        add("wallets", a)
    for m in IPV4_RE.findall(text):
        try:
            ip = ipaddress.ip_address(m)
        except ValueError:
            continue
        if ip.is_global:
            add("ips", str(ip))
    bare = re.sub(r"\S+@\S+", " ", URL_RE.sub(lambda m: " " + (m.group(0).split("/")[2] if m.group(0).count("/") >= 2 else "") + " ", text))
    for d in DOMAIN_RE.findall(bare):
        d = d.lower().strip(".")
        if d.rsplit(".", 1)[-1] in FILE_EXT or re.fullmatch(r"[\d.]+", d):
            continue
        add("domains", d)
    for e in list(found["emails"]):  # an address also names its domain
        add("domains", e.split("@", 1)[1])
    return found


@flowsint_enricher
class EntitiesInProperties(ParamsEnricher):
    """[Generic] Finds domains, email addresses, IP addresses, URLs and crypto wallets written inside any node's own text (WHOIS records, finding descriptions, website content, notes) and adds them as linked nodes. Works on every node type."""

    InputType = Any
    OutputType = Any

    @classmethod
    def name(cls) -> str:
        return "entities_in_properties"

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
                "name": "max_results",
                "type": "string",
                "description": "Add at most this many entities per node.",
                "required": False,
                "default": "50",
            }
        ]

    def preprocess(self, values: List) -> List:
        return [v for v in values if isinstance(v, dict)]

    async def scan(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [{"item": d, "found": extract("\n".join(_texts(d)))} for d in data]

    def postprocess(self, results: List[Dict[str, Any]], input_data: Optional[List[Any]] = None) -> List[Any]:
        cap = int(float(self.params.get("max_results") or 50))
        out: List[Any] = []
        for r in results:
            item, found = r["item"], r["found"]
            label = str(item.get("nodeLabel") or "")
            tname = item.get("nodeType") or _type_name_of(item)
            src = SimpleNamespace(nodeType=str(tname).lower(), nodeLabel=label) if tname and label else None
            if src is None:
                Logger.warn(self.sketch_id, {"message": f"[entities_in_properties] could not tell what type '{label}' is, so results are added without a link back to it."})
            made: List[Tuple[Any, str]] = []
            for kind, ctor, rel in (
                ("emails", lambda v: Email(email=v), "MENTIONS_EMAIL"),
                ("urls", lambda v: Website(url=v), "MENTIONS_URL"),
                ("ips", lambda v: Ip(address=v), "MENTIONS_IP"),
                ("wallets", lambda v: CryptoWallet(address=v), "MENTIONS_WALLET"),
                ("domains", lambda v: Domain(domain=v), "MENTIONS_DOMAIN"),
            ):
                for v in found[kind]:
                    if v.lower() == label.lower():
                        continue
                    try:
                        made.append((ctor(v), rel))
                    except Exception:
                        continue  # a value that is not valid for its type is dropped
            for obj, rel in made[:cap]:
                self.create_node(obj)
                if src is not None:
                    self.create_relationship(src, obj, rel)
                out.append(obj)
            skipped = max(0, len(made) - cap)
            self.log_graph_message(f"{label or 'node'} -> {min(len(made), cap)} entit{'y' if min(len(made), cap) == 1 else 'ies'} found in its properties" + (f" ({skipped} more not added, raise max_results)" if skipped else "."))
        return out


InputType = EntitiesInProperties.InputType
OutputType = EntitiesInProperties.OutputType
