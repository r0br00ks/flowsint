import json
from typing import Any, Dict, List, Optional, Tuple

from flowsint_enrichers import cli
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.technology import Technology
from flowsint_types.website import Website

# Plugins that only describe the request, not software the site runs.
SKIP = {"IP", "Country", "UncommonHeaders", "RedirectLocation", "HTML5", "Title", "Cookies", "Email", "Script", "PasswordField", "Meta-Refresh-Redirect", "HttpOnly", "Strict-Transport-Security", "X-Frame-Options", "X-XSS-Protection"}
# Plugins whose value is the product name itself, e.g. HTTPServer[cloudflare], PoweredBy[LiteSpeed], MetaGenerator[WordPress 7.1].
NAMED_BY_STRING = {"HTTPServer", "PoweredBy", "X-Powered-By", "MetaGenerator", "Generator"}


def _split_name_version(text: str) -> Tuple[str, Optional[str]]:
    for sep in ("/", " "):
        if sep in text:
            name, _, version = text.partition(sep)
            if version and version[0].isdigit():
                return name.strip(), version.strip()
    return text.strip(), None


@flowsint_enricher
class WebsiteToTechnologiesWhatWeb(FetchEnricher):
    """[WhatWeb] Identifies the CMS, frameworks, server and libraries a website runs, with versions where it can. Sends a handful of ordinary page requests. A site behind a bot challenge shows little."""

    InputType = Website
    OutputType = Technology
    RELATIONSHIP = "RUNS"
    SOURCE = "WhatWeb"

    @classmethod
    def name(cls) -> str:
        return "website_to_technologies_whatweb"

    @classmethod
    def category(cls) -> str:
        return "Website"

    @classmethod
    def key(cls) -> str:
        return "url"

    def label_of(self, item) -> str:
        return str(item.url)

    async def fetch(self, item) -> List[Dict[str, Any]]:
        rc, out, err = await cli.run(["whatweb", "-q", "--log-json=-", "--no-errors", "-a", "1", "--color=never", "-U", "Mozilla/5.0 (compatible; flowsint-enricher/1.0)", str(item.url)], timeout=120)
        entries = []
        for line in out.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    entries.append(json.loads(line))
                except ValueError:
                    pass
        if not entries:
            raise cli.ToolFailed(f"whatweb returned no JSON (exit {rc}): {(err or out)[:160]}")
        return entries

    def build(self, item, data: List[Dict[str, Any]]) -> List[Technology]:
        out, seen = [], set()

        def add(name: str, version: Optional[str]) -> None:
            if name and (name.lower(), version) not in seen:
                seen.add((name.lower(), version))
                out.append(Technology(name=name, version=version, source="WhatWeb"))

        for entry in data:
            for plugin, info in (entry.get("plugins") or {}).items():
                if plugin in SKIP:
                    continue
                strings = [str(x) for x in (info.get("string") or [])]
                versions = [str(x) for x in (info.get("version") or [])]
                if plugin in NAMED_BY_STRING:
                    for text in strings:
                        add(*_split_name_version(text))
                else:
                    add(plugin, versions[0] if versions else None)
        return out


InputType = WebsiteToTechnologiesWhatWeb.InputType
OutputType = WebsiteToTechnologiesWhatWeb.OutputType
