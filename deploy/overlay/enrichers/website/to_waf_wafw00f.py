import json
import os
import tempfile
from typing import Any, Dict, List

from flowsint_enrichers import cli
from flowsint_enrichers.osint_base import ActiveEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.technology import Technology
from flowsint_types.website import Website


@flowsint_enricher
class WebsiteToWafWafw00f(ActiveEnricher):
    """[wafw00f] Detects which web application firewall or CDN protects a site. ACTIVE: it sends requests built to trigger a WAF, so it only runs when authorized is set to yes."""

    InputType = Website
    OutputType = Technology
    RELATIONSHIP = "PROTECTED_BY"
    SOURCE = "wafw00f"

    @classmethod
    def name(cls) -> str:
        return "website_to_waf_wafw00f"

    @classmethod
    def category(cls) -> str:
        return "Website"

    @classmethod
    def key(cls) -> str:
        return "url"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [cls.authorized_param()]

    def label_of(self, item) -> str:
        return str(item.url)

    async def fetch(self, item) -> List[Dict[str, Any]]:
        self.require_authorized()
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            rc, out, err = await cli.run(["wafw00f", "-f", "json", "-o", path, str(item.url)], timeout=120)
            with open(path) as f:
                text = f.read().strip()
            if not text:
                raise cli.ToolFailed(f"wafw00f wrote no result (exit {rc}): {(out + err)[-160:]}")
            return json.loads(text)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def build(self, item, data: List[Dict[str, Any]]) -> List[Technology]:
        out = []
        for r in data:
            if r.get("detected") and r.get("firewall") and r["firewall"].lower() != "none":
                out.append(Technology(name=r["firewall"], category="waf", source=f"wafw00f ({r.get('manufacturer') or 'unknown vendor'})"))
        return out


InputType = WebsiteToWafWafw00f.InputType
OutputType = WebsiteToWafWafw00f.OutputType
