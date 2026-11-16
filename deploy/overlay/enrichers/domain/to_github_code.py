from typing import Any, Dict, List

from flowsint_enrichers import osint_http as oh
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.website import Website


@flowsint_enricher
class DomainToGithubCode(FetchEnricher):
    """[GitHub] Public code files that mention a domain: leaked configs, hard-coded hosts, forgotten projects (needs GITHUB_TOKEN on the container; search is limited to 30 requests a minute)."""

    InputType = Domain
    OutputType = Website
    RELATIONSHIP = "MENTIONED_IN_CODE"
    SOURCE = "GitHub code search"

    @classmethod
    def name(cls) -> str:
        return "domain_to_github_code"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [{"name": "max_results", "type": "string", "description": "Return at most this many files (max 100).", "required": False, "default": "30"}]

    def label_of(self, item) -> str:
        return item.domain

    async def fetch(self, item) -> List[Dict[str, Any]]:
        token = oh.env("GITHUB_TOKEN")
        if not token:
            raise oh.SourceError("GITHUB_TOKEN is not set on this container")
        n = min(int(float(self.params.get("max_results") or 30)), 100)
        j = await oh.get_json(
            "https://api.github.com/search/code",
            params={"q": f'"{item.domain}"', "per_page": str(n)},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        )
        return j.get("items", [])

    def build(self, item, data: List[Dict[str, Any]]) -> List[Website]:
        out = []
        for it in data:
            repo = (it.get("repository") or {}).get("full_name", "")
            out.append(Website(url=it["html_url"], domain=Domain(domain="github.com"), title=f"{repo}: {it.get('path', '')}"[:200]))
        return out


InputType = DomainToGithubCode.InputType
OutputType = DomainToGithubCode.OutputType
