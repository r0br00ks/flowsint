from typing import Any, Dict, List

from urllib.parse import urlparse

from flowsint_core.utils import is_valid_domain
from flowsint_enrichers import osint_http as oh
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.website import Website


@flowsint_enricher
class DomainToWaybackUrls(FetchEnricher):
    """[Wayback Machine] URLs the Internet Archive has captured for a domain, including old and forgotten paths."""

    InputType = Domain
    OutputType = Website
    RELATIONSHIP = "HAS_ARCHIVED_URL"
    SOURCE = "Wayback Machine"

    @classmethod
    def name(cls) -> str:
        return "domain_to_wayback_urls"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "max_results",
                "type": "string",
                "description": "Return at most this many distinct URLs.",
                "required": False,
                "default": "100",
            }
        ]

    def label_of(self, item) -> str:
        return item.domain

    async def fetch(self, item) -> List[List[str]]:
        limit = int(float(self.params.get("max_results") or 100))
        rows = await oh.get_json(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{item.domain}/*",
                "output": "json",
                "fl": "original,statuscode",
                "collapse": "urlkey",
                "filter": "statuscode:200",
                "limit": str(limit),
            },
            timeout=90.0,
            retries=3,
        )
        return rows[1:] if rows else []  # first row is the header

    def build(self, item, data: List[List[str]]) -> List[Website]:
        seen, out = set(), []
        for original, _status in data:
            if original in seen:
                continue
            seen.add(original)
            host = (urlparse(original).hostname or "").lower()
            dom = Domain(domain=host) if host and is_valid_domain(host) else None
            out.append(Website(url=original, domain=dom, status_code=200))
        return out


InputType = DomainToWaybackUrls.InputType
OutputType = DomainToWaybackUrls.OutputType
