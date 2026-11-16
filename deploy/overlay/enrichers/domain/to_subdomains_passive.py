from typing import Any, Dict, List

from flowsint_core.core.logger import Logger
from flowsint_core.utils import is_valid_domain
from flowsint_enrichers import osint_http as oh
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain


@flowsint_enricher
class DomainToSubdomainsPassive(FetchEnricher):
    """[CertSpotter, HackerTarget, urlscan, Shodan] Subdomains from several passive sources at once (Shodan only when SHODAN_API_KEY is set on the container)."""

    InputType = Domain
    OutputType = Domain
    RELATIONSHIP = "HAS_SUBDOMAIN"
    SOURCE = "passive subdomains"

    @classmethod
    def name(cls) -> str:
        return "domain_to_subdomains_passive"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    def label_of(self, item) -> str:
        return item.domain

    async def _certspotter(self, d: str) -> List[str]:
        j = await oh.get_json("https://api.certspotter.com/v1/issuances", params={"domain": d, "include_subdomains": "true", "expand": "dns_names"})
        return [n for c in j for n in c.get("dns_names", [])]

    async def _hackertarget(self, d: str) -> List[str]:
        r = await oh.get("https://api.hackertarget.com/hostsearch/", params={"q": d})
        if r.text.lower().startswith(("error", "api count")):
            raise oh.SourceError(r.text[:80])
        return [line.split(",")[0] for line in r.text.splitlines() if "," in line]

    async def _urlscan(self, d: str) -> List[str]:
        j = await oh.get_json("https://urlscan.io/api/v1/search/", params={"q": f"domain:{d}", "size": 100})
        names = []
        for res in j.get("results", []):
            for k in ("page", "task"):
                names.append((res.get(k) or {}).get("domain", ""))
        return names

    async def _shodan(self, d: str) -> List[str]:
        key = oh.env("SHODAN_API_KEY")
        if not key:
            return []
        j = await oh.get_json(f"https://api.shodan.io/dns/domain/{d}", params={"key": key})
        return [f"{s}.{d}" for s in j.get("subdomains", []) if s and s != "*" and not s.startswith("_")]

    async def fetch(self, item) -> Dict[str, List[str]]:
        d = item.domain.lower()
        found: Dict[str, List[str]] = {}
        for label, fn in (("certspotter", self._certspotter), ("hackertarget", self._hackertarget), ("urlscan", self._urlscan), ("shodan", self._shodan)):
            try:
                for n in await fn(d):
                    n = n.strip().lower().lstrip("*.")
                    if n and n != d and n.endswith("." + d) and is_valid_domain(n):
                        found.setdefault(n, []).append(label)
            except Exception as e:  # one source down must not hide the others
                Logger.warn(self.sketch_id, {"message": f"[passive subdomains] {label} failed for {d}: {e}"})
        return found

    def build(self, item, data: Dict[str, List[str]]) -> List[Domain]:
        return [Domain(domain=n) for n in sorted(data)]


InputType = DomainToSubdomainsPassive.InputType
OutputType = DomainToSubdomainsPassive.OutputType
