"""Shodan InternetDB (free, no key): open ports, CPEs, known vulnerabilities and host names seen for an IP."""

from typing import Any, Dict

from flowsint_enrichers import osint_http as oh
from flowsint_enrichers.osint_base import FetchEnricher


class InternetDbEnricher(FetchEnricher):
    """Not registered itself; concrete enrichers subclass it and add @flowsint_enricher."""

    SOURCE = "Shodan InternetDB"

    def label_of(self, item: Any) -> str:
        return item.address

    async def fetch(self, item: Any) -> Dict[str, Any]:
        r = await oh.get(f"https://internetdb.shodan.io/{item.address}", ok=(200, 404))
        return {} if r.status_code == 404 else r.json()  # 404 means Shodan has nothing on this IP
