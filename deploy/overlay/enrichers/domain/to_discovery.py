import asyncio
import secrets
from typing import Any, Dict, List

from flowsint_core.utils import is_valid_domain
from flowsint_enrichers import dns_doh, osint_http as oh
from flowsint_enrichers import page_extract as pe
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.wallet import CryptoWallet

# Maltego: "To DNS Name [Find common DNS names]" / "[Using Name Schema dictionary]". Names that are common on real hosts.
COMMON = (
    "www mail webmail smtp imap pop pop3 ns1 ns2 ns3 mx mx1 mx2 ftp sftp vpn remote portal intranet extranet admin api dev "
    "staging stage test qa uat demo beta alpha preview sandbox app apps web www2 m mobile blog shop store cart pay secure "
    "login sso auth id accounts account my cpanel whm autodiscover autoconfig owa exchange lyncdiscover sip git gitlab "
    "github svn jenkins ci cd build grafana kibana prometheus monitor status stats analytics docs wiki help support "
    "kb forum community news media static assets cdn img images files download downloads upload backup db sql mysql "
    "postgres redis mongo elastic search proxy gateway edge cloud docker k8s registry vault cache old new legacy "
    "crm erp hr billing invoice customer clients partner partners careers jobs events video stream tv radio"
).split()

TLDS = (
    "com net org io ca us co info biz dev app ai xyz online site shop store tech cloud uk de fr nl eu me tv cc in au nz za "
    "br jp cn ru se no fi dk es it pl ch at be ie pt cz gr tr mx ar cl"
).split()


def _root_label(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


async def _resolves(name: str) -> bool:
    for rt in ("A", "AAAA", "CNAME"):
        try:
            recs, _ = await dns_doh.query(name, rt)
        except oh.SourceError:
            continue
        if recs:
            return True
    return False


@flowsint_enricher
class DomainToTldVariants(FetchEnricher):
    """[DNS] Other top-level domains that exist for the same name (techbrooks.ca -> techbrooks.com, .net ...). Shows lookalike and sister domains. Results are not followed by machines."""

    InputType = Domain
    OutputType = Domain
    RELATIONSHIP = "SAME_NAME_OTHER_TLD"
    SOURCE = "DNS"

    @classmethod
    def name(cls) -> str:
        return "domain_to_tld_variants"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    def label_of(self, item) -> str:
        return item.domain

    async def fetch(self, item) -> List[str]:
        label = _root_label(item.domain)
        sem = asyncio.Semaphore(8)

        async def one(tld: str):
            name = f"{label}.{tld}"
            if name == item.domain.lower():
                return None
            async with sem:
                try:
                    recs, _ = await dns_doh.query(name, "NS")
                except oh.SourceError:
                    return None
            return name if recs else None

        return [n for n in await asyncio.gather(*(one(t) for t in TLDS)) if n]

    def build(self, item, data: List[str]) -> List[Domain]:
        return [Domain(domain=n) for n in sorted(data) if is_valid_domain(n)]


@flowsint_enricher
class DomainToCommonSubdomains(FetchEnricher):
    """[DNS] Tries about 200 common host names (mail, vpn, dev, staging, api, git ...) and keeps the ones that resolve. Finds hosts that certificate logs miss. Skips domains with wildcard DNS, where every name would resolve."""

    InputType = Domain
    OutputType = Domain
    RELATIONSHIP = "HAS_SUBDOMAIN"
    SOURCE = "DNS"

    @classmethod
    def name(cls) -> str:
        return "domain_to_subdomains_common"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    def label_of(self, item) -> str:
        return item.domain

    async def fetch(self, item) -> Dict[str, Any]:
        d = item.domain.lower()
        # Wildcard check: a random name that resolves means every guess would "exist".
        if await _resolves(f"{secrets.token_hex(8)}.{d}"):
            return {"wildcard": True, "hits": []}
        sem = asyncio.Semaphore(10)

        async def one(label: str):
            async with sem:
                return f"{label}.{d}" if await _resolves(f"{label}.{d}") else None

        hits = [n for n in await asyncio.gather(*(one(x) for x in COMMON)) if n]
        return {"wildcard": False, "hits": hits}

    def build(self, item, data: Dict[str, Any]) -> List[Domain]:
        if data["wildcard"]:
            self.log_graph_message(f"{item.domain} has wildcard DNS (any name resolves), so guessing host names proves nothing; skipped.")
            return []
        return [Domain(domain=n) for n in sorted(data["hits"]) if is_valid_domain(n)]


@flowsint_enricher
class DomainToWallets(FetchEnricher):
    """[Web page] Crypto wallet addresses (Bitcoin, Ethereum, Litecoin, Dogecoin) published on the domain's site: its home page and its contact, about, donate and support pages. Bitcoin-family addresses are checksum-validated."""

    InputType = Domain
    OutputType = CryptoWallet
    RELATIONSHIP = "MENTIONS_WALLET"
    SOURCE = "web page"

    @classmethod
    def name(cls) -> str:
        return "domain_to_wallets"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    def label_of(self, item) -> str:
        return item.domain

    async def fetch(self, item) -> Dict[str, str]:
        last: Exception = oh.SourceError("no page")
        for u in pe.site_urls(item.domain):
            try:
                return await pe.fetch_pages(u, deep=True)
            except oh.SourceError as e:
                last = e
        raise last

    def build(self, item, data: Dict[str, str]) -> List[CryptoWallet]:
        found = set()
        for html in data.values():
            found |= set(pe.wallets_in(html))
        return [CryptoWallet(address=a) for a in sorted(found)]


InputType = DomainToWallets.InputType
OutputType = DomainToWallets.OutputType
