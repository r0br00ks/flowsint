from typing import Any, Dict, List

from flowsint_enrichers import page_extract as pe
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.email import Email
from flowsint_types.phone import Phone
from flowsint_types.website import Website
from flowsint_types.wallet import CryptoWallet


DEEP_PARAM = [
    {
        "name": "deep",
        "type": "select",
        "description": "Also read a few ordinary contact, about, donate and support pages on the same site (up to 8 extra GET requests).",
        "required": False,
        "default": "yes",
        "options": [{"label": "Yes", "value": "yes"}, {"label": "No", "value": "no"}],
    }
]


class _PageEnricher(FetchEnricher):
    """Shared fetch for the three 'found on this web page' enrichers."""

    InputType = Website
    SOURCE = "web page"

    @classmethod
    def category(cls) -> str:
        return "Website"

    @classmethod
    def key(cls) -> str:
        return "url"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return list(DEEP_PARAM)

    def label_of(self, item) -> str:
        return str(item.url)

    async def fetch(self, item) -> Dict[str, str]:
        return await pe.fetch_pages(str(item.url), deep=str(self.params.get("deep") or "yes") == "yes")


@flowsint_enricher
class WebsiteToWallets(_PageEnricher):
    """[Web page] Crypto wallet addresses (Bitcoin, Ethereum, Litecoin, Dogecoin) published on a site, found by reading the page and its contact, donate and support pages. Bitcoin-family addresses are checksum-validated."""

    OutputType = CryptoWallet
    RELATIONSHIP = "MENTIONS_WALLET"

    @classmethod
    def name(cls) -> str:
        return "website_to_wallets"

    def build(self, item, data: Dict[str, str]) -> List[CryptoWallet]:
        found: Dict[str, str] = {}
        for page, html in data.items():
            for addr, chain in pe.wallets_in(html).items():
                found.setdefault(addr, f"{chain} on {page}")
        return [CryptoWallet(address=a) for a in sorted(found)]


@flowsint_enricher
class WebsiteToEmails(_PageEnricher):
    """[Web page] Email addresses published on a site, including ones Cloudflare hides behind its email protection."""

    OutputType = Email
    RELATIONSHIP = "HAS_EMAIL"

    @classmethod
    def name(cls) -> str:
        return "website_to_emails"

    def build(self, item, data: Dict[str, str]) -> List[Email]:
        found = set()
        for html in data.values():
            found |= pe.emails_in(html)
        out = []
        for e in sorted(found):
            try:
                out.append(Email(email=e))
            except Exception:
                continue
        return out


@flowsint_enricher
class WebsiteToPhones(_PageEnricher):
    """[Web page] Phone numbers published on a site (tel: links and numbers written with a country code)."""

    OutputType = Phone
    RELATIONSHIP = "HAS_PHONE"

    @classmethod
    def name(cls) -> str:
        return "website_to_phones"

    def build(self, item, data: Dict[str, str]) -> List[Phone]:
        found = set()
        for html in data.values():
            found |= pe.phones_in(html)
        out = []
        for p in sorted(found):
            try:
                out.append(Phone(number=p))
            except Exception:
                continue
        return out


InputType = WebsiteToWallets.InputType
OutputType = WebsiteToWallets.OutputType
