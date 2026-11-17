"""Pull crypto wallet addresses, email addresses and phone numbers out of web pages.

Maltego's nearest equivalents are "To Regex Matches [Found on web page]", "To Email Addresses [Found on web page]" and
"To Phone numbers [Found on this web page]". Wallet matches are checksum-validated so a random string that happens to
look like an address is dropped.
"""

import hashlib
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

from flowsint_enrichers import osint_http as oh

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Pages where a site owner is most likely to publish payment details or contact data.
EXTRA_PATHS = ["/contact", "/contact-us", "/about", "/about-us", "/donate", "/donation", "/support", "/pricing", "/payment", "/team"]


def _b58check(addr: str) -> Optional[int]:
    """Version byte if `addr` is valid base58check, else None."""
    n = 0
    for ch in addr:
        i = B58.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    raw = n.to_bytes(25, "big") if n.bit_length() <= 200 else b""
    if len(raw) != 25:
        return None
    if hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] != raw[21:]:
        return None
    return raw[0]


def _bech32_polymod(values: List[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (b >> i) & 1 else 0
    return chk


def _bech32_ok(addr: str) -> bool:
    if addr != addr.lower() or "1" not in addr:
        return False
    hrp, _, data = addr.rpartition("1")
    if not hrp or len(data) < 7 or any(c not in BECH32 for c in data):
        return False
    vals = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + [BECH32.find(c) for c in data]
    return _bech32_polymod(vals) in (1, 0x2BC830A3)  # bech32 and bech32m


def wallets_in(text: str) -> Dict[str, str]:
    """address -> chain, for every valid-looking wallet address in `text`."""
    found: Dict[str, str] = {}
    for m in re.findall(r"(?<![0-9A-Za-z])0x[0-9a-fA-F]{40}(?![0-9A-Za-z])", text):
        found[m] = "Ethereum"
    for m in re.findall(r"(?<![0-9A-Za-z])bc1[02-9ac-hj-np-z]{11,71}(?![0-9A-Za-z])", text):
        if _bech32_ok(m):
            found[m] = "Bitcoin"
    for m in re.findall(r"(?<![0-9A-Za-z])[13LMD][1-9A-HJ-NP-Za-km-z]{25,34}(?![0-9A-Za-z])", text):
        v = _b58check(m)
        chain = {0x00: "Bitcoin", 0x05: "Bitcoin", 0x30: "Litecoin", 0x32: "Litecoin", 0x1E: "Dogecoin"}.get(v)
        if chain:
            found[m] = chain
    return found


EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}(?![\w-])")
JUNK_TLDS = {"png", "jpg", "jpeg", "gif", "webp", "svg", "css", "js", "woff", "woff2", "ico", "map"}


def _decode_cfemail(h: str) -> str:
    try:
        k = int(h[:2], 16)
        return "".join(chr(int(h[i : i + 2], 16) ^ k) for i in range(2, len(h), 2))
    except ValueError:
        return ""


def emails_in(html: str) -> Set[str]:
    text = html
    for h in re.findall(r'data-cfemail="([0-9a-fA-F]+)"', html):  # Cloudflare email obfuscation
        text += " " + _decode_cfemail(h)
    for h in re.findall(r"/cdn-cgi/l/email-protection#([0-9a-fA-F]+)", html):
        text += " " + _decode_cfemail(h)
    text = re.sub(r"\s*[\[(]\s*at\s*[\])]\s*", "@", text, flags=re.I)
    out = set()
    for e in EMAIL_RE.findall(text):
        e = e.lower().strip(".")
        tld = e.rsplit(".", 1)[-1]
        if tld in JUNK_TLDS or e.split("@")[1].startswith(("example.", "sentry.", "wixpress.")):
            continue
        out.add(e)
    return out


def phones_in(html: str) -> Set[str]:
    out = set()
    for m in re.findall(r'href=["\']tel:([^"\']+)["\']', html, flags=re.I):
        d = re.sub(r"[^\d+]", "", m.replace("%20", ""))
        if 8 <= len(re.sub(r"\D", "", d)) <= 15:
            out.add(d if d.startswith("+") else d)
    text = re.sub(r"<[^>]+>", " ", html)
    for m in re.findall(r"\+\d{1,3}[\s().-]?\d{1,4}[\s().-]?\d{2,4}[\s.-]?\d{3,4}(?:[\s.-]?\d{2,4})?", text):
        d = "+" + re.sub(r"\D", "", m)
        if 9 <= len(d) - 1 <= 15:
            out.add(d)
    return out


async def fetch_pages(url: str, deep: bool = True, max_extra: int = 8) -> Dict[str, str]:
    """The page itself plus a handful of ordinary contact/about pages on the same host. Plain GET requests only."""
    pages: Dict[str, str] = {}
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0 (compatible; flowsint-enricher/1.0)"}) as c:
        try:
            r = await c.get(url)
        except httpx.HTTPError as e:
            raise oh.SourceError(f"{url} failed ({type(e).__name__})")
        if r.status_code >= 400:
            raise oh.SourceError(f"{url} returned HTTP {r.status_code}")
        base = str(r.url)
        pages[base] = r.text[:2_000_000]
        if deep:
            seen = {base}
            for p in EXTRA_PATHS[:max_extra]:
                u = urljoin(base, p)
                if u in seen or urlparse(u).hostname != urlparse(base).hostname:
                    continue
                seen.add(u)
                try:
                    rr = await c.get(u)
                except httpx.HTTPError:
                    continue
                if rr.status_code == 200 and "text/html" in rr.headers.get("content-type", ""):
                    pages[str(rr.url)] = rr.text[:1_000_000]
    return pages


def site_urls(domain: str) -> List[str]:
    return [f"https://{domain}/", f"https://www.{domain}/"] if not domain.startswith("www.") else [f"https://{domain}/"]
