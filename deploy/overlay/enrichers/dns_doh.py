"""DNS over HTTPS lookups through Cloudflare's JSON endpoint (no key, no resolver on the host needed)."""

from typing import Any, Dict, List, Tuple

from flowsint_enrichers import osint_http as oh

DOH = "https://cloudflare-dns.com/dns-query"
TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA", 48: "DNSKEY", 257: "CAA"}


async def query(name: str, rtype: str, dnssec: bool = False) -> Tuple[List[Dict[str, Any]], bool]:
    """Return (answer records, authenticated-data flag). Each record: name, type, ttl, data."""
    params: Dict[str, Any] = {"name": name, "type": rtype}
    if dnssec:
        params["do"] = "1"
    j = await oh.get_json(DOH, params=params, headers={"accept": "application/dns-json"}, timeout=15.0)
    recs = []
    for a in j.get("Answer") or []:
        t = TYPE_NAMES.get(a.get("type"))
        if t:
            recs.append({"name": str(a.get("name", "")).rstrip("."), "type": t, "ttl": a.get("TTL"), "data": str(a.get("data", ""))})
    return recs, bool(j.get("AD"))


def unquote_txt(data: str) -> str:
    """TXT data arrives as one or more quoted chunks; join them."""
    parts = [p for p in data.replace('" "', "\x00").strip('"').split("\x00")]
    return "".join(parts)
