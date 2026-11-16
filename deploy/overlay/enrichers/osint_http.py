"""Small HTTP helper shared by the free-source enrichers: browser-style User-Agent, retries with backoff."""

import asyncio
import os
from typing import Any, Dict, Iterable, Optional

import httpx

USER_AGENT = "Mozilla/5.0 (compatible; flowsint-enricher/1.0)"


class SourceError(Exception):
    """A data source was unreachable, refused the call or returned something unexpected."""


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


async def get(
    url: str,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 30.0,
    retries: int = 2,
    ok: Iterable[int] = (200,),
) -> httpx.Response:
    """GET with retries on timeouts, 429 and 5xx. Returns the response if its status is in `ok`."""
    hdrs = {"User-Agent": USER_AGENT}
    hdrs.update(headers or {})
    last = "no response"
    for attempt in range(retries + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
                r = await c.get(url, params=params, headers=hdrs)
            if r.status_code in tuple(ok):
                return r
            last = f"HTTP {r.status_code}: {r.text[:120]}"
            if r.status_code not in (429, 500, 502, 503, 504, 522, 524):
                break
        except (httpx.TimeoutException, httpx.TransportError) as e:
            last = f"{type(e).__name__}: {str(e)[:100]}"
        if attempt < retries:
            await asyncio.sleep(2 * (attempt + 1))
    raise SourceError(f"{url.split('?')[0]} failed ({last})")


async def get_json(url: str, **kw: Any) -> Any:
    r = await get(url, **kw)
    try:
        return r.json()
    except ValueError:
        raise SourceError(f"{url.split('?')[0]} did not return JSON: {r.text[:100]!r}")
