"""Clients for the self-hosted tools on the Dockerfarm (dockerops), used by the enrichers in this fork.

Configuration comes from environment variables set by Coolify on the api and celery services:

    SPIDERFOOT_URL, ABUSEBOX_URL, HEXBRAIN_URL, HEXBRAIN_API_KEY, DEFECTDOJO_URL, DEFECTDOJO_API_TOKEN

The keys originate in Bitwarden (Agent-Shared) and are never written to this repo.
Python enrichers are not subject to the template SSRF guard, so private and Tailscale addresses work.
"""

import asyncio
import html
import os
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx

# Cloudflare in front of DefectDojo answers 403 (error 1010) to library user agents.
USER_AGENT = "Mozilla/5.0 (compatible; flowsint-enricher/1.0)"


class ToolError(Exception):
    """A dockerops tool was unreachable, refused the call or returned something unexpected."""


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _base(name: str, default: str) -> str:
    return env(name, default).rstrip("/")


def spiderfoot_url() -> str:
    return _base("SPIDERFOOT_URL", "http://100.93.251.35:2910")


def abusebox_url() -> str:
    return _base("ABUSEBOX_URL", "http://100.93.251.35:2915")


def hexbrain_url() -> str:
    return _base("HEXBRAIN_URL", "http://100.93.251.35:2921")


def defectdojo_url() -> str:
    return _base("DEFECTDOJO_URL", "https://ddojo.techbrooks.ca")


def _client(timeout: float = 30.0) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout, headers={"User-Agent": USER_AGENT}, follow_redirects=True)


# ---------------------------------------------------------------- SpiderFoot

# SpiderFoot event types that map onto Flowsint entities.
SF_SUBDOMAINS = ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED"]
SF_IPS = ["IP_ADDRESS", "IPV6_ADDRESS"]
SF_EMAILS = ["EMAILADDR", "EMAILADDR_GENERIC"]
SF_HOSTED_DOMAINS = ["CO_HOSTED_SITE", "INTERNET_NAME", "DOMAIN_NAME"]


async def sf_find_recent_scan(target: str, max_age_hours: float) -> Optional[str]:
    """Return the id of a FINISHED scan of this exact target that ended within max_age_hours."""
    async with _client() as c:
        r = await c.get(f"{spiderfoot_url()}/scanlist")
        r.raise_for_status()
        rows = r.json()
    cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
    best = None
    for row in rows:
        # [id, name, target, created, started, ended, status, ...]
        if len(row) < 7 or str(row[2]).strip().lower() != target.strip().lower():
            continue
        if row[6] != "FINISHED":
            continue
        try:
            ended = datetime.strptime(row[5], "%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            continue
        if ended >= cutoff and (best is None or ended > best[0]):
            best = (ended, row[0])
    return best[1] if best else None


async def sf_start_scan(target: str, mode: str) -> str:
    """Start a SpiderFoot scan using one of its built-in use cases and return the scan id."""
    if mode not in ("passive", "footprint", "investigate", "all"):
        raise ToolError(f"unknown SpiderFoot scan mode '{mode}'")
    async with _client() as c:
        r = await c.post(
            f"{spiderfoot_url()}/startscan",
            data={
                "scanname": f"flowsint: {target}",
                "scantarget": target,
                "usecase": mode,
                "modulelist": "",
                "typelist": "",
            },
        )
        r.raise_for_status()
        body = r.json()
    if not (isinstance(body, list) and len(body) >= 2 and body[0] == "SUCCESS"):
        raise ToolError(f"SpiderFoot refused the scan: {str(body)[:200]}")
    return str(body[1])


async def sf_wait(scan_id: str, timeout_s: float, poll_s: float = 10.0) -> str:
    """Poll until the scan stops or timeout_s elapses. Returns the last status seen."""
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while True:
        async with _client() as c:
            r = await c.get(f"{spiderfoot_url()}/scanstatus", params={"id": scan_id})
            r.raise_for_status()
            row = r.json()
        # [name, target, created, started, ended, status, {risk}]
        status = row[5] if isinstance(row, list) and len(row) > 5 else "UNKNOWN"
        if status in ("FINISHED", "ABORTED", "ERROR-FAILED"):
            return status
        if time.monotonic() >= deadline:
            return status
        await asyncio.sleep(poll_s)


async def sf_results(scan_id: str, event_types: List[str]) -> List[str]:
    """Unique event values for the given event types, HTML-unescaped, in first-seen order."""
    seen: Dict[str, None] = {}
    async with _client() as c:
        for et in event_types:
            r = await c.get(
                f"{spiderfoot_url()}/scaneventresultsunique",
                params={"id": scan_id, "eventType": et, "filterfp": "0"},
            )
            r.raise_for_status()
            for row in r.json():
                value = html.unescape(str(row[0])).strip()
                if value:
                    seen.setdefault(value, None)
    return list(seen)


async def sf_run(target: str, mode: str, reuse_hours: float, timeout_s: float) -> tuple[str, str, bool]:
    """Reuse a recent scan of the target or start one. Returns (scan_id, final_status, reused)."""
    if reuse_hours > 0:
        existing = await sf_find_recent_scan(target, reuse_hours)
        if existing:
            return existing, "FINISHED", True
    scan_id = await sf_start_scan(target, mode)
    status = await sf_wait(scan_id, timeout_s)
    return scan_id, status, False


# ------------------------------------------------------------------ AbuseBox


async def abusebox_quick_check(hostname: str) -> Dict[str, Any]:
    """Public DNSBL check of an IP or domain against AbuseBox's resolver and 24 blocklists."""
    async with _client(timeout=60.0) as c:
        r = await c.get(f"{abusebox_url()}/api/blacklist/quick-check/", params={"hostname": hostname})
    if r.status_code != 200:
        raise ToolError(f"AbuseBox quick-check returned {r.status_code}: {r.text[:200]}")
    return r.json()


# ------------------------------------------------------------------ HexBrain


async def hexbrain_call(tool: str, body: Dict[str, Any]) -> Dict[str, Any]:
    key = env("HEXBRAIN_API_KEY")
    if not key:
        raise ToolError("HEXBRAIN_API_KEY is not set on this container")
    async with _client(timeout=60.0) as c:
        r = await c.post(
            f"{hexbrain_url()}/api/v1/{tool}",
            json=body,
            headers={"Authorization": f"Bearer {key}"},
        )
    if r.status_code != 200:
        raise ToolError(f"HexBrain {tool} returned {r.status_code}: {r.text[:200]}")
    return r.json()


# ---------------------------------------------------------------- DefectDojo


async def defectdojo_findings(params: Dict[str, Any], limit: int) -> List[Dict[str, Any]]:
    token = env("DEFECTDOJO_API_TOKEN")
    if not token:
        raise ToolError("DEFECTDOJO_API_TOKEN is not set on this container")
    q = dict(params)
    q["limit"] = min(max(limit, 1), 200)
    async with _client(timeout=60.0) as c:
        r = await c.get(
            f"{defectdojo_url()}/api/v2/findings/",
            params=q,
            headers={"Authorization": f"Token {token}"},
        )
    if r.status_code != 200:
        raise ToolError(f"DefectDojo returned {r.status_code}: {r.text[:200]}")
    return r.json().get("results", [])
