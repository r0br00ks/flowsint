"""Client for the Xalgorix scanner on dockerops (an AI-driven security scanner with a session-cookie API).

Configuration from the celery container's environment: XALGORIX_URL, XALGORIX_USERNAME, XALGORIX_PASSWORD
(copies of the Bitwarden secrets XALGORIX__USERNAME and XALGORIX__PASSWORD). Only start_scan() sends traffic to a
target, and the enricher that calls it is behind the authorized gate. Nothing here resumes Xalgorix's paused
queue or changes its settings.
"""

import asyncio
import time
from typing import Any, Dict, List, Optional

import httpx

from flowsint_enrichers import osint_http as oh

RUNNING = {"running", "queued", "starting", "pending", "active", "admitted", "in_progress"}


class XalgorixError(Exception):
    pass


def base_url() -> str:
    return oh.env("XALGORIX_URL", "http://100.93.251.35:2903").rstrip("/")


class Session:
    def __init__(self) -> None:
        user, pw = oh.env("XALGORIX_USERNAME"), oh.env("XALGORIX_PASSWORD")
        if not (user and pw):
            raise XalgorixError("XALGORIX_USERNAME and XALGORIX_PASSWORD are not set on this container")
        self._user, self._pw = user, pw
        self._c = httpx.AsyncClient(timeout=60.0, headers={"User-Agent": oh.USER_AGENT, "Origin": base_url(), "Referer": base_url() + "/"})

    async def __aenter__(self) -> "Session":
        r = await self._c.post(f"{base_url()}/api/auth/login", json={"username": self._user, "password": self._pw})
        if r.status_code != 200:
            raise XalgorixError(f"Xalgorix login failed: HTTP {r.status_code} {r.text[:120]}")
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self._c.aclose()

    async def get(self, path: str) -> Any:
        r = await self._c.get(base_url() + path)
        if r.status_code != 200:
            raise XalgorixError(f"GET {path} returned {r.status_code}: {r.text[:160]}")
        return r.json()

    async def post(self, path: str, body: Dict[str, Any]) -> Any:
        r = await self._c.post(base_url() + path, json=body)
        if r.status_code not in (200, 201, 202):
            raise XalgorixError(f"POST {path} returned {r.status_code}: {r.text[:200]}")
        return r.json()

    # --- scans

    async def find_recent_scan(self, target: str, within_hours: float) -> Optional[Dict[str, Any]]:
        """Newest scan of exactly this target started within the window, any state."""
        rows = await self.get("/api/scans")
        rows = rows if isinstance(rows, list) else rows.get("scans", [])
        cutoff = time.time() - within_hours * 3600
        best = None
        for r in rows:
            if str(r.get("target", "")).lower() != target.lower():
                continue
            ts = _parse_ts(r.get("started_at"))
            if ts and ts >= cutoff and (best is None or ts > best[0]):
                best = (ts, r)
        return best[1] if best else None

    async def start_scan(self, target: str, name: str, recon_mode: str, scan_intensity: str, phases: Optional[List[int]], severity_filter: Optional[List[str]]) -> Dict[str, Any]:
        body: Dict[str, Any] = {"targets": [target], "name": name, "scan_mode": "single", "recon_mode": recon_mode, "scan_intensity": scan_intensity}
        if phases:
            body["phases"] = phases
        if severity_filter:
            body["severity_filter"] = severity_filter
        return await self.post("/api/scan", body)

    async def scan_detail(self, scan_id: str) -> Dict[str, Any]:
        return await self.get(f"/api/scans/{scan_id}")

    async def scan_for_instance(self, target: str, instance_id: str, started_after: float) -> Optional[Dict[str, Any]]:
        rows = await self.get("/api/scans")
        rows = rows if isinstance(rows, list) else rows.get("scans", [])
        for r in sorted(rows, key=lambda x: _parse_ts(x.get("started_at")) or 0, reverse=True):
            if str(r.get("target", "")).lower() != target.lower():
                continue
            ts = _parse_ts(r.get("started_at")) or 0
            if ts < started_after - 120:
                continue
            d = await self.scan_detail(r["id"])
            if d.get("instance_id") == instance_id or not instance_id:
                return d
        return None

    async def wait(self, target: str, instance_id: str, started_after: float, timeout_s: float, poll_s: float = 20.0) -> Optional[Dict[str, Any]]:
        deadline = time.monotonic() + timeout_s
        detail: Optional[Dict[str, Any]] = None
        while True:
            detail = await self.scan_for_instance(target, instance_id, started_after)
            if detail and str(detail.get("status", "")).lower() not in RUNNING:
                return detail
            if time.monotonic() >= deadline:
                return detail
            await asyncio.sleep(poll_s)


def _parse_ts(v: Any) -> Optional[float]:
    if not v:
        return None
    from datetime import datetime, timezone

    try:
        s = str(v).replace("Z", "+00:00")
        if "." in s:  # nanoseconds: trim to microseconds
            head, rest = s.split(".", 1)
            frac, tz = (rest.split("+", 1) + [""])[:2] if "+" in rest else (rest, "")
            s = f"{head}.{frac[:6]}" + (f"+{tz}" if tz else "")
        return datetime.fromisoformat(s).astimezone(timezone.utc).timestamp()
    except ValueError:
        return None
