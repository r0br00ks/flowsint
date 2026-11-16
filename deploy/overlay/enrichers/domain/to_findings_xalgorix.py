import hashlib
import time
from datetime import date
from typing import Any, Dict, List, Optional

from flowsint_core.core.logger import Logger
from flowsint_enrichers import xalgorix_client as xc
from flowsint_enrichers.osint_base import ActiveEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.finding import Finding

# Phase ids are Xalgorix's methodology list. light_active leaves out injection, authentication, file upload,
# deserialization/RCE, race conditions and exploit verification, which can disturb a live business site.
PHASES = {"recon_only": [1, 22], "light_active": [1, 3, 4, 13, 14, 15, 22], "all": []}
SEVERITIES = {"info": ["info", "low", "medium", "high", "critical"], "low": ["low", "medium", "high", "critical"], "medium": ["medium", "high", "critical"], "high": ["high", "critical"]}


def _first(d: Dict[str, Any], *names: str) -> Optional[Any]:
    for n in names:
        v = d.get(n)
        if v not in (None, "", []):
            return v
    return None


@flowsint_enricher
class DomainToFindingsXalgorix(ActiveEnricher):
    """[Xalgorix] Runs the AI-driven Xalgorix scanner on a domain and returns its findings. ACTIVE: in the default passive mode it only uses public sources, but active mode sends real attack traffic to the target (injection, SSRF, exploit verification). Runs only when authorized is set to yes. Re-running within a day collects the earlier scan's findings instead of starting another."""

    InputType = Domain
    OutputType = Finding
    RELATIONSHIP = "HAS_FINDING"
    SOURCE = "Xalgorix"

    @classmethod
    def name(cls) -> str:
        return "domain_to_findings_xalgorix"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            cls.authorized_param(),
            {
                "name": "mode",
                "type": "select",
                "description": "passive uses public sources only. active sends probes and attack traffic to the target.",
                "required": False,
                "default": "passive",
                "options": [{"label": "Passive (public sources only)", "value": "passive"}, {"label": "Active (probes the target)", "value": "active"}],
            },
            {
                "name": "phases",
                "type": "select",
                "description": "recon_only: reconnaissance and report. light_active: also directory discovery, CORS and cookies, subdomain takeover, open redirect and email security (no injection, upload or exploit tests). all: every phase, including intrusive ones (long).",
                "required": False,
                "default": "recon_only",
                "options": [{"label": "Recon and report only", "value": "recon_only"}, {"label": "Light active (no injection or exploit tests)", "value": "light_active"}, {"label": "All phases (intrusive)", "value": "all"}],
            },
            {
                "name": "min_severity",
                "type": "select",
                "description": "Only report findings at or above this severity.",
                "required": False,
                "default": "info",
                "options": [{"label": s.capitalize(), "value": s} for s in ("info", "low", "medium", "high")],
            },
            {"name": "wait_minutes", "type": "string", "description": "How long to wait for the scan (max 50). If it is still running, run the enricher again later to collect.", "required": False, "default": "30"},
            {"name": "reuse_hours", "type": "string", "description": "Collect an existing scan of this domain started within this many hours instead of starting a new one. 0 always starts a new scan.", "required": False, "default": "24"},
        ]

    def label_of(self, item) -> str:
        return item.domain

    async def fetch(self, item) -> Dict[str, Any]:
        self.require_authorized()
        mode = str(self.params.get("mode") or "passive")
        phases = PHASES[str(self.params.get("phases") or "recon_only")]
        sev = str(self.params.get("min_severity") or "info")
        wait_s = min(float(self.params.get("wait_minutes") or 30), 50.0) * 60
        reuse_h = float(self.params.get("reuse_hours") or 24)
        domain = item.domain.lower()
        async with xc.Session() as sx:
            detail = None
            note = ""
            if reuse_h > 0:
                prior = await sx.find_recent_scan(domain, reuse_h)
                if prior:
                    detail = await sx.scan_detail(prior["id"])
                    note = f"collected existing scan {prior['id']} ({detail.get('status')})"
            if detail is None:
                t0 = time.time()
                started = await sx.start_scan(domain, f"flowsint: {domain}", mode, mode, phases or None, SEVERITIES[sev] if sev != "info" else None)
                iid = str(started.get("instance_id") or started.get("id") or "")
                Logger.info(self.sketch_id, {"message": f"[Xalgorix] started {mode} scan of {domain} (instance {iid}); waiting up to {int(wait_s // 60)} min"})
                detail = await sx.wait(domain, iid, t0, wait_s)
                note = "new scan"
            if detail is None:
                raise xc.XalgorixError("the scan was started but did not appear in Xalgorix; check the dashboard")
            status = str(detail.get("status", "")).lower()
            if status in xc.RUNNING:
                Logger.warn(self.sketch_id, {"message": f"[Xalgorix] {domain}: scan still {status} after the wait; run this enricher again later to collect its findings"})
            elif status == "paused":
                Logger.warn(self.sketch_id, {"message": f"[Xalgorix] {domain}: scan is paused ({detail.get('stop_reason') or 'no reason given'}); it was not resumed"})
            # Xalgorix reports status "finished" even when its model failed mid-run; stop_reason and the phase table say so.
            reason = str(detail.get("stop_reason") or "")
            todo = sorted((k for k, v in (detail.get("phase_status") or {}).items() if v in ("pending", "running")), key=lambda k: int(k) if str(k).isdigit() else 99)
            if reason and reason.lower() not in ("completed", "finished", "done", "success") and status not in xc.RUNNING:
                Logger.warn(self.sketch_id, {"message": f"[Xalgorix] {domain}: scan ended early ({reason}); phases not completed: {', '.join(todo) or 'none listed'}. The findings below may be incomplete."})
                note += f"; ended early: {reason}"
            return {"detail": detail, "note": note, "min_severity": sev}

    def build(self, item, data: Dict[str, Any]) -> List[Finding]:
        d = data["detail"]
        allowed = SEVERITIES[data["min_severity"]]
        scan_id = str(d.get("id", ""))
        out: List[Finding] = []
        for v in d.get("vulns") or []:
            sev = str(_first(v, "severity") or "info").lower()
            if sev not in allowed:
                continue
            title = str(_first(v, "title", "name") or "Xalgorix finding")
            where = _first(v, "endpoint", "url", "location", "host")
            vid = str(_first(v, "id") or hashlib.sha1(f"{title}|{where}".encode()).hexdigest()[:12])
            verified = _first(v, "verified")
            out.append(
                Finding(
                    finding_id=f"xalgorix-{scan_id}-{vid}"[:200],
                    title=title,
                    severity=sev.capitalize(),
                    status="Verified" if verified else "Open (unverified)",
                    cve=str(_first(v, "cve")) if _first(v, "cve") else None,
                    component=str(where)[:300] if where else None,
                    date=date.today().isoformat(),
                    url=f"{xc.base_url()}/scans/{d.get('instance_id') or scan_id}",
                    source="Xalgorix",
                    # Finding allows extra properties; Xalgorix reports a CVSS score and a CWE rather than a CVE.
                    cvss=_first(v, "cvss"),
                    cwe=_first(v, "cwe_id", "cwe"),
                    description=(str(_first(v, "description"))[:600] if _first(v, "description") else None),
                    remediation=(str(_first(v, "remediation", "fix"))[:600] if _first(v, "remediation", "fix") else None),
                    verification=_first(v, "verification_method"),
                )
            )
        self.log_graph_message(f"{item.domain}: Xalgorix scan {scan_id} is {d.get('status')} with {len(d.get('vulns') or [])} finding(s); {data['note']}.")
        return out


InputType = DomainToFindingsXalgorix.InputType
OutputType = DomainToFindingsXalgorix.OutputType
