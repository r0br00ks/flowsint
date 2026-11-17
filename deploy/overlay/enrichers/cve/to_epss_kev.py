import time
from typing import Any, Dict, List, Optional

from flowsint_enrichers import osint_http as oh
from flowsint_enrichers.osint_base import FetchEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.cve import Cve
from flowsint_types.finding import Finding

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_kev: Dict[str, Any] = {"at": 0.0, "by_id": {}}


async def _kev_index() -> Dict[str, Dict[str, Any]]:
    if time.time() - _kev["at"] > 6 * 3600 or not _kev["by_id"]:
        j = await oh.get_json(KEV_URL, timeout=60.0, retries=3)
        _kev["by_id"] = {v["cveID"]: v for v in j.get("vulnerabilities", [])}
        _kev["at"] = time.time()
    return _kev["by_id"]


@flowsint_enricher
class CveToEpssKev(FetchEnricher):
    """[FIRST EPSS + CISA KEV] How likely a CVE is to be exploited (EPSS score and percentile, free, no key) and whether CISA lists it as exploited in the wild. Turns a CVE list into a priority order."""

    InputType = Cve
    OutputType = Finding
    RELATIONSHIP = "HAS_FINDING"
    SOURCE = "EPSS / CISA KEV"

    @classmethod
    def name(cls) -> str:
        return "cve_to_epss_kev"

    @classmethod
    def category(cls) -> str:
        return "Cve"

    @classmethod
    def key(cls) -> str:
        return "cve_id"

    def label_of(self, item) -> str:
        return item.cve_id

    async def fetch(self, item) -> Dict[str, Any]:
        epss = await oh.get_json("https://api.first.org/data/v1/epss", params={"cve": item.cve_id})
        rows = epss.get("data") or []
        return {"epss": rows[0] if rows else None, "kev": (await _kev_index()).get(item.cve_id)}

    def build(self, item, data: Dict[str, Any]) -> List[Finding]:
        out: List[Finding] = []
        e: Optional[Dict[str, Any]] = data["epss"]
        if e:
            score, pct = float(e["epss"]), float(e["percentile"])
            sev = "High" if score >= 0.5 else "Medium" if score >= 0.1 else "Low" if score >= 0.01 else "Info"
            out.append(
                Finding(
                    finding_id=f"epss-{item.cve_id}",
                    title=f"EPSS {score:.3f}: {pct * 100:.0f}th percentile for likelihood of exploitation in the next 30 days",
                    severity=sev,
                    status="Info",
                    cve=item.cve_id,
                    date=e.get("date"),
                    url=f"https://api.first.org/data/v1/epss?cve={item.cve_id}",
                    source="FIRST EPSS",
                )
            )
        k = data["kev"]
        if k:
            ransom = str(k.get("knownRansomwareCampaignUse", "")).lower() == "known"
            out.append(
                Finding(
                    finding_id=f"kev-{item.cve_id}",
                    title=f"CISA KEV: exploited in the wild ({k.get('vendorProject')} {k.get('product')})" + ("; used in ransomware campaigns" if ransom else ""),
                    severity="Critical" if ransom else "High",
                    status="Open",
                    cve=item.cve_id,
                    component=k.get("product"),
                    date=k.get("dateAdded"),
                    url=f"https://nvd.nist.gov/vuln/detail/{item.cve_id}",
                    source="CISA KEV",
                )
            )
        return out


InputType = CveToEpssKev.InputType
OutputType = CveToEpssKev.OutputType
