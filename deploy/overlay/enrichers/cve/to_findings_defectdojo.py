from typing import Any, Dict

from flowsint_enrichers.defectdojo_base import DefectDojoEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.cve import Cve
from flowsint_types.finding import Finding


@flowsint_enricher
class CveToFindingsDefectDojo(DefectDojoEnricher):
    """[DefectDojo] Where this CVE already shows up in your own estate (needs DEFECTDOJO_API_TOKEN on the container)."""

    InputType = Cve
    OutputType = Finding

    @classmethod
    def name(cls) -> str:
        return "cve_to_findings_defectdojo"

    @classmethod
    def category(cls) -> str:
        return "Cve"

    @classmethod
    def key(cls) -> str:
        return "cve_id"

    def query_for(self, item) -> Dict[str, Any]:
        return {"vulnerability_id": item.cve_id}

    def label_of(self, item) -> str:
        return item.cve_id


InputType = CveToFindingsDefectDojo.InputType
OutputType = CveToFindingsDefectDojo.OutputType
