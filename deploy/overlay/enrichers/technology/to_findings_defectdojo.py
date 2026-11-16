from typing import Any, Dict

from flowsint_enrichers.defectdojo_base import DefectDojoEnricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.finding import Finding
from flowsint_types.technology import Technology


@flowsint_enricher
class TechnologyToFindingsDefectDojo(DefectDojoEnricher):
    """[DefectDojo] Findings recorded in your own estate for a package or technology (needs DEFECTDOJO_API_TOKEN on the container)."""

    InputType = Technology
    OutputType = Finding

    @classmethod
    def name(cls) -> str:
        return "technology_to_findings_defectdojo"

    @classmethod
    def category(cls) -> str:
        return "Technology"

    @classmethod
    def key(cls) -> str:
        return "name"

    def query_for(self, item) -> Dict[str, Any]:
        q: Dict[str, Any] = {"component_name": item.name}
        if item.version:
            q["component_version"] = item.version
        return q

    def label_of(self, item) -> str:
        return f"{item.name} {item.version}".strip() if item.version else item.name


InputType = TechnologyToFindingsDefectDojo.InputType
OutputType = TechnologyToFindingsDefectDojo.OutputType
