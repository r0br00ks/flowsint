from typing import Optional, Self

from pydantic import Field, model_validator

from .flowsint_base import FlowsintType
from .registry import flowsint_type


@flowsint_type
class Finding(FlowsintType):
    """A vulnerability finding recorded in a tracking system such as DefectDojo."""

    finding_id: str = Field(
        ...,
        description="Unique id of the finding, prefixed with its source (e.g. dojo-1915)",
        title="Finding ID",
        json_schema_extra={"primary": True},
    )
    title: Optional[str] = Field(None, description="Finding title", title="Title")
    severity: Optional[str] = Field(None, description="Severity (Critical, High, Medium, Low, Info)", title="Severity")
    status: Optional[str] = Field(None, description="Status such as Active or Mitigated", title="Status")
    cve: Optional[str] = Field(None, description="Related CVE id, if any", title="CVE")
    component: Optional[str] = Field(None, description="Affected package or component", title="Component")
    component_version: Optional[str] = Field(None, description="Version of the affected component", title="Component version")
    date: Optional[str] = Field(None, description="Date the finding was recorded", title="Date")
    url: Optional[str] = Field(None, description="Link to the finding in its source system", title="URL")
    source: Optional[str] = Field(None, description="System the finding came from", title="Source")

    @model_validator(mode="after")
    def compute_label(self) -> Self:
        sev = f"[{self.severity}] " if self.severity else ""
        self.nodeLabel = f"{sev}{self.title or self.finding_id}"
        return self
