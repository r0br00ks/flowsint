from typing import Optional, Self

from pydantic import Field, model_validator

from .flowsint_base import FlowsintType
from .registry import flowsint_type


@flowsint_type
class Cve(FlowsintType):
    """A publicly disclosed vulnerability identified by its CVE id."""

    cve_id: str = Field(
        ...,
        description="CVE identifier, e.g. CVE-2021-41773",
        title="CVE ID",
        json_schema_extra={"primary": True},
    )
    name: Optional[str] = Field(None, description="Short title of the vulnerability", title="Name")
    cvss: Optional[float] = Field(None, description="CVSS base score", title="CVSS")
    severity: Optional[str] = Field(None, description="Severity band (low, medium, high, critical)", title="Severity")
    product: Optional[str] = Field(None, description="Affected product", title="Product")
    fixed_in: Optional[str] = Field(None, description="Version(s) that fix it, if known", title="Fixed in")
    exploited_in_the_wild: Optional[bool] = Field(
        None, description="Whether exploitation in the wild has been reported", title="Exploited in the wild"
    )
    published: Optional[str] = Field(None, description="Publication date", title="Published")
    url: Optional[str] = Field(None, description="Link to the write-up", title="URL")
    source: Optional[str] = Field(None, description="Tool that supplied this record", title="Source")

    @model_validator(mode="after")
    def compute_label(self) -> Self:
        self.nodeLabel = self.cve_id
        return self
