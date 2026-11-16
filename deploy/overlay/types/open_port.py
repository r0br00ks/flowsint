from typing import Optional, Self

from pydantic import Field, model_validator

from .flowsint_base import FlowsintType
from .registry import flowsint_type


@flowsint_type
class OpenPort(FlowsintType):
    """A port seen open on one specific host.

    Flowsint's own Port type is keyed on the number alone, so every IP with 443 open would merge into a
    single node. This type is keyed on host, port and protocol so each host keeps its own ports.
    """

    endpoint: str = Field(
        ...,
        description="host:port/protocol, e.g. 66.29.141.57:443/tcp",
        title="Endpoint",
        json_schema_extra={"primary": True},
    )
    host: Optional[str] = Field(None, description="IP address or host name", title="Host")
    number: Optional[int] = Field(None, description="Port number", title="Port")
    protocol: Optional[str] = Field(None, description="tcp or udp", title="Protocol")
    service: Optional[str] = Field(None, description="Service or product name", title="Service")
    banner: Optional[str] = Field(None, description="Version or banner text", title="Banner")
    source: Optional[str] = Field(None, description="Tool that saw the port", title="Source")

    @model_validator(mode="after")
    def compute_label(self) -> Self:
        self.nodeLabel = f"{self.endpoint} {self.service}".strip() if self.service else self.endpoint
        return self
