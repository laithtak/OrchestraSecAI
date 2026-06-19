from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from orchestrasecai.domain.models.scan import PageSnapshot, TLSInfo


@dataclass
class CheckContext:
    scan_id: UUID
    org_id: UUID
    page: PageSnapshot | None = None
    tls: TLSInfo | None = None
    scan_config: dict = field(default_factory=dict)
    reporter: Any = None
