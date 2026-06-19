from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CheckPhase(str, Enum):
    PAGE = "page"
    HOST = "host"
    SCAN = "scan"


@dataclass
class FindingDraft:
    plugin_id: str
    severity: str
    title: str
    description: str
    fingerprint: str
    location: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    cvss_estimate: float | None = None


@dataclass
class PageContext:
    url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    cookies: list[dict[str, str]]
    body_snippet: str
    depth: int


@dataclass
class HostContext:
    hostname: str
    tls_info: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckContext:
    scan_id: str
    org_id: str
    page: PageContext | None = None
    host: HostContext | None = None
    scan_config: dict[str, Any] = field(default_factory=dict)


class SecurityCheck(ABC):
    plugin_id: str
    name: str
    version: str = "1.0.0"
    phase: CheckPhase = CheckPhase.PAGE
    aliases: list[str] = field(default_factory=list)  # type: ignore[misc]

    @abstractmethod
    async def run(self, ctx: CheckContext) -> list[FindingDraft]:
        ...
