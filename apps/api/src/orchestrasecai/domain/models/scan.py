from dataclasses import dataclass, field
from enum import Enum


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
    location: dict = field(default_factory=dict)
    evidence: list[dict] = field(default_factory=list)
    cvss_estimate: float | None = None


@dataclass
class PageSnapshot:
    url: str
    final_url: str | None
    status_code: int | None
    content_type: str | None
    depth: int
    parent_url: str | None
    headers: dict
    body_snippet: str
    cookies: list[dict] = field(default_factory=list)


@dataclass
class TLSInfo:
    host: str
    protocol: str | None = None
    cipher: str | None = None
    cert_expiry_days: int | None = None
    issues: list[str] = field(default_factory=list)
