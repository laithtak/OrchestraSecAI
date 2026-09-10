"""Deprecated linear scan runner — use agent_runner.run_agent_scan instead."""

from orchestrasecai.domain.services.agent_runner import run_agent_scan
from orchestrasecai.domain.services.event_bus import publish_event
from orchestrasecai.domain.services.finding_store import persist_findings

__all__ = ["publish_event", "persist_findings", "run_agent_scan"]

# Backward-compatible alias
run_scan = run_agent_scan
