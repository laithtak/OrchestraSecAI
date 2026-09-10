# Agent Scanning Policy

OrchestraSecAI uses a **LangGraph agent orchestrator** for all scans. Operators provide a natural-language **mission**; the agent plans tool calls, executes them through a gated tool layer, and critiques results in a loop until complete or `max_iterations`.

## Scan flow

1. API creates scan + `agent_sessions` row with mission
2. Worker runs `run_agent_scan_task` → Planner → Executor → Critic loop
3. On completion, `run_ai_analysis_task` generates the report (unchanged)

## Tool layer (mandatory gateway)

All network I/O flows through `ScanToolLayer`. The agent never calls HTTP directly.

| Tool | Engine | HTTP methods |
|------|--------|--------------|
| `passive_crawl` | `CrawlerEngine` | GET only |
| `run_check` | `CheckExecutor` + plugins | GET (on-demand fetch) |
| `active_probe` | `ActiveProbeEngine` | Technique-specific (POST allowed here only) |
| `lookup_cve` | `CveLookupService` (NVD API) | Outbound to NVD |
| `generate_poc` | `PocGenerator` (LLM) | No HTTP |

## Passive vs active

- **Crawler** remains passive-only (`assert_passive_method` enforces GET/HEAD).
- **Mutating probes** (POST, form submission, CORS origin tests, etc.) run only via `active_probe` techniques registered in `ActiveProbeEngine`.
- Every tool call writes an `audit_logs` entry with `action=agent.tool_call`.

## Enforcement

1. **Scope:** `scope.py` + `ssrf.py` validate URLs before any request
2. **Rate limits:** Policy `requests_per_second` + org daily scan limit
3. **Audit:** `{tool, technique, url, params_hash}` in metadata
4. **Trace:** Reasoning stored in `agent_sessions.trace` JSONB (capped at 500 entries)

## Operator responsibilities

- Provide a clear, authorized mission (min 10 characters)
- Configure conservative `scan_policies` (`max_pages`, `requests_per_second`)
- Verify targets before scanning production systems
- Review agent trace and findings before acting on PoC drafts

## Deprecated

Linear `run_scan` (crawl → all plugins) is removed. `plugin_ids` on `POST /scans` is accepted but ignored.
