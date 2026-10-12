# Scan Execution Policy

OrchestraSecAI uses a **LangGraph agent orchestrator** for all scans. Operators provide a
natural-language **mission**; the agent plans tool calls, the executor runs them through
the gated tool layer, and a critic decides whether to iterate (bounded by
`AGENT_MAX_ITERATIONS` and `AGENT_MAX_TOOLS_PER_PLAN`).

Scans run only against targets whose ownership was proven with a DNS TXT challenge; see
[scan-lifecycle.md](./scan-lifecycle.md).

## Tool layer (mandatory gateway)

The agent never performs network I/O itself. `ScanToolLayer` validates and executes:

| Tool | Engine | HTTP behaviour |
|------|--------|----------------|
| `passive_crawl` | `CrawlerEngine` | GET/HEAD, in scope, policy-clamped limits |
| `run_check` | `CheckExecutor` + PAGE-phase plugins | GET (on-demand fetch) or crawled page |
| `active_probe` | `ActiveProbeEngine` | Technique-specific, only when authorized for the scan |
| `lookup_cve` | `CveLookupService` (NVD API) | Outbound to the configured NVD endpoint only |
| `generate_poc` | `PocGenerator` (LLM) | No HTTP; draft stored as AI output, never executed |

All target traffic from these tools goes through the egress transport
(`security/egress.py`): scope, method allowlist, request budget, public-only DNS with
connection pinning, redirect-hop validation and body caps.

## Passive by default

- The crawler and checks are passive (`assert_passive_method` and the transport method
  allowlist enforce GET/HEAD).
- Active techniques (`cors_origin_test`, `open_redirect_follow`, `reflected_xss_check`,
  `cookie_flags_probe`, and `csrf_form_probe`, which sends a fixed inert POST body) run
  only when **all** hold:
  1. the deployment sets `ACTIVE_PROBES_ALLOWED=true`;
  2. the scan was created with `allow_active_probes=true` by a user holding
     `scans:active` (owner/admin) — audited as `scan.active_probes_opt_in`;
  3. it is the scan's first execution attempt (never replayed during crash recovery).
- Model-supplied probe parameters are validated against strict patterns; request bodies
  are fixed by the technique, not by the model.

## Enforcement summary

1. **Authorization:** verified, unexpired ownership of the exact hostname, checked by the
   API and again by the worker at execution time.
2. **Scope:** exact host + explicit subdomains; redirects to other hosts are refused.
3. **SSRF:** all resolved addresses must be public; connections are pinned.
4. **Budgets:** policy pages/depth/RPS, per-scan request budget, response cap, agent
   iteration/tool limits, global deadline.
5. **Audit:** `agent.tool_call` / `agent.tool_denied` entries with tool, reason and a
   parameter hash for active probes; lifecycle events (`scan.create`, `scan.cancel`,
   `scan.completed`, `scan.execution_denied`, …).
6. **Trace:** reasoning in `agent_sessions.trace` (capped at 500 entries).

## Operator responsibilities

- Only register domains you own or are authorized in writing to test.
- Keep scan policies conservative (`max_pages`, `requests_per_second`, blocked paths such
  as `/logout`).
- Review findings and the agent trace before acting on AI enrichment or PoC drafts.

## Deprecated

The linear `run_scan` (crawl → all plugins) is removed. `plugin_ids` on `POST /scans` is
accepted but ignored.
