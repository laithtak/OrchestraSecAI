# OrchestraSecAI Architecture

Modular monolith: one repository, one FastAPI control plane, horizontally scalable ARQ
workers, PostgreSQL as the system of record and Redis for the job queue and live events.

```
orchestrasecai/
├── apps/api/          # FastAPI + agent + scanner + checks + workers + AI
├── apps/web/          # Next.js App Router UI
├── docker/            # Dockerfiles + Compose
├── docs/              # Architecture, lifecycle, policy, threat model
└── packages/check-sdk/  # Future plugin types (stub)
```

## Scan lifecycle (authoritative path)

```text
POST /targets ─► DNS TXT challenge ─► POST /targets/{id}/verify (ownership bound)
POST /scans ─► authorization gate ─► commit (queued) ─► ARQ run_agent_scan_task
  ─► atomic claim (lease) ─► re-authorize from DB ─► LangGraph Planner → Executor → Critic
       Executor ─► ScanToolLayer (deterministic policy, audit)
                     ─► GuardedTransport (scope, SSRF, DNS pinning, budgets)
                     ─► crawler / PAGE checks / allowlisted active probes
  ─► findings + redacted evidence ─► completed + deterministic report (one transaction)
  ─► optional AI enrichment (run_ai_analysis_task) ─► new report version
Reaper (ARQ cron, every minute): deadlines, lost workers, lost jobs, stale queue
```

Details: [scan-lifecycle.md](./scan-lifecycle.md). The legacy linear crawl → all-plugins
runner is removed; `domain/services/scan_runner.py` only re-exports the agent runner.

States: `queued`, `running`, `completed`, `failed`, `cancelled`, `timed_out`.

## Module boundaries

- **api/** — HTTP, authentication, RBAC, request validation; no scanning logic.
- **domain/** — use-cases: verification, lifecycle state machine, agent runner, reaper,
  finding store, reporting, remediation.
- **agent/** — LangGraph planner/executor/critic; proposes tool calls only.
- **scanner/** — tool layer (trust boundary), crawler, active probe engine, CVE lookup,
  PoC drafts, check runtime. No SQL in check plugins.
- **security/** — auth, RBAC, scope, SSRF, egress transport, redaction.
- **checks/** — deterministic check plugins.
- **persistence/** — SQLAlchemy models + Alembic migrations (PostgreSQL is authoritative).
- **workers/** — ARQ entrypoints and cron.
- **ai/** — LLM client, versioned prompts, optional enrichment pipeline.

## Data stores

| Store | Purpose |
|-------|---------|
| PostgreSQL | Orgs, users, targets, verification challenges, scans, findings, evidence, AI analyses, reports, audit logs |
| Redis | ARQ queue, cron, SSE pub/sub, rate limits, report view tokens |
| Qdrant | Optional finding embeddings (`QDRANT_ENABLED`) |

## Trust boundaries

1. Browser → API: bearer JWT, RBAC, organization scoping on every query.
2. API → worker: job payload carries only a scan id; the worker re-establishes tenant,
   authorization and scope from PostgreSQL.
3. LLM → tools: model output is a proposal validated by `ScanToolLayer`.
4. Scanner → network: only through `GuardedTransport`.
5. Target content → storage/reports: treated as hostile; redacted, bounded, escaped.

See [threat-model.md](./threat-model.md) and
[passive-only-policy.md](./passive-only-policy.md).
