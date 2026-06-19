# OrchestraSecAI Architecture

Modular monolith: one repository, one deployable API, horizontally scalable ARQ workers.

```
orchestrasecai/
├── apps/api/          # FastAPI + scanner + checks + workers + AI
├── apps/web/          # Next.js App Router UI
├── docker/            # Dockerfiles + Compose
├── docs/              # Threat model, policies
└── packages/check-sdk/  # Optional plugin types (stub)
```

## Scan lifecycle

1. User creates scan via `POST /api/v1/scans`  
2. API persists `status=queued`, enqueues `run_scan_task` on Redis/ARQ  
3. Worker crawls target (httpx, robots.txt, rate limits)  
4. PAGE/HOST plugins produce `Finding` rows  
5. Worker enqueues `run_ai_analysis_task`  
6. AI pipeline writes `ai_analyses` + HTML/JSON `reports`  
7. UI streams progress via SSE `GET /scans/{id}/events`  

## Module boundaries

- **api/** — HTTP only  
- **domain/** — use-cases (`scan_runner`)  
- **scanner/** — crawler + executor (no SQL in plugins)  
- **checks/** — plugin implementations  
- **persistence/** — SQLAlchemy + Alembic  
- **workers/** — ARQ entrypoints  
- **ai/** — LLM + prompts + report templates  

## Data stores

| Store | Purpose |
|-------|---------|
| PostgreSQL | OLTP: orgs, scans, findings, reports |
| Redis | ARQ queue + SSE pub/sub |
| Qdrant | Optional finding embeddings (`QDRANT_ENABLED`) |

See the full MVP plan in project documentation for roadmap phases.
