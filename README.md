<p align="center">
  <img src="docs/Gemini_Generated_Image_pa9wjvpa9wjvpa9w.png" alt="OrchestraSecAI — passive web security scanner" width="100%" />
</p>

# OrchestraSecAI

Passive web security scanner — modular monolith with FastAPI, ARQ workers, Next.js UI, and optional vLLM-powered reports.

## Quick start (Docker)

The Compose quick start is a development environment. It intentionally uses development seed data,
mock AI, and local service credentials; it is not a production deployment configuration.

```bash
cd orchestrasecai
cp .env.example .env
docker compose -f docker/compose/docker-compose.yml up --build
```

- **Web UI:** http://localhost:3000  
- **API:** http://localhost:8000/api/v1/health  
- **OpenAPI:** http://localhost:8000/api/v1/openapi.json  

Default seed user (from `.env`):

- Email: `admin@orchestrasec.local`
- Password: `changeme123`

## Local development

### API + worker

```bash
cd apps/api
pip install -e ".[dev]"
export DATABASE_URL=postgresql+asyncpg://orchestrasec:orchestrasec@localhost:5432/orchestrasecai
export DATABASE_URL_SYNC=postgresql://orchestrasec:orchestrasec@localhost:5432/orchestrasecai
export REDIS_URL=redis://localhost:6379/0
alembic upgrade head
uvicorn orchestrasecai.main:app --reload --port 8000
# separate terminal (also runs the stale-scan reaper every minute):
arq orchestrasecai.workers.settings.WorkerSettings
```

### Verifying a domain you own

1. **Targets → Add** `https://app.your-domain.com` (must resolve to a public address).
2. **Generate token** and copy the value (it is shown once).
3. Publish a DNS TXT record `_orchestrasec.app.your-domain.com` with that value.
4. **Check DNS**. Once verified, the target can be scanned for
   `DOMAIN_VERIFICATION_MAX_AGE_DAYS` (default 30) before it must be re-checked.

### Local demo (mock target, no external traffic)

Runs the full lifecycle — registration, DNS verification, authorized scan, findings,
deterministic report, cancellation — through the real API and worker code against
PostgreSQL, using an in-process DNS and a mock web server:

```bash
cd apps/api
alembic upgrade head
python scripts/demo_lifecycle.py   # writes reports to apps/api/demo-output/
```

The data is created in the seeded development organization, so it is visible in the web
UI afterwards.

### Web

```bash
cd apps/web
npm install
NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev
```

### Dev Compose (hot reload)

```bash
docker compose -f docker/compose/docker-compose.dev.yml up
```

### GPU vLLM profile (optional)

```bash
docker compose -f docker/compose/docker-compose.yml -f docker/compose/docker-compose.gpu.yml --profile gpu up
```

Set `MOCK_AI=false` and `VLLM_BASE_URL` to your inference endpoint.

## Application environments

`APP_ENV` accepts `development`, `test`, or `production` and defaults to `development`.
Production mode refuses to start unless all of the following are true:

- `JWT_SECRET` is not a published placeholder and is at least 32 bytes.
- `DATABASE_URL` and `DATABASE_URL_SYNC` do not use the published development credentials.
- `SEED_ENABLED=false` prevents automatic creation of the development owner account.
- `MOCK_AI=false` uses a real OpenAI-compatible inference endpoint.
- `CORS_ORIGINS` contains only explicit origins, not `*`.
- `RATE_LIMIT_FAIL_OPEN=false` preserves rate limits when Redis is unavailable.

Production validation is shared by the API, worker, and other processes that load application
settings. Invalid configuration stops the process before it serves requests or executes jobs.

## Architecture

| Layer | Path | Role |
|-------|------|------|
| API | `apps/api/src/orchestrasecai/api/` | REST, auth, enqueue scans |
| Scanner | `apps/api/src/orchestrasecai/scanner/` | Crawler + plugin runtime |
| Checks (plugins) | `apps/api/src/orchestrasecai/checks/` | Header, Cookie, TLS, Disclosure |
| Workers | `apps/api/src/orchestrasecai/workers/` | ARQ `run_agent_scan_task`, `run_ai_analysis_task`, stale-scan reaper cron |
| AI | `apps/api/src/orchestrasecai/ai/` | vLLM client, YAML prompts, reports |
| Web | `apps/web/` | Next.js dashboard |

## Feature flags

| Variable | Default | Purpose |
|----------|---------|---------|
| `MOCK_AI` | `true` | Canned AI JSON without GPU |
| `QDRANT_ENABLED` | `false` | Similar-finding embeddings |
| `MULTI_TENANT_ENABLED` | `false` | Org switcher (UI stub) |

## Security

- **Verified targets only:** DNS TXT ownership challenge (random, hashed, expiring tokens)
  enforced by the API and again by the worker — see `docs/scan-lifecycle.md`
- **Network egress policy:** exact-host scope, every redirect hop validated, public-only
  DNS with connection pinning, request/response budgets — see `docs/threat-model.md`
- **Passive by default:** active probes need `ACTIVE_PROBES_ALLOWED=true` plus an audited
  per-scan opt-in by an owner/admin — see `docs/passive-only-policy.md`
- **Durable lifecycle:** `queued → running → completed | failed | cancelled | timed_out`,
  atomic transitions, leases, cancellation, crash recovery
- **Deterministic reports:** generated without an LLM; AI enrichment is optional and
  labelled non-authoritative

## Tests

```bash
cd apps/api && pytest
cd apps/web && npm run lint && npm run build
```

`tests/integration` runs against PostgreSQL (after `alembic upgrade head`) using the
`DATABASE_URL` from the environment and is skipped when no migrated database is
reachable. DNS and HTTP are always simulated in-process; no test contacts a real target.
To run them locally with throwaway containers:

```bash
docker run -d --name osc-pg -e POSTGRES_USER=orchestrasec -e POSTGRES_PASSWORD=orchestrasec -e POSTGRES_DB=orchestrasecai -p 55432:5432 postgres:16-alpine
docker run -d --name osc-redis -p 56379:6379 redis:7-alpine
export DATABASE_URL=postgresql+asyncpg://orchestrasec:orchestrasec@localhost:55432/orchestrasecai DATABASE_URL_SYNC=postgresql://orchestrasec:orchestrasec@localhost:55432/orchestrasecai REDIS_URL=redis://localhost:56379/0 APP_ENV=test
cd apps/api && alembic upgrade head && pytest
```

## License

Proprietary — OrchestraSecAI MVP.
