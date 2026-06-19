<p align="center">
  <img src="docs/Gemini_Generated_Image_pa9wjvpa9wjvpa9w.png" alt="OrchestraSecAI — passive web security scanner" width="100%" />
</p>

# OrchestraSecAI

Passive web security scanner — modular monolith with FastAPI, ARQ workers, Next.js UI, and optional vLLM-powered reports.

## Quick start (Docker)

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
# separate terminal:
arq orchestrasecai.workers.settings.WorkerSettings
```

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

## Architecture

| Layer | Path | Role |
|-------|------|------|
| API | `apps/api/src/orchestrasecai/api/` | REST, auth, enqueue scans |
| Scanner | `apps/api/src/orchestrasecai/scanner/` | Crawler + plugin runtime |
| Checks (plugins) | `apps/api/src/orchestrasecai/checks/` | Header, Cookie, TLS, Disclosure |
| Workers | `apps/api/src/orchestrasecai/workers/` | ARQ `run_scan_task`, `run_ai_analysis_task` |
| AI | `apps/api/src/orchestrasecai/ai/` | vLLM client, YAML prompts, reports |
| Web | `apps/web/` | Next.js dashboard |

## Feature flags

| Variable | Default | Purpose |
|----------|---------|---------|
| `MOCK_AI` | `true` | Canned AI JSON without GPU |
| `QDRANT_ENABLED` | `false` | Similar-finding embeddings |
| `MULTI_TENANT_ENABLED` | `false` | Org switcher (UI stub) |

## Security

- **Passive-only:** GET/HEAD crawler only — see `docs/passive-only-policy.md`
- **SSRF guards:** Private IP blocklist — see `docs/threat-model.md`
- **Target verification:** `verification_status` stub (`unverified` default); DNS verify deferred

## Tests

```bash
cd apps/api && pytest
cd apps/web && npm run lint
```

## License

Proprietary — OrchestraSecAI MVP.
