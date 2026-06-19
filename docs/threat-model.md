# OrchestraSecAI Threat Model (MVP)

## System context

OrchestraSecAI is a **passive** web scanner: it issues polite HTTP GET/HEAD requests, inspects TLS handshakes, and analyzes responses. It does not exploit vulnerabilities, fuzz inputs, or brute-force credentials.

## Assets

| Asset | Sensitivity | Controls |
|-------|-------------|----------|
| User credentials | High | Argon2 hashing, JWT access (15m), refresh rotation |
| Scan artifacts (headers, snippets) | Medium | Redacted evidence in AI prompts; truncated bodies |
| Target URLs | Medium | SSRF validation before crawl |
| Audit logs | Medium | Append-only, 90-day retention (configurable) |
| Reports | Medium | Org-scoped access via RBAC |

## Threat actors

1. **Malicious tenant** — attempts to scan internal networks via SSRF  
2. **Unauthenticated attacker** — API abuse, credential stuffing  
3. **Compromised worker** — lateral movement to Postgres (mitigated: DB credentials only on API/worker)  
4. **LLM prompt injection** — evidence-only prompts; structured JSON output  

## Mitigations (MVP)

### SSRF

- Resolve hostname before crawl; block private, loopback, link-local, metadata ranges  
- Allow only `http`/`https` schemes  
- Implementation: `security/ssrf.py`

### Passive-only HTTP

- Allowlist: `GET`, `HEAD` only  
- No request bodies in crawler  
- Implementation: `security/passive_http.py`

### Abuse (verification deferred)

- Per-IP API rate limit (`RATE_LIMIT_REQUESTS_PER_MINUTE`)  
- Per-org scan cap (`RATE_LIMIT_SCANS_PER_DAY`)  
- UI disclaimer: scan only targets you are authorized to test  
- `verification_status` on targets: `unverified` | `pending` | `verified` (stub)

### Authentication & authorization

- JWT bearer tokens; RBAC roles: owner, admin, analyst, viewer  
- All queries filtered by `org_id`

## Residual risks

| Risk | Status |
|------|--------|
| No DNS/domain verification | Deferred — legal/ToS + rate limits |
| LLM hallucinations in reports | Disclaimer on reports; mock mode for dev |
| Crawler noise on large sites | `scan_policies` caps (pages, depth, RPS) |
| Multi-tenant data isolation | Schema-ready; RLS in Phase 2 |

## Out of scope (MVP)

Active scanning, authentication testing, injection, DDoS-style crawling.
