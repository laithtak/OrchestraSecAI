# OrchestraSecAI Threat Model

## System context

OrchestraSecAI runs agent-planned security assessments against **verified** web targets.
The agent (LLM) proposes actions; deterministic controls decide what executes. Scanning
is passive by default (GET/HEAD). A small allowlist of active probes exists and requires
an explicit, audited, per-scan opt-in on a deployment that permits it.

## Assets

| Asset | Sensitivity | Controls |
|-------|-------------|----------|
| User credentials / tokens | High | Argon2 hashing, short-lived JWT access tokens, refresh tokens |
| Target authorization (verification) | High | DNS TXT challenge with random, hashed, expiring tokens bound to org + target + hostname |
| Scan evidence and crawl data | High | Redaction of credentials/cookies/keys, size bounds, org scoping |
| Findings and reports | High | Org-scoped access, RBAC, single-use report view tokens, CSP on HTML |
| Audit logs | Medium | Written for target, verification, scan, tool and denial events |
| Internal network / cloud metadata | Critical | Egress transport: scope, public-IP-only DNS, connection pinning |

## Threat actors

1. **Malicious tenant** — scans domains they do not own, pivots to internal networks
   (SSRF), reads another tenant's data, or abuses scans for load.
2. **Malicious target** — serves redirects, DNS rebinding, oversized or hostile content,
   and prompt-injection text aimed at the agent.
3. **Misbehaving or injected LLM** — proposes out-of-scope URLs, larger budgets, active
   probes, or references to other tenants' objects.
4. **Unauthenticated attacker** — API abuse, credential stuffing.
5. **Infrastructure faults** — worker crashes, Redis loss, duplicated or replayed jobs.

## Mitigations

### Scanning domains you do not own
- Scans and worker execution require verified ownership (`authorize_target_for_scan`);
  there is no bypass flag. Tokens are 256-bit random, stored as SHA-256 hashes, expire,
  can be rotated, and checks are rate limited. DNS errors never verify.
- Verification is bound to the target's canonical hostname, the organization and the
  target; request bodies cannot set it. Expiry and failed re-checks revoke it.
- The worker re-checks authorization when the job runs, so revocation after enqueueing
  stops the scan before any traffic.

### SSRF, redirects and DNS rebinding
- Exact-host scope (target host + explicitly listed subdomains, fixed ports, http/https).
- Every request and every redirect hop passes `GuardedTransport`; all DNS answers must be
  public (including IPv4-mapped/NAT64/6to4 forms); the connection is pinned to the
  validated IP; proxies from the environment are ignored.
- Implementation: `security/scope.py`, `security/ssrf.py`, `security/egress.py`.

### Abuse and resource exhaustion
- Per-IP API rate limits, per-org daily scan limit, policy bounds (pages ≤ 500, depth ≤ 10,
  RPS ≤ 10), per-scan request budget, response size cap, bounded crawl frontier, agent
  iteration/tool limits, fixed global deadline, worker concurrency.

### Active / mutating behaviour
- Disabled by default. Requires `ACTIVE_PROBES_ALLOWED=true`, the `scans:active`
  permission (owner/admin) and an audited per-scan opt-in. Techniques are allowlisted with
  fixed request shapes and validated parameters; they are never replayed on recovery.

### LLM and prompt injection
- Target content is data. The tool layer validates every proposed call; scope, budgets
  and permissions cannot be expanded by the model; all calls and denials are audited.
- Findings only come from deterministic checks. AI analyses are stored separately,
  labelled non-authoritative, validated against real finding ids and never modify
  findings or evidence. PoC drafts are never executed.

### Multi-tenancy
- Every query is scoped by the authenticated user's organization; cross-tenant access
  returns 404. The tool layer scopes PoC generation to the scan's own findings.
- Covered by negative integration tests. PostgreSQL RLS is **not** implemented.

### Stored XSS via reports
- HTML reports use autoescaping and are served with `default-src 'none'` CSP and
  `nosniff`.

### Lifecycle integrity
- Compare-and-set transitions, database status constraint, leases and heartbeats,
  idempotent persistence, the reaper, and sanitized error codes.

## Residual risks

| Risk | Status |
|------|--------|
| DNS takeover/compromise of a verified zone | Verification proves DNS control only; mitigated by expiry and re-checks |
| Verification is not periodically re-checked automatically | Expires after `DOMAIN_VERIFICATION_MAX_AGE_DAYS` |
| Split-horizon DNS for the verification lookup | Configure `DOMAIN_VERIFICATION_NAMESERVERS` with public resolvers |
| Compressed-response expansion beyond the byte cap | Mitigated by requesting identity encoding |
| No PostgreSQL RLS | Application-level scoping + tests |
| LLM hallucinations in AI enrichment | Separated, labelled, optional; deterministic report always exists |
| Browser tokens in `localStorage` | Unchanged; see AGENTS.md §37 |
| Development seed account and pre-filled login form | Dev-only; production refuses `SEED_ENABLED=true` |
