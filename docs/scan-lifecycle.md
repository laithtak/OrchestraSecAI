# Secure Scan Lifecycle

This document describes the implemented end-to-end path:

```text
Register target -> Prove domain ownership -> Create scan -> Authorize (API)
  -> Enqueue -> Claim + re-authorize (worker) -> Bounded agent execution
  -> Findings + evidence -> Completion + deterministic report -> Optional AI enrichment
```

Code references are relative to `apps/api/src/orchestrasecai/`.

## 1. Targets and scope

`POST /api/v1/targets` validates the target with `security/scope.py`:

- `http`/`https` only, no credentials in the URL, no fragments.
- The host must be a fully qualified DNS name (IP literals and single-label names are
  rejected); it is lower-cased and IDNA-encoded. The stored `base_url` is canonical.
- `allowed_hosts` may only list the target host or its subdomains, explicitly (no
  wildcards, no ports, at most 20 hosts).
- The hostname must resolve, and every answer must be a public address
  (`security/ssrf.py`).

**Scope is exact-host.** A scan may contact the target hostname and explicitly listed
subdomains on ports 80, 443 and the target's explicit port. There is no implicit
"same registrable domain" expansion: sibling hosts, parent domains and redirects to other
hosts are out of scope.

## 2. Domain ownership verification (DNS TXT)

Implemented in `domain/verification.py`, exposed in `api/v1/targets.py`.

| Endpoint | Permission | Purpose |
|---|---|---|
| `GET /targets/{id}/verification` | `targets:read` | Status, record name, token hint, challenge state |
| `POST /targets/{id}/verification/challenge` | `targets:write` | Issue or rotate a challenge; returns the record value **once** |
| `POST /targets/{id}/verify` | `targets:write` | Check DNS now |

- The token is 32 random bytes (`secrets.token_urlsafe`). Only its SHA-256 hash and a
  6-character hint are stored (`domain_verification_challenges`).
- The operator publishes `TXT _orchestrasec.<hostname> = "orchestrasec-verify=<token>"`.
- A check performs one TXT query for exactly that name with a bounded lifetime
  (`DOMAIN_VERIFICATION_DNS_TIMEOUT_SECONDS`), optionally against configured public
  resolvers (`DOMAIN_VERIFICATION_NAMESERVERS`). Candidate values are compared in
  constant time against the stored hash.
- Challenges expire (`DOMAIN_VERIFICATION_CHALLENGE_TTL_HOURS`, default 72h). Checks are
  rate-limited per challenge (`DOMAIN_VERIFICATION_CHECK_COOLDOWN_SECONDS`, HTTP 429).
- DNS timeouts/errors are reported (`dns_timeout`, `dns_error`) and **never** change state.
- Rotation supersedes the live challenge and revokes verification until re-checked. At
  most one live challenge per target is enforced by a partial unique index.
- A re-check that no longer finds the token **revokes** verification and opens a fresh
  window to restore the record.
- Success binds `verified_domain`, `verified_at` and `verification_expires_at`
  (`DOMAIN_VERIFICATION_MAX_AGE_DAYS`, default 30) on the target. A database check
  constraint requires these fields whenever the status is `verified`.

Target states: `unverified` → `pending` (challenge issued) → `verified`; revocation and
expiry return to `pending`/`unverified`. Check results: `verified`, `record_not_found`,
`token_mismatch`, `dns_timeout`, `dns_error`, `challenge_expired`.

### Authorization gate

`authorize_target_for_scan()` is the single deterministic gate used by both the API and
the worker. It allows a scan only if the target belongs to the scan's organization, its
status is `verified`, `verified_domain` equals the target's current canonical hostname,
and the verification has not expired. Verification is per organization and target: two
tenants registering the same domain each need their own challenge, and request bodies can
never set verification fields.

## 3. Creating a scan

`POST /api/v1/scans` (`scans:write`):

1. Target and policy must belong to the caller's organization (404 otherwise).
2. The authorization gate must pass (403 with the denial reason).
3. `allow_active_probes=true` additionally requires the `scans:active` permission
   (owner/admin) **and** `ACTIVE_PROBES_ALLOWED=true`; the opt-in is audited
   (`scan.active_probes_opt_in`).
4. The organization's daily scan limit is applied.
5. The scan (`queued`) and agent session are **committed before enqueueing** with ARQ job
   id `scan:<id>`. If the queue is unavailable the scan becomes `failed`
   (`queue_unavailable`) and the API returns 503.

## 4. Lifecycle states and transitions

States (`domain/scan_lifecycle.py`, enforced by the `ck_scans_status` constraint):

```text
queued  -> running | failed | cancelled
running -> completed | failed | cancelled | timed_out
running -> running   (lease takeover after a worker crash)
completed, failed, cancelled, timed_out are terminal
```

Every transition is a compare-and-set `UPDATE ... WHERE status IN (...)`, so the API,
the executing worker, duplicate jobs and the reaper cannot produce contradictory states.
Failures persist a stable `error_code` and a fixed, non-sensitive `error_message`:
`target_unverified`, `verification_expired`, `verification_domain_mismatch`,
`invalid_target`, `target_unreachable`, `queue_unavailable`, `queue_timeout`,
`worker_lost`, `timeout`, `cancelled`, `internal_error`. Exception details are logged
(type only), never returned.

## 5. Worker execution

`workers/tasks/scan.py` → `domain/services/agent_runner.py`:

1. **Validate payload**: the scan id must be a UUID.
2. **Claim**: `queued → running` (or takeover of a `running` scan whose lease expired),
   only while `attempts < SCAN_MAX_ATTEMPTS` and before the deadline. A duplicate or
   replayed job fails the claim and exits with no side effects. The deadline
   (`SCAN_GLOBAL_TIMEOUT_SECONDS`) is fixed at the first claim; retries never extend it.
3. **Re-authorize from the database** (never from the job payload): tenant bindings of
   scan/target/policy, the authorization gate, canonical scope, and public DNS resolution
   of the target. Denials are audited (`scan.execution_denied`) and the scan fails
   without any target traffic.
4. **Supervised execution**: the LangGraph planner → executor → critic loop runs as a
   task; a heartbeat task extends the lease every `SCAN_HEARTBEAT_SECONDS` and stops the
   run if the scan was cancelled or reassigned. `ScanToolLayer` also checks before every
   tool call and the crawler checks between pages.
5. **Completion**: `running → completed` and the deterministic report are written in one
   transaction. If the scan was cancelled meanwhile the CAS fails and nothing is
   overwritten. On deadline, the scan becomes `timed_out` with a partial report.
6. **AI enrichment** is enqueued afterwards (`ai:<id>`); its failure does not affect the
   scan.

Scan-level failures are persisted, not raised, so ARQ does not blindly re-run scans.

### Crash recovery and the reaper

`domain/services/reaper.py` runs every minute (ARQ cron):

- `running` past its deadline → `timed_out`;
- `running` with an expired lease and attempts exhausted → `failed` (`worker_lost`);
- `running` with an expired lease and attempts left → re-enqueue `scan:<id>:attempt:<n>`;
- `queued` older than `SCAN_REQUEUE_AFTER_SECONDS` → re-enqueue with the original job id
  (ARQ ignores it while the job still exists, so only lost jobs are recreated);
- `queued` older than `SCAN_QUEUE_MAX_AGE_SECONDS` → `failed` (`queue_timeout`).

Recovery attempts resume idempotently: findings are unique per `(scan_id, fingerprint)`
and crawl pages per `(scan_id, url)`, and **active probes are never replayed** on a
recovery attempt.

### Cancellation

`POST /api/v1/scans/{id}/cancel` (`scans:write`) atomically moves `queued`/`running` to
`cancelled` (409 if already terminal) and is audited. Running workers observe it within
seconds and stop; no report is produced for cancelled scans.

## 6. Network policy enforcement

All target traffic uses `security/egress.py` (`GuardedTransport`), installed on every
scanner HTTP client (crawler, on-demand page fetches, active probes). Because httpx sends
redirect hops through the transport, each check applies to every hop:

- method allowlist (GET/HEAD; active techniques widen it per technique);
- scheme, exact host and port in scope; blocked path patterns from the policy;
- per-scan request budget (`SCAN_MAX_REQUESTS`) shared by all tools;
- DNS resolution where **every** answer must be public (loopback, RFC1918, CGNAT,
  link-local/metadata, multicast, reserved, documentation, NAT64/6to4/IPv4-mapped forms
  are blocked);
- the connection is pinned to the validated address (SNI and certificate verification
  still use the hostname), closing the DNS-rebinding window between check and connect;
- environment proxies are ignored; bodies are capped (`SCAN_MAX_RESPONSE_BYTES`) and
  `Accept-Encoding: identity` is requested.

Other limits: policy `max_pages` (1–500), `max_depth` (0–10), `requests_per_second`
(≤ 10), robots.txt, bounded crawl frontier and links per page, agent `max_iterations`
and `max_tools_per_plan`, and the global deadline. Agent-supplied crawl limits can only
lower policy values.

## 7. Tool layer policy (agent boundary)

`scanner/tools/layer.py` decides deterministically; the LLM only proposes:

| Tool | Policy |
|---|---|
| `passive_crawl` | Policy-clamped limits; GET/HEAD through the egress transport |
| `run_check` | Only PAGE-phase built-in checks; URL must be in scope; checks that would contact third-party hosts stay disabled |
| `active_probe` | Denied unless the scan was authorized (deployment flag + `scans:active` opt-in) and this is the first attempt; allowlisted techniques with fixed request shapes and validated parameters |
| `lookup_cve` | CPE 2.3 identifier required; contacts only the configured NVD API |
| `generate_poc` | Finding must belong to this scan and organization; output stored as an AI analysis, never executed |

Every call is audited (`agent.tool_call`); denials are audited as `agent.tool_denied`
with a reason (`out_of_scope`, `ssrf_blocked`, `budget_exhausted`,
`active_probes_not_authorized`, `check_phase_not_allowed`, `finding_not_in_scan`,
`invalid_parameters`, …).

## 8. Findings and evidence

`domain/services/finding_store.py`:

- Findings originate only from deterministic check output. Each has a stable UUID, a
  deterministic fingerprint (unique per scan), severity, title, description, affected
  location, `check_id`/`check_version` and deterministic remediation guidance
  (`domain/remediation.py`).
- Inserts are idempotent (`ON CONFLICT DO NOTHING`), so retries and repeated tool calls
  do not duplicate findings.
- Evidence is redacted and bounded before storage (`security/redaction.py`): credential
  headers and cookie values are removed, JWTs/keys/tokens are masked, strings, lists and
  payload sizes are capped. Crawl-page headers are redacted the same way.

## 9. Reports

`domain/reporting.py` builds a structured JSON document (schema `1.0`) and an HTML
rendering from persisted state only — no LLM, GPU or network. Findings are ordered
deterministically, so regenerating a report for unchanged data is byte-identical. Reports
are versioned per format with a SHA-256 content hash and a `generator`
(`deterministic` or `deterministic+ai`).

- HTML uses Jinja2 autoescaping; responses carry `Content-Security-Policy: default-src
  'none'`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`.
- `GET /scans/{id}/report?format=json|html[&download=true]` requires `reports:read` in
  the owning organization, or a single-use 30-second view token
  (`POST /scans/{id}/report/view-token`).

## 10. AI enrichment (optional)

`ai/pipelines/report.py` runs after completion. It never changes scan status, findings or
evidence. Each analysis (explain, prioritize, executive summary, technical report) is
recorded in `ai_analyses` with model and prompt version, including failures
(`status=failed`). Finding references produced by the model are filtered to real finding
ids. When at least one analysis succeeds, a new report version is stored with an
`ai_enrichment` section labelled non-authoritative; otherwise the deterministic report
stands. PoC drafts are stored as `ai_analyses` (`poc_draft`), not as evidence.

## 11. Known limitations

- Verification proves control of DNS for the hostname at check time; it is re-checked on
  demand and expires after `DOMAIN_VERIFICATION_MAX_AGE_DAYS`, but there is no scheduled
  re-verification job.
- HOST-phase checks (TLS, subdomain enumeration) are not reachable from the agent path;
  the S3 exposure check's third-party HEAD requests remain disabled.
- Response bodies are capped at the transport; a server that ignores
  `Accept-Encoding: identity` could still send a compressed body that expands on decode
  (bounded by the cap on compressed bytes only).
- There is no per-organization concurrency limit beyond the daily scan limit and worker
  concurrency.
- PostgreSQL row-level security is not implemented; tenant isolation is enforced in the
  application layer and covered by negative tests.
