# Passive-Only Scanning Policy

OrchestraSecAI MVP enforces **observation-only** security assessment.

## Allowed activities

| Activity | Method | Example |
|----------|--------|---------|
| Fetch pages | GET | Crawl linked HTML pages in scope |
| Check headers | GET response | CSP, HSTS, X-Frame-Options |
| Inspect cookies | Set-Cookie analysis | Secure, HttpOnly, SameSite |
| TLS handshake | TCP + TLS | Protocol version, cert expiry |
| Content patterns | Response body (truncated) | Email patterns, server banners |

## Prohibited activities

- POST/PUT/PATCH/DELETE or any mutating HTTP method  
- Form submission, login attempts, session riding  
- Payload fuzzing, SQLi, XSS probes  
- Port scanning beyond HTTPS (443) for declared web targets  
- Brute force, credential stuffing, token guessing  

## Enforcement

1. **Code:** `assert_passive_method()` in crawler before each request  
2. **Plugins:** Checks live only under `checks/`; plugins cannot import persistence  
3. **AI prompts:** System instructions refuse exploitation guidance  
4. **Operations:** Worker containers should not reach internal admin interfaces (network segmentation recommended for production)

## Operator responsibilities

- Obtain written authorization before scanning third-party sites  
- Configure `scan_policies` with conservative `max_pages` and `requests_per_second`  
- Review `verification_status`; MVP defaults to `unverified`  

## Phase 2

- DNS TXT / HTML file domain verification before scan enqueue  
- Optional WAF/CDN detection and scan pause  
