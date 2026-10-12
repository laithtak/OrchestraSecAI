"""Deterministic remediation guidance keyed by finding plugin id (no LLM involved)."""

REMEDIATION: dict[str, str] = {
    "header.missing_strict_transport_security": (
        "Serve 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all HTTPS "
        "responses after confirming every subdomain supports HTTPS."
    ),
    "header.missing_content_security_policy": (
        "Define a Content-Security-Policy that restricts script, object and frame sources; "
        "start in Report-Only mode to tune it before enforcing."
    ),
    "header.missing_x_content_type_options": (
        "Send 'X-Content-Type-Options: nosniff' on all responses."
    ),
    "header.missing_referrer_policy": (
        "Send 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter)."
    ),
    "cookie": (
        "Set the Secure, HttpOnly and SameSite attributes on session and authentication "
        "cookies."
    ),
    "tls.weak_protocol": "Disable SSLv3, TLS 1.0 and TLS 1.1; allow only TLS 1.2 and 1.3.",
    "tls.cert_expiring": "Renew the TLS certificate and automate renewal.",
    "cors.wildcard_with_credentials": (
        "Never combine 'Access-Control-Allow-Origin: *' with credentials; use an explicit "
        "allowlist of trusted origins."
    ),
    "cors.reflected_origin": (
        "Do not reflect the request Origin; validate it against an explicit allowlist."
    ),
    "cors.wildcard_origin": (
        "Restrict Access-Control-Allow-Origin to the origins that need cross-origin access."
    ),
    "csp_quality": (
        "Remove 'unsafe-inline'/'unsafe-eval' and wildcard sources from the CSP; use nonces "
        "or hashes and define default-src, object-src and frame-ancestors."
    ),
    "clickjacking": (
        "Send 'Content-Security-Policy: frame-ancestors 'self'' (and X-Frame-Options: DENY "
        "or SAMEORIGIN for legacy browsers)."
    ),
    "disclosure.debug_header": "Remove debug and version-revealing headers in production.",
    "disclosure.email_in_body": "Avoid exposing personal email addresses in page content.",
    "disclosure.possible_api_key": (
        "Remove the credential from client-visible content, rotate it immediately and "
        "review where it was used."
    ),
    "open_redirect": (
        "Validate redirect targets against an allowlist of relative paths or trusted hosts."
    ),
    "jwt": (
        "Use asymmetric signing, require the 'exp' claim, reject 'alg: none', and avoid "
        "exposing tokens in URLs or page content."
    ),
    "s3_exposure": (
        "Block public access on the storage bucket unless public read is explicitly intended."
    ),
    "tech_fingerprint": (
        "Remove version banners where practical and keep the identified components patched."
    ),
    "subdomain_enum": "Review discovered subdomains and decommission unused hosts.",
}


def remediation_for(plugin_id: str) -> str | None:
    """Most specific match: exact plugin id, then each dotted prefix."""
    key = plugin_id
    while key:
        if key in REMEDIATION:
            return REMEDIATION[key]
        if "." not in key:
            break
        key = key.rsplit(".", 1)[0]
    return None
