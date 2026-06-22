import base64
import json

from _check_helpers import make_page, page_ctx

from orchestrasecai.checks.jwt_check import JWTCheck


def _b64(obj: dict) -> str:
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _make_jwt(header: dict, payload: dict) -> str:
    return f"{_b64(header)}.{_b64(payload)}.sig"


async def test_alg_none_is_high():
    token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "1", "exp": 9999999999})
    page = make_page(body_snippet=f"token={token}")
    findings = await JWTCheck().run(page_ctx(page))
    ids = {f.plugin_id: f for f in findings}
    assert "jwt.alg_none" in ids
    assert ids["jwt.alg_none"].severity == "high"


async def test_missing_exp_is_medium():
    token = _make_jwt({"alg": "RS256", "typ": "JWT"}, {"sub": "1"})
    page = make_page(body_snippet=token)
    findings = await JWTCheck().run(page_ctx(page))
    ids = {f.plugin_id: f for f in findings}
    assert "jwt.missing_exp" in ids
    assert ids["jwt.missing_exp"].severity == "medium"


async def test_expired_hs256_token():
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 1000000000})
    page = make_page(headers={"Authorization": f"Bearer {token}"})
    findings = await JWTCheck().run(page_ctx(page))
    ids = {f.plugin_id: f for f in findings}
    assert "jwt.symmetric_alg" in ids
    assert ids["jwt.symmetric_alg"].severity == "info"
    assert "jwt.expired" in ids
    assert ids["jwt.expired"].severity == "low"


async def test_token_is_redacted_in_evidence():
    token = _make_jwt({"alg": "none"}, {"sub": "1"})
    page = make_page(body_snippet=token)
    findings = await JWTCheck().run(page_ctx(page))
    for f in findings:
        payload_token = f.evidence[0]["payload"]["token"]
        assert token not in payload_token
        assert "..." in payload_token


async def test_no_jwt_returns_empty():
    findings = await JWTCheck().run(page_ctx(make_page(body_snippet="no tokens here")))
    assert findings == []
