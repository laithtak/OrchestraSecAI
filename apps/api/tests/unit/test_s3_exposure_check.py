from _check_helpers import make_page, page_ctx

import orchestrasecai.checks.s3_exposure_check as mod
from orchestrasecai.checks.s3_exposure_check import S3ExposureCheck

BUCKET_URL = "https://my-bucket.s3.amazonaws.com/file.txt"


class _FakeResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code


class _FakeClient:
    def __init__(self, status_code):
        self._status_code = status_code

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def head(self, url):
        return _FakeResponse(self._status_code)


def _patch_client(monkeypatch, status_code):
    monkeypatch.setattr(mod.httpx, "AsyncClient", lambda *a, **k: _FakeClient(status_code))
    monkeypatch.setattr(mod, "validate_target_url", lambda url: None)


async def test_returns_empty_when_flag_absent():
    page = make_page(body_snippet=f'<img src="{BUCKET_URL}">')
    findings = await S3ExposureCheck().run(page_ctx(page))
    assert findings == []


async def test_public_bucket_is_high(monkeypatch):
    _patch_client(monkeypatch, 200)
    page = make_page(body_snippet=f'<img src="{BUCKET_URL}">')
    findings = await S3ExposureCheck().run(
        page_ctx(page, scan_config={"enable_active_network_checks": True})
    )
    assert len(findings) == 1
    assert findings[0].plugin_id == "s3_exposure.public_bucket"
    assert findings[0].severity == "high"


async def test_private_bucket_is_reference(monkeypatch):
    _patch_client(monkeypatch, 403)
    page = make_page(body_snippet=f'<img src="{BUCKET_URL}">')
    findings = await S3ExposureCheck().run(
        page_ctx(page, scan_config={"enable_active_network_checks": True})
    )
    assert len(findings) == 1
    assert findings[0].plugin_id == "s3_exposure.bucket_reference"
    assert findings[0].severity == "info"


async def test_no_bucket_reference_returns_empty(monkeypatch):
    _patch_client(monkeypatch, 200)
    page = make_page(body_snippet="<p>nothing here</p>")
    findings = await S3ExposureCheck().run(
        page_ctx(page, scan_config={"enable_active_network_checks": True})
    )
    assert findings == []
