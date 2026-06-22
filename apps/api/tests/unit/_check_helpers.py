from orchestrasecai.checks.base import CheckContext, HostContext, PageContext


def make_page(
    url: str = "https://example.com/",
    *,
    headers: dict[str, str] | None = None,
    cookies: list[dict[str, str]] | None = None,
    body_snippet: str = "",
    status_code: int = 200,
    depth: int = 0,
) -> PageContext:
    return PageContext(
        url=url,
        final_url=url,
        status_code=status_code,
        headers=headers or {},
        cookies=cookies or [],
        body_snippet=body_snippet,
        depth=depth,
    )


def page_ctx(page: PageContext, scan_config: dict | None = None) -> CheckContext:
    return CheckContext(
        scan_id="scan-1",
        org_id="org-1",
        page=page,
        scan_config=scan_config or {},
    )


def host_ctx(hostname: str = "example.com", scan_config: dict | None = None) -> CheckContext:
    return CheckContext(
        scan_id="scan-1",
        org_id="org-1",
        host=HostContext(hostname=hostname),
        scan_config=scan_config or {},
    )
