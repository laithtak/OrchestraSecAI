from orchestrasecai.scanner.runtime.registry import build_registry

DEFAULT_PASSIVE_PLUGINS = [
    "header",
    "cookie",
    "tls",
    "disclosure",
    "cors",
    "tech_fingerprint",
    "csp_quality",
    "open_redirect",
    "jwt",
    "clickjacking",
]

NEW_PLUGINS = [
    "cors",
    "tech_fingerprint",
    "csp_quality",
    "open_redirect",
    "jwt",
    "subdomain_enum",
    "s3_exposure",
    "clickjacking",
]


def test_registry_has_builtin_checks():
    registry = build_registry()
    checks = registry.get_many(["header", "cookie", "tls", "disclosure"])
    assert len(checks) == 4


def test_default_passive_set_resolves():
    registry = build_registry()
    checks = registry.get_many(DEFAULT_PASSIVE_PLUGINS)
    assert len(checks) == len(DEFAULT_PASSIVE_PLUGINS)
    assert {c.plugin_id for c in checks} == set(DEFAULT_PASSIVE_PLUGINS)


def test_new_plugins_registered():
    registry = build_registry()
    for plugin_id in NEW_PLUGINS:
        check = registry.get(plugin_id)
        assert check is not None, f"{plugin_id} not registered"
        assert check.plugin_id == plugin_id
