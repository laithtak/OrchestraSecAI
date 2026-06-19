from orchestrasecai.scanner.runtime.registry import build_registry


def test_registry_has_builtin_checks():
    registry = build_registry()
    checks = registry.get_many(["header", "cookie", "tls", "disclosure"])
    assert len(checks) == 4
