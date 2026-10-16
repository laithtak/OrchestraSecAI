import pytest

from orchestrasecai.scanner.crawler.scope import is_in_scope
from orchestrasecai.security.scope import ScopeError, validate_target_definition


def test_canonical_scope_is_exact_host():
    scope = validate_target_definition("https://App.Example.com.", [])
    assert scope.hostname == "app.example.com"
    assert scope.base_url == "https://app.example.com/"
    assert scope.hosts == frozenset({"app.example.com"})
    assert scope.contains("https://app.example.com/x")
    assert scope.contains("http://app.example.com/x")  # http->https upgrade redirects
    assert not scope.contains("https://www.example.com/")  # sibling host
    assert not scope.contains("https://example.com/")  # parent domain
    assert not scope.contains("https://app.example.com.evil.net/")


def test_explicit_subdomains_are_allowed():
    scope = validate_target_definition("https://example.com", ["api.example.com"])
    assert scope.contains("https://api.example.com/v1")
    assert not scope.contains("https://admin.example.com/")


def test_explicit_port_is_in_scope_but_others_are_not():
    scope = validate_target_definition("https://example.com:8443/app", [])
    assert scope.contains("https://example.com:8443/app/x")
    assert not scope.contains("https://example.com:9000/")


@pytest.mark.parametrize(
    ("base_url", "allowed"),
    [
        ("ftp://example.com", []),
        ("https://93.184.216.34/", []),
        ("https://[::1]/", []),
        ("https://localhost/", []),
        ("https://user:pw@example.com/", []),
        ("https://example.com", ["evil.com"]),
        ("https://example.com", ["*.example.com"]),
        ("https://example.com", ["api.example.com:8080"]),
        ("https://sub.example.com", ["example.com"]),  # parent of the verified host
        ("https://exa mple.com", []),
    ],
)
def test_invalid_target_definitions(base_url, allowed):
    with pytest.raises(ScopeError):
        validate_target_definition(base_url, allowed)


def test_idna_hostnames_are_normalized():
    scope = validate_target_definition("https://bücher.example/", [])
    assert scope.hostname == "xn--bcher-kva.example"


def test_legacy_is_in_scope_no_longer_expands_to_registrable_domain():
    assert is_in_scope("https://app.example.com/", "https://app.example.com", [])
    assert not is_in_scope("https://cdn.example.com/", "https://app.example.com", [])
