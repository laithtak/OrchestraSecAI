import pytest

from orchestrasecai.security.passive_http import assert_passive_method


def test_get_allowed():
    assert_passive_method("GET")


def test_head_allowed():
    assert_passive_method("head")


def test_post_blocked():
    with pytest.raises(ValueError, match="not allowed"):
        assert_passive_method("POST")
