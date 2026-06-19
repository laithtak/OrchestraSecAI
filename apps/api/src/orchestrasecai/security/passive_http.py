ALLOWED_METHODS = frozenset({"GET", "HEAD"})


def assert_passive_method(method: str) -> None:
    if method.upper() not in ALLOWED_METHODS:
        raise ValueError(f"Passive-only scanner: method {method} not allowed. Use GET or HEAD.")
