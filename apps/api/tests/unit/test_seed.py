from types import SimpleNamespace

import pytest

from orchestrasecai.persistence import seed


@pytest.mark.asyncio
async def test_disabled_seed_does_not_open_database_session(monkeypatch):
    def fail_if_called():
        raise AssertionError("database session factory must not be called when seeding is disabled")

    monkeypatch.setattr(seed, "_settings", SimpleNamespace(seed_enabled=False))
    monkeypatch.setattr(seed, "_factory", fail_if_called)
    monkeypatch.setattr(seed, "_seeded", False)

    await seed.run_seed()

    assert seed._seeded is False
