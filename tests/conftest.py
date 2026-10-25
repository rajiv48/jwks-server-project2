
"""Shared pytest fixtures for testing the SQLite-backed JWKS server."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from jwks_server.app import create_app
from jwks_server.keys import KeyStore


class FakeClock:
    """A controllable clock for deterministic expiry and rotation tests."""

    def __init__(self) -> None:
        self.current = datetime.now(UTC).replace(microsecond=0)

    def __call__(self) -> datetime:
        """Return the current simulated time."""
        return self.current

    def advance(self, delta: timedelta) -> None:
        """Move the simulated time forward."""
        self.current += delta


@pytest.fixture
def clock() -> FakeClock:
    """Provide an independent clock for each test."""
    return FakeClock()


@pytest.fixture
def store(
    clock: FakeClock,
    tmp_path: Path,
) -> KeyStore:
    """Create a KeyStore with an isolated temporary SQLite database."""
    db_path = tmp_path / "totally_not_my_privateKeys.db"

    return KeyStore(
        lifetime=timedelta(hours=1),
        clock=clock,
        db_path=db_path,
    )


@pytest.fixture
def client(store: KeyStore) -> TestClient:
    """Provide a FastAPI test client using the isolated KeyStore."""
    return TestClient(create_app(store))
