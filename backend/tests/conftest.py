"""Shared pytest fixtures.

Every test gets an isolated SQLite file in ``tmp_path`` plus a freshly built
application instance, so tests never share state and never touch ``./data``.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

# Make `import app` work no matter where pytest is invoked from.
BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi.testclient import TestClient  # noqa: E402

from app.core.config import Settings, get_settings  # noqa: E402
from app.db.session import reset_engine_cache  # noqa: E402
from app.main import create_app  # noqa: E402

DEMO_PASSWORD = "Demo@12345"

# Test accounts seeded for every test.
DEMO_ACCOUNTS = {
    "employee": "employee@example.com",
    "employee2": "employee2@example.com",
    "it": "it@example.com",
    "security": "security@example.com",
}


@pytest.fixture(scope="session")
def _settings_env() -> dict[str, str]:
    """Environment overrides shared by the whole session.

    Deliberately obvious dummy values: this project never uses real secrets in
    tests, and ``AUTH_SECRET_KEY`` here is worthless outside the test process.
    """
    return {
        "APP_ENV": "test",
        "DEBUG": "true",
        "LOG_LEVEL": "WARNING",
        "LOG_FORMAT": "text",
        "AUTH_SECRET_KEY": "test-only-secret-key-not-valid-for-production-use",
        "ACCESS_TOKEN_EXPIRE_MINUTES": "60",
        "ALLOW_DEMO_LOGIN": "true",
        "SEED_DEMO_USERS": "true",
        "DEMO_USER_PASSWORD": DEMO_PASSWORD,
        "PASSWORD_HASH_ROUNDS": "4",
        "LLM_PROVIDER": "mock",
        "EMBEDDING_PROVIDER": "tfidf",
        "VECTOR_STORE": "memory",
        "RETRIEVAL_TOP_K": "6",
        "RETRIEVAL_MIN_SCORE": "0.05",
        "RETRIEVAL_RELATIVE_FLOOR": "0.5",
        "RETRIEVAL_MAX_PER_DOCUMENT": "2",
        "KB_STRICT_VALIDATION": "true",
        # The evaluation suite sends many questions from one account; the real
        # limit would throttle it. The limiter itself is tested separately.
        "CHAT_RATE_LIMIT_PER_MINUTE": "10000",
    }


@pytest.fixture
def settings(
    _settings_env: dict[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Settings]:
    """Per-test settings pointing at an isolated SQLite database."""
    for key, value in _settings_env.items():
        monkeypatch.setenv(key, value)
    # Unique database file per test -> no cross-test contamination.
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'test.db').as_posix()}")

    get_settings.cache_clear()
    reset_engine_cache()
    current = get_settings()
    try:
        yield current
    finally:
        reset_engine_cache()
        get_settings.cache_clear()


@pytest.fixture
def app(settings: Settings):
    """Application instance with lifespan startup executed."""
    return create_app(settings)


@pytest.fixture
def knowledge(settings: Settings):
    """A freshly built knowledge service over the real knowledge base."""
    from app.services.knowledge_service import KnowledgeService

    service = KnowledgeService(settings)
    service.startup()
    return service


@pytest.fixture(scope="session")
def kb_dir() -> Path:
    """Absolute path of the shipped knowledge base."""
    return BACKEND_DIR / "knowledge_base"


@pytest.fixture
def client(app) -> Iterator[TestClient]:
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def login(client: TestClient):
    """Return a callable that logs a demo account in and yields auth headers."""

    def _login(role: str = "employee") -> dict[str, str]:
        email = DEMO_ACCOUNTS[role]
        response = client.post(
            "/api/v1/auth/login", json={"email": email, "password": DEMO_PASSWORD}
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    return _login


@pytest.fixture
def employee_headers(login) -> dict[str, str]:
    return login("employee")


@pytest.fixture
def it_headers(login) -> dict[str, str]:
    return login("it")


@pytest.fixture
def security_headers(login) -> dict[str, str]:
    return login("security")
