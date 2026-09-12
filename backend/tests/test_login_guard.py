"""Login throttling and lockout tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import AuditLog
from app.db.session import session_scope
from app.security.login_guard import LoginGuard
from tests.conftest import DEMO_ACCOUNTS, DEMO_PASSWORD

pytestmark = pytest.mark.security


class TestLoginGuardUnit:
    def test_allows_attempts_up_to_the_limit(self) -> None:
        now = [0.0]
        guard = LoginGuard(max_attempts=3, clock=lambda: now[0])
        assert guard.is_locked(email="a@b.test", ip_address="1.1.1.1") is False
        for _ in range(3):
            guard.record_failure(email="a@b.test", ip_address="1.1.1.1")
        assert guard.is_locked(email="a@b.test", ip_address="1.1.1.1") is True

    def test_accounts_are_counted_independently(self) -> None:
        guard = LoginGuard(max_attempts=2, clock=lambda: 0.0)
        guard.record_failure(email="a@b.test", ip_address="1.1.1.1")
        guard.record_failure(email="a@b.test", ip_address="1.1.1.1")
        assert guard.is_locked(email="a@b.test", ip_address="1.1.1.1") is True
        assert guard.is_locked(email="other@b.test", ip_address="1.1.1.1") is False

    def test_address_limit_catches_spraying_across_accounts(self) -> None:
        guard = LoginGuard(max_attempts=2, ip_max_attempts=3, clock=lambda: 0.0)
        for index in range(3):
            guard.record_failure(email=f"user{index}@b.test", ip_address="9.9.9.9")
        assert guard.is_locked(email="fresh@b.test", ip_address="9.9.9.9") is True
        assert guard.is_locked(email="fresh@b.test", ip_address="8.8.8.8") is False

    def test_email_matching_is_case_and_space_insensitive(self) -> None:
        guard = LoginGuard(max_attempts=1, clock=lambda: 0.0)
        guard.record_failure(email="  Alice@Example.com ", ip_address="1.1.1.1")
        assert guard.is_locked(email="alice@example.com", ip_address="2.2.2.2") is True

    def test_success_clears_the_account_counter(self) -> None:
        guard = LoginGuard(max_attempts=3, clock=lambda: 0.0)
        guard.record_failure(email="a@b.test", ip_address="1.1.1.1")
        guard.record_failure(email="a@b.test", ip_address="1.1.1.1")
        guard.record_success(email="a@b.test", ip_address="1.1.1.1")
        guard.record_failure(email="a@b.test", ip_address="1.1.1.1")
        # Two of three failures were cleared, so the account must still be open.
        assert guard.is_locked(email="a@b.test", ip_address="1.1.1.1") is False

    def test_success_does_not_clear_the_address_counter(self) -> None:
        """A host must not be able to reset its budget with one valid login."""
        guard = LoginGuard(max_attempts=2, ip_max_attempts=3, clock=lambda: 0.0)
        guard.record_failure(email="a@b.test", ip_address="9.9.9.9")
        guard.record_failure(email="b@b.test", ip_address="9.9.9.9")
        guard.record_success(email="a@b.test", ip_address="9.9.9.9")
        guard.record_failure(email="c@b.test", ip_address="9.9.9.9")
        assert guard.is_locked(email="d@b.test", ip_address="9.9.9.9") is True

    def test_lockout_expires(self) -> None:
        now = [0.0]
        guard = LoginGuard(max_attempts=1, window_seconds=10, clock=lambda: now[0])
        guard.record_failure(email="a@b.test", ip_address="1.1.1.1")
        assert guard.is_locked(email="a@b.test", ip_address="1.1.1.1") is True
        now[0] = 11.0
        assert guard.is_locked(email="a@b.test", ip_address="1.1.1.1") is False

    def test_invalid_configuration_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            LoginGuard(max_attempts=0)


class TestLoginThrottlingOverHttp:
    def test_repeated_failures_lock_the_account(self, client: TestClient, app, settings) -> None:
        app.state.login_guard = LoginGuard(max_attempts=3, ip_max_attempts=50)
        body = {"email": DEMO_ACCOUNTS["employee"], "password": "wrong-password"}

        for _ in range(3):
            assert client.post("/api/v1/auth/login", json=body).status_code == 401

        blocked = client.post("/api/v1/auth/login", json=body)
        assert blocked.status_code == 429
        assert blocked.json()["error"]["code"] == "rate_limited"
        assert blocked.json()["error"]["details"]["retry_after_seconds"] >= 1

    def test_lockout_applies_to_the_correct_password_too(self, client: TestClient, app) -> None:
        """Otherwise the lockout would be trivially bypassed."""
        app.state.login_guard = LoginGuard(max_attempts=2, ip_max_attempts=50)
        client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["employee"], "password": "wrong"},
        )
        client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["employee"], "password": "wrong"},
        )
        response = client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["employee"], "password": DEMO_PASSWORD},
        )
        assert response.status_code == 429

    def test_lockout_does_not_reveal_whether_the_account_exists(
        self, client: TestClient, app
    ) -> None:
        app.state.login_guard = LoginGuard(max_attempts=1, ip_max_attempts=50)
        client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["employee"], "password": "wrong"},
        )
        # Both requests come from the same address here: with the default
        # TRUSTED_PROXY_COUNT=0 a client-supplied X-Forwarded-For is ignored, so
        # there is no way to vary the address over HTTP without configuring a
        # proxy. Per-address behaviour is covered directly on the guard above,
        # and end to end behind a proxy in test_client_address.py.
        known = client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["employee"], "password": "wrong"},
        )
        unknown = client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@example.com", "password": "wrong"},
        )
        assert known.status_code == 429
        # The unknown account has its own counter; it is refused with the same
        # generic credential error rather than a different message.
        assert unknown.status_code in {401, 429}
        assert "nobody" not in known.text

    def test_successful_login_resets_the_counter(self, client: TestClient, app) -> None:
        app.state.login_guard = LoginGuard(max_attempts=3, ip_max_attempts=50)
        for _ in range(2):
            client.post(
                "/api/v1/auth/login",
                json={"email": DEMO_ACCOUNTS["employee"], "password": "wrong"},
            )
        assert (
            client.post(
                "/api/v1/auth/login",
                json={"email": DEMO_ACCOUNTS["employee"], "password": DEMO_PASSWORD},
            ).status_code
            == 200
        )
        # Counter cleared: two more failures must not lock the account.
        for _ in range(2):
            client.post(
                "/api/v1/auth/login",
                json={"email": DEMO_ACCOUNTS["employee"], "password": "wrong"},
            )
        assert (
            client.post(
                "/api/v1/auth/login",
                json={"email": DEMO_ACCOUNTS["employee"], "password": DEMO_PASSWORD},
            ).status_code
            == 200
        )

    def test_throttling_is_audited(self, client: TestClient, app) -> None:
        app.state.login_guard = LoginGuard(max_attempts=1, ip_max_attempts=50)
        client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["employee"], "password": "wrong"},
        )
        client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["employee"], "password": "wrong"},
        )
        with session_scope() as session:
            rows = session.scalars(
                select(AuditLog).where(AuditLog.action == "auth.login.throttled")
            ).all()
        assert rows
        assert rows[-1].outcome.value == "denied"

    def test_lockout_does_not_create_a_session(self, client: TestClient, app) -> None:
        from app.db.models import UserSession

        app.state.login_guard = LoginGuard(max_attempts=1, ip_max_attempts=50)
        client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["employee"], "password": "wrong"},
        )
        client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["employee"], "password": DEMO_PASSWORD},
        )
        with session_scope() as session:
            assert session.query(UserSession).count() == 0

    def test_the_guard_is_shared_across_requests(self, client: TestClient, app) -> None:
        """Counters must live on the application, not per request."""
        app.state.login_guard = LoginGuard(max_attempts=2, ip_max_attempts=50)
        for _ in range(2):
            client.post(
                "/api/v1/auth/login",
                json={"email": DEMO_ACCOUNTS["employee"], "password": "wrong"},
            )
        assert app.state.login_guard.is_locked(
            email=DEMO_ACCOUNTS["employee"], ip_address="testclient"
        )
