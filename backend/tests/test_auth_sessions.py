"""Session revocation tests.

A signed token used to stay valid until it expired. These tests pin the property
that replaced it: the server-side session record is authoritative, so signing out
or a suspected compromise takes effect immediately.
"""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import create_access_token
from app.db.models import AuditLog, User, UserSession
from app.db.session import session_scope
from app.security.sessions import (
    REASON_LOGOUT,
    count_active_sessions,
    purge_expired_sessions,
    record_session,
    revoke_all_for_user,
    revoke_session,
)
from tests.conftest import DEMO_ACCOUNTS, DEMO_PASSWORD

pytestmark = pytest.mark.security


def login(client: TestClient, role: str = "employee") -> str:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": DEMO_ACCOUNTS[role], "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def schema(settings):
    """Create the schema and seed for tests that use `session_scope` directly.

    Also gives those tests the demo users, so foreign keys hold.
    """
    from app.db.seed import run_seed

    run_seed(settings)
    return settings


class TestSessionIssuance:
    def test_login_records_a_session(self, client: TestClient) -> None:
        token = login(client)
        assert client.get("/api/v1/auth/me", headers=auth(token)).status_code == 200
        with session_scope() as session:
            records = session.scalars(select(UserSession)).all()
        assert len(records) == 1
        assert records[0].revoked_at is None
        assert records[0].expires_at is not None

    def test_session_records_the_user_agent(self, client: TestClient) -> None:
        client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["it"], "password": DEMO_PASSWORD},
            headers={"User-Agent": "pytest-agent/1.0"},
        )
        with session_scope() as session:
            record = session.scalar(select(UserSession))
        assert record is not None
        assert record.user_agent == "pytest-agent/1.0"

    def test_each_login_gets_its_own_session(self, client: TestClient) -> None:
        first = login(client)
        second = login(client)
        assert first != second
        assert client.get("/api/v1/auth/me", headers=auth(first)).status_code == 200
        assert client.get("/api/v1/auth/me", headers=auth(second)).status_code == 200
        with session_scope() as session:
            assert session.query(UserSession).count() == 2

    def test_token_without_a_jti_is_rejected(self, client: TestClient, settings) -> None:
        """A correctly signed token with no session claim must not be accepted."""
        import jwt

        token = jwt.encode(
            {"sub": "1", "role": "employee", "iat": 0, "exp": 4102444800, "iss": "esaa"},
            settings.auth_secret_key,
            algorithm=settings.auth_algorithm,
        )
        response = client.get("/api/v1/auth/me", headers=auth(token))
        assert response.status_code == 401

    def test_token_with_an_unknown_jti_is_rejected(self, client: TestClient, settings) -> None:
        """Signed, unexpired, but never issued by this server."""
        import jwt

        token = jwt.encode(
            {
                "sub": "1",
                "role": "employee",
                "iat": 0,
                "exp": 4102444800,
                "jti": "never-issued-this",
                "iss": "esaa",
            },
            settings.auth_secret_key,
            algorithm=settings.auth_algorithm,
        )
        assert client.get("/api/v1/auth/me", headers=auth(token)).status_code == 401


class TestRevocation:
    def test_logout_revokes_the_token_immediately(self, client: TestClient) -> None:
        token = login(client)
        assert client.get("/api/v1/auth/me", headers=auth(token)).status_code == 200

        assert client.post("/api/v1/auth/logout", headers=auth(token)).status_code == 204

        response = client.get("/api/v1/auth/me", headers=auth(token))
        assert response.status_code == 401
        assert "session has ended" in response.json()["error"]["message"].lower()

    def test_logout_does_not_affect_other_sessions(self, client: TestClient) -> None:
        first = login(client)
        second = login(client)
        client.post("/api/v1/auth/logout", headers=auth(first))
        assert client.get("/api/v1/auth/me", headers=auth(first)).status_code == 401
        assert client.get("/api/v1/auth/me", headers=auth(second)).status_code == 200

    def test_logout_is_idempotent(self, client: TestClient) -> None:
        token = login(client)
        assert client.post("/api/v1/auth/logout", headers=auth(token)).status_code == 204
        # The token is already revoked, so the request itself is unauthenticated.
        assert client.post("/api/v1/auth/logout", headers=auth(token)).status_code == 401

    def test_logout_all_revokes_every_session(self, client: TestClient) -> None:
        first = login(client)
        second = login(client)
        response = client.post("/api/v1/auth/logout-all", headers=auth(first))
        assert response.status_code == 200
        assert response.json()["revoked"] == 2
        assert client.get("/api/v1/auth/me", headers=auth(first)).status_code == 401
        assert client.get("/api/v1/auth/me", headers=auth(second)).status_code == 401

    def test_logout_all_only_affects_the_caller(self, client: TestClient) -> None:
        employee_token = login(client, "employee")
        it_token = login(client, "it")
        client.post("/api/v1/auth/logout-all", headers=auth(employee_token))
        assert client.get("/api/v1/auth/me", headers=auth(it_token)).status_code == 200

    def test_revoked_session_is_audited(self, client: TestClient) -> None:
        token = login(client)
        client.post("/api/v1/auth/logout", headers=auth(token))
        with session_scope() as session:
            rows = session.scalars(select(AuditLog).where(AuditLog.action == "auth.logout")).all()
        assert rows

    def test_revocation_reason_is_recorded(self, client: TestClient) -> None:
        token = login(client)
        client.post("/api/v1/auth/logout", headers=auth(token))
        with session_scope() as session:
            record = session.scalar(select(UserSession).where(UserSession.revoked_at.isnot(None)))
        assert record is not None
        assert record.revoked_reason == REASON_LOGOUT


class TestSessionListing:
    def test_sessions_are_listed_for_the_caller_only(self, client: TestClient) -> None:
        token = login(client)
        login(client)  # a second session for the same user
        body = client.get("/api/v1/auth/sessions", headers=auth(token)).json()
        assert body["count"] == 2
        assert sum(1 for entry in body["sessions"] if entry["current"]) == 1

    def test_another_users_sessions_are_not_visible(self, client: TestClient) -> None:
        employee = login(client, "employee")
        login(client, "security")
        body = client.get("/api/v1/auth/sessions", headers=auth(employee)).json()
        assert body["count"] == 1

    def test_session_listing_exposes_no_token_material(self, client: TestClient) -> None:
        token = login(client)
        raw = client.get("/api/v1/auth/sessions", headers=auth(token)).text
        assert token not in raw
        assert "password" not in raw

    def test_revoked_sessions_drop_out_of_the_listing(self, client: TestClient) -> None:
        first = login(client)
        second = login(client)
        client.post("/api/v1/auth/logout", headers=auth(first))
        body = client.get("/api/v1/auth/sessions", headers=auth(second)).json()
        assert body["count"] == 1


class TestSessionService:
    def test_expired_session_is_not_active(self, schema) -> None:
        from app.db.session import session_scope as scope

        with scope() as session:
            user = session.scalar(select(User).where(User.email == DEMO_ACCOUNTS["employee"]))
            assert user is not None
            record_session(
                session,
                user_id=user.id,
                jti="expired-jti",
                expires_at=dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1),
            )
        from app.security.sessions import get_active_session

        with scope() as session:
            assert get_active_session(session, "expired-jti") is None

    def test_revoking_an_unknown_jti_is_a_no_op(self, schema) -> None:
        with session_scope() as session:
            assert revoke_session(session, jti="does-not-exist") is False

    def test_revoke_all_returns_the_count(self, client: TestClient) -> None:
        login(client)
        login(client)
        with session_scope() as session:
            assert revoke_all_for_user(session, user_id=1) == 2
            assert count_active_sessions(session, user_id=1) == 0

    def test_purge_removes_only_old_rows(self, schema) -> None:
        from app.db.session import session_scope as scope

        with scope() as session:
            record_session(
                session,
                user_id=1,
                jti="ancient",
                expires_at=dt.datetime.now(dt.UTC) - dt.timedelta(days=90),
            )
            record_session(
                session,
                user_id=1,
                jti="recent",
                expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=1),
            )
        with scope() as session:
            removed = purge_expired_sessions(session, retention_days=30)
        assert removed == 1
        with scope() as session:
            remaining = {row.jti for row in session.scalars(select(UserSession)).all()}
        assert remaining == {"recent"}

    def test_session_must_belong_to_the_token_subject(self, client: TestClient, settings) -> None:
        """A valid jti paired with somebody else's subject is rejected."""
        import jwt

        # Two live sessions: one for the employee, one for the IT user.
        employee_token = login(client, "employee")
        login(client, "it")
        employee_claims = jwt.decode(
            employee_token, settings.auth_secret_key, algorithms=[settings.auth_algorithm]
        )

        with session_scope() as session:
            it_record = session.scalar(
                select(UserSession)
                .join(User, User.id == UserSession.user_id)
                .where(User.email == DEMO_ACCOUNTS["it"])
            )
            assert it_record is not None
            it_jti = it_record.jti

        forged = jwt.encode(
            {**employee_claims, "jti": it_jti, "role": "it"},
            settings.auth_secret_key,
            algorithm=settings.auth_algorithm,
        )
        assert client.get("/api/v1/auth/me", headers=auth(forged)).status_code == 401


class TestDisabledAccounts:
    def test_disabling_an_account_invalidates_existing_tokens(self, client: TestClient) -> None:
        """A live session must stop working as soon as the account is disabled."""
        token = login(client, "it")
        assert client.get("/api/v1/auth/me", headers=auth(token)).status_code == 200

        with session_scope() as session:
            user = session.scalar(select(User).where(User.email == DEMO_ACCOUNTS["it"]))
            assert user is not None
            user.is_active = False

        response = client.get("/api/v1/auth/me", headers=auth(token))
        assert response.status_code == 401
        assert "disabled" in response.json()["error"]["message"].lower()

    def test_deleting_a_user_revokes_their_sessions(self, client: TestClient) -> None:
        token = login(client, "employee2")
        with session_scope() as session:
            user = session.scalar(select(User).where(User.email == DEMO_ACCOUNTS["employee2"]))
            assert user is not None
            session.delete(user)
        assert client.get("/api/v1/auth/me", headers=auth(token)).status_code == 401


class TestTokenExpiry:
    def test_short_lived_token_expires(self, client: TestClient, schema) -> None:
        with session_scope() as session:
            issued = create_access_token(
                subject="1", role="employee", settings=schema, expires_minutes=-1
            )
            record_session(
                session,
                user_id=1,
                jti=issued.jti,
                expires_at=issued.expires_at,
            )
        response = client.get("/api/v1/auth/me", headers=auth(issued.token))
        assert response.status_code == 401
