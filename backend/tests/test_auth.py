"""Authentication tests: login, token handling and audit coverage."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.enums import AuditOutcome
from app.core.security import create_access_token, decode_access_token
from app.db.models import AuditLog, User
from app.db.session import session_scope
from tests.conftest import DEMO_ACCOUNTS, DEMO_PASSWORD


class TestLogin:
    @pytest.mark.parametrize("role", ["employee", "it", "security"])
    def test_demo_users_can_log_in(self, client: TestClient, role: str) -> None:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS[role], "password": DEMO_PASSWORD},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["token_type"] == "bearer"
        assert body["expires_in"] > 0
        assert body["user"]["role"] == role
        assert body["user"]["email"] == DEMO_ACCOUNTS[role]

    def test_login_response_never_contains_password_hash(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["security"], "password": DEMO_PASSWORD},
        )
        assert "password_hash" not in response.text
        assert "$2b$" not in response.text

    def test_wrong_password_rejected_with_generic_message(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["employee"], "password": "wrong-password"},
        )
        assert response.status_code == 401
        assert response.json()["error"]["message"] == "Invalid email or password."

    def test_unknown_account_returns_identical_error(self, client: TestClient) -> None:
        """User enumeration must be impossible from the response body."""
        wrong_password = client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["employee"], "password": "wrong-password"},
        )
        unknown_user = client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@example.com", "password": "wrong-password"},
        )
        assert unknown_user.status_code == wrong_password.status_code == 401
        assert (
            unknown_user.json()["error"]["message"] == (wrong_password.json()["error"]["message"])
        )

    def test_email_is_case_insensitive(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["it"].upper(), "password": DEMO_PASSWORD},
        )
        assert response.status_code == 200

    def test_inactive_account_is_rejected(self, client: TestClient) -> None:
        with session_scope() as session:
            user = session.scalar(select(User).where(User.email == DEMO_ACCOUNTS["it"]))
            assert user is not None
            user.is_active = False

        response = client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["it"], "password": DEMO_PASSWORD},
        )
        assert response.status_code == 401
        assert response.json()["error"]["message"] == "This account is disabled."

    def test_oversized_password_is_rejected_before_hashing(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["employee"], "password": "x" * 5000},
        )
        assert response.status_code == 422


class TestCurrentUser:
    def test_me_requires_authentication(self, client: TestClient) -> None:
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "authentication_required"

    def test_me_returns_the_authenticated_user(
        self, client: TestClient, security_headers: dict[str, str]
    ) -> None:
        response = client.get("/api/v1/auth/me", headers=security_headers)
        assert response.status_code == 200
        body = response.json()
        assert body["role"] == "security"
        assert body["role_label"] == "Security Team"

    def test_garbage_token_rejected(self, client: TestClient) -> None:
        response = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer not-a-jwt"})
        assert response.status_code == 401
        assert response.json()["error"]["message"] == "Invalid credentials."

    def test_token_signed_with_other_key_rejected(self, client: TestClient, settings) -> None:
        forged = create_access_token(
            subject="1",
            role="security",
            settings=settings.model_copy(
                update={"auth_secret_key": "attacker-controlled-key-of-sufficient-length"}
            ),
        ).token
        response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"})
        assert response.status_code == 401

    def test_token_for_deleted_user_rejected(self, client: TestClient, login) -> None:
        headers = login("employee2")
        # Simulate deletion by forging a token for an id that does not exist.
        import jwt

        from app.core.config import get_settings

        settings = get_settings()
        token = jwt.encode(
            {
                "sub": "999999",
                "role": "security",
                "iat": 0,
                "exp": 4102444800,
                "iss": "esaa",
            },
            settings.auth_secret_key,
            algorithm=settings.auth_algorithm,
        )
        response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401
        # The legitimate token still works.
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 200

    def test_role_claim_cannot_escalate_privileges(self, client: TestClient, login) -> None:
        """A token whose role claim lies must not gain the claimed role.

        The token is forged with the *real* session id of an employee's live
        session, so it passes the session check and the only thing that could
        grant the escalated role is the claim itself. It must not.
        """
        import jwt

        from app.core.config import get_settings

        headers = login("employee")
        live = get_settings()
        real_token = headers["Authorization"].removeprefix("Bearer ")
        real_claims = jwt.decode(real_token, live.auth_secret_key, algorithms=[live.auth_algorithm])

        forged = jwt.encode(
            {**real_claims, "role": "security"},  # the claim lies
            live.auth_secret_key,
            algorithm=live.auth_algorithm,
        )
        response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"})
        assert response.status_code == 200
        # Authorization state comes from the database, not from the token claim.
        assert response.json()["role"] == "employee"


class TestTokenHandling:
    def test_expired_token_rejected(self, client: TestClient, settings) -> None:
        issued = create_access_token(
            subject="1", role="employee", settings=settings, expires_minutes=-5
        )
        response = client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {issued.token}"}
        )
        assert response.status_code == 401
        assert response.json()["error"]["message"] == "Session expired. Please sign in again."

    def test_decode_rejects_foreign_issuer(self, settings) -> None:
        import jwt

        from app.core.errors import AuthenticationError

        token = jwt.encode(
            {"sub": "1", "role": "employee", "exp": 4102444800, "iss": "somebody-else"},
            settings.auth_secret_key,
            algorithm=settings.auth_algorithm,
        )
        with pytest.raises(AuthenticationError):
            decode_access_token(token, settings)

    def test_token_contains_no_password_or_document_claims(self, settings) -> None:
        issued = create_access_token(subject="1", role="employee", settings=settings)
        token = issued.token
        claims = decode_access_token(token, settings)
        assert set(claims) == {"sub", "role", "iat", "exp", "jti", "iss"}


class TestAuditTrail:
    def test_successful_login_is_audited(self, client: TestClient) -> None:
        client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["it"], "password": DEMO_PASSWORD},
        )
        with session_scope() as session:
            entry = session.scalar(
                select(AuditLog)
                .where(AuditLog.action == "auth.login.success")
                .order_by(AuditLog.id.desc())
            )
        assert entry is not None
        assert entry.actor_email == DEMO_ACCOUNTS["it"]
        assert entry.actor_role == "it"
        assert entry.outcome == AuditOutcome.SUCCESS

    @pytest.mark.security
    def test_failed_login_is_audited_without_recording_the_password(
        self, client: TestClient
    ) -> None:
        client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["it"], "password": "hunter2-should-not-be-stored"},
        )
        with session_scope() as session:
            entry = session.scalar(
                select(AuditLog)
                .where(AuditLog.action == "auth.login.failure")
                .order_by(AuditLog.id.desc())
            )
        assert entry is not None
        assert entry.outcome == AuditOutcome.DENIED
        assert "hunter2-should-not-be-stored" not in repr(entry.detail)

    @pytest.mark.security
    def test_audit_row_records_client_ip(self, client: TestClient) -> None:
        client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_ACCOUNTS["employee"], "password": DEMO_PASSWORD},
        )
        with session_scope() as session:
            entry = session.scalar(
                select(AuditLog)
                .where(AuditLog.action == "auth.login.success")
                .order_by(AuditLog.id.desc())
            )
        assert entry is not None
        assert entry.ip_address  # TestClient reports "testclient"
