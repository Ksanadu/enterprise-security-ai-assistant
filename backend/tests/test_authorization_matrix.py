"""The authorization matrix.

This file is the specification-level view of access control: every endpoint, every
role, and the exact response expected. It also contains a **meta test** that walks
the application's own route table, so an endpoint added later without
authentication fails the suite instead of shipping open.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.enums import Role
from app.db.models import AuditLog
from app.db.session import session_scope
from app.security.rbac import (
    can_update_ticket,
    can_view_ticket,
    describe_ticket_policy,
    visible_ticket_filter,
)

pytestmark = pytest.mark.security

#: Endpoints reachable without a token, and why.
PUBLIC_ENDPOINTS: dict[tuple[str, str], str] = {
    ("GET", "/api/v1/health"): "liveness probe",
    ("GET", "/api/v1/meta"): "public configuration summary",
    ("POST", "/api/v1/auth/login"): "sign-in",
}

#: Endpoints that require a valid token but grant no special privilege.
AUTHENTICATED_ENDPOINTS: list[tuple[str, str]] = [
    ("GET", "/api/v1/auth/me"),
    ("POST", "/api/v1/auth/logout"),
    ("POST", "/api/v1/auth/logout-all"),
    ("GET", "/api/v1/auth/sessions"),
    ("GET", "/api/v1/knowledge/documents"),
    ("GET", "/api/v1/knowledge/documents/KB-001"),
    ("POST", "/api/v1/knowledge/search"),
    ("GET", "/api/v1/knowledge/scope"),
    ("GET", "/api/v1/knowledge/stats"),
    ("GET", "/api/v1/chat/conversations"),
    ("POST", "/api/v1/chat/conversations"),
    ("GET", "/api/v1/chat/capabilities"),
]

#: Endpoints restricted to specific roles: (method, path, {role: expected status}).
ROLE_RESTRICTED: list[tuple[str, str, dict[str, int]]] = [
    (
        "POST",
        "/api/v1/knowledge/reindex",
        {"employee": 403, "it": 403, "security": 200},
    ),
]


def headers_for(client: TestClient, role: str) -> dict[str, str]:
    from tests.conftest import DEMO_ACCOUNTS, DEMO_PASSWORD

    response = client.post(
        "/api/v1/auth/login",
        json={"email": DEMO_ACCOUNTS[role], "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def request_body(method: str, path: str) -> dict[str, object] | None:
    if method != "POST":
        return None
    if path.endswith("/search"):
        return {"query": "password policy"}
    if path.endswith("/conversations"):
        return {}
    return {}


class TestAnonymousAccess:
    @pytest.mark.parametrize(("method", "path"), AUTHENTICATED_ENDPOINTS)
    def test_requires_a_token(self, client: TestClient, method: str, path: str) -> None:
        response = client.request(method, path, json=request_body(method, path))
        assert response.status_code == 401, f"{method} {path} was reachable anonymously"
        assert response.json()["error"]["code"] == "authentication_required"

    @pytest.mark.parametrize(
        ("method", "path"),
        [(method, path) for method, path, _ in ROLE_RESTRICTED],
        ids=[path for _, path, _ in ROLE_RESTRICTED],
    )
    def test_restricted_endpoints_require_a_token(
        self, client: TestClient, method: str, path: str
    ) -> None:
        assert client.request(method, path, json=request_body(method, path)).status_code == 401

    @pytest.mark.parametrize(("method", "path"), list(PUBLIC_ENDPOINTS))
    def test_public_endpoints_stay_public(self, client: TestClient, method: str, path: str) -> None:
        response = client.request(method, path, json=request_body(method, path))
        assert response.status_code not in {401, 403}


class TestEveryRouteIsProtected:
    """A meta test over the framework's own route table."""

    @staticmethod
    def _api_routes(app: FastAPI) -> list[tuple[str, str]]:
        found: list[tuple[str, str]] = []
        for route in app.routes:
            path = getattr(route, "path", "")
            methods = getattr(route, "methods", None) or set()
            if not path.startswith("/api/"):
                continue
            for method in methods:
                if method in {"HEAD", "OPTIONS"}:
                    continue
                found.append((method, path))
        return found

    def test_no_endpoint_is_unauthenticated_by_accident(self, client: TestClient, app) -> None:
        """Every API route must be public *on purpose* or reject anonymous calls.

        A route declared with a path parameter (``/documents/{id}``) is exercised
        with a concrete value; the point is only whether the framework lets the
        request through unauthenticated.
        """
        unprotected: list[str] = []
        for method, path in self._api_routes(app):
            if (method, path) in PUBLIC_ENDPOINTS:
                continue
            concrete = path.replace("{document_id}", "KB-001").replace("{conversation_id}", "1")
            response = client.request(method, concrete, json=request_body(method, concrete))
            if response.status_code != 401:
                unprotected.append(f"{method} {concrete} -> {response.status_code}")
        assert not unprotected, "endpoints reachable without a token: " + "; ".join(unprotected)

    def test_the_route_table_is_not_empty(self, app) -> None:
        assert len(self._api_routes(app)) >= 15


class TestRoleMatrix:
    @pytest.mark.parametrize(("method", "path", "expected"), ROLE_RESTRICTED)
    def test_role_restricted_endpoints(
        self, client: TestClient, method: str, path: str, expected: dict[str, int]
    ) -> None:
        for role, status in expected.items():
            headers = headers_for(client, role)
            response = client.request(
                method, path, headers=headers, json=request_body(method, path)
            )
            assert response.status_code == status, f"{role} {method} {path}"

    @pytest.mark.parametrize(("method", "path"), AUTHENTICATED_ENDPOINTS)
    @pytest.mark.parametrize("role", ["employee", "it", "security"])
    def test_every_role_can_reach_the_shared_endpoints(
        self, client: TestClient, method: str, path: str, role: str
    ) -> None:
        headers = headers_for(client, role)
        response = client.request(method, path, headers=headers, json=request_body(method, path))
        assert response.status_code < 400, f"{role} {method} {path} -> {response.status_code}"

    def test_a_denial_is_audited_with_the_attempted_endpoint(self, client: TestClient) -> None:
        headers = headers_for(client, "employee")
        client.post("/api/v1/knowledge/reindex", headers=headers)
        with session_scope() as session:
            row = session.scalar(
                select(AuditLog)
                .where(AuditLog.action == "authz.denied")
                .order_by(AuditLog.id.desc())
            )
        assert row is not None
        assert row.outcome.value == "denied"
        assert row.resource_id == "POST /api/v1/knowledge/reindex"
        assert row.detail is not None
        assert row.detail["required_roles"] == ["security"]


class TestTicketPolicy:
    """Pure policy functions. Phase 6 consumes them; the rules are fixed here."""

    CREATOR = 42
    OTHER = 7

    @pytest.mark.parametrize(
        ("role", "owner_role", "created_by", "expected"),
        [
            # The creator always sees their own ticket.
            (Role.EMPLOYEE, Role.SECURITY, CREATOR, True),
            (Role.EMPLOYEE, Role.EMPLOYEE, CREATOR, True),
            (Role.IT, Role.SECURITY, CREATOR, True),
            # An employee must not see anybody else's ticket.
            (Role.EMPLOYEE, Role.EMPLOYEE, OTHER, False),
            (Role.EMPLOYEE, Role.IT, OTHER, False),
            (Role.EMPLOYEE, Role.SECURITY, OTHER, False),
            # IT handles its own team's queue and routine employee requests.
            (Role.IT, Role.IT, OTHER, True),
            (Role.IT, Role.EMPLOYEE, OTHER, True),
            (Role.IT, Role.SECURITY, OTHER, False),
            # Security owns incident response and sees everything.
            (Role.SECURITY, Role.SECURITY, OTHER, True),
            (Role.SECURITY, Role.IT, OTHER, True),
            (Role.SECURITY, Role.EMPLOYEE, OTHER, True),
        ],
    )
    def test_view_rules(
        self, role: Role, owner_role: Role, created_by: int, expected: bool
    ) -> None:
        assert (
            can_view_ticket(
                role=role,
                user_id=self.CREATOR,
                ticket_owner_role=owner_role,
                ticket_created_by_user_id=created_by,
            )
            is expected
        )

    @pytest.mark.parametrize(
        ("role", "owner_role", "expected"),
        [
            (Role.EMPLOYEE, Role.EMPLOYEE, False),
            (Role.EMPLOYEE, Role.SECURITY, False),
            (Role.IT, Role.IT, True),
            (Role.IT, Role.EMPLOYEE, True),
            (Role.IT, Role.SECURITY, False),
            (Role.SECURITY, Role.SECURITY, True),
        ],
    )
    def test_update_rules(self, role: Role, owner_role: Role, expected: bool) -> None:
        assert (
            can_update_ticket(
                role=role,
                user_id=self.OTHER,
                ticket_owner_role=owner_role,
                ticket_created_by_user_id=self.OTHER,
            )
            is expected
        )

    def test_an_employee_cannot_update_their_own_ticket(self) -> None:
        assert (
            can_update_ticket(
                role=Role.EMPLOYEE,
                user_id=self.CREATOR,
                ticket_owner_role=Role.EMPLOYEE,
                ticket_created_by_user_id=self.CREATOR,
            )
            is False
        )

    def test_visible_filter_is_least_privilege(self) -> None:
        assert visible_ticket_filter(Role.SECURITY, self.CREATOR) == {}
        assert visible_ticket_filter(Role.EMPLOYEE, self.CREATOR) == {
            "created_by_user_id": self.CREATOR
        }
        assert visible_ticket_filter(Role.IT, self.CREATOR) == {
            "owner_roles": [Role.IT, Role.EMPLOYEE],
            "created_by_user_id": self.CREATOR,
        }

    def test_policy_is_documented_for_every_role(self) -> None:
        described = {entry["role"] for entry in describe_ticket_policy()}
        assert described == {role.value for role in Role}
