"""Knowledge API tests: role-scoped listing, reading and retrieval over HTTP."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import AuditLog
from app.db.session import session_scope
from tests.test_rag_rbac import EMPLOYEE_VISIBLE, IT_ONLY, SECURITY_ONLY

pytestmark = pytest.mark.security

ALL_RESTRICTED = SECURITY_ONLY | IT_ONLY


def actions(prefix: str) -> list[str]:
    with session_scope() as session:
        rows = session.scalars(select(AuditLog).where(AuditLog.action.startswith(prefix))).all()
        return [row.action for row in rows]


class TestAuthenticationRequired:
    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("GET", "/api/v1/knowledge/documents"),
            ("GET", "/api/v1/knowledge/documents/KB-001"),
            ("GET", "/api/v1/knowledge/stats"),
            ("GET", "/api/v1/knowledge/scope"),
            ("POST", "/api/v1/knowledge/search"),
            ("POST", "/api/v1/knowledge/reindex"),
        ],
    )
    def test_endpoints_require_authentication(
        self, client: TestClient, method: str, path: str
    ) -> None:
        response = client.request(method, path, json={"query": "password"})
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "authentication_required"


class TestDocumentListing:
    def test_employee_sees_only_their_scope(self, client: TestClient, employee_headers) -> None:
        response = client.get("/api/v1/knowledge/documents", headers=employee_headers)
        assert response.status_code == 200
        body = response.json()
        ids = {document["document_id"] for document in body["documents"]}
        assert ids == EMPLOYEE_VISIBLE
        assert body["role"] == "employee"
        assert body["count"] == len(EMPLOYEE_VISIBLE)

    def test_response_never_mentions_restricted_documents(
        self, client: TestClient, employee_headers
    ) -> None:
        raw = client.get("/api/v1/knowledge/documents", headers=employee_headers).text
        for document_id in ALL_RESTRICTED:
            assert document_id not in raw

    def test_it_sees_more_than_employee(
        self, client: TestClient, it_headers, employee_headers
    ) -> None:
        employee = client.get("/api/v1/knowledge/documents", headers=employee_headers).json()
        it_support = client.get("/api/v1/knowledge/documents", headers=it_headers).json()
        assert it_support["count"] > employee["count"]
        assert {d["document_id"] for d in it_support["documents"]} == EMPLOYEE_VISIBLE | IT_ONLY

    def test_security_sees_everything(self, client: TestClient, security_headers) -> None:
        body = client.get("/api/v1/knowledge/documents", headers=security_headers).json()
        ids = {document["document_id"] for document in body["documents"]}
        assert ids >= EMPLOYEE_VISIBLE | IT_ONLY | SECURITY_ONLY

    def test_metadata_contract_is_exposed(self, client: TestClient, employee_headers) -> None:
        body = client.get("/api/v1/knowledge/documents", headers=employee_headers).json()
        for document in body["documents"]:
            assert set(document) >= {
                "document_id",
                "title",
                "category",
                "allowed_roles",
                "summary",
            }
            assert document["allowed_roles"]
            assert "content" not in document

    def test_listing_is_audited(self, client: TestClient, employee_headers) -> None:
        client.get("/api/v1/knowledge/documents", headers=employee_headers)
        assert "knowledge.documents.listed" in actions("knowledge.")


class TestDocumentRead:
    def test_employee_can_read_a_visible_document(
        self, client: TestClient, employee_headers
    ) -> None:
        response = client.get("/api/v1/knowledge/documents/KB-001", headers=employee_headers)
        assert response.status_code == 200
        body = response.json()
        assert body["document_id"] == "KB-001"
        assert "14 characters" in body["content"]

    @pytest.mark.parametrize("document_id", sorted(ALL_RESTRICTED))
    def test_restricted_document_returns_not_found(
        self, client: TestClient, employee_headers, document_id: str
    ) -> None:
        response = client.get(
            f"/api/v1/knowledge/documents/{document_id}", headers=employee_headers
        )
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"

    def test_permission_failure_is_indistinguishable_from_absence(
        self, client: TestClient, employee_headers
    ) -> None:
        restricted = client.get("/api/v1/knowledge/documents/KB-004", headers=employee_headers)
        missing = client.get("/api/v1/knowledge/documents/KB-999", headers=employee_headers)
        assert restricted.status_code == missing.status_code == 404
        assert restricted.json()["error"]["message"] == missing.json()["error"]["message"]

    def test_denial_is_audited(self, client: TestClient, employee_headers) -> None:
        client.get("/api/v1/knowledge/documents/KB-004", headers=employee_headers)
        assert "knowledge.document.denied" in actions("knowledge.")

    def test_it_can_read_the_vpn_sop(self, client: TestClient, it_headers) -> None:
        response = client.get("/api/v1/knowledge/documents/KB-005", headers=it_headers)
        assert response.status_code == 200

    def test_it_cannot_read_security_only_material(self, client: TestClient, it_headers) -> None:
        response = client.get("/api/v1/knowledge/documents/KB-004", headers=it_headers)
        assert response.status_code == 404


class TestSearchEndpoint:
    def test_search_returns_sources_for_the_caller(
        self, client: TestClient, employee_headers
    ) -> None:
        response = client.post(
            "/api/v1/knowledge/search",
            headers=employee_headers,
            json={"query": "what are the password requirements"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["role"] == "employee"
        assert body["result_count"] >= 1
        assert body["results"][0]["document_id"] == "KB-001"
        assert body["results"][0]["score"] > 0

    def test_same_query_returns_different_sources_per_role(
        self, client: TestClient, employee_headers, security_headers
    ) -> None:
        query = {"query": "how do we investigate a phishing campaign with credentials"}
        employee = client.post(
            "/api/v1/knowledge/search", headers=employee_headers, json=query
        ).json()
        security = client.post(
            "/api/v1/knowledge/search", headers=security_headers, json=query
        ).json()

        employee_docs = {source["document_id"] for source in employee["results"]}
        security_docs = {source["document_id"] for source in security["results"]}
        assert employee_docs <= EMPLOYEE_VISIBLE
        assert security_docs - employee_docs, "the security team should reach extra material"

    def test_search_never_leaks_restricted_sources(
        self, client: TestClient, employee_headers
    ) -> None:
        response = client.post(
            "/api/v1/knowledge/search",
            headers=employee_headers,
            json={"query": "malware incident response evidence retention playbook"},
        )
        raw = response.text
        for document_id in ALL_RESTRICTED:
            assert document_id not in raw

    def test_no_match_is_reported_honestly(self, client: TestClient, employee_headers) -> None:
        response = client.post(
            "/api/v1/knowledge/search",
            headers=employee_headers,
            json={"query": "zzzz qqqq xxxx yyyy"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["result_count"] == 0
        assert body["no_authorized_match"] is True

    def test_search_is_audited_with_counts_only(self, client: TestClient, employee_headers) -> None:
        client.post(
            "/api/v1/knowledge/search",
            headers=employee_headers,
            json={"query": "password policy"},
        )
        with session_scope() as session:
            entry = session.scalar(
                select(AuditLog)
                .where(AuditLog.action == "rag.retrieval.performed")
                .order_by(AuditLog.id.desc())
            )
        assert entry is not None
        assert entry.detail is not None
        assert "withheld_documents" in entry.detail
        # The audit record carries counters and ids, never document text.
        assert "14 characters" not in repr(entry.detail)

    def test_oversized_query_is_rejected(self, client: TestClient, employee_headers) -> None:
        response = client.post(
            "/api/v1/knowledge/search",
            headers=employee_headers,
            json={"query": "x" * 3000},
        )
        assert response.status_code == 422

    def test_top_k_is_bounded_by_the_schema(self, client: TestClient, employee_headers) -> None:
        response = client.post(
            "/api/v1/knowledge/search",
            headers=employee_headers,
            json={"query": "password", "top_k": 500},
        )
        assert response.status_code == 422

    def test_empty_query_is_rejected(self, client: TestClient, employee_headers) -> None:
        response = client.post(
            "/api/v1/knowledge/search", headers=employee_headers, json={"query": ""}
        )
        assert response.status_code == 422


class TestScopeEndpoint:
    def test_scope_is_available_to_every_role(self, client: TestClient, employee_headers) -> None:
        response = client.get("/api/v1/knowledge/scope", headers=employee_headers)
        assert response.status_code == 200
        roles = {entry["role"] for entry in response.json()["roles"]}
        assert roles == {"employee", "it", "security"}

    def test_scope_counts_match_the_policy(self, client: TestClient, employee_headers) -> None:
        body = client.get("/api/v1/knowledge/scope", headers=employee_headers).json()
        by_role = {entry["role"]: entry for entry in body["roles"]}
        assert by_role["employee"]["document_count"] == len(EMPLOYEE_VISIBLE)
        assert by_role["it"]["document_count"] == len(EMPLOYEE_VISIBLE | IT_ONLY)

    def test_scope_describes_each_role(self, client: TestClient, employee_headers) -> None:
        body = client.get("/api/v1/knowledge/scope", headers=employee_headers).json()
        for entry in body["roles"]:
            assert entry["description"]


class TestStatsAndReindex:
    def test_stats_are_visible_to_any_role(self, client: TestClient, employee_headers) -> None:
        body = client.get("/api/v1/knowledge/stats", headers=employee_headers).json()
        assert body["ready"] is True
        assert body["document_count"] >= 10
        assert body["chunk_count"] >= body["document_count"]
        assert body["vector_store"] in {"memory", "faiss"}

    def test_stats_never_expose_document_titles(self, client: TestClient, employee_headers) -> None:
        raw = client.get("/api/v1/knowledge/stats", headers=employee_headers).text
        assert "Password Policy" not in raw
        assert "KB-001" not in raw

    def test_reindex_is_denied_for_employee(self, client: TestClient, employee_headers) -> None:
        response = client.post("/api/v1/knowledge/reindex", headers=employee_headers)
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "permission_denied"
        # The denial goes through the shared authorization dependency, which
        # records every refusal together with the endpoint that was attempted.
        assert "authz.denied" in actions("authz.")

    def test_reindex_is_denied_for_it(self, client: TestClient, it_headers) -> None:
        assert client.post("/api/v1/knowledge/reindex", headers=it_headers).status_code == 403

    def test_reindex_succeeds_for_security(self, client: TestClient, security_headers) -> None:
        response = client.post("/api/v1/knowledge/reindex", headers=security_headers)
        assert response.status_code == 200
        body = response.json()
        assert body["reindexed"] is True
        assert body["ready"] is True
        assert "knowledge.reindex.performed" in actions("knowledge.")

    def test_reindex_preserves_role_scoping(
        self, client: TestClient, security_headers, employee_headers
    ) -> None:
        client.post("/api/v1/knowledge/reindex", headers=security_headers)
        body = client.get("/api/v1/knowledge/documents", headers=employee_headers).json()
        assert {d["document_id"] for d in body["documents"]} == EMPLOYEE_VISIBLE


class TestHealthIntegration:
    def test_health_reports_the_knowledge_base(self, client: TestClient) -> None:
        body = client.get("/api/v1/health").json()
        assert body["checks"]["knowledge_base"] == "ok"
        assert body["status"] == "ok"
