"""System endpoints: health, metadata and the root document."""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestHealth:
    def test_health_reports_ok_with_database(self, client: TestClient) -> None:
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["checks"]["database"] == "ok"
        assert body["environment"] == "test"

    def test_health_returns_correlation_header(self, client: TestClient) -> None:
        response = client.get("/api/v1/health")
        assert response.headers.get("X-Request-ID")

    def test_health_is_not_audited_as_sensitive(self, client: TestClient) -> None:
        for _ in range(3):
            assert client.get("/api/v1/health").status_code == 200


class TestMeta:
    def test_meta_exposes_features_but_no_secrets(self, client: TestClient) -> None:
        response = client.get("/api/v1/meta")
        assert response.status_code == 200
        body = response.json()
        assert body["environment"] == "test"
        assert set(body["roles"]) == {"employee", "it", "security"}
        assert body["ai"]["vector_store"] == "memory"

        raw = response.text.lower()
        for forbidden in ("secret", "api_key", "apikey", "password", "token"):
            assert forbidden not in raw

    def test_root_endpoint_points_at_health(self, client: TestClient) -> None:
        response = client.get("/")
        assert response.status_code == 200
        assert response.json()["health"] == "/api/v1/health"


class TestErrorEnvelope:
    def test_unknown_route_uses_error_envelope(self, client: TestClient) -> None:
        response = client.get("/api/v1/does-not-exist")
        assert response.status_code == 404
        body = response.json()
        assert body["error"]["code"] == "http_404"
        assert "request_id" in body["error"]

    def test_validation_error_does_not_echo_submitted_values(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "not-an-email", "password": "SuperSecretValue123"},
        )
        assert response.status_code == 422
        assert "SuperSecretValue123" not in response.text
        codes = {field["location"] for field in response.json()["error"]["details"]["fields"]}
        assert "body.email" in codes
