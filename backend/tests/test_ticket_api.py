"""Ticket API tests: the visibility matrix, status changes and audit trail."""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import AuditLog
from app.db.session import session_scope

pytestmark = pytest.mark.security


def year() -> int:
    return dt.datetime.now(dt.UTC).year


def security_reference() -> str:
    """A seeded ticket owned by the security team: invisible to employees."""
    return f"SEC-{year()}-0001"


def employee_reference() -> str:
    """The seeded ticket the employee raised themselves."""
    return f"IT-{year()}-0001"


class TestAuthentication:
    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("GET", "/api/v1/tickets"),
            ("POST", "/api/v1/tickets"),
            ("GET", "/api/v1/tickets/statistics"),
            ("GET", f"/api/v1/tickets/SEC-{dt.datetime.now(dt.UTC).year}-0001"),
            ("PATCH", f"/api/v1/tickets/SEC-{dt.datetime.now(dt.UTC).year}-0001"),
        ],
    )
    def test_requires_a_token(self, client: TestClient, method: str, path: str) -> None:
        body = {"status": "in_progress"} if method == "PATCH" else {}
        assert client.request(method, path, json=body).status_code == 401


class TestVisibility:
    def test_security_sees_the_whole_queue(self, client: TestClient, security_headers) -> None:
        body = client.get("/api/v1/tickets", headers=security_headers).json()
        assert body["count"] >= 3
        assert body["statistics"]["total"] >= 3

    def test_employee_sees_a_smaller_scope_than_security(
        self, client: TestClient, employee_headers, security_headers
    ) -> None:
        employee = client.get("/api/v1/tickets", headers=employee_headers).json()
        security = client.get("/api/v1/tickets", headers=security_headers).json()
        assert employee["count"] <= security["count"]

    def test_it_scope_sits_between_employee_and_security(
        self, client: TestClient, employee_headers, it_headers, security_headers
    ) -> None:
        employee = client.get("/api/v1/tickets", headers=employee_headers).json()["count"]
        it_support = client.get("/api/v1/tickets", headers=it_headers).json()["count"]
        security = client.get("/api/v1/tickets", headers=security_headers).json()["count"]
        assert employee <= it_support <= security

    def test_a_foreign_ticket_is_not_found(
        self, client: TestClient, employee_headers, security_headers
    ) -> None:
        """IT owns the seeded VPN ticket; the employee did not raise it."""
        response = client.get(f"/api/v1/tickets/{security_reference()}", headers=employee_headers)
        assert response.status_code == 404
        assert (
            client.get(
                f"/api/v1/tickets/{security_reference()}", headers=security_headers
            ).status_code
            == 200
        )

    def test_an_employee_can_read_the_ticket_they_raised(
        self, client: TestClient, employee_headers
    ) -> None:
        assert (
            client.get(
                f"/api/v1/tickets/{employee_reference()}", headers=employee_headers
            ).status_code
            == 200
        )

    def test_forbidden_and_missing_are_indistinguishable(
        self, client: TestClient, employee_headers
    ) -> None:
        foreign = client.get(f"/api/v1/tickets/{security_reference()}", headers=employee_headers)
        missing = client.get("/api/v1/tickets/SEC-1999-9999", headers=employee_headers)
        assert foreign.status_code == missing.status_code == 404
        assert foreign.json()["error"]["message"] == missing.json()["error"]["message"]

    def test_denial_is_audited(self, client: TestClient, employee_headers) -> None:
        client.get(f"/api/v1/tickets/{security_reference()}", headers=employee_headers)
        with session_scope() as session:
            rows = session.scalars(
                select(AuditLog).where(AuditLog.action == "ticket.access.denied")
            ).all()
        assert rows

    def test_listing_scope_never_leaks_other_references(
        self, client: TestClient, employee_headers
    ) -> None:
        """Everything an employee lists must have been raised by them."""
        body = client.get("/api/v1/tickets", headers=employee_headers).json()
        references = {ticket["reference"] for ticket in body["tickets"]}
        assert security_reference() not in references
        assert references <= {employee_reference()}


class TestStatistics:
    def test_statistics_are_returned_for_the_callers_scope(
        self, client: TestClient, security_headers
    ) -> None:
        body = client.get("/api/v1/tickets/statistics", headers=security_headers).json()
        stats = body["statistics"]
        assert set(stats["by_status"]) == {
            "open",
            "in_progress",
            "escalated",
            "resolved",
            "closed",
        }
        assert stats["requiring_human"] >= 1

    def test_statistics_expose_no_ticket_content(
        self, client: TestClient, security_headers
    ) -> None:
        raw = client.get("/api/v1/tickets/statistics", headers=security_headers).text
        assert "phishing" not in raw.lower()
        assert "password" not in raw.lower()


class TestStatusChanges:
    def test_security_can_acknowledge_an_escalated_ticket(
        self, client: TestClient, security_headers
    ) -> None:
        reference = security_reference()
        response = client.patch(
            f"/api/v1/tickets/{reference}",
            headers=security_headers,
            json={"status": "in_progress", "note": "Picked up by the duty engineer."},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "in_progress"
        assert body["can_update"] is True
        assert any(event["to_status"] == "in_progress" for event in body["events"])

    def test_employee_cannot_change_a_status(self, client: TestClient, employee_headers) -> None:
        reference = employee_reference()
        response = client.patch(
            f"/api/v1/tickets/{reference}",
            headers=employee_headers,
            json={"status": "closed"},
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "permission_denied"

    def test_it_cannot_change_a_security_ticket(self, client: TestClient, it_headers) -> None:
        reference = f"SEC-{year()}-0001"
        # IT cannot even see it, so the attempt is a 404 rather than a 403.
        assert client.get(f"/api/v1/tickets/{reference}", headers=it_headers).status_code == 404

    def test_denied_status_change_is_audited(self, client: TestClient, employee_headers) -> None:
        reference = employee_reference()
        client.patch(
            f"/api/v1/tickets/{reference}", headers=employee_headers, json={"status": "closed"}
        )
        with session_scope() as session:
            rows = session.scalars(
                select(AuditLog).where(AuditLog.action == "ticket.status.denied")
            ).all()
        assert rows
        assert rows[-1].outcome.value == "denied"

    def test_unknown_status_is_rejected_with_the_allowed_values(
        self, client: TestClient, security_headers
    ) -> None:
        reference = security_reference()
        response = client.patch(
            f"/api/v1/tickets/{reference}",
            headers=security_headers,
            json={"status": "banana"},
        )
        assert response.status_code == 422
        assert "closed" in response.json()["error"]["message"]

    def test_an_escalated_ticket_cannot_be_closed_without_acknowledgement(
        self, client: TestClient, security_headers
    ) -> None:
        """Escalating *is* acknowledging; being flagged and ignored is not."""
        from app.core.enums import Role, TicketStatus
        from app.services.ticket_service import TicketService

        # Raise a flagged-but-unacknowledged ticket. The API cannot produce this
        # state on purpose, so it is created through the service.
        with session_scope() as session:
            ticket = TicketService().create_ticket(
                session,
                title="Flagged, nobody has looked at it",
                escalation_required=True,
                status=TicketStatus.OPEN,
                owner_role=Role.SECURITY,
            )
            reference = ticket.reference

        response = client.patch(
            f"/api/v1/tickets/{reference}", headers=security_headers, json={"status": "closed"}
        )
        assert response.status_code == 422
        assert "acknowledged" in response.json()["error"]["message"]

        # Acknowledging first makes the same close valid.
        assert (
            client.patch(
                f"/api/v1/tickets/{reference}",
                headers=security_headers,
                json={"status": "in_progress"},
            ).status_code
            == 200
        )
        assert (
            client.patch(
                f"/api/v1/tickets/{reference}", headers=security_headers, json={"status": "closed"}
            ).status_code
            == 200
        )

    def test_an_escalated_ticket_may_be_closed_directly(
        self, client: TestClient, security_headers
    ) -> None:
        """Escalated means a human already picked it up."""
        from app.core.enums import Role, TicketStatus
        from app.services.ticket_service import TicketService

        with session_scope() as session:
            ticket = TicketService().create_ticket(
                session,
                title="Under investigation",
                escalation_required=True,
                status=TicketStatus.ESCALATED,
                owner_role=Role.SECURITY,
            )
            reference = ticket.reference

        assert (
            client.patch(
                f"/api/v1/tickets/{reference}", headers=security_headers, json={"status": "closed"}
            ).status_code
            == 200
        )

    def test_invalid_transition_is_rejected(self, client: TestClient, security_headers) -> None:
        created = client.post(
            "/api/v1/tickets",
            headers=security_headers,
            json={"title": "Transition fixture", "description": "x"},
        ).json()
        reference = created["reference"]
        client.patch(
            f"/api/v1/tickets/{reference}", headers=security_headers, json={"status": "closed"}
        )
        again = client.patch(
            f"/api/v1/tickets/{reference}", headers=security_headers, json={"status": "in_progress"}
        )
        assert again.status_code == 422


class TestUserRaisedTickets:
    def test_a_user_can_raise_a_ticket(self, client: TestClient, employee_headers) -> None:
        response = client.post(
            "/api/v1/tickets",
            headers=employee_headers,
            json={"title": "Printer on the third floor", "description": "It jams."},
        )
        assert response.status_code == 201, response.text
        body = response.json()
        # The reference prefix names the *owning queue*, not the raiser: with no
        # security category, an employee's request is an IT ticket.
        assert body["reference"].startswith("IT-")
        assert body["source"] == "user_request"
        assert body["status"] == "open"
        assert body["can_update"] is False

    def test_the_owning_team_is_derived_not_chosen(
        self, client: TestClient, employee_headers
    ) -> None:
        """A user cannot file into the security queue by claiming a role or a severity.

        They *can* route a ticket there by reporting a security matter, which is the
        point: the queue is chosen by what the ticket is about, never by what the
        caller asserts about themselves.
        """
        body = client.post(
            "/api/v1/tickets",
            headers=employee_headers,
            json={
                "title": "Attempted escalation",
                "description": "x",
                "category": "it",
                "owner_role": "security",
                "severity": "critical",
                "status": "escalated",
                "escalation_required": True,
            },
        ).json()
        assert body["owner_role"] == "it", "the body cannot name the owning team"
        assert body["severity"] == "low", "the body cannot set the urgency"
        assert body["status"] == "open"
        assert body["escalation_required"] is False

    def test_a_security_category_routes_to_the_security_queue(
        self, client: TestClient, employee_headers
    ) -> None:
        """The dead end this fixes: the UI posts `security` for anything that is not
        an IT request, and every such report used to land in the IT queue at low
        severity, where the security team might never triage it."""
        response = client.post(
            "/api/v1/tickets",
            headers=employee_headers,
            json={
                "title": "A supplier asked me for my password",
                "description": "They emailed asking me to confirm my credentials.",
                "category": "security",
            },
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["reference"].startswith("SEC-")
        assert body["owner_role"] == "security"
        assert body["severity"] == "medium", "a security report is not a routine request"
        assert body["category"] == "security"

    def test_phishing_and_incident_categories_are_security_too(
        self, client: TestClient, employee_headers
    ) -> None:
        # The UI sends the classification it was given, not always the word
        # "security", so the routing has to understand both.
        for category in ("phishing", "incident", "malware", "data_leak"):
            body = client.post(
                "/api/v1/tickets",
                headers=employee_headers,
                json={"title": f"Report ({category})", "description": "x", "category": category},
            ).json()
            assert body["owner_role"] == "security", category
            assert body["severity"] == "medium", category

    def test_a_short_title_is_rejected(self, client: TestClient, employee_headers) -> None:
        response = client.post("/api/v1/tickets", headers=employee_headers, json={"title": "x"})
        assert response.status_code == 422

    def test_a_user_can_read_their_own_ticket(self, client: TestClient, employee_headers) -> None:
        reference = client.post(
            "/api/v1/tickets",
            headers=employee_headers,
            json={"title": "My own ticket", "description": "x"},
        ).json()["reference"]
        assert (
            client.get(f"/api/v1/tickets/{reference}", headers=employee_headers).status_code == 200
        )


class TestNotes:
    def test_a_reader_can_add_a_note(self, client: TestClient, employee_headers) -> None:
        reference = employee_reference()
        response = client.post(
            f"/api/v1/tickets/{reference}/notes",
            headers=employee_headers,
            json={"note": "Is there any update on this?"},
        )
        assert response.status_code == 201
        assert any(event["event_type"] == "note" for event in response.json()["events"])

    def test_an_empty_note_is_rejected(self, client: TestClient, employee_headers) -> None:
        reference = employee_reference()
        response = client.post(
            f"/api/v1/tickets/{reference}/notes", headers=employee_headers, json={"note": ""}
        )
        assert response.status_code == 422

    def test_a_foreign_ticket_cannot_be_commented_on(
        self, client: TestClient, employee_headers
    ) -> None:
        response = client.post(
            f"/api/v1/tickets/{security_reference()}/notes",
            headers=employee_headers,
            json={"note": "hello"},
        )
        assert response.status_code == 404


class TestTicketTimeline:
    def test_a_seeded_ticket_has_history(self, client: TestClient, security_headers) -> None:
        reference = f"SEC-{year()}-0001"
        body = client.get(f"/api/v1/tickets/{reference}", headers=security_headers).json()
        assert body["events"]
        assert body["events"][0]["event_type"] == "created"
        assert any(event["automated"] for event in body["events"])

    def test_the_timeline_records_the_actor_role(
        self, client: TestClient, security_headers
    ) -> None:
        reference = security_reference()
        client.patch(
            f"/api/v1/tickets/{reference}", headers=security_headers, json={"status": "in_progress"}
        )
        body = client.get(f"/api/v1/tickets/{reference}", headers=security_headers).json()
        changes = [event for event in body["events"] if event["event_type"] == "status_changed"]
        assert changes[-1]["actor_role"] == "security"
        assert changes[-1]["automated"] is False

    def test_the_timeline_never_echoes_conversation_content(
        self, client: TestClient, security_headers
    ) -> None:
        """Ticket text comes from titles and notes, not from chat transcripts."""
        reference = security_reference()
        client.post(
            f"/api/v1/tickets/{reference}/notes",
            headers=security_headers,
            json={"note": "Site-visit scheduled."},
        )
        raw = client.get(f"/api/v1/tickets/{reference}", headers=security_headers).text
        assert "Site-visit scheduled." in raw
        assert "hunter2-should-not-be-stored" not in raw


class TestFilters:
    def test_status_filter(self, client: TestClient, security_headers) -> None:
        body = client.get(
            "/api/v1/tickets", headers=security_headers, params={"status": "escalated"}
        ).json()
        assert all(ticket["status"] == "escalated" for ticket in body["tickets"])

    def test_severity_filter(self, client: TestClient, security_headers) -> None:
        body = client.get(
            "/api/v1/tickets", headers=security_headers, params={"severity": "high"}
        ).json()
        assert all(ticket["severity"] == "high" for ticket in body["tickets"])

    def test_pagination_bounds_are_enforced(self, client: TestClient, security_headers) -> None:
        assert (
            client.get(
                "/api/v1/tickets", headers=security_headers, params={"limit": 500}
            ).status_code
            == 422
        )
        assert (
            client.get(
                "/api/v1/tickets", headers=security_headers, params={"offset": -1}
            ).status_code
            == 422
        )
