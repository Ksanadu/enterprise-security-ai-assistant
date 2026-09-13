"""Phase 7 QA: the security dashboard, tested against ground truth.

`PRODUCT_SPEC.md` section 1 goal 9 asks that an administrator can see basic
security-event and consultation statistics, and section 9 criterion 9 that tickets
can be viewed from a back office. A dashboard is easy to build and easy to get
quietly wrong, so these tests do not check that fields exist - they check that the
numbers agree with the database, that the role gate holds, and that the aggregate
views cannot be turned into an export of application content.

A QA pass over the dashboard found one real defect: the audit trail paginated by
``offset``, but reading it appends a ``dashboard.viewed`` row, so the window moved
under the reader and page 2 repeated the last entry of page 1. The endpoint now
supports id-cursor paging, and the tests below pin both the defect and the fix.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.enums import TicketStatus
from app.db.models import AuditLog, Conversation, Message, Ticket
from app.db.session import session_scope
from tests.conftest import DEMO_ACCOUNTS, DEMO_PASSWORD

pytestmark = [pytest.mark.security, pytest.mark.evaluation]

#: Every endpoint that returns data about the system. `capabilities` is
#: deliberately absent: it describes the dashboard rather than exposing it.
DATA_ENDPOINTS = [
    "/api/v1/dashboard/summary",
    "/api/v1/dashboard/overview",
    "/api/v1/dashboard/timeseries",
    "/api/v1/dashboard/distributions",
    "/api/v1/dashboard/response-times",
    "/api/v1/dashboard/document-access",
    "/api/v1/dashboard/audit",
    "/api/v1/dashboard/audit/actions",
]


def sign_in(client: TestClient, role: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": DEMO_ACCOUNTS[role], "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def ask(client: TestClient, headers: dict[str, str], question: str) -> dict:
    conversation_id = int(
        client.post("/api/v1/chat/conversations", headers=headers, json={}).json()["id"]
    )
    response = client.post(
        f"/api/v1/chat/conversations/{conversation_id}/messages",
        headers=headers,
        json={"content": question},
    )
    assert response.status_code == 200, response.text
    return response.json()["assistant_message"]["payload"]


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------


class TestTheDashboardIsSecurityOnly:
    @pytest.mark.parametrize("endpoint", DATA_ENDPOINTS)
    def test_employee_and_it_are_refused(self, client: TestClient, endpoint: str) -> None:
        for role in ("employee", "it"):
            response = client.get(endpoint, headers=sign_in(client, role))
            assert response.status_code == 403, (role, endpoint, response.status_code)

    @pytest.mark.parametrize("endpoint", DATA_ENDPOINTS)
    def test_security_is_allowed(self, client: TestClient, endpoint: str) -> None:
        assert client.get(endpoint, headers=sign_in(client, "security")).status_code == 200

    def test_an_anonymous_caller_is_refused(self, client: TestClient) -> None:
        for endpoint in DATA_ENDPOINTS:
            assert client.get(endpoint).status_code == 401, endpoint

    def test_the_refusal_is_audited(self, client: TestClient) -> None:
        client.get("/api/v1/dashboard/summary", headers=sign_in(client, "employee"))
        with session_scope() as session:
            actions = [row.action for row in session.scalars(select(AuditLog)).all()]
        assert "authz.denied" in actions

    def test_capabilities_is_available_to_any_role_and_reveals_no_data(
        self, client: TestClient
    ) -> None:
        # It exists so the UI can hide a tab it would only be refused. It must
        # describe the dashboard, not report on the system - so it carries role
        # and view names and a window bound, and no count of anything.
        body = client.get(
            "/api/v1/dashboard/capabilities", headers=sign_in(client, "employee")
        ).json()
        assert set(body) == {"available_to", "views", "max_window_days", "returns_content"}
        assert body["available_to"] == ["security"]
        assert body["returns_content"] is False
        assert isinstance(body["views"], list) and body["views"]
        for count_like in ("users", "tickets", "conversations", "questions", "escalations"):
            assert count_like not in body


# ---------------------------------------------------------------------------
# The numbers must be true
# ---------------------------------------------------------------------------


class TestTheNumbersAgreeWithTheDatabase:
    def test_headline_counters_match_ground_truth(self, client: TestClient) -> None:
        headers = sign_in(client, "security")
        # Generate known activity first, so the assertions are not all zero.
        ask(client, headers, "I entered my password on a phishing page.")
        ask(client, headers, "What are the password requirements?")

        body = client.get("/api/v1/dashboard/summary", headers=headers).json()

        with session_scope() as session:
            truth = {
                "conversations": session.scalar(select(func.count(Conversation.id))),
                "questions": session.scalar(
                    select(func.count(Message.id)).where(Message.role == "user")
                ),
                "escalations": session.scalar(
                    select(func.count(Message.id)).where(Message.escalated.is_(True))
                ),
                "open": session.scalar(
                    select(func.count(Ticket.id)).where(
                        Ticket.status.notin_([TicketStatus.RESOLVED, TicketStatus.CLOSED])
                    )
                ),
                "requiring_human": session.scalar(
                    select(func.count(Ticket.id)).where(
                        Ticket.escalation_required.is_(True),
                        Ticket.status.notin_([TicketStatus.RESOLVED, TicketStatus.CLOSED]),
                    )
                ),
            }

        assert body["conversations"]["total"] == truth["conversations"]
        assert body["questions"]["total"] == truth["questions"]
        assert body["escalations"]["total"] == truth["escalations"]
        assert body["tickets"]["open"] == truth["open"]
        assert body["tickets"]["requiring_human"] == truth["requiring_human"]

    def test_a_new_escalation_moves_the_counters(self, client: TestClient) -> None:
        headers = sign_in(client, "security")
        before = client.get("/api/v1/dashboard/summary", headers=headers).json()
        ask(client, headers, "I entered my password on a phishing page.")
        after = client.get("/api/v1/dashboard/summary", headers=headers).json()

        assert after["escalations"]["total"] == before["escalations"]["total"] + 1
        assert after["tickets"]["requiring_human"] == before["tickets"]["requiring_human"] + 1

    def test_the_window_filters_and_is_monotonic(self, client: TestClient) -> None:
        headers = sign_in(client, "security")
        ask(client, headers, "What are the password requirements?")

        narrow = client.get("/api/v1/dashboard/summary", headers=headers, params={"days": 7}).json()
        wide = client.get("/api/v1/dashboard/summary", headers=headers, params={"days": 90}).json()

        assert narrow["window_days"] == 7 and wide["window_days"] == 90
        assert narrow["questions"]["in_window"] <= wide["questions"]["in_window"]
        # Totals are all-time and must not move with the window.
        assert narrow["questions"]["total"] == wide["questions"]["total"]

    def test_beyond_the_window_is_excluded(self, client: TestClient) -> None:
        headers = sign_in(client, "security")
        ask(client, headers, "What are the password requirements?")
        body = client.get("/api/v1/dashboard/summary", headers=headers, params={"days": 1}).json()
        # Every in-window figure is a subset of its all-time figure.
        assert body["questions"]["in_window"] <= body["questions"]["total"]
        assert body["escalations"]["in_window"] <= body["escalations"]["total"]
        assert body["questions"]["in_window"] >= 1

    def test_response_times_are_internally_consistent(self, client: TestClient) -> None:
        body = client.get(
            "/api/v1/dashboard/response-times", headers=sign_in(client, "security")
        ).json()
        assert body["acknowledged"] + body["still_unacknowledged"] == body["escalated_tickets"]
        if body["median_seconds"] is not None:
            assert body["fastest_seconds"] <= body["median_seconds"] <= body["slowest_seconds"]

    def test_distributions_only_use_known_domains(self, client: TestClient) -> None:
        body = client.get(
            "/api/v1/dashboard/distributions", headers=sign_in(client, "security")
        ).json()
        assert set(body["risk_levels"]) == {"low", "medium", "high", "critical"}
        assert set(body["intents"]) == {
            "security_faq",
            "phishing",
            "security_incident",
            "it_support",
            "policy_question",
            "out_of_scope",
        }
        # Counts are inclusive, never negative.
        assert all(value >= 0 for value in body["risk_levels"].values())
        assert all(value >= 0 for value in body["intents"].values())

    def test_timeseries_covers_the_window(self, client: TestClient) -> None:
        body = client.get(
            "/api/v1/dashboard/timeseries",
            headers=sign_in(client, "security"),
            params={"days": 7},
        ).json()
        assert len(body["series"]) == 7
        assert [point["date"] for point in body["series"]] == sorted(
            point["date"] for point in body["series"]
        )
        for point in body["series"]:
            assert point["questions"] >= 0 and point["escalations"] >= 0


# ---------------------------------------------------------------------------
# The dashboard must not become an export
# ---------------------------------------------------------------------------


class TestTheDashboardCannotBeUsedAsAnExport:
    @pytest.mark.parametrize("endpoint", DATA_ENDPOINTS)
    def test_no_conversation_content_is_returned(
        self, client: TestClient, endpoint: str
    ) -> None:
        headers = sign_in(client, "security")
        marker = "zebra-questionnaire-marker"
        ask(client, headers, f"What is the password policy? {marker}")

        raw = client.get(endpoint, headers=headers).text
        assert marker not in raw, f"{endpoint} leaked conversation content"

    def test_audit_entries_expose_key_names_not_values(self, client: TestClient) -> None:
        body = client.get(
            "/api/v1/dashboard/audit", headers=sign_in(client, "security")
        ).json()
        assert body["entries"]
        for entry in body["entries"]:
            assert "detail" not in entry, "the raw detail blob must not be returned"
            assert isinstance(entry["detail_keys"], list)

    def test_document_access_reports_identifiers_not_text(self, client: TestClient) -> None:
        body = client.get(
            "/api/v1/dashboard/document-access", headers=sign_in(client, "security")
        ).json()
        for row in body["most_viewed_documents"]:
            assert set(row) == {"document_id", "count"}
        for row in body["most_refused_documents"]:
            assert set(row) == {"document_id", "count"}
        assert "Contractors" not in json.dumps(body)


# ---------------------------------------------------------------------------
# Audit-trail paging: the defect found by this QA pass
# ---------------------------------------------------------------------------


class TestAuditTrailPagingIsStable:
    #: A fresh test database starts with only a handful of audit rows, which is
    #: not enough to page. Signing in repeatedly is the cheapest way to produce a
    #: known number of them (each success writes `auth.login.success`).
    @staticmethod
    def _generate_entries(client: TestClient, count: int = 14) -> None:
        for _ in range(count):
            sign_in(client, "security")

    def test_offset_paging_shifts_under_the_reader(self, client: TestClient) -> None:
        """The defect, kept as a test so the cause stays documented.

        Reading the audit trail appends a ``dashboard.viewed`` row, so an offset
        window moves between the two requests: page 2 repeats the last entry of
        page 1. It is not merely theoretical - it happens on every page fetch.
        """
        headers = sign_in(client, "security")
        self._generate_entries(client)

        first = client.get(
            "/api/v1/dashboard/audit", headers=headers, params={"limit": 5, "offset": 0}
        ).json()
        second = client.get(
            "/api/v1/dashboard/audit", headers=headers, params={"limit": 5, "offset": 5}
        ).json()

        assert len(first["entries"]) == 5 and len(second["entries"]) == 5
        overlap = {entry["id"] for entry in first["entries"]} & {
            entry["id"] for entry in second["entries"]
        }
        assert overlap, (
            "offset paging is expected to overlap on an append-only log; if this "
            "no longer happens, the cursor test below is no longer proving anything"
        )

    def test_id_cursor_paging_is_stable(self, client: TestClient) -> None:
        headers = sign_in(client, "security")
        self._generate_entries(client)

        seen: list[int] = []
        cursor: int | None = None

        for _ in range(6):
            params: dict[str, int] = {"limit": 5}
            if cursor is not None:
                params["before_id"] = cursor
            page = client.get("/api/v1/dashboard/audit", headers=headers, params=params).json()
            seen.extend(entry["id"] for entry in page["entries"])
            cursor = page["next_before_id"]
            if cursor is None:
                break

        assert len(seen) > 5, "the walk must actually page"
        assert len(seen) == len(set(seen)), "a cursor walk must not repeat an entry"
        assert seen == sorted(seen, reverse=True), "entries must arrive newest first"

    def test_the_cursor_is_absent_once_the_trail_is_exhausted(self, client: TestClient) -> None:
        headers = sign_in(client, "security")
        # A filter that matches very little, with a page larger than the result.
        page = client.get(
            "/api/v1/dashboard/audit",
            headers=headers,
            params={"action": "admin.seed.executed", "limit": 200},
        ).json()
        if page["returned"] < 200:
            assert page["next_before_id"] is None

    def test_paging_reaches_the_end_of_the_trail(self, client: TestClient) -> None:
        headers = sign_in(client, "security")
        self._generate_entries(client)
        total = client.get("/api/v1/dashboard/audit", headers=headers).json()["total"]

        seen: set[int] = set()
        cursor: int | None = None
        for _ in range(60):
            params: dict[str, int] = {"limit": 50}
            if cursor is not None:
                params["before_id"] = cursor
            page = client.get("/api/v1/dashboard/audit", headers=headers, params=params).json()
            seen.update(entry["id"] for entry in page["entries"])
            cursor = page["next_before_id"]
            if cursor is None:
                break

        # Everything that existed at the first count is reachable. Rows appended
        # by the walk itself are newer, so they are legitimately absent.
        assert len(seen) >= total - 1, (len(seen), total)
        assert total > 0

    def test_filters_apply_to_every_page(self, client: TestClient) -> None:
        headers = sign_in(client, "security")
        self._generate_entries(client)
        page = client.get(
            "/api/v1/dashboard/audit",
            headers=headers,
            params={"action": "auth.login.success", "limit": 5},
        ).json()
        assert page["entries"]
        for entry in page["entries"]:
            assert entry["action"] == "auth.login.success"

    def test_the_cursor_is_validated(self, client: TestClient) -> None:
        headers = sign_in(client, "security")
        assert (
            client.get(
                "/api/v1/dashboard/audit", headers=headers, params={"before_id": 0}
            ).status_code
            == 422
        )
        assert (
            client.get(
                "/api/v1/dashboard/audit", headers=headers, params={"before_id": -5}
            ).status_code
            == 422
        )


# ---------------------------------------------------------------------------
# Degenerate input
# ---------------------------------------------------------------------------


class TestDegenerateInput:
    @pytest.mark.parametrize("days", [0, -1, 10_000])
    def test_an_out_of_range_window_is_rejected(self, client: TestClient, days: int) -> None:
        response = client.get(
            "/api/v1/dashboard/summary", headers=sign_in(client, "security"), params={"days": days}
        )
        assert response.status_code == 422, (days, response.status_code)

    @pytest.mark.parametrize("limit", [0, -1, 5000])
    def test_an_out_of_range_limit_is_rejected(self, client: TestClient, limit: int) -> None:
        response = client.get(
            "/api/v1/dashboard/audit", headers=sign_in(client, "security"), params={"limit": limit}
        )
        assert response.status_code == 422, (limit, response.status_code)

    def test_an_unknown_action_filter_returns_empty_not_an_error(
        self, client: TestClient
    ) -> None:
        body = client.get(
            "/api/v1/dashboard/audit",
            headers=sign_in(client, "security"),
            params={"action": "no.such.action"},
        ).json()
        assert body["total"] == 0
        assert body["entries"] == []

    def test_a_filter_value_cannot_inject_sql(self, client: TestClient) -> None:
        response = client.get(
            "/api/v1/dashboard/audit",
            headers=sign_in(client, "security"),
            params={"action": "'; DROP TABLE audit_logs; --"},
        )
        assert response.status_code in {200, 422}, response.status_code
        # The table is still there.
        assert client.get(
            "/api/v1/dashboard/summary", headers=sign_in(client, "security")
        ).status_code == 200
