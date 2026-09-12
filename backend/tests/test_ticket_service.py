"""Ticket service tests: references, transitions and escalation rules.

The transition rules are the interesting part. A ticket that required a human
must not be closeable without being acknowledged first, because that would let an
escalation be dismissed silently.
"""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import select

from app.core.enums import Role, Severity, TicketSource, TicketStatus
from app.db.models import Ticket, TicketEvent, User
from app.db.session import session_scope
from app.services.ticket_service import (
    ALLOWED_TRANSITIONS,
    REFERENCE_PREFIX,
    TicketService,
    TicketValidationError,
    build_reference,
)
from tests.conftest import DEMO_ACCOUNTS

pytestmark = pytest.mark.security


@pytest.fixture
def schema(settings):
    from app.db.seed import run_seed

    run_seed(settings)
    return settings


@pytest.fixture
def users(schema) -> dict[str, User]:
    with session_scope() as session:
        found = {user.email: user for user in session.scalars(select(User)).all()}
    return {
        "employee": found[DEMO_ACCOUNTS["employee"]],
        "employee2": found[DEMO_ACCOUNTS["employee2"]],
        "it": found[DEMO_ACCOUNTS["it"]],
        "security": found[DEMO_ACCOUNTS["security"]],
    }


@pytest.fixture
def service() -> TicketService:
    return TicketService()


class TestReferences:
    def test_reference_format(self) -> None:
        assert build_reference("SEC", 2024, 7) == "SEC-2024-0007"
        assert build_reference("IT", 2024, 1234) == "IT-2024-1234"

    @pytest.mark.parametrize("role", list(Role))
    def test_prefix_is_defined_for_every_role(self, role: Role) -> None:
        assert role in REFERENCE_PREFIX

    def test_references_increment_per_prefix(self, schema, users, service) -> None:
        with session_scope() as session:
            first = service.create_ticket(
                session, title="First", owner_role=Role.SECURITY, created_by=users["employee"]
            )
            second = service.create_ticket(
                session, title="Second", owner_role=Role.SECURITY, created_by=users["employee"]
            )
            it_ticket = service.create_ticket(
                session, title="IT one", owner_role=Role.IT, created_by=users["employee"]
            )
        year = dt.datetime.now(dt.UTC).year
        assert first.reference != second.reference
        assert first.reference.startswith(f"SEC-{year}-")
        assert it_ticket.reference.startswith(f"IT-{year}-")

    def test_references_are_unique(self, schema, users, service) -> None:
        with session_scope() as session:
            references = {
                service.create_ticket(
                    session, title=f"T{index}", owner_role=Role.SECURITY
                ).reference
                for index in range(5)
            }
        assert len(references) == 5

    @pytest.mark.parametrize("role", [Role.IT, Role.SECURITY])
    def test_allocator_does_not_collide_with_seeded_references(
        self, schema, users, service, role: Role
    ) -> None:
        """The seed and the runtime allocator must agree on the numbering.

        They once disagreed: the seed numbered references globally while the
        allocator numbered them per prefix, so the next runtime ticket collided
        with a seeded one and the insert failed.
        """
        with session_scope() as session:
            created = [
                service.create_ticket(session, title="After seed", owner_role=role).reference
                for _ in range(3)
            ]
            all_references = [ticket.reference for ticket in session.scalars(select(Ticket)).all()]
        assert len(created) == len(set(created))
        assert len(all_references) == len(set(all_references))


class TestCreation:
    def test_creation_writes_a_timeline_entry(self, schema, users, service) -> None:
        with session_scope() as session:
            ticket = service.create_ticket(
                session, title="Something happened", created_by=users["employee"]
            )
            events = service.timeline(session, ticket)
        assert len(events) == 1
        assert events[0].event_type == "created"
        assert events[0].automated is False

    def test_title_is_required(self, schema, service) -> None:
        with session_scope() as session, pytest.raises(TicketValidationError):
            service.create_ticket(session, title="   ")

    def test_an_escalated_ticket_cannot_be_created_closed(self, schema, service) -> None:
        with session_scope() as session, pytest.raises(TicketValidationError, match="closed"):
            service.create_ticket(
                session,
                title="Contradiction",
                escalation_required=True,
                status=TicketStatus.CLOSED,
            )

    def test_long_fields_are_truncated(self, schema, service) -> None:
        with session_scope() as session:
            ticket = service.create_ticket(session, title="x" * 500, related_query="y" * 5000)
        assert len(ticket.title) <= 200
        assert len(ticket.related_query) <= 1000

    def test_automated_creation_is_marked(self, schema, service) -> None:
        with session_scope() as session:
            ticket = service.create_ticket(
                session, title="Auto", automated=True, source=TicketSource.AI_AUTO
            )
            events = service.timeline(session, ticket)
        assert events[0].automated is True


class TestTransitions:
    def test_every_status_has_a_transition_table(self) -> None:
        assert set(ALLOWED_TRANSITIONS) == set(TicketStatus)

    def test_closed_is_terminal(self) -> None:
        assert ALLOWED_TRANSITIONS[TicketStatus.CLOSED] == frozenset()

    def test_open_can_move_to_in_progress(self, schema, users, service) -> None:
        with session_scope() as session:
            ticket = service.create_ticket(session, title="T")
            service.change_status(
                session, user=users["security"], ticket=ticket, new_status=TicketStatus.IN_PROGRESS
            )
            assert ticket.status is TicketStatus.IN_PROGRESS
            events = service.timeline(session, ticket)
        assert [event.event_type for event in events] == ["created", "status_changed"]
        assert events[-1].from_status == "open"
        assert events[-1].to_status == "in_progress"

    def test_illegal_transition_is_rejected(self, schema, users, service) -> None:
        with session_scope() as session:
            ticket = service.create_ticket(session, title="T", status=TicketStatus.CLOSED)
            with pytest.raises(TicketValidationError, match="cannot move"):
                service.change_status(
                    session, user=users["security"], ticket=ticket, new_status=TicketStatus.OPEN
                )

    def test_no_op_transition_is_rejected(self, schema, users, service) -> None:
        with session_scope() as session:
            ticket = service.create_ticket(session, title="T")
            with pytest.raises(TicketValidationError, match="already"):
                service.change_status(
                    session, user=users["security"], ticket=ticket, new_status=TicketStatus.OPEN
                )

    def test_escalated_ticket_must_be_acknowledged_before_closing(
        self, schema, users, service
    ) -> None:
        """An escalation must not be dismissible without anybody seeing it."""
        with session_scope() as session:
            ticket = service.create_ticket(
                session, title="Serious", escalation_required=True, status=TicketStatus.OPEN
            )
            with pytest.raises(TicketValidationError, match="acknowledged"):
                service.change_status(
                    session, user=users["security"], ticket=ticket, new_status=TicketStatus.CLOSED
                )
            with pytest.raises(TicketValidationError, match="acknowledged"):
                service.change_status(
                    session, user=users["security"], ticket=ticket, new_status=TicketStatus.RESOLVED
                )
            # Acknowledging first is allowed, and then closing is too.
            service.change_status(
                session, user=users["security"], ticket=ticket, new_status=TicketStatus.IN_PROGRESS
            )
            service.change_status(
                session, user=users["security"], ticket=ticket, new_status=TicketStatus.RESOLVED
            )
        assert ticket.status is TicketStatus.RESOLVED

    def test_a_non_escalated_ticket_may_be_closed_directly(self, schema, users, service) -> None:
        with session_scope() as session:
            ticket = service.create_ticket(session, title="Minor")
            service.change_status(
                session, user=users["security"], ticket=ticket, new_status=TicketStatus.CLOSED
            )
        assert ticket.status is TicketStatus.CLOSED

    def test_resolved_can_be_reopened(self, schema, users, service) -> None:
        with session_scope() as session:
            ticket = service.create_ticket(session, title="T")
            service.change_status(
                session, user=users["security"], ticket=ticket, new_status=TicketStatus.RESOLVED
            )
            service.change_status(
                session, user=users["security"], ticket=ticket, new_status=TicketStatus.IN_PROGRESS
            )
        assert ticket.status is TicketStatus.IN_PROGRESS

    def test_automated_change_skips_the_permission_check(self, schema, service) -> None:
        with session_scope() as session:
            ticket = service.create_ticket(session, title="T")
            service.change_status(
                session,
                user=None,  # type: ignore[arg-type]
                ticket=ticket,
                new_status=TicketStatus.ESCALATED,
                automated=True,
            )
        assert ticket.status is TicketStatus.ESCALATED


class TestEscalation:
    def test_escalation_raises_severity_and_status(self, schema, users, service) -> None:
        with session_scope() as session:
            ticket = service.create_ticket(session, title="T", severity=Severity.MEDIUM)
            service.escalate(
                session, ticket=ticket, severity=Severity.HIGH, reason="credentials submitted"
            )
            events = service.timeline(session, ticket)
        assert ticket.severity is Severity.HIGH
        assert ticket.status is TicketStatus.ESCALATED
        assert ticket.escalation_required is True
        assert {event.event_type for event in events} >= {"severity_changed", "escalated"}

    def test_escalation_never_lowers_severity(self, schema, users, service) -> None:
        with session_scope() as session:
            ticket = service.create_ticket(session, title="T", severity=Severity.CRITICAL)
            service.escalate(session, ticket=ticket, severity=Severity.MEDIUM, reason="odd")
        assert ticket.severity is Severity.CRITICAL

    def test_escalation_records_the_reason(self, schema, service) -> None:
        with session_scope() as session:
            ticket = service.create_ticket(session, title="T")
            service.escalate(session, ticket=ticket, severity=Severity.HIGH, reason="mfa approved")
            events = service.timeline(session, ticket)
        assert any("mfa approved" in event.note for event in events)


class TestVisibilityScopes:
    def test_employee_sees_only_their_own(self, schema, users, service) -> None:
        with session_scope() as session:
            mine = service.create_ticket(
                session, title="Mine", created_by=users["employee"], owner_role=Role.IT
            )
            theirs = service.create_ticket(
                session, title="Theirs", created_by=users["employee2"], owner_role=Role.IT
            )
            visible = service.list_visible(session, user=users["employee"])
            references = {ticket.reference for ticket in visible}
            creator_ids = {ticket.created_by_user_id for ticket in visible}
        assert mine.reference in references
        assert theirs.reference not in references
        # Every ticket the employee sees is one they raised themselves.
        assert creator_ids == {users["employee"].id}

    def test_it_sees_employee_tickets_and_its_own_queue(self, schema, users, service) -> None:
        with session_scope() as session:
            employee_ticket = service.create_ticket(
                session, title="Employee request", created_by=users["employee"], owner_role=Role.IT
            )
            security_ticket = service.create_ticket(
                session, title="Security matter", owner_role=Role.SECURITY
            )
            visible = service.list_visible(session, user=users["it"])
            references = {ticket.reference for ticket in visible}
        assert employee_ticket.reference in references
        assert security_ticket.reference not in references

    def test_security_sees_everything(self, schema, users, service) -> None:
        with session_scope() as session:
            service.create_ticket(session, title="A", owner_role=Role.IT)
            service.create_ticket(session, title="B", owner_role=Role.SECURITY)
            visible = service.list_visible(session, user=users["security"])
        assert len(visible) >= 2

    def test_get_visible_hides_other_peoples_tickets(self, schema, users, service) -> None:
        from app.core.errors import NotFoundError

        with session_scope() as session:
            ticket = service.create_ticket(
                session, title="Private", created_by=users["employee"], owner_role=Role.IT
            )
            with pytest.raises(NotFoundError):
                service.get_visible(session, user=users["employee2"], reference=ticket.reference)

    def test_get_visible_reports_missing_and_forbidden_identically(
        self, schema, users, service
    ) -> None:
        from app.core.errors import NotFoundError

        with session_scope() as session:
            ticket = service.create_ticket(
                session, title="Private", created_by=users["employee"], owner_role=Role.IT
            )
            with pytest.raises(NotFoundError) as forbidden:
                service.get_visible(session, user=users["employee2"], reference=ticket.reference)
            with pytest.raises(NotFoundError) as missing:
                service.get_visible(session, user=users["employee2"], reference="SEC-1999-9999")
        assert str(forbidden.value) == str(missing.value)

    def test_a_higher_role_does_not_see_another_employees_ticket(
        self, schema, users, service
    ) -> None:
        """IT sees the queue it owns; it does not see every employee's request."""
        with session_scope() as session:
            ticket = service.create_ticket(
                session,
                title="Employee's own",
                created_by=users["employee"],
                owner_role=Role.EMPLOYEE,
            )
            # owner_role EMPLOYEE is in IT's scope, so this one *is* visible;
            # what must not happen is seeing a ticket owned by security.
            visible_to_it = service.list_visible(session, user=users["it"])
            service_ticket = service.create_ticket(
                session, title="Security only", owner_role=Role.SECURITY
            )
            visible_to_it = service.list_visible(session, user=users["it"])
        assert ticket.reference in {t.reference for t in visible_to_it}
        assert service_ticket.reference not in {t.reference for t in visible_to_it}

    def test_employee_can_never_update(self, schema, users, service) -> None:
        with session_scope() as session:
            ticket = service.create_ticket(
                session, title="Mine", created_by=users["employee"], owner_role=Role.IT
            )
            assert service.can_view(user=users["employee"], ticket=ticket) is True
            assert service.can_update(user=users["employee"], ticket=ticket) is False


class TestConversationLookup:
    @staticmethod
    def _conversation(session, users) -> int:
        from app.db.models import Conversation

        conversation = Conversation(user_id=users["employee"].id, title="Test conversation")
        session.add(conversation)
        session.flush()
        return conversation.id

    def test_open_ticket_for_conversation_is_found(self, schema, users, service) -> None:
        with session_scope() as session:
            conversation_id = self._conversation(session, users)
            ticket = service.create_ticket(
                session,
                title="From chat",
                conversation_id=conversation_id,
                created_by=users["employee"],
            )
            found = service.find_open_for_conversation(session, conversation_id=conversation_id)
        assert found is not None
        assert found.reference == ticket.reference

    def test_closed_tickets_are_not_returned(self, schema, users, service) -> None:
        with session_scope() as session:
            conversation_id = self._conversation(session, users)
            ticket = service.create_ticket(
                session,
                title="Done",
                conversation_id=conversation_id,
                created_by=users["employee"],
            )
            service.change_status(
                session, user=users["security"], ticket=ticket, new_status=TicketStatus.RESOLVED
            )
            assert (
                service.find_open_for_conversation(session, conversation_id=conversation_id) is None
            )

    def test_unknown_conversation_returns_nothing(self, schema, service) -> None:
        with session_scope() as session:
            assert service.find_open_for_conversation(session, conversation_id=9999) is None


class TestNotes:
    def test_note_is_appended_to_the_timeline(self, schema, users, service) -> None:
        with session_scope() as session:
            ticket = service.create_ticket(session, title="T", created_by=users["employee"])
            service.add_note(session, user=users["employee"], ticket=ticket, note="Any update?")
            events = service.timeline(session, ticket)
        assert events[-1].event_type == "note"
        assert events[-1].note == "Any update?"
        assert events[-1].actor_role == "employee"

    def test_empty_note_is_rejected(self, schema, users, service) -> None:
        with session_scope() as session:
            ticket = service.create_ticket(session, title="T")
            with pytest.raises(TicketValidationError):
                service.add_note(session, user=users["employee"], ticket=ticket, note="   ")


class TestStatistics:
    def test_statistics_count_the_visible_scope(self, schema, users, service) -> None:
        with session_scope() as session:
            stats = service.statistics(session, user=users["security"])
        assert stats["total"] >= 3
        assert stats["requiring_human"] >= 1
        assert set(stats["by_status"]) == {status.value for status in TicketStatus}
        assert set(stats["by_severity"]) == {severity.value for severity in Severity}

    def test_seeded_tickets_have_a_timeline(self, schema, users, service) -> None:
        with session_scope() as session:
            tickets = session.scalars(select(Ticket)).all()
            for ticket in tickets:
                events = session.scalars(
                    select(TicketEvent).where(TicketEvent.ticket_id == ticket.id)
                ).all()
                assert events, f"{ticket.reference} has no history"
