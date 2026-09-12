"""Database, model and seeding tests."""

from __future__ import annotations

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError

from app.core.enums import RiskLevel, Role, Severity, TicketStatus
from app.db.models import AuditLog, Ticket, User
from app.db.seed import seed_tickets, seed_users
from app.db.session import get_engine, init_db, session_scope


class TestSchema:
    def test_all_required_tables_exist(self, settings) -> None:
        init_db(settings)
        tables = set(inspect(get_engine(settings)).get_table_names())
        assert {
            "users",
            "conversations",
            "messages",
            "tickets",
            "audit_logs",
        } <= tables

    def test_sqlite_foreign_keys_are_enabled(self, settings) -> None:
        from sqlalchemy import text

        init_db(settings)
        with get_engine(settings).connect() as connection:
            assert connection.execute(text("PRAGMA foreign_keys")).scalar() == 1

    def test_init_db_is_idempotent(self, settings) -> None:
        init_db(settings)
        init_db(settings)  # must not raise


class TestSeeding:
    def test_seed_creates_one_user_per_role(self, settings) -> None:
        init_db(settings)
        with session_scope() as session:
            users = seed_users(session, settings)
        roles = {user.role for user in users}
        assert roles == {Role.EMPLOYEE, Role.IT, Role.SECURITY}

    def test_seeding_twice_does_not_duplicate(self, settings) -> None:
        init_db(settings)
        with session_scope() as session:
            first = len(seed_users(session, settings))
        with session_scope() as session:
            second = len(seed_users(session, settings))
        with session_scope() as session:
            count = len(session.scalars(select(User)).all())
        assert first == second == count

    def test_seeded_passwords_are_hashed(self, settings) -> None:
        init_db(settings)
        with session_scope() as session:
            users = seed_users(session, settings)
        for user in users:
            assert user.password_hash.startswith("$2b$")
            assert settings.demo_user_password not in user.password_hash

    def test_seeding_refused_in_production(self) -> None:
        from app.core.config import Settings

        production = Settings(
            _env_file=None,
            app_env="production",
            debug=False,
            allow_demo_login=False,
            seed_demo_users=False,
            auth_secret_key="b" * 48,
            demo_user_password="NotTheDefault@1",
            api_cors_origins=["https://assistant.example.com"],
        )
        with session_scope() as session:
            assert seed_users(session, production) == []

    def test_demo_tickets_cover_several_severities(self, settings) -> None:
        init_db(settings)
        with session_scope() as session:
            users = seed_users(session, settings)
            seed_tickets(session, users)
        with session_scope() as session:
            tickets = session.scalars(select(Ticket)).all()
        assert len(tickets) >= 3
        assert {ticket.severity for ticket in tickets} >= {Severity.LOW, Severity.HIGH}
        assert any(ticket.escalation_required for ticket in tickets)
        assert {ticket.owner_role for ticket in tickets} >= {Role.IT, Role.SECURITY}


class TestConstraints:
    def test_duplicate_email_is_rejected(self, settings) -> None:
        init_db(settings)
        with session_scope() as session:
            seed_users(session, settings)
        with (
            pytest.raises(IntegrityError),
            session_scope() as session,
        ):
            session.add(
                User(
                    email="employee@example.com",
                    full_name="Impostor",
                    role=Role.SECURITY,
                    password_hash="$2b$fake",
                )
            )

    def test_duplicate_ticket_reference_is_rejected(self, settings) -> None:
        import datetime as dt

        init_db(settings)
        with session_scope() as session:
            users = seed_users(session, settings)
            seed_tickets(session, users)

        # Seeded references are built from the current year, so build the
        # duplicate the same way rather than hardcoding one.
        reference = f"SEC-{dt.datetime.now(dt.UTC).year}-0001"
        with (
            pytest.raises(IntegrityError),
            session_scope() as session,
        ):
            session.add(
                Ticket(
                    reference=reference,
                    title="Duplicate reference",
                    description="",
                )
            )


class TestEnumVocabulary:
    def test_high_and_critical_risk_require_escalation(self) -> None:
        assert RiskLevel.LOW.requires_escalation is False
        assert RiskLevel.MEDIUM.requires_escalation is False
        assert RiskLevel.HIGH.requires_escalation is True
        assert RiskLevel.CRITICAL.requires_escalation is True

    def test_role_privilege_ordering(self) -> None:
        assert Role.SECURITY.at_least(Role.IT)
        assert Role.IT.at_least(Role.EMPLOYEE)
        assert not Role.EMPLOYEE.at_least(Role.IT)

    def test_severity_maps_from_risk(self) -> None:
        assert Severity.from_risk(RiskLevel.CRITICAL) is Severity.CRITICAL

    def test_terminal_ticket_states(self) -> None:
        assert TicketStatus.RESOLVED.is_terminal
        assert TicketStatus.CLOSED.is_terminal
        assert not TicketStatus.OPEN.is_terminal


class TestAuditLog:
    def test_audit_rows_are_insert_only_in_application_code(self, settings) -> None:
        """The application layer must not expose update/delete helpers."""
        import app.security.audit as audit_module

        public = {name for name in dir(audit_module) if not name.startswith("_")}
        assert "record_audit" in public
        assert not any("delete" in name.lower() for name in public)

    def test_audit_log_stores_metadata_as_json(self, settings) -> None:
        init_db(settings)
        from app.core.enums import AuditOutcome
        from app.security.audit import record_audit

        with session_scope() as session:
            record_audit(
                session,
                action="test.action",
                outcome=AuditOutcome.SUCCESS,
                detail={"nested": {"count": 2}},
            )
        with session_scope() as session:
            entry = session.scalar(select(AuditLog).where(AuditLog.action == "test.action"))
        assert entry is not None
        assert entry.detail == {"nested": {"count": 2}}
