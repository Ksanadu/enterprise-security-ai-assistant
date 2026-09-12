"""Seed simulated demo data.

Every account, ticket and document in this project is fictional. Seeding is
hard-disabled outside development/test environments so a production deployment
can never inherit demo credentials.
"""

from __future__ import annotations

import datetime as dt
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.enums import Role, Severity, TicketSource, TicketStatus
from app.core.security import hash_password
from app.db.models import Ticket, TicketEvent, User
from app.db.session import init_db, session_scope

logger = logging.getLogger(__name__)

#: (email, full_name, role) - all fictional personas.
DEMO_USERS: tuple[tuple[str, str, Role], ...] = (
    ("employee@example.com", "Alice Chen (Employee)", Role.EMPLOYEE),
    ("employee2@example.com", "Dave Okafor (Employee)", Role.EMPLOYEE),
    ("it@example.com", "Bob Martinez (IT Support)", Role.IT),
    ("security@example.com", "Carol Nguyen (Security Team)", Role.SECURITY),
)

#: Demo tickets as (prefix, title, category, severity, status, owner_role, source,
#: escalation, creator_email).
#:
#: References are built from the current year so the demo data looks consistent
#: with the tickets the assistant raises itself, and each record has a *different*
#: creator: if every ticket had the same raiser, every role would see all of them
#: and the visibility rules would be impossible to demonstrate.
DEMO_TICKETS: tuple[
    tuple[str, str, str, Severity, TicketStatus, Role, TicketSource, bool, str | None], ...
] = (
    (
        "SEC",
        "Suspected credential phishing - password submitted",
        "phishing",
        Severity.HIGH,
        TicketStatus.ESCALATED,
        Role.SECURITY,
        TicketSource.AI_AUTO,
        True,
        "security@example.com",
    ),
    (
        "SEC",
        "Unusual outbound traffic from workstation WKS-4412",
        "malware",
        Severity.MEDIUM,
        TicketStatus.IN_PROGRESS,
        Role.SECURITY,
        TicketSource.SECURITY_TEAM,
        False,
        "security@example.com",
    ),
    (
        "IT",
        "VPN client cannot establish tunnel after client upgrade",
        "vpn",
        Severity.LOW,
        TicketStatus.OPEN,
        Role.IT,
        TicketSource.USER_REQUEST,
        False,
        "employee@example.com",
    ),
)


def seed_users(session: Session, settings: Settings, *, password: str | None = None) -> list[User]:
    """Create the demo accounts if they do not exist yet. Idempotent."""
    if not settings.seed_demo_users:
        logger.info("seed_users_skipped reason=disabled")
        return []

    if settings.is_production:
        # Defence in depth: config validation already refuses this combination.
        raise RuntimeError("Refusing to seed demo users in a production environment")

    password = password or settings.demo_user_password
    password_hash = hash_password(password, rounds=settings.password_hash_rounds)
    created: list[User] = []

    for email, full_name, role in DEMO_USERS:
        existing = session.scalar(select(User).where(User.email == email))
        if existing is not None:
            created.append(existing)
            continue
        user = User(
            email=email,
            full_name=full_name,
            role=role,
            password_hash=password_hash,
            is_active=True,
        )
        session.add(user)
        created.append(user)

    session.flush()
    logger.info("seed_users_done count=%d", len(created))
    return created


def seed_tickets(session: Session, users: list[User]) -> int:
    """Create example tickets with a short history. Idempotent."""
    by_email = {user.email: user for user in users}
    created = 0
    now = dt.datetime.now(dt.UTC)
    year = now.year
    # References are numbered **per prefix**, matching the allocator in
    # TicketService. Numbering them globally here would hand out IT-2026-0003
    # while the allocator's next IT value is 0002, and the two would collide.
    counters: dict[str, int] = {}

    for (
        prefix,
        title,
        category,
        severity,
        status,
        owner_role,
        source,
        escalation,
        creator_email,
    ) in DEMO_TICKETS:
        counters[prefix] = counters.get(prefix, 0) + 1
        reference = f"{prefix}-{year}-{counters[prefix]:04d}"
        if session.scalar(select(Ticket).where(Ticket.reference == reference)) is not None:
            continue

        creator = by_email.get(creator_email) if creator_email else None
        ticket = Ticket(
            reference=reference,
            title=title,
            description=("Simulated demo record. No real person, system or incident is involved."),
            category=category,
            severity=severity,
            status=status,
            source=source,
            escalation_required=escalation,
            owner_role=owner_role,
            created_by_user_id=creator.id if creator else None,
            related_query="",
            created_at=now,
            updated_at=now,
        )
        session.add(ticket)
        session.flush()
        _seed_ticket_history(session, ticket, actor=creator, now=now)
        created += 1

    session.flush()
    logger.info("seed_tickets_done count=%d", created)
    return created


def _seed_ticket_history(
    session: Session, ticket: Ticket, *, actor: User | None, now: dt.datetime
) -> None:
    """Give a seeded ticket a plausible timeline.

    A demo ticket that opens with an empty history looks broken: a reviewer
    expects to see how it reached its current state.
    """
    entries: list[tuple[str, str | None, str | None, str, bool]] = [
        ("created", None, TicketStatus.OPEN.value, "Ticket created from the demo dataset.", True)
    ]
    if ticket.status is not TicketStatus.OPEN:
        entries.append(
            (
                "status_changed",
                TicketStatus.OPEN.value,
                ticket.status.value,
                "Triaged by the security team.",
                False,
            )
        )
    if ticket.escalation_required:
        entries.append(
            (
                "escalated",
                None,
                None,
                "Credentials were submitted, so a human must review this.",
                True,
            )
        )

    for event_type, from_status, to_status, note, automated in entries:
        session.add(
            TicketEvent(
                ticket_id=ticket.id,
                created_at=now,
                event_type=event_type,
                from_status=from_status,
                to_status=to_status,
                actor_user_id=None if automated else (actor.id if actor else None),
                actor_role=None if automated else (actor.role.value if actor else None),
                automated=automated,
                note=note,
            )
        )
    session.flush()


def run_seed(settings: Settings | None = None) -> dict[str, int]:
    """Create the schema and load demo data. Returns a small summary."""
    settings = settings or get_settings()
    init_db(settings)
    with session_scope() as session:
        users = seed_users(session, settings)
        tickets = seed_tickets(session, users)
    return {"users": len(users), "tickets": tickets}


if __name__ == "__main__":  # pragma: no cover - manual entry point
    import json

    from app.core.logging import configure_logging

    _settings = get_settings()
    configure_logging(_settings.log_level, _settings.log_format)
    print(json.dumps(run_seed(_settings), indent=2))
