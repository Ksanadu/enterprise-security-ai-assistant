"""Role-based access control policy.

**This module is the only place in the codebase allowed to decide whether a
principal may read a knowledge document.** The LLM is never consulted, the
client is never trusted, and no caller may pass its own permission list.

The policy is intentionally simple and auditable: a document declares which
roles may read it (``allowed_roles`` in its front matter), and a principal may
read it if their role is in that set. Everything else - chunking, retrieval,
prompt construction - consumes the decision from here.

Fail-closed rules:

* a document with an empty or missing ``allowed_roles`` is inaccessible to
  everyone (the loader rejects it outright, and this module still denies it);
* an unknown role denies.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol, TypedDict, TypeVar

from app.core.enums import Role


class _HasAllowedRoles(Protocol):
    """Anything that carries an audience: documents and chunks both do."""

    @property
    def document_id(self) -> str: ...

    @property
    def allowed_roles(self) -> frozenset[Role]: ...


T = TypeVar("T", bound=_HasAllowedRoles)

#: Human-readable description of what each role can reach. Used by the API to
#: explain scope to the UI, and by tests to keep documentation and policy aligned.
ROLE_SCOPE_DESCRIPTIONS: dict[Role, str] = {
    Role.EMPLOYEE: (
        "Security FAQ, employee-visible policies and first-line guides. "
        "Cannot reach security-team investigation material."
    ),
    Role.IT: (
        "Everything an employee can reach, plus IT service management SOPs, "
        "endpoint and VPN troubleshooting, access control policy and incident "
        "severity classification."
    ),
    Role.SECURITY: (
        "All security knowledge: incident response, malware handling, phishing "
        "investigation, severity classification and internal investigation "
        "material."
    ),
}


def can_access_document(role: Role, allowed_roles: frozenset[Role]) -> bool:
    """Core decision: may ``role`` read a document with this audience?"""
    if not allowed_roles:
        # Fail closed: a document with no declared audience is readable by nobody.
        return False
    return role in allowed_roles


def permits(item: _HasAllowedRoles, role: Role) -> bool:
    """Convenience wrapper for objects carrying ``allowed_roles``."""
    return can_access_document(role, item.allowed_roles)


def filter_authorized(items: Iterable[T], role: Role) -> list[T]:
    """Return only the items ``role`` may read, preserving input order."""
    return [item for item in items if permits(item, role)]


def authorized_document_ids(items: Iterable[_HasAllowedRoles], role: Role) -> frozenset[str]:
    """Resolve the set of document ids ``role`` may retrieve from.

    The return value is passed straight into the vector store's ``search`` call,
    so this function *is* the retrieval authorisation boundary. It is derived
    from the document metadata loaded from disk, never from the vector store's
    own contents.
    """
    return frozenset(item.document_id for item in items if permits(item, role))


def describe_role(role: Role, documents: Sequence[_HasAllowedRoles] = ()) -> dict[str, object]:
    """Explain a role's scope, optionally with live document counts."""
    reachable = filter_authorized(documents, role) if documents else []
    return {
        "role": role.value,
        "label": role.label,
        "rank": role.rank,
        "description": ROLE_SCOPE_DESCRIPTIONS[role],
        "document_count": len(reachable) if documents else None,
        "document_ids": sorted(item.document_id for item in reachable) if documents else [],
    }


def is_more_privileged(left: Role, right: Role) -> bool:
    """True when ``left`` has at least the privileges of ``right``."""
    return left.at_least(right)


# --------------------------------------------------------------------------
# Ticket policy
# --------------------------------------------------------------------------
#
# Tickets are scoped differently from knowledge documents. A document declares
# an audience; a ticket belongs to a person and to an owning team, so visibility
# has to consider both:
#
#   * the **creator** always sees their own ticket;
#   * the **owning team** sees the tickets it is responsible for;
#   * the **security team** sees everything, because it owns incident response;
#   * nobody sees another user's employee-owned ticket.
#
# `owner_role` is the least-privileged role that may handle the ticket, so
# "employee-owned" means "a routine request", not "a security incident".


def can_view_ticket(
    *,
    role: Role,
    user_id: int | None,
    ticket_owner_role: Role,
    ticket_created_by_user_id: int | None,
) -> bool:
    """May this principal read this ticket?"""
    if ticket_created_by_user_id is not None and ticket_created_by_user_id == user_id:
        return True
    if role is Role.SECURITY:
        return True
    if role is Role.IT:
        return ticket_owner_role in {Role.IT, Role.EMPLOYEE}
    # An employee with no claim on the ticket sees nothing, including tickets
    # owned by IT that mention them.
    return False


def can_update_ticket(
    *,
    role: Role,
    user_id: int | None,
    ticket_owner_role: Role,
    ticket_created_by_user_id: int | None,
) -> bool:
    """May this principal change this ticket's status?

    Reading and writing are separate questions: an employee may follow their own
    ticket but must not be able to close it.
    """
    if role is Role.SECURITY:
        return True
    if role is Role.IT:
        return ticket_owner_role in {Role.IT, Role.EMPLOYEE}
    del user_id, ticket_created_by_user_id
    return False


class TicketFilter(TypedDict, total=False):
    """Scope criteria a repository applies so the database does the filtering.

    A ``TypedDict`` rather than ``dict[str, object]`` so the query builder keeps
    its types: ``owner_roles`` is a list of roles, not an opaque object.
    """

    owner_roles: list[Role]
    created_by_user_id: int


def visible_ticket_filter(role: Role, user_id: int) -> TicketFilter:
    """Criteria describing which tickets this principal may read.

    Returning a filter rather than a list keeps the policy in one place while
    letting the query stay efficient; the same predicates are also available as
    functions for single-object checks and for tests.
    """
    if role is Role.SECURITY:
        return {}
    if role is Role.IT:
        return {"owner_roles": [Role.IT, Role.EMPLOYEE], "created_by_user_id": user_id}
    return {"created_by_user_id": user_id}


def describe_ticket_policy() -> list[dict[str, object]]:
    """Human-readable summary of the ticket rules, for the UI and for tests."""
    return [
        {
            "role": Role.EMPLOYEE.value,
            "can_view": "Only tickets they created",
            "can_update": "No",
        },
        {
            "role": Role.IT.value,
            "can_view": "Tickets they created, plus tickets owned by IT or Employee",
            "can_update": "Tickets in their view",
        },
        {
            "role": Role.SECURITY.value,
            "can_view": "All tickets",
            "can_update": "All tickets",
        },
    ]
