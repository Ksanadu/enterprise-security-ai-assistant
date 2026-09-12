"""Shared domain enumerations.

These are the vocabulary of the whole system: roles, intents, risk levels and
ticket lifecycle states. Keeping them in one module prevents stringly-typed
drift between the API, the database and the AI pipeline.
"""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """String enum that serialises to its value in JSON and in the database."""

    def __str__(self) -> str:  # pragma: no cover - convenience
        return str(self.value)


class Role(StrEnum):
    """User roles, ordered from least to most privileged."""

    EMPLOYEE = "employee"
    IT = "it"
    SECURITY = "security"

    @property
    def rank(self) -> int:
        return {"employee": 0, "it": 1, "security": 2}[self.value]

    @property
    def label(self) -> str:
        return {
            "employee": "Employee",
            "it": "IT Support",
            "security": "Security Team",
        }[self.value]

    def at_least(self, other: Role) -> bool:
        """True when this role is at least as privileged as ``other``."""
        return self.rank >= other.rank


class Intent(StrEnum):
    """What the user is actually asking for."""

    SECURITY_FAQ = "security_faq"
    PHISHING = "phishing"
    SECURITY_INCIDENT = "security_incident"
    IT_SUPPORT = "it_support"
    POLICY_QUESTION = "policy_question"
    OUT_OF_SCOPE = "out_of_scope"


class RiskLevel(StrEnum):
    """Assessed severity of the user's situation."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]

    @property
    def requires_escalation(self) -> bool:
        """High and critical events are always escalated to a human."""
        return self.rank >= RiskLevel.HIGH.rank


class TicketStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    CLOSED = "closed"

    @property
    def is_terminal(self) -> bool:
        return self in {TicketStatus.RESOLVED, TicketStatus.CLOSED}


class Severity(StrEnum):
    """Ticket severity, aligned with the risk scale."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]

    @classmethod
    def from_risk(cls, risk: RiskLevel) -> Severity:
        return cls(risk.value)


class MessageRole(StrEnum):
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    ERROR = "error"


class TicketSource(StrEnum):
    """Where a ticket came from."""

    AI_AUTO = "ai_auto"  # created automatically by the workflow manager
    AI_SUGGESTED = "ai_suggested"  # suggested by AI, confirmed by the user
    USER_REQUEST = "user_request"  # created explicitly by the user
    SECURITY_TEAM = "security_team"
