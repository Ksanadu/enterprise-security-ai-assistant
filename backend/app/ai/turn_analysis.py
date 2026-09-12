"""The result of running one turn through the assistant pipeline.

This is a plain data structure shared by the pipeline stages and the workflow
manager. It lives in its own module so the chat service and the workflow manager
can both depend on it without depending on each other.
"""

from __future__ import annotations

import dataclasses

from app.ai.prompt_guard import GuardResult
from app.ai.risk_classifier import RiskAssessment
from app.core.enums import Intent, RiskLevel


@dataclasses.dataclass(frozen=True, slots=True)
class TurnAnalysis:
    """Everything the classification stages decided about one turn."""

    intent: Intent
    intent_confidence: float
    intent_source: str
    risk: RiskAssessment
    guard: GuardResult
    peak_risk: RiskLevel
    intent_signals: tuple[str, ...] = ()
    context_findings: int = 0
    blocked: bool = False
    #: Set when the workflow created or escalated a ticket for this turn.
    ticket_reference: str | None = None
    ticket_status: str | None = None

    @property
    def requires_escalation(self) -> bool:
        return self.risk.requires_escalation

    def audit_detail(self) -> dict[str, object]:
        """Metadata-only summary for the audit log."""
        return {
            "intent": self.intent.value,
            "intent_source": self.intent_source,
            "intent_confidence": round(self.intent_confidence, 2),
            "risk_level": self.risk.level.value,
            "risk_source": self.risk.source,
            "risk_signals": [signal.label for signal in self.risk.signals],
            "requires_escalation": self.requires_escalation,
            "peak_risk_level": self.peak_risk.value,
            "blocked": self.blocked,
            "context_injections_removed": self.context_findings,
            "ticket_reference": self.ticket_reference,
        }
