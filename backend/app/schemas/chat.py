"""Chat API schemas.

Note what is absent: there is no `role`, `allowed_roles`, `document_ids` or
`user_id` field anywhere in a request body. The caller's identity comes from the
bearer token and their scope from their database role, so a client cannot
influence either.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class SourceDocument(BaseModel):
    """A citation. Only documents the caller was authorised to retrieve appear."""

    document_id: str
    title: str
    category: str
    section: str
    score: float
    snippet: str


class RecommendedAction(BaseModel):
    text: str


class RiskSignalOut(BaseModel):
    label: str
    level: str
    evidence: str


class MessagePayload(BaseModel):
    """The structured assistant response stored with each assistant message.

    PRODUCT_SPEC.md section 8 fixes the fields of this object. ``answer`` repeats
    ``MessageOut.content`` deliberately, so the payload on its own is a complete
    record of the turn - intent, risk_level, answer, recommended_actions,
    source_documents, human_escalation, create_ticket - rather than something
    that only makes sense beside its parent row.
    """

    answer: str = ""
    recommended_actions: list[str] = Field(default_factory=list)
    source_documents: list[SourceDocument] = Field(default_factory=list)
    grounded: bool = False
    provider: str = "none"
    model: str = "none"
    offline: bool = True

    #: Intent classification (Phase 5).
    intent: str | None = None
    intent_confidence: float = 0.0
    intent_source: str = "rules"

    #: Risk classification and the escalation decision (Phase 5).
    risk_level: str | None = None
    risk_signals: list[RiskSignalOut] = Field(default_factory=list)
    risk_reason: str = ""
    #: ``human_escalation`` and ``create_ticket`` are decided from the risk level
    #: in backend code, never from model output.
    human_escalation: bool = False
    create_ticket: bool = False
    peak_risk_level: str | None = None

    #: Prompt-injection handling.
    blocked: bool = False
    block_reason: str | None = None
    block_categories: list[str] = Field(default_factory=list)
    context_injection_blocked: int = 0

    #: Set when the workflow manager created or escalated a ticket for this turn.
    ticket_reference: str | None = None
    ticket_status: str | None = None


class MessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    conversation_id: int
    role: str
    content: str
    payload: MessagePayload | None = None
    created_at: str | None = None


class ConversationSummary(BaseModel):
    id: int
    title: str
    message_count: int
    created_at: str | None = None
    updated_at: str | None = None


class ConversationDetail(ConversationSummary):
    messages: list[MessageOut] = Field(default_factory=list)


class ConversationListResponse(BaseModel):
    count: int
    conversations: list[ConversationSummary] = Field(default_factory=list)


class CreateConversationRequest(BaseModel):
    title: str | None = Field(default=None, max_length=120)


class PostMessageRequest(BaseModel):
    #: Bounded so an oversized prompt is rejected before it reaches the model.
    content: str = Field(min_length=1, max_length=4000)


class PostMessageResponse(BaseModel):
    conversation_id: int
    user_message: MessageOut
    assistant_message: MessageOut
