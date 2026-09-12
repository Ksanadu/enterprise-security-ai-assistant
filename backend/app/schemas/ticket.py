"""Ticket API schemas.

No request body carries a `user_id`, `role` or `owner_role` that the client
could use to influence what it sees: scope comes from the bearer token, and the
owning role is decided by the workflow, not by the caller.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class TicketEventOut(BaseModel):
    id: int
    created_at: str | None = None
    event_type: str
    from_status: str | None = None
    to_status: str | None = None
    from_severity: str | None = None
    to_severity: str | None = None
    actor_role: str | None = None
    #: True when the system produced the event rather than a person.
    automated: bool = False
    note: str = ""


class TicketSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    reference: str
    title: str
    category: str
    severity: str
    status: str
    source: str
    owner_role: str
    escalation_required: bool
    created_at: str | None = None
    updated_at: str | None = None


class TicketDetail(TicketSummary):
    description: str = ""
    related_query: str = ""
    #: Whether the caller may change this ticket's status.
    can_update: bool = False
    events: list[TicketEventOut] = Field(default_factory=list)


class TicketListResponse(BaseModel):
    count: int
    statistics: dict = Field(default_factory=dict)
    tickets: list[TicketSummary] = Field(default_factory=list)


class TicketStatisticsResponse(BaseModel):
    statistics: dict = Field(default_factory=dict)


class UpdateTicketRequest(BaseModel):
    status: str = Field(description="Target status")
    note: str = Field(default="", max_length=2000)


class AddNoteRequest(BaseModel):
    note: str = Field(min_length=1, max_length=2000)


class CreateTicketRequest(BaseModel):
    """A ticket a user raises themselves."""

    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=8000)
    #: Callers may not choose the owning team; the service derives it from their
    #: role so a user cannot file into another team's queue.
    category: str = Field(default="security", max_length=64)
