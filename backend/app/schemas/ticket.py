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
    #: Counts of the tickets the caller can see, computed in SQL over the same visibility
    #: filter as the list and with no page cap. `open` means "not resolved and not closed"
    #: and therefore *includes* escalated tickets - which is why `open` and `escalated`
    #: can both be non-zero for the same row set. The key is named for what it counts
    #: (`is_open` on the model) rather than renamed, because renaming a field is a
    #: contract change with no correctness gain.
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
    #: The category decides the owning queue (security categories go to the security
    #: team, everything else to the raiser's own team), so the default is a neutral
    #: one. It used to be "security", which - once the category started routing -
    #: would have filed a bare "printer is jammed" request into the security queue.
    #: Neither `severity` nor `owner_role` is declared here: a caller cannot set the
    #: urgency of their own report or choose a queue to file into.
    category: str = Field(default="other", max_length=64)
