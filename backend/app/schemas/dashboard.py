"""Dashboard API schemas.

Everything here is a count, an aggregate or an identifier. There are no free-text
fields: the dashboard reports *how much*, never *what was said*.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class DashboardSummary(BaseModel):
    window_days: int
    window_start: str
    users: dict = Field(default_factory=dict)
    conversations: dict = Field(default_factory=dict)
    questions: dict = Field(default_factory=dict)
    escalations: dict = Field(default_factory=dict)
    tickets: dict = Field(default_factory=dict)
    security_signals: dict = Field(default_factory=dict)


class TimeseriesPoint(BaseModel):
    date: str
    questions: int
    escalations: int
    tickets: int
    denials: int
    logins: int


class TimeseriesResponse(BaseModel):
    window_days: int
    series: list[TimeseriesPoint] = Field(default_factory=list)


class DistributionsResponse(BaseModel):
    window_days: int
    risk_levels: dict[str, int] = Field(default_factory=dict)
    intents: dict[str, int] = Field(default_factory=dict)
    ticket_status: dict[str, int] = Field(default_factory=dict)
    ticket_severity: dict[str, int] = Field(default_factory=dict)
    ticket_owner_role: dict[str, int] = Field(default_factory=dict)
    ticket_source: dict[str, int] = Field(default_factory=dict)
    top_actions: list[dict] = Field(default_factory=list)


class ResponseTimesResponse(BaseModel):
    window_days: int
    escalated_tickets: int
    acknowledged: int
    still_unacknowledged: int
    median_seconds: float | None = None
    slowest_seconds: float | None = None
    fastest_seconds: float | None = None


class DocumentAccessResponse(BaseModel):
    window_days: int
    most_viewed_documents: list[dict] = Field(default_factory=list)
    most_refused_documents: list[dict] = Field(default_factory=list)
    denials_by_role: dict[str, int] = Field(default_factory=dict)


class DashboardOverview(BaseModel):
    summary: DashboardSummary
    timeseries: TimeseriesResponse
    distributions: DistributionsResponse
    response_times: ResponseTimesResponse
    document_access: DocumentAccessResponse
    outcomes: dict = Field(default_factory=dict)


class AuditEntry(BaseModel):
    """One audit record. Note what is absent: the ``detail`` payload."""

    id: int
    created_at: str | None = None
    action: str
    outcome: str
    actor_role: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    request_id: str | None = None
    ip_address: str | None = None
    #: Which keys the stored detail contains - not their values.
    detail_keys: list[str] = Field(default_factory=list)


class AuditLogResponse(BaseModel):
    total: int
    returned: int
    offset: int
    entries: list[AuditEntry] = Field(default_factory=list)


class AuditActionsResponse(BaseModel):
    actions: list[str] = Field(default_factory=list)
