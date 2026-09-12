"""Knowledge base API schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DocumentMetadata(BaseModel):
    document_id: str
    title: str
    category: str
    allowed_roles: list[str]
    version: str | None = None
    owner: str | None = None
    summary: str | None = None
    last_reviewed: str | None = None


class DocumentDetail(DocumentMetadata):
    content: str


class DocumentListResponse(BaseModel):
    """Documents visible to the calling role.

    The list is already filtered by RBAC; the client is not told how many
    documents exist that it may not see.
    """

    role: str
    count: int
    categories: dict[str, int] = Field(default_factory=dict)
    documents: list[DocumentMetadata] = Field(default_factory=list)


class SourceReference(BaseModel):
    document_id: str
    title: str
    category: str
    section: str
    score: float
    snippet: str


class SearchRequest(BaseModel):
    query: str = Field(min_length=2, max_length=2000)
    top_k: int | None = Field(default=None, ge=1, le=20)


class SearchResponse(BaseModel):
    query: str
    role: str
    result_count: int
    results: list[SourceReference] = Field(default_factory=list)
    #: True when nothing in the caller's scope matched above the threshold.
    no_authorized_match: bool = False


class RoleScopeResponse(BaseModel):
    roles: list[dict] = Field(default_factory=list)


class IndexStatsResponse(BaseModel):
    """Index health, for any authenticated role.

    Counts and provider names only. The knowledge base's **path on disk** is
    deliberately absent: it is a server detail no client needs, and it discloses
    the operating system, the account the service runs as and the deployment
    layout to anyone who can sign in.
    """

    ready: bool
    document_count: int
    chunk_count: int
    embedding_dimension: int
    embedding_provider: str
    vector_store: str
    documents_per_role: dict[str, int] = Field(default_factory=dict)
    reindexed: bool = False
