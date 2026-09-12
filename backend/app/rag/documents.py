"""Knowledge base data model.

A :class:`KnowledgeDocument` is a full document with its security metadata. A
:class:`Chunk` is a retrievable slice of one document. Chunks carry a **copy** of
the parent's ``allowed_roles`` so that a permission check never depends on a
lookup that could fail open.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
from typing import Any

from app.core.enums import Role


class DocumentValidationError(ValueError):
    """Raised when a knowledge base document has invalid metadata or content.

    The message lists every problem found, so one run reports all of them.
    """

    def __init__(self, source: str, problems: list[str]) -> None:
        self.source = source
        self.problems = tuple(problems)
        detail = "; ".join(problems)
        super().__init__(f"{source}: {detail}")


@dataclasses.dataclass(frozen=True, slots=True)
class KnowledgeDocument:
    """A knowledge base document plus the metadata that scopes it."""

    document_id: str
    title: str
    category: str
    allowed_roles: frozenset[Role]
    content: str
    version: str | None = None
    last_reviewed: dt.date | None = None
    owner: str | None = None
    summary: str | None = None
    source_path: str | None = None

    @property
    def allowed_role_values(self) -> list[str]:
        """Role values in a stable, display-friendly order."""
        return sorted(role.value for role in self.allowed_roles)

    def permits(self, role: Role) -> bool:
        return role in self.allowed_roles

    def to_metadata(self) -> dict[str, Any]:
        """Metadata safe to expose to a client that is already authorized."""
        return {
            "document_id": self.document_id,
            "title": self.title,
            "category": self.category,
            "allowed_roles": self.allowed_role_values,
            "version": self.version,
            "owner": self.owner,
            "summary": self.summary,
            "last_reviewed": self.last_reviewed.isoformat() if self.last_reviewed else None,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class Chunk:
    """A retrievable slice of a document."""

    chunk_id: str
    document_id: str
    title: str
    category: str
    #: Copied from the parent document. Never resolved lazily.
    allowed_roles: frozenset[Role]
    section: str
    text: str
    position: int

    def permits(self, role: Role) -> bool:
        return role in self.allowed_roles

    def searchable_text(self) -> str:
        """The representation that gets embedded.

        The title and section are included (and the title repeated, which
        doubles its term frequency) because a document titled "VPN
        Troubleshooting SOP" is far more likely to answer a VPN question than a
        general policy that merely mentions VPN many times. Without this boost,
        a long policy document outranks the specific procedure.

        ``text`` remains the display/context representation: what the user sees
        is never the synthetic search string.
        """
        return f"{self.title}\n{self.title}\n{self.section}\n{self.text}"


@dataclasses.dataclass(frozen=True, slots=True)
class ScoredChunk:
    """A chunk plus its similarity score for one query."""

    chunk: Chunk
    score: float

    def to_reference(self) -> dict[str, Any]:
        """Citation payload returned to the user and stored with the message."""
        return {
            "document_id": self.chunk.document_id,
            "title": self.chunk.title,
            "category": self.chunk.category,
            "section": self.chunk.section,
            "score": round(self.score, 4),
            "snippet": _shorten(self.chunk.text, 320),
        }


def _shorten(text: str, limit: int) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1].rstrip() + "…"
