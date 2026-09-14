"""Knowledge base loader: reads Markdown documents with YAML front matter and
validates their security metadata.

The loader is intentionally strict. A document whose ``allowed_roles`` metadata
is missing, misspelled or empty is **rejected**, not silently published: a
metadata typo must never widen who can read a document.
"""

from __future__ import annotations

import datetime as dt
import logging
import re
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

import yaml

from app.core.enums import Role
from app.rag.documents import DocumentValidationError, KnowledgeDocument

logger = logging.getLogger(__name__)

DOCUMENT_ID_PATTERN = re.compile(r"^[A-Z]{2,6}-\d{3}$")
ALLOWED_CATEGORIES = frozenset({"policy", "sop", "standard", "guide", "faq"})

#: Front-matter keys the loader understands. Anything else is an error, so a
#: typo such as `allow_roles` cannot silently drop an access restriction.
ALLOWED_KEYS = frozenset(
    {
        "document_id",
        "title",
        "category",
        "allowed_roles",
        "version",
        "last_reviewed",
        "owner",
        "summary",
        "content",
    }
)

#: Front-matter keys every document must carry. `content` is required by
#: `PRODUCT_SPEC.md` §5 as well, but not as a front-matter key: it is the Markdown body
#: (or an inline `content` key), and it is validated by MIN_CONTENT_CHARS below rather
#: than by presence - so a document with the four keys above and an empty body is still
#: rejected. The distinction is recorded here because a reader comparing this tuple with
#: the specification would otherwise conclude that `content` is unchecked.
REQUIRED_KEYS = ("document_id", "title", "category", "allowed_roles")

MIN_CONTENT_CHARS = 200
FRONT_MATTER_DELIMITER = "---"


def split_front_matter(raw: str, source: str) -> tuple[dict[str, Any], str]:
    """Split a Markdown document into (front matter mapping, body)."""
    text = raw.lstrip("\ufeff")
    if not text.startswith(FRONT_MATTER_DELIMITER):
        raise DocumentValidationError(source, ["missing YAML front matter block"])

    # Locate the closing delimiter of the front matter block.
    lines = text.splitlines()
    closing = None
    for index in range(1, len(lines)):
        if lines[index].strip() == FRONT_MATTER_DELIMITER:
            closing = index
            break
    if closing is None:
        raise DocumentValidationError(source, ["unterminated YAML front matter block"])

    front_raw = "\n".join(lines[1:closing])
    body = "\n".join(lines[closing + 1 :]).strip()

    try:
        parsed = yaml.safe_load(front_raw)
    except yaml.YAMLError as exc:
        raise DocumentValidationError(source, [f"invalid YAML front matter: {exc}"]) from exc

    if parsed is None:
        parsed = {}
    if not isinstance(parsed, dict):
        raise DocumentValidationError(source, ["front matter must be a YAML mapping"])
    return parsed, body


def _parse_roles(value: Any, problems: list[str]) -> frozenset[Role]:
    if value is None:
        problems.append("'allowed_roles' is required; a document with no audience is invalid")
        return frozenset()

    if isinstance(value, str):
        raw_items = [item.strip() for item in value.split(",")]
    elif isinstance(value, list | tuple | set):
        raw_items = [str(item).strip() for item in value]
    else:
        problems.append("'allowed_roles' must be a list or a comma-separated string")
        return frozenset()

    raw_items = [item for item in raw_items if item]
    if not raw_items:
        problems.append("'allowed_roles' must not be empty")
        return frozenset()

    known = {role.value: role for role in Role}
    roles: set[Role] = set()
    for item in raw_items:
        role = known.get(item.lower())
        if role is None:
            problems.append(
                f"unknown role {item!r} in 'allowed_roles' (expected one of {sorted(known)})"
            )
            continue
        roles.add(role)
    return frozenset(roles)


def _parse_date(value: Any, problems: list[str]) -> dt.date | None:
    if value is None:
        return None
    if isinstance(value, dt.date):
        return value
    try:
        return dt.date.fromisoformat(str(value))
    except ValueError:
        problems.append(f"'last_reviewed' must be an ISO date (YYYY-MM-DD), got {value!r}")
        return None


def parse_document(raw: str, source: str = "<memory>") -> KnowledgeDocument:
    """Parse and validate one document.

    Raises:
        DocumentValidationError: when any metadata or content rule fails.
    """
    front, body = split_front_matter(raw, source)
    problems: list[str] = []

    unknown = sorted(set(front) - ALLOWED_KEYS)
    if unknown:
        problems.append(
            f"unknown front matter key(s) {unknown}; allowed keys are {sorted(ALLOWED_KEYS)}"
        )
    for key in REQUIRED_KEYS:
        if key not in front:
            problems.append(f"missing required front matter key {key!r}")

    document_id = str(front.get("document_id", "")).strip()
    if document_id and not DOCUMENT_ID_PATTERN.match(document_id):
        problems.append(f"'document_id' {document_id!r} must match {DOCUMENT_ID_PATTERN.pattern}")

    title = str(front.get("title", "")).strip()
    if not title:
        problems.append("'title' must not be empty")

    category = str(front.get("category", "")).strip().lower()
    if category and category not in ALLOWED_CATEGORIES:
        problems.append(f"'category' {category!r} is not one of {sorted(ALLOWED_CATEGORIES)}")

    roles = _parse_roles(front.get("allowed_roles"), problems)
    last_reviewed = _parse_date(front.get("last_reviewed"), problems)

    # An inline `content` key is supported for tests and for programmatic
    # documents; the Markdown body wins when it is present.
    inline_content = front.get("content")
    content = body if body else (str(inline_content).strip() if inline_content else "")
    if len(content) < MIN_CONTENT_CHARS:
        problems.append(
            f"content is too short ({len(content)} chars); minimum is {MIN_CONTENT_CHARS}"
        )

    if problems:
        raise DocumentValidationError(source, problems)

    return KnowledgeDocument(
        document_id=document_id,
        title=title,
        category=category,
        allowed_roles=roles,
        content=content,
        version=str(front["version"]) if front.get("version") is not None else None,
        last_reviewed=last_reviewed,
        owner=str(front["owner"]).strip() if front.get("owner") else None,
        summary=str(front["summary"]).strip() if front.get("summary") else None,
        source_path=source,
    )


def _is_document_file(path: Path) -> bool:
    return path.suffix.lower() in {".md", ".markdown"} and path.name.lower() != "readme.md"


def discover_document_files(kb_dir: Path) -> list[Path]:
    """Return every candidate document file, sorted for deterministic loading."""
    if not kb_dir.exists():
        return []
    return sorted(
        (path for path in kb_dir.rglob("*") if path.is_file() and _is_document_file(path)),
        key=lambda path: path.as_posix(),
    )


def load_documents(
    kb_dir: Path,
    *,
    strict: bool = True,
) -> tuple[list[KnowledgeDocument], list[DocumentValidationError]]:
    """Load every document in ``kb_dir``.

    Returns ``(documents, errors)``. When ``strict`` is true the first validation
    problem raises, because a knowledge base that silently drops documents is a
    security problem: the assistant's answers would change without any signal.
    """
    documents: list[KnowledgeDocument] = []
    errors: list[DocumentValidationError] = []
    seen_ids: dict[str, str] = {}

    for path in discover_document_files(kb_dir):
        source = path.name
        try:
            raw = path.read_text(encoding="utf-8")
            document = parse_document(raw, source)
        except DocumentValidationError as exc:
            if strict:
                raise
            errors.append(exc)
            logger.warning("knowledge_document_skipped source=%s problems=%s", source, exc.problems)
            continue

        previous = seen_ids.get(document.document_id)
        if previous is not None:
            duplicate = DocumentValidationError(
                source,
                [f"duplicate document_id {document.document_id!r} (already defined in {previous})"],
            )
            if strict:
                raise duplicate
            errors.append(duplicate)
            logger.warning("knowledge_document_skipped source=%s reason=duplicate_id", source)
            continue

        seen_ids[document.document_id] = source
        documents.append(document)

    logger.info(
        "knowledge_base_loaded dir=%s documents=%d errors=%d",
        kb_dir,
        len(documents),
        len(errors),
    )
    return documents, errors


def build_documents(items: Iterable[dict[str, Any]]) -> list[KnowledgeDocument]:
    """Build in-memory documents from mappings (used by tests and fixtures)."""
    documents: list[KnowledgeDocument] = []
    for item in items:
        payload = {**item}
        body = payload.pop("content", "")
        front = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True).strip()
        raw = f"{FRONT_MATTER_DELIMITER}\n{front}\n{FRONT_MATTER_DELIMITER}\n\n{body}"
        documents.append(parse_document(raw, str(payload.get("document_id", "<memory>"))))
    return documents


def summarise_audience(documents: Sequence[KnowledgeDocument]) -> dict[str, int]:
    """Count documents per role; used by the dashboard and by tests."""
    counts = {role.value: 0 for role in Role}
    for document in documents:
        for role in document.allowed_roles:
            counts[role.value] += 1
    return counts
