"""Deterministic Markdown chunking.

Chunking is content-addressed by position only - the same document always
produces the same chunk ids and the same text. That matters for two reasons:
retrieval results are reproducible in tests, and an audit record that names a
chunk id still refers to the same content later.
"""

from __future__ import annotations

import re

from app.rag.documents import Chunk, KnowledgeDocument

DEFAULT_MAX_CHARS = 900
DEFAULT_OVERLAP_CHARS = 120

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
#: A single oversized line (a long table row) must not break the size bound.
_HARD_SPLIT_CHARS = 1600


#: Bump when the chunking algorithm changes how text is divided. The value is
#: folded into the index fingerprint, because chunk boundaries decide what a
#: vector represents: a cached index built by an older chunker holds different
#: chunks for the same documents, and reusing it would silently serve vectors
#: that no longer match the text.
#:
#: 1 - original. The overlap prefix was prepended after the hard split, so a
#:     chunk could exceed _HARD_SPLIT_CHARS (the shipped knowledge base produced
#:     a 1640-character chunk against a 1600-character ceiling).
#: 2 - the ceiling is enforced; the overlap yields when it would breach it.
CHUNKER_VERSION = "2"


class ChunkingConfig:
    """Chunking parameters."""

    __slots__ = ("max_chars", "overlap_chars")

    def __init__(
        self, max_chars: int = DEFAULT_MAX_CHARS, overlap_chars: int = DEFAULT_OVERLAP_CHARS
    ):
        if max_chars < 100:
            raise ValueError("max_chars must be >= 100")
        if not 0 <= overlap_chars < max_chars:
            raise ValueError("overlap_chars must be >= 0 and smaller than max_chars")
        self.max_chars = max_chars
        self.overlap_chars = overlap_chars


def _iter_blocks(content: str) -> list[tuple[str, str]]:
    """Split the body into ``(section_title, block_text)`` units.

    Blocks are separated at headings and at blank lines, so a chunk never splits
    a paragraph in the middle.
    """
    blocks: list[tuple[str, str]] = []
    heading_stack: list[tuple[int, str]] = []
    buffer: list[str] = []

    def flush() -> None:
        if not buffer:
            return
        text = "\n".join(buffer).strip()
        buffer.clear()
        if not text:
            return
        # Section paths use U+203A (single right-pointing angle quotation mark)
        # as a deliberate typographic separator for display text.
        section = " › ".join(title for _, title in heading_stack if title) or "Overview"  # noqa: RUF001
        blocks.append((section, text))

    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        match = _HEADING_RE.match(line.strip())
        if match:
            flush()
            level = len(match.group(1))
            title = match.group(2).strip()
            while heading_stack and heading_stack[-1][0] >= level:
                heading_stack.pop()
            heading_stack.append((level, title))
            continue

        if not line.strip():
            flush()
            continue

        buffer.append(line)

    flush()
    return blocks


def _split_long_text(text: str, limit: int) -> list[str]:
    """Break a single oversized block into <= ``limit`` character pieces."""
    if len(text) <= limit:
        return [text]
    pieces: list[str] = []
    remaining = text
    while len(remaining) > limit:
        window = remaining[:limit]
        cut = window.rfind("\n")
        if cut < limit // 2:
            cut = window.rfind(" ")
        if cut < limit // 2:
            cut = limit
        pieces.append(remaining[:cut].rstrip())
        remaining = remaining[cut:].lstrip()
    if remaining:
        pieces.append(remaining.rstrip())
    return pieces


def chunk_document(
    document: KnowledgeDocument,
    config: ChunkingConfig | None = None,
) -> list[Chunk]:
    """Split one document into retrievable chunks.

    The parent's ``allowed_roles`` are copied onto every chunk so a permission
    check can never fall back to "no restriction".
    """
    config = config or ChunkingConfig()
    blocks = _iter_blocks(document.content)
    if not blocks:
        return []

    chunks: list[Chunk] = []
    current_text = ""
    current_section = blocks[0][0]

    def emit() -> None:
        nonlocal current_text
        text = current_text.strip()
        current_text = ""
        if not text:
            return
        chunks.append(
            Chunk(
                chunk_id=f"{document.document_id}#{len(chunks):03d}",
                document_id=document.document_id,
                title=document.title,
                category=document.category,
                allowed_roles=document.allowed_roles,
                section=current_section,
                text=text,
                position=len(chunks),
            )
        )

    for section, block in blocks:
        for piece in _split_long_text(block, _HARD_SPLIT_CHARS):
            candidate = f"{current_text}\n\n{piece}".strip() if current_text else piece
            if len(candidate) <= config.max_chars:
                if not current_text:
                    current_section = section
                current_text = candidate
                continue

            # The block does not fit: close the current chunk and carry a small
            # overlap into the next one so a question spanning the boundary still
            # matches.
            emit()
            overlap = ""
            if config.overlap_chars and chunks:
                tail = chunks[-1].text[-config.overlap_chars :].lstrip()
                # Mark the carried text so a reader can tell it is a continuation.
                if tail:
                    overlap = f"… {tail}"

            current_section = section
            current_text = f"{overlap}\n\n{piece}".strip() if overlap else piece

            # Keep the ceiling. `piece` is already <= _HARD_SPLIT_CHARS, but the
            # overlap prefix is added afterwards, which used to push an oversized
            # block 40-odd characters past the bound it was supposed to respect.
            # The overlap is a nicety; the bound is what keeps a single chunk from
            # dominating the prompt budget, so the overlap yields.
            if len(current_text) > _HARD_SPLIT_CHARS:
                current_text = piece

            if len(current_text) > config.max_chars:
                # A single block larger than the budget: emit as its own chunk.
                emit()
                current_section = section
                current_text = ""

    emit()
    return chunks


def chunk_documents(
    documents: list[KnowledgeDocument],
    config: ChunkingConfig | None = None,
) -> list[Chunk]:
    """Chunk every document, preserving document order."""
    config = config or ChunkingConfig()
    chunks: list[Chunk] = []
    for document in documents:
        chunks.extend(chunk_document(document, config))
    return chunks
