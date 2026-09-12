"""Knowledge base loader tests: the metadata contract that scopes retrieval."""

from __future__ import annotations

import pytest

from app.core.enums import Role
from app.rag.documents import DocumentValidationError
from app.rag.loader import (
    ALLOWED_CATEGORIES,
    MIN_CONTENT_CHARS,
    discover_document_files,
    load_documents,
    parse_document,
    split_front_matter,
    summarise_audience,
)

VALID_BODY = "This is a sufficiently long body of documentation. " * 8

VALID_DOCUMENT = f"""---
document_id: KB-100
title: Example Policy
category: policy
allowed_roles:
  - employee
  - security
version: "1.0"
last_reviewed: "2024-05-01"
owner: Example Owner
summary: An example document used by tests.
---

# Example Policy

{VALID_BODY}
"""


class TestFrontMatter:
    def test_splits_metadata_and_body(self) -> None:
        front, body = split_front_matter(VALID_DOCUMENT, "example.md")
        assert front["document_id"] == "KB-100"
        assert body.startswith("# Example Policy")

    def test_missing_front_matter_is_rejected(self) -> None:
        with pytest.raises(DocumentValidationError, match="missing YAML front matter"):
            split_front_matter("# Just a heading\n\ntext", "example.md")

    def test_unterminated_front_matter_is_rejected(self) -> None:
        raw = "---\ndocument_id: KB-100\ntitle: Broken\n"
        with pytest.raises(DocumentValidationError, match="unterminated"):
            split_front_matter(raw, "example.md")

    def test_invalid_yaml_is_rejected(self) -> None:
        raw = "---\ndocument_id: [unclosed\n---\n\nbody"
        with pytest.raises(DocumentValidationError, match="invalid YAML"):
            split_front_matter(raw, "example.md")

    def test_non_mapping_front_matter_is_rejected(self) -> None:
        raw = "---\n- just\n- a list\n---\n\nbody"
        with pytest.raises(DocumentValidationError, match="must be a YAML mapping"):
            split_front_matter(raw, "example.md")


class TestValidation:
    def test_valid_document_parses(self) -> None:
        document = parse_document(VALID_DOCUMENT, "example.md")
        assert document.document_id == "KB-100"
        assert document.title == "Example Policy"
        assert document.category == "policy"
        assert document.allowed_roles == frozenset({Role.EMPLOYEE, Role.SECURITY})
        assert document.version == "1.0"
        assert document.last_reviewed is not None
        assert document.owner == "Example Owner"
        assert document.summary == "An example document used by tests."

    def test_all_problems_are_reported_at_once(self) -> None:
        raw = "---\ntitle: ''\ncategory: nonsense\nallowed_roles: []\n---\n\nshort"
        with pytest.raises(DocumentValidationError) as excinfo:
            parse_document(raw, "bad.md")
        problems = excinfo.value.problems
        assert len(problems) >= 4
        assert any("document_id" in problem for problem in problems)
        assert any("category" in problem for problem in problems)
        assert any("allowed_roles" in problem for problem in problems)
        assert any("too short" in problem for problem in problems)

    @pytest.mark.parametrize(
        "document_id",
        ["kb-100", "KB-1", "100", "KB-1000", "TOOLONGID-100", "KB-10A", "KB100"],
    )
    def test_document_id_format_is_enforced(self, document_id: str) -> None:
        raw = VALID_DOCUMENT.replace("KB-100", document_id)
        with pytest.raises(DocumentValidationError, match="document_id"):
            parse_document(raw, "example.md")

    def test_any_short_uppercase_prefix_is_accepted(self) -> None:
        """The pattern is intentionally generic (KB, SEC, IT, ...) - only the
        shape matters, and uniqueness is enforced separately."""
        raw = VALID_DOCUMENT.replace("KB-100", "SEC-100")
        assert parse_document(raw, "example.md").document_id == "SEC-100"

    @pytest.mark.parametrize("category", sorted(ALLOWED_CATEGORIES))
    def test_known_categories_are_accepted(self, category: str) -> None:
        raw = VALID_DOCUMENT.replace("category: policy", f"category: {category}")
        assert parse_document(raw, "example.md").category == category

    def test_unknown_category_is_rejected(self) -> None:
        raw = VALID_DOCUMENT.replace("category: policy", "category: whitepaper")
        with pytest.raises(DocumentValidationError, match="category"):
            parse_document(raw, "example.md")

    def test_roles_accept_a_comma_separated_string(self) -> None:
        raw = VALID_DOCUMENT.replace(
            "allowed_roles:\n  - employee\n  - security", "allowed_roles: employee, security"
        )
        assert parse_document(raw, "example.md").allowed_roles == frozenset(
            {Role.EMPLOYEE, Role.SECURITY}
        )

    def test_roles_are_case_insensitive(self) -> None:
        raw = VALID_DOCUMENT.replace("  - employee", "  - EMPLOYEE")
        assert Role.EMPLOYEE in parse_document(raw, "example.md").allowed_roles

    def test_invalid_date_is_reported(self) -> None:
        raw = VALID_DOCUMENT.replace('"2024-05-01"', '"last Tuesday"')
        with pytest.raises(DocumentValidationError, match="last_reviewed"):
            parse_document(raw, "example.md")

    def test_minimum_content_length_is_enforced(self) -> None:
        raw = VALID_DOCUMENT.replace(VALID_BODY, "too short")
        with pytest.raises(DocumentValidationError, match="too short"):
            parse_document(raw, "example.md")
        assert MIN_CONTENT_CHARS >= 100

    def test_optional_metadata_may_be_absent(self) -> None:
        raw = f"""---
document_id: KB-101
title: Minimal
category: faq
allowed_roles: [employee]
---

{VALID_BODY}
"""
        document = parse_document(raw, "minimal.md")
        assert document.version is None
        assert document.last_reviewed is None
        assert document.owner is None


class TestShippedKnowledgeBase:
    def test_every_shipped_document_loads(self, kb_dir) -> None:
        documents, errors = load_documents(kb_dir, strict=True)
        assert errors == []
        assert len(documents) >= 10, "the specification requires at least 10 documents"

    def test_required_topics_are_present(self, kb_dir) -> None:
        documents, _ = load_documents(kb_dir)
        titles = {document.title.lower() for document in documents}
        required = [
            "password policy",
            "phishing response sop",
            "malware incident response sop",
            "vpn troubleshooting sop",
            "remote work security policy",
            "data leakage prevention policy",
            "access control policy",
            "incident severity classification",
            "endpoint security guide",
            "security contact guide",
        ]
        for topic in required:
            assert topic in titles, f"missing required document: {topic}"

    def test_document_ids_are_unique_and_sorted(self, kb_dir) -> None:
        documents, _ = load_documents(kb_dir)
        ids = [document.document_id for document in documents]
        assert len(ids) == len(set(ids))
        assert ids == sorted(ids)

    def test_every_document_declares_the_full_metadata_contract(self, kb_dir) -> None:
        documents, _ = load_documents(kb_dir)
        for document in documents:
            assert document.document_id
            assert document.title
            assert document.category in ALLOWED_CATEGORIES
            assert document.allowed_roles
            assert len(document.content) >= MIN_CONTENT_CHARS

    def test_readme_is_not_loaded_as_a_document(self, kb_dir) -> None:
        names = {path.name for path in discover_document_files(kb_dir)}
        assert "README.md" not in names

    def test_audience_summary_matches_the_policy_matrix(self, kb_dir) -> None:
        documents, _ = load_documents(kb_dir)
        summary = summarise_audience(documents)
        assert summary["employee"] == 7
        assert summary["it"] == 10
        assert summary["security"] == len(documents)

    def test_duplicate_document_id_is_rejected(self, tmp_path) -> None:
        (tmp_path / "a.md").write_text(VALID_DOCUMENT, encoding="utf-8")
        (tmp_path / "b.md").write_text(VALID_DOCUMENT, encoding="utf-8")
        with pytest.raises(DocumentValidationError, match="duplicate document_id"):
            load_documents(tmp_path, strict=True)

    def test_non_strict_mode_reports_instead_of_raising(self, tmp_path) -> None:
        (tmp_path / "good.md").write_text(VALID_DOCUMENT, encoding="utf-8")
        (tmp_path / "bad.md").write_text("---\ntitle: broken\n---\n\nshort", encoding="utf-8")
        documents, errors = load_documents(tmp_path, strict=False)
        assert len(documents) == 1
        assert len(errors) == 1

    def test_missing_directory_yields_no_documents(self, tmp_path) -> None:
        documents, errors = load_documents(tmp_path / "does-not-exist", strict=True)
        assert documents == []
        assert errors == []
