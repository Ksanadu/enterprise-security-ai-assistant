"""Retrieval quality tests against the specification's demo scenarios.

These are behavioural, not unit, tests: they assert that the *right document* is
retrieved for the four scenarios in PRODUCT_SPEC.md, for the role described
there. They are the contract Phase 5 (answer generation) builds on.

Phase 8 expands this into the full 30+ question evaluation set.
"""

from __future__ import annotations

import pytest

from app.core.enums import Role

# (scenario, role, question, document that must be retrieved)
DEMO_SCENARIOS = [
    (
        "A - security FAQ",
        Role.EMPLOYEE,
        "What are the company password requirements?",
        "KB-001",
    ),
    (
        "B - phishing email",
        Role.EMPLOYEE,
        "I received an email asking me to click a link and log in to my company "
        "mailbox again, is that normal?",
        "KB-002",
    ),
    (
        "C - suspected malware",
        Role.EMPLOYEE,
        "After I opened an email attachment my computer started showing strange " "pop-up windows.",
        "KB-010",
    ),
    (
        "D - VPN failure",
        Role.EMPLOYEE,
        "I suddenly cannot connect to the company VPN today.",
        "KB-012",
    ),
    (
        "D - VPN failure (service desk)",
        Role.IT,
        "A user reports the VPN client will not connect, what do I check?",
        "KB-005",
    ),
    (
        "C - malware (security team)",
        Role.SECURITY,
        "A malicious email attachment executed on an endpoint, how do we contain "
        "and eradicate the malware?",
        "KB-004",
    ),
    (
        "B - phishing investigation (security team)",
        Role.SECURITY,
        "We need to investigate a phishing campaign where a user submitted their " "credentials.",
        "KB-003",
    ),
    (
        "severity classification (service desk)",
        Role.IT,
        "How do we classify the severity of a security incident?",
        "KB-009",
    ),
    (
        "access review (service desk)",
        Role.IT,
        "What is the process for disabling accounts when someone leaves the company?",
        "KB-008",
    ),
    (
        "data handling",
        Role.EMPLOYEE,
        "Can I share a confidential document with an external partner by email?",
        "KB-007",
    ),
    (
        "security contacts",
        Role.EMPLOYEE,
        "Who do I contact outside business hours if I think my account is compromised?",
        "KB-011",
    ),
    (
        "remote work",
        Role.EMPLOYEE,
        "What are the rules for working from home on a public network?",
        "KB-006",
    ),
]


@pytest.mark.parametrize(
    ("scenario", "role", "question", "expected_document"),
    DEMO_SCENARIOS,
    ids=[scenario for scenario, *_ in DEMO_SCENARIOS],
)
def test_scenario_retrieves_the_expected_document(
    knowledge, scenario: str, role: Role, question: str, expected_document: str
) -> None:
    result = knowledge.search(question, role=role)
    retrieved = [match.chunk.document_id for match in result.matches]
    assert (
        expected_document in retrieved
    ), f"{scenario}: expected {expected_document} for role {role.value}, got {retrieved}"


def test_scenarios_never_retrieve_out_of_scope_documents(knowledge) -> None:
    """Every scenario, for every role, stays inside that role's scope."""
    from app.security.rbac import authorized_document_ids

    for _, role, question, _ in DEMO_SCENARIOS:
        allowed = authorized_document_ids(knowledge.index.documents, role)
        result = knowledge.search(question, role=role)
        for match in result.matches:
            assert match.chunk.document_id in allowed


def test_top_ranked_result_is_relevant_for_demo_scenarios(knowledge) -> None:
    """For the four headline scenarios the best match is the expected document."""
    headline = list(DEMO_SCENARIOS[:4])
    for _, role, question, expected_document in headline:
        result = knowledge.search(question, role=role)
        assert result.matches
        assert result.matches[0].chunk.document_id == expected_document, (
            f"top match for {question!r} was "
            f"{result.matches[0].chunk.document_id}, expected {expected_document}"
        )


def test_citations_are_usable(knowledge) -> None:
    result = knowledge.search("What are the company password requirements?", role=Role.EMPLOYEE)
    source = result.sources[0]
    assert source["document_id"] == "KB-001"
    assert source["title"] == "Password Policy"
    assert source["section"]
    assert source["snippet"]
    assert len(source["snippet"]) <= 321
    assert 0 < source["score"] <= 1


def test_context_is_grounded_and_labelled(knowledge) -> None:
    result = knowledge.search("What are the company password requirements?", role=Role.EMPLOYEE)
    context = result.context(max_chars=6000)
    assert "KB-001" in context
    assert "14 characters" in context
    assert context.index("KB-001") == context.find("[1]") + len("[1] ")


def test_context_stays_within_the_budget(knowledge, settings) -> None:
    result = knowledge.search("security policy procedures and guides", role=Role.SECURITY)
    assert len(result.context(max_chars=settings.retrieval_max_context_chars)) <= (
        settings.retrieval_max_context_chars
    )


def test_no_chunks_from_one_document_crowd_out_others(knowledge, settings) -> None:
    result = knowledge.search("security policy", role=Role.SECURITY)
    counts: dict[str, int] = {}
    for match in result.matches:
        counts[match.chunk.document_id] = counts.get(match.chunk.document_id, 0) + 1
    for document_id, count in counts.items():
        assert count <= settings.retrieval_max_per_document, document_id


def test_irrelevant_query_returns_nothing_rather_than_noise(knowledge) -> None:
    result = knowledge.search("what is the capital of France", role=Role.EMPLOYEE)
    assert len(result.matches) <= 1


def test_index_stats_are_consistent(knowledge) -> None:
    stats = knowledge.stats()
    assert stats["ready"] is True
    assert stats["document_count"] >= 10
    assert stats["chunk_count"] >= stats["document_count"]
    assert stats["embedding_provider"] == "tfidf"
    assert stats["documents_per_role"]["employee"] < stats["documents_per_role"]["security"]


def test_reindex_is_deterministic(knowledge) -> None:
    before = knowledge.search("password requirements", role=Role.EMPLOYEE)
    knowledge.reindex()
    after = knowledge.search("password requirements", role=Role.EMPLOYEE)
    assert [m.chunk.chunk_id for m in before.matches] == [m.chunk.chunk_id for m in after.matches]
    assert [m.score for m in before.matches] == pytest.approx([m.score for m in after.matches])


def test_cached_index_matches_a_fresh_build(knowledge, settings) -> None:
    """A restart that reuses cached vectors must rank identically to a rebuild."""
    from app.services.knowledge_service import KnowledgeService

    cached = knowledge.search("phishing response procedure", role=Role.EMPLOYEE)
    fresh = KnowledgeService(settings)
    fresh.startup()
    rebuilt = fresh.search("phishing response procedure", role=Role.EMPLOYEE)
    assert [m.chunk.chunk_id for m in cached.matches] == [m.chunk.chunk_id for m in rebuilt.matches]
    assert [m.score for m in cached.matches] == pytest.approx([m.score for m in rebuilt.matches])
