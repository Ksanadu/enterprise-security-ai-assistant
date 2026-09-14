"""Corpora shared between test files, so they cannot drift apart silently.

The evaluation set (a JSON fixture a reviewer can read) and the guard's own corpus both
hold injection attempts, and the same five phrasings appear in both - near-verbatim
rather than letter-for-letter, which is worse: a duplicated corpus drifts quietly, one
copy grows a case, the other keeps passing, and the two documents disagree about what
the product refuses.

The JSON stays the data source for the evaluation set. This module is the single place
that reads it, and `test_prompt_guard.py` asserts the two cannot diverge *behaviourally*:
every question the evaluation set expects to be refused must be refused by the guard
directly, not only by the pipeline that surrounds it.
"""

from __future__ import annotations

import json
from pathlib import Path

EVALUATION_SET = Path(__file__).resolve().parent / "data" / "evaluation_questions.json"


def evaluation_questions() -> list[dict[str, object]]:
    """Every question in the evaluation set, in file order."""
    data = json.loads(EVALUATION_SET.read_text(encoding="utf-8"))
    questions = data["questions"] if isinstance(data, dict) else data
    return list(questions)


def expected_blocked_questions() -> list[str]:
    """The questions the evaluation set expects the guard to refuse."""
    blocked: list[str] = []
    for question in evaluation_questions():
        expected = question.get("expected") or {}
        if isinstance(expected, dict) and expected.get("blocked"):
            blocked.append(str(question["question"]))
    return blocked
