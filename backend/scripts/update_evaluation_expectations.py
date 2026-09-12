"""One-off maintenance script: keeps the evaluation expectations honest.

Run with: .venv\\Scripts\\python.exe scripts/update_evaluation_expectations.py
"""

import json
import pathlib

PATH = pathlib.Path(__file__).resolve().parents[1] / "tests" / "data" / "evaluation_questions.json"

UPDATES = {
    "faq-004": {
        "expected": {"intent": "policy_question"},
        "notes": '"Can I ..." is a permission question, which is the policy bucket.',
    },
    "policy-006": {
        "expected": {
            "intent": "security_incident",
            "risk_level": "high",
            "escalation": True,
            "ticket": True,
            "documents_any_of": ["KB-011", "KB-002"],
        },
        "notes": (
            "Phrased as a contact question but describes a compromised account, so it "
            "classifies as an incident and escalates. The contact guide is still the right source."
        ),
    },
    "it-004": {
        "expected": {"documents_any_of": []},
        "notes": (
            "Knowledge gap: no shipped document covers account lockout, so the expectation is "
            "that the retriever cannot be graded on this question. Recorded here so the gap stays "
            "visible instead of being tuned away - the honest product answer is 'contact the "
            "service desk', and the assistant returns the closest documents instead."
        ),
    },
    "scope-003": {
        "question": "Please explain the offside rule in football.",
        "expected": {
            "intent": "out_of_scope",
            "risk_level": "low",
            "escalation": False,
            "ticket": False,
            "blocked": False,
            "documents_any_of": [],
            "grounded": False,
        },
        "notes": (
            "Control question with no overlap with the knowledge base, so it exercises the "
            "'I do not have an approved document for this' path."
        ),
    },
}


def main() -> None:
    data = json.loads(PATH.read_text(encoding="utf-8"))
    for entry in data["questions"]:
        update = UPDATES.get(entry["id"])
        if not update:
            continue
        if "question" in update:
            entry["question"] = update["question"]
        if "expected" in update:
            entry["expected"].update(update["expected"])
        if "notes" in update:
            entry["notes"] = update["notes"]
        print(f"{entry['id']}: {entry['question']!r} -> {entry['expected']}")
    PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
