"""Incident shape: a cheap, deterministic backstop against silent drops.

The classification rules are a finite list, and a finite list cannot cover every way
a person describes a breach. When a phrasing falls outside it the turn used to become
`out_of_scope` with a `low` default, which meant **no answer source, no ticket and no
human** - the worst outcome the product can produce, and one that was measured eight
times in a row with phrasings nobody had written a rule for ("our database is being
sold on the dark web", "an attacker has our source code", "we are being blackmailed
after a leak").

This module does not try to be a classifier. It answers one much easier question: does
this message *pair an incident noun with a compromise verb*? If it does, the pipeline
must not behave as though nothing was reported:

* retrieval happens even when the intent classifier said `out_of_scope`, because a
  report is not an off-topic question;
* the risk assessment is floored at ``medium`` and carries the ``incident_shape``
  signal;
* the workflow tracks the report and asks the decisive question, instead of deciding
  there is no situation to track.

Requiring *both* halves is what keeps it precise: a noun alone is a topic ("what is the
malware response procedure?"), a verb alone is ordinary language ("I lost my keys").
The failure mode it is designed against is under-reporting, so it errs toward tracking
something that turns out to be benign - which the medium tier then resolves by asking.
"""

from __future__ import annotations

import dataclasses
import re

__all__ = ["SHAPE_SIGNAL", "IncidentShape", "detect_incident_shape"]

#: Label carried on the risk signal, so the workflow and the audit trail can see that
#: this assessment came from the backstop rather than from a specific rule.
SHAPE_SIGNAL = "incident_shape"

#: Things that can be lost, sold, stolen or exposed.
_INCIDENT_NOUN = (
    r"(?:data|database|datasets?|records?|files?|documents?|backups?|source\s+code|"
    r"customer\s+(?:list|data|records)|customers?|client\s+(?:list|data)|payroll|"
    r"mailbox|e-?mail|account|logins?|sign[\s-]?in\s+details?|credentials?|passwords?|"
    r"api\s+keys?|access\s+tokens?|"
    r"systems?|servers?|endpoints?|workstations?|laptops?|devices?)"
)

#: What happened to them. Deliberately broad in the *reporting* direction: an incident
#: described in an unusual way should still be tracked.
_COMPROMISE_VERB = (
    r"(?:sold|selling|sale|stolen|stole|taken|take|took|leaked|leaking|exfiltrat\w*|"
    r"blackmail\w*|extort\w*|ransom\w*|published|posted|dumped|uploaded|exported|"
    r"downloaded|copied|deleted|dropped|wiped|overwrote|encrypted|locked|"
    r"breached|compromised|hacked|accessed|exposed|disclosed|missing|lost|gone|"
    r"walked\s+out\s+with|left\s+with|took\s+with|"
    r"(?:wrong|incorrect|mistaken)\s+(?:address|recipient|person|party|domain)|"
    r"held\s+to\s+ransom|appeared\s+(?:online|publicly|on)|for\s+sale)"
)

#: noun ... verb, and verb ... noun. The window is short because the two halves have to
#: belong to the same clause; a longer reach starts matching unrelated sentences.
_FORWARD = re.compile(rf"\b{_INCIDENT_NOUN}\b[\s\S]{{0,40}}?\b{_COMPROMISE_VERB}\b", re.IGNORECASE)
_BACKWARD = re.compile(rf"\b{_COMPROMISE_VERB}\b[\s\S]{{0,40}}?\b{_INCIDENT_NOUN}\b", re.IGNORECASE)

#: Extortion is an incident shape on its own: "we are being blackmailed after a leak"
#: pairs no noun with a verb from the lists above, and it is about as reportable as a
#: message gets.
_EXTORTION = re.compile(
    r"\b(?:blackmail\w*|extort\w*|held\s+to\s+ransom|ransom\s+note|demanding\s+payment)\b",
    re.IGNORECASE,
)

#: An actor plus a compromise verb is an incident shape on its own: "an attacker has our
#: source code" reads as noun-verb only by accident of word order.
_ACTOR = re.compile(
    r"\b(?:attacker|attackers|hacker|hackers|intruder|thief|thieves|criminal|"
    r"cybercriminal|outsider|former\s+employee|ex-employee|insider)\b"
    r"[\s\S]{0,40}?"
    r"\b(?:has|have|had|got|took|stole|stolen|walked|left|accessed|downloaded|exported|"
    r"leaked|sold|demanding|demands|asking|wants|holds|holding)\b",
    re.IGNORECASE,
)

#: Questions about the topic rather than reports of an event. "What is the malware
#: response procedure?" pairs a noun with nothing, but "how do I report a suspicious
#: email?" and "what is the policy on encrypting USB drives?" are how a *question*
#: looks, and a shape match inside one must not trigger the backstop.
_QUESTION_SHAPE = re.compile(
    r"^\s*(?:what|which|who|where|when|why|how|is|are|does|do|can|should|may)\b",
    re.IGNORECASE,
)

#: Words that make the pairing hypothetical or defensive rather than a report.
_NOT_A_REPORT = re.compile(
    r"\b(?:policy|procedure|sop|guideline|standard|template|checklist|training|"
    r"awareness|steps?\s+to|how\s+to|what\s+(?:is|are)|if\s+(?:i|we|someone)\s+(?:lose|lost)|"
    r"to\s+prevent|prevention|protect\s+against)\b"
    # A lockout is a support request, not a breach: "I am locked out of my account after
    # too many failed attempts" pairs the noun `account` with the verb `locked` and was
    # measured being lifted to medium by the backstop, where KB-009 has it as a routine
    # IT matter.
    r"|\block(?:ed)?\s+out\b",
    re.IGNORECASE,
)


#: Mitigating evidence the risk classifier already honours for a lost device: KB-009
#: reduces "lost device, encrypted, remote wipe succeeded" to S4. The backstop must not
#: track what the policy says needs no tracking, so the same evidence is honoured here.
_MITIGATED_LOSS = re.compile(
    r"\b(?:encrypted|bitlocker|filevault)\b[\s\S]{0,60}?\b(?:wiped|wipe\s+succeeded|erased|remote\s+wipe)\b"
    r"|\b(?:wiped|wipe\s+succeeded|erased)\b[\s\S]{0,60}?\b(?:encrypted|bitlocker|filevault)\b",
    re.IGNORECASE,
)


@dataclasses.dataclass(frozen=True, slots=True)
class IncidentShape:
    """Which words paired up, kept for the audit trail and the ticket description."""

    noun: str
    verb: str
    evidence: str

    def audit_detail(self) -> dict[str, str]:
        return {"noun": self.noun, "verb": self.verb, "evidence": self.evidence}


def detect_incident_shape(text: str) -> IncidentShape | None:
    """Return the incident shape in ``text``, or ``None`` when there is not one."""
    if not text or not text.strip():
        return None
    if _NOT_A_REPORT.search(text):
        # A question *about* incidents is not a report of one. This is the same
        # distinction that keeps "what is the malware response procedure?" at low.
        return None
    if _MITIGATED_LOSS.search(text):
        # KB-009 says a lost device that was encrypted and remotely wiped is S4, and the
        # risk classifier already declines to escalate it. Tracking it here would
        # contradict the published policy in the other direction.
        return None

    for pattern in (_FORWARD, _BACKWARD):
        match = pattern.search(text)
        if match is None:
            continue
        fragment = match.group(0)
        noun_match = _first(_INCIDENT_NOUN, fragment)
        verb_match = _first(_COMPROMISE_VERB, fragment)
        if noun_match is None or verb_match is None:
            continue
        return IncidentShape(
            noun=noun_match.lower(),
            verb=verb_match.lower(),
            evidence=" ".join(fragment.split())[:120],
        )

    extortion = _EXTORTION.search(text)
    if extortion is not None:
        return IncidentShape(
            noun="extortion",
            verb=extortion.group(0).lower(),
            evidence=" ".join(extortion.group(0).split())[:120],
        )

    actor = _ACTOR.search(text)
    if actor is not None:
        return IncidentShape(
            noun="actor",
            verb="compromise",
            evidence=" ".join(actor.group(0).split())[:120],
        )

    # Nothing paired up. A question phrased about incidents is a question.
    return None


def _first(pattern: str, fragment: str) -> str | None:
    found = re.search(pattern, fragment, re.IGNORECASE)
    return found.group(0) if found else None
