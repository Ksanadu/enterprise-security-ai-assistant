"""Redaction of credential-like material from stored text.

Users paste secrets into chat. A user reporting "I entered my password hunter2"
is doing exactly what they should, but the *value* must not then be copied into a
ticket body, a note, or an audit detail where it lives on for months and gets
read by more people than the original conversation.

This module extends the log redactor with a pattern for the conversational form -
a credential noun followed by a bare value - which the log patterns deliberately
do not cover, because log lines are usually ``key=value``.

The heuristic errs towards masking: a false positive costs a reader one
``***REDACTED***`` in a ticket, a false negative leaves a password on record.
"""

from __future__ import annotations

import re

from app.core.logging import redact as redact_assignments

#: Nouns that introduce a credential value in ordinary prose.
CREDENTIAL_NOUNS = (
    r"(?:password|passwd|passphrase|credential|secret|token|api[\s-]?key|otp|"
    r"one[\s-]?time\s+(?:code|password|pin)|recovery\s+code|verification\s+code|pin)"
)

#: "my password hunter2" / "the token abc123def" / "password: hunter2"
_PROSE_CREDENTIAL = re.compile(
    rf"(?i)\b(?P<noun>{CREDENTIAL_NOUNS})\b"
    r"(?P<sep>\s*(?:is|was|=|:)?\s*)"
    r"(?P<value>[A-Za-z0-9][A-Za-z0-9!@#$%^&*_\-.]{7,})"
)

#: A quoted value after a credential noun is the secret almost by definition, so
#: it is masked regardless of shape: `passphrase "correct horse battery staple"`.
_QUOTED_CREDENTIAL = re.compile(
    rf"(?i)\b(?P<noun>{CREDENTIAL_NOUNS})\b"
    r"(?P<sep>\s*(?:is|was|=|:)?\s*)"
    r"(?P<q>[\"'])(?P<value>[^\"']{3,})(?P=q)"
)

#: One-time codes are short, so the length rule above would miss them.
#: "otp 918273" and "recovery code 483920" must still be masked.
#: Note the single braces: this fragment is a plain raw string, not an f-string.
_SHORT_CODE = re.compile(
    rf"(?i)\b(?P<noun>{CREDENTIAL_NOUNS})\b"
    r"(?P<sep>\s*(?:is|was|=|:)?\s*)"
    r"(?P<value>\d{4,10})\b"
)

#: Values that are clearly not secrets, so masking them would only confuse the
#: reader: the words people use when describing the *concept*.
_NOT_A_SECRET = frozenset(
    """
    requirement requirements policy policies guideline guidelines manager management
    strength complexity rotation expiry expired changed changing reset resets
    authentication authorisation authorization protection compromised breached
    something anything anything nothing everything problem question incident
    """.split()
)

_REDACTED = "***REDACTED***"

#: Characters that make a token obviously secret-shaped.
_SECRET_SHAPE = re.compile(r"[!@#$%^&*_\-.]|\d")


def _looks_like_a_secret(value: str) -> bool:
    """A value worth masking: long, and either unusual or containing a digit."""
    lowered = value.lower()
    if lowered in _NOT_A_SECRET:
        return False
    if len(value) >= 20:
        return True
    return bool(_SECRET_SHAPE.search(value))


def redact_credentials(text: str) -> str:
    """Mask credential-like values in ``text``.

    Applies the assignment and quoted patterns used for logs, then the
    conversational patterns above. Quoted values and short numeric codes are
    masked unconditionally; unquoted prose values only when they look like a
    secret, so an ordinary sentence about password policy is left alone.
    """
    if not text:
        return text

    cleaned = redact_assignments(text)

    def _mask_unconditional(match: re.Match[str]) -> str:
        quote = match.groupdict().get("q") or ""
        return f"{match.group('noun')}{match.group('sep')}{quote}{_REDACTED}{quote}"

    def _mask_if_secret(match: re.Match[str]) -> str:
        value = match.group("value")
        if not _looks_like_a_secret(value):
            return match.group(0)
        if value.endswith("."):
            # Keep a sentence-ending period outside the mask.
            return f"{match.group('noun')}{match.group('sep')}{_REDACTED}."
        return f"{match.group('noun')}{match.group('sep')}{_REDACTED}"

    cleaned = _QUOTED_CREDENTIAL.sub(_mask_unconditional, cleaned)
    cleaned = _SHORT_CODE.sub(_mask_unconditional, cleaned)
    return _PROSE_CREDENTIAL.sub(_mask_if_secret, cleaned)
