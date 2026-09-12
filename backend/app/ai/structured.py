"""Structured output handling.

Model output is untrusted text. Everything that comes back from a language model
is parsed into a validated Pydantic object here, and a parse failure is a
*handled* outcome rather than an exception: the caller falls back to the
deterministic path instead of failing the request.

Nothing in this module decides access, risk or escalation on the strength of
model output alone - it only converts text into a typed structure that backend
code then evaluates.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)

TModel = TypeVar("TModel", bound=BaseModel)

#: ```json ... ``` or ``` ... ``` fences around the payload.
_FENCE = re.compile(r"```(?:json|JSON)?\s*(?P<body>.*?)```", re.DOTALL)

#: Deepest bracket nesting accepted in a model response.
#:
#: This is not a style preference. `json.loads` decodes recursively, so a
#: response containing a few thousand nested brackets raises `RecursionError` -
#: which is a `RuntimeError`, not a `JSONDecodeError`, and therefore escapes every
#: handler on this path and turns a bad model response into a failed request.
#: Nothing this application asks a model for nests more than two or three levels,
#: so the limit is generous and the check is a cheap character scan.
MAX_JSON_DEPTH = 32


def _nesting_exceeds(text: str, limit: int) -> bool:
    """True when brackets nest deeper than ``limit``, ignoring brackets in strings."""
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            if depth > limit:
                return True
        elif char in "}]":
            depth -= 1
    return False


def strip_code_fences(text: str) -> str:
    """Remove a Markdown code fence if the model wrapped its JSON in one."""
    match = _FENCE.search(text)
    if match:
        return match.group("body").strip()
    return text.strip()


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Find and parse the first JSON object in ``text``.

    Models add prose before or after the payload, so the first balanced
    ``{...}`` block is extracted rather than assuming the whole response is JSON.
    Returns ``None`` when nothing parseable is present.
    """
    if not text or not text.strip():
        return None

    candidate = strip_code_fences(text)

    # Reject pathological nesting before handing the text to a recursive decoder.
    if _nesting_exceeds(candidate, MAX_JSON_DEPTH):
        logger.warning(
            "structured_output_rejected reason=nesting_depth chars=%d", len(candidate)
        )
        return None

    try:
        parsed = json.loads(candidate)
    except (json.JSONDecodeError, RecursionError):
        # RecursionError is included defensively: the depth check above should
        # make it unreachable, and a decoder that still finds a way to recurse
        # must not be able to fail the request.
        parsed = None
    if isinstance(parsed, dict):
        return parsed

    # Fall back to scanning for a balanced object. String literals are tracked so
    # a brace inside a quoted value does not end the scan early.
    start = candidate.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(candidate)):
            char = candidate[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    block = candidate[start : index + 1]
                    try:
                        parsed = json.loads(block)
                    except (json.JSONDecodeError, RecursionError):
                        break
                    if isinstance(parsed, dict):
                        return parsed
                    break
        start = candidate.find("{", start + 1)

    return None


def parse_model(
    text: str,
    model: type[TModel],
    *,
    context: str = "model output",
) -> TModel | None:
    """Parse and validate ``text`` into ``model``, or return ``None``.

    Validation failures are logged with the field names only: the payload itself
    can quote user content and must not be copied into the log stream.
    """
    payload = extract_json_object(text)
    if payload is None:
        logger.info("structured_output_unparsable context=%s chars=%d", context, len(text or ""))
        return None
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        fields = [".".join(str(part) for part in error.get("loc", ())) for error in exc.errors()]
        logger.info("structured_output_invalid context=%s fields=%s", context, fields)
        return None
    except RecursionError:
        # Belt and braces: validation also walks the structure recursively.
        logger.warning("structured_output_invalid context=%s reason=depth", context)
        return None


def clamp_confidence(value: Any, default: float = 0.0) -> float:
    """Coerce a model-reported confidence into ``[0, 1]``."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if number != number or number in {float("inf"), float("-inf")}:  # NaN / infinity
        return default
    return min(1.0, max(0.0, number))
