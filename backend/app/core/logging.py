"""Logging configuration with request correlation and secret redaction.

Audit-relevant events are logged as structured records. A redaction filter makes
sure obvious secrets (API keys, bearer tokens, passwords) never reach the log
stream by accident.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from contextvars import ContextVar
from typing import Any

# Correlation id for the current request/task; set by middleware.
request_id_var: ContextVar[str] = ContextVar("request_id", default="-")

_REDACTED = "***REDACTED***"

# Sensitive key names. A value only counts as a secret when it is actually
# assigned (`key=value`, `key: value`) or quoted (`password "hunter2"`), so
# ordinary prose such as "the password policy" is left alone.
# Regex of secret *key names* (not a credential itself).
_SECRET_NAMES = r"(?:api[_-]?key|apikey|authorization|password|passwd|secret|token|bearer)"  # noqa: S105
# key = value  /  key: "value"
_SECRET_ASSIGNMENT = re.compile(
    rf"(?i)\b(?P<key>{_SECRET_NAMES})\b(?P<sep>\s*[:=]\s*)(?P<q>[\"']?)(?P<val>[^\s\"',;)]+)(?P=q)"
)
# key "quoted value"
_SECRET_QUOTED = re.compile(
    rf"(?i)\b(?P<key>{_SECRET_NAMES})\b(?P<sep>\s+)(?P<q>[\"'])(?P<val>[^\"']+)(?P=q)"
)
_BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+")
_SK_PATTERN = re.compile(r"\bsk-[A-Za-z0-9._\-]{8,}")


def _mask(match: re.Match[str]) -> str:
    quote = match.group("q")
    return f"{match.group('key')}{match.group('sep')}{quote}{_REDACTED}{quote}"


def redact(text: str) -> str:
    """Return ``text`` with recognised secret material masked."""
    if not text:
        return text
    text = _BEARER_PATTERN.sub(f"Bearer {_REDACTED}", text)
    text = _SK_PATTERN.sub(_REDACTED, text)
    text = _SECRET_QUOTED.sub(_mask, text)
    text = _SECRET_ASSIGNMENT.sub(_mask, text)
    return text


class RedactionFilter(logging.Filter):
    """Mask secrets in the fully formatted log message."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        cleaned = redact(message)
        if cleaned != message:
            record.msg = cleaned
            record.args = ()
        return True


class TextFormatter(logging.Formatter):
    """Human-readable single-line format including the request id."""

    def format(self, record: logging.LogRecord) -> str:
        record.request_id = request_id_var.get()
        return super().format(record)


class JsonFormatter(logging.Formatter):
    """One JSON object per line, suitable for log shipping."""

    _RESERVED = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()) | {
        "request_id",
        "message",
        "asctime",
        "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "request_id": request_id_var.get(),
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: str = "INFO", fmt: str = "text") -> None:
    """Install handlers on the root logger. Idempotent."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))

    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(stream=sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            TextFormatter(
                fmt="%(asctime)s %(levelname)-8s [%(request_id)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
    handler.addFilter(RedactionFilter())
    root.addHandler(handler)

    # Access logs from uvicorn duplicate our own request logging.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger."""
    return logging.getLogger(name)
