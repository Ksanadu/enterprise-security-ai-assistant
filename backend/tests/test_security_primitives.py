"""Unit tests for security primitives: hashing, tokens and log redaction."""

from __future__ import annotations

import logging

import pytest

from app.core.logging import RedactionFilter, redact
from app.core.security import (
    constant_time_equals,
    hash_password,
    validate_password_strength,
    verify_password,
)

pytestmark = pytest.mark.security


class TestPasswordHashing:
    def test_hash_is_not_reversible_and_uses_bcrypt(self) -> None:
        digest = hash_password("Correct@Horse1", rounds=4)
        assert digest.startswith("$2b$")
        assert "Correct@Horse1" not in digest

    def test_same_password_yields_different_hashes(self) -> None:
        first = hash_password("Correct@Horse1", rounds=4)
        second = hash_password("Correct@Horse1", rounds=4)
        assert first != second  # per-hash salt

    def test_verify_accepts_correct_password(self) -> None:
        digest = hash_password("Correct@Horse1", rounds=4)
        assert verify_password("Correct@Horse1", digest) is True

    @pytest.mark.parametrize("candidate", ["correct@horse1", "Correct@Horse2", "", " "])
    def test_verify_rejects_wrong_password(self, candidate: str) -> None:
        digest = hash_password("Correct@Horse1", rounds=4)
        assert verify_password(candidate, digest) is False

    def test_verify_tolerates_malformed_hash(self) -> None:
        assert verify_password("anything", "not-a-bcrypt-hash") is False
        assert verify_password("anything", "") is False

    def test_empty_password_cannot_be_hashed(self) -> None:
        with pytest.raises(ValueError):
            hash_password("", rounds=4)

    def test_long_passwords_are_truncated_safely(self) -> None:
        """bcrypt's 72-byte limit must not cause a false positive."""
        base = "A1" + "x" * 80
        digest = hash_password(base, rounds=4)
        assert verify_password(base, digest) is True
        # A password sharing the first 72 bytes must be treated as identical,
        # which is why we truncate explicitly rather than silently.
        assert verify_password(base[:72], digest) is True

    def test_unicode_password_roundtrip(self) -> None:
        digest = hash_password("密码Password1", rounds=4)
        assert verify_password("密码Password1", digest) is True


class TestPasswordPolicy:
    @pytest.mark.parametrize(
        ("password", "expected"),
        [
            ("short1", "at least"),
            ("alllettersonly", "digit"),
            ("1234567890", "letter"),
        ],
    )
    def test_policy_violations_are_reported(self, password: str, expected: str) -> None:
        problems = validate_password_strength(password)
        assert any(expected in problem for problem in problems)

    def test_strong_password_passes(self) -> None:
        assert validate_password_strength("Str0ngEnough!") == []


class TestConstantTimeCompare:
    def test_equal_and_unequal(self) -> None:
        assert constant_time_equals("abc", "abc") is True
        assert constant_time_equals("abc", "abd") is False
        assert constant_time_equals("", "") is True


class TestRedaction:
    @pytest.mark.parametrize(
        "message",
        [
            "api_key=sk-abcdef1234567890",
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
            'password="hunter2"',
            "LLM_API_KEY: sk-proj-abcdefghijklmnop",
            "token=abc123def456",
        ],
    )
    def test_secrets_are_masked(self, message: str) -> None:
        cleaned = redact(message)
        assert "***REDACTED***" in cleaned
        for fragment in (
            "hunter2",
            "sk-abcdef1234567890",
            "sk-proj-abcdefghijklmnop",
            "abc123def456",
        ):
            assert fragment not in cleaned

    def test_ordinary_text_is_untouched(self) -> None:
        message = "user employee@example.com asked about the password policy"
        assert redact(message) == message

    def test_filter_rewrites_the_log_record(self) -> None:
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="call failed api_key=%s",
            args=("sk-live-abcdef123456",),
            exc_info=None,
        )
        assert RedactionFilter().filter(record) is True
        assert "sk-live-abcdef123456" not in record.getMessage()
