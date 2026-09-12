"""Login attempt throttling and account lockout.

Two independent limits are applied, because they stop different attacks:

* **per account** - slows a distributed password-spray against one user, and is
  what actually protects the account;
* **per source address** - slows a single host trying many accounts.

Being locked out is deliberately *not* distinguishable from a wrong password by
response body or status code beyond the generic rate-limit error: an attacker
must not be able to use lockout as an account-enumeration oracle. The lockout
applies to the *credential check*, so a correct password during a lockout is
still refused - otherwise the lockout would be trivial to bypass.

The state is held in memory. It is correct for a single process and is honest
about its limits: behind multiple workers the effective limit is per process, and
restarting clears it. A shared store is the production answer and is noted rather
than pretended away.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from app.core.errors import RateLimitError
from app.security.rate_limit import SlidingWindowLimiter

logger = logging.getLogger(__name__)

#: Generic message: never reveal whether the account exists or is locked.
LOCKOUT_MESSAGE = "Too many failed sign-in attempts. Please wait and try again."


class LoginGuard:
    """Tracks failed sign-ins and refuses further attempts past the threshold."""

    def __init__(
        self,
        *,
        max_attempts: int = 5,
        window_seconds: float = 900.0,
        lockout_seconds: float = 900.0,
        ip_max_attempts: int = 20,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        self._account = SlidingWindowLimiter(
            limit=max_attempts, window_seconds=window_seconds, clock=clock
        )
        self._address = SlidingWindowLimiter(
            limit=max(ip_max_attempts, max_attempts), window_seconds=window_seconds, clock=clock
        )
        self._max_attempts = max_attempts
        self._lockout_seconds = lockout_seconds

    @property
    def max_attempts(self) -> int:
        return self._max_attempts

    def is_locked(self, *, email: str, ip_address: str | None) -> bool:
        """True when this account or address has exhausted its attempts."""
        return (
            self._account.remaining(self._account_key(email)) == 0
            or self._address.remaining(self._address_key(ip_address)) == 0
        )

    def record_failure(self, *, email: str, ip_address: str | None) -> None:
        """Count a failed attempt."""
        for limiter, key in (
            (self._account, self._account_key(email)),
            (self._address, self._address_key(ip_address)),
        ):
            try:
                limiter.check(key)
            except RateLimitError:
                # The limiter raises once the count is at the limit; here that
                # means "already counted", which is exactly the desired state.
                logger.info("login_attempt_limit_reached key=%s", key.split(":", 1)[0])

    def record_success(self, *, email: str, ip_address: str | None) -> None:
        """Clear the counters after a successful sign-in.

        Clearing the *account* counter is important: a user who mistypes a few
        times and then succeeds should not stay one failure away from a lockout.
        The address counter is left alone, so a host cannot reset its own budget
        by holding one valid credential.
        """
        self._account.reset(self._account_key(email))

    def lockout_seconds(self) -> float:
        return self._lockout_seconds

    @staticmethod
    def _account_key(email: str) -> str:
        # The email is normalised the same way the lookup normalises it, so
        # "Alice@Example.com" and "alice@example.com" share one counter.
        return f"account:{email.strip().lower()}"

    @staticmethod
    def _address_key(ip_address: str | None) -> str:
        return f"address:{ip_address or 'unknown'}"
