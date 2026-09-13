"""In-process rate limiting.

A chat message triggers an embedding, a vector search and a model call, so an
unthrottled endpoint is both a cost and a denial-of-service risk.

The limiter is deliberately simple - a sliding window per key, held in memory.
It is correct for a single process and honest about its limits: behind multiple
workers or replicas the effective limit is per process. A shared store (Redis)
is the production answer and is noted as such rather than pretended away.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable

from app.core.errors import RateLimitError


class SlidingWindowLimiter:
    """Allow at most ``limit`` events per ``window_seconds`` for each key."""

    def __init__(
        self,
        *,
        limit: int,
        window_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 10_000,
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        self._limit = limit
        self._window = window_seconds
        self._clock = clock
        self._max_keys = max_keys
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    @property
    def limit(self) -> int:
        return self._limit

    def _prune(self, key: str, now: float) -> deque[float]:
        events = self._events.setdefault(key, deque())
        cutoff = now - self._window
        while events and events[0] <= cutoff:
            events.popleft()
        return events

    def check(self, key: str) -> None:
        """Record an event for ``key``, raising when the limit is exceeded."""
        with self._lock:
            now = self._clock()
            events = self._prune(key, now)
            if len(events) >= self._limit:
                retry_after = max(1, int(self._window - (now - events[0])) + 1)
                raise RateLimitError(
                    # Deliberately not "another message": the same limiter now covers
                    # the retrieval endpoint too, which sends no message.
                    "Too many requests. Please wait before trying again.",
                    details={"retry_after_seconds": retry_after, "limit": self._limit},
                )
            events.append(now)

            # Bound memory: drop the least recently used keys when the table
            # grows past the cap. An attacker cannot exhaust memory by using
            # many keys.
            if len(self._events) > self._max_keys:
                for stale in sorted(
                    self._events,
                    key=lambda item: self._events[item][-1] if self._events[item] else 0.0,
                )[: self._max_keys // 4]:
                    self._events.pop(stale, None)

    def remaining(self, key: str) -> int:
        with self._lock:
            events = self._prune(key, self._clock())
            return max(0, self._limit - len(events))

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._events.clear()
            else:
                self._events.pop(key, None)
