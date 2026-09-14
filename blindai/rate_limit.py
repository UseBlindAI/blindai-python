"""A client-side rate limiter that refuses, and never permits.

This is the one piece of local logic a thin client may carry, and the reason is precise: on limit
it **raises**. It never returns a verdict, so it cannot produce an allow, and it cannot answer a
question that was never asked of the server. A limiter that returned "allowed" when the bucket was
empty would be a second enforcement engine wearing a throttle's clothes.
"""
from __future__ import annotations

import threading
import time

from .errors import BlindAIError


class RateLimitExceeded(BlindAIError):
    """The local limiter refused before a request was made. No decision exists for this call."""

    def __init__(self, retry_after: float) -> None:
        super().__init__(f"local rate limit exceeded; retry in {retry_after:.2f}s")
        self.retry_after = retry_after


class RateLimiter:
    """A token bucket. `acquire()` raises `RateLimitExceeded` or returns None."""

    def __init__(self, rate_per_second: float, burst: int) -> None:
        if rate_per_second <= 0 or burst <= 0:
            raise ValueError("rate_per_second and burst must both be positive")
        self._rate = rate_per_second
        self._burst = burst
        self._tokens = float(burst)
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            self._tokens = min(self._burst, self._tokens + (now - self._updated) * self._rate)
            self._updated = now
            if self._tokens < 1.0:
                raise RateLimitExceeded((1.0 - self._tokens) / self._rate)
            self._tokens -= 1.0
