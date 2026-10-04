"""
backend/utils/rate_limiter.py
--------------------------------------------------------------------------
PURPOSE
    A tiny in-memory token-bucket rate limiter for the analysis endpoints.

WHY A PUBLIC ANALYSIS ENDPOINT NEEDS ONE
    * It is a free CPU service. Without a limit, one client can consume the
      whole process (the pattern detector is O(n^2) on repeated substrings).
    * It discourages automated probing of *this* tool. Attackers who find a
      password-strength API sometimes try to use it as an oracle.
    * Real deployments should prefer a shared store (Redis) so the limit is
      enforced across workers -- this implementation is deliberately simple
      and single-process, and the docstring says so.

DESIGN
    Each client key gets a bucket of `capacity` tokens that refills at
    `refill_per_second`. One request costs one token. Exceeding the bucket
    returns HTTP 429 with a Retry-After header.

PRIVACY
    The only thing stored per client is a counter. Submitted passwords are
    never involved, and the limiter never logs request bodies.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Tuple


@dataclass
class _Bucket:
    tokens: float
    last_refill: float = field(default_factory=time.monotonic)


class TokenBucketRateLimiter:
    """Thread-safe in-memory token bucket."""

    def __init__(self, capacity: int = 60, refill_per_second: float = 1.0) -> None:
        self.capacity = float(capacity)
        self.refill_per_second = float(refill_per_second)
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def check(self, key: str, cost: float = 1.0) -> Tuple[bool, float]:
        """
        Attempt to spend `cost` tokens for `key`.

        Returns (allowed, retry_after_seconds).
        """
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=self.capacity)
                self._buckets[key] = bucket

            elapsed = now - bucket.last_refill
            bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.refill_per_second)
            bucket.last_refill = now

            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return True, 0.0

            missing = cost - bucket.tokens
            retry_after = missing / self.refill_per_second if self.refill_per_second else 60.0
            return False, round(retry_after, 2)

    def reset(self, key: str | None = None) -> None:
        """Clear one bucket (or all buckets) -- used by tests."""
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)

    def snapshot(self) -> Dict[str, float]:
        """Current token counts per key (metadata only, no secrets)."""
        with self._lock:
            return {key: round(bucket.tokens, 2) for key, bucket in self._buckets.items()}


# Two limiters with different budgets:
#   analyse: heavier endpoint (full engine run)
#   generate: cheap, but should still be bounded
analyze_limiter = TokenBucketRateLimiter(capacity=120, refill_per_second=2.0)
generate_limiter = TokenBucketRateLimiter(capacity=60, refill_per_second=1.0)
