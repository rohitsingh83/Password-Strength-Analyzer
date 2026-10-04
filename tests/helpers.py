"""
tests/helpers.py
--------------------------------------------------------------------------
PURPOSE
    Shared, dependency-free helpers for the test-suite.

WHY NOT `random`
    The whole project bans Python's `random` module (it is not suitable for
    anything security-related, and tests must not model bad habits). When a test
    needs a long, pattern-free value, it builds one from a SHA-256 keystream
    instead. That has a second benefit: the value is identical on every run, so
    a test can never flake because of an unlucky draw.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import hashlib
import string

ALPHANUMERIC = string.ascii_letters + string.digits


def deterministic_long_value(length: int = 256, salt: str = "psa-long-value") -> str:
    """
    Return a long, uniform, pattern-free alphanumeric string.

    Uniform because of rejection sampling (bytes >= 248 are discarded, which
    removes the modulo bias a naive `% 62` would introduce), and deterministic
    because the keystream comes from SHA-256 over a counter.
    """
    characters = []
    counter = 0
    while len(characters) < length:
        digest = hashlib.sha256(f"{salt}-{counter}".encode()).digest()
        for byte in digest:
            if byte < 248:                      # rejection sampling -> uniform
                characters.append(ALPHANUMERIC[byte % len(ALPHANUMERIC)])
                if len(characters) == length:
                    break
        counter += 1
    return "".join(characters)
