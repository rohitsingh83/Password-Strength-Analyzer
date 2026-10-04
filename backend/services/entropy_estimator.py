"""
backend/services/entropy_estimator.py
--------------------------------------------------------------------------
PURPOSE
    Estimate the *theoretical* entropy of a password and explain, in plain
    language, why that number is optimistic for human-chosen passwords.

THEORY (kept simple on purpose)
    Entropy ~= L * log2(N)

        L = number of characters (or words, for a passphrase)
        N = size of the pool the characters were chosen from

    Example pools:
        lowercase only ......... 26
        + uppercase ............ 52
        + digits ............... 62
        + symbols (common) ..... 94
        uncommon / unicode ..... up to ~200

WHY WE DO NOT TRUST IT ALONE
    The formula assumes every character was chosen uniformly at random and
    independently. Humans do not do that: they pick "Password" then add "123!"
    for "extra security". So "Password123!" can score an optimistic ~72 bits
    of theoretical entropy while an attacker's first few thousand guesses
    include it.

    That is why scoring_engine.py treats this number as ONE signal, then
    applies penalties for common passwords, sequences, keyboard walks,
    repetition, predictable word+year structures and personal context.

LEGAL / ETHICAL NOTE
    Nothing here attempts to crack anything. It is a maths estimate aimed at
    education, and the UI labels it "educational estimate only".
--------------------------------------------------------------------------
"""

from __future__ import annotations

import math
import re
from typing import FrozenSet, List

from .data_loader import load_passphrase_words

# -----------------------------------------------------------------------------
# Character pools
# -----------------------------------------------------------------------------
LOWER_POOL = 26
UPPER_POOL = 26
DIGIT_POOL = 10
SYMBOL_POOL = 33          # ASCII punctuation set size
SPACE_POOL = 1
COMMON_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/\\`~"

# Rough guesses-per-second figures used ONLY for the labelled educational
# "guess resistance" text. These numbers vary wildly between attackers, which
# is exactly why the UI says "educational estimate only" and never claims a
# guaranteed crack time.
ONLINE_THROTTLED_GUESSES_PER_SECOND = 10          # rate-limited login form
OFFLINE_SLOW_HASH_GUESSES_PER_SECOND = 1e5        # Argon2id / bcrypt, GPU cluster
OFFLINE_FAST_HASH_GUESSES_PER_SECOND = 1e11       # unsalted MD5/SHA-1, GPU cluster


# -----------------------------------------------------------------------------
# 1. Pool size
# -----------------------------------------------------------------------------
def estimate_pool_size(password: str) -> int:
    """
    Estimate how many distinct characters the *author* of the password could
    have been drawing from, based on the classes actually present.

    This mirrors the classic "character set size" used in entropy maths.
    """
    if not password:
        return 0

    pool = 0
    if any(c.islower() for c in password):
        pool += LOWER_POOL
    if any(c.isupper() for c in password):
        pool += UPPER_POOL
    if any(c.isdigit() for c in password):
        pool += DIGIT_POOL
    if any(c in COMMON_SYMBOLS for c in password):
        pool += SYMBOL_POOL
    if any(c == " " for c in password):
        pool += SPACE_POOL
    if any(ord(c) > 127 for c in password):
        # Unicode expands the pool, but relying on keyboard layout quirks is
        # a bad strategy: many systems normalise (or reject) exotic characters.
        pool += 100

    return max(pool, 1)   # never return 0, avoids log2(0)


# -----------------------------------------------------------------------------
# 2. Theoretical entropy
# -----------------------------------------------------------------------------
def estimate_theoretical_entropy(password: str, pool_size: int | None = None) -> float:
    """
    Return the classic theoretical entropy estimate in bits:

        L * log2(N)

    This is an UPPER BOUND for a human-chosen password. It is optimistic,
    never pessimistic, so the scoring engine must subtract predictability.
    """
    if not password:
        return 0.0
    pool = pool_size or estimate_pool_size(password)
    return len(password) * math.log2(pool)


# -----------------------------------------------------------------------------
# 3. Effective (reality-adjusted) entropy
# -----------------------------------------------------------------------------
def estimate_effective_entropy(password: str, pattern_penalty: float = 0.0) -> float:
    """
    Reality-adjusted entropy = theoretical - predictability penalty.

    `pattern_penalty` is provided by pattern_detector.py (in bits-equivalents)
    and represents how many bits an attacker gains for free from structure:
    dictionaries, sequences, keyboard walks, repetition, dates, context.
    """
    theoretical = estimate_theoretical_entropy(password)
    return max(theoretical - abs(pattern_penalty), 0.0)


# -----------------------------------------------------------------------------
# 4. Character-per-character entropy (Shannon-inspired estimate)
# -----------------------------------------------------------------------------
def shannon_entropy_bits(password: str) -> float:
    """
    Per-character Shannon entropy multiplied by length.

        H = -sum(p_i * log2(p_i)) * L

    Educational value: it shows how much *internal variety* a string has.
    "aaaaaaaaaaaaaaaa" has ~0 bits, while a random 16-char string has ~4
    bits per character. It still cannot see "Password" as a dictionary word,
    so it is displayed as a variety indicator, not as a strength verdict.
    """
    if not password:
        return 0.0
    counts: dict[str, int] = {}
    for char in password:
        counts[char] = counts.get(char, 0) + 1
    length = len(password)
    per_char = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return per_char * length


# -----------------------------------------------------------------------------
# 5. Passphrase entropy (Diceware style)
# -----------------------------------------------------------------------------
def passphrase_entropy_bits(word_count: int, wordlist_size: int | None = None) -> float:
    """
    Entropy of a passphrase built from randomly selected words:

        bits = words * log2(wordlist_size)

    A 7,776-word Diceware list gives 12.9 bits per word, so 4 words ~= 51.7
    bits and 6 words ~= 77.5 bits. Our bundled list has ~6,300 words, giving
    ~12.6 bits per word -- nearly identical for teaching purposes.
    """
    size = wordlist_size or max(len(load_passphrase_words()), 2)
    return word_count * math.log2(size)


# -----------------------------------------------------------------------------
# 6. Educational "guess resistance" label
# -----------------------------------------------------------------------------
def _humanise_seconds(seconds: float) -> str:
    """Convert a big number of seconds into a readable, obviously-approximate string."""
    if seconds < 1:
        return "well under a second"
    units = [
        ("seconds", 60),
        ("minutes", 60),
        ("hours", 24),
        ("days", 365),
        ("years", 1000),
        ("thousand years", 1000),
        ("million years", 1000),
        ("billion years", 1000),
    ]
    value = seconds
    label = "seconds"
    for next_label, divisor in units:
        if value < divisor:
            return f"{value:,.1f} {label}".replace(".0 ", " ")
        value /= divisor
        label = next_label
    return "far beyond the age of the universe"


# Beyond this many bits a double cannot represent the key space at all
# (2**1024 is already the floating-point limit), and no realistic attacker model
# needs the arithmetic. Long random values simply report the ceiling label.
MAX_REPRESENTABLE_BITS = 1024

SCENARIO_LABELS = {
    "online_throttled": "Online, rate-limited login form",
    "offline_slow_hash": "Offline attack on a slow hash (Argon2id/bcrypt)",
    "offline_fast_hash": "Offline attack on a fast hash (unsalted MD5/SHA-1)",
}


def estimate_guess_resistance(effective_bits: float) -> dict:
    """
    Turn an entropy estimate into three *labelled* scenarios.

    IMPORTANT: this is an educational estimate only. Real guessing resistance
    depends on the attacker model (online vs offline), the hash function and
    its work factor, rate limiting, account lockout, key rotation, whether the
    hash database has already leaked -- and on whether the password is reused
    somewhere that already leaked.
    """
    label = "Educational estimate only -- not a guaranteed crack time"
    caveat = (
        "Real guessing resistance depends on the attacker model (online vs offline), the hash "
        "function and its work factor, rate limiting and lockout, whether a hash database has "
        "already leaked, and whether this password is reused elsewhere. An estimate is an "
        "illustration, not a fact."
    )

    def scenario(key: str, attempts: float, rate: float, instant: bool = False) -> dict:
        return {
            "key": key,
            "label": SCENARIO_LABELS[key],
            "guesses_per_second": int(rate),
            "estimate": "Instant" if instant else _humanise_seconds(attempts / rate),
        }

    if effective_bits <= 0:
        return {
            "estimate_label": label,
            "caveat": caveat,
            "scenarios": [
                scenario("online_throttled", 0, ONLINE_THROTTLED_GUESSES_PER_SECOND, instant=True),
                scenario("offline_slow_hash", 0, OFFLINE_SLOW_HASH_GUESSES_PER_SECOND, instant=True),
                scenario("offline_fast_hash", 0, OFFLINE_FAST_HASH_GUESSES_PER_SECOND, instant=True),
            ],
            "online_throttled": {"label": "Instant", "guesses_per_second": ONLINE_THROTTLED_GUESSES_PER_SECOND},
            "offline_slow_hash": {"label": "Instant", "guesses_per_second": int(OFFLINE_SLOW_HASH_GUESSES_PER_SECOND)},
            "offline_fast_hash": {"label": "Instant", "guesses_per_second": int(OFFLINE_FAST_HASH_GUESSES_PER_SECOND)},
            "half_search_space": 0,
        }

    # An attacker on average needs to try about half of the keyspace.
    if effective_bits > MAX_REPRESENTABLE_BITS:
        # Avoid a float OverflowError: report the ceiling without arithmetic.
        attempts = float("inf")
        ceiling = "far beyond the age of the universe"
        scenarios = [
            {"key": key, "label": SCENARIO_LABELS[key],
             "guesses_per_second": int(rate), "estimate": ceiling}
            for key, rate in (("online_throttled", ONLINE_THROTTLED_GUESSES_PER_SECOND),
                              ("offline_slow_hash", OFFLINE_SLOW_HASH_GUESSES_PER_SECOND),
                              ("offline_fast_hash", OFFLINE_FAST_HASH_GUESSES_PER_SECOND))
        ]
        return {
            "estimate_label": label,
            "caveat": caveat,
            "scenarios": scenarios,
            "online_throttled": {"label": ceiling, "guesses_per_second": ONLINE_THROTTLED_GUESSES_PER_SECOND},
            "offline_slow_hash": {"label": ceiling, "guesses_per_second": int(OFFLINE_SLOW_HASH_GUESSES_PER_SECOND)},
            "offline_fast_hash": {"label": ceiling, "guesses_per_second": int(OFFLINE_FAST_HASH_GUESSES_PER_SECOND)},
            "half_search_space": attempts,
        }

    attempts = 2 ** (effective_bits - 1)
    scenarios = [
        scenario("online_throttled", attempts, ONLINE_THROTTLED_GUESSES_PER_SECOND),
        scenario("offline_slow_hash", attempts, OFFLINE_SLOW_HASH_GUESSES_PER_SECOND),
        scenario("offline_fast_hash", attempts, OFFLINE_FAST_HASH_GUESSES_PER_SECOND),
    ]
    return {
        "estimate_label": label,
        "caveat": caveat,
        "scenarios": scenarios,
        "online_throttled": {"label": scenarios[0]["estimate"],
                             "guesses_per_second": ONLINE_THROTTLED_GUESSES_PER_SECOND},
        "offline_slow_hash": {"label": scenarios[1]["estimate"],
                              "guesses_per_second": int(OFFLINE_SLOW_HASH_GUESSES_PER_SECOND)},
        "offline_fast_hash": {"label": scenarios[2]["estimate"],
                              "guesses_per_second": int(OFFLINE_FAST_HASH_GUESSES_PER_SECOND)},
        "half_search_space": attempts,
    }


# -----------------------------------------------------------------------------
# 7. Convenience wrapper used by the analyzer
# -----------------------------------------------------------------------------
def entropy_report(password: str, pattern_penalty_bits: float = 0.0) -> dict:
    """Bundle every entropy signal into one dict for the API/UI layer."""
    pool = estimate_pool_size(password)
    theoretical = estimate_theoretical_entropy(password, pool)
    effective = estimate_effective_entropy(password, pattern_penalty_bits)
    words = [w for w in re.split(r"[\W_]+", password.lower()) if w]

    return {
        "pool_size": pool,
        "theoretical_bits": round(theoretical, 1),
        "effective_bits": round(effective, 1),
        "shannon_bits": round(shannon_entropy_bits(password), 1),
        "pattern_penalty_bits": round(abs(pattern_penalty_bits), 1),
        "is_passphrase_like": len(words) >= 3 and (" " in password or "-" in password or "_" in password),
        "passphrase_estimate_bits": round(passphrase_entropy_bits(max(len(words), 1)), 1),
        "formula": "Entropy (theoretical) ~= length x log2(pool size)",
        "caveat": (
            "Theoretical entropy assumes truly random character selection. "
            "Human-chosen passwords are predictable, so this number is an "
            "upper bound. Effective bits additionally subtract pattern, "
            "dictionary and context penalties."
        ),
    }
