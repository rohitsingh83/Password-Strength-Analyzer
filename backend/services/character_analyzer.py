"""
backend/services/character_analyzer.py
--------------------------------------------------------------------------
PURPOSE
    Length + character-composition metrics.

    Contains two required public helpers:
        analyze_length(password)     -> length bands and guidance
        analyze_characters(password) -> diversity metrics

DESIGN PRINCIPLE
    Length and variety are *contributors*, never verdicts. The scoring engine
    uses them as positive signals and then subtracts predictability found by
    pattern_detector.py. That is the whole point of this project:

        LENGTH + UNPREDICTABILITY + PATTERN RESISTANCE + COMMON-PW CHECK + CONTEXT

    "aaaaaaaaaaaaaaaaaaaaaaaa" is 24 characters long and earns full length
    credit in this module -- and then loses it again in the scoring engine
    because detect_repetition() proves it is predictable. Both signals are
    needed; neither is sufficient.
--------------------------------------------------------------------------
"""

from __future__ import annotations

from typing import Dict, List

from .entropy_estimator import COMMON_SYMBOLS

# -----------------------------------------------------------------------------
# Configuration -- every band/limit lives in one place so it is auditable
# -----------------------------------------------------------------------------
LENGTH_BANDS = [
    # (min_length, max_length, label, guidance, credit_fraction)
    (0, 0, "Empty", "No password entered.", 0.0),
    (1, 7, "Very short", "Below the minimum used by any modern guidance.", 0.05),
    (8, 11, "Short", "Acceptable only for low-value accounts, and even then it is risky.", 0.40),
    (12, 15, "Better length", "Meets the common 12-character modern baseline.", 0.72),
    (16, 19, "Strong length", "16+ characters is where length starts to carry real weight.", 0.92),
    (20, 10_000, "Excellent length", "Very strong length contribution -- keep it unpredictable too.", 1.00),
]

MIN_LENGTH = 1
MAX_SUPPORTED_LENGTH = 256      # NIST SP 800-63B: support at least 64; we allow far more
RECOMMENDED_MIN_LENGTH = 12
RECOMMENDED_PASSPHRASE_WORDS = 4
RECOMMENDED_RANDOM_LENGTH = 16


# -----------------------------------------------------------------------------
# 1. analyze_length()
# -----------------------------------------------------------------------------
def analyze_length(password: str) -> Dict:
    """
    Return a complete length report.

    {
      "length": 14,
      "band": "Better length",
      "credit": 0.72,               # 0..1 contribution used by the scorer
      "guidance": "...",
      "is_empty": False,
      "is_recommended_length": True,
      "character_pool_note": "..."
    }
    """
    length = len(password or "")

    band_label, guidance, credit = "Empty", "No password entered.", 0.0
    for low, high, label, text, fraction in LENGTH_BANDS:
        if low <= length <= high:
            band_label, guidance, credit = label, text, fraction
            break

    return {
        "length": length,
        "band": band_label,
        "credit": round(credit, 3),
        "guidance": guidance,
        "is_empty": length == 0,
        "is_recommended_length": length >= RECOMMENDED_MIN_LENGTH,
        "is_very_long": length >= 20,
        "max_supported_length": MAX_SUPPORTED_LENGTH,
        "recommended_minimum": RECOMMENDED_MIN_LENGTH,
        "note": (
            "Length is the single most useful lever you control, because each extra "
            "character multiplies an attacker's work. It is not sufficient on its "
            "own: 20 repeated characters are still trivially guessable."
        ),
    }


# -----------------------------------------------------------------------------
# 2. analyze_characters()
# -----------------------------------------------------------------------------
def analyze_characters(password: str) -> Dict:
    """
    Return character-diversity metrics.

    Includes the required surface:
        lowercase / uppercase / digits / symbols / spaces presence,
        unique_character_count, character_type_count, unique_character_ratio
    """
    text = password or ""
    length = len(text)

    has_lower = any(c.islower() for c in text)
    has_upper = any(c.isupper() for c in text)
    has_digit = any(c.isdigit() for c in text)
    has_symbol = any(c in COMMON_SYMBOLS for c in text)
    has_space = any(c == " " for c in text)
    has_unicode = any(ord(c) > 127 for c in text)

    type_count = sum([has_lower, has_upper, has_digit, has_symbol, has_space])
    unique_count = len(set(text))
    unique_ratio = (unique_count / length) if length else 0.0

    # Repeat pressure: how much of the string is "new" information?
    repeated_characters = length - unique_count

    return {
        "length": length,
        "has_lowercase": has_lower,
        "has_uppercase": has_upper,
        "has_digits": has_digit,
        "has_symbols": has_symbol,
        "has_spaces": has_space,
        "has_unicode": has_unicode,
        "character_type_count": type_count,
        "character_types": [
            name for name, present in (
                ("lowercase", has_lower), ("uppercase", has_upper),
                ("digits", has_digit), ("symbols", has_symbol), ("spaces", has_space),
            ) if present
        ],
        "unique_character_count": unique_count,
        "unique_character_ratio": round(unique_ratio, 3),
        "repeated_character_count": repeated_characters,
        "caveat": (
            "Character diversity is useful but weak on its own: a single common word with a "
            "capital letter and a trailing digit satisfies every composition rule while "
            "remaining one of the most predictable shapes in existence. That is why "
            "composition cannot be the only test."
        ),
    }


# -----------------------------------------------------------------------------
# 3. Convenience: variety credit used by the scoring engine
# -----------------------------------------------------------------------------
def variety_credit(character_report: Dict, length_report: Dict) -> float:
    """
    Collapse diversity metrics into a 0..1 credit.

    Weighting (documented for the report):
        * character_type_count : up to 0.6   (4+ types earns full)
        * unique ratio         : up to 0.4   (0.8+ unique ratio earns full)
    """
    type_credit = min(character_report["character_type_count"] / 4.0, 1.0) * 0.6
    ratio_credit = min(character_report["unique_character_ratio"] / 0.8, 1.0) * 0.4

    # A very short password cannot earn meaningful diversity credit even if it
    # technically contains 3+ character types (e.g. "aB1").
    if length_report["length"] < 8:
        type_credit *= 0.5

    return round(type_credit + ratio_credit, 3)


# -----------------------------------------------------------------------------
# 4. Quick self-test when running the module directly
# -----------------------------------------------------------------------------
if __name__ == "__main__":       # pragma: no cover
    for sample in ["", "123456", "Password123!", "aaaaaaaaaaaaaaaa", "Sunset-Orchid-River-Pebble"]:
        print(f"{sample!r:32} len={analyze_length(sample)['band']:16} "
              f"types={analyze_characters(sample)['character_type_count']}")
