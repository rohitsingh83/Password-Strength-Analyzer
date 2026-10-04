"""
backend/services/scoring_engine.py
--------------------------------------------------------------------------
PURPOSE
    Turn every signal into a single 0-100 score plus a classification band.

SCORE COMPOSITION (project-defined rubric -- NOT a universal standard)

    POSITIVE CONTRIBUTIONS                       MAX
      Length                                      35
      Character diversity                         15
      Unique-character ratio                      10
      Pattern resistance                          20
      Not a common password                       10
      Additional unpredictability                 10
                                                 ---
                                                 100

    PENALTIES (applied after the positive total)
      Common password ............ -45 (and classification floor of VERY WEAK)
      Breach corpus hit .......... -45 (same floor)
      Keyboard walk .............. up to -15
      Sequential characters ...... up to -15
      Repeated pattern ........... up to -15
      Personal information ....... up to -20
      Predictable word + year .... up to -15
      Dictionary word ............ up to -12

    The final value is clamped to 0..100.

CLASSIFICATION BANDS
    0-20   VERY WEAK
    21-40  WEAK
    41-60  MODERATE
    61-80  STRONG
    81-100 VERY STRONG

    These bands are deliberately *project-defined* so the tool can be graded
    and tested. Real-world strength meters (zxcvbn, the NIST-oriented guidance,
    enterprise IAM vendors) use different scales and weights. Nothing here
    should be presented as an industry certification of strength.

WHY PENALTIES ARE CAPPED
    Without caps, a single long predictable password could pile up penalties
    from several overlapping detectors for the same underlying weakness. Caps
    keep the rubric explainable: every number in the breakdown maps to a
    sentence you can read in the report.
--------------------------------------------------------------------------
"""

from __future__ import annotations

from typing import Dict, List

from .character_analyzer import analyze_characters, analyze_length, variety_credit

# -----------------------------------------------------------------------------
# Weights and bands
# -----------------------------------------------------------------------------
WEIGHTS = {
    "length": 35,
    "diversity": 15,
    "uniqueness": 10,
    "pattern_resistance": 20,
    "not_common": 10,
    "unpredictability": 10,
}

BANDS = [
    (0, 20, "VERY WEAK", "This password would be guessed almost immediately."),
    (21, 40, "WEAK", "Better than nothing, but it will not survive a targeted or automated attack."),
    (41, 60, "MODERATE", "Reasonable for a throwaway account, not for email, banking or work."),
    (61, 80, "STRONG", "Good, provided it is unique to this one account and MFA is enabled."),
    (81, 100, "VERY STRONG", "Excellent, provided it is unique and stored in a password manager."),
]

# Maximum penalty per weakness category (keeps overlapping detectors fair).
PENALTY_CAPS = {
    "common_password": 45,
    "common_phrase": 45,
    "breach": 45,
    "keyboard_pattern": 15,
    "sequence": 15,
    "repeated_characters": 15,
    "repeated_substring": 15,
    "personal_info": 20,
    "predictable_structure": 15,
    "year_pattern": 8,
    "date_pattern": 8,
    "phone_pattern": 10,
    "dictionary_word": 12,
    "short_length": 10,
    "low_variety": 6,
    "passphrase_structure": 0,
}

# Severity -> fraction of the category cap that one finding consumes.
SEVERITY_FRACTION = {
    "critical": 1.00,
    "high": 0.85,
    "medium": 0.55,
    "low": 0.30,
    "info": 0.10,
}


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def classify(score: int) -> Dict[str, str]:
    """Map a numeric score to one of the five classification labels."""
    for low, high, label, summary in BANDS:
        if low <= score <= high:
            return {"classification": label, "summary": summary, "band": f"{low}-{high}"}
    return {"classification": "VERY STRONG", "summary": BANDS[-1][3], "band": "81-100"}


def _pattern_penalty_points(findings: List[Dict]) -> tuple[int, Dict[str, int]]:
    """
    Convert pattern findings into a total penalty, respecting per-category caps.

    Returns (total_penalty, per_category_penalty).
    """
    per_category: Dict[str, float] = {}
    for finding in findings:
        ftype = finding["type"]
        cap = PENALTY_CAPS.get(ftype, 5)
        fraction = SEVERITY_FRACTION.get(finding["severity"], 0.3)
        per_category[ftype] = per_category.get(ftype, 0) + cap * fraction

    capped = {k: min(v, PENALTY_CAPS.get(k, 5)) for k, v in per_category.items()}
    return int(round(sum(capped.values()))), {k: int(round(v)) for k, v in capped.items()}


# -----------------------------------------------------------------------------
# Score caps: structural realities that arithmetic alone cannot express
# -----------------------------------------------------------------------------
# Each entry is (rule_id, human explanation). The cap list is applied in order
# and the LOWEST applicable cap wins, because it represents the most serious
# structural limitation of the value.
def _applicable_caps(password: str, findings: List[Dict], length_report: Dict,
                     character_report: Dict) -> List[Dict]:
    """Return every structural cap that applies, with a readable reason."""
    types = {f["type"] for f in findings}
    length = length_report["length"]
    unique = character_report["unique_character_count"]
    has_letters = character_report["has_lowercase"] or character_report["has_uppercase"]
    caps: List[Dict] = []

    def add(cap: int, rule: str, reason: str) -> None:
        caps.append({"cap": cap, "rule": rule, "reason": reason})

    if length == 0:
        add(0, "empty", "No value submitted.")
        return caps

    if length <= 3:
        add(10, "extremely_short",
            f"{length} character(s) is guessable instantly regardless of which characters were used.")
    elif length < 8:
        add(20, "too_short",
            f"{length} characters is below every modern minimum; no combination of symbols fixes that.")

    if unique == 1 and length >= 8:
        add(15, "single_repeated_character",
            "The entire value is one character repeated, so only the length and the character "
            "need to be guessed.")
    elif unique <= 3 and length >= 6:
        add(25, "very_low_uniqueness",
            f"Only {unique} distinct characters are used across {length} positions, so the real "
            f"search space is tiny.")

    if not has_letters and length < 12:
        add(35, "no_letters_short",
            "Digits/symbols only and under 12 characters: the pool may look large, but the value "
            "is short enough to brute force.")

    # Digits/symbols only, ANY length. The pool looks big, but the value is still
    # just a number with decoration -- absent letters, entropy per character is
    # far lower than the pool size suggests. Held below the STRONG band, and
    # below MODERATE when it is also short.
    if not has_letters and length >= 12:
        add(45, "no_letters", "Digits and symbols only: without letters the search pool is much "
                              "smaller than the character-space estimate implies, so the value is "
                              "held below the STRONG band.")

    # A visibly "thin" character set (two or three distinct characters) cannot be
    # made strong by repeating it, whatever the length. These are progressively
    # stricter caps that sit BELOW the repeated-character rule above.
    if length >= 16 and unique <= 4:
        add(45, "thin_character_set",
            f"Only {unique} distinct characters are used across {length} positions, so the value "
            f"is far more repetitive than its length suggests.")
    if length >= 16 and unique <= 3:
        add(30, "thin_character_set_low",
            f"{unique} distinct characters repeated across {length} positions -- length cannot "
            f"compensate for so little variety.")
    if length >= 16 and unique <= 2:
        add(20, "extremely_thin_character_set",
            f"Only {unique} distinct characters are used across {length} positions.")

    if ("common_password" in types) or ("breach" in types) or ("common_phrase" in types):
        add(20, "known_common_or_breached",
            "This value is a known common password, a known phrase, or present in the demo breach "
            "corpus, so it is never allowed above the VERY WEAK band.")

    if "personal_info" in types:
        add(40, "contains_personal_information",
            "The value contains personal information you supplied. That information is "
            "discoverable from profiles and breach data, so the score is held in the WEAK band.")

    if "year_pattern" in types and ({"dictionary_word", "predictable_structure",
                                     "passphrase_structure"} & types):
        add(45, "word_plus_year",
            "A recognisable word (or words) combined with a year is one of the most-modelled "
            "attack shapes, so it is capped below the STRONG band.")
    elif "predictable_structure" in types and "dictionary_word" in types:
        add(60, "word_plus_number_shape",
            "A memorable word combined with a short number is a pattern attackers model "
            "explicitly, so it is capped below the STRONG band even when it looks complex.")

    return caps


# -----------------------------------------------------------------------------
# Main scoring function
# -----------------------------------------------------------------------------
def score_password(password: str, findings: List[Dict]) -> Dict:
    """
    Produce the full scoring breakdown.

    {
      "score": 74,
      "classification": "STRONG",
      "summary": "...",
      "breakdown": { "length": {"earned": 26, "max": 35, ...}, ... },
      "penalties": {"total": 6, "by_category": {}},
      "raw_score": 80
    }
    """
    length_report = analyze_length(password)
    character_report = analyze_characters(password)

    # ---------------------------------------------------------------- positives
    length_earned = length_report["credit"] * WEIGHTS["length"]
    diversity_earned = variety_credit(character_report, length_report) * WEIGHTS["diversity"]
    uniqueness_earned = min(character_report["unique_character_ratio"] / 1.0, 1.0) * WEIGHTS["uniqueness"]

    # Pattern resistance: start from full credit, lose it with each distinct
    # weakness category (so 5 findings of the same type do not stack to -100).
    distinct_categories = {f["type"] for f in findings}
    pattern_loss = 0.0
    for category in distinct_categories:
        worst = max(f["penalty_bits"] for f in findings if f["type"] == category)
        pattern_loss += min(worst / 30.0, 1.0) / max(len(distinct_categories), 1) * 1.6
    pattern_resistance_credit = max(1.0 - pattern_loss, 0.0)
    pattern_earned = pattern_resistance_credit * WEIGHTS["pattern_resistance"]

    # Common-password credit
    common_hit = any(f["type"] == "common_password" for f in findings)
    breach_hit = any(f["type"] == "breach" for f in findings)
    not_common_earned = 0.0 if (common_hit or breach_hit) else WEIGHTS["not_common"]

    # Additional unpredictability: length *beyond* the strong band, combined with
    # genuinely mixed character types and no single-letter repetition.
    unpredictability = 0.0
    if length_report["length"] >= 16:
        unpredictability += 0.5
    if length_report["length"] >= 20:
        unpredictability += 0.2
    if character_report["character_type_count"] >= 3:
        unpredictability += 0.3
    if character_report["unique_character_ratio"] >= 0.75:
        unpredictability += 0.2
    if character_report["character_type_count"] >= 4:
        unpredictability += 0.2
    if not findings:
        unpredictability += 0.3
    unpredictability = min(unpredictability, 1.0) * WEIGHTS["unpredictability"]

    raw_positive = (
        length_earned + diversity_earned + uniqueness_earned
        + pattern_earned + not_common_earned + unpredictability
    )

    # ---------------------------------------------------------------- penalties
    pattern_penalty, penalty_breakdown = _pattern_penalty_points(findings)

    # An empty password is a special case: score 0, no partial credit.
    if not password:
        return {
            "score": 0,
            "raw_score": 0,
            "classification": "VERY WEAK",
            "summary": "No password entered.",
            "band": "0-20",
            "breakdown": {
                "length": {"earned": 0, "max": WEIGHTS["length"], "detail": length_report["band"]},
                "character_diversity": {"earned": 0, "max": WEIGHTS["diversity"], "detail": "none"},
                "unique_character_ratio": {"earned": 0, "max": WEIGHTS["uniqueness"], "detail": "0%"},
                "pattern_resistance": {"earned": 0, "max": WEIGHTS["pattern_resistance"], "detail": "n/a"},
                "not_a_common_password": {"earned": 0, "max": WEIGHTS["not_common"], "detail": "n/a"},
                "unpredictability": {"earned": 0, "max": WEIGHTS["unpredictability"], "detail": "n/a"},
            },
            "penalties": {"total": 0, "by_category": {}},
            "length_report": length_report,
            "character_report": character_report,
            "score_cap_applied": None,
            "caps_evaluated": [],
        }

    # Round the accumulated value to 6 decimals before classifying. The
    # individual contributions are doubles, so a long chain of additions can
    # land a hair either side of a .5 boundary (36.49999999999 vs 36.5).
    # Normalising here makes the score reproducible across implementations and
    # is what the JavaScript port mirrors.
    score = round(raw_positive - pattern_penalty, 6)

    # ---- structural caps (see _applicable_caps for the reasoning per rule) ----
    caps = _applicable_caps(password, findings, length_report, character_report)
    cap_applied = None
    if caps:
        tightest = min(caps, key=lambda item: item["cap"])
        if score > tightest["cap"]:
            cap_applied = (
                f"Score capped at {tightest['cap']} ({tightest['rule']}): {tightest['reason']}"
            )
        score = min(score, tightest["cap"])

    score = int(max(0, min(100, round(score))))
    verdict = classify(score)

    return {
        "score": score,
        "raw_score": int(round(raw_positive)),
        "classification": verdict["classification"],
        "summary": verdict["summary"],
        "band": verdict["band"],
        "breakdown": {
            "length": {
                "earned": round(length_earned, 1), "max": WEIGHTS["length"],
                "detail": f"{length_report['length']} characters ({length_report['band']})",
            },
            "character_diversity": {
                "earned": round(diversity_earned, 1), "max": WEIGHTS["diversity"],
                "detail": f"{character_report['character_type_count']} character types "
                          f"({', '.join(character_report['character_types']) or 'none'})",
            },
            "unique_character_ratio": {
                "earned": round(uniqueness_earned, 1), "max": WEIGHTS["uniqueness"],
                "detail": f"{character_report['unique_character_ratio'] * 100:.0f}% unique characters",
            },
            "pattern_resistance": {
                "earned": round(pattern_earned, 1), "max": WEIGHTS["pattern_resistance"],
                "detail": f"{len(distinct_categories)} distinct weakness categories detected"
                          if distinct_categories else "no predictable patterns detected",
            },
            "not_a_common_password": {
                "earned": round(not_common_earned, 1), "max": WEIGHTS["not_common"],
                "detail": "common password or breach match" if (common_hit or breach_hit)
                          else "not found in the common-password list",
            },
            "unpredictability": {
                "earned": round(unpredictability, 1), "max": WEIGHTS["unpredictability"],
                "detail": "bonus for length combined with variety and clear pattern scans",
            },
        },
        "penalties": {"total": pattern_penalty, "by_category": penalty_breakdown},
        "length_report": length_report,
        "character_report": character_report,
        "score_cap_applied": cap_applied,
        "caps_evaluated": caps,
    }
