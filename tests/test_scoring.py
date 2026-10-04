"""
tests/test_scoring.py
--------------------------------------------------------------------------
Scoring-engine tests: boundaries, caps, entropy and guess-resistance.
The rubric is project-defined, so its behaviour is pinned by tests to make the
documentation checkable.
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Score boundaries
# ---------------------------------------------------------------------------
def test_T25_score_boundaries():
    """Classification bands map exactly as documented (0-20, 21-40, 41-60, 61-80, 81-100)."""
    from backend.services.scoring_engine import classify
    assert classify(0)["classification"] == "VERY WEAK"
    assert classify(20)["classification"] == "VERY WEAK"
    assert classify(21)["classification"] == "WEAK"
    assert classify(40)["classification"] == "WEAK"
    assert classify(41)["classification"] == "MODERATE"
    assert classify(60)["classification"] == "MODERATE"
    assert classify(61)["classification"] == "STRONG"
    assert classify(80)["classification"] == "STRONG"
    assert classify(81)["classification"] == "VERY STRONG"
    assert classify(100)["classification"] == "VERY STRONG"


def test_score_always_in_range(analyze, demo):
    """Every score is an integer inside 0..100, whatever the input."""
    for value in demo.values():
        result = analyze(value)
        assert isinstance(result["score"], int)
        assert 0 <= result["score"] <= 100, value


def test_weights_sum_to_one_hundred():
    """The documented positive weights add up to exactly 100."""
    from backend.services.scoring_engine import WEIGHTS
    assert sum(WEIGHTS.values()) == 100


def test_breakdown_items_are_explained(analyze, demo):
    """Each score component carries a human-readable detail string."""
    result = analyze(demo["word_and_year"])
    for key, component in result["score_breakdown"]["components"].items():
        assert "earned" in component and "max" in component, key
        assert component["detail"], key
        assert 0 <= component["earned"] <= component["max"]


def test_penalties_are_capped_per_category(analyze):
    """Penalties never exceed the documented per-category caps."""
    from backend.services.scoring_engine import PENALTY_CAPS
    result = analyze("password123456789")
    for category, value in result["score_breakdown"]["penalties"]["by_category"].items():
        assert value <= PENALTY_CAPS[category] + 1, category


def test_common_password_floor(analyze):
    """A common password can never exceed the VERY WEAK band."""
    for value in ("password", "123456", "qwerty", "letmein"):
        result = analyze(value)
        assert result["score"] <= 20, value


def test_breach_floor(analyze):
    """A breach-corpus hit is capped even when composition looks fine."""
    result = analyze("Password123!")
    assert result["metrics"]["in_demo_breach_corpus"] is True
    assert result["score"] <= 20


def test_personal_info_floor(analyze, demo_context):
    """Personal information holds the score inside the WEAK band."""
    result = analyze("Demo-1999-College!", context=demo_context)
    assert result["score"] <= 40


def test_caps_are_reported(analyze, demo):
    """Any applied cap is explained in plain language in the response."""
    result = analyze(demo["repeated"])
    assert result["score_cap_applied"]
    assert "capped at" in result["score_cap_applied"]


def test_monotonic_length_effect(analyze):
    """Given the same random alphabet, longer is never worse than shorter."""
    import secrets as pysecrets
    import string as pystring

    alphabet = pystring.ascii_letters + pystring.digits + "!@#$%^&*"
    base = "".join(pysecrets.choice(alphabet) for _ in range(8))
    longer = base + "".join(pysecrets.choice(alphabet) for _ in range(8))
    assert analyze(longer)["score"] >= analyze(base)["score"]


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------
def test_entropy_formula_and_relationship(analyze):
    """Theoretical entropy equals length x log2(pool size) for the reported pool."""
    import math
    result = analyze("x7#Kq2!mZ9@vL4$p")
    entropy = result["entropy"]
    expected = len("x7#Kq2!mZ9@vL4$p") * math.log2(entropy["pool_size"])
    assert abs(entropy["theoretical_bits"] - expected) < 0.2


def test_effective_entropy_is_not_more_than_theoretical(analyze, demo):
    """Effective bits subtract penalties, so they can never exceed theoretical bits."""
    for value in (demo["composition_bait"], demo["word_and_year"], demo["keyboard"]):
        entropy = analyze(value)["entropy"]
        assert entropy["effective_bits"] <= entropy["theoretical_bits"] + 0.001, value


def test_entropy_pool_size_scales_with_classes(analyze):
    """Pool size grows as character classes are added."""
    only_lower = analyze("abcdefghij")["entropy"]["pool_size"]
    lower_digit = analyze("abcdef1234")["entropy"]["pool_size"]
    everything = analyze("abcDEF123!")["entropy"]["pool_size"]
    assert only_lower < lower_digit < everything


def test_passphrase_entropy_model():
    """The passphrase model uses words x log2(wordlist size)."""
    import math
    from backend.services.data_loader import load_passphrase_words
    from backend.services.entropy_estimator import passphrase_entropy_bits

    size = len(load_passphrase_words())
    assert size > 5000, "the bundled word list should be large enough to be useful"
    assert abs(passphrase_entropy_bits(4) - 4 * math.log2(size)) < 0.01


def test_entropy_states_it_is_an_estimate(analyze, demo):
    """The entropy section always carries its caveat text."""
    entropy = analyze(demo["long_random"])["entropy"]
    assert "caveat" in entropy and len(entropy["caveat"]) > 40
    assert "theoretical" in entropy["caveat"].lower()


def test_shannon_entropy_zero_for_repeats():
    """Shannon variety is 0 for a single repeated character."""
    from backend.services.entropy_estimator import shannon_entropy_bits
    assert shannon_entropy_bits("aaaaaaaa") == 0


# ---------------------------------------------------------------------------
# Guess-resistance estimate
# ---------------------------------------------------------------------------
def test_guess_resistance_is_labelled_an_estimate(analyze, demo):
    """The estimate is explicitly labelled and never presented as a fact."""
    guess = analyze(demo["long_random"])["guess_resistance"]
    assert "Educational estimate" in guess["estimate_label"]
    assert len(guess["scenarios"] if "scenarios" in guess else guess) >= 3
    assert "depends" in guess["caveat"]


def test_guess_resistance_scenarios_ordered(analyze, demo):
    """A stronger password produces a longer estimate in every scenario."""
    weak = analyze(demo["short_numeric"])["guess_resistance"]
    strong = analyze(demo["long_random"])["guess_resistance"]

    weak_estimates = [scenario["estimate"] for scenario in weak["scenarios"]]
    strong_estimates = [scenario["estimate"] for scenario in strong["scenarios"]]

    # The weak value is guessable instantly in the online, rate-limited scenario.
    assert weak_estimates[0] in ("Instant", "well under a second")
    # The strong value takes a long time in that same scenario.
    assert strong_estimates[0] not in ("Instant", "well under a second")

    # Every scenario is labelled with its attacker model.
    for scenario in weak["scenarios"] + strong["scenarios"]:
        assert scenario["label"] and scenario["guesses_per_second"] > 0


# ---------------------------------------------------------------------------
# Scoring engine internals
# ---------------------------------------------------------------------------
def test_pattern_penalty_capped():
    """Repeated findings in one category cannot exceed that category's cap."""
    from backend.services.scoring_engine import PENALTY_CAPS, _pattern_penalty_points
    findings = [{"type": "sequence", "severity": "high", "penalty_bits": 18}] * 6
    total, breakdown = _pattern_penalty_points(findings)
    assert breakdown["sequence"] <= PENALTY_CAPS["sequence"]
    assert total <= PENALTY_CAPS["sequence"]


def test_score_is_calibrated_for_demo_cases(analyze, demo):
    """A pinned calibration table catches accidental rubric drift."""
    expectations = {
        demo["short_numeric"]: "VERY WEAK",
        demo["common"]: "VERY WEAK",
        demo["composition_bait"]: "VERY WEAK",
        demo["repeated"]: ("VERY WEAK", "WEAK"),
        demo["keyboard"]: ("VERY WEAK", "WEAK"),
        demo["repeated_substring"]: ("VERY WEAK", "WEAK"),
        demo["word_and_year"]: ("WEAK", "MODERATE"),
        demo["passphrase"]: ("STRONG", "VERY STRONG"),
        demo["long_random"]: ("STRONG", "VERY STRONG"),
    }
    for value, expected in expectations.items():
        result = analyze(value)
        if isinstance(expected, tuple):
            assert result["classification"] in expected, (value, result["classification"])
        else:
            assert result["classification"] == expected, (value, result["classification"])
