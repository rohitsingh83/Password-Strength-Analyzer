"""
tests/test_suggestions.py
--------------------------------------------------------------------------
Suggestion-engine tests (T26): suggestions must be specific, prioritised,
password-free and always include the hygiene essentials.
"""

from __future__ import annotations

VAGUE_PHRASES = [
    "make it stronger",
    "make your password stronger",
    "use a strong password",
    "be more secure",
    "try harder",
]


def test_T26_suggestions_generated(analyze, demo):
    """Every weak finding produces at least one specific suggestion."""
    result = analyze(demo["common"])
    assert len(result["suggestions"]) >= 3
    for suggestion in result["suggestions"]:
        assert suggestion["title"] and suggestion["action"]
        assert suggestion["priority"] in ("high", "medium", "low")
        assert suggestion["weakness"]


def test_suggestions_are_specific_not_generic(analyze, demo):
    """No suggestion may be the useless 'make it stronger' style advice."""
    for value in (demo["composition_bait"], demo["short_numeric"], demo["word_and_year"]):
        result = analyze(value)
        for suggestion in result["suggestions"]:
            text = (suggestion["title"] + " " + suggestion["action"]).lower()
            for vague in VAGUE_PHRASES:
                assert vague not in text, (value, suggestion["title"])
            assert len(suggestion["action"]) > 40, "actions must be concrete"


def test_suggestions_never_contain_the_password(analyze, demo):
    """Not a single suggestion may echo the submitted value."""
    probe = demo["probe"]
    result = analyze(probe)
    blob = str(result["suggestions"])
    assert probe not in blob
    # The masked evidence of findings may appear, but only as bullets.
    for suggestion in result["suggestions"]:
        assert probe not in suggestion.get("detected", "")


def test_high_priority_first(analyze, demo):
    """The most important suggestion is presented first."""
    result = analyze(demo["common"])
    assert result["suggestions"][0]["priority"] == "high"


def test_specific_weakness_advice(analyze):
    """Each detected weakness family maps to its own tailored advice."""
    expectations = {
        "123456": "sequence",
        "qwerty123": "keyboard_pattern",
        "aaaaaaaaaaaa": "repeated_characters",
        "welcome123": "predictable_structure",
    }
    for value, weakness in expectations.items():
        result = analyze(value)
        weaknesses = {s["weakness"] for s in result["suggestions"]}
        assert weakness in weaknesses, (value, weaknesses)


def test_personal_information_advice(analyze, demo_context):
    """Overlapping personal information produces its own warning."""
    result = analyze("Demo@1234", context=demo_context)
    assert any(s["weakness"] == "personal_info" for s in result["suggestions"])


def test_hygiene_advice_always_present(analyze, demo):
    """Reuse, password managers and MFA are always mentioned (awareness duty)."""
    result = analyze(demo["long_random"])
    text = " ".join(s["action"].lower() for s in result["suggestions"])
    assert "reus" in text
    assert "password manager" in text
    assert "mfa" in text


def test_hygiene_can_be_disabled(analyze, demo):
    """include_hygiene=False keeps the list focused on detected weaknesses."""
    from backend.services.password_analyzer import analyze_password
    result = analyze_password(demo["long_random"], include_hygiene=False)
    weaknesses = {s["weakness"] for s in result["suggestions"]}
    assert "awareness" not in weaknesses


def test_length_advice_for_short_values(analyze):
    """Short values get the length/passphrase suggestion."""
    result = analyze("Tq9!x")
    text = " ".join(s["action"].lower() for s in result["suggestions"])
    assert "longer password or a passphrase" in text


def test_generator_suggestion_for_weak_values(analyze, demo):
    """Weak values are pointed at the secure generator."""
    result = analyze(demo["short_numeric"])
    assert any(s["weakness"] == "generator" for s in result["suggestions"])


def test_passphrase_guidance_present(analyze, demo):
    """The response always includes passphrase education with a 'do not reuse' warning."""
    result = analyze(demo["composition_bait"])
    guidance = result["passphrase_guidance"]
    assert guidance["recommended_words"] >= 4
    warning = guidance["warning"].lower()
    assert "do not reuse" in warning or "never reuse" in warning
    assert guidance["four_word_entropy_bits"] > 40
    assert guidance["six_word_entropy_bits"] > guidance["four_word_entropy_bits"]


def test_no_suggestion_when_nothing_is_wrong(analyze):
    """A clean random value still gets hygiene advice but no weakness criticism."""
    result = analyze("Zq7#vP2!mL9@Rk4t")
    weaknesses = {s["weakness"] for s in result["suggestions"]}
    assert weaknesses <= {"awareness", "hygiene"}
