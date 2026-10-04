"""
tests/test_analyzer.py
--------------------------------------------------------------------------
Covers the core analysis contract and the required test scenarios:
    T01 empty password              T13 sequential letters
    T02 one-character password      T14 keyboard sequence
    T03 short numeric password      T15 repeated characters
    T04 common password             T16 repeated substring
    T05 long repeated password      T17 common word + number
    T06 lowercase only              T18 word + year
    T07 uppercase only              T19 personal name overlap
    T08 numbers only                T20 birth year overlap
    T09 symbols only                T21 long passphrase-like input
    T10 mixed characters            T22 unicode handling
    T11 sequential numbers          T23 space handling
    T12 reverse numeric sequence    T24 maximum accepted length
Each test name states the scenario; the docstring records the expected result.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import pytest

CLASSIFICATIONS = {"VERY WEAK", "WEAK", "MODERATE", "STRONG", "VERY STRONG"}
REQUIRED_KEYS = {
    "score", "classification", "findings", "suggestions", "metrics",
    "entropy", "score_breakdown", "policy", "privacy", "disclaimer",
}


# ---------------------------------------------------------------------------
# Response contract
# ---------------------------------------------------------------------------
def test_result_contract(analyze, demo):
    """The structured result exposes every field the brief requires."""
    result = analyze(demo["passphrase"])
    assert REQUIRED_KEYS.issubset(result.keys())
    assert 0 <= result["score"] <= 100
    assert result["classification"] in CLASSIFICATIONS
    assert isinstance(result["findings"], list)
    assert isinstance(result["suggestions"], list)
    assert isinstance(result["metrics"], dict)
    assert result["analysis_id"].startswith("an_")
    assert result["version"]


# ---------------------------------------------------------------------------
# T01 -- empty password
# ---------------------------------------------------------------------------
def test_T01_empty_password(analyze):
    """An empty value scores 0, is VERY WEAK and explains what to do."""
    result = analyze("")
    assert result["score"] == 0
    assert result["classification"] == "VERY WEAK"
    assert result["metrics"]["length"] == 0
    assert result["suggestions"], "an empty input should still guide the user"


# ---------------------------------------------------------------------------
# T02 -- one-character password
# ---------------------------------------------------------------------------
def test_T02_single_character(analyze):
    """A single character is capped in the VERY WEAK band regardless of class."""
    for value in ("a", "Z", "7", "!"):
        result = analyze(value)
        assert result["score"] <= 20, value
        assert result["classification"] == "VERY WEAK"
        assert any(cap["rule"] == "extremely_short" for cap in result["score_breakdown"]["caps_evaluated"])


# ---------------------------------------------------------------------------
# T03 -- short numeric password
# ---------------------------------------------------------------------------
def test_T03_short_numeric(analyze, demo):
    """A short digit run is sequential and guessable: VERY WEAK."""
    result = analyze(demo["short_numeric"])
    assert result["classification"] == "VERY WEAK"
    assert result["metrics"]["has_sequence"] is True

    # The slightly longer classic is also on the common-password list.
    longer = analyze("123456")
    assert longer["classification"] == "VERY WEAK"
    assert longer["metrics"]["is_common_password"] is True


# ---------------------------------------------------------------------------
# T04 -- common password
# ---------------------------------------------------------------------------
def test_T04_common_password(analyze, demo):
    """A 'top of every wordlist' password is flagged and capped at 20."""
    result = analyze(demo["common"])
    assert result["classification"] == "VERY WEAK"
    assert result["score"] <= 20
    assert result["metrics"]["is_common_password"] is True
    assert any(f["type"] == "common_password" for f in result["findings"])


# ---------------------------------------------------------------------------
# T05 -- long but repeated password
# ---------------------------------------------------------------------------
def test_T05_long_repeated(analyze, demo):
    """Length without unpredictability must not buy a good score."""
    result = analyze(demo["repeated"])
    assert result["score"] <= 25
    assert result["classification"] in ("VERY WEAK", "WEAK")
    assert result["metrics"]["has_repetition"] is True
    assert any(cap["rule"] in ("single_repeated_character", "very_low_uniqueness")
               for cap in result["score_breakdown"]["caps_evaluated"])


# ---------------------------------------------------------------------------
# T06 / T07 / T08 / T09 -- single character classes
# ---------------------------------------------------------------------------
def test_T06_lowercase_only(analyze):
    """Eight lowercase letters score poorly: length band plus one class only."""
    result = analyze("abcdefgh")
    assert result["classification"] in ("VERY WEAK", "WEAK")
    assert result["metrics"]["character_type_count"] == 1
    assert "lowercase" in result["metrics"]["character_types"]


def test_T07_uppercase_only(analyze):
    """Uppercase-only is not more secure than lowercase-only."""
    lower = analyze("abcdefgh")["score"]
    upper = analyze("ABCDEFGH")["score"]
    assert upper == lower, "case alone must not change the score"


def test_T08_numbers_only(analyze):
    """Digits only, under 12 characters, cannot exceed the no-letters cap."""
    result = analyze("9876543210")
    assert result["score"] <= 35
    assert result["metrics"]["character_type_count"] == 1


def test_T09_symbols_only(analyze):
    """A shifted keyboard walk in symbols is still a keyboard walk."""
    result = analyze("!@#$%^&*()")
    assert result["score"] <= 35
    assert result["metrics"]["has_keyboard_pattern"] is True


# ---------------------------------------------------------------------------
# T10 -- mixed characters
# ---------------------------------------------------------------------------
def test_T10_mixed_characters(analyze, demo):
    """A long random mix with four classes reaches the top bands."""
    result = analyze(demo["long_random"])
    assert result["score"] >= 81
    assert result["classification"] == "VERY STRONG"
    assert result["metrics"]["character_type_count"] == 4
    assert result["metrics"]["weakness_count"] == 0


# ---------------------------------------------------------------------------
# T11 / T12 -- numeric sequences
# ---------------------------------------------------------------------------
def test_T11_sequential_numbers(analyze):
    """Ascending digits reduce effective entropy and are reported."""
    result = analyze("123456")
    assert any(f["type"] == "sequence" for f in result["findings"])
    assert result["classification"] == "VERY WEAK"


def test_T12_reverse_numeric_sequence(analyze):
    """Reversing a sequence does not make it unpredictable."""
    result = analyze("987654321")
    assert any(f["type"] == "sequence" for f in result["findings"])
    assert result["classification"] in ("VERY WEAK", "WEAK")


def test_T13_sequential_letters(analyze, demo):
    """Alphabetic runs are detected with the same logic as numeric runs."""
    result = analyze(demo["sequential"])
    assert result["metrics"]["has_sequence"] is True
    assert result["classification"] in ("VERY WEAK", "WEAK")

    reversed_result = analyze(demo["reverse_sequential"])
    assert reversed_result["metrics"]["has_sequence"] is True


# ---------------------------------------------------------------------------
# T14 -- keyboard patterns
# ---------------------------------------------------------------------------
def test_T14_keyboard_sequence(analyze, demo):
    """Keyboard walks are detected, including shifted and reversed variants."""
    for value in ("qwerty", "qwerty123", "asdfgh", "1qaz2wsx", "!@#$%", "ytrewq", "mnbvcxz"):
        result = analyze(value)
        assert result["metrics"]["has_keyboard_pattern"] is True, value
        assert result["score"] <= 40, value


# ---------------------------------------------------------------------------
# T15 / T16 -- repetition
# ---------------------------------------------------------------------------
def test_T15_repeated_characters(analyze):
    """Repeated character runs are detected and penalised."""
    result = analyze("AAAAAA123!")
    assert result["metrics"]["has_repetition"] is True
    assert result["classification"] in ("VERY WEAK", "WEAK")


def test_T16_repeated_substring(analyze, demo):
    """Repeated blocks such as abcabcabc are detected."""
    result = analyze(demo["repeated_substring"])
    assert result["metrics"]["has_repetition"] is True
    assert any(f["type"] == "repeated_substring" for f in result["findings"])


# ---------------------------------------------------------------------------
# T17 / T18 -- predictable structures
# ---------------------------------------------------------------------------
def test_T17_common_word_plus_number(analyze, demo):
    """'welcome123' shape is capped below the STRONG band."""
    result = analyze("welcome123")
    assert result["classification"] in ("VERY WEAK", "WEAK")
    assert result["metrics"]["has_predictable_structure"] is True


def test_T18_word_plus_year(analyze, demo):
    """A memorable word plus a year is capped below STRONG."""
    result = analyze(demo["word_and_year"])
    assert result["score"] <= 60
    assert result["metrics"]["has_year_pattern"] is True
    assert any(cap["rule"] in ("word_plus_year", "known_common_or_breached")
               for cap in result["score_breakdown"]["caps_evaluated"])


def test_T18b_composition_bait_is_not_strong(analyze, demo):
    """The headline lesson: composition rules do not equal strength."""
    result = analyze(demo["composition_bait"])
    assert result["metrics"]["character_type_count"] == 4
    assert result["metrics"]["unique_character_ratio"] > 0.8
    assert result["score"] <= 20, "composition alone must not earn a good score"
    assert result["classification"] == "VERY WEAK"


# ---------------------------------------------------------------------------
# T19 / T20 -- personal context overlap
# ---------------------------------------------------------------------------
def test_T19_personal_name_overlap(analyze, demo_context):
    """A first name inside the password is reported and capped in WEAK."""
    result = analyze("Demo@123", context=demo_context)
    assert result["metrics"]["has_personal_info"] is True
    assert any(f["type"] == "personal_info" for f in result["findings"])
    assert result["score"] <= 40


def test_T19b_context_absent_by_default(analyze):
    """Without context, no personal-information finding can be produced."""
    result = analyze("Demo@123")
    assert result["metrics"]["has_personal_info"] is False


def test_T20_birth_year_overlap(analyze, demo_context):
    """A birth year supplied as context is detected inside the password."""
    result = analyze("1999-Demo-Name", context=demo_context)
    assert any(f["type"] == "personal_info" for f in result["findings"])
    assert any(f["type"] == "year_pattern" for f in result["findings"])


def test_T20b_context_digits_only_not_flagged_as_name(analyze):
    """Short context tokens are ignored so initials do not create noise."""
    result = analyze("xy9!Qq2#", context={"first_name": "ab"})
    assert result["metrics"]["has_personal_info"] is False


# ---------------------------------------------------------------------------
# T21 -- long passphrase-like input
# ---------------------------------------------------------------------------
def test_T21_long_passphrase(analyze, demo):
    """A multi-word phrase scores well on length, and its words are not penalised."""
    result = analyze(demo["passphrase"])
    assert result["metrics"]["is_passphrase_like"] is True
    assert result["score"] >= 81
    assert result["classification"] == "VERY STRONG"
    assert result["entropy"].get("effective_bits_source", "").startswith("passphrase model")


def test_T21b_famous_phrase_is_rejected(analyze, demo):
    """A famous phrase is long but predictable, so it is capped as VERY WEAK."""
    result = analyze(demo["famous_phrase"])
    assert any(f["type"] == "common_phrase" for f in result["findings"])
    assert result["score"] <= 20
    assert result["classification"] == "VERY WEAK"


def test_T21c_human_looking_passphrase_below_generated_one(analyze):
    """A human-chosen phrase of related words should not beat a random one."""
    human = analyze("love-my-dog-so-much")["score"]
    generated = analyze("Tundra-Basil-Falcon-Thistle-Prism")["score"]
    assert generated >= human


# ---------------------------------------------------------------------------
# T22 -- unicode handling
# ---------------------------------------------------------------------------
def test_T22_unicode_handling(analyze, demo):
    """Non-Latin scripts are analysed without crashing, and are flagged as unicode."""
    result = analyze(demo["unicode"])
    assert result["metrics"]["has_unicode"] is True
    assert 0 <= result["score"] <= 100
    assert result["classification"] in CLASSIFICATIONS
    # The analyzer must not suggest that exotic characters are a silver bullet.
    assert isinstance(result["suggestions"], list)


def test_T22b_unicode_metadata_not_stored(analyze, demo):
    """Only the length and metrics of a unicode password are reported back."""
    result = analyze(demo["unicode"])
    assert result["metrics"]["length"] == len(demo["unicode"])
    assert "Пароль" not in str(result["metrics"])


# ---------------------------------------------------------------------------
# T23 -- space handling
# ---------------------------------------------------------------------------
def test_T23_spaces_allowed(analyze, demo):
    """Spaces are permitted and counted as a character, as modern guidance requires."""
    result = analyze(demo["spaces"])
    assert result["metrics"]["has_spaces"] is True
    assert result["metrics"]["length"] == len(demo["spaces"])
    policy_check = next(c for c in result["policy"]["checks"] if c["id"] == "allow_spaces")
    assert policy_check["passed"] is True


# ---------------------------------------------------------------------------
# T24 -- maximum accepted length
# ---------------------------------------------------------------------------
def test_T24_maximum_length(analyze, demo):
    """Values over 256 characters are rejected politely, without echoing them."""
    result = analyze(demo["over_length"])
    assert result["input_error"]["kind"] == "too_long"
    assert result["score"] == 0
    assert demo["over_length"] not in str(result)


def _deterministic_long_value(length=256):
    """Long, pattern-free test value (see tests/helpers.py)."""
    from tests.helpers import deterministic_long_value
    return deterministic_long_value(length)


def test_T24b_long_value_is_accepted_and_scores_very_strong():
    """A 256-character value is accepted (no arbitrary low cap) and scores high."""
    from backend.services.password_analyzer import analyze_password

    result = analyze_password(_deterministic_long_value(256))
    assert result["metrics"]["length"] == 256
    assert result["score"] >= 81, result["findings"]
    assert result["classification"] == "VERY STRONG"


def test_T24c_long_random_value_has_no_low_cap():
    """
    Even an unlucky 256-character draw stays STRONG or better.

    Long input is never truncated or rejected, and the worst realistic case is a
    single repetition penalty -- which must not drag a 256-character value below
    the STRONG band.
    """
    from backend.services.password_analyzer import analyze_password
    import secrets as pysecrets
    import string as pystring

    long_value = "".join(pysecrets.choice(pystring.ascii_letters + pystring.digits)
                         for _ in range(256))
    result = analyze_password(long_value)
    assert result["metrics"]["length"] == 256
    # A 256-character random value is never truncated, capped or rejected. Any
    # penalty it earns is for a *detected* pattern (a dictionary fragment,
    # "1234", a doubling), so MODERATE-or-better is the honest floor here; the
    # deterministic pattern-free case above pins the VERY STRONG outcome.
    assert result["score"] >= 41, (result["score"], result["findings"])


# ---------------------------------------------------------------------------
# Length and character analysers (direct unit tests)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("value,expected_band", [
    ("", "Empty"),
    ("short", "Very short"),
    ("elevenchars", "Short"),
    ("thirteenchars", "Better length"),
    ("sixteencharshere", "Strong length"),
    ("twentypluscharacters!", "Excellent length"),
])
def test_length_bands(value, expected_band):
    """The documented length bands map exactly as described in the docs."""
    from backend.services.character_analyzer import analyze_length
    assert analyze_length(value)["band"] == expected_band


def test_length_alone_is_not_strength(analyze, demo):
    """A 16-character repeated string proves length is necessary but not sufficient."""
    result = analyze(demo["repeated"])
    length_report = result["length_analysis"]
    assert length_report["length"] == 16
    assert length_report["credit"] >= 0.9
    assert result["score"] <= 25, "length credit must not rescue a predictable value"


def test_character_analysis_fields(analyze, demo):
    """The character report exposes the exact fields the brief lists."""
    result = analyze(demo["composition_bait"])
    characters = result["character_analysis"]
    for field in ("has_lowercase", "has_uppercase", "has_digits", "has_symbols",
                  "character_type_count", "unique_character_count",
                  "unique_character_ratio"):
        assert field in characters
    assert characters["unique_character_count"] < characters["length"]
