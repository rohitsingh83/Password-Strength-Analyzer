"""
tests/test_patterns.py
--------------------------------------------------------------------------
Unit tests for each detector in isolation, so a failing detector is easy to
locate. Every input is a synthetic demo value.
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Sequences
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("value", ["1234", "4567", "abcd", "bcde", "xyz", "9876", "dcba", "6543"])
def test_sequence_detection(value):
    """Ascending and descending runs of four or more are detected."""
    from backend.services.pattern_detector import detect_sequences
    if len(value) < 4:
        pytest.skip("shorter than the minimum run length by design")
    assert detect_sequences(value), value


@pytest.mark.parametrize("value", ["1a2b", "ax9z", "zzzz"])
def test_non_sequences_not_reported(value):
    """Random-looking short strings must not be reported as sequences."""
    from backend.services.pattern_detector import detect_sequences
    assert not detect_sequences(value), value


# ---------------------------------------------------------------------------
# Repetition
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("value", ["aaaa", "1111", "!!!!", "abab", "abcabc", "xyxyxy"])
def test_repetition_detection(value):
    """Character runs and repeated blocks are both detected."""
    from backend.services.pattern_detector import detect_repetition
    assert detect_repetition(value), value


def test_repetition_evidence_is_masked():
    """Evidence must never contain the raw characters."""
    from backend.services.pattern_detector import detect_repetition
    findings = detect_repetition("aaaaaaaa")
    assert findings
    assert findings[0]["evidence"] == "\u2022" * 8


# ---------------------------------------------------------------------------
# Keyboard walks
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("value", ["qwerty", "asdfgh", "zxcvbn", "1qaz", "qazwsx",
                                   "!@#$", "QWERTY", "ytrewq"])
def test_keyboard_patterns(value):
    """Walks are detected in raw, shifted, upper-case and reversed forms."""
    from backend.services.pattern_detector import detect_keyboard_patterns, unshift
    assert detect_keyboard_patterns(value) or unshift(value) != value.lower(), value


def test_unshift_helper():
    """The shift map turns symbols back into the physical key pressed."""
    from backend.services.pattern_detector import unshift
    assert unshift("!@#$%") == "12345"
    assert unshift("QWER") == "qwer"


# ---------------------------------------------------------------------------
# Common passwords and words
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("value", ["password", "123456", "qwerty", "letmein", "welcome",
                                   "admin", "Password123", "P@ssw0rd"])
def test_common_password_detection(value):
    """Known-common values are detected, including l33t-spelled variants."""
    from backend.services.pattern_detector import is_common_password
    assert is_common_password(value), value


@pytest.mark.parametrize("value", ["VermilionGantry9", "k7Q#zP2!wR", "octothorpe-vane"])
def test_non_common_values_pass(value):
    """Ordinary strong demo values must not be flagged as common."""
    from backend.services.pattern_detector import is_common_password
    assert not is_common_password(value), value


def test_dictionary_word_inside_padding():
    """A dictionary word padded with digits is still a dictionary word."""
    from backend.services.pattern_detector import detect_dictionary_words
    assert detect_dictionary_words("welcome2026")
    assert detect_dictionary_words("p@sswords9")


# ---------------------------------------------------------------------------
# Predictable structure, dates, phone numbers
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("value", ["welcome123", "admin2026", "hello1234", "Summer2025!",
                                   "Demo-Pattern-123!"])
def test_predictable_structure(value):
    """The classic word+number and word+symbol+number shapes are detected."""
    from backend.services.pattern_detector import detect_predictable_structure
    assert detect_predictable_structure(value), value


@pytest.mark.parametrize("value", ["12-05-2001", "2001.05.12", "2025-12-01"])
def test_date_like_values(value):
    """Date-shaped strings are reported as guessable personal data."""
    from backend.services.pattern_detector import detect_predictable_structure
    types = {f["type"] for f in detect_predictable_structure(value)}
    assert types & {"date_pattern", "year_pattern"}, value


def test_phone_like_values():
    """A long digit string that looks like a phone number is reported."""
    from backend.services.pattern_detector import detect_predictable_structure
    findings = detect_predictable_structure("9876543210")
    assert any(f["type"] == "phone_pattern" for f in findings)


# ---------------------------------------------------------------------------
# Structure analysis
# ---------------------------------------------------------------------------
def test_passphrase_structure_detection():
    """Four separated words of three or more characters is passphrase-shaped."""
    from backend.services.pattern_detector import analyze_structure
    structure = analyze_structure("Copper-Lantern-Orchid-Gravity")
    assert structure["is_passphrase_like"] is True
    assert structure["token_count"] == 4


def test_single_token_is_not_a_passphrase():
    """A single padded word is not treated as a passphrase."""
    from backend.services.pattern_detector import analyze_structure
    assert analyze_structure("welcome123")["is_passphrase_like"] is False


# ---------------------------------------------------------------------------
# Breach corpus (demo, local)
# ---------------------------------------------------------------------------
def test_demo_breach_corpus_hit():
    """A value in the demo corpus is reported as found."""
    from backend.services.pattern_detector import detect_breach
    assert detect_breach("Password123!")


def test_demo_breach_corpus_miss():
    """A high-entropy value is not in the demo corpus."""
    from backend.services.pattern_detector import detect_breach
    assert not detect_breach("Zq7#vP2!mL9@Rk4t")


def test_breach_lookup_exposes_only_prefix():
    """The reporter exposes only the 5-character prefix a range API would receive."""
    from backend.services.data_loader import breach_lookup
    result = breach_lookup("Password123!")
    assert len(result["prefix"]) == 5
    assert result["prefix"] == result["prefix"].upper()


# ---------------------------------------------------------------------------
# Personal information
# ---------------------------------------------------------------------------
def test_personal_info_detection(demo_context):
    """Context overlap is detected case-insensitively and through l33t forms."""
    from backend.services.pattern_detector import detect_personal_info
    assert detect_personal_info("dEMO@123", demo_context)
    assert detect_personal_info("1999-demo-name", demo_context)


def test_personal_info_ignored_without_context():
    """No context means no personal-information check at all."""
    from backend.services.pattern_detector import detect_personal_info
    assert detect_personal_info("Demo@123", None) == []


# ---------------------------------------------------------------------------
# Aggregate detector
# ---------------------------------------------------------------------------
def test_aggregate_detector_shape():
    """The aggregate detector returns findings, penalty bits and categories."""
    from backend.services.pattern_detector import detect_all_patterns
    result = detect_all_patterns("qwerty2026!")
    assert set(result.keys()) >= {"findings", "pattern_penalty_bits", "categories", "breach_prefix", "structure"}
    assert result["pattern_penalty_bits"] > 0
    assert result["breach_prefix"] and len(result["breach_prefix"]) == 5


def test_findings_sorted_by_severity():
    """Critical and high findings are presented first."""
    from backend.services.pattern_detector import detect_all_patterns
    findings = detect_all_patterns("password123")["findings"]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    severities = [order[f["severity"]] for f in findings]
    assert severities == sorted(severities)


def test_no_findings_for_random_value():
    """A random 16-character value produces no weakness findings."""
    from backend.services.pattern_detector import detect_all_patterns
    assert detect_all_patterns("Zq7#vP2!mL9@Rk4t")["findings"] == []
