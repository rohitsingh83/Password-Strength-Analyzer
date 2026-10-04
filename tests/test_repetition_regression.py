"""
tests/test_repetition_regression.py
--------------------------------------------------------------------------
PURPOSE
    Regression tests for the repetition detector.

WHY THIS FILE EXISTS
    An earlier version of `detect_repetition()` compared the LOWERCASED password
    when looking for repeated blocks. That made these two different strings look
    identical:

        "jdDjDd"  ->  "jddjdd"   reported as "a 3-character block repeated twice"
        "abcabc"  ->  "abcabc"   correctly reported

    The first is a false positive: changing the case of a character adds a real
    choice for an attacker, so "jdD" followed by "jDd" is not a repetition of
    the same block. Random, high-entropy strings hit it often enough to matter
    (it dragged a 256-character random value from ~86 down to ~52).

    These tests pin the corrected, case-sensitive behaviour, prove the detector
    still catches genuine repeats, and prove a 256-character value is never
    capped by an arbitrary length limit.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import json
import pathlib
import subprocess

import pytest

from backend.services.pattern_detector import detect_repetition
from tests.helpers import deterministic_long_value

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "expected_results.json"


def _types(findings):
    return [f["type"] for f in findings]


# ---------------------------------------------------------------------------
# 1. The false positive is gone
# ---------------------------------------------------------------------------
def test_case_only_differences_are_not_reported_as_a_repeat():
    """`jdDjDd` is two different blocks, not one repeated block."""
    assert "repeated_substring" not in _types(detect_repetition("jdDjDd"))


@pytest.mark.parametrize("value", [
    "jdDjDd",                # the original false positive
    "KldixYLn3KNQKaZK",      # a realistic random-looking slice
    "aBcAbC",                # alternating case of the same letters
    "Xy7xY7",                # digits + letters, case-only difference
])
def test_casing_variants_are_not_flagged(value):
    assert "repeated_substring" not in _types(detect_repetition(value))


def test_long_pattern_free_value_is_very_strong():
    """
    A 256-character pattern-free value must score VERY STRONG.

    This is the case that exposed the bug: an unlucky random draw containing a
    case-only "repeat" lost 12 points and two whole bands.
    """
    from backend.services.password_analyzer import analyze_password

    result = analyze_password(deterministic_long_value(256))
    assert result["metrics"]["length"] == 256
    assert result["score"] >= 81, (result["score"], result["findings"])
    assert result["classification"] == "VERY STRONG"


def _function_body(source: str, start_marker: str, end_marker: str) -> str:
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    return source[start:end]


def test_both_engines_compare_blocks_exactly_and_use_the_case_echo_rule():
    """
    Guard the two things the fix introduced:

      1. blocks are compared using the ORIGINAL characters (not a lower-cased
         copy of the whole value, which is what caused the false positives), and
      2. the narrow "case echo" escape hatch is present in both engines.
    """
    python_body = _function_body(
        (REPO_ROOT / "backend/services/pattern_detector.py").read_text(encoding="utf-8"),
        "def detect_repetition(", "def detect_sequences(")
    js_body = _function_body(
        (REPO_ROOT / "frontend/js/engine.js").read_text(encoding="utf-8"),
        "function detectRepetition(", "function detectPredictableStructure(")

    # 1. no whole-value lower-casing inside the repetition detector
    assert "lowered" not in python_body
    assert "const lowered" not in js_body

    # 2. the case-echo rule exists in both engines, and both compare raw blocks
    assert "_case_echo(" in python_body and "def _case_echo(" in (
        REPO_ROOT / "backend/services/pattern_detector.py").read_text(encoding="utf-8")
    assert "caseEcho(" in js_body
    assert "password[start + repeats * size: start + (repeats + 1) * size] == block" in python_body
    assert 'chars.slice(start + repeats * size, start + (repeats + 1) * size).join("") === block' in js_body


def test_fixture_file_contains_the_regression_cases():
    """
    The shared fixture (used by the JavaScript parity test) must cover the bug.

    If someone regenerates the fixtures with an older engine, parity would pass
    against the wrong behaviour -- so the cases are asserted to be present.
    """
    fixtures = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))["fixtures"]
    values = {entry["password"] for entry in fixtures}
    assert {"jdDjDd", "PassPass", "Ab1Ab1Ab1"} <= values


# ---------------------------------------------------------------------------
# 2. Genuine repetition is still detected
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("value", [
    "abcabc",            # classic 3-character block repeated
    "abcdefabcdef",      # 6-character block repeated
    "121212",            # numeric block repeated
    "PassPass",          # a word typed twice
    "aaaaaaaa",          # character run
    "Ab1Ab1Ab1",         # block repeated three times (-> high severity)
])
def test_real_repeats_are_still_detected(value):
    assert detect_repetition(value), value


def test_three_or_more_repeats_are_high_severity():
    findings = detect_repetition("Ab1Ab1Ab1")
    repeats = [f for f in findings if f["type"] == "repeated_substring"]
    assert repeats and repeats[0]["severity"] == "high"


def test_repetition_evidence_stays_masked():
    for finding in detect_repetition("PassPass"):
        assert set(finding["evidence"]) == {"\u2022"}


def test_repeated_blocks_do_not_make_a_password_strong():
    """A long string built from one repeated block must stay out of STRONG."""
    from backend.services.password_analyzer import analyze_password

    result = analyze_password("abcdabcdabcdabcdabcd")
    assert result["score"] < 61, result["score"]
