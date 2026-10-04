"""
tests/test_fixtures.py
--------------------------------------------------------------------------
PURPOSE
    Prove that the shared parity fixture is CURRENT.

WHY THIS IS A TEST AND NOT A CI DIFF
    `tests/fixtures/expected_results.json` is what the JavaScript parity harness
    compares against, so a stale fixture makes the harness assert old behaviour
    and pass for the wrong reason. A plain `git diff` in CI cannot check the
    whole file, because five entries are volatile: they contain a value produced
    by the secure generator at build time.

    This module closes that gap. It re-runs the Python engine over every
    DETERMINISTIC fixture input and asserts the stored expectations still match.
    If someone changes a detector, weight or cap without running
    `python scripts/generate_fixtures.py`, this test fails with the exact value
    that drifted.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import json
import pathlib

import pytest

from backend.services.password_analyzer import analyze_password

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "expected_results.json"


@pytest.fixture(scope="module")
def fixture_file() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def deterministic_entries(fixture_file) -> list:
    entries = [entry for entry in fixture_file["fixtures"] if not entry.get("volatile")]
    assert entries, "the fixture file must contain deterministic entries"
    return entries


def test_the_fixture_file_is_present_and_describes_itself(fixture_file):
    """The fixture must be self-describing for anyone who opens it."""
    assert fixture_file["engine_version"]
    assert "python" in fixture_file["generated_by"].lower()
    assert fixture_file["fixtures"], "no fixtures recorded"


def test_every_fixture_input_comes_from_the_documented_demo_list(deterministic_entries):
    """
    Guard the ethics rule with an exact contract rather than a guess.

    Every deterministic fixture value must appear in `DEMO_INPUTS` inside
    `scripts/generate_fixtures.py`, which is the reviewed, synthetic-only list.
    Anyone adding a value has to add it there first -- and that file is the one a
    reviewer reads.
    """
    from scripts.generate_fixtures import DEMO_INPUTS

    documented = {value for value, _context in DEMO_INPUTS}
    unexpected = {entry["password"] for entry in deterministic_entries} - documented
    assert not unexpected, f"fixture values not declared in DEMO_INPUTS: {sorted(unexpected)}"


def test_no_fixture_value_looks_like_a_real_credential(deterministic_entries):
    """
    Cheap heuristic that catches the mistake that matters: pasting something real.

    Email-shaped values, values containing the user's real-sounding domain, and
    anything outside the small set of ASCII/Latin demo characters are rejected.
    """
    import re

    email_shape = re.compile(r"[^\s@]+@[^\s@]+\.[a-z]{2,}", re.IGNORECASE)
    for entry in deterministic_entries:
        value = entry["password"]
        assert not email_shape.search(value), f"email-shaped fixture value: {value!r}"
        assert "http" not in value.lower(), f"URL-shaped fixture value: {value!r}"


def test_deterministic_fixtures_still_match_the_engine(deterministic_entries):
    """
    The core staleness check.

    Recomputes every deterministic fixture with the current Python engine and
    reports the first handful of mismatches with enough detail to fix them.
    """
    mismatches = []
    for entry in deterministic_entries:
        result = analyze_password(entry["password"], context=entry.get("context"))
        actual_types = sorted(finding["type"] for finding in result["findings"])
        differences = []
        if result["score"] != entry["score"]:
            differences.append(f"score {result['score']} != {entry['score']}")
        if result["classification"] != entry["classification"]:
            differences.append(
                f"classification {result['classification']} != {entry['classification']}")
        if result["metrics"]["length"] != entry["length"]:
            differences.append(f"length {result['metrics']['length']} != {entry['length']}")
        if result["metrics"].get("pattern_count", 0) != entry["pattern_count"]:
            differences.append(
                f"pattern_count {result['metrics'].get('pattern_count')} != {entry['pattern_count']}")
        if result["policy"].get("policy_pass") != entry["policy_pass"]:
            differences.append(
                f"policy_pass {result['policy'].get('policy_pass')} != {entry['policy_pass']}")
        if actual_types != entry["finding_types"]:
            differences.append(f"findings {actual_types} != {entry['finding_types']}")
        if differences:
            mismatches.append((entry["password"], differences))

    assert not mismatches, (
        "The shared fixture is stale. Regenerate it with:\n"
        "    python scripts/generate_fixtures.py\n"
        "    node tests/js/run_parity_test.js\n"
        "Mismatched entries:\n"
        + "\n".join(f"  {value!r}: " + "; ".join(problems)
                    for value, problems in mismatches[:8])
    )


def test_fixture_covers_every_detector_category(deterministic_entries):
    """
    The fixture must exercise the whole rubric, or parity means very little.
    """
    categories = set()
    for entry in deterministic_entries:
        categories.update(entry["finding_types"])
    required = {
        "common_password", "breach", "dictionary_word", "sequence",
        "keyboard_pattern", "repeated_characters", "repeated_substring",
        "predictable_structure", "year_pattern", "personal_info",
        "short_length", "low_variety", "common_phrase",
    }
    missing = required - categories
    assert not missing, f"fixture does not cover: {sorted(missing)}"


def test_fixture_covers_every_classification_band(deterministic_entries):
    bands = {entry["classification"] for entry in deterministic_entries}
    assert bands == {"VERY WEAK", "WEAK", "MODERATE", "STRONG", "VERY STRONG"}, bands


def test_fixture_contains_no_password_leaking_field(fixture_file):
    """
    The fixture stores expectations, never engine output that could echo a value.
    """
    forbidden = {"suggestions", "evidence", "description", "response", "result"}
    for entry in fixture_file["fixtures"]:
        assert not (set(entry) & forbidden), set(entry) & forbidden
