"""
tests/test_hashing_demo.py
--------------------------------------------------------------------------
Tests for the SEPARATE password-hashing teaching module.

The point of these tests is twofold:
  1. The demonstration must actually work (hashing, salting, verification).
  2. It must stay isolated from the analyzer, so a real submitted value can
     never be funnelled into a persistent password store.
"""

from __future__ import annotations

import inspect


def test_hash_and_verify_round_trip():
    """The correct value verifies; a wrong value does not."""
    from backend.services.password_hashing_demo import DEMO_PASSWORD, hash_password, verify_password

    record = hash_password(DEMO_PASSWORD)
    assert verify_password(DEMO_PASSWORD, record) is True
    assert verify_password(DEMO_PASSWORD + "x", record) is False
    assert verify_password("", record) is False


def test_salt_is_random_per_record():
    """The same value hashed twice yields different salt and hash values."""
    from backend.services.password_hashing_demo import (
        DEMO_PASSWORD, hash_password, verify_password,
    )

    first = hash_password(DEMO_PASSWORD)
    second = hash_password(DEMO_PASSWORD)
    assert first["salt_b64"] != second["salt_b64"]
    assert first["hash_b64"] != second["hash_b64"]
    assert verify_password(DEMO_PASSWORD, first)
    assert verify_password(DEMO_PASSWORD, second)


def test_no_plaintext_in_stored_record():
    """The stored record must not contain the plaintext value."""
    from backend.services.password_hashing_demo import DEMO_PASSWORD, hash_password

    record = hash_password(DEMO_PASSWORD)
    assert DEMO_PASSWORD not in str(record)


def test_encoded_record_is_self_describing():
    """Algorithm and parameters travel with the hash so it can be upgraded later."""
    from backend.services.password_hashing_demo import DEMO_PASSWORD, hash_password

    record = hash_password(DEMO_PASSWORD, algorithm="scrypt")
    assert record["encoded"].startswith("scrypt$")
    assert "n=" in record["encoded"]

    pbkdf2 = hash_password(DEMO_PASSWORD, algorithm="pbkdf2")
    assert pbkdf2["encoded"].startswith("pbkdf2_sha256$")
    assert pbkdf2["params"]["iterations"] >= 600_000


def test_slow_hash_is_slower_than_a_fast_hash():
    """The demonstration must show that a KDF costs measurably more than SHA-256 alone."""
    from backend.services.password_hashing_demo import DEMO_PASSWORD, hash_password

    slow = hash_password(DEMO_PASSWORD, algorithm="scrypt")
    fast = hash_password(DEMO_PASSWORD, algorithm="sha256_fast")
    assert slow["duration_ms"] > fast["duration_ms"]


def test_fast_hashes_are_flagged_as_anti_patterns():
    """Using MD5 or plain SHA-256 for password storage is labelled as wrong."""
    from backend.services.password_hashing_demo import DEMO_PASSWORD, hash_password

    for algorithm in ("md5_fast", "sha256_fast"):
        params = hash_password(DEMO_PASSWORD, algorithm=algorithm)["params"]
        assert "DO NOT use this for real password storage" in params["warning"]


def test_demonstration_is_complete_and_labelled():
    """The walk-through covers every algorithm, both verification paths and lessons."""
    from backend.services.password_hashing_demo import demonstration

    report = demonstration()
    algorithms = {step["algorithm"] for step in report["steps"]}
    assert {"scrypt", "pbkdf2", "sha256_fast", "md5_fast"} <= algorithms
    for step in report["steps"]:
        assert step["verify_correct_password"] is True
        assert step["verify_wrong_password"] is False
        assert step["salt_changed_output"] is True
        assert step["guidance"]
    assert len(report["lessons"]) >= 4
    assert "SYNTHETIC" in report["demo_password_label"]


def test_argon2id_guidance_is_documented():
    """The recommended modern option is described with concrete parameters."""
    from backend.services.password_hashing_demo import argon2id_guidance

    guidance = argon2id_guidance()
    assert guidance["recommended"] == "Argon2id"
    assert "argon2-cffi" in guidance["install"]
    assert "PasswordHasher" in guidance["example"]
    assert set(guidance["peer_options"]) == {"bcrypt", "scrypt", "pbkdf2"}


def test_uses_standard_library_only():
    """No third-party hashing dependency is required for the demonstration."""
    from backend.services import password_hashing_demo as module

    source = inspect.getsource(module)
    assert "import hashlib" in source
    assert "import hmac" in source
    assert "import os" in source
    assert "bcrypt" not in source.split("argon2id_guidance")[0]   # only mentioned in guidance text


def test_constant_time_comparison_is_used():
    """Verification must use a timing-safe comparison."""
    from backend.services import password_hashing_demo as module

    source = inspect.getsource(module.verify_password)
    assert "compare_digest" in source


def test_hashing_module_is_not_used_by_the_analyzer():
    """The analyzer must not import the hashing demo: analysis never stores values."""
    from backend.services import password_analyzer as analyzer_module
    from backend.services import pattern_detector as detector_module

    assert "password_hashing_demo" not in inspect.getsource(analyzer_module)
    assert "password_hashing_demo" not in inspect.getsource(detector_module)


def test_demo_salt_pair_shows_different_outputs():
    """Two salts over the same value produce unrelated stored hashes."""
    from backend.services.password_hashing_demo import generate_demo_salt_pair

    pair = generate_demo_salt_pair()
    assert pair["salt_1"] != pair["salt_2"]
    assert pair["hash_1"] != pair["hash_2"]
    assert "different" in pair["conclusion"].lower()
    assert "hidden" in pair["same_password"].lower()


def test_refuses_empty_input():
    """Hashing an empty value is a programming error, not a valid call."""
    import pytest

    from backend.services.password_hashing_demo import hash_password

    with pytest.raises(ValueError):
        hash_password("")
