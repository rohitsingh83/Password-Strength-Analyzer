"""
tests/test_policy.py
--------------------------------------------------------------------------
Policy-checker tests: policy verdict must be independent of the strength
score, configurable by an administrator, and must reflect modern guidance.
"""

from __future__ import annotations


def test_policy_pass_and_fail_are_separate_from_score(analyze):
    """A strong password can fail a policy, and a predictable one can pass it."""
    from backend.services.policy_checker import PasswordPolicy

    # Strong value, strict legacy policy requiring every composition rule.
    strict = PasswordPolicy(name="strict", minimum_length=16, require_uppercase=True,
                            require_lowercase=True, require_digit=True, require_symbol=True,
                            min_unique_characters=10)
    result = analyze("Copper-Lantern-Orchid-Gravity", policy=strict)
    assert result["score"] >= 81
    assert result["policy"]["policy_pass"] is False
    assert result["policy"]["failure_count"] >= 1

    # Predictable value that happens to satisfy a permissive length-only policy.
    permissive = PasswordPolicy(name="permissive", minimum_length=4, min_unique_characters=2,
                               common_password_check=False)
    weak_result = analyze("Summer2025!", policy=permissive)
    assert weak_result["policy"]["policy_pass"] is True
    assert weak_result["classification"] in ("WEAK", "MODERATE")


def test_minimum_length_is_configurable(analyze):
    """The administrator's minimum length is enforced."""
    from backend.services.policy_checker import PasswordPolicy

    result = analyze("SixteenChars!9xy", policy=PasswordPolicy(minimum_length=20))
    length_check = next(c for c in result["policy"]["checks"] if c["id"] == "minimum_length")
    assert length_check["passed"] is False
    assert result["policy"]["policy_pass"] is False


def test_common_password_check_is_configurable(analyze):
    """Turning the blocklist off changes the verdict without changing the score."""
    from backend.services.policy_checker import PasswordPolicy

    on = analyze("password123", policy=PasswordPolicy(minimum_length=4, min_unique_characters=2,
                                                     common_password_check=True))
    off = analyze("password123", policy=PasswordPolicy(minimum_length=4, min_unique_characters=2,
                                                      common_password_check=False))
    assert on["policy"]["policy_pass"] is False
    assert off["policy"]["policy_pass"] is True
    assert on["score"] == off["score"], "a policy flag must not alter measured strength"


def test_personal_info_check_is_configurable(analyze, demo_context):
    """The optional context check can be disabled by policy."""
    from backend.services.policy_checker import PasswordPolicy

    enforced = analyze("Demo-Name-9xy!z", context=demo_context,
                       policy=PasswordPolicy(minimum_length=8, min_unique_characters=4,
                                             personal_info_check=True))
    skipped = analyze("Demo-Name-9xy!z", context=demo_context,
                      policy=PasswordPolicy(minimum_length=8, min_unique_characters=4,
                                            personal_info_check=False))
    assert enforced["policy"]["policy_pass"] is False
    assert skipped["policy"]["policy_pass"] is True


def test_modern_policy_does_not_force_rotation():
    """The default preset follows current guidance: no forced periodic expiry."""
    from backend.services.policy_checker import PRESET_POLICIES

    assert PRESET_POLICIES["standard_account"].password_expiry_days == 0
    assert PRESET_POLICIES["enterprise_iam"].password_expiry_days == 0


def test_legacy_preset_is_labelled_an_anti_pattern():
    """The legacy banking preset exists to demonstrate the outdated approach."""
    from backend.services.policy_checker import PRESET_POLICIES

    legacy = PRESET_POLICIES["legacy_bank"]
    assert legacy.require_uppercase and legacy.require_lowercase
    assert legacy.password_expiry_days == 90
    assert "anti-pattern" in legacy.name.lower()


def test_policy_checks_include_explanations(analyze):
    """Every policy check explains its own requirement and observed value."""
    result = analyze("TwelveChars1")
    for check in result["policy"]["checks"]:
        assert check["label"]
        assert check["detail"]
        assert isinstance(check["passed"], bool)


def test_spaces_policy(analyze):
    """A policy that disallows spaces fails a spaced passphrase."""
    from backend.services.policy_checker import PasswordPolicy

    result = analyze("with space passphrase here",
                     policy=PasswordPolicy(minimum_length=12, allow_spaces=False))
    space_check = next(c for c in result["policy"]["checks"] if c["id"] == "allow_spaces")
    assert space_check["passed"] is False


def test_strength_threshold_policy(analyze):
    """An enterprise policy can require a minimum strength score."""
    from backend.services.policy_checker import PasswordPolicy

    policy = PasswordPolicy(minimum_length=8, min_unique_characters=4, minimum_strength_score=81)
    weak = analyze("Summer2025!", policy=policy)
    strong = analyze("Copper-Lantern-Orchid-Gravity", policy=policy)
    assert weak["policy"]["policy_pass"] is False
    assert strong["policy"]["policy_pass"] is True


def test_policy_note_explains_the_distinction(analyze):
    """The response explains that policy and strength are different concepts."""
    result = analyze("SomeValue123!")
    assert "separate" in result["policy"]["note"].lower()


def test_policy_from_dict_ignores_unknown_keys():
    """An API client can post back a policy object it previously received."""
    from backend.services.policy_checker import PasswordPolicy

    policy = PasswordPolicy.from_dict({"minimum_length": 16, "unknown_future_field": True})
    assert policy.minimum_length == 16


def test_all_presets_are_reported_by_the_checker(analyze):
    """Every preset produces a complete verdict."""
    from backend.services.policy_checker import PRESET_POLICIES

    for name, policy in PRESET_POLICIES.items():
        result = analyze("Demo-Pattern-2026!", policy=policy)
        assert result["policy"]["policy_name"] == policy.name, name
        assert result["policy"]["checks"], name
