"""
backend/services/policy_checker.py
--------------------------------------------------------------------------
PURPOSE
    Evaluate a password against an administrator-defined POLICY, separately
    from its STRENGTH SCORE.

WHY THEY ARE DIFFERENT
    * STRENGTH  is a measurement: how hard is this string to guess?
    * POLICY    is a rule set: does this password satisfy what THIS
                organisation requires for THIS account type?

    Real examples of the difference:
      - "River-Pebble-Orchid-Sunset" is very strong but might fail a policy
        that requires a digit.
      - "Str0ng!2026" might pass a naive policy while being a predictable
        word+year structure, so it scores poorly on strength.

    A password can therefore be STRONG and still fail policy, or WEAK and pass
    policy. Both results are reported side by side.

MODERN GUIDANCE REFLECTED HERE (NIST SP 800-63B / OWASP ASVS 2.1)
    * Prefer minimum length over composition rules.
    * Do NOT force periodic expiry unless there is evidence of compromise.
    * Allow long passwords, spaces and all printable characters.
    * Block known-common / breached passwords.
    * Do not impose arbitrary maximum lengths (64+ minimum support).
--------------------------------------------------------------------------
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from .pattern_detector import is_common_password, detect_personal_info

# -----------------------------------------------------------------------------
# Policy definition
# -----------------------------------------------------------------------------
@dataclass
class PasswordPolicy:
    """
    Administrator-configurable policy.

    Defaults aim at the modern (NIST/OWASP-aligned) baseline rather than the
    outdated "8 chars with 1 upper, 1 number, 1 symbol, rotate monthly" rule set.
    """
    name: str = "Standard account policy"
    minimum_length: int = 12
    maximum_supported_length: int = 256
    common_password_check: bool = True
    personal_info_check: bool = True
    require_uppercase: bool = False
    require_lowercase: bool = False
    require_digit: bool = False
    require_symbol: bool = False
    allow_spaces: bool = True
    min_unique_characters: int = 6
    reject_breached: bool = True
    password_expiry_days: int = 0          # 0 = no forced rotation (recommended)
    minimum_strength_score: int = 0        # 0 = strength not enforced by policy

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict]) -> "PasswordPolicy":
        """Build a policy from a dict, ignoring unknown keys (safe for API use)."""
        if not data:
            return cls()
        known = {f for f in cls().to_dict()}
        return cls(**{k: v for k, v in data.items() if k in known})


# Preset policies so the dashboard can demonstrate enterprise scenarios.
PRESET_POLICIES: Dict[str, PasswordPolicy] = {
    "nist_baseline": PasswordPolicy(
        name="NIST-style baseline (length + blocklist, no composition rules)",
        minimum_length=8, min_unique_characters=4,
    ),
    "standard_account": PasswordPolicy(name="Standard account (12+ characters)"),
    "enterprise_iam": PasswordPolicy(
        name="Enterprise IAM (16+ characters, strength enforced)",
        minimum_length=16, min_unique_characters=8, minimum_strength_score=61,
    ),
    "legacy_bank": PasswordPolicy(
        name="Legacy banking-style policy (shown as an anti-pattern)",
        minimum_length=8, require_uppercase=True, require_lowercase=True,
        require_digit=True, require_symbol=True, password_expiry_days=90,
    ),
    "passphrase_friendly": PasswordPolicy(
        name="Passphrase-friendly (16+ characters, spaces allowed)",
        minimum_length=16, min_unique_characters=5, allow_spaces=True,
        require_digit=False, require_symbol=False,
    ),
}


# -----------------------------------------------------------------------------
# Evaluation
# -----------------------------------------------------------------------------
def check_policy(
    password: str,
    policy: Optional[PasswordPolicy] = None,
    strength_score: Optional[int] = None,
    context: Optional[Dict[str, str]] = None,
) -> Dict:
    """
    Evaluate `password` against `policy`.

    Returns:
        {
          "policy_name": "...",
          "policy_pass": True/False,
          "checks": [ {id, label, required, passed, detail}, ... ],
          "failures": [...],
          "strength_score": 74,
          "strength_meets_policy": True
        }
    """
    policy = policy or PasswordPolicy()
    text = password or ""
    checks: List[Dict] = []

    def add(check_id: str, label: str, passed: bool, detail: str, required: bool = True) -> None:
        checks.append({
            "id": check_id, "label": label, "passed": passed,
            "detail": detail, "required": required,
        })

    # --- length ---------------------------------------------------------
    add(
        "minimum_length", f"At least {policy.minimum_length} characters",
        len(text) >= policy.minimum_length,
        f"length = {len(text)}",
    )
    add(
        "maximum_length", f"Not more than {policy.maximum_supported_length} characters",
        len(text) <= policy.maximum_supported_length,
        f"length = {len(text)} (modern guidance: support 64+ and never truncate)",
    )

    # --- unique characters ---------------------------------------------
    unique = len(set(text))
    add(
        "unique_characters", f"At least {policy.min_unique_characters} unique characters",
        unique >= policy.min_unique_characters,
        f"unique characters = {unique}",
    )

    # --- common / breached ---------------------------------------------
    if policy.common_password_check:
        common = bool(is_common_password(text))
        add(
            "common_password", "Not a known common password",
            not common,
            "matched the educational common-password list" if common
            else "not present in the common-password list",
        )

    # --- personal information -------------------------------------------
    if policy.personal_info_check:
        hits = detect_personal_info(text, context) if context else []
        add(
            "personal_info", "No personal information from the provided context",
            not hits,
            "overlap detected with supplied context" if hits
            else ("no overlap detected" if context else "no context supplied (skipped)"),
            required=bool(context),
        )

    # --- optional composition rules (opt-in only) ------------------------
    composition_rules = [
        ("require_uppercase", policy.require_uppercase, "Contains an uppercase letter",
         lambda s: any(c.isupper() for c in s)),
        ("require_lowercase", policy.require_lowercase, "Contains a lowercase letter",
         lambda s: any(c.islower() for c in s)),
        ("require_digit", policy.require_digit, "Contains a digit",
         lambda s: any(c.isdigit() for c in s)),
        ("require_symbol", policy.require_symbol, "Contains a symbol",
         lambda s: any(not c.isalnum() and c != " " for c in s)),
    ]
    composition_failures = 0
    for check_id, required, label, predicate in composition_rules:
        if required:
            passed = predicate(text)
            composition_failures += 0 if passed else 1
            add(check_id, label, passed, "required by policy" + ("" if passed else " -- not satisfied"))
    add(
        "composition_rules", "Composition rules are opt-in only",
        True,
        "This policy " + ("enforces" if any(r for _, r, _, _ in composition_rules) else "does not enforce")
        + " uppercase/digit/symbol rules. Modern guidance prefers length + blocklists "
          "over mandatory composition, because it pushes users towards 'Password1!' patterns.",
        required=False,
    )

    # --- spaces ---------------------------------------------------------
    if not policy.allow_spaces and " " in text:
        add("allow_spaces", "Spaces not permitted by this policy", False,
            "spaces were used but this policy disallows them")
    else:
        add("allow_spaces", "Spaces handled as configured", True,
            "spaces allowed" if policy.allow_spaces else "no spaces used", required=False)

    # --- expiry ----------------------------------------------------------
    add(
        "expiry", "Password rotation policy",
        True,
        ("Forces rotation every "
         f"{policy.password_expiry_days} days. Modern guidance: rotate only on evidence of "
         "compromise, because forced rotation produces predictable increments (typically the "
         "same word with the next year appended) and weaker passwords.")
        if policy.password_expiry_days else
        "No forced periodic rotation. Rotate immediately if a breach or suspicion of compromise occurs.",
        required=False,
    )

    # --- strength threshold ---------------------------------------------
    strength_ok = True
    if policy.minimum_strength_score and strength_score is not None:
        strength_ok = strength_score >= policy.minimum_strength_score
        add(
            "minimum_strength_score",
            f"Strength score of at least {policy.minimum_strength_score}/100",
            strength_ok,
            f"score = {strength_score}/100",
        )

    required_checks = [c for c in checks if c["required"]]
    failures = [c for c in required_checks if not c["passed"]]

    return {
        "policy_name": policy.name,
        "policy": policy.to_dict(),
        "policy_pass": len(failures) == 0,
        "checks": checks,
        "failures": failures,
        "failure_count": len(failures),
        "strength_score": strength_score,
        "strength_meets_policy": strength_ok,
        "note": (
            "Policy compliance and password strength are separate ideas. A policy says "
            "'this is allowed here'; strength says 'this is hard to guess'. Both are reported."
        ),
    }
