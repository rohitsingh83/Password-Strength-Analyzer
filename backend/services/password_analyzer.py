"""
backend/services/password_analyzer.py
--------------------------------------------------------------------------
PURPOSE
    The public façade of the analysis engine. One function, one structured
    result, everything the UI needs:

        analyze_password("Demo-Pass-2026!")  ->  {...}

    Internally it orchestrates:

        character_analyzer  -> length + diversity metrics
        pattern_detector    -> common passwords, dictionary, sequences,
                               keyboard walks, repetition, predictable
                               structures, dates/phone, personal context,
                               demo breach corpus
        entropy_estimator   -> theoretical vs effective entropy + guess estimate
        scoring_engine      -> 0-100 score, breakdown and classification
        suggestion_engine   -> specific, actionable advice
        policy_checker      -> separate POLICY PASS / POLICY FAIL verdict

RETURN CONTRACT (as required by the project brief)
    {
      "score": 0,
      "classification": "",
      "findings": [],
      "suggestions": [],
      "metrics": {}
      ... plus entropy, guess_resistance, score_breakdown, policy, privacy
    }

PRIVACY
    The password exists only as a function argument and a local variable. It is
    never logged, never stored, never returned in the response and never put in
    a URL. Everything derived from it that leaves this module is masked,
    aggregated or numeric.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .character_analyzer import (
    MAX_SUPPORTED_LENGTH,
    RECOMMENDED_MIN_LENGTH,
    RECOMMENDED_PASSPHRASE_WORDS,
    analyze_characters,
    analyze_length,
)
from .entropy_estimator import entropy_report, estimate_guess_resistance, passphrase_entropy_bits
from .pattern_detector import analyze_structure, detect_all_patterns
from .policy_checker import PasswordPolicy, check_policy
from .scoring_engine import PENALTY_CAPS, WEIGHTS, score_password
from .suggestion_engine import generate_suggestions

# Structured result version -- bump when the JSON shape changes.
RESULT_VERSION = "1.0"


# -----------------------------------------------------------------------------
# Validation helpers
# -----------------------------------------------------------------------------
def validate_input(password: str, max_length: int = MAX_SUPPORTED_LENGTH) -> Dict:
    """
    Validate the submitted value *without* echoing it anywhere.

    Returns {"ok": bool, "reason": str, "kind": str}
    """
    if password is None:
        return {"ok": False, "reason": "No value submitted.", "kind": "missing"}
    if not isinstance(password, str):
        return {"ok": False, "reason": "Password must be a string.", "kind": "type"}
    if len(password) > max_length:
        return {
            "ok": False,
            "reason": f"Password exceeds the supported length ({max_length} characters). "
                      f"Long values are rejected to protect the service, not because length hurts security.",
            "kind": "too_long",
        }
    # Control characters (other than tab) can break shells, logs and JSON viewers.
    if any(ord(c) < 32 and c not in "\t" for c in password):
        return {"ok": False, "reason": "Password contains control characters.", "kind": "control_chars"}
    return {"ok": True, "reason": "", "kind": "ok"}


def _redact_context(context: Optional[Dict[str, str]]) -> Optional[Dict[str, int]]:
    """
    Return a *length-only* fingerprint of the supplied context for debugging,
    so we can prove the context was used without recording what it was.
    """
    if not context:
        return None
    return {key: len(str(value)) for key, value in context.items() if value}


# -----------------------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------------------
def analyze_password(
    password: str,
    context: Optional[Dict[str, str]] = None,
    policy: Optional[PasswordPolicy] = None,
    include_hygiene: bool = True,
) -> Dict:
    """
    Analyze a password and return the full structured result.

    Parameters
    ----------
    password : str
        The candidate password. Present only in memory.
    context : dict, optional
        OPTIONAL personal context for the overlap check, e.g.
        {"first_name": "Demo", "birth_year": "1999", "organisation": "Example College"}.
        Used in memory for the duration of this call and then discarded.
    policy : PasswordPolicy, optional
        Administrator policy to evaluate against (defaults to the standard policy).
    include_hygiene : bool
        Include general password-hygiene education in the suggestions list.
    """
    started = time.perf_counter()
    analysis_id = f"an_{uuid.uuid4().hex[:12]}"

    # ---------------------------------------------------------------- validate
    validation = validate_input(password)
    if not validation["ok"]:
        return _invalid_result(validation, analysis_id, context)

    text = password or ""

    # ---------------------------------------------------------------- analyse
    length_report = analyze_length(text)
    character_report = analyze_characters(text)

    pattern_result = detect_all_patterns(text, context)
    findings: List[Dict] = pattern_result["findings"]
    penalty_bits = pattern_result["pattern_penalty_bits"]
    structure = pattern_result["structure"]
    passphrase_like = structure["is_passphrase_like"]

    # Structural findings that are not "patterns" but still matter.
    if 0 < length_report["length"] < RECOMMENDED_MIN_LENGTH:
        findings.append({
            "type": "short_length",
            "severity": "medium" if length_report["length"] < 8 else "low",
            "title": "Short password",
            "description": f"Your password is {length_report['length']} characters long. "
                           f"{RECOMMENDED_MIN_LENGTH}+ is the common modern baseline, and 16+ is better "
                           f"for email, banking and work accounts.",
            "evidence": "\u2022" * length_report["length"],
            "positions": [],
            "penalty_bits": 8.0 if length_report["length"] < 8 else 4.0,
        })
    if text and character_report["character_type_count"] < 2:
        findings.append({
            "type": "low_variety",
            "severity": "low",
            "title": "Single character class",
            "description": "Only one character class is used, which keeps the search pool small.",
            "evidence": "\u2022" * len(text),
            "positions": [],
            "penalty_bits": 3.0,
        })

    # Re-sort after appending so critical items stay on top.
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), -f["penalty_bits"]))

    entropy = entropy_report(text, penalty_bits)

    # Passphrase correction: the "L x log2(pool)" estimate assumes random
    # character selection, which understates a phrase of independent words and
    # overstates "Password123!". For a genuine multi-word phrase we swap in the
    # Diceware-style estimate (words x log2(wordlist size)).
    if passphrase_like:
        word_entropy = entropy["passphrase_estimate_bits"]
        non_phrase_findings = [f for f in findings if f["type"] != "passphrase_structure"]
        if not non_phrase_findings:
            # Take the more conservative of the two models. The Diceware number
            # is an UPPER BOUND that assumes the words were picked randomly from
            # the whole list; a human-chosen phrase ("I-love-my-dog") is weaker.
            entropy["effective_bits"] = round(min(word_entropy, entropy["effective_bits"]), 1)
            entropy["effective_bits_source"] = (
                f"passphrase model (upper bound): {structure['token_count']} words x "
                f"~12.6 bits per word, assuming random word selection"
            )
            entropy["passphrase_model_caveat"] = (
                "This assumes the words were chosen randomly and independently. A "
                "human-chosen phrase of related or pretty words is much weaker than "
                "this number suggests."
            )

    # Published-value correction: the character-space estimate is a *theoretical*
    # upper bound that simply does not apply to a value that already appears in a
    # public list. "correct horse battery staple" is 28 characters and looks like
    # ~130 bits of entropy, yet an attacker tries it within the first few
    # thousand guesses. The bit count stays visible (it is a teaching point) but
    # it is clearly labelled as inapplicable rather than left to mislead.
    #
    # The wording below is duplicated verbatim in frontend/js/engine.js so both
    # runtimes explain the same number in the same words.
    known_types = {"common_password", "common_phrase", "breach"}
    if known_types & {f["type"] for f in findings}:
        entropy["effective_bits_source"] = (
            "character-space upper bound -- NOT applicable here"
        )
        entropy["known_value_caveat"] = (
            "This value is in a public/common list, so the character-space formula "
            "does not describe it. Its true cost to an attacker is a few thousand "
            "guesses at most, no matter how long or complex the string looks."
        )
    scoring = score_password(text, findings)
    guess = estimate_guess_resistance(entropy["effective_bits"])
    suggestions = generate_suggestions(
        findings,
        length_report=length_report,
        character_report=character_report,
        classification=scoring["classification"],
        include_hygiene=include_hygiene,
    )
    policy_result = check_policy(text, policy, strength_score=scoring["score"], context=context)

    duration_ms = round((time.perf_counter() - started) * 1000, 2)

    # ---------------------------------------------------------------- assemble
    return {
        "analysis_id": analysis_id,
        "version": RESULT_VERSION,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": duration_ms,

        # --- headline ---------------------------------------------------
        "score": scoring["score"],
        "classification": scoring["classification"],
        "classification_summary": scoring["summary"],
        "classification_band": scoring["band"],
        "score_cap_applied": scoring["score_cap_applied"],

        # --- required structured sections --------------------------------
        "findings": findings,
        "suggestions": suggestions,
        "metrics": {
            "length": length_report["length"],
            "length_band": length_report["band"],
            "length_credit": length_report["credit"],
            "recommended_minimum_length": RECOMMENDED_MIN_LENGTH,
            "is_recommended_length": length_report["is_recommended_length"],
            "character_type_count": character_report["character_type_count"],
            "character_types": character_report["character_types"],
            "unique_character_count": character_report["unique_character_count"],
            "unique_character_ratio": character_report["unique_character_ratio"],
            "has_lowercase": character_report["has_lowercase"],
            "has_uppercase": character_report["has_uppercase"],
            "has_digits": character_report["has_digits"],
            "has_symbols": character_report["has_symbols"],
            "has_spaces": character_report["has_spaces"],
            "has_unicode": character_report["has_unicode"],
            "is_common_password": any(f["type"] == "common_password" for f in findings),
            "in_demo_breach_corpus": any(f["type"] == "breach" for f in findings),
            "breach_prefix_checked": pattern_result.get("breach_prefix"),
            "is_passphrase_like": passphrase_like,
            "token_count": structure["token_count"],
            "separators_used": structure["separators_used"],
            "pattern_count": len([f for f in findings if f["type"] not in
                                  ("short_length", "low_variety", "passphrase_structure")]),
            "weakness_count": len(findings),
            "weakness_categories": pattern_result["categories"],
            "has_sequence": any(f["type"] == "sequence" for f in findings),
            "has_keyboard_pattern": any(f["type"] == "keyboard_pattern" for f in findings),
            "has_repetition": any(f["type"] in ("repeated_characters", "repeated_substring") for f in findings),
            "has_dictionary_word": any(f["type"] == "dictionary_word" for f in findings),
            "has_personal_info": any(f["type"] == "personal_info" for f in findings),
            "has_predictable_structure": any(f["type"] == "predictable_structure" for f in findings),
            "has_year_pattern": any(f["type"] == "year_pattern" for f in findings),
        },

        # --- detail sections ---------------------------------------------
        "length_analysis": length_report,
        "character_analysis": character_report,
        "structure_analysis": structure,
        "entropy": entropy,
        "score_breakdown": {
            "weights": WEIGHTS,
            "penalty_caps": PENALTY_CAPS,
            "raw_score": scoring["raw_score"],
            "components": scoring["breakdown"],
            "penalties": scoring["penalties"],
            "final_score": scoring["score"],
            "caps_evaluated": scoring.get("caps_evaluated", []),
            "rubric_note": (
                "Project-defined rubric (length 35 + diversity 15 + uniqueness 10 + pattern "
                "resistance 20 + not-common 10 + unpredictability 10, minus capped penalties). "
                "These weights are not a universal security standard."
            ),
        },
        "guess_resistance": guess,
        "policy": policy_result,
        "passphrase_guidance": {
            "recommended_words": RECOMMENDED_PASSPHRASE_WORDS,
            "bits_per_word_note": "4 randomly chosen words from a 6,000+ word list is roughly 50 bits; "
                                  "6 words is roughly 76 bits.",
            "four_word_entropy_bits": round(passphrase_entropy_bits(4), 1),
            "six_word_entropy_bits": round(passphrase_entropy_bits(6), 1),
            "examples": [
                "DEMO ONLY -- do not reuse: 'copper-lantern-orchid-gravity'",
                "DEMO ONLY -- do not reuse: 'tundra-basil-falcon-thistle-prism'",
            ],
            "warning": "Never reuse a passphrase taken from a website, article, song lyric or this demo. "
                       "Generate your own with a password manager or the built-in generator.",
        },
        "privacy": {
            "password_stored": False,
            "password_logged": False,
            "password_returned_in_response": False,
            "password_sent_to_external_service": False,
            "context_stored": False,
            "context_fingerprint_lengths": _redact_context(context),
            "evidence_masked": True,
            "note": "The password was processed in memory for this single request and discarded. "
                    "All evidence strings in findings are masked with bullets.",
        },
        "disclaimer": (
            "Educational estimate only. Password strength cannot be perfectly determined by one "
            "formula: it depends on the attacker model, the hashing algorithm and work factor, "
            "rate limiting, entry-point exposure and whether the password is reused elsewhere."
        ),
    }


# -----------------------------------------------------------------------------
# Empty / invalid input result
# -----------------------------------------------------------------------------
def _invalid_result(validation: Dict, analysis_id: str, context: Optional[Dict]) -> Dict:
    """Return a well-formed response for missing or invalid input (never echoes it)."""
    guidance = {
        "missing": "Enter a password to analyze. Nothing is stored or transmitted when you type.",
        "type": "Submit the password as text.",
        "too_long": validation["reason"],
        "control_chars": validation["reason"],
    }.get(validation["kind"], "The submitted value could not be analyzed.")

    return {
        "analysis_id": analysis_id,
        "version": RESULT_VERSION,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": 0.0,
        "score": 0,
        "classification": "VERY WEAK",
        "classification_summary": "No password to analyze yet.",
        "classification_band": "0-20",
        "score_cap_applied": None,
        "findings": [{
            "type": "input",
            "severity": "info",
            "title": "Nothing to analyze",
            "description": guidance,
            "evidence": "",
            "positions": [],
            "penalty_bits": 0.0,
        }],
        "suggestions": [{
            "priority": "low",
            "weakness": "input",
            "title": "Start typing",
            "risk": "The analyzer needs a value to evaluate.",
            "action": "Type a synthetic demo password, or use the generator to create one.",
            "detected": "",
        }],
        "metrics": {
            "length": 0, "length_band": "Empty", "character_type_count": 0,
            "unique_character_count": 0, "unique_character_ratio": 0.0,
            "pattern_count": 0, "weakness_count": 0, "weakness_categories": {},
        },
        "entropy": {
            "pool_size": 0, "theoretical_bits": 0.0, "effective_bits": 0.0,
            "shannon_bits": 0.0, "pattern_penalty_bits": 0.0,
            "formula": "Entropy (theoretical) ~= length x log2(pool size)",
            "caveat": "Nothing was analyzed.",
        },
        "score_breakdown": {"weights": WEIGHTS, "penalty_caps": PENALTY_CAPS,
                            "raw_score": 0, "components": {}, "penalties": {"total": 0, "by_category": {}},
                            "final_score": 0},
        "guess_resistance": estimate_guess_resistance(0),
        "policy": {"policy_pass": False, "checks": [], "failures": [],
                   "failure_count": 1, "note": "No password supplied."},
        "passphrase_guidance": {},
        "privacy": {
            "password_stored": False, "password_logged": False,
            "password_returned_in_response": False,
            "password_sent_to_external_service": False,
            "context_stored": False,
            "context_fingerprint_lengths": _redact_context(context),
            "evidence_masked": True,
        },
        "disclaimer": "Educational estimate only.",
        "input_error": {"kind": validation["kind"], "reason": validation["reason"]},
    }


# -----------------------------------------------------------------------------
# CLI convenience: python -m backend.services.password_analyzer "Demo123!"
# -----------------------------------------------------------------------------
if __name__ == "__main__":       # pragma: no cover
    import json
    import sys

    sample = sys.argv[1] if len(sys.argv) > 1 else "Password123!"
    result = analyze_password(sample)
    slim = {k: v for k, v in result.items() if k not in ("score_breakdown", "length_analysis", "character_analysis")}
    print(json.dumps(slim, indent=2)[:4000])
