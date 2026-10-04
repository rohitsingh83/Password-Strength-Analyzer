"""
backend/services/suggestion_engine.py
--------------------------------------------------------------------------
PURPOSE
    Convert findings into SPECIFIC, actionable, non-shaming advice.

THE RULE WE FOLLOW
    Bad:  "Make your password stronger."      (useless, tells the user nothing)
    Good: "Your password contains a predictable numeric sequence (masked)."

    Every suggestion therefore names the weakness, explains the risk in one
    line, and gives a concrete next action.

PRIVACY RULE
    Suggestions NEVER include the submitted password, not even partially.
    All evidence shown in the UI is already masked by pattern_detector.py.
--------------------------------------------------------------------------
"""

from __future__ import annotations

from typing import Dict, List, Optional

# Per-weakness advice: title, why it matters, what to do instead.
ADVICE_LIBRARY: Dict[str, Dict[str, str]] = {
    "common_password": {
        "title": "Stop using this password",
        "risk": "It appears in the bundled educational list of the most-used passwords, "
                "so it is inside the first few thousand guesses of every attack tool.",
        "action": "Create a brand-new password for this account and change it on any other "
                  "account where you reused it.",
    },
    "breach": {
        "title": "Treat this password as compromised",
        "risk": "It matches an entry in the demo breach corpus. Real breach lists are built "
               "into credential-stuffing tools and are tried automatically on login pages.",
        "action": "Change it now, and enable MFA so a leaked password alone is not enough.",
    },
    "dictionary_word": {
        "title": "Replace common words with unpredictable combinations",
        "risk": "Dictionary words -- even with capital letters or symbol swaps like '@' for 'a' -- "
                "are enumerated early by cracking tools.",
        "action": "Use a phrase of 4+ randomly chosen, unrelated words, or a password manager's "
                  "random generator.",
    },
    "sequence": {
        "title": "Remove predictable sequences",
        "risk": "Runs such as 1234, abcd or their reverse shrink the search space dramatically: "
                "the attacker guesses a pattern plus a start point, not every character.",
        "action": "Break the run apart and mix in unrelated characters that do not follow each other "
                  "on the keyboard or in the alphabet.",
    },
    "keyboard_pattern": {
        "title": "Avoid keyboard walks",
        "risk": "Shapes like qwerty, asdf, 1qaz or zxcv are in every wordlist, including reversed, "
                "shifted and case-flipped versions.",
        "action": "Pick characters that are not physically adjacent, or switch to a random "
                  "generated password.",
    },
    "repeated_characters": {
        "title": "Stop repeating the same character",
        "risk": "A long run of one character (aaaa, 1111) adds length but almost zero "
                "unpredictability.",
        "action": "Keep the length, replace the repeated run with unrelated characters.",
    },
    "repeated_substring": {
        "title": "Break up repeated blocks",
        "risk": "Repeating a block such as 'abcabc' or '121212' makes the password look longer "
                "without making it harder to guess.",
        "action": "Use a random generator, or choose a passphrase whose words do not repeat.",
    },
    "predictable_structure": {
        "title": "Avoid word-plus-number shapes",
        "risk": "'word + 123' and 'Word!2026' are two of the first patterns tools try, because "
                "they satisfy composition rules while staying memorable.",
        "action": "Prefer a longer passphrase or a fully random password. If you must remember it, "
                  "make the length do the work rather than the symbol.",
    },
    "year_pattern": {
        "title": "Take the year out",
        "risk": "Birth years and the current year are the most attempted numeric suffixes, and "
                "they are often discoverable from public profiles.",
        "action": "Remove dates entirely, or bury them inside a long random string.",
    },
    "date_pattern": {
        "title": "Remove date-shaped strings",
        "risk": "Birthdays and anniversaries are guessable from social media and public records.",
        "action": "Pick unrelated characters that carry no personal meaning.",
    },
    "phone_pattern": {
        "title": "Do not use a phone number",
        "risk": "Phone numbers are directly identifiable and appear in breach and marketing "
                "datasets.",
        "action": "Use a random generated password instead.",
    },
    "personal_info": {
        "title": "Remove your personal information",
        "risk": "Names, usernames and birth years can be collected from profiles, resumes, "
                "company pages and breach dumps, then tried automatically.",
        "action": "Avoid anything that identifies you; keep personal details out of passwords "
                  "even when they are easy to remember.",
    },
    "short_length": {
        "title": "Increase the length",
        "risk": "Short passwords are guessed with brute force far more quickly than long ones.",
        "action": "Aim for at least 12 characters, and 16+ for email, banking and work accounts.",
    },
    "low_variety": {
        "title": "Add character variety",
        "risk": "Using only one character class keeps the search pool small.",
        "action": "Mix upper and lower case, digits and symbols -- but rely on length and "
                  "unpredictability first.",
    },
}


# -----------------------------------------------------------------------------
# Context-sensitive advice the findings alone cannot express
# -----------------------------------------------------------------------------
def _hygiene_suggestions(character_report: Dict, length_report: Dict, findings: List[Dict]) -> List[str]:
    """Always-useful hygiene reminders, included based on what was detected."""
    advice: List[str] = []

    if length_report["length"] < 12:
        advice.append("Consider using a longer password or a passphrase of 4+ unrelated words "
                      "(for example: 'three-word-demo-example' style, but unique to you).")

    if character_report["character_type_count"] < 3:
        advice.append("Add another character type (upper case, digits or symbols) to widen the "
                      "pool an attacker must search.")

    if any(f["type"] in ("repeated_characters", "repeated_substring") for f in findings):
        advice.append("Do not pad a memorable word with repeated characters -- padding adds "
                      "length without adding unpredictability.")

    if length_report["length"] >= 16 and not findings:
        advice.append("Store this password in a password manager so you never need to reuse it "
                      "or remember it manually.")

    return advice


ALWAYS_USEFUL: List[str] = [
    "Avoid reusing passwords across different accounts -- one breach would then expose every "
    "account that shares the password.",
    "Use a password manager to generate and store unique passwords for every site.",
    "Enable MFA (app, hardware key or passkey) wherever it is offered; it protects you even "
    "if the password leaks.",
    "Never share a password over email, chat or a phone call, and be sceptical of any page "
    "that asks you to re-enter it after you clicked a link.",
]


# -----------------------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------------------
def generate_suggestions(
    findings: List[Dict],
    length_report: Optional[Dict] = None,
    character_report: Optional[Dict] = None,
    classification: str = "",
    include_hygiene: bool = True,
) -> List[Dict]:
    """
    Build an ordered list of suggestion objects:

        {"priority": "high|medium|low", "title": "...", "risk": "...", "action": "..."}

    Ordered by severity so the most important fix is always first.
    """
    suggestions: List[Dict] = []
    seen_titles: set[str] = set()

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    priority_map = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "low"}

    for finding in sorted(findings, key=lambda f: order.get(f["severity"], 9)):
        library_entry = ADVICE_LIBRARY.get(finding["type"])
        if not library_entry:
            continue
        if library_entry["title"] in seen_titles:
            continue
        seen_titles.add(library_entry["title"])
        suggestions.append({
            "priority": priority_map.get(finding["severity"], "low"),
            "weakness": finding["type"],
            "title": library_entry["title"],
            "risk": library_entry["risk"],
            "action": library_entry["action"],
            "detected": finding["description"],
        })

    # Structural advice that is not tied to a specific finding.
    if length_report and character_report:
        for text in _hygiene_suggestions(character_report, length_report, findings):
            suggestions.append({
                "priority": "medium",
                "weakness": "hygiene",
                "title": text.split("(")[0].strip().rstrip("."),
                "risk": "Structural improvements raise the floor of your password regardless of "
                        "which specific pattern was detected.",
                "action": text,
                "detected": "",
            })

    if classification in ("VERY WEAK", "WEAK") and not any(
        s["weakness"] == "generator" for s in suggestions
    ):
        suggestions.append({
            "priority": "high",
            "weakness": "generator",
            "title": "Let the tool generate one for you",
            "risk": "Human-chosen passwords strongly favour memorable patterns, which is exactly "
                    "what attackers model.",
            "action": "Use the built-in generator (Python's `secrets` module) and save the result "
                      "in a password manager.",
        })

    if include_hygiene:
        for line in ALWAYS_USEFUL:
            suggestions.append({
                "priority": "low",
                "weakness": "awareness",
                "title": line.split("--")[0].split(";")[0].split(",")[0].strip().rstrip("."),
                "risk": "Password strength is only one part of account security.",
                "action": line,
                "detected": "",
            })

    return suggestions
