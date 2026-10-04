"""
backend/services/pattern_detector.py
--------------------------------------------------------------------------
PURPOSE
    The "predictability radar" of the project. It scans a password for every
    structural weakness a real attacker exploits first:

        1. common-password match        (dictionary attack, first few guesses)
        2. dictionary word inside it    (l33t + prefix/suffix padding)
        3. repeated characters          (aaaa, 1111)
        4. repeated substrings          (ababab, abcabcabc)
        5. sequential characters        (abcd, 1234, dcba, 9876)
        6. keyboard walks               (qwerty, asdf, 1qaz, zxcv)
        7. predictable word + number    (welcome123, admin2026, Password123!)
        8. year / date / phone shapes   (1998, 12-05-2001, 9876543210)
        9. personal context overlap     (optional: name, birth year, org)
       10. breach-corpus membership     (local SHA-1 demo set, k-anonymity style)

PRIVACY RULES ENFORCED HERE
    * Findings never contain the raw password.
    * Any snippet shown in `evidence` is masked with bullets, e.g. "•••••".
    * Nothing is written to disk or to a log in this module.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional

from .data_loader import (
    RE_SEPARATORS,
    breach_lookup,
    dictionary_index,
    load_common_phrases,
    load_keyboard_patterns,
    sha1_hex,
)

# -----------------------------------------------------------------------------
# Tunable constants (documented so a reviewer can see the reasoning)
# -----------------------------------------------------------------------------
MIN_SEQUENCE_LEN = 4          # "abc" is too short to be meaningful, "abcd" is not
MIN_REPEAT_LEN = 4            # "aaaa" / "abab"
MIN_KEYBOARD_LEN = 4          # "qwer", "asdf"
MIN_DICT_WORD_LEN = 4         # ignore "a", "ab" noise
MIN_CONTEXT_LEN = 3           # ignore 1-2 char context tokens like initials

# Keyboard rows used for adjacent-key walk detection.
KEYBOARD_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]
KEYBOARD_ROW_NAMES = {
    0: "number row",
    1: "top letter row (qwertyuiop)",
    2: "home row (asdfghjkl)",
    3: "bottom row (zxcvbnm)",
}

# L33t-speak replacement pairs: what a human *meant* vs what they typed.
LEET_MAP = {
    "4": "a", "@": "a", "8": "b", "3": "e", "6": "g", "9": "g", "1": "i",
    "!": "i", "|": "i", "0": "o", "$": "s", "5": "s", "7": "t", "+": "t",
    "2": "z",
}

# Shifted characters -> the physical key a user actually pressed.
# This lets us catch "!@#$%" (shifted 12345) and "QWER" as keyboard walks.
SHIFT_MAP = {
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7",
    "*": "8", "(": "9", ")": "0", "_": "-", "+": "=", "~": "`",
    "{": "[", "}": "]", "|": "\\", ":": ";", '"': "'", "<": ",", ">": ".", "?": "/",
}

# Severity weights, expressed in "bits an attacker gains for free".
SEVERITY_BITS = {
    "critical": 30.0,
    "high": 18.0,
    "medium": 10.0,
    "low": 5.0,
    "info": 1.0,
}


# -----------------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------------
def mask(value: str) -> str:
    """
    Replace every character with a bullet so a finding can point at WHERE a
    problem is without revealing WHAT the characters were.
    """
    return "\u2022" * len(value)


def redact_positions(text: str, start: int, end: int, keep: int = 0) -> str:
    """
    Return a masked rendering of `text` that hides everything except `keep`
    leading characters (default: hide all).
    """
    visible = text[:keep] if keep else ""
    return visible + mask(text[keep:])


def _finding(finding_type: str, severity: str, title: str, description: str,
             evidence: str, positions: Optional[List[int]] = None) -> Dict:
    """Build one consistently-shaped finding dict."""
    return {
        "type": finding_type,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,                      # ALWAYS masked
        "positions": positions or [],
        "penalty_bits": SEVERITY_BITS[severity],
    }


def unshift(text: str) -> str:
    """
    Return the lowercase string of PHYSICAL keys pressed.

        "!@#$%" -> "12345"      "QWER" -> "qwer"      "AsDf" -> "asdf"
    """
    return "".join(SHIFT_MAP.get(ch, ch).lower() for ch in text)


def analyze_structure(password: str) -> Dict:
    """
    Describe the coarse shape of the value: single token vs multi-word phrase.

    {
      "token_count": 4,
      "tokens": 4,                      # count only -- never the words themselves
      "separators_used": ["-"],
      "is_multi_word": True,
      "is_passphrase_like": True,
      "average_token_length": 6.5,
      "note": "..."
    }

    A 4+ word phrase with separators is treated differently from a single word
    padded with digits: the words are independent draws from a huge space,
    which is what makes a passphrase work. (Single-word passwords padded with
    123 are handled by detect_predictable_structure() instead.)
    """
    text = password or ""
    raw_tokens = [t for t in RE_SEPARATORS.split(text) if t]
    separators = sorted({ch for ch in text if ch in " -_.+\t"} and {
        ch for ch in text if RE_SEPARATORS.match(ch) or ch == "\t"
    })
    lengths = [len(t) for t in raw_tokens]
    is_multi_word = len(raw_tokens) >= 3
    is_passphrase_like = (
        len(raw_tokens) >= 4
        and all(length >= 3 for length in lengths)
        and len(text) >= 18
    )
    return {
        "token_count": len(raw_tokens),
        "separators_used": separators,
        "is_multi_word": is_multi_word,
        "is_passphrase_like": is_passphrase_like,
        "average_token_length": round(sum(lengths) / len(lengths), 2) if lengths else 0.0,
        "note": (
            "A phrase of 4 or more separate words is scored as a passphrase: the value "
            "gains length and independence from the words themselves, so individual "
            "dictionary words are no longer treated as weaknesses."
        ),
    }


# -----------------------------------------------------------------------------
# 1. Common-password detection
# -----------------------------------------------------------------------------
def is_common_password(password: str, ignore_case: bool = True) -> bool:
    """
    True when the password (optionally case-folded) appears in the bundled
    educational common-password list.

    This is a *local set lookup*: no network call, no telemetry.
    """
    if not password:
        return False
    candidate = password.lower() if ignore_case else password
    common = {w.lower() for w in _common_words()}
    return candidate in common


def detect_common_password(password: str) -> List[Dict]:
    """Flag exact matches against the common-password list (including l33t forms)."""
    if not password:
        return []

    findings: List[Dict] = []
    candidate = password.lower()
    common = {w.lower() for w in _common_words()}
    normalised = deleet(password)

    if candidate in common or normalised.lower() in common:
        findings.append(_finding(
            "common_password", "critical",
            "Known common password",
            "Your password matches a commonly used password pattern and should not be used. "
            "These strings are first in every attacker's list.",
            mask(password),
        ))
    return findings


def detect_common_phrases(password: str) -> List[Dict]:
    """
    Flag famous phrases ("correct horse battery staple", song lyrics, etc.).

    Educational point: the most quoted advice about passphrases is itself one
    of the worst passphrases you could choose, because it is in every
    cracking wordlist. Length only helps when the phrase is also unpredictable.
    """
    if not password:
        return []
    phrases = load_common_phrases()
    if not phrases:
        return []

    normalised = RE_SEPARATORS.sub(" ", password.lower()).strip()
    for phrase in phrases:
        if phrase and phrase in normalised:
            return [_finding(
                "common_phrase", "critical",
                "Famous / predictable phrase",
                f"This password contains a well-known phrase or quote. Famous phrases are "
                f"collected in cracking wordlists, so length does not protect them. Choose "
                f"your own unrelated words instead of a quotation, lyric or proverb.",
                mask(password),
            )]
    return []


def _common_words() -> Iterable[str]:
    """Indirection so tests can monkey-patch the list if needed."""
    from .data_loader import load_common_passwords
    return load_common_passwords()


# -----------------------------------------------------------------------------
# 2. Dictionary words (with l33t and padding handling)
# -----------------------------------------------------------------------------
def deleet(text: str) -> str:
    """Convert common symbol/digit substitutions back to letters ("P@ssw0rd" -> "Password")."""
    out = []
    for char in text:
        out.append(LEET_MAP.get(char.lower(), char) if char.lower() in LEET_MAP else char)
    return "".join(out)


def detect_dictionary_words(password: str) -> List[Dict]:
    """
    Find dictionary words hidden inside the password.

    Handles 'welcome2026!', 'My-Welcome-Home', 'P@ssword' style padding by
    splitting on non-letters and also fully de-leeting the string first.
    """
    if len(password) < MIN_DICT_WORD_LEN:
        return []

    vocabulary = dictionary_index()
    candidates: List[tuple[str, str]] = []      # (token, how_it_was_found)

    # (a) plain split on non-letters   (b) de-leeted whole string, same split
    for text, how in ((password.lower(), "plain"), (deleet(password).lower(), "after l33t substitution")):
        for token in re.split(r"[^a-z]+", text):
            if len(token) < MIN_DICT_WORD_LEN:
                continue
            if token in vocabulary:
                candidates.append((token, how))
                continue
            # Digit->letter substitutions can corrupt a word's tail (the classic
            # "p@sswords9" case becomes "passwordsg"). If the whole token is not a
            # dictionary word, test its prefixes longest-first so the underlying
            # word is still found. Documented trade-off: this can occasionally
            # match a prefix of a non-word, which only ever makes the tool more
            # conservative -- never more permissive.
            for length in range(len(token), MIN_DICT_WORD_LEN - 1, -1):
                prefix = token[:length]
                if prefix in vocabulary:
                    candidates.append((prefix, how + " (word prefix match)"))
                    break

    findings: List[Dict] = []
    seen: set[str] = set()
    for token, how in candidates:
        if token in seen:
            continue
        seen.add(token)
        severity = "high" if len(token) >= 6 else "medium"
        findings.append(_finding(
            "dictionary_word", severity,
            "Common word detected",
            f"A word from the common-word dictionary was found in your password "
            f"({how}). Attackers try dictionary words, capitalisations and l33t "
            f"variants before anything else.",
            mask(token),
        ))
    return findings


def _case_echo(first: str, second: str) -> bool:
    """
    True when two blocks hold the same letters and differ in case in AT MOST one
    position ("Co" vs "co", "Pass" vs "pass").

    This is intentionally stricter than a lower-cased comparison. Comparing
    lower-cased copies treats "jdD" and "jDd" as identical, which adds a false
    positive to every random mixed-case value; allowing at most one case change
    keeps the useful cases (a single capital letter hiding a repeat) without
    inventing repeats that are not there.
    """
    if len(first) != len(second) or first.lower() != second.lower():
        return False
    return sum(1 for a, b in zip(first, second) if a != b) <= 1


# -----------------------------------------------------------------------------
# 3. Repeated characters and substrings
# -----------------------------------------------------------------------------
def detect_repetition(password: str) -> List[Dict]:
    """
    Detect:
        * repeated single characters:  aaaa, 1111  (regex (.)\\1{n,})
        * repeated substrings:         ababab, abcabcabc, 121212

    Both are cheap for an attacker to guess and easy for a human to type,
    which is exactly the wrong combination.
    """
    if not password:
        return []
    findings: List[Dict] = []

    # --- repeated single characters -------------------------------------
    for match in re.finditer(r"(.)\1{" + str(MIN_REPEAT_LEN - 1) + r",}", password):
        run = match.group(0)
        char = match.group(1)
        severity = "high" if len(run) >= 6 else "medium"
        # We reveal only the *category* of character, never the character itself.
        if char.isdigit():
            kind = "repeated digit"
        elif char.isalpha():
            kind = "repeated letter"
        elif char == " ":
            kind = "repeated space"
        else:
            kind = "repeated symbol"
        findings.append(_finding(
            "repeated_characters", severity,
            "Repeated character run",
            f"A {kind} is repeated {len(run)} times. Long runs collapse the "
            f"real search space: the attacker only needs to guess the pattern, "
            f"not every character.",
            mask(run),
            list(range(match.start(), match.end())),
        ))

    # --- repeated substrings -------------------------------------------
    # Two rules, applied to block sizes from LARGE to SMALL so that the most
    # meaningful repetition ("abcabcabc") is reported before the smaller one
    # inside it ("abcabc"):
    #
    #   RULE A (exact)      the same characters repeat, e.g. "abcabc", "121212".
    #   RULE B (case echo)  the same LETTERS repeat with a case change in at most
    #                       one position, e.g. "Coco" ("Co" + "co") or
    #                       "Passpass". A single capital cannot hide a repeat.
    #
    # RULE B deliberately does NOT fire when the case pattern differs in several
    # positions ("jdD" + "jDd"), because that is genuinely different data -- an
    # earlier version compared lower-cased copies and reported exactly that,
    # which produced false positives on random mixed-case strings (a 256-char
    # random value could drop from ~86 to ~52).
    #
    # Noise control: in a value longer than 20 characters, an isolated
    # two-character echo is not meaningful, so a 2-character block must repeat at
    # least three times there. Short values are judged strictly.
    length = len(password)
    reported_spans: List[tuple[int, int]] = []
    for size in range(max(length // 2, 2), 1, -1):
        start = 0
        while start + size * 2 <= length:
            block = password[start:start + size]
            if len(set(block)) == 1:        # pure character run: already covered
                start += 1
                continue

            repeats = 1
            while password[start + repeats * size: start + (repeats + 1) * size] == block:
                repeats += 1

            if repeats < 2:
                # RULE B -- a case echo counts as ONE repetition at most.
                following = password[start + size:start + 2 * size]
                if block.isalpha() and following.isalpha() and _case_echo(block, following):
                    repeats = 2

            too_short_a_repeat = size <= 2 and repeats < 3 and length > 20
            if repeats >= 2 and not too_short_a_repeat:
                span_end = start + repeats * size
                overlaps = any(start < e and span_end > s for s, e in reported_spans)
                if not overlaps:
                    reported_spans.append((start, span_end))
                    findings.append(_finding(
                        "repeated_substring", "high" if repeats >= 3 else "medium",
                        "Repeated block pattern",
                        f"A {size}-character block is repeated {repeats} times. "
                        f"Repeating a block adds almost no unpredictability -- the "
                        f"string looks longer without being harder to guess.",
                        mask(password[start:span_end]),
                        list(range(start, span_end)),
                    ))
                start = span_end
            else:
                start += 1
        if len(reported_spans) >= 2:        # keep the finding list readable
            break

    # de-duplicate by (type, masked evidence)
    unique: Dict[tuple, Dict] = {}
    for item in findings:
        unique[(item["type"], item["evidence"])] = item
    return list(unique.values())


# -----------------------------------------------------------------------------
# 4. Sequential characters
# -----------------------------------------------------------------------------
def _find_sequence_runs(text: str, step: int) -> List[tuple[int, int]]:
    """Return (start, end) spans of runs whose ord() changes by exactly `step`."""
    spans: List[tuple[int, int]] = []
    start = 0
    for index in range(1, len(text) + 1):
        continues = (
            index < len(text)
            and (ord(text[index]) - ord(text[index - 1])) == step
        )
        if not continues:
            if index - start >= MIN_SEQUENCE_LEN:
                spans.append((start, index))
            start = index
    return spans


def detect_sequences(password: str) -> List[Dict]:
    """
    Detect ascending and descending alphabetic / numeric runs:
        1234, 4567, abcd, bcde, 9876, dcba, XYZW ...
    """
    if not password:
        return []
    findings: List[Dict] = []
    lowered = password.lower()

    for step, direction in ((1, "ascending"), (-1, "descending")):
        for start, end in _find_sequence_runs(lowered, step):
            span = password[start:end]
            is_digit = span.isdigit()
            findings.append(_finding(
                "sequence", "high" if len(span) >= 5 else "medium",
                f"Predictable {direction} {'numeric' if is_digit else 'alphabetical'} sequence",
                f"A {direction} {'number' if is_digit else 'letter'} run of {len(span)} "
                f"characters was found. Sequences reduce effective entropy because "
                f"the attacker guesses 'pattern + start + direction' instead of "
                f"every character independently.",
                mask(span),
                list(range(start, end)),
            ))
    return findings


# -----------------------------------------------------------------------------
# 5. Keyboard walks
# -----------------------------------------------------------------------------
def detect_keyboard_patterns(password: str) -> List[Dict]:
    """
    Detect keyboard-adjacent walks using two independent methods:

      (a) exact match against a curated fragment list (qwerty, asdf, 1qaz ...)
      (b) geometric adjacency runs per keyboard row (q-w-e-r, a-s-d-f, z-x-c-v)

    Method (b) is what catches variants the list would miss.
    """
    if not password:
        return []
    findings: List[Dict] = []
    lowered = password.lower()
    known = load_keyboard_patterns()

    # --- (a) curated fragments ------------------------------------------
    # We test the typed string AND its "physical keys" form, so "!@#$" and
    # "QWER" are recognised as the same walk as "1234" and "qwer".
    haystacks = (lowered, unshift(password))
    for fragment in sorted(known, key=len, reverse=True):
        if len(fragment) < MIN_KEYBOARD_LEN:
            continue
        if any(fragment in hay for hay in haystacks):
            index = lowered.index(fragment)
            findings.append(_finding(
                "keyboard_pattern", "high",
                "Keyboard walk detected",
                f"A known keyboard sequence of {len(fragment)} adjacent keys was "
                f"found. Keyboard walks are among the first patterns automated "
                f"tools try because they are easy to type and easy to guess.",
                mask(password[index:index + len(fragment)]),
                list(range(index, index + len(fragment))),
            ))
            # A curated hit is the strongest evidence available, so we stop
            # here rather than also reporting the geometric walk it implies.
            # (The JavaScript engine does the same, and the parity test asserts
            # the two agree.)
            return findings

    # --- (b) row-adjacency runs -----------------------------------------
    # Walk every ascending run and ask "does this run live inside one row of
    # the keyboard?"  e.g. 'fghj' is adjacent on the home row.
    for start, end in _find_sequence_runs(unshift(password), 1):
        span = unshift(password)[start:end]
        for row_index, row in enumerate(KEYBOARD_ROWS):
            if all(ch in row for ch in span):
                findings.append(_finding(
                    "keyboard_pattern", "medium",
                    "Keyboard row walk",
                    f"A run of {len(span)} characters follows adjacent keys on the "
                    f"{KEYBOARD_ROW_NAMES[row_index]}. Attacker wordlists include "
                    f"these shapes with every shift/case variation.",
                    mask(password[start:end]),
                    list(range(start, end)),
                ))
                break

    # --- (c) reversed walks such as 'ytrewq' -----------------------------
    # A reversed walk is NOT a descending code-point run ('y' is not one less
    # than 't'), so it needs its own check: does the value contain a run taken
    # from a keyboard row read right-to-left?
    physical = unshift(password)
    for row in KEYBOARD_ROWS:
        reversed_row = row[::-1]
        for source, label in ((row, "Keyboard row walk"), (reversed_row, "Reversed keyboard walk")):
            for start_index in range(len(source)):
                for length in range(len(source) - start_index, MIN_KEYBOARD_LEN - 1, -1):
                    candidate = source[start_index:start_index + length]
                    if candidate in physical:
                        position = physical.index(candidate)
                        findings.append(_finding(
                            "keyboard_pattern", "medium",
                            "Reversed keyboard walk" if label.startswith("Reversed") else "Keyboard row walk",
                            "A run of adjacent keys read along a keyboard row was found. "
                            "Reversing or shifting a keyboard walk does not make it "
                            "meaningfully harder to guess.",
                            mask(password[position:position + len(candidate)]),
                            list(range(position, position + len(candidate))),
                        ))
                        break
                else:
                    continue
                break
            else:
                continue
            break

    unique: Dict[tuple, Dict] = {}
    for item in findings:
        unique[(item["type"], item["title"], item["evidence"])] = item
    return list(unique.values())


# -----------------------------------------------------------------------------
# 6. Predictable word + number / year / date / phone structures
# -----------------------------------------------------------------------------
YEAR_RE = re.compile(r"(19\d{2}|20\d{2})")
DATE_RE = re.compile(r"(\d{2,4}[-/.]\d{1,2}[-/.]\d{1,4})")
PHONE_RE = re.compile(r"(?:\+?\d[\s-]?){9,}")

# Trailing digits/symbols commonly bolted onto a word:  "welcome123!", "admin2026"
PADDED_WORD_RE = re.compile(r"^[a-z]{3,}[0-9]{1,4}[!@#$%^&*_.-]?$", re.IGNORECASE)
ROTATED_RE = re.compile(r"^[a-z]{3,}[!@#$%^&*_.-]{1,3}[0-9]{1,4}$", re.IGNORECASE)
# Two memorable words joined by a separator and finished with a short number,
# e.g. "Demo-Pattern-123!" -- longer than PADDED_WORD_RE but the same weakness.
WORD_WORD_NUMBER_RE = re.compile(
    r"^[a-z]{3,}[^a-z0-9]{1,2}[a-z]{3,}[^a-z0-9]{1,2}[0-9]{1,4}[^a-z0-9]{0,2}$", re.IGNORECASE)


def detect_predictable_structure(password: str) -> List[Dict]:
    """
    Catch the classic "word + number" and "word + number + symbol" shapes, plus
    year/date/phone-like strings.

    The key teaching point: adding '123' or '!' to a common word does NOT turn
    it into a strong password. It turns it into a strong *pattern* that tools
    enumerate in the first few thousand attempts.
    """
    if not password:
        return []
    findings: List[Dict] = []

    # --- word + digits (+ symbol) ---------------------------------------
    if PADDED_WORD_RE.match(password):
        findings.append(_finding(
            "predictable_structure", "medium",
            "Common word + trailing number",
            "Your password looks like a memorable word plus a short number. "
            "Cracking tools generate exactly this shape first: word lists crossed "
            "with years, 1234, and common symbol endings.",
            mask(password),
        ))
    elif WORD_WORD_NUMBER_RE.match(password):
        findings.append(_finding(
            "predictable_structure", "medium",
            "Memorable words + trailing number",
            "Your password is built from recognisable words joined by separators and finished "
            "with a short number. Attackers combine wordlists with separators and year/number "
            "suffixes, so this shape is only marginally stronger than a single word.",
            mask(password),
        ))
    elif ROTATED_RE.match(password):
        findings.append(_finding(
            "predictable_structure", "medium",
            "Word + symbol + number shape",
            "Your password follows the well-known 'word + symbol + number' shape. "
            "It satisfies composition rules while staying highly predictable.",
            mask(password),
        ))

    # --- years -----------------------------------------------------------
    for match in YEAR_RE.finditer(password):
        year = int(match.group(0))
        # 1900-2026 = plausible birth year; next few years = "current year" habit
        likely_birth_year = 1940 <= year <= 2012
        findings.append(_finding(
            "year_pattern", "medium" if likely_birth_year else "low",
            "Year-like number detected",
            f"A {'plausible birth year' if likely_birth_year else 'year-like number'} "
            f"({mask(match.group(0))}) appears in your password. Birth years and the "
            f"current year are among the most attempted numeric suffixes.",
            mask(match.group(0)),
            list(range(match.start(), match.end())),
        ))

    # --- full dates -------------------------------------------------------
    for match in DATE_RE.finditer(password):
        findings.append(_finding(
            "date_pattern", "medium",
            "Date-like pattern detected",
            "A date-shaped string was found. Birthdays and anniversaries are "
            "guessable from public profile data and social media.",
            mask(match.group(0)),
            list(range(match.start(), match.end())),
        ))

    # --- phone-like -------------------------------------------------------
    phone = PHONE_RE.search(password)
    if phone:
        findings.append(_finding(
            "phone_pattern", "medium",
            "Phone-like digit string detected",
            "A long digit string that looks like a phone number was found. "
            "Phone numbers are identifiable information and appear in breach "
            "corpora used for targeted guessing.",
            mask(phone.group(0)),
            list(range(phone.start(), phone.end())),
        ))

    return findings


# -----------------------------------------------------------------------------
# 7. Personal information overlap (optional, in-memory only)
# -----------------------------------------------------------------------------
def _context_tokens(context: Optional[Dict[str, str]]) -> List[tuple[str, str]]:
    """Turn the user-supplied context dict into (field, token) pairs."""
    if not context:
        return []
    tokens: List[tuple[str, str]] = []
    for field in ("first_name", "last_name", "username", "email", "birth_year", "organisation", "company", "college"):
        raw = (context.get(field) or "").strip()
        if not raw:
            continue
        if field == "email":
            tokens.append((field, raw.split("@")[0]))
            continue
        tokens.extend((field, part) for part in re.split(r"[\s._-]+", raw) if part)
    return [(field, token.lower()) for field, token in tokens if len(token) >= MIN_CONTEXT_LEN]


def detect_personal_info(password: str, context: Optional[Dict[str, str]] = None) -> List[Dict]:
    """
    OPTIONAL check. Compares the password in memory with user-supplied context
    (first name, birth year, organisation) and reports overlap.

    PRIVACY: the context dict is never stored, logged or persisted. It exists
    only for the duration of this function call. This is why the UI labels the
    fields "optional -- nothing is saved".
    """
    if not password or not context:
        return []

    findings: List[Dict] = []
    lowered = password.lower()
    deleet_lowered = deleet(password).lower()

    for field, token in _context_tokens(context):
        if len(token) < MIN_CONTEXT_LEN:
            continue
        if token in lowered or token in deleet_lowered:
            findings.append(_finding(
                "personal_info", "high",
                "Personal information in password",
                f"Your password appears to contain the {field.replace('_', ' ')} you "
                f"provided. Attackers use personal details from social media, breach "
                f"dumps and company websites to build targeted guesses.",
                mask(token),
            ))

    unique: Dict[tuple, Dict] = {}
    for item in findings:
        unique[(item["type"], item["title"], item["evidence"])] = item
    return list(unique.values())


# -----------------------------------------------------------------------------
# 8. Breach-corpus membership (local, k-anonymity style)
# -----------------------------------------------------------------------------
def detect_breach(password: str) -> List[Dict]:
    """
    Check the password against the bundled DEMO SHA-1 corpus.

    Why SHA-1? It is the convention used by the public Have I Been Pwned range
    API. The demo corpus contains only synthetic/common patterns, and the
    lookup is entirely local -- nothing leaves the machine.
    """
    if not password:
        return []
    result = breach_lookup(password)
    if not result["found"]:
        return []
    return [_finding(
        "breach", "critical",
        "Found in demo breach corpus",
        "This password appears in the bundled demo list of publicly known weak "
        "patterns. If a real service reported this, the password must be changed "
        "immediately and never reused.",
        mask(password),
    )]


# -----------------------------------------------------------------------------
# 9. Aggregate detector
# -----------------------------------------------------------------------------
def detect_all_patterns(password: str, context: Optional[Dict[str, str]] = None) -> Dict:
    """
    Run every detector and return:

        {
          "findings": [ ... ],
          "penalty_points": int,     # consumed by scoring_engine
          "penalty_bits": float,     # consumed by entropy_estimator
          "categories": {type: count}
        }
    """
    findings: List[Dict] = []
    structure = analyze_structure(password)

    if password:
        findings += detect_common_password(password)
        findings += detect_common_phrases(password)

        # Dictionary words are a weakness in a *single token* such as
        # "welcome123", but they are the intended building blocks of a genuine
        # multi-word passphrase. This is the one place where structure changes
        # how a signal is interpreted -- documented in docs/SCORING.md.
        if structure["is_passphrase_like"]:
            findings.append(_finding(
                "passphrase_structure", "info",
                "Passphrase structure detected",
                f"This value looks like a passphrase built from {structure['token_count']} words. "
                f"Independent, randomly chosen words are a legitimate way to gain length, so the "
                f"individual words are not counted as weaknesses here.",
                mask(password),
            ))
        else:
            findings += detect_dictionary_words(password)

        findings += detect_sequences(password)
        findings += detect_keyboard_patterns(password)
        findings += detect_repetition(password)
        findings += detect_predictable_structure(password)
        findings += detect_personal_info(password, context)
        findings += detect_breach(password)

    # k-anonymity style detail: expose ONLY the 5-character hash prefix that a
    # real range API would receive. The prefix alone cannot recover a password.
    breach_prefix = sha1_hex(password)[:5] if password else None

    # Sort the most serious findings first so the UI shows what matters.
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), -f["penalty_bits"]))

    categories: Dict[str, int] = {}
    for finding in findings:
        categories[finding["type"]] = categories.get(finding["type"], 0) + 1

    return {
        "findings": findings,
        "pattern_penalty_bits": sum(f["penalty_bits"] for f in findings),
        "categories": categories,
        "breach_prefix": breach_prefix,
        "structure": structure,
    }
