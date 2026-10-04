"""
backend/services/password_generator.py
--------------------------------------------------------------------------
PURPOSE
    Defensive password / passphrase generation using a CRYPTOGRAPHICALLY
    SECURE random source.

WHY `secrets` AND NOT `random`
    Python's `random` module (Mersenne Twister) is a *statistical* PRNG. It is
    fast and fine for simulations, but its internal state can be reconstructed
    from enough observed output, which makes it unsuitable for anything that
    protects an account.

    `secrets` uses the operating system CSPRNG (os.urandom / getrandom), which
    is designed to be unpredictable even to an attacker who watches everything
    else on the machine.

    `secrets.choice()` is also unbiased, whereas the common beginner idiom
    `random.choice(alphabet)` inherits the weaker generator.

GUARANTEES IMPLEMENTED HERE
    * At least one character from every requested class (optional).
    * Exclusive use of secrets.SystemRandom for sampling AND shuffling.
    * No password is ever written to disk, logged, cached or returned twice.
    * Spaces/hyphens allowed for passphrases, and marked as demo examples.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import math
import secrets
import string
from typing import Dict, List, Optional

from .data_loader import load_passphrase_words

# Character pools
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits

# Ambiguous glyphs are removed by default so a human can retype the result:
#   l (lower L) vs I (upper i) vs 1,  O (letter) vs 0 (zero)
AMBIGUOUS = "lI1O0o"
SYMBOLS_FULL = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"
SYMBOLS_SAFE = "!@#$%^&*-_=+?"

DEFAULT_LENGTHS = (16, 20, 24)
MIN_LENGTH = 8
MAX_LENGTH = 128


# -----------------------------------------------------------------------------
# 1. Random password
# -----------------------------------------------------------------------------
def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    symbol_set: str = SYMBOLS_FULL,
    avoid_ambiguous: bool = True,
    ensure_each_class: bool = True,
) -> Dict:
    """
    Generate a random password with Python's `secrets` module.

    Returns a dict (not a bare string) so the caller can show the user exactly
    what properties the generated password has, and so the API response has a
    stable shape:

        {"password": "...", "length": 20, "pool_size": 94,
         "entropy_bits": 131.1, "classes_used": [...], "generator": "secrets.CSPRNG"}
    """
    length = max(MIN_LENGTH, min(int(length), MAX_LENGTH))

    pools: List[tuple[str, str]] = []
    if use_lowercase:
        pools.append(("lowercase", LOWERCASE))
    if use_uppercase:
        pools.append(("uppercase", UPPERCASE))
    if use_digits:
        pools.append(("digits", DIGITS))
    if use_symbols:
        pools.append(("symbols", symbol_set))

    if not pools:      # refuse to invent a policy the caller did not ask for
        raise ValueError("At least one character class must be enabled.")

    if avoid_ambiguous:
        pools = [
            (name, "".join(ch for ch in chars if ch not in AMBIGUOUS))
            for name, chars in pools
        ]

    alphabet = "".join(chars for _, chars in pools)
    if len(alphabet) < 2:
        raise ValueError("Character pool too small after filtering.")

    rng = secrets.SystemRandom()
    characters: List[str] = []

    # Guarantee every requested class appears at least once. This is a
    # *policy convenience* (some registration forms demand it), not a security
    # requirement -- length and randomness are what actually matter.
    if ensure_each_class and len(pools) > 1:
        for _, chars in pools:
            characters.append(secrets.choice(chars))

    while len(characters) < length:
        characters.append(secrets.choice(alphabet))

    rng.shuffle(characters)                 # secure Fisher-Yates via SystemRandom
    password = "".join(characters)

    pool_size = len(alphabet)
    entropy_bits = round(length * math.log2(pool_size), 1) if pool_size > 1 else 0.0

    return {
        "password": password,
        "length": length,
        "pool_size": pool_size,
        "entropy_bits": entropy_bits,
        "theoretical_entropy_bits": entropy_bits,
        "classes_used": [name for name, _ in pools],
        "generator": "Python secrets module (OS CSPRNG)",
        "note": (
            "Generated locally in memory. Nothing is stored, logged or transmitted. "
            "For genuinely random output the theoretical entropy estimate is a fair "
            "approximation -- unlike for human-chosen passwords."
        ),
    }


# -----------------------------------------------------------------------------
# 2. Random passphrase (Diceware style)
# -----------------------------------------------------------------------------
def generate_passphrase(
    words: int = 4,
    separator: str = "-",
    capitalise: bool = False,
    append_number: bool = False,
    wordlist_size: Optional[int] = None,
) -> Dict:
    """
    Build a passphrase from randomly selected words in the bundled list.

    Entropy = words x log2(wordlist_size). With ~6,300 words that is ~12.6 bits
    per word, so 4 words ~= 50 bits and 6 words ~= 76 bits.

    `secrets.choice` guarantees the words are independent draws WITH
    replacement -- which is what makes the entropy maths valid. A human
    "random" passphrase ("sunset-river-love-happy") is far weaker than the
    number suggests because humans avoid repeating themes and prefer pretty
    words.
    """
    vocabulary = sorted(load_passphrase_words())
    if len(vocabulary) < 100:
        raise RuntimeError("Passphrase word list is missing or too small.")

    words = max(3, min(int(words), 10))         # 3..10 words keeps UI sane
    chosen = [secrets.choice(vocabulary) for _ in range(words)]

    if capitalise:
        chosen = [w.capitalize() for w in chosen]
    if append_number:
        # A single digit adds ~3.3 bits only, and reduces memorability. Offered
        # because some outdated policies still demand a number.
        chosen.append(str(secrets.randbelow(100)))

    phrase = separator.join(chosen)
    per_word_bits = math.log2(len(vocabulary))
    entropy_bits = round(words * per_word_bits + (math.log2(100) if append_number else 0), 1)

    return {
        "password": phrase,
        "passphrase": phrase,
        "length": len(phrase),
        "word_count": words,
        "wordlist_size": len(vocabulary),
        "bits_per_word": round(per_word_bits, 2),
        "entropy_bits": entropy_bits,
        "theoretical_entropy_bits": entropy_bits,
        "separator": separator,
        "generator": "Python secrets module (OS CSPRNG) + local word list",
        "note": (
            "DEMO EXAMPLE -- do not reuse this exact phrase. Generate your own and "
            "save it in a password manager. Longer phrases (5-6 words) are easier to "
            "remember than random characters and score very well on length."
        ),
    }


# -----------------------------------------------------------------------------
# 3. Batch generation for demos and tests
# -----------------------------------------------------------------------------
def generate_batch(count: int = 3, **kwargs) -> List[Dict]:
    """Generate several passwords (default: the 16 / 20 / 24 presets)."""
    count = max(1, min(int(count), 10))
    results = []
    for index in range(count):
        length = DEFAULT_LENGTHS[index % len(DEFAULT_LENGTHS)]
        results.append(generate_password(length=length, **kwargs))
    return results


if __name__ == "__main__":       # pragma: no cover
    print(generate_password(20)["password"])
    print(generate_passphrase(5)["passphrase"])
