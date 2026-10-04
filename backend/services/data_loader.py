"""
backend/services/data_loader.py
--------------------------------------------------------------------------
PURPOSE
    Central, cached loader for the small *educational* data files used by
    the analyzer (common passwords, keyboard patterns, demo breach hashes,
    passphrase word list).

WHY CACHING MATTERS
    Loading a 300-line file on every keystroke would be wasteful. We load
    each file once (module-level cache) and reuse the in-memory set.

PRIVACY NOTE
    These files are read-only reference data. The password submitted by the
    user is NEVER written to any of these files.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import functools
import hashlib
import pathlib
import re
from typing import FrozenSet, List, Set

# --------------------------------------------------------------------------
# Path resolution
# --------------------------------------------------------------------------
# DATA_DIR points at <project root>/data no matter where the app is started
# from, which keeps `python app.py`, `pytest` and `uvicorn` all consistent.
# Separator characters that humans use to glue passphrase words together.
RE_SEPARATORS = re.compile(r"[\s._\-+]+")

SERVICE_DIR = pathlib.Path(__file__).resolve().parent          # backend/services
BACKEND_DIR = SERVICE_DIR.parent                                # backend
PROJECT_ROOT = BACKEND_DIR.parent                               # project root
DATA_DIR = PROJECT_ROOT / "data"


# --------------------------------------------------------------------------
# Low-level helper
# --------------------------------------------------------------------------
def _read_lines(path: pathlib.Path) -> List[str]:
    """Read a text file, skipping comments (#) and blank lines."""
    if not path.exists():
        # Failing soft keeps the analyzer usable even if a data file is
        # missing; the related check simply reports "not found" later.
        return []
    lines: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            lines.append(line)
    return lines


# --------------------------------------------------------------------------
# Cached loaders
# --------------------------------------------------------------------------
@functools.lru_cache(maxsize=1)
def load_common_passwords() -> FrozenSet[str]:
    """
    Return the educational common-password list, lowercased.

    The list contains only well-documented, publicly known weak password
    *strings* (e.g. "password123", "qwerty"). It contains no personal data
    and no leaked credential pairs.
    """
    return frozenset(word.lower() for word in _read_lines(DATA_DIR / "common_passwords.txt"))


@functools.lru_cache(maxsize=1)
def load_keyboard_patterns() -> FrozenSet[str]:
    """Return known keyboard-walk fragments (qwerty, asdf, 1qaz, ...)."""
    return frozenset(word.lower() for word in _read_lines(DATA_DIR / "keyboard_patterns.txt"))


@functools.lru_cache(maxsize=1)
def load_common_phrases() -> FrozenSet[str]:
    """
    Return famous / highly predictable multi-word phrases, normalised to a
    single space between words. Used to show that a long but well-known
    phrase is still weak (for example the famous 'correct horse battery
    staple' example from the XKCD comic).
    """
    normalised = set()
    for line in _read_lines(DATA_DIR / "common_phrases.txt"):
        normalised.add(RE_SEPARATORS.sub(" ", line.lower()).strip())
    return frozenset(p for p in normalised if p)


@functools.lru_cache(maxsize=1)
def load_breach_hashes() -> FrozenSet[str]:
    """
    Return uppercase SHA-1 hex digests for the DEMO breach corpus.

    SECURITY / PRIVACY DESIGN
        The demo file stores SHA-1 digests of synthetic / publicly documented
        common passwords -- never plaintext, never real credentials.
        Lookup is a local set membership test, so the submitted password is
        never transmitted anywhere.

        In production you would instead query a k-anonymity range API:
        send only the first 5 hex characters of SHA-1, receive ~500 hash
        suffixes, and compare in memory. That way the server learns a
        "bucket" and never the full hash of the password.
    """
    return frozenset(
        h.strip().upper() for h in _read_lines(DATA_DIR / "breached_sha1_demo.txt") if h.strip()
    )


@functools.lru_cache(maxsize=1)
def load_passphrase_words() -> FrozenSet[str]:
    """Return the passphrase-generator word list (lowercase, alphabetic)."""
    words = {w.lower() for w in _read_lines(DATA_DIR / "passphrase_words.txt")}
    return frozenset(w for w in words if w.isalpha())


@functools.lru_cache(maxsize=1)
def dictionary_index() -> Set[str]:
    """
    Build the *dictionary* used for common-word detection.

    It merges:
      * the common-password list, and
      * the passphrase word list (so we can flag phrases built from overly
        predictable words too, if they are used alone).

    Words shorter than 4 characters are dropped because short tokens such as
    "as" or "45" appear inside many legitimate passwords and would create
    noisy false positives.
    """
    words = set(load_common_passwords()) | set(load_passphrase_words())
    return {w for w in words if len(w) >= 4}


# --------------------------------------------------------------------------
# Breach helper (k-anonymity style, works fully offline)
# --------------------------------------------------------------------------
def sha1_hex(value: str) -> str:
    """Return the uppercase SHA-1 hex digest of a string (HIBP convention)."""
    return hashlib.sha1(value.encode("utf-8")).hexdigest().upper()


def breach_lookup(password: str) -> dict:
    """
    Check a password against the local demo breach corpus.

    Returns a dict:
        {
          "checked": True,
          "found": bool,
          "prefix": "5 hex chars",       # what a real API would receive
          "count": int                   # 1 when present in the demo set
        }

    NOTE: `count` here is always 1 because the demo corpus stores no hit
    counts. The real HIBP range API returns real counts; the field exists so
    the front-end contract stays the same.
    """
    digest = sha1_hex(password)
    corpus = load_breach_hashes()
    return {
        "checked": True,
        "found": digest in corpus,
        "prefix": digest[:5],
        "count": 1 if digest in corpus else 0,
    }
