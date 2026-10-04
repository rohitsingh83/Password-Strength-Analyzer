"""
backend/services/password_hashing_demo.py
--------------------------------------------------------------------------
PURPOSE
    A SEPARATE, isolated teaching module that demonstrates how a production
    authentication system stores passwords:

        Password  ->  + random Salt  ->  Password Hashing Function  ->  Stored Hash

KEY RULES OBEYED BY THIS FILE
    * It is NOT wired into the analyzer. Nothing the user analyzes is ever
      hashed into persistent storage. (Doing so would turn an analytics tool
      into a credential store, which is exactly what this project refuses to
      do.)
    * The only inputs it accepts are SYNTHETIC demo values supplied by the
      caller -- by default the literal string "Demo-Passphrase-Example-2026".
    * It never logs, stores or returns anything derived from a real password.
    * It does not implement cracking. There is no loop over candidate lists,
      no dictionary attack, no brute-force search. Verification is a single
      comparison, exactly as a login endpoint does it.

WHAT IT TEACHES
    1. Hashing is ONE-WAY verification, not encryption.
    2. A per-user random salt defeats precomputed rainbow tables.
    3. Fast hashes (MD5/SHA-1/SHA-256 alone) are the wrong tool for passwords;
       key-derivation functions exist to be deliberately slow.
    4. Work factors/parameters are tunable, and higher cost = slower guessing
       for the attacker too.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Which algorithms we demonstrate
# ---------------------------------------------------------------------------
# scrypt: available in the Python standard library (hashlib.scrypt), memory-hard,
#         so it resists GPU/ASIC parallel guessing far better than PBKDF2.
# pbkdf2: also standard library; widely supported, but cheaper for an attacker
#         with specialised hardware at the same wall-clock cost.
# Argon2id: the modern recommendation (OWASP first choice). We do NOT import it
#         by default to keep the project dependency-light, but we show the
#         exact call shape in the documentation and in `argon2id_guidance()`.
SCRYPT_PARAMS = {"n": 2 ** 14, "r": 8, "p": 1, "dklen": 32}    # ~16 MB, ~50-100 ms
PBKDF2_ITERATIONS = 600_000                                    # OWASP 2023 guidance
SALT_BYTES = 16


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------
def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def generate_salt(nbytes: int = SALT_BYTES) -> bytes:
    """
    Create a fresh random salt with the OS CSPRNG.

    Why a salt?
        Without a salt, every user with the password "password123" produces an
        identical hash, so one precomputed table cracks every account at once,
        and a single lookup reveals which users share a password. A unique salt
        per user makes each stored hash independent.
    """
    return os.urandom(nbytes)


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------
def hash_password(password: str, algorithm: str = "scrypt",
                  salt: Optional[bytes] = None) -> Dict:
    """
    Hash a password and return a self-describing, storable record.

    Returns e.g.
        {
          "algorithm": "scrypt",
          "salt_b64": "...",
          "hash_b64": "...",
          "params": {"n": 16384, "r": 8, "p": 1, "dklen": 32},
          "encoded": "scrypt$n=16384,r=8,p=1$<salt>$<hash>",
          "duration_ms": 63.4
        }

    The `encoded` string is what you would actually store in a users table:
    it carries the algorithm and parameters so future upgrades stay possible
    (a stored hash must be verifiable years later).
    """
    if not isinstance(password, str) or password == "":
        raise ValueError("Password must be a non-empty string.")
    if len(password.encode("utf-8")) > 1024:
        raise ValueError("Demo limit: refusing to hash unusually large inputs.")

    salt = salt or generate_salt()
    started = time.perf_counter()

    if algorithm == "scrypt":
        raw = hashlib.scrypt(password.encode("utf-8"), salt=salt, **SCRYPT_PARAMS)
        params = dict(SCRYPT_PARAMS)
        encoded = f"scrypt$n={params['n']},r={params['r']},p={params['p']}${_b64(salt)}${_b64(raw)}"
    elif algorithm == "pbkdf2":
        raw = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
        params = {"iterations": PBKDF2_ITERATIONS, "hash": "sha256", "dklen": len(raw)}
        encoded = (f"pbkdf2_sha256${PBKDF2_ITERATIONS}${_b64(salt)}${_b64(raw)}")
    elif algorithm in ("sha256_fast", "md5_fast"):
        # Deliberately included to DEMONSTRATE the anti-pattern.
        raw = hashlib.new("md5" if algorithm == "md5_fast" else "sha256",
                          salt + password.encode("utf-8")).digest()
        params = {"warning": "fast hash -- DO NOT use this for real password storage"}
        encoded = f"{algorithm}${_b64(salt)}${_b64(raw)}"
    else:
        raise ValueError(f"Unsupported demo algorithm: {algorithm!r}")

    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    return {
        "algorithm": algorithm,
        "salt_b64": _b64(salt),
        "hash_b64": _b64(raw),
        "params": params,
        "encoded": encoded,
        "duration_ms": duration_ms,
    }


def verify_password(password: str, stored: Dict) -> bool:
    """
    Verify a login attempt with a CONSTANT-TIME comparison.

    * One candidate, one comparison -- this is what a login endpoint does.
    * `hmac.compare_digest` avoids leaking information through comparison
      timing (a normal `==` can return early on the first differing byte).
    """
    algorithm = stored["algorithm"]
    salt = _unb64(stored["salt_b64"])
    expected = _unb64(stored["hash_b64"])

    if algorithm == "scrypt":
        candidate = hashlib.scrypt(password.encode("utf-8"), salt=salt, **SCRYPT_PARAMS)
    elif algorithm == "pbkdf2":
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                        stored["params"]["iterations"])
    else:
        candidate = hashlib.new("md5" if algorithm == "md5_fast" else "sha256",
                                salt + password.encode("utf-8")).digest()

    return hmac.compare_digest(candidate, expected)


# ---------------------------------------------------------------------------
# The demonstration walk-through used by the UI / report
# ---------------------------------------------------------------------------
# Synthetic only. Never a real user's password.
DEMO_PASSWORD = "Demo-Passphrase-Example-2026"


def demonstration(password: str = DEMO_PASSWORD,
                  algorithms: Optional[List[str]] = None) -> Dict:
    """
    Produce a complete, human-readable walk-through:

        Password -> Salt -> KDF -> Stored Hash -> Verification

    Everything returned is derived from the SYNTHETIC demo value. The UI labels
    this panel clearly, and the analyzer never calls this function.
    """
    algorithms = algorithms or ["scrypt", "pbkdf2", "sha256_fast", "md5_fast"]
    steps: List[Dict] = []

    for algorithm in algorithms:
        record = hash_password(password, algorithm=algorithm)

        # Show that the SAME password with a DIFFERENT salt produces a
        # completely different hash -- the core salt lesson.
        second = hash_password(password, algorithm=algorithm)

        steps.append({
            "algorithm": algorithm,
            "salt_b64": record["salt_b64"],
            "hash_b64": record["hash_b64"],
            "encoded": record["encoded"],
            "duration_ms": record["duration_ms"],
            "same_password_different_salt_hash": second["hash_b64"],
            "salt_changed_output": second["hash_b64"] != record["hash_b64"],
            "verify_correct_password": verify_password(password, record),
            "verify_wrong_password": verify_password(password + "x", record),
            "params": record["params"],
            "guidance": {
                "scrypt": "Memory-hard KDF. Good default; tune n/r/p so hashing takes ~100-250 ms on your hardware.",
                "pbkdf2": "Widely supported KDF. Use >= 600,000 SHA-256 iterations (OWASP 2023) and raise it over time.",
                "sha256_fast": "FAST hash -- easy for GPUs. Shown only to demonstrate why it is the wrong choice.",
                "md5_fast": "Broken and fast. Never use for password storage. Shown only as an anti-pattern.",
            }.get(algorithm, ""),
        })

    return {
        "demo_password_label": "SYNTHETIC DEMO VALUE -- not a real credential",
        "flow": ["Password", "Random Salt (per user)", "Password Hashing Function (KDF)",
                 "Stored Hash + Parameters", "Login: re-hash and compare in constant time"],
        "steps": steps,
        "lessons": [
            "Hashing is one-way: you cannot recover the password from the stored value, and you do not need to.",
            "A unique random salt per user makes identical passwords produce different stored hashes.",
            "Password-hashing functions (Argon2id, scrypt, bcrypt, PBKDF2) are deliberately slow and tunable; "
            "general-purpose hashes are designed to be fast, which helps the attacker.",
            "Encryption is reversible with a key; hashing is not reversible at all. They solve different problems.",
            "Even a perfect hash cannot protect a password that is reused elsewhere: reuse is the attacker's shortcut.",
        ],
        "safety_note": (
            "This module stores nothing, logs nothing and is completely separate from the analyzer. "
            "No value you type into the analyzer is ever passed to these functions."
        ),
    }


def argon2id_guidance() -> Dict:
    """
    Show the recommended modern option without adding a dependency.

    In a real application you would install `argon2-cffi` and write:

        from argon2 import PasswordHasher
        ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
        stored = ph.hash(password)          # includes salt + params
        ph.verify(stored, password)         # raises VerifyMismatchError if wrong
        ph.check_needs_rehash(stored)       # for parameter upgrades
    """
    return {
        "recommended": "Argon2id",
        "why": "Winner of the Password Hashing Competition; combines resistance to GPU "
               "parallelism (memory hardness) with side-channel resistance (hybrid mode).",
        "owasp_minimum": "m=19456 KiB (19 MiB), t=2, p=1 for Argon2id",
        "install": "pip install argon2-cffi",
        "example": (
            "from argon2 import PasswordHasher\n"
            "ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)\n"
            "stored = ph.hash('synthetic-demo-value')   # salt is generated for you\n"
            "ph.verify(stored, 'synthetic-demo-value')  # True, or raises an exception\n"
        ),
        "peer_options": {
            "bcrypt": "Well-tested, 72-byte input limit; cost factor >= 10.",
            "scrypt": "Standard library, memory-hard; used in this demo.",
            "pbkdf2": "Very widely supported; use >= 600,000 iterations with SHA-256.",
        },
    }


def generate_demo_salt_pair() -> Dict[str, str]:
    """Two random salts + the same password, to show salts differ per record."""
    password = DEMO_PASSWORD
    first = hash_password(password, "scrypt", salt=secrets.token_bytes(SALT_BYTES))
    second = hash_password(password, "scrypt", salt=secrets.token_bytes(SALT_BYTES))
    return {
        "same_password": "hidden deliberately -- the same synthetic value is used for both",
        "salt_1": first["salt_b64"][:12] + "...",
        "hash_1": first["hash_b64"][:24] + "...",
        "salt_2": second["salt_b64"][:12] + "...",
        "hash_2": second["hash_b64"][:24] + "...",
        "conclusion": "Same password, different salts, completely different stored hashes.",
    }


if __name__ == "__main__":       # pragma: no cover
    import json

    report = demonstration()
    for step in report["steps"]:
        print(f"{step['algorithm']:12} {step['duration_ms']:7.1f} ms  "
              f"verify(correct)={step['verify_correct_password']}  "
              f"verify(wrong)={step['verify_wrong_password']}")
    print(json.dumps(generate_demo_salt_pair(), indent=2))
