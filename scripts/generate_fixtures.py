"""
scripts/generate_fixtures.py
--------------------------------------------------------------------------
PURPOSE
    Produce a shared fixture file from the PYTHON engine so the JavaScript
    engine can be checked for parity.

    Pipeline:
        scripts/generate_fixtures.py            (Python engine  -> JSON)
        tests/js/run_parity_test.js             (JS engine reads the JSON)
        .github/workflows/ci.yml                (runs both on every push)

    Every password in the fixture list is a SYNTHETIC demo value.

USAGE
    python scripts/generate_fixtures.py
"""

from __future__ import annotations

import json
import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.services.password_analyzer import analyze_password     # noqa: E402
from backend.services.password_generator import (                   # noqa: E402
    generate_passphrase,
    generate_password,
)

# Synthetic demo inputs only. Grouped so the fixture exercises every detector.
DEMO_INPUTS = [
    ("", None),
    ("a", None),
    ("ab", None),
    ("123456", None),
    ("12345678", None),
    ("987654321", None),
    ("password", None),
    ("password123", None),
    ("Password123!", None),
    ("P@ssw0rd", None),
    ("letmein", None),
    ("welcome", None),
    ("admin", None),
    ("iloveyou1", None),
    ("qwerty", None),
    ("qwerty123", None),
    ("qwerty2026!", None),
    ("1qaz2wsx", None),
    ("asdfghjkl", None),
    ("zxcvbnm123", None),
    ("aaaaaaaaaaaaaaaa", None),
    ("aaaaaaaa", None),
    ("111111111111", None),
    ("abcabcabc", None),
    ("ababababab", None),
    ("abc123abc123", None),
    ("1234abcd", None),
    ("abcdefgh", None),
    ("zyxwvuts", None),
    ("ABCDEFGHIJ", None),
    ("!@#$%^&*()", None),
    ("9876543210", None),
    ("Summer2025!", None),
    ("welcome123", None),
    ("admin2026", None),
    ("hello1234", None),
    ("Demo-Pattern-123!", None),
    ("Demo-Pattern-Shape-2026", None),
    ("correct-horse-battery-staple", None),
    ("Copper-Lantern-Orchid-Gravity", None),
    ("Tundra-Basil-Falcon-Thistle-Prism", None),
    ("Tr0ub4dor&3", None),
    ("x7#Kq2!mZ9@vL4$p", None),
    ("9fJ#2Lm$8Qz!5Xr@7Tb", None),
    ("Sunset-Orchid-River", None),
    ("with space passphrase here", None),
    ("Rahul@123", {"first_name": "Rahul", "birth_year": "1999", "organisation": "Demo College"}),
    ("Hyderabad@2026", {"organisation": "Demo College"}),
    ("DemoCollege@123", {"organisation": "Demo College"}),
    ("1999-Demo-Name", {"first_name": "Demo", "birth_year": "1999"}),
    ("Абвгдеж1234!", None),
    ("пароль123", None),
    ("pass word demo 2026", None),
    ("test", None),
    ("MyDog-Is-Named-Coco", None),
    # --- repetition regression cases (case-sensitivity bug, see
    #     tests/test_repetition_regression.py). Both engines must agree. ---
    ("jdDjDd", None),
    ("PassPass", None),
    ("Ab1Ab1Ab1", None),
    ("JHN7c1VQ27KldixYLn3KNQKaZK", None),
    # --- famous phrases: long but one of the first things a cracker tries ---
    ("correct horse battery staple", None),
    ("The-Quick-Brown-Fox-2026", None),
]


def main() -> None:
    fixtures = []
    for password, context in DEMO_INPUTS:
        result = analyze_password(password, context=context)
        fixtures.append({
            "password": password,
            "context": context,
            "score": result["score"],
            "classification": result["classification"],
            "finding_types": sorted(f["type"] for f in result["findings"]),
            "weakness_count": result["metrics"].get("weakness_count", 0),
            "length": result["metrics"].get("length", 0),
            "unique_character_ratio": result["metrics"].get("unique_character_ratio", 0.0),
            "pattern_count": result["metrics"].get("pattern_count", 0),
            "policy_pass": result["policy"].get("policy_pass", False),
            "score_cap_applied": bool(result.get("score_cap_applied")),
        })

    # Generated samples: only the *properties* are recorded, never the value.
    for mode, meta in (("password16", generate_password(16)),
                       ("password20", generate_password(20)),
                       ("password24", generate_password(24)),
                       ("passphrase4", generate_passphrase(4)),
                       ("passphrase6", generate_passphrase(6))):
        result = analyze_password(meta["password"])
        fixtures.append({
            "password": meta["password"],
            "context": None,
            "generated_mode": mode,
            # Generated values differ on every run, so CI cannot check this entry
            # for staleness. The deterministic entries above are checked instead
            # (tests/test_fixtures.py recomputes them), while these volatile
            # entries only prove that the JavaScript engine scores a
            # freshly-generated value the same way Python did.
            "volatile": True,
            "score": result["score"],
            "classification": result["classification"],
            "finding_types": sorted(f["type"] for f in result["findings"]),
            "weakness_count": result["metrics"].get("weakness_count", 0),
            "length": result["metrics"].get("length", 0),
            "unique_character_ratio": result["metrics"].get("unique_character_ratio", 0.0),
            "pattern_count": result["metrics"].get("pattern_count", 0),
            "policy_pass": result["policy"].get("policy_pass", False),
            "score_cap_applied": bool(result.get("score_cap_applied")),
        })

    out_dir = PROJECT_ROOT / "tests" / "fixtures"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "expected_results.json"
    out_path.write_text(json.dumps({
        "generated_by": "scripts/generate_fixtures.py (Python engine)",
        "engine_version": "1.0",
        "note": "All passwords are synthetic demo values. Generated entries are runtime samples "
                "used only to check that both engines agree.",
        "fixtures": fixtures,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(fixtures)} fixtures to {out_path.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
