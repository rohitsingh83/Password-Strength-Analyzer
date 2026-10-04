"""
scripts/capture_screenshots.py
--------------------------------------------------------------------------
PURPOSE
    Drive the real user interface with a headless browser and save the
    screenshots that the README, the project report and the placement portfolio
    refer to.

WHY PLAYWRIGHT
    The images must be genuine captures of the running product, not mockups or
    hand-edited images. Playwright renders the single-file build
    (Password-Strength-Analyzer-standalone.html), so the captures need no
    server and show exactly what a visitor sees.

PRIVACY RULE FOR THIS SCRIPT
    Every value typed into the UI is a SYNTHETIC demo password from
    data/capture-scenarios (defined below). The script must never be pointed at
    a real deployment with a real password.

USAGE
    pip install playwright
    python -m playwright install chromium        # one-time browser download
    sudo apt-get install -y libnspr4 libnss3 libasound2 ...   # if the browser
                                                 # complains about libraries
    python scripts/capture_screenshots.py        # writes screenshots/
    python scripts/capture_screenshots.py --only analyzer-dashboard
--------------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import time

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
STANDALONE = PROJECT_ROOT / "Password-Strength-Analyzer-standalone.html"
OUT_DIR = PROJECT_ROOT / "screenshots"

WIDTH, HEIGHT = 1440, 1000

# ---------------------------------------------------------------------------
# Synthetic capture plan: (filename, caption for the docs, steps)
# ---------------------------------------------------------------------------
SCENARIOS = [
    ("03-analyzer-homepage", "Analyzer tab on first load", [
        ("shot", None),
    ]),
    ("04-password-field-hidden", "Password field hidden by default (type=masked)", [
        ("type", "Password123!"),
        ("shot", None),
    ]),
    ("05-very-weak-result", "VERY WEAK result for a synthetic 6-digit value", [
        ("type", "123456"),
        ("shot", None),
    ]),
    ("06-weak-result", "WEAK result for a repeated-block value", [
        ("type", "abcabcabc"),
        ("shot", None),
    ]),
    ("07-moderate-result", "MODERATE result for a word + year shape", [
        ("type", "Hyderabad@2026"),
        ("shot", None),
    ]),
    ("08-strong-result", "STRONG result for a mixed random value", [
        ("type", "x7#Kq2!mZ9@vL4$p"),
        ("shot", None),
    ]),
    ("09-very-strong-result", "VERY STRONG result for a generated passphrase", [
        ("type", "Tundra-Basil-Falcon-Thistle-Prism"),
        ("shot", None),
    ]),
    ("10-length-and-character-analysis", "Length and character-class analysis tiles", [
        ("type", "Sunset-Orchid-River"),
        ("scroll", "#metric-tiles"),
        ("shot", None),
    ]),
    ("11-sequence-detection", "Descending sequence detected", [
        ("type", "zyxwvuts"),
        ("scroll", "#findings-list"),
        ("shot", None),
    ]),
    ("12-keyboard-pattern-detection", "Keyboard walk detected", [
        ("type", "qwerty123"),
        ("scroll", "#findings-list"),
        ("shot", None),
    ]),
    ("13-repetition-detection", "Repeated character run detected", [
        ("type", "aaaaaaaaaaaaaaaa"),
        ("scroll", "#findings-list"),
        ("shot", None),
    ]),
    ("14-common-password-warning", "Common-password / breach warning", [
        ("type", "Password123!"),
        ("scroll", "#findings-list"),
        ("shot", None),
    ]),
    ("15-strength-distribution-chart", "Score distribution chart", [
        ("tab", "dashboard"), ("click", "#load-samples"), ("wait", 900),
        ("scroll", "#panel-dashboard"), ("shot", None),
    ]),
    ("16-weakness-frequency-chart", "Weakness frequency chart", [
        ("tab", "dashboard"),
        ("scroll", "#chart-weakness"), ("shot", None),
    ]),
    ("17-analytics-dashboard", "Session analytics dashboard (metadata only)", [
        # Self-contained: load the synthetic sample set first, so this capture
        # is identical whether it runs alone (--only) or in the full batch.
        ("tab", "dashboard"), ("click", "#load-samples"), ("wait", 900),
        ("scroll", "top"), ("wait", 400), ("shot", None),
    ]),
    ("18-password-generator", "Secure generator (secrets / crypto.getRandomValues)", [
        ("tab", "generator"), ("click", "#generate-btn"), ("wait", 400), ("shot", None),
    ]),
    ("19-policy-checker", "Policy checker with a modern baseline preset", [
        ("tab", "analyzer"), ("type", "with space passphrase here"), ("wait", 400),
        ("scroll", "#policy-panel"), ("shot", None),
    ]),
    ("20-entropy-explanation", "Entropy panel with its limitations spelled out", [
        ("type", "Tr0ub4dor&3"), ("wait", 400),
        ("scroll", "#entropy-panel"), ("shot", None),
    ]),
    ("21-hashing-demonstration", "Separate hashing demonstration (synthetic value)", [
        ("tab", "learn"), ("click", "#run-hash-demo"), ("wait", 3200),
        ("scroll", "#hash-demo-output"), ("shot", None),
    ]),
    ("30-education-rules", "Ten password security rules", [
        ("tab", "learn"), ("scroll", "#rule-grid"), ("shot", None),
    ]),
    ("31-interview-qa", "Interview Q&A section", [
        ("tab", "learn"), ("scroll", "#qa-list"), ("shot", None),
    ]),
    ("32-privacy-guarantees", "Privacy guarantees page", [
        ("tab", "privacy"), ("scroll", "top"), ("wait", 300), ("shot", None),
    ]),
]


def capture(only: str | None, url: str) -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Playwright is not installed. Run: pip install playwright")
        return 2

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    written, failed = [], []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": WIDTH, "height": HEIGHT})
        page.goto(url, wait_until="load")
        page.wait_for_timeout(700)

        for name, caption, steps in SCENARIOS:
            if only and name != only:
                continue
            try:
                for action, argument in steps:
                    if action == "type":
                        page.fill("#password-input", argument)
                        page.wait_for_timeout(450)
                    elif action == "tab":
                        page.click(f'[data-tab="{argument}"]')
                        page.wait_for_timeout(450)
                    elif action == "click":
                        page.click(argument)
                        page.wait_for_timeout(450)
                    elif action == "wait":
                        page.wait_for_timeout(int(argument))
                    elif action == "scroll":
                        if argument == "top":
                            page.evaluate("window.scrollTo({top: 0})")
                        else:
                            # Selector is passed as an argument (never interpolated
                            # into the script) so the call stays injection-safe.
                            page.evaluate(
                                "(selector) => { const node = document.querySelector(selector);"
                                " if (node) node.scrollIntoView({block: 'center'}); }",
                                argument)
                        page.wait_for_timeout(350)
                    elif action == "shot":
                        path = OUT_DIR / f"{name}.png"
                        page.screenshot(path=str(path))
                        written.append(name)
                        print(f"  saved screenshots/{name}.png  -- {caption}")
            except Exception as error:                       # noqa: BLE001
                failed.append((name, str(error).split("\n")[0]))
                print(f"  FAILED {name}: {str(error).splitlines()[0]}")

        browser.close()

    print()
    print(f"Captured {len(written)} screenshot(s) into {OUT_DIR.relative_to(PROJECT_ROOT)}/")
    if failed:
        print(f"{len(failed)} scenario(s) failed:")
        for name, message in failed:
            print(f"  - {name}: {message}")
        return 1
    print("Add the images to docs/SCREENSHOTS.md captions if you add new scenarios.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--only", help="capture a single scenario by filename stem")
    parser.add_argument("--url", default=None, help="capture a server instead of the local file")
    args = parser.parse_args()

    if args.url:
        url = args.url
    else:
        if not STANDALONE.exists():
            print("Building the single-file bundle first ...")
            import subprocess
            subprocess.run([sys.executable, str(PROJECT_ROOT / "scripts" / "build_standalone.py")],
                           check=True, cwd=str(PROJECT_ROOT))
        url = "file://" + str(STANDALONE.resolve())
        print(f"Capturing {STANDALONE.name} (no server needed)")

    started = time.time()
    code = capture(args.only, url)
    print(f"Finished in {time.time() - started:.1f}s")
    return code


if __name__ == "__main__":
    sys.exit(main())
