# Screenshot and proof checklist

Two parts, and the file names run `01`–`28` so the checklist is easy to follow:

* **A. 22 UI captures that ship in this repository** — produced automatically from
  the real interface by `python scripts/capture_screenshots.py` (Playwright, no
  manual editing, no mockups). These are files `03`–`21`.
* **B. 7 terminal/repository proofs you capture on your own machine** — your
  environment, your test run and your GitHub repository. These are files `01`,
  `02` and `22`–`28`.

Together: the **28-item proof checklist** for the project report, the README and a
placement portfolio. Files `30`–`32` are three extras (education rules, interview
Q&A, privacy page) captured by the same script.

> **Privacy rule:** every captured value is synthetic (see
> [`SAFE_DEMO_CASES.md`](SAFE_DEMO_CASES.md)). Never capture a screenshot with a
> real password in it, and never capture the personal-context panel with real
> personal data.

---

## A. Automated captures (in `screenshots/`)

| File | Shows | Why a reviewer cares |
|---|---|---|
| `03-analyzer-homepage.png` | Analyzer tab on first load | First impression: layout, branding, the "Offline · Private" badge |
| `04-password-field-hidden.png` | Password field masked by default | Proves the privacy-by-default decision |
| `05-very-weak-result.png` | `123456` → 0 VERY WEAK | The baseline case; multiple overlapping findings |
| `06-weak-result.png` | `abcabcabc` → 25 WEAK | Repetition detected in a short value |
| `07-moderate-result.png` | `Hyderabad@2026` → 45 MODERATE | Word + year cap in action |
| `08-strong-result.png` | `x7#Kq2!mZ9@vL4$p` → 97 VERY STRONG | A genuinely random value |
| `09-very-strong-result.png` | `Tundra-Basil-Falcon-Thistle-Prism` → 91 | A passphrase that beats the random value per character |
| `10-length-and-character-analysis.png` | Length + character-class tiles | Shows the positive-score components, not just penalties |
| `11-sequence-detection.png` | `zyxwvuts` → sequence finding | Detector evidence, masked |
| `12-keyboard-pattern-detection.png` | `qwerty123` → keyboard walk | Detector evidence, masked |
| `13-repetition-detection.png` | `aaaaaaaaaaaaaaaa` → repeated run | Long ≠ strong |
| `14-common-password-warning.png` | `Password123!` → breach + dictionary | The headline lesson of the project |
| `15-strength-distribution-chart.png` | 5-band distribution chart | Hand-built SVG, no chart library, works offline |
| `16-weakness-frequency-chart.png` | Weakness frequency chart | Aggregate analytics with no secret material |
| `17-analytics-dashboard.png` | Full dashboard incl. metadata table | The exact columns the SQLite schema stores |
| `18-password-generator.png` | Generator with a fresh value | `secrets` / `crypto.getRandomValues`, entropy label |
| `19-policy-checker.png` | POLICY PASS shown separately from the score | Policy is a rule set, not a measurement |
| `20-entropy-explanation.png` | Entropy panel with its limitations | The caveat is part of the product, not the small print |
| `21-hashing-demonstration.png` | Two hashes for one repeated value | Salting, demonstrated in isolation from the analyzer |
| `30-education-rules.png` | Ten password security rules | The teaching artefact of the project |
| `31-interview-qa.png` | Interview Q&A section | Placement prep built into the product |
| `32-privacy-guarantees.png` | Privacy page | The guarantees, each matched by an automated test |

Regenerate everything (about 40 seconds):

```bash
pip install playwright
python -m playwright install chromium
python scripts/capture_screenshots.py
```

Linux may need the browser's shared libraries once:

```bash
sudo apt-get install -y libnspr4 libnss3 libasound2t64 libatk1.0-0t64 \
     libatk-bridge2.0-0t64 libcups2t64 libdrm2 libxkbcommon0 libxcomposite1 \
     libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2
```

Capture a single scenario while iterating: `python scripts/capture_screenshots.py --only 17-analytics-dashboard`.
Capture a live Flask server instead of the file build: `python scripts/capture_screenshots.py --url http://127.0.0.1:5000`.

---

## B. Proofs you capture locally

| File | Command / source | What it proves |
|---|---|---|
| `01-project-folder-structure.png` | `python scripts/show_tree.py` | The documented structure, file sizes and line counts match reality |
| `02-architecture-diagram.png` | `docs/architecture.svg`, or a screenshot of the ASCII diagram in the README | You can explain data flow, not just code |
| `22-unit-tests-passing.png` | `python -m pytest -q` → **261 passed, 1 skipped** | The suite really is green |
| `23-privacy-security-tests.png` | `python -m pytest tests/test_privacy.py tests/test_scope.py -v` | The privacy claims are enforced by tests, not asserted in prose |
| `24-api-response-json.png` | the `curl` example in the README, piped through `python -m json.tool` | The API returns metrics and masked evidence, never the value |
| `25-database-schema-no-password-column.png` | `python scripts/show_schema.py` | The database physically cannot store a password |
| `26-js-engine-parity-test.png` | `node tests/js/run_parity_test.js` → **74 passed** | Two independent engines agree on all 66 shared fixtures |
| `27-github-repository.png` | `https://github.com/<you>/Password-Strength-Analyzer-Security-Tool` | The repository is public, described and topic-tagged |
| `28-readme-preview.png` | The README rendered on GitHub | Documentation quality |

Two tiny helpers keep those captures reproducible (they exist so nobody has to
invent a command during a demo):

```bash
# 01 -- print the documented tree with file sizes and line counts
python scripts/show_tree.py

# 25 -- print the real SQLite schema and assert no column can hold a password
python scripts/show_schema.py
```

Both scripts are read-only. `show_schema.py` exits non-zero if a password-capable
column is ever introduced, which makes it usable as a pre-demo sanity check.

## C. Extras captured by the same script

| File | Shows |
|---|---|
| `30-education-rules.png` | The ten password security rules |
| `31-interview-qa.png` | The interview Q&A section |
| `32-privacy-guarantees.png` | The privacy guarantees page |

---

## D. Caption template for reports

Use this shape so every figure in the report is self-explanatory:

```
Figure 7 — MODERATE classification for the synthetic value "Hyderabad@2026".
The word-plus-year structure is recognised and the score is capped at 45, below
the STRONG band. The password itself is masked and never displayed, logged or
stored. (Source: screenshots/07-moderate-result.png)
```

Rules for report figures:

1. Name the figure, the classification and the value's **shape** (a word plus a
   year) — and say that the value is synthetic.
2. State the finding the image demonstrates.
3. Repeat the privacy note at least once in the report, not once per figure.
4. Never embed a screenshot that shows an unmasked field.
