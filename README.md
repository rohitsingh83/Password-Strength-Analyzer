# Password Strength Analyzer & Security Suggestion Tool

> A **privacy-first, defensive** cybersecurity project that scores password strength by
> **predictability** — not by counting symbols — and explains every point it adds or removes.

[![CI](https://github.com/your-username/Password-Strength-Analyzer-Security-Tool/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/Password-Strength-Analyzer-Security-Tool/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-261%20passing-brightgreen)](#testing)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](#technology-stack)
[![Licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)
[![Privacy](https://img.shields.io/badge/passwords%20stored-0-success)](#privacy-design)
[![Scope](https://img.shields.io/badge/cracking%20functionality-none-success)](#security-disclaimer)

**Live demo (GitHub Pages):** `https://<your-username>.github.io/Password-Strength-Analyzer-Security-Tool/`
**No-server demo:** open `Password-Strength-Analyzer-standalone.html` — a single self-contained file.

---

## Table of contents

1. [Overview](#overview)
2. [Problem statement](#problem-statement)
3. [Objectives](#objectives)
4. [Cybersecurity relevance](#cybersecurity-relevance)
5. [Features](#features)
6. [Architecture](#architecture)
7. [Technology stack](#technology-stack)
8. [Password analysis](#password-analysis)
9. [Length analysis](#length-analysis)
10. [Pattern detection](#pattern-detection)
11. [Common password detection](#common-password-detection)
12. [Entropy estimation](#entropy-estimation)
13. [Strength scoring](#strength-scoring)
14. [Security suggestions](#security-suggestions)
15. [Password generator](#password-generator)
16. [Password policy checker](#password-policy-checker)
17. [Privacy design](#privacy-design)
18. [Installation](#installation)
19. [Usage](#usage)
20. [API documentation](#api-documentation)
21. [Testing](#testing)
22. [Security testing](#security-testing)
23. [Results](#results)
24. [Limitations](#limitations)
25. [Future improvements](#future-improvements)
26. [Screenshots](#screenshots)
27. [Learning outcomes](#learning-outcomes)
28. [Security disclaimer](#security-disclaimer)
29. [Author](#author)
30. [Documentation index](#documentation-index)

---

## Overview

Most password meters ask one question: *does it contain uppercase, lowercase, a digit and a
symbol?* That test is trivially satisfied by `Password123!` — one of the most predictable strings
in existence.

This project measures something more useful:

```
LENGTH + UNPREDICTABILITY + PATTERN RESISTANCE + COMMON-PASSWORD CHECKS + CONTEXT
                                = BETTER PASSWORD ASSESSMENT
```

A user types a password and immediately receives a **0–100 score**, a **classification**
(`VERY WEAK` → `VERY STRONG`), a list of **findings that explain the score**, **specific
security suggestions**, an **entropy-style estimate with honest caveats**, a **administrator
policy verdict**, and a **cryptographically secure generator** they can use instead.

Everything is processed **in memory**. Passwords are **never stored, never logged, never
returned in an API response, never placed in a URL and never sent to an external service**.
Each of those guarantees is enforced by code *and* asserted by an automated test.

---

## Problem statement

1. **Weak and reused passwords remain a leading cause of account takeover.** Credential stuffing
   replays username/password pairs from one breach against every other service.
2. **Composition rules give false confidence.** They reward predictable transformations
   (`password` → `P@ssw0rd!`) while rejecting genuinely strong values that omit a symbol.
3. **Users cannot see *why* a password is weak.** A red bar with no explanation changes nothing.
4. **Analytics for password tools are a trap.** Storing or hashing arbitrary submitted passwords
   creates exactly the risk the tool is supposed to prevent.
5. **Modern guidance has moved on.** NIST SP 800-63B and OWASP ASVS emphasise length, blocklists
   and breach checks over mandatory composition and forced periodic rotation.

---

## Objectives

| # | Objective | Where it is delivered |
|---|---|---|
| 1 | Score strength from multiple independent signals | `backend/services/scoring_engine.py` |
| 2 | Measure length and character diversity as contributors, never verdicts | `backend/services/character_analyzer.py` |
| 3 | Detect dictionaries, sequences, keyboard walks, repetition, dates/phones, famous phrases | `backend/services/pattern_detector.py` |
| 4 | Check a small, licensed, educational common-password list locally | `data/common_passwords.txt` |
| 5 | Estimate theoretical **and** effective entropy, with explicit limitations | `backend/services/entropy_estimator.py` |
| 6 | Produce specific, prioritised, password-free advice | `backend/services/suggestion_engine.py` |
| 7 | Generate passwords/passphrases with a CSPRNG (`secrets`) | `backend/services/password_generator.py` |
| 8 | Evaluate an administrator policy **separately** from the score | `backend/services/policy_checker.py` |
| 9 | Store only non-secret aggregate metadata, and allow it to be disabled | `backend/services/audit_store.py` |
| 10 | Ship a real-time meter, dashboard, and education module | `frontend/` |
| 11 | Prove the privacy claims with automated tests | `tests/test_privacy.py` |
| 12 | Demonstrate safe password *storage* concepts in isolation | `backend/services/password_hashing_demo.py` |

---

## Cybersecurity relevance

| Area | How this project relates |
|---|---|
| Authentication systems | Strength feedback belongs at registration and reset, where the choice is made. |
| Banking / e-commerce | Blocking known-breached and patterned passwords reduces account takeover and fraud. |
| Enterprise portals & IAM | Administrators need a configurable policy engine plus aggregate reporting that never collects secrets. |
| Cloud applications | Signup flows integrate an estimator client-side or via one API call. |
| Employee security | Awareness content explains *why* each rule exists, which changes behaviour. |
| Customer accounts | Fewer resets and lockouts; reduced support cost. |
| Password managers | The generator demonstrates what users should rely on instead of memorable passwords. |
| SOC / incident response | Aggregate weakness trends show which habits to target in awareness campaigns. |

**Relevant roles this project demonstrates skills for:** Cybersecurity Analyst · Application
Security Analyst · IAM Analyst · Security Engineer · SOC Analyst · Secure Software Developer.
See [`docs/RESUME_LINKEDIN.md`](docs/RESUME_LINKEDIN.md) for the exact resume bullets,
LinkedIn copy and interview framing.

---

## Features

**Analysis engine**
- ✅ Length analysis with documented, configurable bands
- ✅ Character diversity + unique-character-ratio metrics
- ✅ Common-password detection (local, educational list, l33t-aware)
- ✅ Dictionary word detection incl. l33t substitution and word-prefix matching
- ✅ Sequential (ascending/descending) number and letter detection
- ✅ Keyboard-walk detection incl. shifted (`!@#$`), reversed (`ytrewq`) and row walks
- ✅ Repeated-character and repeated-substring detection
- ✅ Predictable word+number, word+symbol+number and word+year shapes
- ✅ Year / date / phone-like pattern detection
- ✅ Famous-phrase detection (a long phrase is still weak if everyone knows it)
- ✅ Optional personal-context overlap (first name, birth year, organisation) — in memory only
- ✅ Local demo breach-corpus lookup using the SHA-1 prefix convention (k-anonymity style)
- ✅ Theoretical **and** effective entropy, plus Shannon variety, with caveats
- ✅ Structural score caps that arithmetic alone cannot express
- ✅ Classification into `VERY WEAK / WEAK / MODERATE / STRONG / VERY STRONG`
- ✅ Specific, prioritised suggestions — never "make it stronger"

**Application**
- ✅ Real-time meter that updates as you type, with a show/hide toggle (hidden by default)
- ✅ Itemised score breakdown: positive contributions, capped penalties and every applied cap
- ✅ Administrator policy checker with five presets and a separate `POLICY PASS / POLICY FAIL`
- ✅ Secure generator (random password or passphrase) using `secrets` / `crypto.getRandomValues`
- ✅ Privacy-safe dashboard: five charts over non-secret metadata only
- ✅ Education module: 10 rules, entropy explained honestly, hashing demonstration, interview Q&A
- ✅ Flask REST API (+ optional FastAPI variant) with validation, rate limiting and security headers
- ✅ Zero-dependency static build that works offline from a single HTML file

---

## Architecture

```
                            ┌──────────────────────────────┐
                            │            User              │
                            └──────────────┬───────────────┘
                                           │ types a password
                                           ▼
                        ┌──────────────────────────────────┐
                        │  Secure web interface (html/css) │
                        │  password field (hidden by default)│
                        └──────────────┬───────────────────┘
                                       │ in-memory value only
                                       ▼
        ┌────────────────────────────────────────────────────────────────┐
        │                     ANALYSIS ENGINE                            │
        │   (frontend/js/engine.js  ≡  backend/services/*.py)            │
        ├────────────────┬───────────────┬───────────────┬───────────────┤
        │ Length         │ Character     │ Common        │ Sequence      │
        │ analyzer       │ analyzer      │ password      │ detector      │
        ├────────────────┼───────────────┼───────────────┼───────────────┤
        │ Keyboard       │ Repetition    │ Predictable   │ Personal      │
        │ detector       │ detector      │ structure     │ context       │
        ├────────────────┼───────────────┼───────────────┼───────────────┤
        │ Entropy        │ Demo breach   │ Famous phrase │ Structure     │
        │ estimator      │ corpus        │ detector      │ classifier    │
        └────────────────┴───────┬───────┴───────────────┴───────────────┘
                                 ▼
                    ┌────────────────────────┐
                    │  Strength score 0–100  │  ← weights + capped penalties
                    ├────────────────────────┤
                    │  Classification        │  ← VERY WEAK … VERY STRONG
                    ├────────────────────────┤
                    │  Suggestion engine     │  ← specific, prioritised advice
                    ├────────────────────────┤
                    │  Policy checker        │  ← POLICY PASS / FAIL (independent)
                    └───────────┬────────────┘
                                ▼
                        ┌───────────────┐
                        │     User      │
                        └───────────────┘

     OPTIONAL (metadata only — the password never travels this path)
                        ┌──────────────────────────┐
                        │ Aggregate metadata store │  score, classification, length,
                        │ (SQLite; no password or  │  ratios, counts, timestamp
                        │  hash column)            │
                        └───────────┬──────────────┘
                                    ▼
                        ┌──────────────────────────┐
                        │        Dashboard         │  5 charts, aggregates only
                        └──────────────────────────┘
```

**Two runtimes, one engine.** The Python modules and `frontend/js/engine.js` implement the same
rubric. `scripts/generate_fixtures.py` runs the Python engine over 60+ synthetic inputs and
`tests/js/run_parity_test.js` asserts the JavaScript engine produces identical scores,
classifications, finding types and policy verdicts. A divergence fails CI.

---

## Technology stack

| Layer | Choice | Why |
|---|---|---|
| Analysis engine | Python 3.10+ **standard library only** | Zero third-party dependencies in the security-critical path; easy to audit. |
| REST API | **Flask 3** (Option A) | Minimal, one obvious way to do things, ideal for a first API. |
| API variant | **FastAPI** (Option B, optional) | Automatic OpenAPI docs at `/docs`, type-hint validation, async. |
| Analytics | **SQLite** via `sqlite3` | No server to run; schema is inspectable proof that no password is stored. |
| Front-end | **HTML + CSS + vanilla JS** | No build step, no CDN, no network requests — deploys to GitHub Pages as-is. |
| Charts | **hand-written SVG** (`frontend/js/charts.js`) | Chart.js would require a CDN; offline-first matters more than convenience here. |
| Tests | **pytest** (261 tests) + **Node** parity harness (74 assertions) | Python unit/integration suite plus a cross-engine consistency check. |

**Recommended for a student portfolio:** Option A (Flask + vanilla JS). It demonstrates that you
understand HTTP, routing, validation and the DOM without hiding them behind a framework — and it
runs anywhere. Option B is included so you can *compare* the two approaches in your report.

---

## Password analysis

`analyze_password(password, context=None, policy=None, include_hygiene=True)` returns:

```jsonc
{
  "analysis_id": "an_9f2c...",
  "score": 74,                       // 0-100
  "classification": "STRONG",        // VERY WEAK … VERY STRONG
  "classification_summary": "Good, provided it is unique…",
  "findings":  [ { "type": "year_pattern", "severity": "medium",
                   "title": "Year-like number detected",
                   "description": "…", "evidence": "••••" } ],
  "suggestions": [ { "priority": "high", "weakness": "sequence",
                     "title": "Remove predictable sequences",
                     "risk": "…", "action": "…" } ],
  "metrics": { "length": 14, "character_type_count": 4,
               "unique_character_ratio": 0.786, "pattern_count": 1, … },
  "entropy": { "theoretical_bits": 96.4, "effective_bits": 71.4, … },
  "score_breakdown": { "components": {…}, "penalties": {…}, "caps_evaluated": [ … ] },
  "guess_resistance": { "scenarios": [ … ], "estimate_label": "Educational estimate only…" },
  "policy": { "policy_pass": false, "checks": [ … ] },
  "privacy": { "password_stored": false, "password_logged": false, … }
}
```

`evidence` is always **masked with bullet characters** (`••••`), so a finding can point at
*where* a problem is without revealing *what* the characters were.

---

## Length analysis

| Length | Band | Credit |
|---|---|---|
| 0 | Empty | 0.00 |
| 1–7 | Very short | 0.05 |
| 8–11 | Short | 0.40 |
| 12–15 | Better length | 0.72 |
| 16–19 | Strong length | 0.92 |
| 20+ | Excellent length | 1.00 |

Length is the strongest lever a user controls — each extra character multiplies the work an
attacker must do — but **length alone is not security**. `aaaaaaaaaaaaaaaa` earns full length
credit and still cannot exceed **15/100**, because a single repeated character is trivially
guessable. The analyzer demonstrates that tension deliberately:

```
length: 16 characters (Strong length)   ← full length credit
score cap applied: single_repeated_character → capped at 15
classification: VERY WEAK
```

---

## Pattern detection

| Detector | Catches | Example (synthetic) |
|---|---|---|
| `detect_common_password` | exact list matches incl. l33t | `password`, `P@ssw0rd` |
| `detect_common_phrases` | famous quotes/lyrics/proverbs | `correct-horse-battery-staple` |
| `detect_dictionary_words` | words behind padding and substitutions | `welcome2026`, `p@sswords9` |
| `detect_sequences` | ascending/descending runs | `1234`, `abcd`, `9876`, `dcba` |
| `detect_keyboard_patterns` | walks, shifted, reversed, row runs | `qwerty`, `!@#$`, `ytrewq` |
| `detect_repetition` | character runs and repeated blocks | `aaaa`, `1111`, `abcabcabc` |
| `detect_predictable_structure` | word+number, word+symbol+number | `welcome123`, `Demo-Pattern-123!` |
| year / date / phone | calendar and telephone shapes | `1998`, `12-05-2001`, `9876543210` |
| `detect_personal_info` | optional user context overlap | `Demo@123` (context: Demo) |
| `detect_breach` | local demo corpus via SHA-1 prefix | `Password123!` |

Each finding carries a severity, a plain-language explanation, masked evidence and a penalty
weight in "bits an attacker gains for free".

---

## Common password detection

`data/common_passwords.txt` holds ~280 of the most commonly breached **pattern strings**
(`123456`, `qwerty`, `letmein`, `welcome1`, …), compiled from widely published "most common
password" reporting. It contains **no personal data and no user:password pairs**.

```python
from backend.services.pattern_detector import is_common_password
is_common_password("Qwerty123!")   # True  (case-folded)
is_common_password("VermilionGantry9")  # False
```

A match produces:

> "Your password matches a commonly used password pattern and should not be used."

…and a hard cap that keeps the value inside the `VERY WEAK` band, regardless of how good its
composition looks. The same list is used by the policy checker as a registration blocklist.

---

## Entropy estimation

```
Entropy (theoretical) ≈ L × log2(N)        L = length, N = estimated pool size

pool sizes: lowercase 26 · +uppercase 52 · +digits 62 · +symbols ~94 · unicode +100
```

**The limitation is the point.** The formula assumes every character was chosen uniformly at
random. Humans take a memorable word and add a year or a symbol. So `Password123!` looks
respectable in the theoretical estimate while sitting at the top of every attacker's list.

This tool therefore reports three numbers and never hides the reasoning:

| Metric | Meaning |
|---|---|
| **Theoretical bits** | the optimistic `L × log2(N)` figure |
| **Effective bits** | theoretical **minus** a penalty for every predictable structure detected |
| **Shannon bits** | internal character variety — useful signal, blind to dictionaries |

For a genuine passphrase, effective entropy switches to the Diceware model
(`words × log2(word-list size)` ≈ 12.6 bits/word with the bundled 6,300-word list), and the
response states that this assumes the words were picked **randomly** — a human-chosen phrase of
pretty, related words is far weaker than the number suggests.

Guess-resistance is shown as three labelled scenarios (online rate-limited, offline slow hash,
offline fast hash) under the banner **"Educational estimate only — not a guaranteed crack time."**

---

## Strength scoring

```
POSITIVE CONTRIBUTIONS                     MAX     PENALTIES (capped per category)
  Length                                    35       Common password / breach ...... −45
  Character diversity                       15       Personal information ........... −20
  Unique-character ratio                    10       Keyboard walk ................. −15
  Pattern resistance                        20       Sequence ...................... −15
  Not a common password                     10       Repetition .................... −15
  Additional unpredictability               10       Predictable structure ......... −15
                                           ----      Dictionary word ............... −12
                                           100       Year / date / phone ........... −10

STRUCTURAL CAPS (the lowest applicable cap wins)
  empty ....................... 0        single repeated character ....... 15
  extremely short (≤3) ........ 10       very low uniqueness ............. 25
  no letters & short (<12) .... 35       personal information ............ 40
  known common / breach ....... 20       word + year ..................... 45
  word + number shape ......... 60

BANDS   0–20 VERY WEAK · 21–40 WEAK · 41–60 MODERATE · 61–80 STRONG · 81–100 VERY STRONG
```

> ⚠️ **These weights and bands are project-defined**, not a universal security standard.
> Real meters (zxcvbn, vendor products, NIST-oriented guidance) use different scales. The value
> of this rubric is that it is **transparent, itemised and testable** — not that it is
> authoritative. See [`docs/SCORING.md`](docs/SCORING.md) for the full rubric with worked examples.

---

## Security suggestions

Advice is generated per detected weakness. It is always specific, always explains the risk, and
**never contains the submitted password**.

| Instead of… | This tool says… |
|---|---|
| "Make your password stronger." | "Your password contains a predictable numeric sequence (positions 5–8, masked). Break the run apart and mix in unrelated characters." |
| "Use a complex password." | "A memorable word plus a short number is one of the first shapes cracking tools generate. Prefer a passphrase of 4+ unrelated words or a generated password." |
| "Password is weak." | "Stop using this password — it appears in the bundled educational list of the most-used passwords, so it is inside the first few thousand guesses of every attack tool." |

Hygiene reminders (no reuse, use a password manager, enable MFA, never share passwords) are
always included, and can be switched off with `include_hygiene=False`.

---

## Password generator

```python
from backend.services.password_generator import generate_password, generate_passphrase

generate_password(20)          # {'password': '…', 'entropy_bits': 129.8, …}
generate_passphrase(5)         # {'password': 'word-word-word-word-word', …}
```

* **`secrets.SystemRandom`** (Python) / **`crypto.getRandomValues`** (browser) — never `random`.
  `tests/test_generator.py::test_uses_csprng_not_random_module` parses the module with `ast` and
  fails the build if the `random` module ever appears.
* Length presets **16 / 20 / 24** (custom 8–128), class toggles, and an optional look-alike filter
  that removes `l I 1 O 0`.
* Passphrase mode uses a bundled 6,300-word list → ~12.6 bits per word (4 words ≈ 50 bits,
  6 words ≈ 76 bits), with a "generate your own, do not reuse this demo" warning.
* Generated values are returned once and **never stored, logged or cached**; analytics record
  only length, entropy estimate and class count.

---

## Password policy checker

Policy compliance and password strength are **different questions**, and the tool answers both:

```python
from backend.services.policy_checker import PRESET_POLICIES, check_policy

result = check_policy("Copper-Lantern-Orchid-Gravity",
                      PRESET_POLICIES["legacy_bank"], strength_score=92)
result["policy_pass"]      # False  →  missing uppercase/digit/symbol
result["strength_score"]   # 92     →  strong value
```

| Preset | Minimum length | Composition rules | Rotation | Strength floor |
|---|---|---|---|---|
| `nist_baseline` | 8 | none | none | — |
| `standard_account` | 12 | none | none | — |
| `enterprise_iam` | 16 | none | none | ≥ 61 |
| `passphrase_friendly` | 16 | none | none | — |
| `legacy_bank` | 8 | upper+lower+digit+symbol | 90 days | — |

Administrators configure `minimum_length`, `common_password_check`, `personal_info_check` and
more. The `legacy_bank` preset exists to demonstrate the **anti-pattern**: forced composition plus
90-day rotation pushes users towards `Summer2026!` — predictable, and worse than the passphrase it
replaced. Modern guidance (NIST SP 800-63B, OWASP ASVS 2.1) prefers **length + blocklists** and
rotation **only on evidence of compromise**.

---

## Privacy design

| Claim | Enforcement | Test |
|---|---|---|
| No password is stored | no storage API is called; SQLite schema has no password column | `test_T28_password_not_stored` |
| No password is logged | logging filter redacts secret-shaped text; the audit helper literally has no parameter for a value | `test_T29_password_not_in_logs` |
| No password in the response | responses are built from metrics; evidence is bullet-masked | `test_response_never_echoes_password` |
| No password in URLs | value travels only in a JSON body | `test_password_never_in_url` |
| No localStorage / sessionStorage / cookies | session statistics live in a JavaScript variable | `test_no_client_side_persistence_in_frontend` |
| No external transmission | no HTTP client in the backend; the static build makes **0 requests** (and counts them in the UI) | `test_no_outbound_network_code_in_backend` |
| Analytics are metadata only | columns: score, classification, length, ratios, counts, timestamp | `test_schema_has_no_secret_columns` |
| Personal context is never persisted | used in memory for one call; only field *lengths* are echoed back | `test_context_is_not_stored` |
| Secure randomness for generation | `secrets` / `crypto.getRandomValues` | `test_uses_csprng_not_random_module` |
| No cracking functionality | no candidate or guessing loops anywhere | `test_no_cracking_terminology_in_code` |

**Why no hash either?** Storing `sha1(password)` "for analytics" creates a reversible artifact for
short passwords and turns the analytics table into a credential-like store. `test_privacy.py`
asserts that no hash, salt or raw value is written. Only **length, score and category counts** are
kept — which is all the dashboard needs. Full rationale: [`docs/PRIVACY.md`](docs/PRIVACY.md).

---

## Installation

```bash
# 1. Clone
git clone https://github.com/your-username/Password-Strength-Analyzer-Security-Tool.git
cd Password-Strength-Analyzer-Security-Tool

# 2. Virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Dependencies (only Flask + pytest are needed)
pip install -r requirements.txt

# 4. Optional: environment file (safe defaults apply if you skip this)
cp .env.example .env
```

**Zero-install options**

* **Open a single file:** `Password-Strength-Analyzer-standalone.html` runs the entire tool offline.
* **Static site:** publish `frontend/` (or the repo root) with GitHub Pages — see
  [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

---

## Usage

### 1. Local execution — step by step

```bash
# STEP 1 — create the project folder (done by git clone above)
cd Password-Strength-Analyzer-Security-Tool

# STEP 2 — create and activate a virtual environment
python -m venv .venv && source .venv/bin/activate

# STEP 3 — install dependencies
pip install -r requirements.txt

# STEP 4 — start the backend (serves the API *and* the front-end)
python backend/app.py
#   → http://127.0.0.1:5000

# STEP 5 — (optional) run the FastAPI variant instead
# pip install fastapi uvicorn
# uvicorn backend.main:app --reload --port 8000

# STEP 6 — open the browser at http://127.0.0.1:5000

# STEP 7 — analyze the synthetic demo values (or click the chips in the UI)
curl -s -X POST http://127.0.0.1:5000/api/analyze \
     -H "Content-Type: application/json" \
     -d '{"password":"Password123!"}' | head -40

# STEP 8 — read the recommendations in the UI, or inspect them in JSON
curl -s -X POST http://127.0.0.1:5000/api/analyze \
     -H "Content-Type: application/json" \
     -d '{"password":"qwerty2026!"}' | python -m json.tool | grep -A3 '"title"'

# STEP 9 — generate a secure demo password
curl -s -X POST http://127.0.0.1:5000/api/generate-password \
     -H "Content-Type: application/json" \
     -d '{"length":24}'

# STEP 10 — view the aggregate dashboard
curl -s http://127.0.0.1:5000/api/dashboard/stats | python -m json.tool
```

### 2. Safe demonstration cases

All values below are **synthetic demo passwords**. Never demonstrate with a real credential.

| # | Input | Expected result | Why |
|---|---|---|---|
| 1 | `123456` | **VERY WEAK** (0) | common, short, numeric, sequential, keyboard row |
| 2 | `Password123!` | **VERY WEAK** (0) | passes composition; common word + number pattern + demo breach hit → capped ≤ 20 |
| 3 | `aaaaaaaaaaaaaaaa` | **VERY WEAK** (15) | 16 characters of length with essentially zero unpredictability |
| 4 | `qwerty2026!` | **VERY WEAK** (0) | keyboard walk + year + predictable structure |
| 5 | `Copper-Lantern-Orchid-Gravity` | **VERY STRONG** (92) | 4 independent words: length *and* unpredictability |
| 6 | `correct-horse-battery-staple` | **VERY WEAK** (20) | the most famous passphrase advice is in every wordlist |
| 7 | *(runtime)* `generate_password(20)` | **VERY STRONG** (≥ 96) | real randomness from `secrets` |

> Case 2 and case 3 are deliberately *stricter* than a composition-based meter would be — that is
> the entire point of the project, and [`docs/SAFE_DEMO_CASES.md`](docs/SAFE_DEMO_CASES.md)
> documents each deviation and the reasoning behind it.

### 3. Command line

```bash
python -m backend.services.password_analyzer "Demo-Pattern-2026!"     # JSON summary
python scripts/generate_fixtures.py                                  # regenerate parity fixtures
python scripts/build_frontend_data.py                                # rebuild browser data files
python scripts/build_standalone.py                                   # rebuild the single-file demo
python scripts/capture_screenshots.py                                # rebuild the screenshots
```

---

## API documentation

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/analyze` | Analyze one password in memory |
| `POST` | `/api/generate-password` | Generate a password or passphrase (CSPRNG) |
| `GET` | `/api/dashboard/stats` | Aggregate counters, distributions, averages |
| `GET` | `/api/analytics/weaknesses` | Weakness-type frequency (chart data) |
| `GET` | `/api/analytics/recent` | Recent metadata rows (no secret material) |
| `POST` | `/api/analytics/reset` | Clear aggregate metadata |
| `GET` | `/api/policy/presets` | Administrator policy presets |
| `GET` | `/api/education/hashing-demo` | Synthetic password-hashing walk-through |
| `GET` | `/api/schema` | Machine-readable API contract |
| `GET` | `/api/health` | Liveness + privacy flags |

### `POST /api/analyze`

```bash
curl -s -X POST http://127.0.0.1:5000/api/analyze \
     -H "Content-Type: application/json" \
     -d '{
           "password": "Demo-Pattern-2026!",
           "context":  { "first_name": "Demo", "birth_year": "1999" },
           "policy":   { "minimum_length": 16 },
           "include_hygiene": true
         }'
```

```jsonc
{
  "analysis_id": "an_b40bd3552e1a",
  "score": 45,
  "classification": "MODERATE",
  "findings": [
    { "type": "predictable_structure", "severity": "medium",
      "title": "Memorable words + trailing number",
      "description": "…", "evidence": "••••••••••••••••" },
    { "type": "personal_info", "severity": "high",
      "title": "Personal information in password",
      "description": "…", "evidence": "••••" }
  ],
  "suggestions": [ { "priority": "high", "weakness": "personal_info",
                     "title": "Remove your personal information",
                     "risk": "…", "action": "…" } ],
  "metrics": { "length": 17, "character_type_count": 4, "pattern_count": 2 },
  "privacy": { "password_stored": false, "password_logged": false }
}
```

**Status codes**

| Code | When |
|---|---|
| `200` | analyzed (an empty `password` returns a helpful 200 state for the live meter) |
| `400` | validation failure — structured `details[]` naming the field and the limit, never the value |
| `413` | request body larger than `MAX_CONTENT_LENGTH` |
| `429` | rate limited, with a `Retry-After` header |
| `500` | unexpected error — logs the exception **type only**, never a message that could contain input |

**Validation and abuse controls:** JSON body required (form-encoded posts are rejected so a value
cannot slip into a URL-encoded access log), max 256 characters, control characters rejected,
token-bucket rate limiting per client, security headers (`CSP`, `X-Content-Type-Options`,
`Referrer-Policy`, `X-Frame-Options`), and **HTTPS is required in production** because the
password is transmitted to the backend in that deployment mode.

Interactive docs for the FastAPI variant: `http://127.0.0.1:8000/docs`.

---

## Testing

```bash
python -m pytest                       # 261 tests + 74 parity assertions
python -m pytest --cov=backend         # with coverage
node tests/js/run_parity_test.js       # cross-engine parity (68 checks)
```

```
261 passed, 1 skipped in ~3s
JavaScript engine parity test: 68 passed, 0 failed
```

The suite covers all 30 required scenarios from the project brief — empty, single character,
short numeric, common, long repeated, single-class, sequences (both directions), keyboard walks,
repetition, word+number, word+year, personal name, birth year, passphrase, unicode, spaces,
maximum length, band boundaries, suggestions, generation, no-storage, no-logging and analytics —
plus schema inspection, rate limiting, security headers and scope constraints (no cracking code,
no credential data files, no outbound clients).

Full test matrix with the ID → scenario → input → expected → actual → pass/fail table:
[`docs/TESTING.md`](docs/TESTING.md) and [`reports/TEST_REPORT.md`](reports/TEST_REPORT.md).

---

## Security testing

```bash
python -m pytest tests/test_privacy.py tests/test_scope.py -v      # 19 privacy/scope tests
python -m pytest tests/test_analytics.py -v                        # schema inspection
```

| Verification | Result |
|---|---|
| Password not stored (DB bytes + schema) | ✅ |
| Password not logged (captured handler output) | ✅ |
| Password not in the API response | ✅ |
| Password not in the URL | ✅ |
| Input rendered as a password field, hidden by default | ✅ |
| No localStorage / sessionStorage / cookies | ✅ |
| Analytics contains metadata only | ✅ |
| No outbound HTTP client in the backend | ✅ |
| No cracking or guessing functionality | ✅ |
| No credential pairs in the data files | ✅ |

Plus manual checks you can reproduce: inspect `data/analytics.db` with
`sqlite3 data/analytics.db ".schema"` and confirm there is no password column; open DevTools →
Application → Local Storage and confirm nothing is written; open the Network tab and confirm
**zero** requests in the static build.

---

## Results

Calibration table produced by the shipped rubric (all inputs synthetic):

| Input | Score | Classification | Primary signals |
|---|---|---|---|
| `` (empty) | 0 | VERY WEAK | nothing submitted |
| `a` | 10 | VERY WEAK | cap: extremely short |
| `123456` | 0 | VERY WEAK | common + sequence + keyboard row + breach |
| `Password123!` | 0 | VERY WEAK | composition OK; **predictable** → capped ≤ 20 |
| `aaaaaaaaaaaaaaaa` | 15 | VERY WEAK | cap: single repeated character |
| `qwerty2026!` | 0 | VERY WEAK | keyboard walk + year + structure |
| `abcdefgh` | 37 | WEAK | 8 characters, one class, sequence |
| `!@#$%^&*()` | 35 | WEAK | shifted keyboard row, no letters, short |
| `Summer2025!` | 40 | WEAK | dictionary word + year → capped ≤ 45 |
| `Demo-Pattern-123!` | 60 | MODERATE | two words + trailing number → capped ≤ 60 |
| `Hyderabad@2026` | 45 | MODERATE | word + year → capped ≤ 45 |
| `Rahul@123` *(with context)* | 40 | WEAK | personal information → capped ≤ 40 |
| `abcabcabc` | 25 | WEAK | repeated block, 3 unique characters |
| `Tr0ub4dor&3` | 68 | STRONG | 12 characters, four classes, no patterns |
| `Sunset-Orchid-River` | 62 | STRONG | three unrelated words |
| `Copper-Lantern-Orchid-Gravity` | 92 | VERY STRONG | 4 words, ~50 effective bits |
| `correct-horse-battery-staple` | 20 | VERY WEAK | famous phrase → capped ≤ 20 |
| `x7#Kq2!mZ9@vL4$p` | 97 | VERY STRONG | full class mix, no patterns |
| `generate_password(24)` | 100 | VERY STRONG | CSPRNG output |
| `generate_passphrase(5)` | 83 | VERY STRONG | 5 random words (~63 bits) |

Takeaways:

1. **Composition is not strength.** Adding `123!` to a common word changes nothing an attacker
   cares about.
2. **Length is necessary but not sufficient.** Sixteen repeated characters still score 15/100.
3. **Famous advice is a weak passphrase.** The most quoted example fails, by design.
4. **Context matters.** A city + year scores MODERATE despite looking complex.
5. **Randomness wins.** Generated values and genuinely random passphrases occupy the top bands.

Full write-up: [`reports/PROJECT_REPORT.md`](reports/PROJECT_REPORT.md).

---

## Limitations

* The **0–100 rubric and the five bands are project-defined**, not a certified standard.
* The common-password, phrase and keyboard lists are **small and educational**; a production
  deployment should use a properly licensed corpus (e.g. a 10k+ list) with attribution.
* **Entropy is an estimate.** No single formula determines strength; the tool says so on every
  result rather than implying precision.
* The demo breach corpus is **tiny and local**. Production would use a k-anonymity range API that
  sends only the first five hash characters and compares suffixes locally.
* Strength modelling **cannot see reuse, phishing, malware or session theft** — the surrounding
  controls decide whether an account actually survives.
* Unicode handling is deliberately conservative: exotic characters widen the pool but may be
  normalised or rejected by some systems, so they are not presented as a silver bullet.
* The in-process rate limiter is per-worker; multi-worker deployments need a shared store.

---

## Future improvements

* Integrate a peer-reviewed estimator (zxcvbn-style) **alongside** this rubric and report
  disagreements — the most honest way to validate weights.
* Enterprise policy packs with audit export and IAM/SCIM integration concepts.
* Privacy-preserving breached-password lookup via k-anonymity range queries.
* Passkey/WebAuthn and passwordless education flows; MFA adoption nudges.
* Password-manager integration concepts (local-only generation, no clipboard exposure).
* Localisation, screen-reader review, and colour-blind-safe chart modes.
* Organisation-level **aggregate** reporting that still never collects a password.
* A browser-extension mode that scores locally on any signup form.

---

## Screenshots

The **28-item proof checklist** is: files `01`–`28` below. Twenty-two of them are produced
automatically from the real interface and live in [`screenshots/`](screenshots/):

```
03-analyzer-homepage.png                17-analytics-dashboard.png
04-password-field-hidden.png            18-password-generator.png
05-very-weak-result.png                 19-policy-checker.png
06-weak-result.png                      20-entropy-explanation.png
07-moderate-result.png                  21-hashing-demonstration.png
08-strong-result.png                    30-education-rules.png
09-very-strong-result.png               31-interview-qa.png
10-length-and-character-analysis.png    32-privacy-guarantees.png
11-sequence-detection.png
12-keyboard-pattern-detection.png
13-repetition-detection.png
14-common-password-warning.png
15-strength-distribution-chart.png
16-weakness-frequency-chart.png
```

They are genuine browser captures, not mockups — regenerate them with
`python scripts/capture_screenshots.py` (Playwright drives the real UI, and every
value typed is synthetic). The other seven proofs (`01` folder structure, `02`
architecture diagram, `22` tests passing, `23` privacy tests, `24` API response,
`25` database schema, `26` parity test, `27` GitHub repository, `28` README
preview) are captured on your own machine; each one has an exact command in
[`docs/SCREENSHOTS.md`](docs/SCREENSHOTS.md), together with the caption template
used in the written report.

---

## Learning outcomes

* Implemented a **multi-signal security metric** and learned why single-formula strength claims are
  misleading.
* Practised **pattern analysis** (regex, rolling-window sequence detection, dictionary matching,
  l33t normalisation) on adversarial input.
* Designed a **privacy-preserving analytics schema** and proved the guarantees with schema-level
  tests rather than promises.
* Applied **secure coding** habits: memory-only handling, redaction filters, structured error
  contracts that never echo input, rate limiting, security headers.
* Learned **password storage theory** (hashing vs encryption, salting, key stretching, Argon2id /
  scrypt / bcrypt / PBKDF2 work factors) and demonstrated it in isolation from the analyzer.
* Learned **modern policy design** (NIST SP 800-63B, OWASP ASVS 2.1) and why forced rotation and
  composition rules are counter-productive.
* Built and documented a **full-stack application**: engine, REST API, real-time UI, dashboard,
  tests, CI and deployment.
* Wrote **cross-engine parity tests** so a Python and a JavaScript implementation of the same
  rubric cannot silently diverge.

---

## Security disclaimer

This project is an **educational, defensive** security tool.

* It analyses passwords a user voluntarily submits, **in memory**, and returns an estimate plus
  advice.
* It contains **no password-cracking, credential-stuffing, credential-harvesting or
  authentication-bypass functionality**, and none may be added.
* A strength score is an **educational estimate**. It is not a guarantee of account security, not
  a compliance certification, and it cannot see reuse, phishing or endpoint compromise.
* **Never** point this tool at an account you do not own, and **never** enter a real password into
  a demo deployment. Use synthetic values in demonstrations, screenshots and coursework.
* Password security is one layer: **password + MFA + secure hashing + rate limiting + account
  lockout + session security + phishing protection + monitoring.**

---

## Documentation index

| Document | What is in it |
|---|---|
| [`docs/SCORING.md`](docs/SCORING.md) | The full rubric: every weight, penalty, cap and band, with worked examples and how to retune it |
| [`docs/PRIVACY.md`](docs/PRIVACY.md) | Threat model, data-flow guarantees, the schema, why no hash is stored, logging design and the production checklist |
| [`docs/TESTING.md`](docs/TESTING.md) | Test strategy, the 40 numbered scenarios, the privacy suite, parity rules and the browser smoke test |
| [`docs/SAFE_DEMO_CASES.md`](docs/SAFE_DEMO_CASES.md) | The five-minute demonstration script, the full expected-results table and demo hygiene rules |
| [`docs/SCREENSHOTS.md`](docs/SCREENSHOTS.md) | The 28-item proof checklist with captions and regeneration commands |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | GitHub Pages, local Flask, managed hosts, CI and troubleshooting |
| [`docs/GITHUB_SETUP.md`](docs/GITHUB_SETUP.md) | Repository name, description, 11 topics, exact git commands and 14 recommended commit messages |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | Rules for contributors, the golden parity workflow and parity pitfalls to avoid |
| [`docs/RESUME_LINKEDIN.md`](docs/RESUME_LINKEDIN.md) | Resume bullets, LinkedIn copy, repository description, topics and skills |
| [`docs/INTERVIEW_QA.md`](docs/INTERVIEW_QA.md) | The ten interview questions with model answers, plus traps to avoid |
| [`reports/PROJECT_REPORT.md`](reports/PROJECT_REPORT.md) | The complete 28-section project report |
| [`reports/TEST_REPORT.md`](reports/TEST_REPORT.md) | Test results, defect log with root causes, calibration and performance measurements |
| [`SECURITY.md`](SECURITY.md) | Guarantee-to-test mapping and the vulnerability disclosure process |

---

## Author

**Your Name** — cybersecurity student
GitHub: [@your-username](https://github.com/your-username) · LinkedIn: [your-profile](https://www.linkedin.com/in/your-profile)

Built as a defensive cybersecurity course project. Contributions, corrections and issue reports
are welcome — especially anything that improves the accuracy of the rubric or the strength of the
privacy tests. See [`SECURITY.md`](SECURITY.md) for how to report a security issue and
[`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) for the development workflow.

> ⭐ If this project helped you understand password security, star the repository — it helps other
> students find it.
