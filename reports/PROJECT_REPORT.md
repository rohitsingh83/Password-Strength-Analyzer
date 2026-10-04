# Project report

**Password Strength Analyzer & Security Suggestion Tool**

| | |
|---|---|
| **Type** | Defensive cybersecurity course project (industry-oriented) |
| **Author** | *Your Name* — cybersecurity student |
| **Repository** | `https://github.com/<your-username>/Password-Strength-Analyzer-Security-Tool` |
| **Live demo** | `https://<your-username>.github.io/Password-Strength-Analyzer-Security-Tool/` |
| **Stack** | Python 3 · Flask · SQLite · JavaScript (ES2020) · HTML/CSS · pytest · Playwright · GitHub Actions |
| **Status** | Complete — 261 pytest tests + 74 parity assertions passing |
| **Scope** | Educational, defensive. No cracking, no credential collection, no external transmission. |

---

## Contents

1. Abstract · 2. Introduction · 3. Problem statement · 4. Objectives ·
5. Literature and guidance review · 6. Domain background · 7. Requirements ·
8. Architecture · 9. Design decisions · 10. Scoring model · 11. Pattern
detection · 12. Entropy model · 13. Suggestion engine · 14. Generator ·
15. Policy checker · 16. Hashing demonstration · 17. Privacy and security design ·
18. Database design · 19. API design · 20. Front-end design · 21. Dual-engine
parity · 22. Implementation summary · 23. Testing and results · 24. Limitations ·
25. Future work · 26. Lessons learned · 27. Conclusion · 28. References and
appendices

---

## 1. Abstract

Password meters are the security control users encounter most often, and most of
them are wrong. A meter that demands an uppercase letter, a lowercase letter, a
digit and a symbol awards full marks to `Password123!`, a value that appears in
the first few thousand guesses of any cracking tool. This project implements a
password strength analyzer that scores **predictability instead of symbol
counting**, explains every finding and every point in ordinary language, and
processes the submitted value **in memory only** — never storing, logging,
returning or transmitting it.

The system is delivered twice from one rubric: a Python engine of eleven service
modules exposed through a Flask REST API with aggregate SQLite analytics, and a
JavaScript port of the same engine that runs entirely in the browser and is
published to GitHub Pages, where it analyses passwords with **zero network
requests**. A Node parity harness runs 66 shared fixtures through both engines so
they cannot silently diverge; during development it caught real Unicode
classification, floating-point rounding and duplicate-finding bugs.

Correctness and privacy are treated as testable properties. 261 pytest tests and
74 parity assertions cover the scoring rubric (pinned by a calibration table), all
14 detectors, the API contract, the policy checker, the generator, the hashing
demonstration, and — most importantly — the privacy guarantees, which are
enforced at the schema level, the log-filter level and the source level. The
project ships with 22 automated UI screenshots, a 28-item proof checklist, a safe
demonstration script, a deployment guide and placement documentation.

---

## 2. Introduction

A password is still the most common authentication factor, and it is the one users
choose themselves. Strength estimation exists to give users immediate, actionable
feedback at the moment of choice — usually registration or a password change.

Most deployed meters answer a composition question: *does this string contain at
least one character from each of several classes?* That question is easy to
implement and easy to satisfy, which is exactly why it fails. Attackers do not
brute-force the full character space; they guess dictionaries with mangling rules,
keyboard walks, dates, names and previously leaked values, in order of
likelihood. This project restates the problem in the attacker's terms, and then
builds a tool that also demonstrates good engineering practice around a value that
must never be mishandled.

---

## 3. Problem statement

1. **Composition rules mislabel predictable passwords as strong.** `Password123!`,
   `Admin@123` and `Welcome1!` all pass a composition check and all fall in the
   first few thousand guesses.
2. **Length alone is not sufficient.** `aaaaaaaaaaaaaaaa` is 16 characters and
   trivially guessable; `correct-horse-battery-staple` is 28 characters and
   published in every wordlist.
3. **Entropy formulas overstate human-chosen strength** because they assume
   uniform random selection.
4. **Generic advice is not actionable.** "Use a stronger password" does not tell a
   user which part of their choice is the problem.
5. **Asking users to type their most sensitive string creates a duty of care.**
   Many tools that measure passwords also log, store or transmit them.
6. **Policy is conflated with strength.** A strong password can fail an
   organisation's rules, and a weak one can pass them.

---

## 4. Objectives

| # | Objective | Delivered as |
|---|---|---|
| O1 | Score strength by predictability, using many independent signals | `score_password()` with six positive components, per-category penalties and structural caps |
| O2 | Detect the patterns attackers actually use | 14 detectors: common/breached values, dictionary and l33t variants, sequences (both directions), keyboard walks (both directions), repeated characters, repeated blocks, word+number, word+year, dates, phones, personal context, famous phrases |
| O3 | Explain the result | Itemised breakdown, per-capita penalty list, finding cards with masked evidence, and a suggestion for each finding |
| O4 | Estimate entropy *and* state its limits | `entropy_report()` with theoretical and effective bits plus caveats, and a labelled guess-resistance table |
| O5 | Never mishandle the value | Memory-only processing, no storage, no logging, no echo, no transmission — each with an automated test |
| O6 | Provide safe analytics | Aggregate-only SQLite schema with no password-capable column |
| O7 | Separate policy from strength | `policy_checker.py` with five presets, reporting POLICY PASS/FAIL independently |
| O8 | Teach | Ten password rules, passphrase education, login-security guidance, hashing demonstration, interview Q&A |
| O9 | Be deployable and demonstrable | Zero-network GitHub Pages site plus a single-file offline build |
| O10 | Be verifiable | 261 pytest tests, 74 parity assertions, pinned calibration table, 22 automated screenshots |

---

## 5. Literature and guidance review

| Source | What it changed in this project |
|---|---|
| **NIST SP 800-63B** (Digital Identity Guidelines) | Minimum length over composition rules; blocklist of compromised values; **no** arbitrary periodic expiry; allow spaces and long values; maximum length at least 64 |
| **OWASP ASVS 2.1** (password security requirements) | Permits composition rules but treats length and blocklists as primary; recommends breach checking |
| **OWASP Password Storage Cheat Sheet** | Argon2id first, then scrypt/bcrypt/PBKDF2 with explicit work factors; per-user salt; upgrade path via encoded parameters |
| **OWASP Authentication Cheat Sheet** | Rate limiting, lockout, generic error messages, secure session cookies |
| **zxcvbn** (Wheeler, Dropbox) | Confirms the multi-signal approach: dictionary, spatial, repeat and sequence matchers, sequence-date detection, and a guess-estimate combination model. This project borrows the *ideas* and mirrors specific behaviour (case-sensitive repeat matching) but uses a transparent, explainable, project-defined rubric instead of a hidden guess model |
| **Diceware / EFF wordlists** | Word-based entropy (`words × log2(wordlist)`) for passphrases, used as an *upper bound* and labelled as such |
| **Shannon entropy** | Reported for comparison only; documented as unsuitable as a strength score because it measures the distribution of characters within one string rather than the number of sequences an attacker must try |
| **Have I Been Pwned k-anonymity model** | The design for a safe breach check; the tool ships a *local* demo corpus and returns the 5-character prefix a real integration would transmit, so the mechanism is visible without any network call |
| **XKCD 936** ("correct horse battery staple") | The canonical illustration of both the pro-passphrase argument and its failure mode — the phrase itself is now a famous password, and this tool scores it 20/100 |

**Synthesis applied to the design:** length is necessary but not sufficient; every
predictability signal must reduce the score; the score must explain itself;
policy is separate from measurement; and the tool's own handling of the value is
part of the security question.

---

## 6. Domain background

**Authentication vs authorisation.** Authentication establishes *who you are*
(a password, a passkey, a certificate). Authorisation decides *what you may do*.
A password is an authentication factor; no password strength can grant or remove
permission. This distinction matters because password policy is often confused
with access control.

**How attackers actually guess.** From cheapest to most expensive:

1. **Credential stuffing** — replay leaked username/password pairs against other
   services. Zero guessing required; defeated only by uniqueness, MFA and
   monitoring for anomalous logins.
2. **Password spraying** — a few very common passwords against many accounts, to
   avoid lockout thresholds.
3. **Dictionary + rule attacks** — a wordlist with mangling rules (`password` →
   `Password1!`), l33t substitutions, capitalisation patterns, appended years.
4. **Pattern/markov models** — statistical guesses ordered by likelihood learned
   from real leaked sets.
5. **Targeted guessing** — names, birth years, pet names, employers, teams — often
   gathered from social media.
6. **Brute force** — the full character space; the last resort, and only feasible
   for short or low-variety values (or against a fast, unsalted hash).

Every detector in this project maps to steps 2–5, because that is where real
attacks succeed.

**Defences that matter more than any meter.** MFA (ideally phishing-resistant
passkeys), rate limiting, progressive lockout with alerting, secure session and
cookie handling, secret-manager-issued API credentials, security monitoring, and
user education about phishing. A meter only improves the quality of the factor;
it cannot compensate for the absence of the others.

---

## 7. Requirements

### Functional

| ID | Requirement | Verified by |
|---|---|---|
| F1 | Analyse a value and return score, classification, findings, suggestions and metrics | `tests/test_analyzer.py` |
| F2 | Detect common passwords, breaches, dictionary words (incl. l33t), sequences, keyboard walks, repetition, predictable structures, dates, phones, famous phrases and personal-context overlap | `tests/test_patterns.py` (58 tests) |
| F3 | Provide an itemised score breakdown with every applicable cap and its reason | `tests/test_scoring.py` |
| F4 | Estimate entropy with limitations stated | `tests/test_scoring.py`, UI entropy panel |
| F5 | Generate strong passwords and passphrases using a CSPRNG | `tests/test_generator.py` |
| F6 | Check an administrator policy separately from strength | `tests/test_policy.py` |
| F7 | Expose a REST API with correct status codes and validation | `tests/test_api.py` (28 tests) |
| F8 | Provide aggregate-only analytics | `tests/test_analytics.py` |
| F9 | Demonstrate hashing, salting and key stretching on synthetic values only | `tests/test_hashing_demo.py` |
| F10 | Present everything in a real-time, accessible web UI | `scripts/capture_screenshots.py` (22 scenarios) |

### Non-functional

| ID | Requirement | Target | Result |
|---|---|---|---|
| N1 | Analysis latency | < 50 ms for a typical value | 0.7–9 ms measured (typical 0.7–2 ms) |
| N2 | No value stored, logged, echoed or transmitted | Absolute | Enforced by 21 privacy tests + byte scan |
| N3 | Browser build works with no network | Absolute | 0 external requests, verified live |
| N4 | Accessible | Keyboard operable, ARIA labels on charts, masked-by-default field | Implemented |
| N5 | Portable | Runs on Windows/macOS/Linux with Python 3.9+ and any modern browser | Verified |
| N6 | Beginner-readable | Modular, commented, one concept per module | 11 services, each with a purpose header |
| N7 | Offline demonstrable | Single-file build | 273 KB standalone HTML |

---

## 8. Architecture

```
                      ┌──────────────────────────────────────────┐
   Browser            │  Frontend (frontend/)                    │
   (GitHub Pages or   │  index.html · styles.css                 │
    served by Flask)  │  js/engine.js   ← same rubric in JS      │
                      │  js/charts.js   ← hand-built SVG         │
                      │  js/hashdemo.js · js/app.js              │
                      └───────────────┬──────────────────────────┘
                                      │  POST /api/analyze (JSON body only)
                                      ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │  Flask API  (backend/app.py, backend/routes/)                        │
   │  analyze · generate-password · dashboard/stats · analytics/*         │
   │  policy/presets · education/* · schema · health                      │
   │  validation · rate limiting · security headers · pages               │
   └───────────────┬──────────────────────────────────────────────────────┘
                   ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │  Services  (backend/services/ — the graded core, 11 modules)         │
   │  password_analyzer  · character_analyzer  · pattern_detector         │
   │  entropy_estimator  · scoring_engine      · suggestion_engine        │
   │  password_generator · policy_checker      · data_loader              │
   │  audit_store        · hashing_demo                                   │
   └───────┬───────────────────────────┬──────────────────────────────────┘
           │                           │ aggregates only
           ▼                           ▼
   ┌───────────────┐           ┌──────────────────────────────┐
   │ data/ (read)  │           │ SQLite: analyses, findings,  │
   │ wordlists,    │           │ generated_passwords_meta     │
   │ patterns,     │           │ (no password-capable column) │
   │ demo corpus   │           └──────────────────────────────┘
   └───────────────┘
```

**Data flow for one analysis** (the privacy-critical path):

```
user input → [memory only] → detectors → penalties + caps → score/band
          → suggestions (masked, value never echoed)
          → response (metrics + masked evidence)
          → aggregate metadata row (score, band, length, ratios, counts, time)
```

## 9. Design decisions and trade-offs

| Decision | Alternative | Why this choice |
|---|---|---|
| Transparent, documented rubric | A trained guess model (zxcvbn-style) | The project is educational: a student must be able to explain every point. Explanations are also shown to users, which a hidden model cannot do |
| Two engines (Python **and** JavaScript) | JavaScript only | The Python engine is the citable artefact for the report and the API; the JS engine makes the tool deployable with no server and no network |
| Parity harness over shared fixtures | "Keep them in sync by hand" | Silent divergence is the realistic failure mode; 66 fixtures make it a build failure |
| No CDN, no chart library | Chart.js (as the brief allowed) | The brief also requires offline/GitHub Pages operation; a CDN dependency contradicts the privacy claim and breaks in sandboxes |
| Aggregate-only analytics | Storing a password hash "for analytics" | A fast hash of a weak password is recoverable and turns analytics into a credential store. Counts and bands give the same educational value |
| Local demo breach corpus | Calling an external breach API | Keeps the "no transmission" guarantee absolute; the k-anonymity mechanism is demonstrated without a network dependency, and the shape of a real integration is visible in the response |
| Structural caps on top of arithmetic | Weights only | Arithmetic cannot express "16 identical characters is not 16 characters of strength" |
| Policy separate from score | One merged verdict | Mirrors how IAM products work, and teaches that measurement ≠ requirement |
| Masked-by-default UI | Visible input with a toggle | A projector, a screen recording or a shoulder-surfer is a realistic leak |

---

## 10. Scoring model

Full detail in [`docs/SCORING.md`](../docs/SCORING.md). Summary:

**Positive (max 100):** length 35 · diversity 15 · unique ratio 10 · pattern
resistance 20 · not-common 10 · unpredictability 10.

**Penalties (per-category cap, then summed):** common/breach/phrase −45 ·
personal info −20 · keyboard walk −15 · sequence −15 · repetition −15 ·
predictable structure −15 · dictionary word −12 · year/date −8 · phone −10 ·
short length −10 · low variety −6.

**Structural caps (lowest wins):** empty 0 · ≤3 characters 10 · <8 characters 20 ·
single repeated character 15 · ≤2 distinct characters 30/20 · ≤4 distinct across
16+ positions 45 · ≤3 distinct across 6+ positions 25 · digits/symbols only and
<12 characters 35, ≥12 characters 45 · known-common/breached/phrase 20 · personal
information 40 · word+year 45 · word+number shape 60.

**Bands:** VERY WEAK 0–20 · WEAK 21–40 · MODERATE 41–60 · STRONG 61–80 ·
VERY STRONG 81–100.

The rubric is **project-defined**, and the application says so.

### Calibration table (pinned by tests)

| Value | Score | Band |
|---|---:|---|
| *(empty)* | 0 | VERY WEAK |
| `123456` | 0 | VERY WEAK |
| `Password123!` | 0 | VERY WEAK |
| `qwerty2026!` | 0 | VERY WEAK |
| `a` | 10 | VERY WEAK |
| `aaaaaaaaaaaaaaaa` | 15 | VERY WEAK |
| `correct-horse-battery-staple` | 20 | VERY WEAK |
| `abcabcabc` | 25 | WEAK |
| `!@#$%^&*()` | 35 | WEAK |
| `zyxwvuts` | 37 | WEAK |
| `Summer2025!` | 40 | WEAK |
| `Hyderabad@2026` | 45 | MODERATE |
| `Demo-Pattern-123!` | 60 | MODERATE |
| `Sunset-Orchid-River` | 62 | STRONG |
| `Tr0ub4dor&3` | 68 | STRONG |
| `Tundra-Basil-Falcon-Thistle-Prism` | 91 | VERY STRONG |
| `Copper-Lantern-Orchid-Gravity` | 92 | VERY STRONG |
| `x7#Kq2!mZ9@vL4$p` | 97 | VERY STRONG |
| generated 16/20/24 characters | 96/98/99 | VERY STRONG |

---

## 11. Pattern detection

Fourteen detectors, each returning a structured finding
(`type`, `severity`, `title`, `description`, masked `evidence`, `positions`,
`penalty_bits`). Highlights:

* **Common passwords** — 272-entry educational list, matched directly and after
  l33t normalisation (`@`→`a`, `0`→`o`, `1`→`i`/`l`, `3`→`e`, `$`→`s`, …).
* **Dictionary words** — longest-prefix fallback so `p@sswords9` is still
  recognised, with a *noise guard*: an isolated 3–4 character substring in a long
  random value is not punished. Non-Latin scripts are compared against the Latin
  wordlist only after transliteration-aware normalisation, so Unicode input is
  analysed rather than mangled.
* **Sequences** — both directions, over letters and digits, minimum run length
  three.
* **Keyboard walks** — 53 curated rows and zigzags, matched forwards and
  backwards (`ytrewq`, `mnbvc`), which required an explicit reversed-row pass
  rather than relying on descending code points.
* **Repetition** — character runs plus repeated blocks, with a deliberately
  case-sensitive block comparison and a narrow "case echo" allowance
  (`Co` + `co` = `Coco`) that fires at most in one position. This was the most
  interesting bug of the project: an earlier lower-cased comparison invented
  repeats in random mixed-case strings and dragged a 256-character random value
  from 86 down to 52.
* **Predictable structures** — word+digits, word+year, dates, phone-shaped digit
  strings.
* **Personal context** — user-supplied first name, birth year and organisation are
  checked in memory for one call; only field *lengths* are echoed back.

---

## 12. Entropy model

`theoretical_bits = length × log2(pool)` where the pool is derived from the
character classes actually used (26/52/62/94, plus ~200 for non-ASCII).
`effective_bits` subtracts pattern penalties. For passphrase-shaped input the
Diceware model (`words × log2(wordlist) = words × ~12.6`) is reported **as an
upper bound** and only when the phrase is otherwise clean.

Three corrections keep the number honest, and all three are visible in the
response:

1. `effective_bits_source` states which model produced the number.
2. A passphrase caveat explains that human-chosen related words are weaker than
   the model assumes.
3. A **known-value** correction relabels the character-space figure as
   *"NOT applicable here"* whenever the value is common, breached or a famous
   phrase — because a number that suggests 133 bits for
   `correct-horse-battery-staple` is actively misleading.

Guess resistance is presented as three labelled scenarios (throttled online form
at 10 guesses/s, unthrottled online at 1 000/s, offline GPU at 10¹⁰/s), each with
a plain-language estimate and the standing caveat that these are educational
figures, not predictions.

---

## 13. Suggestion engine

Every finding maps to a specific, actionable suggestion that (a) never restates
the value, (b) explains *why* the weakness matters, and (c) proposes a concrete
change. For example a `year_pattern` finding produces: *"Remove the year — birth
years and recent years are among the first things an attacker tries. Replace it
with two or three unrelated words instead."* Suggestions are ordered by severity,
de-duplicated, and supplemented by standing hygiene advice (uniqueness, a manager,
MFA, phishing awareness) that is included in the API response and the UI.

---

## 14. Generator

`secrets.SystemRandom` in Python and `crypto.getRandomValues` with rejection
sampling in the browser — never the `random` module, which is enforced by an AST
check in the test suite. Features: password mode with length selection (16/20/24
and custom) and charset toggles (lowercase, uppercase, digits, symbols, exclude
ambiguous characters), and passphrase mode with 4/5/6 words from the 6 314-word
list. Generated values are returned once, scored immediately, and never stored —
only length, entropy estimate, class count and a timestamp are recorded.

---

## 15. Policy checker

Five presets, each documented with its rationale:

| Preset | Contents |
|---|---|
| `nist_baseline` | 8+ characters, blocklist, no composition rules, no expiry |
| `standard_account` | 12+ characters, blocklist, personal-info check, spaces allowed |
| `enterprise_iam` | 16+ characters, 8 unique characters, strength score ≥ 61 |
| `legacy_bank` | 8 characters, all four classes, 90-day expiry — **labelled an anti-pattern** and used to demonstrate why it produces `Password1!` |
| `passphrase_friendly` | 16+ characters, spaces allowed, no forced digit or symbol |

The verdict is reported as **POLICY PASS / POLICY FAIL**, independently of the
strength score, which is the point: a strong passphrase can fail a policy that
requires a digit, and a weak value can satisfy a naive policy.

---

## 16. Hashing demonstration

Deliberately **isolated from the analyzer** (a scope test enforces that the
analyzer never imports it). Given a synthetic value, it shows:

1. The same value hashed twice with different random salts → different digests
   (salting).
2. `scrypt` (n = 2¹⁴, r = 8, p = 1) and `pbkdf2_hmac` SHA-256 (600 000
   iterations) with measured durations (key stretching).
3. Verification with `hmac.compare_digest` (constant-time comparison) and the
   encoded string format that lets parameters be upgraded later.
4. Argon2id guidance (OWASP: m = 19456 KiB, t = 2, p = 1) for production, with
   the trade-offs explained.

---

## 17. Privacy and security design

Full detail in [`docs/PRIVACY.md`](../docs/PRIVACY.md). Guarantees and their
enforcement:

| Guarantee | Enforcement |
|---|---|
| The value is never stored | Schema test + byte-level scan of the database file after a real analysis |
| No password-capable column exists | `PRAGMA table_info` over every table, with SQL comments stripped first so explanatory prose cannot mask a real column |
| The value is never logged | A handler with `SecretRedactionFilter` attached during a real analysis |
| The audit helper cannot log a value | Signature inspection — no parameter could accept one |
| Responses never echo the value | Serialisation check with a high-entropy probe |
| Evidence is always masked | Regex assertion over every finding of every demo input |
| Nothing is persisted in the browser | Regex scan for `localStorage`, `sessionStorage`, `indexedDB`, cookies, Cache API |
| Nothing is transmitted | Scan for `fetch`/`XHR`/`sendBeacon`/`WebSocket`; the live page counts its own requests and displays 0 |
| No third-party resources | Scan for remote `src`/`href` attributes |
| No cracking capability exists | Function-name scan; the standalone build check refuses remote resources |

Additional application hardening: 64 KB request-body limit, JSON-schema-style
validation with structured error contracts, token-bucket rate limiting with
`Retry-After`, security headers (`Content-Security-Policy: default-src 'self'`,
`X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`), generic error
messages, and an explicit HTTPS note.

---

## 18. Database design

```sql
analyses(analysis_id PK, score, classification, password_length,
         unique_character_ratio, character_type_count, weakness_count,
         pattern_count, top_weakness, duration_ms, analyzed_at)

findings(finding_id PK, analysis_id FK, finding_type, severity, description)

generated_passwords_meta(meta_id PK, generator, length, entropy_bits,
                         class_count, created_at)
```

**What is deliberately absent:** any password, hash, salt, masked value, context
field, IP address or user identifier. `scripts/show_schema.py` prints the schema
and exits non-zero if such a column is ever introduced; `tests/test_privacy.py`
asserts the same in CI.

---

## 19. API design

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/analyze` | Full analysis (JSON body only) |
| POST | `/api/generate-password` | Password or passphrase |
| GET | `/api/dashboard/stats` | Aggregate dashboard data |
| GET | `/api/analytics/weaknesses` | Weakness frequency |
| GET | `/api/analytics/recent?limit=` | Recent metadata rows |
| POST | `/api/analytics/reset` | Clear the metadata store |
| GET | `/api/policy/presets` | Policy presets and their rationale |
| GET | `/api/education/hashing-demo` | Hashing, salting and stretching demo |
| GET | `/api/education/content` | Rules, passphrase guidance, interview Q&A |
| GET | `/api/schema` | Response schema (self-documenting) |
| GET | `/api/health` | Health + privacy flags |
| GET | `/` | Serves the web UI |

Conventions: `200` for a completed analysis (even when the verdict is VERY WEAK),
`400 validation_error` for a malformed or missing body, `400 too_long` for input
over 256 characters, `415` for a non-JSON content type, `429` with `Retry-After`
when the rate limit is hit, `404` for unknown routes with a structured body.
Errors describe the *shape* of the problem and never echo the input.

---

## 20. Front-end design

Five tabs (Analyzer, Generator, Dashboard, Learn, Privacy) in a single page, dark
security-console theme, no build step and no framework.

* Real-time analysis on input, with a score gauge, classification pill and a
  five-band scale.
* Findings as cards with severity colouring, masked evidence and position
  highlighting; suggestions as an ordered, numbered list.
* An itemised score breakdown (bars per component) and a penalty list showing
  which categories cost what, plus a banner naming the structural cap that decided
  the outcome.
* An entropy panel that prints its own limitations.
* Accessibility: masked-by-default input with an accessible 👁 toggle, ARIA
  labels and text summaries for every chart, keyboard-operable controls, a
  screen-reader-only help region, and colour never used as the only signal.

---

## 21. Dual-engine parity

`scripts/generate_fixtures.py` runs 66 inputs (including generated values and
passphrases, whose *properties* only are recorded) through the Python engine and
writes `tests/fixtures/expected_results.json`. `tests/js/run_parity_test.js` runs
the JavaScript engine over the same fixtures and compares score, classification,
length, pattern count, finding types and the policy verdict — 74 assertions in
total, re-executed inside pytest so CI cannot skip it.

Bugs this caught, all fixed:

1. Unicode character classification (`[a-zA-Z]` vs `\p{L}`).
2. Rounding at band boundaries (half-to-even, six-decimal normalisation).
3. Duplicate keyboard-walk findings in Python but not JavaScript.
4. Penalty summation and display rounding differences.
5. The repetition false positive described in section 11.

---

## 22. Implementation summary

| Area | Files | Notes |
|---|---|---|
| Engine | 11 service modules (~3 500 lines) | One concept per module, each with a purpose header |
| API | `app.py`, `main.py`, 4 blueprints, schemas | Flask plus a FastAPI variant sharing the same services |
| Front end | `index.html`, `styles.css`, 4 JS modules + 4 generated data files | Zero dependencies, ~1 700 lines |
| Data | 5 text files | 272 common passwords, 53 keyboard patterns, 69 phrases, 6 314 passphrase words, demo breach hashes |
| Tooling | 6 scripts | Data build, fixture generation, standalone build, screenshot capture, tree and schema proofs |
| Tests | 12 pytest files + 1 Node harness | 261 tests + 74 parity assertions |
| Documentation | README + 9 docs + 2 reports | Includes deployment, contributing and placement material |

---

## 23. Testing and results

Summary; full detail in [`reports/TEST_REPORT.md`](TEST_REPORT.md).

| Suite | Result |
|---|---|
| `python -m pytest -q` | **261 passed, 1 skipped, 0 failed** (~3.2 s) |
| `node tests/js/run_parity_test.js` | **74 passed, 0 failed** |
| Screenshot/browser smoke test | 22 scenarios captured, 0 console errors, 0 external requests |
| Calibration table | 19 pinned values reproduce exactly |

The one skip is deliberate: a three-character sequence is below the documented
minimum run length, and the skip records that boundary.

---

## 24. Limitations

Stated plainly, because a project that hides its limits is not trustworthy:

1. **The rubric is heuristic and project-defined.** A different weighting is
   defensible; the value here is transparency, not authority.
2. **No probabilistic model.** A Markov/neural guess model would estimate human
   likelihood better than hand-tuned penalties, at the cost of explainability.
3. **Entropy is an upper bound.** The tool says so in four places.
4. **Breach checking is a local demo corpus, not a live service.**
5. **The rate limiter is per process.** Correct for one worker, insufficient
   behind several — a shared store is required in production.
6. **English-centric dictionaries.** Non-Latin input is analysed by character
   classes and patterns, but not by a native-language wordlist.
7. **No reuse detection by design.** The tool cannot know whether a value is used
   elsewhere, which is the single biggest real-world risk — so the education layer
   emphasises it instead.
8. **The score is not a security guarantee** and cannot see phishing, malware,
   session theft or a compromised server.

---

## 25. Future work

Real breach integration behind k-anonymity (opt-in, disclosed) · a probabilistic
guess model with the explainable breakdown retained · passkey/WebAuthn guidance ·
a shared rate-limit store · localisation and a native-language wordlist ·
property-based and fuzz testing of the API · a published container image and
signed releases · SBOM and dependency scanning.

---

## 26. Lessons learned

* **Measurement beats checklists**, and a measurement must explain itself to be
  useful to a non-expert.
* **Claims become guarantees only when a test can fail on them.** The privacy
  section of this project is a test suite, not a paragraph.
* **Two implementations of one rubric will diverge** unless something forces them
  not to. Parity fixtures turned a silent risk into four real bug fixes.
* **False positives destroy trust in a security tool.** The repetition bug was
  the most instructive failure of the project: a detector that cries wolf on a
  random 256-character value is worse than no detector.
* **Overlapping signals need caps, not sums.** Without per-category caps, one
  repetition problem could consume a third of the total score five times over.
* **Boring engineering decisions carry the security properties**: a request-size
  limit, a redaction filter, a missing column, a constant-time comparison.

---

## 27. Conclusion

The project set out to show that password strength is a question about
*predictability*, not character composition, and to do so in a way a beginner can
explain and a professional can audit. The resulting tool scores `Password123!` at
0 and a four-word passphrase at 92 while explaining each point; it analyses
fourteen classes of weakness; it states the limits of entropy instead of hiding
them; it separates policy from measurement; and it handles the value it is given
as a liability rather than an asset — in memory only, never stored, never logged,
never echoed, never transmitted, with every one of those claims enforced by
automated tests. It is delivered as both a documented Python/Flask service and a
zero-network browser build published on GitHub Pages, with 261 tests, 74 parity
assertions, 22 automated screenshots and complete deployment, demonstration and
placement documentation.

---

## 28. References and appendices

**References** — NIST SP 800-63B (Digital Identity Guidelines; authentication and
lifecycle management) · OWASP ASVS 2.1 · OWASP Password Storage Cheat Sheet ·
OWASP Authentication Cheat Sheet · OWASP Top 10 (A02 Cryptographic Failures, A07
Identification and Authentication Failures) · Wheeler, D. *zxcvbn: realistic
password strength estimation* · EFF Diceware wordlist · Have I Been Pwned
k-anonymity model · XKCD #936 · Munroe, R. (illustration of passphrase entropy)
· Python `secrets`, `hashlib.scrypt`, `pbkdf2_hmac` documentation · MDN Web Docs
(Crypto API, `crypto.getRandomValues`).

**Appendix A — run the project**

```bash
pip install -r requirements.txt
python backend/app.py                 # http://127.0.0.1:5000
python -m pytest -q                   # 261 passed, 1 skipped
node tests/js/run_parity_test.js      # 74 passed
python scripts/capture_screenshots.py # 22 screenshots
```

**Appendix B — demonstration values** — see
[`docs/SAFE_DEMO_CASES.md`](../docs/SAFE_DEMO_CASES.md).

**Appendix C — proof checklist** — see
[`docs/SCREENSHOTS.md`](../docs/SCREENSHOTS.md) (28 items).

**Appendix D — scoring rubric** — see [`docs/SCORING.md`](../docs/SCORING.md).

**Appendix E — privacy guarantees** — see [`docs/PRIVACY.md`](../docs/PRIVACY.md).
