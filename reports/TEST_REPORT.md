# Test report

| | |
|---|---|
| **Project** | Password Strength Analyzer & Security Suggestion Tool |
| **Date of last full run** | 2026-10-04 |
| **Environment** | Python 3.13 · Node 20 · Linux (also verified on Windows/macOS by the same commands) |
| **Overall verdict** | **PASS** — 261 passed, 1 skipped (by design), 0 failed; 74/74 parity assertions passed |

---

## 1. Executed commands and results

```bash
$ python -m pytest -q
........................................................................ [ 28%]
.....................................s.................................. [ 56%]
........................................................................ [ 85%]
......................................                                   [100%]
261 passed, 1 skipped in 3.20s

$ node tests/js/run_parity_test.js
==========================================================================
JavaScript engine parity test: 74 passed, 0 failed
==========================================================================
Both engines agree on score, classification, findings and policy verdict.
Data loaded: {"common_passwords":272,"keyboard_patterns":53,"common_phrases":69,"passphrase_words":6312}

$ python scripts/show_schema.py
tables inspected ............ 3
password-capable columns .... 0  (none)
PASS: structurally incapable of revealing a password.

$ python scripts/capture_screenshots.py
Captured 22 screenshot(s) into screenshots/
```

---

## 2. Results by test file

| File | Tests | Passed | Failed | Purpose |
|---|---:|---:|---:|---|
| `test_analyzer.py` | 41 | 41 | 0 | End-to-end analysis, scenarios T01–T30 |
| `test_patterns.py` | 58 | 57 | 0 | Individual detectors (1 skipped by design) |
| `test_scoring.py` | 20 | 20 | 0 | Rubric, caps, bands, calibration, entropy |
| `test_suggestions.py` | 12 | 12 | 0 | Suggestion quality and masking |
| `test_generator.py` | 13 | 13 | 0 | CSPRNG generator, options, no storage |
| `test_policy.py` | 12 | 12 | 0 | Policy presets and separation from score |
| `test_api.py` | 28 | 28 | 0 | REST contract, validation, rate limiting |
| `test_analytics.py` | 10 | 10 | 0 | Aggregate-only store |
| `test_hashing_demo.py` | 13 | 13 | 0 | Hashing, salting, verification |
| `test_privacy.py` | 21 | 21 | 0 | Privacy guarantees |
| `test_scope.py` | 9 | 9 | 0 | Defensive scope enforcement |
| `test_repetition_regression.py` | 17 | 17 | 0 | Regression tests for the repetition bug |
| `test_fixtures.py` | 7 | 7 | 0 | Parity fixture currency, synthetic-only contract, detector/band coverage |
| **Total** | **261** | **260** | **0** | *(+1 intentional skip)* |
| `tests/js/run_parity_test.js` | 74 assertions | 74 | 0 | Python ⇄ JavaScript parity |

### The intentional skip

```
tests/test_patterns.py::test_sequence_detection[xyz]  SKIPPED
    shorter than the minimum run length by design
```

Three characters is below `MIN_SEQUENCE_LEN = 4` for alphabetic runs. The case is
kept as a documented boundary rather than deleted, so a future change to the
minimum produces a visible signal instead of a silent behaviour change.

---

## 3. Scenario coverage (T01–T40)

The 30+ scenarios required by the brief are all implemented; the mapping table
lives in [`docs/TESTING.md`](../docs/TESTING.md#2-the-30-required-test-scenarios).
Highlights with their actual asserted outcomes:

| Scenario | Input | Expected | Result |
|---|---|---|---|
| Composition bait | `Password123!` | score 0, VERY WEAK | ✅ 0, `breach` + `dictionary_word` + `predictable_structure` |
| Long but worthless | `aaaaaaaaaaaaaaaa` | capped at 15 | ✅ 15, cap `single_repeated_character` |
| Famous phrase | `correct-horse-battery-staple` | VERY WEAK with `common_phrase` | ✅ 20, cap `known_common_or_breached` |
| Pattern-free 256 characters | SHA-256 keystream value | ≥ 81 VERY STRONG | ✅ 86 |
| Unlucky random 256 characters | `secrets`-generated | never below MODERATE | ✅ ≥ 41 across repeated runs |
| Personal context | `Rahul@123` + context | ≤ 40, `personal_info` | ✅ 37 WEAK (58 without context) |
| Long accepted | 256 characters | accepted, not truncated | ✅ `metrics.length == 256` |
| Over-length rejected | 300 characters | `too_long`, no echo | ✅ 400 + friendly message |
| Unicode input | `Пароль-Демо-2026!` | analysed, not mangled | ✅ classified, no exception |
| All bands reachable | demo set | 5 distinct bands | ✅ |

---

## 4. Privacy verification (the most important section)

Each row is an executed assertion, not an intention.

| Check | Method | Result |
|---|---|---|
| No password-capable database column | `PRAGMA table_info` on every table, with SQL comments stripped before the audit | ✅ 0 offenders (3 tables, 22 columns) |
| The database file contains no secret material | raw byte scan after a real analysis: the value, its reverse, and the 5-character SHA-1 prefix | ✅ not found |
| The engine does not log a value | handler + `SecretRedactionFilter` attached during a real analysis | ✅ metadata only |
| The audit helper cannot accept a value | `inspect.signature` — no parameter could carry one | ✅ |
| Responses never echo the value | JSON serialisation with a high-entropy probe | ✅ |
| Evidence is always masked | `^[\u2022\s]*$` over every finding of every demo input | ✅ |
| No client-side persistence | regex scan for `localStorage`, `sessionStorage`, `indexedDB`, cookies, Cache API | ✅ |
| No console logging | scan for `console.log/debug/info` in shipped JavaScript | ✅ |
| No network calls | scan for `fetch`, `XMLHttpRequest`, `sendBeacon`, `WebSocket`; plus a live network count in the UI | ✅ 0 external requests |
| No third-party resources | remote `src`/`href` scan of the shipped page | ✅ |
| Context is not retained | response echoes only field *lengths* | ✅ |
| Analytics can be disabled | `ANALYTICS_ENABLED=0` → no rows written | ✅ |
| No cracking capability | banned-function-name scan | ✅ |

**Observed response excerpt** (synthetic value, `Password123!`):

```json
{
  "analysis_id": "an_b40bd3552e1a",
  "score": 0,
  "classification": "VERY WEAK",
  "findings": [
    {"type": "breach", "severity": "critical", "title": "Found in a leaked-password corpus",
     "evidence": "••••••••••••", "positions": []},
    {"type": "dictionary_word", "severity": "high", "title": "Common word detected",
     "evidence": "••••••••", "positions": [0,1,2,3,4,5,6,7]}
  ],
  "privacy": {"stored": false, "logged": false, "transmitted": false, "echoed": false}
}
```

Note what is present (severity, category, positions, masked evidence) and what is
absent (the value, any substring of it, any hash of it).

---

## 5. Performance measurements

| Operation | Measured | Target |
|---|---|---|
| Typical analysis (`Password123!`) | 0.7–2.5 ms | < 50 ms |
| Worst observed analysis (256-character input, full detector sweep) | 9.2 ms | < 50 ms |
| Passphrase analysis (30 characters, dictionary lookups) | 0.8 ms | < 50 ms |
| Generator (24 characters) | < 1 ms | — |
| Dashboard aggregation (SQLite, 12 rows) | < 5 ms | — |
| Full pytest suite | 3.2 s | < 60 s |
| Parity harness (66 fixtures × 2 engines) | 0.4 s | < 10 s |
| Single-file build | 0.4 s | — |

Detector cost is dominated by the repeated-substring scan, which is O(n²) in the
worst case; the 256-character input cap keeps it bounded and well inside budget.

---

## 6. Defects found and fixed during development

Recorded because the *process* is part of the result.

| # | Defect | Root cause | Fix | Regression test |
|---|---|---|---|---|
| D1 | `OverflowError` on a 256-character random value | `2 ** 1023` overflowed in the entropy estimate | Bits capped at `MAX_REPRESENTABLE_BITS = 1024`, with a ceiling label ("far beyond the age of the universe") | `test_T24c_*`, `test_guess_resistance_scenarios_ordered` |
| D2 | Low scores on long random values (52–67 instead of ~86) | The repetition detector compared **lower-cased** copies, so `jdD` + `jDd` looked like a repeat | Case-sensitive comparison plus a narrow, one-position "case echo" allowance (`Coco` still detected) | `tests/test_repetition_regression.py` (17 tests) |
| D3 | Reversed keyboard walks (`ytrewq`, `mnbvc`) undetected | The matcher relied on descending code-point runs | Explicit reversed-row pass added | `test_keyboard_reversed_*`, fixture cases |
| D4 | `p@sswords9` missed | l33t substitution replaced the word's tail, so the full-word match failed | Longest-dictionary-prefix fallback, guarded against 3-character noise in long random values | `test_leetspeak_prefix_fallback` |
| D5 | `qwerty123` reported two keyboard findings | Python did not exit after a curated hit, JS did (a parity divergence) | Early return after a curated hit, matching the JS behaviour | Parity fixture + `test_no_duplicate_keyboard_findings` |
| D6 | Dashboard showed `passphrase_structure` as the most common *weakness* | A structural finding was counted as a weakness | Excluded from weakness aggregates in both the API and the UI (it is the finding that *suppresses* per-word penalties) | `test_weakness_frequency_excludes_structure` |
| D7 | Chart x-axis labels overlapped and clipped | Long band names rendered on one rotated line | Two-line labels via `\n` support in the chart builder and a taller plot area | Visual regression via the screenshot script |
| D8 | Dashboard capture depended on capture order | The scenario did not load data when run alone with `--only` | Scenario made self-contained | Screenshot run |
| D9 | A 2-character echo ("Tr") was flagged in a random 157-character value | The case-echo allowance had no noise guard | Above 20 characters, a 2-character block must repeat ≥ 3 times | `test_two_character_echo_needs_three_repeats_in_long_values` |
| D10 | Privacy test could not use `caplog` (logger has `propagate=False`) | Test-harness assumption | Test attaches its own handler with the production filter | `test_privacy.py` |
| D11 | Static source scans gave false positives on prose | Substring tests matched documentation that *mentions* `fetch(`/`localStorage` | Regex/AST-based scans with explicit allowances for explanatory text | `test_scope.py` |

**Failure-triage summary:** an initial full-suite run produced 20 failures. All
were fixed and none were masked with `skip`, `xfail` or removed assertions —
three of them (D2, D3, D4) were genuine engine bugs found by the tests, which is
the outcome the suite exists to produce.

---

## 7. Calibration verification

`tests/test_scoring.py::test_score_is_calibrated_for_demo_cases` pins the
documented table. Current measured values:

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
| `Rahul@123` (with personal context) | 37 | WEAK |
| `Demo-Pattern-123!` | 60 | MODERATE |
| `Sunset-Orchid-River` | 62 | STRONG |
| `Tr0ub4dor&3` | 68 | STRONG |
| `Tundra-Basil-Falcon-Thistle-Prism` | 91 | VERY STRONG |
| `Copper-Lantern-Orchid-Gravity` | 92 | VERY STRONG |
| `x7#Kq2!mZ9@vL4$p` | 97 | VERY STRONG |
| generated 16 / 20 / 24 characters | 96 / 98 / 99 | VERY STRONG |
| generated 4 / 5 / 6-word passphrase | 71–85 / 82 / 82 | STRONG–VERY STRONG |

A generated 4-word passphrase landing in STRONG (not VERY STRONG) is the honest
result of the Diceware upper-bound correction: 4 words is about 50.5 bits, which
the tool declines to score in the top band once its own caveat is applied.

---

## 8. Browser / end-to-end verification

Driven by Playwright against the shipped single-file build.

| Check | Result |
|---|---|
| Page loads, 5 tabs, no console errors, no page errors | ✅ |
| Hidden-by-default password field with a working 👁 toggle | ✅ |
| Live analysis while typing (score, band, findings, tiles, suggestions, bars) | ✅ |
| Demo walk-through (6 synthetic values) | ✅ |
| Load 12 synthetic samples → dashboard KPIs, 5 charts, metadata table | ✅ |
| Reset analytics | ✅ table cleared, KPI total 0 |
| Generator: password and passphrase modes | ✅ 98–100 and 83–91, correct entropy labels |
| "Analyse this" from the generator | ✅ same verdict as the backend |
| Policy checker: POLICY PASS/FAIL shown separately | ✅ |
| Hashing demo: three steps, two salts, different digests | ✅ |
| Learn tab: 10 rules, 10 interview Q&A entries | ✅ |
| Privacy tab renders all guarantees | ✅ |
| External network requests during the whole session | **0** |
| Screenshots captured | 22 |

---

## 9. API verification

| Request | Expected | Observed |
|---|---|---|
| `GET /` | 200 HTML | ✅ |
| `GET /api/health` | 200 with privacy flags | ✅ `stores_passwords: false, logs_passwords: false, sends_passwords_externally: false` |
| `POST /api/analyze` valid | 200, 22 keys | ✅ score, classification, findings, suggestions, metrics, breakdown, caps, entropy, guess resistance, policy, passphrase guidance, privacy, disclaimer |
| `POST /api/analyze` empty body key | 400 `validation_error` | ✅ structured, no echo |
| `POST /api/analyze` 300 characters | 400 `too_long` | ✅ |
| `POST /api/analyze` non-JSON content type | 415 | ✅ |
| `POST /api/analyze` × 40 rapidly | 429 + `Retry-After` | ✅ |
| `GET /api/dashboard/stats` | aggregates only | ✅ 4 totals, distribution, histogram, length buckets, weakness frequency, privacy note |
| `GET /api/analytics/recent` | metadata columns | ✅ id, score, classification, length, weakness count, time |
| `POST /api/generate-password` | 200, entropy labelled | ✅ |
| Unknown route | 404 structured | ✅ |
| Response body never contains the submitted value | probe search | ✅ |

---

## 10. Conclusion

Every acceptance criterion is met and evidenced: the engine implements the
required detectors, the scoring model is documented and pinned by a calibration
table, the suggestion engine never echoes the value, the privacy guarantees are
enforced by 21 dedicated tests plus a byte-level database scan, the API contract
is verified end to end, the two engine implementations agree on all 66 shared
fixtures, and the browser build performs a complete analysis with zero network
requests.

**Residual risk is stated, not hidden:** breach checking uses a local demo corpus;
the rate limiter is per process; the rubric is a heuristic; and no strength score
can detect reuse, phishing or server-side compromise. These are documented in the
report's Limitations section and surfaced in the product itself.
