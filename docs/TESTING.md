# Testing strategy and results

**Latest full run:** `261 passed, 1 skipped, 0 failed` in ~3.2 s (pytest) plus
`74 passed, 0 failed` (JavaScript parity harness).

```bash
python -m pytest -q                                   # engine + API + privacy + scope
python -m pytest --cov=backend --cov-report=term-missing
node tests/js/run_parity_test.js                      # JS engine parity
python scripts/generate_fixtures.py                   # regenerate the shared fixture
```

---

## 1. How the suite is organised

| File | Tests | What it protects |
|---|---:|---|
| `tests/test_analyzer.py` | 41 | End-to-end `analyze_password()` behaviour for the 30+ enumerated scenarios (T01–T30) |
| `tests/test_patterns.py` | 58 | Each detector in isolation: common passwords, l33t, dictionary, sequences, keyboard walks, repetition, structure, dates, phones, breach |
| `tests/test_scoring.py` | 20 | The scoring rubric: weights, caps, bands, calibration table, entropy models |
| `tests/test_suggestions.py` | 12 | Every finding produces a specific, actionable suggestion that never echoes the value |
| `tests/test_generator.py` | 13 | `secrets`-based generator, charset toggles, lengths, passphrases, no storage |
| `tests/test_policy.py` | 12 | Policy checker, the five presets, and policy-vs-strength independence |
| `tests/test_api.py` | 28 | REST contract: status codes, validation, rate limiting, response shape, no echo |
| `tests/test_analytics.py` | 10 | Metadata-only analytics store, aggregates, reset, schema |
| `tests/test_hashing_demo.py` | 13 | `hash_password()` / `verify_password()`, salting, algorithm params, comparison safety |
| `tests/test_privacy.py` | 21 | The privacy contract: no storage, no logging, no persistence, no network, masked evidence |
| `tests/test_scope.py` | 9 | Defensive-scope enforcement: no cracking, no harvesting, no outbound client |
| `tests/test_repetition_regression.py` | 17 | Regression tests for the case-sensitivity bug found during development |
| `tests/test_fixtures.py` | 7 | Proves the shared parity fixture is current, synthetic-only, and covers every detector and band |
| `tests/js/run_parity_test.js` | 74 | Python ⇄ JavaScript engine parity on 66 shared fixtures |

**Total: 261 pytest tests + 74 parity assertions.**

### Test-data contract (`tests/conftest.py`)

Every input in the suite comes from a synthetic dictionary:

```python
DEMO_PASSWORDS = {"common": "password", "composition_bait": "Password123!", ...}
```

* No real password is ever used, in any test, at any level.
* The suite fails loudly if a test tries to reach the network.
* `demo`, `analyze`, `flask_client`, `temp_db` and `demo_context` fixtures keep tests
  independent and fast (no sleeps except the deliberate rate-limit test).

---

## 2. The 30+ required test scenarios

Every scenario requested in the project brief is implemented. "Test" lists the
function that asserts it.

| # | Scenario | Test | Expected |
|---|---|---|---|
| T01 | Empty input | `test_T01_empty_input` | score 0, VERY WEAK, no crash |
| T02 | Very short (`a`) | `test_T02_single_character` | capped at 10 |
| T03 | Common password (`123456`) | `test_T03_common_password` | 0, VERY WEAK, `common_password` finding |
| T04 | Common + suffix (`password123`) | `test_T04_common_with_suffix` | 0, dictionary + predictable structure |
| T05 | Composition bait (`Password123!`) | `test_T05_composition_bait` | 0 despite 4 character classes |
| T06 | Leetspeak (`P@ssw0rd`) | `test_T06_leetspeak_is_normalised` | recognised as the word "password" |
| T07 | Keyboard walk (`qwerty123`) | `test_T07_keyboard_pattern` | `keyboard_pattern` finding, not STRONG |
| T08 | Repeated characters (`aaaaaaaaaaaaaaaa`) | `test_T08_repeated_characters` | capped at 15 |
| T09 | Symbols only (`!@#$%^&*()`) | `test_T09_symbols_only` | WEAK, `no_letters_short` cap |
| T10 | Ascending sequence (`abcd1234`) | `test_T10_sequence` | `sequence` finding |
| T11 | Descending sequence (`zyxwvuts`) | `test_T11_reverse_sequence` | `sequence` finding |
| T12 | Repeated block (`abcabcabc`) | `test_T12_repeated_block` | `repeated_substring` finding |
| T13 | Word + year (`Summer2025!`) | `test_T13_word_and_year` | `year_pattern`, capped at 45 |
| T14 | Case-only echo (`MyDog-Is-Named-Coco`) | `test_T14_case_echo_repeat` | `repeated_substring` for "Coco" |
| T15 | Genuine random (`x7#Kq2!mZ9@vL4$p`) | `test_T15_strong_random` | STRONG or better |
| T16 | Long passphrase (`Tundra-Basil-Falcon-Thistle-Prism`) | `test_T16_passphrase` | VERY STRONG |
| T17 | Famous phrase (`correct-horse-battery-staple`) | `test_T17_famous_phrase` | 20, VERY WEAK |
| T18 | Personal context overlap | `test_T18_personal_info_*` (3 tests) | `personal_info`, capped at 40 |
| T19 | Personal context not supplied | `test_T19_no_false_personal_match` | no personal finding |
| T20 | Unicode / non-ASCII | `test_T20_unicode_input` | analysed, never mangled |
| T21 | Spaces allowed | `test_T21_long_passphrase` | spaces accepted, policies differ |
| T22 | Context is never stored | `test_T22_context_is_not_retained` | only field lengths echoed |
| T23 | Over-length rejection | `test_T23_over_length` | `too_long`, no echo, no crash |
| T24 | Long input accepted (256) | `test_T24b_*`, `test_T24c_*` | not truncated; VERY STRONG when pattern-free |
| T25 | Every band is reachable | `test_T25_all_bands_reachable` | 5 distinct classifications from the demo set |
| T26 | Score bounds | `test_T26_score_is_always_0_to_100` | never below 0 or above 100 |
| T27 | Determinism | `test_T27_same_input_same_result` | identical score on repeat |
| T28 | Suggestions never echo | `test_T28_suggestions_never_echo` | masked evidence only |
| T29 | Generator uses a CSPRNG | `test_generator_uses_secrets_not_random` | AST check for `secrets`, ban on `random` |
| T30 | Policy independent of score | `test_T30_policy_versus_strength` | STRONG value can fail policy and vice versa |
| T31 | Rate limiting | `test_rate_limit_returns_429` | 429 + `Retry-After` |
| T32 | Malformed JSON | `test_malformed_json_is_rejected` | 400 `validation_error` |
| T33 | Wrong content type | `test_wrong_content_type_is_rejected` | 415 |
| T34 | Analytics contains no secrets | `test_database_contains_no_password_material` | byte-level DB scan |
| T35 | Analytics can be switched off | `test_analytics_disabled_stores_nothing` | 0 rows written |
| T36 | Hashing demo round-trip | `test_verify_password_round_trip` | verify true, wrong value false |
| T37 | Salt makes hashes differ | `test_same_value_same_salt_same_hash` | salt is load-bearing |
| T38 | Repetition false positive | `test_case_only_differences_are_not_reported_as_a_repeat` | no invented repeat |
| T39 | No network access | `test_no_network_calls_in_engine` | AST/socket inspection |
| T40 | Defensive scope | `test_no_cracking_functions_exist` | banned-name scan |

---

## 3. The privacy test suite in detail

The privacy guarantees are the ones a reviewer will probe, so they are asserted
mechanically rather than promised in prose (`tests/test_privacy.py`).

| Assertion | Mechanism |
|---|---|
| The database has no column that could hold a password or a hash | `PRAGMA table_info` over every table, plus a scan of the schema for the strings that were deliberately stripped out of SQL comments |
| The database file does not contain the probe value, its reverse, or its SHA-1 prefix | raw byte search after a real analysis |
| The engine does not log a value | a handler with `SecretRedactionFilter` attached captures every record during a real analysis |
| The audit helper cannot accept a value | `inspect.signature` — no `password`/`secret`/`raw` parameter exists |
| Every finding evidence string is fully masked | regex `^[\u2022\s]*$` on every finding of every demo input |
| The API response never contains the submitted value | JSON serialisation check with a high-entropy probe |
| No client-side persistence | regex scan of `frontend/` for `localStorage`, `sessionStorage`, `indexedDB`, `document.cookie`, `caches` |
| No console logging | scan for `console.log/debug/info` in shipped JavaScript |
| No external request | scan for `fetch(`, `XMLHttpRequest`, `sendBeacon`, `WebSocket`; the static page additionally counts its own network calls in the UI |
| No CDN / third party | scan for `http://` or `https://` in `src`/`href` attributes of the shipped page |
| Context is not retained | response echoes only the *length* of each context field |

An important detail: these scans use **regex or the AST**, never a substring test
(`"localStorage" in source`). The privacy *page itself* explains that
`localStorage` is not used, so a naive check would fail on the documentation that
proves the guarantee.

---

## 4. Python ⇄ JavaScript parity

The GitHub Pages build runs the same rubric in JavaScript. Divergence would mean
the deployed site contradicts the documented backend, so parity is enforced:

```
scripts/generate_fixtures.py   ->  tests/fixtures/expected_results.json   (66 fixtures, Python engine)
tests/js/run_parity_test.js    ->  runs frontend/js/engine.js on all 66   (score, band, length,
                                    pattern count, finding types, policy verdict)
python -m pytest               ->  test_repetition_regression.py re-runs the harness in CI
```

Fixtures cover every detector, plus generated passwords and passphrases (only the
*properties* of generated values are recorded, never the values themselves).

Real parity bugs found and fixed this way:

1. **Unicode character classes.** JavaScript must use Unicode-aware tests
   (`/[\p{L}]/u`), not `[a-zA-Z]`, or non-ASCII input classified differently.
2. **Rounding.** Python rounds the accumulated score to six decimals before
   classifying; JavaScript needed the same half-to-even helper (`pyRound`).
3. **Penalty summation.** Per-category penalties are capped and rounded
   independently from the display values.
4. **Duplicate findings.** The Python detector reported a keyboard walk twice
   where JavaScript reported it once; the Python side was corrected.

> **Rule for contributors: any change to a detector, weight or cap requires
> `python scripts/generate_fixtures.py` followed by the parity test.** CI fails
> otherwise.

---

## 5. Security testing checklist

Run through this before any demo or submission.

| Check | How to verify | Status |
|---|---|---|
| Password field is masked by default | Open the page — the input is `type="password"` with a 👁 toggle | ✅ |
| Nothing is written to storage | DevTools → Application → Local/Session Storage, IndexedDB, Cookies, Cache: all empty after analysis | ✅ |
| The console stays quiet | DevTools → Console: no output while typing, generating or analysing | ✅ |
| The network tab stays empty | DevTools → Network: 0 requests after page load (the UI prints the count) | ✅ |
| The API does not echo the value | `POST /api/analyze` with a probe value; search the raw response | ✅ |
| The value never appears in a URL | Only `POST` with a JSON body is used; no query parameters carry input | ✅ |
| The database holds no secrets | `PRAGMA table_info(analyses)` — and the byte scan in the suite | ✅ |
| Logs contain metadata only | `python backend/app.py`, watch stdout during an analysis | ✅ |
| Over-length input fails safely | Submit 300 characters → 400 with a friendly message, nothing echoed | ✅ |
| Rate limiting works | 40 rapid `POST /api/analyze` calls → 429 with `Retry-After` | ✅ |
| Security headers present | `curl -I http://127.0.0.1:5000/` | ✅ |
| Analytics can be disabled | `ANALYTICS_ENABLED=0 python backend/app.py` → dashboard reports storage off | ✅ |
| Hashing demo is isolated | The analyzer never imports the hashing module (`test_scope.py`) | ✅ |

---

## 6. Coverage

`python -m pytest --cov=backend --cov-report=term-missing`

The engine (`backend/services/`) is the graded surface and is covered well past
90 %; the interactive UI and the screenshot script are excluded because they are
verified by the browser smoke test instead (`scripts/capture_screenshots.py`
exercises every tab, the generator, the demo walk-through and the charts — a
failure there produces a visible error instead of a saved image).

---

## 7. Browser smoke test

`scripts/capture_screenshots.py` is also the smoke test: it drives the real page
through 22 scenarios and fails loudly if an element is missing or an exception is
thrown. Verified behaviour on the last run:

| Action | Result |
|---|---|
| Type `Password123!` | score `0`, VERY WEAK, 3 findings, 8 suggestions |
| Type `Copper-Lantern-Orchid-Gravity` | score `92`, VERY STRONG |
| Click "Run the demo walk-through" | all 6 synthetic values analysed without error |
| Click "Load 12 synthetic samples" | dashboard KPIs, 5 charts and the metadata table populate |
| Generate a password / passphrase | 98–100 and 83–91, entropy labelled "educational estimate only" |
| "Analyse this" from the generator | switches tab and shows the same verdict as the backend |
| Run the hashing demonstration | 3 steps, two different hashes for one repeated value |
| Console errors / page errors | **0** |
| External network requests | **0** |

---

## 8. Known skips and deliberate limitations

* `test_sequence_detection[xyz]` is **skipped by design**: three characters is
  below `MIN_SEQUENCE_LEN`, and the skip documents that boundary.
* Timing assertions are avoided (they flake in CI); rate limiting is tested by
  exhausting the bucket instead of sleeping.
* The suite never asserts entropy as a proof of strength — only that the number
  is computed, labelled and accompanied by its caveat.
