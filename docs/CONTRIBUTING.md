# Contributing

This is a teaching project, so contributions are welcome if they keep it
**accurate, defensive, testable and beginner-readable**.

---

## 1. Non-negotiable rules

1. **Defensive only.** No cracking, brute-forcing, credential harvesting, key
   logging, credential stuffing or authentication bypass — not even as a
   "demonstration". `tests/test_scope.py` fails the build if such a function
   appears, and `tests/test_scope.py::test_no_outbound_http_client_is_imported`
   fails if an HTTP client is added to the engine.
2. **Never store, log or transmit a submitted value.** If a change touches the
   analysis path, run `python -m pytest tests/test_privacy.py -v` before you
   commit. The guarantees there are contract, not aspiration.
3. **Never put a real password in a fixture, screenshot, dataset or comment.**
   Synthetic values only. The existing examples show the pattern to follow.
4. **Use `secrets`, never `random`.** Applies to generators, fixtures and tests.
5. **A strength score is an estimate.** Any new output must keep its caveat
   attached; do not let the UI present a score as a guarantee.
6. **Do not add a periodic-expiry policy requirement.** Modern guidance
   (NIST SP 800-63B) discourages forced rotation without evidence of compromise;
   `legacy_bank` exists as an anti-pattern demonstration, clearly labelled.
7. **Do not echo the value in a response string.** Describe the *shape* of the
   problem ("looks like a word plus a year"), never the value.

---

## 2. Development setup

```bash
git clone https://github.com/<your-username>/Password-Strength-Analyzer-Security-Tool.git
cd Password-Strength-Analyzer-Security-Tool
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q                       # 261 passed, 1 skipped
node tests/js/run_parity_test.js          # 74 passed
```

Serve the app while you work:

```bash
python backend/app.py                     # http://127.0.0.1:5000
```

---

## 3. The golden rule: the two engines must agree

The Python engine (`backend/services/`) and the JavaScript engine
(`frontend/js/engine.js`) implement the same rubric. Parity is enforced by CI.

**Any change to a detector, a weight, a penalty or a score cap requires this
sequence:**

```bash
# 1. make the change in BOTH engines
# 2. regenerate the shared fixture (uses the Python engine as the source of truth)
python scripts/generate_fixtures.py
# 3. prove the two runtimes agree
node tests/js/run_parity_test.js
# 4. re-run the pinned calibration table and the fixture-staleness check
python -m pytest tests/test_scoring.py tests/test_fixtures.py -v
# 5. if data/*.txt changed, regenerate the browser copies too
python scripts/build_frontend_data.py
# 6. rebuild the single-file artefact that ships
python scripts/build_standalone.py
```

### Parity pitfalls already solved — do not regress them

| Pitfall | Rule |
|---|---|
| Unicode characters | JavaScript must use Unicode-aware tests (`/\p{L}/u`), never `[a-zA-Z]` |
| Rounding | Both sides round the accumulated score to 6 decimals before classifying (JS uses a half-to-even `pyRound`) |
| Penalty totals | Per-category penalties are capped and rounded independently of the displayed values |
| Duplicate findings | A curated dictionary hit returns immediately; do not also report the keyboard walk |
| Repetition matching | Compare blocks **case-sensitively**; a case echo is allowed in at most one position (see `tests/test_repetition_regression.py`) |
| Structural findings | `short_length` and `low_variety` carry an explicit `penalty_bits` (8.0 / 4.0 / 3.0) so both engines compute the same total |

---

## 4. Adding a detector

1. Implement it in `backend/services/pattern_detector.py` returning the shared
   finding shape:

   ```python
   {
       "type": "sequence",            # stable identifier (used by analytics)
       "severity": "medium",          # critical | high | medium | low | info
       "title": "Sequential characters",
       "description": "…",            # explain WHY it is weak, not just what was found
       "evidence": "••••",            # masked, always
       "positions": [3, 4, 5],
       "penalty_bits": 12.0,
   }
   ```

2. Register the category in `PENALTY_CAPS` (`scoring_engine.py`) and in the JS
   mirror.
3. If it is a *structural* problem that arithmetic cannot express, add a cap in
   `_applicable_caps()` — and explain the reasoning in the `reason` string,
   because the UI shows that sentence to the user.
4. Add a suggestion for the category in `suggestion_engine.py` — a specific,
   actionable fix, never a restatement of the problem.
5. Mirror all of it in `frontend/js/engine.js`.
6. Add tests: a positive case, a negative case (no false positive), a masking
   assertion, and the regression pair in the fixture list.
7. Document it in `README.md` (pattern table) and `docs/SCORING.md` (penalty
   table).

---

## 5. Adding a test

* Put engine tests in the file that matches the module under test; end-to-end
  scenarios belong in `tests/test_analyzer.py` with a `T⟨number⟩` prefix so the
  scenario table in `docs/TESTING.md` stays traceable.
* Take every input from `tests/conftest.py::DEMO_PASSWORDS`. If you need a new
  value, add it there **and** mark it clearly as synthetic.
* Do not assert on timing (it flakes). Do not assert that a specific string is
  weak "because it looks weak" — assert the *reason* (the finding type).
* Prefer deterministic construction over randomness. If you need a long random
  value, use `tests/helpers.py::deterministic_long_value`, which builds one from
  a SHA-256 keystream (uniform, reproducible, and free of the `random` module).

---

## 6. Documentation changes

If you change behaviour, update in the same commit:

* `README.md` — the section a newcomer reads first
* `docs/SCORING.md` — if a weight, penalty or cap moved
* `docs/TESTING.md` — if the scenario table or counts changed
* `docs/SAFE_DEMO_CASES.md` — if the documented scores changed
  (they are pinned by `tests/test_scoring.py`)

---

## 7. Commit messages

Conventional, imperative and specific:

```
feat(engine): add descending keyboard-walk detection
fix(scoring): cap thin character sets below the STRONG band
test(privacy): assert the audit helper cannot accept a value
docs(scoring): document the no_letters cap
chore(ci): run the parity harness before the screenshot build
refactor(analyzer): extract the passphrase entropy correction
```

---

## 8. Pull-request checklist

- [ ] `python -m pytest -q` is green
- [ ] `node tests/js/run_parity_test.js` reports 0 failures
- [ ] `python scripts/generate_fixtures.py` committed (if the engine changed)
- [ ] `python scripts/build_standalone.py` rebuilt (if `frontend/` changed)
- [ ] No real password, name, email or employer anywhere in the diff
- [ ] Privacy tests still pass
- [ ] Documentation updated
- [ ] The change is something you can explain out loud, in your own words

---

## 9. Reporting a security issue in *this* project

See [`SECURITY.md`](../SECURITY.md). Please do not open a public issue for a
vulnerability; the private disclosure route is described there.
