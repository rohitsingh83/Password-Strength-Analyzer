# Scoring rubric

> **This rubric is project-defined.** It is designed to be transparent, itemised and testable —
> it is **not** a universal security standard and should never be presented as one. zxcvbn, the
> NIST-oriented guidance and commercial IAM products all weigh these signals differently.

---

## 1. Why not composition rules?

A composition meter answers: *does this string contain at least one uppercase letter, one
lowercase letter, one digit and one symbol?* Every one of these passes:

```
Password123!     Admin@123      Welcome1!      Qwerty@2026
```

All four are inside the first few thousand guesses of any cracking tool, because they follow the
**shape** attackers expect: a dictionary word, a fixed separator, a short numeric suffix and a
symbol.

So the score is built from five questions instead:

1. **Is it long enough** to multiply an attacker's work? (necessary)
2. **Is it unpredictable** — no dictionary words, sequences or walks? (necessary)
3. **Is it a known password or a famous phrase?** (disqualifying)
4. **Does it contain information about the person** who created it? (dangerous)
5. **Is it structurally something arithmetic cannot express?** (caps)

---

## 2. Positive contributions (maximum 100)

| Component | Max | How it is earned |
|---|---|---|
| **Length** | 35 | Multiplied by a band credit: 0–7 → 0.05, 8–11 → 0.40, 12–15 → 0.72, 16–19 → 0.92, 20+ → 1.00 |
| **Character diversity** | 15 | 0.6 × min(classes / 4, 1) + 0.4 × min(unique ratio / 0.8, 1); halved below 8 characters |
| **Unique-character ratio** | 10 | Distributed evenly between characters; `unique / length` |
| **Pattern resistance** | 20 | Starts at full credit and loses it per distinct weakness category (a category with an 18-bit severity removes ~32 % of this component) |
| **Not a common password** | 10 | All-or-nothing: 0 when the value is a common password, a famous phrase or a breach-corpus hit |
| **Additional unpredictability** | 10 | +0.5 for ≥16 chars, +0.2 for ≥20 chars, +0.3 for ≥3 character classes, +0.2 for ≥75 % unique, +0.2 for 4 classes, +0.3 for no findings at all |

Every component reports `earned`, `max` and a human-readable `detail` string, so the UI can show
*why* each number is what it is.

---

## 3. Penalties (capped per category)

Each finding has a severity that maps to a fraction of its category cap:

`critical 1.00 · high 0.85 · medium 0.55 · low 0.30 · info 0.10`

| Category | Cap | Typical trigger |
|---|---|---|
| `common_password` | −45 | exact match in the educational common-password list (l33t-aware) |
| `common_phrase` | −45 | famous quote, lyric or proverb |
| `breach` | −45 | present in the local demo breach corpus |
| `keyboard_pattern` | −15 | `qwerty`, `!@#$`, `ytrewq`, row walks |
| `sequence` | −15 | `1234`, `abcd`, `9876`, `dcba` |
| `repeated_characters` | −15 | `aaaa`, `1111` |
| `repeated_substring` | −15 | `abcabc`, `121212` |
| `predictable_structure` | −15 | `welcome123`, `Demo-Pattern-123!` |
| `personal_info` | −20 | overlap with user-supplied context |
| `dictionary_word` | −12 | `welcome`, `password` (including word-prefix matches) |
| `year_pattern` | −8 | `1998`, `2026` |
| `date_pattern` | −8 | `12-05-2001` |
| `phone_pattern` | −10 | `9876543210` |
| `short_length` | −10 | under 12 characters (8-bit at under 8) |
| `low_variety` | −6 | only one character class |

Penalties are summed **per category** and capped there, so five overlapping repetition findings
cannot stack into a −75 penalty for one underlying problem. The total is the rounded sum of the
capped values — which is why the displayed per-category integers can add up to one less than the
total.

---

## 4. Structural score caps

Arithmetic alone cannot express some realities, so a small set of caps is applied. **The lowest
applicable cap wins**, because it represents the most serious structural limitation:

| Rule | Cap | Reasoning |
|---|---|---|
| `empty` | 0 | nothing was submitted |
| `extremely_short` (≤ 3 chars) | 10 | guessable instantly, whatever characters were used |
| `too_short` (< 8 chars) | 20 | below every modern minimum; symbols cannot compensate |
| `single_repeated_character` | 15 | only the length and the character need guessing |
| `very_low_uniqueness` (≤ 3 distinct chars, ≥ 8 long) | 25 | the real search space is tiny |
| `no_letters_short` (digits/symbols only, < 12) | 35 | large-looking pool, brute-forceable length |
| `known_common_or_breached` | 20 | known-common, famous phrase or breach hit is never above VERY WEAK |
| `contains_personal_information` | 40 | that information is discoverable from profiles and breach data |
| `word_plus_year` | 45 | word(s) + year is one of the most-modelled attack shapes |
| `word_plus_number_shape` | 60 | memorable word + short number: capped below STRONG |

The response exposes `caps_evaluated` (every cap that applied, with its reason) and
`score_cap_applied` (the one that decided the outcome), so nothing about the verdict is hidden.

---

## 5. Classification bands

| Score | Classification | Summary shown to the user |
|---|---|---|
| 0–20 | **VERY WEAK** | This password would be guessed almost immediately. |
| 21–40 | **WEAK** | Better than nothing, but it will not survive a targeted or automated attack. |
| 41–60 | **MODERATE** | Reasonable for a throwaway account, not for email, banking or work. |
| 61–80 | **STRONG** | Good, provided it is unique to this one account and MFA is enabled. |
| 81–100 | **VERY STRONG** | Excellent, provided it is unique and stored in a password manager. |

Rounding uses Python's `round()` (half-to-even) after normalising accumulated floating-point noise
to six decimals, and the JavaScript engine mirrors that exactly so both runtimes agree on boundary
values. `tests/test_scoring.py::test_score_is_calibrated_for_demo_cases` pins the table below, so
any accidental change to the rubric fails CI.

---

## 6. Worked examples

### `Password123!` → 0 / 100 (VERY WEAK)

| Signal | Value |
|---|---|
| Length | 12 characters → 0.72 × 35 = **25.2** |
| Diversity | 4 classes, 92 % unique → **15.0** |
| Unique ratio | 11/12 → **9.2** |
| Pattern resistance | 3 distinct weakness categories → **0.0** |
| Not common | breach hit → **0** |
| Unpredictability | length < 16 → **7.0** |
| **Raw total** | **56.4** |
| Penalties | breach −45, dictionary word −10, predictable structure −8 → **−63** |
| Cap | `known_common_or_breached` → ≤ 20 |
| **Final** | **0 · VERY WEAK** |

The lesson: a composition meter would call this "strong". Its composition *is* strong. Its
predictability is fatal.

### `aaaaaaaaaaaaaaaa` → 15 / 100 (VERY WEAK)

Full length credit (16 chars → 35.0 points) is earned, then erased: one repeating character means
an attacker guesses the pattern, not the value. Cap `single_repeated_character` → ≤ 15.

### `Copper-Lantern-Orchid-Gravity` → 92 / 100 (VERY STRONG)

| Signal | Value |
|---|---|
| Structure | recognised as a 4-word passphrase, so individual dictionary words are **not** penalised |
| Length | 30 characters → **35.0** |
| Diversity / unique ratio | 2 classes, 53 % unique → **13.8** |
| Pattern resistance | no findings → **20.0** |
| Not common | **10.0** |
| Unpredictability | long + no findings → **10.0** |
| Effective entropy | Diceware model: 4 × ~12.6 = **50.5 bits** (reported as an upper bound) |
| **Final** | **92** |

### `correct-horse-battery-staple` → 20 / 100 (VERY WEAK)

The most famous passphrase advice on the internet is also one of the worst passphrases you could
choose, because it is in every cracking wordlist. Structure alone earns 4/4 words; the
`common_phrase` finding caps the score at 20. *Generate your own.*

---

## 7. Changing the rubric

Weights and caps live in single dictionaries at the top of
`backend/services/scoring_engine.py` (`WEIGHTS`, `BANDS`, `PENALTY_CAPS`, `_applicable_caps`), and
the JavaScript mirror cites the same numbers in `frontend/js/engine.js`. To retune:

```bash
# 1. edit the weights/caps in BOTH engines
# 2. regenerate the shared fixture
python scripts/generate_fixtures.py
# 3. prove the two runtimes still agree
node tests/js/run_parity_test.js
# 4. re-run the pinned calibration table
python -m pytest tests/test_scoring.py -v
```

If you change the rubric, update this document in the same commit — the tests compare against the
values written here.
