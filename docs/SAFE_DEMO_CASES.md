# Safe demo cases

Everything below is **synthetic**. Every value either belongs to the class of
universally documented "worst password" examples or was generated at runtime by
this tool. Nothing here is, or ever was, a real credential.

> **Rule for any demonstration, screenshot, report or viva:** type these values,
> never a personal password. If you want to show a real-world habit, describe the
> *shape* ("a name plus a year") instead of typing your own.

---

## 1. The five-minute demonstration script

| # | Value to type | Score | Band | The point it proves |
|---|---|---:|---|---|
| 1 | `123456` | 0 | VERY WEAK | The most-used password on earth; length and composition checks alone never catch it |
| 2 | `Password123!` | 0 | VERY WEAK | **The centrepiece.** 12 characters, all four character classes, and still worthless — a composition meter would call it strong |
| 3 | `aaaaaaaaaaaaaaaa` | 15 | VERY WEAK | 16 characters can be worthless: only the pattern needs guessing |
| 4 | `qwerty2026!` | 0 | VERY WEAK | "It has a symbol and this year!" — a keyboard walk with decoration |
| 5 | `Copper-Lantern-Orchid-Gravity` | 92 | VERY STRONG | Four unrelated words: long, memorable, unpredictable, and no single word is penalised |
| 6 | *runtime-generated 20-character value* | 96–100 | VERY STRONG | The same tool can create what it cannot break |

Steps:

1. Open the analyzer tab. Point out that the field is **masked by default**.
2. Type `Password123!` and let the score land. Expand *Why this score* (the
   breakdown bars) and the penalty list.
3. Type `aaaaaaaaaaaaaaaa` — the length tile turns green while the score does not.
   That contrast is the whole lesson.
4. Type `Copper-Lantern-Orchid-Gravity` (or use the generator tab) and show the
   entropy panel: 50.5 bits from the **passphrase model**, with the upper-bound
   caveat visible.
5. Click **Run the demo walk-through** to cycle through the six curated values.
6. Open **Dashboard** → **Load 12 synthetic samples** and show that the only
   columns are id, score, classification, length, findings and time.
7. Open **Privacy** and read the in-page network counter: **0 requests**.

---

## 2. Full expected-results table

These numbers come from the shipped engine and are pinned by
`tests/test_scoring.py::test_score_is_calibrated_for_demo_cases`. If the engine
changes, this table changes with it — that is what makes it a demo you can trust
under questioning.

| Value | Score | Band | Main finding(s) |
|---|---:|---|---|
| *(empty)* | 0 | VERY WEAK | Nothing submitted |
| `a` | 10 | VERY WEAK | Capped: 1 character is guessable instantly |
| `123456` | 0 | VERY WEAK | Common password + breach corpus |
| `password` | 0 | VERY WEAK | Common password |
| `password123` | 0 | VERY WEAK | Common password + word+number shape |
| `Password123!` | 0 | VERY WEAK | Breach hit + dictionary + predictable structure |
| `P@ssw0rd` | 0 | VERY WEAK | l33t normalised to "password", then matched as a common password |
| `qwerty` / `qwerty123` | 0 | VERY WEAK | Keyboard walk (+ breach) |
| `qwerty2026!` | 0 | VERY WEAK | Keyboard walk + year + breach |
| `abcd1234` | 0 | VERY WEAK | Common password **and** a sequence — a good example of overlapping findings |
| `zyxwvuts` | 37 | WEAK | Descending sequence; composition is fine, predictability is the problem |
| `abcabcabc` | 25 | WEAK | Repeated block; only 3 distinct characters |
| `aaaaaaaa` | 15 | VERY WEAK | Repeated character run |
| `aaaaaaaaaaaaaaaa` | 15 | VERY WEAK | Same run, longer — the cap explains why |
| `!@#$%^&*()` | 35 | WEAK | No letters, under 12 characters |
| `Sunset-Orchid-River` | 62 | STRONG | Recognised as a 3-word phrase; still short of VERY STRONG |
| `correct-horse-battery-staple` | 20 | VERY WEAK | Famous phrase: long but in every wordlist |
| `Tr0ub4dor&3` | 68 | STRONG | The famous XKCD example — strong, but a 4-word phrase beats it |
| `Demo-Pattern-123!` | 60 | MODERATE | Word + number shape, capped below STRONG |
| `Summer2025!` | 40 | WEAK | Word + year, capped at 45 |
| `Hyderabad@2026` | 45 | MODERATE | Word + year (also personal context if supplied) |
| `x7#Kq2!mZ9@vL4$p` | 97 | VERY STRONG | 16 random characters, 105 bits |
| `Copper-Lantern-Orchid-Gravity` | 92 | VERY STRONG | 4-word passphrase, 50.5 bits |
| `Tundra-Basil-Falcon-Thistle-Prism` | 91 | VERY STRONG | 5-word passphrase, 63.1 bits |
| `with space passphrase here` | 83 | VERY STRONG | Spaces are legitimate characters |
| `Rahul@123` + context | 37 | WEAK | Without context: 58 MODERATE — the context check matters |
| `!` + 24 random characters *(generated)* | 96–100 | VERY STRONG | What the generator produces |

---

## 3. Values that make specific teaching points

### The composition-rule trap

```
Password123!    composition 4/4    score 0
```

Ask the audience: *"Which is stronger, `Password123!` or `x7#Kq2!mZ9@vL4$p`?"*
Then show 0 versus 97. Composition is a checklist; predictability is a
measurement.

### The famous-phrase trap

`correct-horse-battery-staple` is 28 characters long and would "look" like 130
bits of entropy. It scores **20 — VERY WEAK**, because it appears in every
cracking wordlist. This is the fastest way to show why entropy formulas must be
qualified.

### The l33t illusion

`P@ssw0rd` → the engine normalises `@`→`a`, `0`→`o` and matches the dictionary
word. Attackers apply the same substitutions automatically, so "leetspeak" adds
approximately nothing.

### The reuse point (cannot be demonstrated by a score)

A strength score cannot see reuse. Say it out loud:

> `Copper-Lantern-Orchid-Gravity` is 92/100. If you use it on five websites and
> one of them is breached, all five accounts fall. Strength is necessary,
> uniqueness is what actually protects you — that is why a password manager is
> the real answer.

### The entropy lesson

| Value | Theoretical bits | What actually matters |
|---|---:|---|
| `Password123!` | ~72 | It is guess number ~100 in a real attack |
| `aaaaaaaaaaaaaaaa` | ~75 | The pattern, not the characters, is guessed |
| `correct-horse-battery-staple` | ~133 | Published phrase: a few thousand guesses |
| `Copper-Lantern-Orchid-Gravity` | 50.5 | Words chosen by you, never published |

The UI prints this sentence under the number: *"theoretical entropy assumes
truly random character selection… human-chosen passwords are predictable, so this
number is an upper bound."*

---

## 4. Demo hygiene checklist

- [ ] Use only the values in this document, or values generated by the tool.
- [ ] Never demonstrate on an account that exists (no live login screens).
- [ ] Blur or avoid typing any real name, birth year or employer in the context
      panel — use `Demo Name`, `1999`, `Demo College`.
- [ ] Keep the password field masked unless you are specifically demonstrating
      the 👁 toggle.
- [ ] Do not save the analysis page as an HTML file with a value baked in.
- [ ] If you show the API, use `curl` with a synthetic value and note that the
      response contains no echo of it.
- [ ] Regenerate the generator screenshot instead of reusing an old one, so the
      captured value is clearly machine-made.
