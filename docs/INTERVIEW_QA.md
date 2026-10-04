# Interview questions and answers

Ten questions, in the order they are most likely to arrive, with the answers
written the way you should *say* them: short first sentence, then the detail.
The same ten questions appear inside the app on the **Learn** tab, so you can
rehearse while using the tool.

---

## 1. Explain your project.

> "I built a Password Strength Analyzer & Security Suggestion Tool. It evaluates a
> password using many signals instead of only checking whether it contains
> uppercase, lowercase, digits and symbols."

Then the three-part structure:

* **What it measures.** Length and character diversity first, then
  *predictability*: common passwords, dictionary words including l33t variants,
  numeric and alphabetic sequences, keyboard walks, repeated characters and
  blocks, predictable word-plus-number and word-plus-year shapes, and optional
  overlap with personal context the user volunteers. Each finding carries a
  penalty, and a few structural rules cap the score. The output is 0–100 across
  five bands, with an itemised breakdown and specific suggestions.
* **How it is built.** A Python engine of eleven service modules behind a Flask
  REST API with SQLite for aggregate analytics, plus a JavaScript port of the same
  engine so the whole tool runs in the browser with no server. The two are kept in
  step by a Node parity harness over 66 shared fixtures.
* **The property I care about most.** The password is processed in memory only —
  never stored, never logged, never returned in the API response, never sent to an
  external service. In the browser build it never leaves the page. That is
  enforced by tests, not just documented.

Finish with the differentiator: *"A composition meter gives `Password123!` full
marks. My tool scores it 0, because it is one of the first few thousand guesses
for any cracking tool."*

---

## 2. How does your analyzer decide whether a password is strong?

Two layers.

**Layer one — positives, maximum 100 points:** length (35, banded so 20+
characters earns full credit), character diversity (15), unique-character ratio
(10), pattern resistance (20), not being a common password (10), and an
unpredictability bonus (10) for length, class count and a clean finding list.

**Layer two — penalties and caps.** Each finding category has a cap (a
common-password or breach hit up to −45, personal information −20, keyboard walk
−15, sequence −15, repetition −15, predictable structure −15, dictionary word
−12, year/date/phone −8 to −10) and penalties are capped *per category*, so five
overlapping repetition findings cannot stack into a −75 penalty for one problem.
Then a small set of structural caps applies — the lowest one wins — because some
realities cannot be expressed arithmetically. A single repeated character caps at
15 whatever the length; a value with four or fewer distinct characters used
across 16+ positions caps at 45; a known-common or breached value caps at 20;
personal information caps at 40.

Add the honest caveat: *"It is a heuristic, and the rubric is project-defined and
documented rather than being a universal standard. That is why the response lists
every cap that was evaluated with its reason, instead of just printing a number."*

---

## 3. What is password entropy, and what are its limitations?

The estimate is `entropy ≈ L × log2(N)` — the number of characters multiplied by
the base-2 logarithm of the pool size, for example 94 for printable ASCII. 16
characters drawn from 94 symbols is about 105 bits.

Four limitations, and you should list them:

1. **It assumes random, independent, uniform selection.** Humans are not random.
   `Password123!` computes to about 72 bits of "entropy" while being guess number
   ~100 in practice.
2. **It does not know about public lists.** `correct-horse-battery-staple` is 28
   characters, worth ~133 bits by the formula, and appears in every cracking
   wordlist. That is why the tool labels it *"character-space upper bound — NOT
   applicable here"* whenever a value is found in a public list.
3. **Pool size is guesswork.** Does a user know that a keyboard has 33 punctuation
   marks? If they use 8 symbols in practice, the real pool is smaller.
4. **It ignores the attacker model.** Online guessing against a rate-limited login
   form and offline guessing against a stolen hash file are different problems by
   many orders of magnitude.

The project therefore reports *theoretical* bits, *effective* bits after pattern
penalties, and a labelled guess-resistance scenario table — all under the heading
"educational estimate only".

---

## 4. Why is `Password123!` not a strong password?

It satisfies every composition rule — 12 characters, upper, lower, digit and
symbol — and it is still worthless. Three signals:

* It matches a **breach corpus** entry (the real one appears millions of times in
  leaks) and contains the dictionary word `password`.
* Its **shape** is the most-modelled attack pattern there is: a common word,
  capitalised, plus two or three digits plus a symbol. Cracking tools have rules
  for exactly that transformation, so `password`, `Password`, `password1`,
  `Password1!`, `P@ssw0rd` and so on are all in the first few thousand guesses.
* **Entropy is a lie here.** The formula says ~72 bits; the practical cost is a
  few thousand guesses.

Then the general point: **composition is a checklist, predictability is a
measurement.** Attackers guess with dictionaries, mangling rules and Markov
models — not by brute-forcing the whole character space.

---

## 5. What is the difference between hashing and encryption?

* **Encryption** is reversible *by design*: with the key you get the plaintext
  back. It is for data you need to read again.
* **Hashing** is one-way: a fixed-length digest you cannot invert. Storing a
  password means storing a hash, and verifying means hashing the attempt and
  comparing.

That is why a leaked password database of properly hashed passwords does not
directly reveal the passwords — but *does* allow offline guessing: an attacker
tries candidates locally as fast as their hardware allows. So the hash must be
slow and salted, and verification must use a constant-time comparison
(`hmac.compare_digest`) to avoid leaking information through timing.

I demonstrate all of this in the project's hashing demo, which is deliberately
**isolated from the analyzer**: the analyzer never imports the hashing module, and
a scope test enforces that.

---

## 6. What is salting and why does it matter?

A salt is a unique, random value per user, stored next to the hash and combined
with the password before hashing. Two users with the same password then get
completely different hashes.

It defeats three attacks specifically:

1. **Rainbow tables** — precomputed hash lookups become useless, because the salt
   is not in the table.
2. **Cross-user correlation** — you cannot see that two accounts share a password,
   and cracking one does not reveal the other.
3. **The "one famous hash" shortcut** — the classic `5f4dcc3b5aa765d61d8327deb882cf99`
   for `password` with unsalted MD5 is instantly recognisable.

The salt does **not** need to be secret (it is stored in the clear) and it does
not make a weak password strong — it only removes the free shortcuts. In the demo
you can see the same input hashed three times with three different salts, giving
three different digests.

---

## 7. Why shouldn't passwords be stored with a fast hash such as SHA-256 on its own?

Because speed helps the attacker. A GPU computes billions of SHA-256 hashes per
second, so an intercepted hash file can be attacked at that rate — and even without
special hardware, common passwords fall immediately.

The fix is a **key-stretching** algorithm designed to be slow and tunable:
**Argon2id** (the current recommendation; memory-hard, which frustrates GPUs and
ASICs), **scrypt** (also memory-hard), **bcrypt**, and **PBKDF2** (older, FIPS
approved, not memory-hard; needs a high iteration count, e.g. 600,000 for
SHA-256). Parameters are a cost-per-verification budget: OWASP currently suggests
about 19 MiB of memory, 2 iterations and 1 degree of parallelism for Argon2id.

Two more rules: the same stretched algorithm is still salted per user, and the
algorithm and its parameters are stored **with** the hash (in a standard encoded
string such as `$argon2id$v=19$m=19456,t=2,p=1$…`) so you can raise the cost later
and re-hash on next login.

In this project the backend demonstrably uses `hashlib.scrypt` (n = 2¹⁴, r = 8,
p = 1) and `pbkdf2_hmac` (600,000 iterations) with a random per-call salt and
`hmac.compare_digest` for verification — with Argon2id documented as the
recommendation in production.

---

## 8. How did you protect user privacy in this project?

The tool asks for the most sensitive string a user has, so the design has to be
worthy of it. Five mechanisms, each backed by an automated test:

1. **Memory only.** The value exists as a function argument and a local variable
   for one call. It is never written to disk, a cache or a queue.
2. **Aggregate analytics.** The SQLite schema stores score, classification,
   length, ratios, counts and a timestamp. There is **no column** for a password,
   a hash, a salt or personal context — a schema test and a byte-level scan of the
   database file enforce it, and I deliberately do *not* store even a hash
   "for analytics", because a fast hash of a weak password is recoverable and
   turns an analytics table into a credential artefact.
3. **No logging.** A redaction filter scrubs secret-shaped patterns, and the audit
   helper has no parameter that can accept a value — so a future developer cannot
   log one by accident.
4. **No echo.** Responses and suggestions are built from metrics; every finding's
   evidence string is masked bullets. The API never returns the value, and the
   tool never puts it in a URL.
5. **No transmission.** Nothing is sent anywhere. The demo breach check is local
   (the real integration would use k-anonymity, sending only the first 5
   characters of a SHA-1 digest). In the browser build the UI counts its own
   network requests and displays **0**.

---

## 9. Is a strong password enough to secure an account?

No. A strength score is one control and it cannot see the other failure modes:

* **Reuse.** A 92/100 value used on five sites falls with the weakest one — that
  is exactly how credential stuffing works.
* **Phishing and real-time proxies** beat any password, however strong, because the
  user hands it over voluntarily.
* **Server-side compromise.** If the site stores passwords badly, your strength is
  irrelevant; if it stores them well, a leak still enables offline guessing.
* **Malware, keyloggers and session theft** operate after authentication.
* **Recovery paths** are often the weakest link — a weak support process bypasses a
  perfect password.

The layered answer is: a unique password from a password manager, **MFA** (and
phishing-resistant **passkeys/WebAuthn** where available), rate limiting and
lockout on the server, secure hashing with a modern algorithm, short-lived
sessions with secure cookies, monitoring and alerting, and user education. The
project's policy checker reflects the modern guidance: minimum length over
composition rules, no arbitrary periodic expiry, spaces and long passwords
allowed, and known-common values rejected.

---

## 10. How would you improve this project in the future?

Concrete, ordered, and each one honest about its trade-off:

1. **Real breach checking with k-anonymity** — send only the first five characters
   of a SHA-1 digest; the local demo corpus already models the flow. Trade-off:
   it introduces the project's only network dependency, so it would have to be
   opt-in and clearly disclosed.
2. **Markov / probabilistic strength models** trained on synthetic data, to replace
   hand-tuned penalties with a statistical estimate — while keeping the explainable
   per-category breakdown, because explainability is the point of this tool.
3. **Passkey and MFA guidance** in the education layer, since passwords are being
   displaced as the primary factor.
4. **A shared rate-limit store (Redis)** so the limiter is correct behind multiple
   workers — currently it is per process, which I would state as a known limitation.
5. **Accessibility and internationalisation** — screen-reader passes on the charts,
   localisation of the education layer, and locale-aware analysis. The engine is
   already Unicode-aware and uses `\p{L}` character classes.
6. **An expanded detector test corpus** with property-based testing, and a fuzzing
   pass over the API to prove no input shape can produce a 500 or an echo.
7. **Signed releases and a published container image**, plus a short security
   policy and a dependency-update bot.

Close with: *"I would also keep the same discipline — every claim about privacy or
scoring stays backed by a test, because that is what turns a claim into a
guarantee."*

---

## Two questions to ask *them*

Asking one good question at the end changes how you are remembered:

* "How does your team handle password policy for internal systems — is it still
  composition and rotation, or have you moved to length plus a blocklist and MFA?"
* "When your team reviews a tool that handles credentials, what evidence do you
  expect — a written policy, or tests that fail if the guarantee is broken?"

---

## Traps to avoid in the interview

| Don't say | Say instead |
|---|---|
| "Entropy proves how strong a password is." | "Entropy is an *upper bound* that assumes random selection; pattern analysis corrects it." |
| "A strong password means it can't be cracked." | "It means the guessing cost is high *for that attacker model*; reuse, phishing and server compromise are separate problems." |
| "I copied the algorithm from zxcvbn." | "I built a transparent, documented rubric inspired by the same ideas (and my repetition matcher is deliberately case-sensitive like zxcvbn's), but the weights and caps are mine and are pinned by tests." |
| "The tool is secure because it's small." | "It never handles the value beyond memory, the schema cannot store it, and tests fail if that changes." |
| "I'd store a hash of the password for analytics." | "No — a fast hash of a weak password is recoverable, and it turns analytics into a credential store." |
