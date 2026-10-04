# Resume, LinkedIn and repository copy

Ready-to-use text for placements. Replace `<your-username>`, the dates and the
university line with your details, and **keep every claim true** — you can defend
all of it, because it is all in the repository.

---

## 1. Resume — Project section (3 bullets)

**Password Strength Analyzer & Security Suggestion Tool** — *Python, JavaScript, Flask, SQLite, pytest* — [github.com/&lt;your-username&gt;/Password-Strength-Analyzer-Security-Tool](https://github.com/)

- Built a multi-signal password strength engine in Python and mirrored it in
  JavaScript, detecting 14 weakness classes (dictionary and l33t variants,
  sequences, keyboard walks, repetition, word+year shapes, personal-context
  overlap) and producing a 0–100 score, a five-band classification and
  itemised, non-echoing remediation advice.
- Designed a privacy-safe analytics schema and REST API in which the analysed
  value is never stored, logged, returned or transmitted; enforced the guarantee
  with 21 automated privacy tests, a byte-level database scan and an in-page
  network counter that reports zero external requests.
- Shipped 261 passing pytest tests plus a 74-assertion Node harness that proves
  Python/JavaScript engine parity on 66 shared fixtures, and deployed the tool as
  a dependency-free GitHub Pages site and a single 273 KB offline HTML build.

### Two-line project description

> A beginner-friendly, defensive cybersecurity project that measures password
> strength by predictability instead of symbol counting, explains every finding
> and suggestion, and stores nothing about the password it analyses.
> Implemented twice — a Python/Flask backend and a zero-network JavaScript
> engine — with the two kept in step by automated parity tests.

---

## 2. LinkedIn — Project entry

**Password Strength Analyzer & Security Suggestion Tool** · Personal project

Most password meters count character types. Attackers do not. This project scores
a password the way an attack actually works: length and diversity are treated as
*necessary* signals, while predictability — common passwords, dictionary and l33t
variants, numeric and alphabetic sequences, keyboard walks, repetition,
word-plus-number and word-plus-year shapes, and optional overlap with personal
context — decides the outcome. The result is a 0–100 score across five bands, with
suggestions that explain *why* each weakness matters and never repeat the value
back to the user.

The engineering work that made it interesting:

* **A privacy-first data model.** The SQLite schema for the analytics dashboard
  has no column that could hold a password, a hash or personal context. That is
  not a policy — it is enforced by schema-level tests, a byte scan of the
  database file and a redaction filter on the logger.
* **A real-time web UI** with a masked-by-default field, score gauge, itemised
  penalty breakdown, live findings, a secure generator (`secrets` /
  `crypto.getRandomValues`), a policy checker that reports POLICY PASS/FAIL
  separately from the strength score, and hand-built SVG charts with no CDN
  dependency.
* **Two implementations kept honest.** The engine exists in Python (backend) and
  in JavaScript (browser/GitHub Pages). A Node harness runs 66 shared fixtures
  through both and fails CI the moment they disagree — which caught genuine
  Unicode, rounding and duplicate-finding bugs during development.
* **Education as a deliverable.** The app ships a ten-rule password guide, an
  interview-question-and-answer section, a hashing demonstration (salting and key
  stretching, shown in isolation from the analyzer) and an explicit statement
  that a strength score is an estimate, not a guarantee.

**Stack:** Python · Flask · SQLite · JavaScript (ES2020) · HTML/CSS · pytest ·
Playwright · GitHub Actions · GitHub Pages

**What I learned:** why composition rules alone fail (`Password123!` scores 0),
why entropy formulas must be qualified, why rate limiting and MFA matter more
than any meter, and how to turn a privacy claim into something a test can fail on.

---

## 3. Skills to list from this project

**Security**
Password strength estimation · pattern and dictionary analysis · entropy
estimation and its limits · secure password storage theory (hashing, salting,
key stretching, Argon2id/bcrypt/scrypt/PBKDF2 work factors) · MFA and
phishing-resistant authentication · rate limiting, lockout and session security ·
NIST SP 800-63B / OWASP ASVS policy design · privacy-by-design · threat modelling
of a tool that handles secrets · defensive-scope discipline

**Development**
Python 3 · Flask · REST API design and status-code discipline · input validation ·
SQLite schema design · JavaScript (ES2020) · semantic HTML and accessibility ·
responsive CSS · SVG data visualisation · `secrets` / `crypto.getRandomValues`

**Testing and tooling**
pytest (261 tests) · fixtures and test-data contracts · cross-language parity
testing · Playwright browser automation · coverage · Git and GitHub ·
GitHub Actions CI · GitHub Pages deployment · black-box API testing · static
source analysis (AST/regex) to enforce security properties

---

## 4. Repository description (GitHub "About" field)

```
Defensive project: a password strength analyzer that scores predictability, not symbol
count, explains every finding, and never stores, logs or transmits the value it analyses.
Python/Flask + a zero-network JavaScript build for GitHub Pages.
```

### Suggested topics

The 11 slots the repository actually uses (see
[`GITHUB_SETUP.md`](GITHUB_SETUP.md#the-11-topics)): `password-strength`,
`password-security`, `cybersecurity`, `infosec`, `security-tools`, `python`, `flask`,
`javascript`, `pytest`, `privacy-by-design`, `defensive-security`.

Longer list for LinkedIn skills / the About text:

```
password-strength  password-security  cybersecurity  infosec  security-tools
python  flask  javascript  sqlite  pytest  github-pages  nist-800-63b  passphrases
entropy  defensive-security  secure-coding  web-security
```

### Suggested one-line tagline for the social preview

> **Predictability, not symbol counting.**

---

## 5. Cover-letter / interview soundbite

> "I built a password strength analyzer because password meters are the most
> common security control users actually see, and most of them are wrong. A meter
> that checks for an uppercase letter, a digit and a symbol gives
> `Password123!` full marks — and it is one of the first few thousand guesses for
> any cracking tool. So I scored predictability instead: dictionary and l33t
> matching, sequences, keyboard walks, repetition, word-plus-year shapes and
> personal-context overlap, each producing a specific finding and a specific fix.
>
> The part I am proudest of is the privacy design. The tool asks you to type your
> most sensitive string, so it must be trustworthy. The value is processed in
> memory only: never stored, never logged, never returned in the API response and
> never sent anywhere. In the browser build the engine runs locally, so the value
> never leaves the page at all — and the UI proves it by counting its own network
> requests and reporting zero.
>
> I also learned that a claim is not a guarantee. Every privacy property in that
> project is backed by an automated test, the scoring rubric is pinned by a
> calibration table, and the Python and JavaScript engines are checked against
> each other by 66 shared fixtures so they cannot silently drift apart."

---

## 6. Portfolio one-pager layout (if your course requires it)

1. **Title + one-line problem statement** (predictability, not symbol counting)
2. **Live link** (GitHub Pages) + **repository link**
3. **Three screenshots** — analyzer with `Password123!` at 0, a VERY STRONG
   passphrase, the privacy page with the zero-network counter
4. **Architecture diagram** (from the README)
5. **Three bullets on engineering decisions** — privacy schema, dual engines with
   parity tests, policy-vs-strength separation
6. **Test evidence** — `261 passed` and `74 passed` command output
7. **What you would do next** — from the "Future improvements" section of the
   README (breach-check k-anonymity integration, WebAuthn/passkey guidance,
   i18n, a shared rate-limit store)
