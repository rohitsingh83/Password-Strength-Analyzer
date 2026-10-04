# GitHub setup, publishing and commit history

Copy-and-paste material for turning this folder into the repository that appears
on your resume. Replace `<your-username>` everywhere.

---

## 1. Repository identity

| Field | Value |
|---|---|
| **Name** | `Password-Strength-Analyzer-Security-Tool` |
| **Description** | `Defensive cybersecurity project: scores password strength by predictability (dictionary, l33t, sequences, keyboard walks, repetition, context) instead of symbol counting. Python/Flask engine + zero-network JavaScript build, privacy-safe analytics, 261 tests.` |
| **Website** | `https://<your-username>.github.io/Password-Strength-Analyzer-Security-Tool/` |
| **Visibility** | Public |
| **Licence** | MIT (already in the repository) |

### The 11 topics

```
password-strength  password-security  cybersecurity  infosec  security-tools
python  flask  javascript  pytest  privacy-by-design  defensive-security
```

*(Add these as "Topics" on the repository page. The longer list in
[`RESUME_LINKEDIN.md`](RESUME_LINKEDIN.md) is for the "About" text and for
LinkedIn skills, not for the 11 topic slots.)*

---

## 2. Exact git commands

```bash
# 1. Initialise the repository in the project folder
cd Password-Strength-Analyzer
git init
git branch -M main

# 2. Tell git who you are (once per machine, if not already configured)
git config --global user.name  "Your Name"
git config --global user.email "you@example.com"

# 3. Stage everything and make the first commit
git add .
git commit -m "feat: initial commit - password strength analyzer, engine, tests and docs"

# 4. Create the empty repository on GitHub (web UI: New repository, name it
#    Password-Strength-Analyzer-Security-Tool, do NOT add a README), then:
git remote add origin https://github.com/<your-username>/Password-Strength-Analyzer-Security-Tool.git

# 5. Push
git push -u origin main

# --- for later changes -------------------------------------------------------
git add <files>
git commit -m "fix(scoring): cap thin character sets below the STRONG band"
git push
```

### Then enable GitHub Pages

**Settings → Pages → Source: Deploy from a branch → Branch: `main` / `/ (root)` → Save.**
URL: `https://<your-username>.github.io/Password-Strength-Analyzer-Security-Tool/`

Checklist before you share the link:

- [ ] `index.html` (root) redirects into `frontend/` — it is committed.
- [ ] `.nojekyll` is committed, so nothing is transformed by Jekyll.
- [ ] `frontend/js/data/*.js` are committed (they are generated, but Pages has no
      build step — see [`DEPLOYMENT.md`](DEPLOYMENT.md#13-what-must-be-in-the-repository-for-the-page-to-work)).
- [ ] The Pages URL is set in the repository's **About** panel, next to the description.
- [ ] The CI badge in the README resolves (it needs the workflow file, which is
      already at `.github/workflows/ci.yml`).
- [ ] Open the page in a private window and confirm the DevTools **Network** panel
      stays empty while you analyse a value.

---

## 3. Fourteen recommended commit messages

Make the history tell the story of the build, in this order. Each message is
conventional, specific, and says *why*:

```
 1. feat: initial commit - password strength analyzer, engine, tests and docs
 2. feat(engine): add length, character-class and unique-ratio analysers
 3. feat(engine): detect common passwords, dictionary words and l33t variants
 4. feat(engine): detect sequences, keyboard walks and repeated blocks
 5. feat(engine): estimate entropy with theoretical and effective bits
 6. feat(scoring): add the 0-100 rubric with per-category penalties and structural caps
 7. feat(engine): generate specific, non-echoing suggestions per finding
 8. feat(generator): add a secrets-based password and passphrase generator
 9. feat(policy): check administrator policy separately from the strength score
10. feat(api): expose analyze, generate, dashboard and education endpoints in Flask
11. feat(analytics): store aggregate metadata only - no password-capable column
12. feat(ui): build the real-time analyzer, dashboard, generator and learn tabs
13. test: add 261 pytest tests plus a JavaScript parity harness
14. docs: add README, scoring, privacy, testing, deployment and portfolio docs
```

**Why the history is laid out this way.** A reviewer reads commits, not just the
final state. This sequence shows a working increment at each step, puts the
privacy decision in a commit of its own (11), and separates tests and docs from
feature work so the discipline is visible.

### Bonus: committing a change the right way

```bash
# after changing a detector in BOTH engines
python scripts/build_frontend_data.py      # if data/*.txt changed
python scripts/generate_fixtures.py        # regenerate the parity fixture
node tests/js/run_parity_test.js           # prove the engines agree
python -m pytest -q                        # full suite
python scripts/build_standalone.py         # refresh the shipped single file
git add backend frontend tests scripts README.md docs
git commit -m "feat(engine): add descending keyboard-walk detection"
git push
```

---

## 4. Making the repository look professional in 10 minutes

1. **About panel:** description from section 1, website = the Pages URL, topics =
   the 11 above. This is what search results and link previews show.
2. **Social preview image:** Settings → Social preview → upload
   `screenshots/03-analyzer-homepage.png`. Instant credibility on LinkedIn.
3. **Pin the repository** on your profile and add the Pages link to your LinkedIn
   "Featured" section.
4. **Badges already work:** CI, tests, Python version, licence, "passwords stored:
   0" and "cracking functionality: none". They are the first thing a reviewer sees
   and they are honest.
5. **Issues:** leave one or two open *good first issue* items from the future-work
   list — a repository with a plan looks alive.
6. **Releases:** tag `v1.0.0` with release notes summarising the scoring rubric and
   the privacy guarantees. Attaching the standalone HTML as a release asset makes
   it a one-click demo for anyone who cannot run Python.
7. **Never commit:** `.env`, `data/analytics.db`, `__pycache__`, `screenshots` of a
   real password. `.gitignore` already covers the first three.
8. **Repository description discipline:** say "defensive" and "educational" in the
   description. It sets expectations and keeps the project on the right side of
   the course's rules.

---

## 5. What a recruiter or examiner will click

| They click | They should find |
|---|---|
| The Pages link | A working tool, dark and polished, that analyses a value instantly |
| The README | A one-line summary, a live link, badges, a screenshot of `Password123!` scoring 0, and a privacy section |
| `docs/SCORING.md` | The complete rubric, honestly labelled as project-defined |
| `docs/PRIVACY.md` | Guarantees mapped to the tests that enforce them |
| The tests | `python -m pytest -q` → 261 passed |
| The commit history | A visible, ordered build process |
| The license and SECURITY.md | That you know a security tool carries responsibilities |
