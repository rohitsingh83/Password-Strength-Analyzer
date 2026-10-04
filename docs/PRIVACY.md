# Privacy & security design

Every claim in this document is asserted by an automated test. If a future change breaks a
guarantee, CI fails instead of the documentation quietly becoming a lie.

---

## 1. The threat this design addresses

A password-strength tool asks users to type their **most sensitive string** into a box. That
creates a set of risks the tool itself must not introduce:

| Risk | Why it matters | How this project avoids it |
|---|---|---|
| Plaintext storage | A read-only database leak becomes instant account takeover for every user | No password is written anywhere, ever |
| Hashing "for analytics" | Short passwords are reversible from fast hashes; a hash table becomes a credential store | Analytics store no hash, no salt and no derived value |
| Log leakage | Access logs, error logs and debug logs are widely readable and often shipped to third parties | A redaction filter plus an audit helper with no parameter for a value |
| Response reflection | An echoed value lands in browser history, dev tools, proxies and support tickets | Responses are built from metrics; all evidence is masked |
| URL leakage | Query strings appear in server logs, browser history and `Referer` headers | The value travels only in a JSON body; the static build never transmits it |
| Client-side persistence | `localStorage` survives logout and is readable by any XSS | The UI keeps session statistics in a JavaScript variable only |
| Third-party transmission | Breach-check APIs learn the password; CDNs learn usage patterns | Zero external requests; the demo breach corpus is local |
| Over-collection of context | Name/birth-year checks can turn into a personal-data store | Context is used in memory for one call; only field *lengths* are echoed back |

---

## 2. Data-flow guarantees

```
        User input
            │
            ▼
   ┌──────────────────┐   the value exists only here, as a function argument
   │  In-memory engine │   and a local variable, for the duration of one call
   └────────┬─────────┘
            │ derived, non-secret values only
            ▼
   ┌──────────────────┐        ┌───────────────────────────────┐
   │  API response     │        │  Aggregate metadata store      │
   │  score, findings, │        │  score · classification ·      │
   │  masked evidence, │        │  length · ratios · counts ·    │
   │  metrics          │        │  timestamp                     │
   └──────────────────┘        └───────────────────────────────┘
            │                              │
            └──────────► never contains the value ◄────────────┘
```

**What is stored** (`data/analytics.db`, only when `ANALYTICS_ENABLED=1`):

```sql
CREATE TABLE analyses (
    analysis_id            TEXT PRIMARY KEY,
    score                  INTEGER NOT NULL,
    classification         TEXT    NOT NULL,
    password_length        INTEGER NOT NULL,
    unique_character_ratio REAL    NOT NULL,
    character_type_count   INTEGER NOT NULL,
    weakness_count         INTEGER NOT NULL,
    pattern_count          INTEGER NOT NULL,
    top_weakness           TEXT,
    duration_ms            REAL,
    analyzed_at            TEXT    NOT NULL
);

CREATE TABLE findings (
    finding_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id   TEXT NOT NULL,
    finding_type  TEXT NOT NULL,      -- e.g. "sequence"
    severity      TEXT NOT NULL,      -- e.g. "high"
    description   TEXT NOT NULL,      -- generic category text, never the value
    FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id) ON DELETE CASCADE
);

CREATE TABLE generated_passwords_meta (
    meta_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    generator     TEXT NOT NULL,
    length        INTEGER NOT NULL,
    entropy_bits  REAL NOT NULL,
    class_count   INTEGER NOT NULL,
    created_at    TEXT NOT NULL
);
```

There is **no column** for a password, a password hash, a salt, a partially masked value or the
user's context. `tests/test_scope.py::test_no_database_column_can_hold_a_password` strips SQL
comments from the schema string and asserts exactly that.

---

## 3. Why we do not store a password hash

Storing `sha1(password)` or `md5(password)` "just for analytics" is a common and serious mistake:

1. **Fast hashes are reversible for weak secrets.** A rainbow table or an offline brute force
   recovers most short human passwords in seconds. Unsalted MD5/SHA-1 is not a cryptographic
   protection for a password.
2. **An analytics table becomes a credential store by accident.** If the same value appears in a
   real authentication store, the two datasets correlate; a leaked analytics file then tells an
   attacker which accounts share a password.
3. **It invites scope creep.** "We only store a hash" is one commit away from "we also store the
   salt and the algorithm" and then from "let's verify submissions".
4. **It is unnecessary.** The dashboard needs counts, bands and averages. Length, score and
   category counts deliver all five charts. A hash adds zero educational value and real risk.

So: **no hash, no salt, no raw value.** `tests/test_privacy.py` checks the database bytes for the
probe value, its reverse, and the 5-character SHA-1 prefix that the breach lookup computes.

---

## 4. Logging design

```python
# backend/utils/logging_config.py
class SecretRedactionFilter(logging.Filter):
    """Scrubs secrets out of record.msg and record.args before formatting."""
```

* The filter rewrites anything matching `password=…`, `"password": "…"`, `passphrase: …`,
  `token=…`, `api_key=…` and `Bearer <token>` into `[REDACTED]`.
* The audit helper has a signature that **cannot** accept a value:

  ```python
  def log_analysis_metadata(logger, analysis_id, score, classification, length, duration_ms):
  ```

  There is no `password` parameter, so a future developer cannot accidentally log one through it.
  `tests/test_privacy.py::test_audit_helper_cannot_accept_a_password` inspects the signature.
* The unhandled-exception handler logs the exception **type** only — never `str(exception)`,
  because exception messages can embed the offending value.

What a normal run logs:

```
2026-10-04T09:01:29 | INFO | psa | analysis id=an_b40bd3552e1a score=45 classification=MODERATE length=17 duration_ms=6.19
2026-10-04T09:01:29 | INFO | psa | generated mode=passphrase length=38 entropy_bits=63.1
```

---

## 5. Browser-side guarantees (static build)

| Guarantee | Mechanism |
|---|---|
| Nothing is transmitted | No `fetch`, no `XMLHttpRequest`, no beacon, no WebSocket — the page has no backend to call |
| The claim is visible, not asserted | `app.js` wraps `fetch`/`XMLHttpRequest.open`/`sendBeacon` to count calls and displays the count ("Network requests made: 0") |
| No client-side persistence | No `localStorage`, `sessionStorage`, `indexedDB`, cookies or Cache API usage anywhere in `frontend/` |
| No console leakage | No `console.log`/`debug`/`info` calls in the shipped JavaScript |
| No CDN or third party | No external `<script>`, `<link>` or font — everything is inline or local, so there is nothing to leak usage to |
| Evidence is masked | Finding evidence is composed purely of `•` characters |

`tests/test_privacy.py` enforces the persistence, logging, CDN and fetch rules with regex checks
over the actual shipped files (allowing the *prose* on the privacy page that explains the APIs are
not used, but forbidding real access).

---

## 6. Breach checking without disclosure

The public breached-password APIs work on a **k-anonymity** model:

```
1. hash the candidate with SHA-1               →  5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
2. send ONLY the first 5 characters            →  5BAA6
3. receive ~500–800 hash suffixes for that bucket
4. compare the remaining 35 characters locally →  match / no match
```

The server learns a bucket shared by hundreds of thousands of passwords; it never learns the
value. This repository **does not call any external service**. It ships a tiny demo corpus of
synthetic/common-pattern hashes and performs the identical local comparison, and
`backend/services/data_loader.py::breach_lookup` returns the 5-character prefix that a real
integration *would* transmit, so the design is visible in the response (`breach_prefix_checked`).

---

## 7. Generating passwords safely

* Python: `secrets.SystemRandom` (OS CSPRNG), `tests/...::test_uses_csprng_not_random_module`
  parses the module with `ast` and fails if `random` is ever imported or called.
* Browser: `crypto.getRandomValues` with rejection sampling to remove modulo bias.
* Generated values are returned once and never stored, logged or cached. Analytics record shape
  only (length, entropy estimate, class count).

---

## 8. Deployment checklist (production)

- [ ] Serve over **HTTPS only**; terminate TLS in front of the app and redirect HTTP → HTTPS.
- [ ] Keep the UI and API on the **same origin** so the same-origin policy applies.
- [ ] Replace the in-process token-bucket limiter with a **shared** store (e.g. Redis) when
      running multiple workers.
- [ ] Set `ANALYTICS_ENABLED=0` if the dashboard is not needed.
- [ ] Review `Content-Security-Policy` for your environment (the shipped default is
      `default-src 'self'`).
- [ ] Disable Flask debug mode (`FLASK_DEBUG=0`) and any request-body logging at the proxy.
- [ ] Add a retention policy for the metadata table (for example delete rows older than 90 days).
- [ ] **Never** adapt this tool to collect real user passwords for analysis. If you need strength
      feedback in a real product, run the estimator client-side (as the static build does) or use
      the policy checker at registration where you are already receiving the value for hashing.

---

## 9. Scope statement

This project is defensive by construction:

* No cracking, no brute force, no credential stuffing, no dictionary attack against anything.
* No data collection beyond non-secret aggregates the operator can switch off.
* `tests/test_scope.py` fails the build if a `crack`/`harvest`/`keylogger`/`exfiltrate` style
  function, an outbound HTTP client, or a credential-pair data file ever appears.

**A strength score is not a security guarantee.** It cannot see reuse, phishing, malware, session
theft or a careless support process. Password strength is one control among many.
