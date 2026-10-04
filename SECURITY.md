# Security Policy

## Purpose of this project

This repository is a **defensive, educational** cybersecurity tool. It analyzes
password strength **locally / in memory** and gives the user security
recommendations. It does **not** crack, harvest, transmit or store passwords.

## Design guarantees (each one is asserted by an automated test)

| Guarantee | Enforced by | Test |
|---|---|---|
| The submitted password is never stored | no storage API is called; the SQLite schema has no password column | `tests/test_privacy.py::test_T28_password_not_stored` |
| The submitted password is never logged | logging filter redacts secret-shaped text; the audit helper has no parameter that could hold a value | `tests/test_privacy.py::test_T29_password_not_in_logs` |
| The password is never returned in a response | responses are built from metrics and masked evidence | `tests/test_api.py::test_response_never_echoes_password` |
| The password is never placed in a URL | the value travels in a JSON body only | `tests/test_api.py::test_password_never_in_url` |
| Nothing is transmitted externally | no HTTP client exists in the backend; the static build makes zero network requests | `tests/test_privacy.py::test_no_outbound_network_code_in_backend` |
| Analytics contain metadata only | schema columns are score/length/counts/timestamps | `tests/test_analytics.py::test_schema_has_no_secret_columns` |
| Personal context is never persisted | context is used in memory for one call; only field lengths are echoed | `tests/test_privacy.py::test_context_is_not_stored` |
| Generation uses a CSPRNG | `secrets` in Python, `crypto.getRandomValues` in the browser | `tests/test_generator.py::test_uses_csprng_not_random_module` |
| No cracking functionality exists | no candidate/guessing loops anywhere | `tests/test_scope.py::test_no_cracking_terminology_in_code` |

## Reporting a vulnerability

If you find a security issue in this project (for example a way to make the
tool log or persist a submitted value), please report it privately:

1. Do **not** open a public issue for anything that could expose a user.
2. Open a GitHub *security advisory* (Security tab → "Report a vulnerability"),
   or contact the maintainer through the address listed in the repository
   profile.
3. Include: the affected file, reproduction steps using **synthetic demo
   values only**, the impact you believe it has, and any suggested fix.

Please do not test against any system you do not own or have written
permission to test. This project must never be pointed at live accounts.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |

## Production deployment notes

* Serve the API over **HTTPS** only; put TLS termination in front of Flask.
* Replace the in-process token-bucket limiter with a shared store (for example
  Redis) when running more than one worker.
* Keep the UI and the API on the same origin so the same-origin policy applies.
* Set `ANALYTICS_ENABLED=0` if you do not need the dashboard at all.
* Re-read `docs/PRIVACY.md` before adapting this code for any real system.
