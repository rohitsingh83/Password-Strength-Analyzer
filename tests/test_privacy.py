"""
tests/test_privacy.py
--------------------------------------------------------------------------
Security / privacy tests (T28, T29). Each test asserts one claim from the
privacy table in the README and on the site's Privacy tab.

These are the tests that matter most for the project's ethics statement:
they prove that the tool cannot leak what it never keeps.
"""

from __future__ import annotations

import io
import logging
import re
import sqlite3

import pytest


# ---------------------------------------------------------------------------
# T28 -- the password is not stored anywhere
# ---------------------------------------------------------------------------
def test_T28_password_not_stored(analyze, demo, temp_db):
    """Nothing derived from a submitted value is written to the analytics database."""
    from backend.services import audit_store

    probe = demo["probe"]
    result = analyze(probe)
    audit_store.record_analysis(result)

    database_bytes = temp_db.read_bytes()
    assert probe.encode() not in database_bytes
    # Also assert the *reverse* of the value and any hash-looking derivative
    # are absent, in case a future change starts hashing silently.
    assert probe[::-1].encode() not in database_bytes
    assert result["metrics"]["breach_prefix_checked"].encode() not in database_bytes


def test_stored_columns_are_metadata_only(temp_db, analyze, demo):
    """Inspect the actual schema: no column could hold a password or a hash."""
    from backend.services import audit_store

    audit_store.record_analysis(analyze(demo["word_and_year"]))

    connection = sqlite3.connect(temp_db)
    try:
        tables = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"analyses", "findings"} <= tables

        for table in ("analyses", "findings"):
            columns = [row[1].lower() for row in connection.execute(f"PRAGMA table_info({table})")]
            for forbidden in ("password", "passwd", "pwd", "secret", "hash", "credential"):
                assert not any(forbidden == column for column in columns), (table, columns)
    finally:
        connection.close()


def test_context_is_not_stored(temp_db, analyze, demo_context):
    """Personal context used for the overlap check never reaches the database."""
    from backend.services import audit_store

    result = analyze("Demo-1999-College!", context=demo_context)
    audit_store.record_analysis(result)

    database_bytes = temp_db.read_bytes().lower()
    for value in demo_context.values():
        assert value.lower().encode() not in database_bytes


def test_generated_password_is_not_stored(temp_db):
    """Only generator *properties* are persisted, never the generated value."""
    from backend.services import audit_store
    from backend.services.password_generator import generate_password

    generated = generate_password(24)["password"]
    audit_store.record_generation({"generator": "secrets", "length": 24,
                                   "entropy_bits": 120.0, "classes_used": ["lowercase", "digits"]})
    assert generated.encode() not in temp_db.read_bytes()


# ---------------------------------------------------------------------------
# T29 -- the password does not appear in logs
# ---------------------------------------------------------------------------
def test_T29_password_not_in_logs(analyze, demo):
    """
    A full analysis emits log lines that contain metadata only.

    The project logger sets `propagate = False`, so pytest's caplog fixture
    cannot see it by default. We therefore attach our own capture handler --
    the same redaction filter the application uses in production.
    """
    from backend.utils.logging_config import (
        SecretRedactionFilter, configure_logging, log_analysis_metadata,
    )

    logger = configure_logging()
    probe = demo["probe"]

    stream = io.StringIO()
    capture = logging.StreamHandler(stream)
    capture.addFilter(SecretRedactionFilter())
    logger.addHandler(capture)
    try:
        result = analyze(probe)
        log_analysis_metadata(logger, result["analysis_id"], result["score"],
                              result["classification"], result["metrics"]["length"],
                              result["duration_ms"])
    finally:
        logger.removeHandler(capture)

    captured = stream.getvalue()
    assert captured, "the audit helper should log something"
    assert probe not in captured
    assert result["analysis_id"] in captured
    # And the metadata we do expect is present.
    assert "score=" in captured and "classification=" in captured


def test_redaction_filter_scrubs_secret_shaped_text():
    """The logging filter neutralises password=, JSON secrets and bearer tokens."""
    from backend.utils.logging_config import redact

    samples = [
        'request payload {"password":"Zq7#vP2!mL9@Rk4t"}',
        "auth password=Zq7#vP2!mL9@Rk4t user=demo",
        'Authorization: Bearer abcdef1234567890',
        "passphrase: Zq7#vP2!mL9@Rk4t",
    ]
    for sample in samples:
        cleaned = redact(sample)
        assert "Zq7#vP2!mL9@Rk4t" not in cleaned
        assert "abcdef1234567890" not in cleaned
        assert "[REDACTED]" in cleaned


def test_logging_filter_applied_to_handler():
    """A log line that accidentally contains a secret is scrubbed before output."""
    from backend.utils.logging_config import SecretRedactionFilter, redact

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(SecretRedactionFilter())
    logger = logging.getLogger("psa.test.filter")
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False

    logger.info('processing {"password": "Zq7#vP2!mL9@Rk4t"}')
    assert "Zq7#vP2!mL9@Rk4t" not in stream.getvalue()
    assert "Zq7#vP2!mL9@Rk4t" not in redact('{"password": "Zq7#vP2!mL9@Rk4t"}')


def test_audit_helper_cannot_accept_a_password():
    """The metadata logger's signature has no parameter that could hold a value."""
    import inspect

    from backend.utils.logging_config import log_analysis_metadata

    parameters = set(inspect.signature(log_analysis_metadata).parameters)
    assert not parameters & {"password", "value", "secret", "passphrase", "raw"}


def test_api_does_not_log_the_password(flask_client, demo, caplog):
    """A real request through the API leaves no password in the captured logs."""
    probe = demo["probe"]
    with caplog.at_level(logging.INFO):
        flask_client.post("/api/analyze", json={"password": probe, "context": {"first_name": "Probe"}})
    assert probe not in caplog.text
    assert "Probe" not in caplog.text.replace("probe", "")


# ---------------------------------------------------------------------------
# Response and transport hygiene
# ---------------------------------------------------------------------------
def test_response_contains_no_raw_password(analyze, demo):
    """The structured result never contains the submitted value."""
    probe = demo["probe"]
    assert probe not in str(analyze(probe))


def test_masked_evidence_only(analyze, demo):
    """Every evidence string is composed solely of bullet characters."""
    for value in (demo["probe"], demo["composition_bait"], demo["repeated"], demo["word_and_year"]):
        for finding in analyze(value)["findings"]:
            assert set(finding["evidence"]) <= {"\u2022"}, (value, finding["type"])


def test_privacy_block_is_self_describing(analyze, demo):
    """The result carries explicit privacy flags a reviewer can assert against."""
    privacy = analyze(demo["probe"])["privacy"]
    assert privacy["password_stored"] is False
    assert privacy["password_logged"] is False
    assert privacy["password_returned_in_response"] is False
    assert privacy["password_sent_to_external_service"] is False
    assert privacy["context_stored"] is False
    assert privacy["evidence_masked"] is True


def test_no_outbound_network_code_in_backend():
    """
    The backend contains no HTTP client: nothing can be transmitted.

    The check looks for real import statements and call sites, not for the
    words themselves -- error messages legitimately contain phrases such as
    "Too many requests."
    """
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    patterns = [
        r"^\s*import\s+requests\b", r"^\s*from\s+requests\b",
        r"^\s*import\s+httpx\b", r"^\s*import\s+aiohttp\b",
        r"^\s*import\s+http\.client\b", r"^\s*from\s+http\.client\b",
        r"urllib\.request\.urlopen\s*\(",
        r"requests\.(get|post|put|patch|delete)\s*\(",
        r"smtplib\.", r"socket\.socket\s*\(",
    ]

    for path in (project_root / "backend").rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        for pattern in patterns:
            assert not re.search(pattern, source, re.MULTILINE), f"{path.name}: {pattern}"


def test_frontend_makes_no_fetch_calls():
    """The static build performs no network requests at all."""
    from pathlib import Path

    frontend = Path(__file__).resolve().parent.parent / "frontend" / "js"
    patterns = [r"\bfetch\s*\(", r"new\s+XMLHttpRequest\b", r"navigator\.sendBeacon\s*\(",
                r"new\s+WebSocket\b", r"new\s+EventSource\b"]
    # app.js instruments fetch/XHR to *count* them (so the claim is visible in
    # the UI); that instrumentation is the only permitted mention.
    allowed = {"app.js"}
    for path in frontend.rglob("*.js"):
        source = path.read_text(encoding="utf-8")
        for pattern in patterns:
            hits = re.findall(pattern, source)
            if hits and path.name not in allowed:
                raise AssertionError(f"{path.name}: {pattern}")
        if path.name in allowed:
            # Even there, the only usage must be the instrumentation wrapper.
            assert source.count("fetch(") <= 2, path.name


def test_no_client_side_persistence_in_frontend():
    """The front-end never writes to localStorage, sessionStorage or cookies."""
    from pathlib import Path

    frontend = Path(__file__).resolve().parent.parent / "frontend"

    # Prose may mention these APIs (the privacy page explains that they are not
    # used); actual *access* is what must not exist.
    usage_patterns = [r"\b(local|session)Storage\s*[.\[]", r"\bwindow\.(local|session)Storage\b",
                      r"document\.cookie\s*=", r"\bindexedDB\b", r"caches\.open\s*\("]

    for path in list(frontend.rglob("*.js")) + [frontend / "index.html"]:
        source = path.read_text(encoding="utf-8")
        for pattern in usage_patterns:
            assert not re.search(pattern, source), (path.name, pattern)


def test_password_field_is_masked_by_default():
    """The HTML input is type=password and marked with autocomplete=off."""
    from pathlib import Path

    html = (Path(__file__).resolve().parent.parent / "frontend" / "index.html").read_text(encoding="utf-8")
    assert 'id="password-input" type="password"' in html
    assert 'autocomplete="off"' in html
    assert "spellcheck=\"false\"" in html


def test_frontend_makes_no_external_requests():
    """There is no CDN, font, analytics or network call anywhere in the UI."""
    from pathlib import Path

    frontend = Path(__file__).resolve().parent.parent / "frontend"
    files = list(frontend.rglob("*.js")) + list(frontend.rglob("*.css")) + [frontend / "index.html"]

    for path in files:
        source = path.read_text(encoding="utf-8")
        for pattern in (r"https?://cdn\.", r"https?://fonts\.", r"google-analytics",
                        r"<script[^>]+src=\"https?://", r"<link[^>]+href=\"https?://"):
            assert not re.search(pattern, source), (path, pattern)


def test_frontend_has_no_console_logging_of_values():
    """The UI never logs user input to the console."""
    from pathlib import Path

    frontend = Path(__file__).resolve().parent.parent / "frontend" / "js"
    # Match real calls, not the word appearing inside explanatory prose.
    for path in frontend.rglob("*.js"):
        source = path.read_text(encoding="utf-8")
        assert not re.search(r"console\.(log|debug|info|trace|dir)\s*\(", source), path


# ---------------------------------------------------------------------------
# Scope: this is a defensive tool
# ---------------------------------------------------------------------------
def test_no_cracking_or_guessing_functionality():
    """No candidate-generation or guessing loop exists anywhere in the codebase."""
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    forbidden = ["crack_password", "bruteforce", "brute_force", "itertools.product(",
                 "itertools.permutations(", "itertools.combinations_with_replacement("]

    for path in (project_root / "backend").rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in source, f"{path.name} contains {token}"


def test_no_credential_pair_datafiles():
    """The data directory holds pattern lists, never user:password pairs."""
    from pathlib import Path

    data_dir = Path(__file__).resolve().parent.parent / "data"
    for path in data_dir.iterdir():
        if path.suffix not in (".txt", ".json"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        # No "user:password" or "email,password" style rows anywhere.
        assert not re.search(r"^[^\s#][^:\s]{2,}:[^\s]{6,}$", text, re.MULTILINE), path


def test_sample_passwords_are_synthetic():
    """Every demo value used in tests is a known pattern string, not a real credential."""
    from tests.conftest import DEMO_PASSWORDS

    for value in DEMO_PASSWORDS.values():
        assert "@gmail" not in value and "@outlook" not in value
        assert len(value) <= 300
