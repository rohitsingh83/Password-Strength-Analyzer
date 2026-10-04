"""
tests/test_scope.py
--------------------------------------------------------------------------
Scope and ethics tests.

These tests document the boundaries of the project as executable assertions:
the tool must never grow cracking functionality, credential collection, an
external transmission path or a plaintext store. If someone adds one of those
in a future commit, CI fails.
"""

from __future__ import annotations

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND = PROJECT_ROOT / "backend"


def _python_sources():
    return sorted(BACKEND.rglob("*.py"))


def test_no_cracking_terminology_in_code():
    """
    Defensive scope: no cracking / harvesting / bypass functionality exists.

    The patterns look for definitions and call sites. Documentation legitimately
    explains what the tool refuses to do (for example the sentence "there is no
    key to steal"), and awareness text legitimately mentions phishing defence.
    """
    code_patterns = [
        r"def\s+\w*(crack|bruteforce|brute_force|harvest|keylog|phish|exfiltrat)\w*\s*\(",
        r"\b(crack|bruteforce|harvest|keylog|exfiltrate)_\w+\s*\(",
        r"\bbypass_auth\w*\s*\(",
        r"extract_password\s*\(",
    ]
    for path in _python_sources():
        source = path.read_text(encoding="utf-8")
        for pattern in code_patterns:
            assert not re.search(pattern, source, re.IGNORECASE), (path.name, pattern)


def test_no_wordlist_iteration_against_a_target():
    """There is no loop that tests candidate passwords against an account or hash."""
    patterns = [
        r"for .* in .*(wordlist|dictionary|candidates).*:\s*\n\s*.*verify",
        r"while\s+True:\s*\n\s*.*guess",
        r"subprocess\.(run|Popen)\(",
        r"socket\.socket\(",
    ]
    for path in _python_sources():
        source = path.read_text(encoding="utf-8")
        for pattern in patterns:
            assert not re.search(pattern, source, re.IGNORECASE), (path.name, pattern)


def test_no_network_clients_in_backend():
    """Nothing in the service layer can transmit data off the machine."""
    forbidden = ["import requests", "from requests", "import httpx", "import aiohttp",
                 "urllib.request.urlopen", "http.client.HTTPConnection", "smtplib"]
    for path in _python_sources():
        source = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in source, f"{path.name}: {token}"


def test_no_database_column_can_hold_a_password():
    """The schema constant is inspected directly for forbidden column names."""
    from backend.services.audit_store import SCHEMA

    # Strip SQL comments first: the schema's own explanatory comment mentions a
    # password, which is exactly the point being documented.
    sql_without_comments = re.sub(r"--[^\n]*", "", SCHEMA).lower()

    for forbidden in ("password ", "passwd", "pwd", "secret", "salt", "hash", "raw_value",
                      "context", "credential"):
        assert forbidden not in sql_without_comments, forbidden
    assert "password_length" in sql_without_comments, "length metadata should still be stored"


def test_analyzer_function_signature_is_documented():
    """The public entry point keeps its documented parameters and docstring."""
    import inspect

    from backend.services.password_analyzer import analyze_password

    signature = inspect.signature(analyze_password)
    assert list(signature.parameters)[:3] == ["password", "context", "policy"]
    assert inspect.getdoc(analyze_password)
    assert "in memory" in inspect.getdoc(analyze_password).lower() or \
           "memory" in inspect.getdoc(analyze_password).lower()


def test_result_never_contains_a_field_named_password():
    """No response field name could be mistaken for the value itself."""
    from backend.services.password_analyzer import analyze_password

    result = analyze_password("Zq7#vP2!mL9@Rk4t")
    assert "password" not in result
    for key, value in result.items():
        if isinstance(value, str):
            assert key != "password"
        assert not (isinstance(value, dict) and "password" in value and isinstance(value["password"], str))


def test_demo_data_contains_no_email_addresses():
    """Pattern lists must not contain anyone's email address or credential pair."""
    for path in (PROJECT_ROOT / "data").glob("*.txt"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert not re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", text), path


def test_readme_states_the_defensive_scope():
    """The top-level documentation carries the ethics/scope statement."""
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    lowered = readme.lower()
    assert "never store" in lowered or "not stored" in lowered
    assert "defensive" in lowered
    assert "no password-cracking" in lowered or "never create password-cracking" in lowered


def test_license_and_disclaimer_present():
    """A licence and a security disclaimer are part of a publishable project."""
    assert (PROJECT_ROOT / "LICENSE").exists()
    assert (PROJECT_ROOT / "SECURITY.md").exists()
