"""
tests/conftest.py
--------------------------------------------------------------------------
PURPOSE
    Shared pytest fixtures and path setup.

    IMPORTANT: every password used in this test suite is a SYNTHETIC demo
    value. No real credential is used, stored or logged anywhere in the test
    suite -- and the tests that check logging capture assert the opposite.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import pathlib
import sys
import tempfile

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Synthetic demo values used across the suite (safe to publish)
# ---------------------------------------------------------------------------
DEMO_PASSWORDS = {
    "empty": "",
    "single_char": "a",
    "short_numeric": "1234",
    "common": "password",
    "common_with_suffix": "password123",
    "composition_bait": "Password123!",
    "repeated": "aaaaaaaaaaaaaaaa",
    "sequential": "abcdefgh",
    "reverse_sequential": "zyxwvuts",
    "keyboard": "qwerty123",
    "repeated_substring": "abcabcabc",
    "word_and_year": "Summer2025!",
    "famous_phrase": "correct-horse-battery-staple",
    "passphrase": "Copper-Lantern-Orchid-Gravity",
    "long_random": "x7#Kq2!mZ9@vL4$p",
    "unicode": "Пароль-Демо-2026!",
    "spaces": "with space passphrase here",
    "symbols_only": "!@#$%^&*()",
    "over_length": "A" * 300,
    "probe": "Zq7#vP2!mL9@Rk4t",       # high-entropy probe for privacy tests
}


@pytest.fixture(scope="session")
def demo() -> dict:
    """Return the dictionary of synthetic demo passwords."""
    return DEMO_PASSWORDS


@pytest.fixture()
def analyze():
    """Return the analyze_password callable."""
    from backend.services.password_analyzer import analyze_password
    return analyze_password


@pytest.fixture()
def flask_client(tmp_path, monkeypatch):
    """
    Return a Flask test client with analytics pointed at a temporary database,
    so the test suite never touches the developer's real data/analytics.db.
    """
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test_analytics.db"))
    import importlib

    from backend.services import audit_store
    importlib.reload(audit_store)          # pick up the temporary DATABASE_PATH

    from backend.app import create_app
    app = create_app({"TESTING": True, "PSA_STORE_ANALYTICS": True})
    with app.test_client() as client:
        yield client


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    """Point the analytics store at a throwaway database file."""
    path = tmp_path / "analytics_test.db"
    monkeypatch.setenv("DATABASE_PATH", str(path))
    import importlib

    from backend.services import audit_store
    importlib.reload(audit_store)
    yield path


@pytest.fixture()
def demo_context() -> dict:
    """Synthetic personal context for the overlap check."""
    return {
        "first_name": "Demo",
        "birth_year": "1999",
        "organisation": "Demo College",
    }


@pytest.fixture()
def tmp_dir():
    """A temporary directory that is cleaned up automatically."""
    with tempfile.TemporaryDirectory() as directory:
        yield pathlib.Path(directory)
