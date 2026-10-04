"""
tests/test_generator.py
--------------------------------------------------------------------------
Generator tests (T27): secure randomness, requested shape, no storage, no
duplicates, and honest entropy reporting.
"""

from __future__ import annotations

import inspect
import re

import pytest


def test_T27_generate_and_analyze():
    """A generated 20-character password is scored in the top bands by the analyzer."""
    from backend.services.password_analyzer import analyze_password
    from backend.services.password_generator import generate_password

    generated = generate_password(20)
    result = analyze_password(generated["password"])
    assert result["score"] >= 81
    assert result["classification"] == "VERY STRONG"


def test_uses_csprng_not_random_module():
    """
    The generator must use `secrets` and must not import or call the `random`
    module. The check parses the module with AST so that prose in docstrings
    (which mentions the anti-pattern by name) cannot confuse the result.
    """
    import ast

    from backend.services import password_generator as module

    tree = ast.parse(inspect.getsource(module))

    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    assert "secrets" in imported, "the generator must import secrets"
    assert "random" not in imported, "the generator must not import the random module"

    # No attribute access on a `random` object anywhere in the code.
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            assert not (node.value.id == "random" and node.attr.startswith("rand")), node.attr
            assert not (node.value.id == "random" and node.attr == "choice"), node.attr

    source = inspect.getsource(module)
    assert "secrets.SystemRandom" in source
    assert "secrets.choice" in source


def test_requested_length_and_classes():
    """The generator honours the requested length and enabled classes."""
    from backend.services.password_generator import generate_password

    generated = generate_password(24, use_uppercase=True, use_lowercase=True,
                                  use_digits=True, use_symbols=False)
    password = generated["password"]
    assert len(password) == 24
    assert any(c.islower() for c in password)
    assert any(c.isupper() for c in password)
    assert any(c.isdigit() for c in password)
    assert not any(c in "!@#$%^&*" for c in password)
    assert generated["classes_used"] == ["lowercase", "uppercase", "digits"]


def test_every_requested_class_appears():
    """Guaranteeing one character per class keeps registration forms happy."""
    from backend.services.password_generator import generate_password

    for _ in range(25):
        password = generate_password(12)["password"]
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert any(c.isdigit() for c in password)
        assert any(not c.isalnum() for c in password)


def test_generated_values_are_unique():
    """No duplicates in a batch -- evidence of real randomness, not a template."""
    from backend.services.password_generator import generate_password

    values = {generate_password(20)["password"] for _ in range(200)}
    assert len(values) == 200


def test_avoid_ambiguous_characters():
    """The look-alike filter removes l I 1 O 0 when requested."""
    from backend.services.password_generator import generate_password

    for _ in range(30):
        password = generate_password(32, avoid_ambiguous=True)["password"]
        for character in "lI1O0o":
            assert character not in password


def test_pool_size_and_entropy_are_consistent():
    """Reported entropy matches length x log2(pool size)."""
    import math
    from backend.services.password_generator import generate_password

    generated = generate_password(20)
    expected = 20 * math.log2(generated["pool_size"])
    assert abs(generated["entropy_bits"] - expected) < 0.2
    assert generated["generator"].lower().count("csprng") + generated["generator"].lower().count("secret") >= 1


def test_length_is_clamped_to_supported_range():
    """Absurd lengths are clamped instead of trusted."""
    from backend.services.password_generator import generate_password, MAX_LENGTH, MIN_LENGTH

    assert len(generate_password(5000)["password"]) == MAX_LENGTH
    assert len(generate_password(1)["password"]) == MIN_LENGTH


def test_refuses_empty_pool():
    """Disabling every class is an explicit error, not a silent weak password."""
    from backend.services.password_generator import generate_password

    with pytest.raises(ValueError):
        generate_password(16, use_uppercase=False, use_lowercase=False,
                          use_digits=False, use_symbols=False)


def test_passphrase_generation():
    """A generated passphrase is strong, spaced correctly and labelled a demo."""
    from backend.services.password_analyzer import analyze_password
    from backend.services.password_generator import generate_passphrase

    generated = generate_passphrase(5)
    phrase = generated["password"]
    assert phrase.count("-") == 4
    assert generated["word_count"] == 5
    assert generated["wordlist_size"] > 5000
    assert generated["entropy_bits"] > 55
    assert "DEMO EXAMPLE" in generated["note"]
    assert analyze_password(phrase)["classification"] == "VERY STRONG"


def test_passphrase_words_come_from_the_local_list():
    """Every word in a generated phrase exists in the bundled list."""
    from backend.services.data_loader import load_passphrase_words
    from backend.services.password_generator import generate_passphrase

    vocabulary = load_passphrase_words()
    for _ in range(20):
        phrase = generate_passphrase(4)["password"]
        for word in phrase.split("-"):
            assert word in vocabulary


def test_batch_generation_uses_presets():
    """The batch helper produces the documented 16/20/24 length presets."""
    from backend.services.password_generator import generate_batch

    batch = generate_batch(3)
    assert [item["length"] for item in batch] == [16, 20, 24]


def test_generated_password_is_never_persisted(tmp_path, monkeypatch):
    """Generation must not write the value anywhere (analytics store only counts)."""
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "gen.db"))
    import importlib
    from backend.services import audit_store
    importlib.reload(audit_store)

    from backend.services.password_generator import generate_password

    generated = generate_password(24)["password"]
    audit_store.record_generation({"generator": "secrets", "length": 24,
                                   "entropy_bits": 120.0, "classes_used": ["lowercase"]})

    database_bytes = (tmp_path / "gen.db").read_bytes()
    assert generated.encode() not in database_bytes

    # Inspect the schema rather than the raw bytes: the table name legitimately
    # contains the word "generated_passwords_meta", but no *column* could hold a
    # value.
    import sqlite3
    connection = sqlite3.connect(tmp_path / "gen.db")
    try:
        columns = [row[1].lower() for row in connection.execute(
            "PRAGMA table_info(generated_passwords_meta)")]
    finally:
        connection.close()
    assert columns == ["meta_id", "generator", "length", "entropy_bits", "class_count", "created_at"]
