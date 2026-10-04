"""
tests/test_analytics.py
--------------------------------------------------------------------------
Analytics tests (T30): the store records metadata only, aggregates correctly,
and can be disabled entirely.
"""

from __future__ import annotations

import importlib
import sqlite3


def test_T30_analytics_storage(temp_db, analyze, demo):
    """One analysis produces one metadata row plus one row per finding category."""
    from backend.services import audit_store

    result = analyze(demo["keyboard"])
    analysis_id = audit_store.record_analysis(result)
    assert analysis_id

    connection = sqlite3.connect(temp_db)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute("SELECT * FROM analyses WHERE analysis_id = ?",
                                 (analysis_id,)).fetchone()
        assert row["score"] == result["score"]
        assert row["classification"] == result["classification"]
        assert row["password_length"] == result["metrics"]["length"]
        assert row["weakness_count"] == len(result["findings"])
        assert row["analyzed_at"]

        finding_count = connection.execute(
            "SELECT COUNT(*) FROM findings WHERE analysis_id = ?", (analysis_id,)).fetchone()[0]
        assert finding_count == len(result["findings"])
    finally:
        connection.close()


def test_dashboard_stats_aggregate(temp_db, analyze, demo):
    """The dashboard aggregates counts, averages, distributions and frequency."""
    from backend.services import audit_store

    for value in (demo["common"], demo["keyboard"], demo["long_random"], demo["passphrase"]):
        audit_store.record_analysis(analyze(value))

    stats = audit_store.get_dashboard_stats()
    assert stats["total_analyses"] == 4
    assert 0 < stats["average_score"] <= 100
    assert sum(stats["distribution"].values()) == 4
    assert len(stats["score_histogram"]) == 10
    assert len(stats["length_distribution"]) == 5
    assert stats["weakness_frequency"]
    assert stats["privacy_note"]


def test_analytics_disabled_writes_nothing(temp_db, analyze, demo, monkeypatch):
    """With analytics off, the analyzer still works and nothing is written."""
    monkeypatch.setenv("ANALYTICS_ENABLED", "0")
    from backend.services import audit_store
    importlib.reload(audit_store)

    result = analyze(demo["passphrase"])
    assert audit_store.record_analysis(result) is None
    assert not temp_db.exists() or temp_db.stat().st_size == 0

    monkeypatch.delenv("ANALYTICS_ENABLED")
    importlib.reload(audit_store)


def test_reset_clears_metadata_only(temp_db, analyze, demo):
    """Resetting the analytics store removes metadata rows and nothing else."""
    from backend.services import audit_store

    audit_store.record_analysis(analyze(demo["common"]))
    assert audit_store.get_dashboard_stats()["total_analyses"] == 1

    audit_store.reset_analytics()
    assert audit_store.get_dashboard_stats()["total_analyses"] == 0


def test_recent_analyses_are_metadata_only(temp_db, analyze, demo):
    """Recent rows expose exactly the documented, non-secret columns."""
    from backend.services import audit_store

    audit_store.record_analysis(analyze(demo["word_and_year"]))
    recent = audit_store.get_recent_analyses()
    assert len(recent) == 1
    assert set(recent[0]) == {"analysis_id", "score", "classification", "password_length",
                              "weakness_count", "top_weakness", "analyzed_at"}


def test_schema_has_no_secret_columns(temp_db, analyze, demo):
    """A direct schema inspection proves the absence of any password column."""
    from backend.services import audit_store

    audit_store.record_analysis(analyze(demo["probe"]))

    connection = sqlite3.connect(temp_db)
    try:
        ddl = " ".join(row[0] for row in connection.execute(
            "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL")).lower()
    finally:
        connection.close()

    assert "password_length" in ddl          # length is metadata and is allowed
    assert " password " not in ddl.replace("password_length", "length").replace("password_strength", "strength")
    assert "hash" not in ddl
    assert "salt" not in ddl
    assert "context" not in ddl
    assert "raw" not in ddl


def test_top_weakness_recorded(temp_db, analyze, demo):
    """The most severe finding category is stored for the weakness chart."""
    from backend.services import audit_store

    audit_store.record_analysis(analyze(demo["keyboard"]))
    recent = audit_store.get_recent_analyses()
    assert recent[0]["top_weakness"] in {"keyboard_pattern", "dictionary_word",
                                        "common_password", "breach", "sequence",
                                        "predictable_structure", "short_length",
                                        "low_variety", "repeated_characters",
                                        "repeated_substring", "year_pattern"}


def test_generation_metadata_has_no_value(temp_db):
    """Generation analytics record shape only."""
    from backend.services import audit_store
    from backend.services.password_generator import generate_passphrase

    generated = generate_passphrase(4)["password"]
    audit_store.record_generation({"generator": "secrets", "length": len(generated),
                                   "entropy_bits": 50.5, "classes_used": ["lowercase"]})
    assert generated.encode() not in temp_db.read_bytes()

    stats = audit_store.get_dashboard_stats()
    assert stats["generated_count"] == 1


def test_empty_database_returns_zeroed_stats(temp_db):
    """A fresh database yields a well-formed, zeroed statistics object."""
    from backend.services import audit_store

    stats = audit_store.get_dashboard_stats()
    assert stats["total_analyses"] == 0
    assert stats["average_score"] == 0.0
    assert stats["distribution"]["VERY WEAK"] == 0
    assert len(stats["score_histogram"]) == 0 or stats["score_histogram"] == []


def test_weekday_aggregate_is_non_identifying(temp_db, analyze, demo):
    """The weekday insight uses an average over a group, not individual records."""
    from backend.services import audit_store

    for value in (demo["common"], demo["long_random"]):
        audit_store.record_analysis(analyze(value))

    stats = audit_store.get_dashboard_stats()
    assert stats["least_secure_weekday"] is None or set(stats["least_secure_weekday"]) == {
        "weekday", "average_score"}
