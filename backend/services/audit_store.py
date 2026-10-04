"""
backend/services/audit_store.py
--------------------------------------------------------------------------
PURPOSE
    Optional analytics. Stores ONLY non-secret aggregate metadata about each
    analysis so the dashboard has something to chart.

WHAT IS STORED
    analysis_id, score, classification, password_length,
    unique_character_ratio, character_type_count, weakness_count,
    pattern_count, top_weakness, analyzed_at, duration_ms

WHAT IS NEVER STORED
    * the password
    * any reversible or partially masked form of it
    * a hash of it (see the design note below)
    * the personal context the user optionally supplied

WHY WE DO NOT STORE A HASH
    Storing `sha1(password)` "for analytics" is still a secret-derived value:
    unsalted SHA-1/MD5 over a password is trivially reversible with rainbow
    tables. A password hash may also collide with a real credential store
    hash, which turns an analytics table into a credential database by
    accident. This table only needs length, score and category counts -- so
    that is all it keeps.

WHY THE DB PATH IS CONFIGURABLE
    `ANALYTICS_ENABLED=0` (or ANON_HISTORY_ENABLED=0 in the legacy name)
    turns storage off entirely; the analyzer still works. For the GitHub Pages
    build there is no backend at all, so nothing can be stored by design.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import os
import sqlite3
import statistics
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
DEFAULT_DB_PATH = os.environ.get(
    "DATABASE_PATH",
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "analytics.db"),
)

# Accept both spellings: ANALYTICS_ENABLED (docs) and ANON_HISTORY_ENABLED (legacy).
ANALYTICS_ENABLED = os.environ.get("ANALYTICS_ENABLED", os.environ.get("ANON_HISTORY_ENABLED", "1")) not in ("0", "false", "False")


# -----------------------------------------------------------------------------
# Schema
# -----------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
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

CREATE TABLE IF NOT EXISTS findings (
    finding_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id   TEXT NOT NULL,
    finding_type  TEXT NOT NULL,
    severity      TEXT NOT NULL,
    description   TEXT NOT NULL,
    FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS generated_passwords_meta (
    meta_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    generator     TEXT NOT NULL,
    length        INTEGER NOT NULL,
    entropy_bits  REAL NOT NULL,
    class_count   INTEGER NOT NULL,
    created_at    TEXT NOT NULL
);
-- NOTE: there is deliberately NO column for a password anywhere in this file.
-- The database schema is itself one of the project's security proofs.
"""

CLASSIFICATION_ORDER = ["VERY WEAK", "WEAK", "MODERATE", "STRONG", "VERY STRONG"]


# -----------------------------------------------------------------------------
# Connection handling
# -----------------------------------------------------------------------------
@contextmanager
def _connect(db_path: Optional[str] = None) -> Iterator[sqlite3.Connection]:
    path = db_path or DEFAULT_DB_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_db(db_path: Optional[str] = None) -> None:
    """Create tables if they do not exist."""
    with _connect(db_path) as connection:
        connection.executescript(SCHEMA)


# -----------------------------------------------------------------------------
# Writing
# -----------------------------------------------------------------------------
def record_analysis(analysis_result: Dict, db_path: Optional[str] = None) -> Optional[str]:
    """
    Persist ONLY safe aggregate metadata. Returns the analysis_id, or None when
    analytics are disabled.

    The caller passes the finished analysis dict. Note what this function reads
    from it: metrics and categories -- never `password`.
    """
    if not ANALYTICS_ENABLED:
        return None

    metrics = analysis_result.get("metrics", {})
    findings = analysis_result.get("findings", [])
    analysis_id = analysis_result.get("analysis_id") or f"an_{int(time.time() * 1000)}"

    top_weakness = findings[0]["type"] if findings else None

    init_db(db_path)
    with _connect(db_path) as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO analyses
            (analysis_id, score, classification, password_length, unique_character_ratio,
             character_type_count, weakness_count, pattern_count, top_weakness,
             duration_ms, analyzed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                analysis_id,
                int(analysis_result.get("score", 0)),
                analysis_result.get("classification", "VERY WEAK"),
                int(metrics.get("length", 0)),
                float(metrics.get("unique_character_ratio", 0.0)),
                int(metrics.get("character_type_count", 0)),
                len(findings),
                int(metrics.get("pattern_count", 0)),
                top_weakness,
                float(analysis_result.get("duration_ms", 0.0)),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        for finding in findings:
            connection.execute(
                """
                INSERT INTO findings (analysis_id, finding_type, severity, description)
                VALUES (?, ?, ?, ?)
                """,
                (analysis_id, finding["type"], finding["severity"], finding["title"]),
            )

    return analysis_id


def record_generation(meta: Dict, db_path: Optional[str] = None) -> None:
    """Store only the *properties* of a generated password -- never the value."""
    if not ANALYTICS_ENABLED:
        return
    init_db(db_path)
    with _connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO generated_passwords_meta (generator, length, entropy_bits, class_count, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                meta.get("generator", "unknown"),
                int(meta.get("length", 0)),
                float(meta.get("entropy_bits", 0.0)),
                len(meta.get("classes_used", [])),
                datetime.now(timezone.utc).isoformat(),
            ),
        )


# -----------------------------------------------------------------------------
# Reading / dashboard aggregates
# -----------------------------------------------------------------------------
def _empty_stats() -> Dict:
    return {
        "total_analyses": 0,
        "very_weak": 0, "weak": 0, "moderate": 0, "strong": 0, "very_strong": 0,
        "average_score": 0.0,
        "median_score": 0.0,
        "distribution": {label: 0 for label in CLASSIFICATION_ORDER},
        "score_histogram": [],
        "length_distribution": [],
        "weakness_frequency": [],
        "pattern_frequency": [],
        "least_secure_weekday": None,
        "generated_count": 0,
        "privacy_note": "Aggregate metadata only. No password, no password hash, no personal data.",
    }


def get_dashboard_stats(db_path: Optional[str] = None) -> Dict:
    """
    Aggregate everything the dashboard needs.

    The front-end receives numbers and labels only -- it is structurally
    impossible for it to render a password, because none is ever stored.
    """
    stats = _empty_stats()
    if not ANALYTICS_ENABLED:
        return stats

    init_db(db_path)
    with _connect(db_path) as connection:
        rows = connection.execute(
            "SELECT score, classification, password_length, analyzed_at FROM analyses"
        ).fetchall()
        finding_rows = connection.execute(
            "SELECT finding_type, severity, COUNT(*) AS n FROM findings GROUP BY finding_type, severity"
        ).fetchall()
        generated = connection.execute(
            "SELECT COUNT(*) AS n FROM generated_passwords_meta"
        ).fetchone()

    if not rows:
        stats["generated_count"] = generated["n"] if generated else 0
        return stats

    scores = [row["score"] for row in rows]
    lengths = [row["password_length"] for row in rows]

    stats["total_analyses"] = len(rows)
    stats["average_score"] = round(statistics.fmean(scores), 1)
    stats["median_score"] = round(statistics.median(scores), 1)
    stats["generated_count"] = generated["n"] if generated else 0

    counts = {label: 0 for label in CLASSIFICATION_ORDER}
    for row in rows:
        label = row["classification"] if row["classification"] in counts else "VERY WEAK"
        counts[label] += 1
    stats["distribution"] = counts
    stats["very_weak"] = counts["VERY WEAK"]
    stats["weak"] = counts["WEAK"]
    stats["moderate"] = counts["MODERATE"]
    stats["strong"] = counts["STRONG"]
    stats["very_strong"] = counts["VERY STRONG"]

    # Score histogram in 10-point buckets (0-9, 10-19, ... 90-100)
    buckets = {f"{start}-{start + 9}": 0 for start in range(0, 100, 10)}
    for score in scores:
        bucket_index = 90 if score >= 90 else (score // 10) * 10
        buckets[f"{bucket_index}-{bucket_index + 9}"] += 1
    stats["score_histogram"] = [{"bucket": k, "count": v} for k, v in buckets.items()]

    # Length distribution
    length_buckets = {"1-7": 0, "8-11": 0, "12-15": 0, "16-19": 0, "20+": 0}
    for length in lengths:
        if length <= 7:
            length_buckets["1-7"] += 1
        elif length <= 11:
            length_buckets["8-11"] += 1
        elif length <= 15:
            length_buckets["12-15"] += 1
        elif length <= 19:
            length_buckets["16-19"] += 1
        else:
            length_buckets["20+"] += 1
    stats["length_distribution"] = [{"bucket": k, "count": v} for k, v in length_buckets.items()]

    # Weakness / pattern frequency
    frequency: Dict[str, int] = {}
    for row in finding_rows:
        frequency[row["finding_type"]] = frequency.get(row["finding_type"], 0) + row["n"]
    # Separate the *weaknesses* (things that lost points) from the *structure*
    # finding (a recognised multi-word shape, which is not itself a weakness).
    # Keeping them apart stops "passphrase_structure" from looking like the only
    # problem in the dashboard's weakness chart.
    pattern_frequency = sorted(
        ({"type": k, "count": v} for k, v in frequency.items()), key=lambda item: -item["count"]
    )
    stats["pattern_frequency"] = pattern_frequency[:8]
    stats["weakness_frequency"] = [
        item for item in pattern_frequency if item["type"] != "passphrase_structure"
    ][:8]

    # Which weekday produced the weakest average score? (fun, safe aggregate)
    per_weekday: Dict[str, List[int]] = {}
    for row in rows:
        try:
            weekday = datetime.fromisoformat(row["analyzed_at"]).strftime("%A")
        except (TypeError, ValueError):
            continue
        per_weekday.setdefault(weekday, []).append(row["score"])
    if per_weekday:
        weakest = min(per_weekday.items(), key=lambda item: statistics.fmean(item[1]))
        stats["least_secure_weekday"] = {
            "weekday": weakest[0],
            "average_score": round(statistics.fmean(weakest[1]), 1),
        }

    return stats


def get_recent_analyses(limit: int = 20, db_path: Optional[str] = None) -> List[Dict]:
    """Return the most recent analyses WITHOUT any secret material."""
    if not ANALYTICS_ENABLED:
        return []
    init_db(db_path)
    with _connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT analysis_id, score, classification, password_length, weakness_count,
                   top_weakness, analyzed_at
            FROM analyses ORDER BY analyzed_at DESC LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
    return [dict(row) for row in rows]


def reset_analytics(db_path: Optional[str] = None) -> None:
    """Delete all analytics rows (used by tests and by the demo 'reset' button)."""
    if not ANALYTICS_ENABLED:
        return
    init_db(db_path)
    with _connect(db_path) as connection:
        connection.execute("DELETE FROM findings")
        connection.execute("DELETE FROM analyses")
        connection.execute("DELETE FROM generated_passwords_meta")
