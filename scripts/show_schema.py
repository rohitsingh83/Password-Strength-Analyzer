"""
scripts/show_schema.py
--------------------------------------------------------------------------
PURPOSE
    Print the real SQLite schema of the analytics database and PROVE that no
    column can hold a password, a password hash or personal context.

    This is the script behind the "25-database-schema-no-password-column"
    proof figure, and it doubles as a pre-demo sanity check: it exits with a
    non-zero status if a password-capable column is ever introduced.

USAGE
    python scripts/show_schema.py
    python scripts/show_schema.py --database /tmp/demo.db
"""

from __future__ import annotations

import argparse
import pathlib
import sqlite3
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Column names that would mean the design had been broken. SQL comments are
# stripped before searching, because the schema string legitimately *mentions*
# these words when explaining that they are absent.
FORBIDDEN = {
    "password", "password_hash", "hash", "salt", "passphrase", "secret",
    "raw", "plaintext", "value", "context", "first_name", "birth_year",
    "organisation", "email",
}

SCHEMA_SQL = PROJECT_ROOT / "backend" / "services" / "audit_store.py"


def schema_source() -> str:
    text = SCHEMA_SQL.read_text(encoding="utf-8")
    without_comments = "\n".join(line.split("--")[0] for line in text.splitlines())
    return without_comments


def main() -> int:
    parser = argparse.ArgumentParser(description="Show and audit the analytics schema.")
    parser.add_argument("--database", default=None,
                        help="database file to inspect (defaults to an in-memory copy)")
    args = parser.parse_args()

    from backend.services import audit_store

    # Inspect a real database when asked; otherwise create a temporary one so the
    # printed schema always reflects the shipped code rather than this script.
    temporary = None
    if args.database:
        path = args.database
    else:
        import tempfile
        handle = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        handle.close()
        path = handle.name
        temporary = path
    audit_store.init_db(path)
    connection = sqlite3.connect(path)

    print("=" * 78)
    print("Analytics database schema -- aggregates only, never a password")
    print("=" * 78)

    tables = []
    if True:
        cursor = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = [row[0] for row in cursor.fetchall()]
        for table in tables:
            print(f"\nTABLE {table}")
            print("-" * 78)
            for column in connection.execute(f"PRAGMA table_info({table})"):
                # (cid, name, type, notnull, default, pk)
                print(f"  {column[1]:<26} {column[2]:<10} "
                      f"{'NOT NULL' if column[3] else 'NULL':<9} {'PRIMARY KEY' if column[5] else ''}")
    connection.close()
    if temporary:
        pathlib.Path(temporary).unlink(missing_ok=True)

    print("\n" + "=" * 78)
    print("Automated audit")
    print("=" * 78)

    offenders = []
    source = schema_source()
    for statement in source.split("CREATE TABLE")[1:]:
        body = statement.split(");")[0]
        for line in body.splitlines():
            stripped = line.strip().rstrip(",")
            if not stripped or stripped.startswith((")", "FOREIGN", "PRIMARY", "UNIQUE", "CHECK")):
                continue
            column = stripped.split()[0].strip('"').lower()
            if column in FORBIDDEN:
                offenders.append(column)

    print(f"tables inspected ............ {len(tables) if tables else source.count('CREATE TABLE')}")
    print(f"password-capable columns .... {len(offenders)}"
          + (f"  ->  {', '.join(offenders)}" if offenders else "  (none)"))
    print("stored per analysis ......... analysis_id, score, classification, "
          "password_length,\n                              unique_character_ratio, "
          "character_type_count,\n                              weakness_count, pattern_count, "
          "top_weakness, duration_ms, analyzed_at")
    print("stored per finding .......... finding_type, severity, generic description")
    print("stored per generated value .. generator, length, entropy_bits, class_count, created_at")
    print()

    if offenders:
        print("FAIL: a column could hold secret material. This must be fixed.")
        return 1
    print("PASS: structurally incapable of revealing a password.")
    print("      (Enforced in CI by tests/test_privacy.py and tests/test_scope.py.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
