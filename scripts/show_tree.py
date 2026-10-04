"""
scripts/show_tree.py
--------------------------------------------------------------------------
PURPOSE
    Print the project tree with file sizes and line counts, so the structure
    documented in README.md can be proven against reality (this is the output
    used for the "01-project-folder-structure" figure).

WHY
    A screenshot of `tree` requires the tool to be installed and produces output
    that drifts from the README. This script is deterministic, works everywhere
    Python works, and skips generated directories.

USAGE
    python scripts/show_tree.py
    python scripts/show_tree.py --depth 2
"""

from __future__ import annotations

import argparse
import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent

SKIP_DIRECTORIES = {
    "__pycache__", ".git", ".pytest_cache", ".mypy_cache", ".venv", "venv",
    "node_modules", ".idea", ".vscode", ".ruff_cache",
}
SKIP_SUFFIXES = {".pyc", ".pyo", ".db", ".sqlite3", ".log"}

# Directories that carry the most weight get a one-line purpose note.
NOTES = {
    "backend": "Flask/FastAPI application: routes, models, services",
    "backend/services": "the 11 analysis services (the graded core)",
    "backend/routes": "REST blueprints",
    "backend/utils": "logging + redaction helpers",
    "frontend": "static SPA used by Flask and by GitHub Pages",
    "frontend/js": "browser engine, charts, generator/hash UI, app wiring",
    "frontend/js/data": "GENERATED browser data files (scripts/build_frontend_data.py)",
    "data": "read-only reference data: wordlists, patterns, demo breach corpus",
    "scripts": "build, fixture and screenshot tooling",
    "tests": "pytest suite + JavaScript parity harness",
    "tests/js": "Node harness that proves JS/Python engine parity",
    "docs": "scoring, privacy, testing, deployment and portfolio documentation",
    "reports": "project report and test report",
    "screenshots": "captured proof-of-work images",
}


def count_lines(path: pathlib.Path) -> int:
    try:
        return sum(1 for _ in path.open("r", encoding="utf-8", errors="ignore"))
    except OSError:
        return 0


def render(directory: pathlib.Path, depth: int, max_depth: int, prefix: str = "") -> None:
    try:
        entries = sorted(directory.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
    except OSError:
        return
    entries = [e for e in entries
               if e.name not in SKIP_DIRECTORIES and e.suffix not in SKIP_SUFFIXES]

    for index, entry in enumerate(entries):
        last = index == len(entries) - 1
        connector = "└── " if last else "├── "
        relative = entry.relative_to(PROJECT_ROOT).as_posix()
        note = NOTES.get(relative)
        if entry.is_dir():
            print(f"{prefix}{connector}{entry.name}/" + (f"   # {note}" if note else ""))
            if depth < max_depth:
                render(entry, depth + 1, max_depth, prefix + ("    " if last else "│   "))
        else:
            size = entry.stat().st_size
            lines = count_lines(entry) if entry.suffix in {
                ".py", ".js", ".html", ".css", ".md", ".txt", ".yml", ".yaml", ".ini"} else None
            detail = f"{size:>7,} B"
            if lines:
                detail += f"  {lines:>5,} lines"
            print(f"{prefix}{connector}{entry.name:<38} {detail}"
                  + (f"   # {note}" if note else ""))


def main() -> int:
    parser = argparse.ArgumentParser(description="Print the documented project tree.")
    parser.add_argument("--depth", type=int, default=3, help="maximum directory depth")
    args = parser.parse_args()

    print(f"{PROJECT_ROOT.name}/")
    render(PROJECT_ROOT, 1, args.depth)

    total_files = sum(1 for p in PROJECT_ROOT.rglob("*")
                      if p.is_file() and p.suffix not in SKIP_SUFFIXES
                      and not any(part in SKIP_DIRECTORIES for part in p.parts))
    total_lines = sum(count_lines(p) for p in PROJECT_ROOT.rglob("*.py")) \
        + sum(count_lines(p) for p in PROJECT_ROOT.rglob("*.js"))
    print()
    print(f"{total_files} files tracked  |  {total_lines:,} lines of Python + JavaScript")
    print("Note: frontend/js/data/*.js are generated -- run scripts/build_frontend_data.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
