"""Verify a MoneyLog SQLite backup without restoring over production."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from backup_sqlite import connect_read_only, sha256_file


def table_counts(connection: sqlite3.Connection) -> dict[str, int]:
    tables = [
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]
    return {
        table: connection.execute(
            f'SELECT count(*) FROM "{table.replace(chr(34), chr(34) * 2)}"'
        ).fetchone()[0]
        for table in tables
    }


def verify(source: Path, backup: Path) -> dict:
    if not backup.exists() or backup.stat().st_size == 0:
        raise FileNotFoundError("backup is missing or empty")
    source_connection = connect_read_only(source)
    backup_connection = connect_read_only(backup)
    try:
        source_integrity = source_connection.execute("PRAGMA integrity_check").fetchone()[0]
        backup_integrity = backup_connection.execute("PRAGMA integrity_check").fetchone()[0]
        source_counts = table_counts(source_connection)
        backup_counts = table_counts(backup_connection)
    finally:
        source_connection.close()
        backup_connection.close()

    passed = (
        source_integrity == "ok"
        and backup_integrity == "ok"
        and source_counts == backup_counts
    )
    return {
        "status": "PASS" if passed else "FAIL",
        "backup_path": str(backup.resolve()),
        "backup_size_bytes": backup.stat().st_size,
        "backup_sha256": sha256_file(backup),
        "source_integrity_check": source_integrity,
        "backup_integrity_check": backup_integrity,
        "source_table_counts": source_counts,
        "backup_table_counts": backup_counts,
        "table_counts_match": source_counts == backup_counts,
        "restore_read_test": "backup opened independently with mode=ro and query_only=ON",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = verify(args.source, args.backup)
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered)
    raise SystemExit(0 if report["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
