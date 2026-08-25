"""Fail-closed one-time cleanup for the approved legacy Naver spend rows.

Dry-run is the default. This script must never be pointed at tracker.db or a
copy of the Finance database; the CLI accepts only the production absolute
path and requires an exact confirmation phrase before deleting anything.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path


TARGET_DB = Path("/var/data/render/sbrocor_finance.db")
EXPECTED_WORKSPACE_ID = 1
EXPECTED_CUSTOMER_ID = "999569"
EXPECTED_COUNT = 24
EXPECTED_TOTAL = 434_846
EXPECTED_MIN_DATE = "2026-08-01"
EXPECTED_MAX_DATE = "2026-08-24"
CONFIRMATION = "DELETE LEGACY NAVER 999569"


class CleanupRefused(RuntimeError):
    pass


def _after_delete_hook() -> None:
    """Fault-injection seam for rollback tests."""


def _rows(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    return connection.execute(
        """SELECT ms.id,ms.date,ms.brand_id,ms.amount_krw,ms.external_key,
                  ms.ad_account_connection_id,ac.account_id customer_id,
                  ac.account_name,ac.workspace_id
           FROM marketing_spend ms
           JOIN ad_account_connection ac
             ON ac.id=ms.ad_account_connection_id AND ac.workspace_id=ms.workspace_id
           WHERE ms.workspace_id=? AND ms.source='naver_api'
             AND ac.platform='naver' AND ac.account_id=?
           ORDER BY ms.date,ms.id""",
        (EXPECTED_WORKSPACE_ID, EXPECTED_CUSTOMER_ID),
    ).fetchall()


def _summary(rows: list[sqlite3.Row]) -> dict:
    return {
        "workspace_id": EXPECTED_WORKSPACE_ID,
        "customer_id": EXPECTED_CUSTOMER_ID,
        "row_count": len(rows),
        "total_amount": sum(int(row["amount_krw"] or 0) for row in rows),
        "min_date": min((row["date"] for row in rows), default=None),
        "max_date": max((row["date"] for row in rows), default=None),
        "items": [dict(row) for row in rows],
    }


def _validate(summary: dict) -> None:
    expected = {
        "workspace_id": EXPECTED_WORKSPACE_ID,
        "customer_id": EXPECTED_CUSTOMER_ID,
        "row_count": EXPECTED_COUNT,
        "total_amount": EXPECTED_TOTAL,
        "min_date": EXPECTED_MIN_DATE,
        "max_date": EXPECTED_MAX_DATE,
    }
    mismatches = {key: {"expected": value, "actual": summary.get(key)} for key, value in expected.items() if summary.get(key) != value}
    if mismatches:
        raise CleanupRefused(f"REFUSE: legacy Naver expected state mismatch: {json.dumps(mismatches, ensure_ascii=False, sort_keys=True)}")


def cleanup(
    database_path: Path,
    *,
    apply: bool = False,
    confirmation: str | None = None,
    expected_target: Path = TARGET_DB,
) -> dict:
    path = database_path.resolve()
    target = expected_target.resolve()
    if path.name.casefold() == "tracker.db":
        raise CleanupRefused("REFUSE: tracker.db is never a Finance cleanup target")
    if path != target:
        raise CleanupRefused(f"REFUSE: target must be exactly {target}")
    if not path.is_file():
        raise CleanupRefused("REFUSE: target database does not exist")
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    try:
        summary = _summary(_rows(connection))
        _validate(summary)
        result = {"database_path": str(path), "dry_run": not apply, **summary}
        if not apply:
            return result
        if confirmation != CONFIRMATION:
            raise CleanupRefused(f'REFUSE: --confirm must exactly equal "{CONFIRMATION}"')
        try:
            connection.execute("BEGIN IMMEDIATE")
            locked_summary = _summary(_rows(connection))
            _validate(locked_summary)
            ids = [int(row["id"]) for row in locked_summary["items"]]
            placeholders = ",".join("?" for _ in ids)
            cursor = connection.execute(
                f"DELETE FROM marketing_spend WHERE workspace_id=? AND source='naver_api' AND id IN ({placeholders}) "
                "AND ad_account_connection_id IN (SELECT id FROM ad_account_connection WHERE workspace_id=? AND platform='naver' AND account_id=?)",
                [EXPECTED_WORKSPACE_ID, *ids, EXPECTED_WORKSPACE_ID, EXPECTED_CUSTOMER_ID],
            )
            if cursor.rowcount != EXPECTED_COUNT or _rows(connection):
                raise CleanupRefused("REFUSE: cleanup post-check failed")
            _after_delete_hook()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        return {**result, "dry_run": False, "deleted_rows": EXPECTED_COUNT, "post_count": 0}
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("database", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm")
    args = parser.parse_args()
    try:
        print(json.dumps(cleanup(args.database, apply=args.apply, confirmation=args.confirm), ensure_ascii=False, indent=2))
        return 0
    except CleanupRefused as error:
        print(str(error))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
