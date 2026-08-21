"""Explicit MoneyLog schema migration command.

Usage: python scripts/migrate_moneylog.py --confirm
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import AdSpend, app, db  # noqa: E402
from moneylog_maintenance.migrations import run_all  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm that a verified backup exists and run the migrations.",
    )
    args = parser.parse_args()
    if not args.confirm:
        parser.error("refusing to migrate without --confirm")

    with app.app_context():
        safe_url = db.engine.url.render_as_string(hide_password=True)
        print(f"Migrating explicitly configured database: {safe_url}")
        run_all(db, AdSpend)
    print("MoneyLog migration completed")


if __name__ == "__main__":
    main()
