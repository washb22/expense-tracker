"""Explicitly initialize a new isolated Finance DB with confirmation guards."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sbrocor_finance.config import get_finance_database_path
from sbrocor_finance.database import initialize_database


CONFIRMATION = "CREATE SBROCOR FINANCE DB"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        parser.error(f"--confirm '{CONFIRMATION}' is required")
    path = get_finance_database_path()
    if path.exists():
        print(f"Refusing to initialize existing Finance DB: {path}", file=sys.stderr)
        return 2
    print(initialize_database(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
