"""One-time, fail-closed importer for an empty Finance workspace."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sbrocor_finance.database import finance_connection
from sbrocor_finance.repository import FinanceRepository
from sbrocor_finance.service import FinanceService


CONFIRMATION = "IMPORT EMPTY SBROCOR FINANCE WORKSPACE"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--workspace-id", required=True, type=int)
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        parser.error(f"--confirm '{CONFIRMATION}' is required")
    if not args.manifest.is_file():
        parser.error("manifest file does not exist")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    with finance_connection() as connection:
        result = FinanceService(FinanceRepository(connection)).import_initial_manifest(
            args.workspace_id, manifest
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Import aborted: {exc}", file=sys.stderr)
        raise SystemExit(2)
