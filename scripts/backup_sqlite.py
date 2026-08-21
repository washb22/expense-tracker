"""Guarded SQLite Online Backup API command for MoneyLog production."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


CONFIRMATION = "CREATE MONEYLOG SQLITE BACKUP"


def connect_read_only(path: Path) -> sqlite3.Connection:
    resolved = path.resolve(strict=True)
    connection = sqlite3.connect(f"file:{resolved.as_posix()}?mode=ro", uri=True)
    connection.execute("PRAGMA query_only=ON")
    return connection


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_backup(source: Path, destination: Path) -> dict:
    source_resolved = source.resolve(strict=True)
    destination_resolved = destination.resolve(strict=False)
    if source_resolved == destination_resolved:
        raise ValueError("backup destination must differ from source")
    if destination_resolved.exists():
        raise FileExistsError(f"refusing to overwrite existing backup: {destination}")
    destination_resolved.parent.mkdir(parents=True, exist_ok=True)

    source_connection = connect_read_only(source_resolved)
    destination_connection = sqlite3.connect(destination_resolved)
    try:
        source_connection.backup(destination_connection)
        destination_connection.commit()
    except Exception:
        destination_connection.close()
        source_connection.close()
        destination_resolved.unlink(missing_ok=True)
        raise
    else:
        destination_connection.close()
        source_connection.close()

    try:
        os.chmod(destination_resolved, 0o600)
    except OSError:
        pass
    return {
        "status": "CREATED",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": str(source_resolved),
        "destination": str(destination_resolved),
        "size_bytes": destination_resolved.stat().st_size,
        "sha256": sha256_file(destination_resolved),
        "method": "sqlite3 online backup API; source mode=ro; query_only=ON",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirmation")
    args = parser.parse_args()

    if not args.execute:
        print(json.dumps({
            "status": "BACKUP_NOT_CREATED",
            "source": str(args.source),
            "destination": str(args.destination),
            "required_confirmation": CONFIRMATION,
        }, indent=2))
        return
    if args.confirmation != CONFIRMATION:
        raise SystemExit(f"Refusing backup. Pass --confirmation '{CONFIRMATION}'")
    print(json.dumps(create_backup(args.source, args.destination), indent=2))


if __name__ == "__main__":
    main()
