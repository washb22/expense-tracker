"""Fail-closed configuration for the isolated Finance SQLite database."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import unquote, urlparse


DEFAULT_FINANCE_PATH = "/var/data/render/sbrocor_finance.db"


class FinanceConfigurationError(RuntimeError):
    pass


def _sqlite_path_from_url(database_url: str | None) -> Path | None:
    if not database_url or not database_url.startswith("sqlite:"):
        return None
    parsed = urlparse(database_url)
    raw_path = unquote(parsed.path)
    if os.name == "nt" and raw_path.startswith("/") and len(raw_path) > 2 and raw_path[2] == ":":
        raw_path = raw_path[1:]
    return Path(raw_path).resolve()


def get_finance_database_path() -> Path:
    path = Path(os.environ.get("SBROCOR_FINANCE_DB_PATH", DEFAULT_FINANCE_PATH)).expanduser().resolve()
    if path.name.casefold() == "tracker.db":
        raise FinanceConfigurationError("Finance database must never be tracker.db")

    legacy_path = _sqlite_path_from_url(os.environ.get("DATABASE_URL"))
    if legacy_path is not None and path == legacy_path:
        raise FinanceConfigurationError("Finance and MoneyLog database paths must be different")

    known_legacy = Path("/var/data/render/tracker.db").resolve()
    if path == known_legacy:
        raise FinanceConfigurationError("Finance database path resolves to the production MoneyLog database")
    return path


def get_hmac_settings() -> tuple[str, bytes, int]:
    key_id = os.environ.get("SBROCOR_FINANCE_HMAC_KEY_ID", "sbrocor")
    secret = os.environ.get("SBROCOR_FINANCE_HMAC_SECRET", "")
    if len(secret.encode("utf-8")) < 32:
        raise FinanceConfigurationError("SBROCOR_FINANCE_HMAC_SECRET must be at least 32 bytes")
    try:
        max_skew = int(os.environ.get("SBROCOR_FINANCE_HMAC_MAX_SKEW_SECONDS", "300"))
    except ValueError as exc:
        raise FinanceConfigurationError("HMAC max skew must be an integer") from exc
    if max_skew < 1 or max_skew > 900:
        raise FinanceConfigurationError("HMAC max skew must be between 1 and 900 seconds")
    return key_id, secret.encode("utf-8"), max_skew
