"""SQLite connection and schema management for SBROCOR Finance only."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .config import get_finance_database_path


SCHEMA_VERSION = 2

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS workspace (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS finance_transaction (
    id TEXT PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    date TEXT NOT NULL,
    merchant TEXT NOT NULL,
    amount INTEGER NOT NULL,
    category TEXT NOT NULL DEFAULT '미분류'
);
CREATE TABLE IF NOT EXISTS brand (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, name)
);
CREATE TABLE IF NOT EXISTS rule (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    keyword TEXT NOT NULL,
    category TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS product (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    sku TEXT,
    cost_price INTEGER NOT NULL,
    category TEXT,
    brand_id INTEGER REFERENCES brand(id) ON DELETE SET NULL,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS platform (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    commission_rate REAL NOT NULL,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS sale (
    id TEXT PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    date TEXT NOT NULL,
    product_id INTEGER NOT NULL REFERENCES product(id) ON DELETE RESTRICT,
    platform_id INTEGER NOT NULL REFERENCES platform(id) ON DELETE RESTRICT,
    selling_price INTEGER NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    total_selling_amount INTEGER NOT NULL,
    total_cost_amount INTEGER NOT NULL,
    commission_amount INTEGER NOT NULL,
    net_profit INTEGER NOT NULL,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS workspace_settings (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL UNIQUE REFERENCES workspace(id) ON DELETE RESTRICT,
    meta_ad_account_id TEXT,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS ad_spend (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    date TEXT NOT NULL,
    platform TEXT NOT NULL DEFAULT 'meta',
    campaign_id TEXT,
    campaign_name TEXT,
    adset_id TEXT,
    adset_name TEXT,
    ad_id TEXT,
    ad_name TEXT,
    spend REAL NOT NULL DEFAULT 0,
    impressions INTEGER NOT NULL DEFAULT 0,
    clicks INTEGER NOT NULL DEFAULT 0,
    ctr REAL NOT NULL DEFAULT 0,
    cpc REAL NOT NULL DEFAULT 0,
    cpm REAL NOT NULL DEFAULT 0,
    conversions INTEGER NOT NULL DEFAULT 0,
    conversion_value REAL NOT NULL DEFAULT 0,
    roas REAL NOT NULL DEFAULT 0,
    created_at TEXT,
    UNIQUE(workspace_id, date, platform, ad_id)
);
CREATE TABLE IF NOT EXISTS marketing_allocation (
    id TEXT PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    transaction_id TEXT NOT NULL REFERENCES finance_transaction(id) ON DELETE CASCADE,
    brand_id INTEGER REFERENCES brand(id) ON DELETE RESTRICT,
    product_id INTEGER REFERENCES product(id) ON DELETE RESTRICT,
    channel TEXT NOT NULL,
    amount INTEGER NOT NULL CHECK(amount > 0),
    memo TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS auth_nonce (
    key_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    seen_at INTEGER NOT NULL,
    PRIMARY KEY(key_id, nonce)
);
CREATE INDEX IF NOT EXISTS ix_transaction_workspace_date ON finance_transaction(workspace_id, date);
CREATE INDEX IF NOT EXISTS ix_sale_workspace_date ON sale(workspace_id, date);
CREATE INDEX IF NOT EXISTS ix_ad_spend_workspace_date ON ad_spend(workspace_id, date);
CREATE INDEX IF NOT EXISTS ix_brand_workspace_active ON brand(workspace_id, active, name);
CREATE INDEX IF NOT EXISTS ix_allocation_workspace_transaction ON marketing_allocation(workspace_id, transaction_id);
CREATE INDEX IF NOT EXISTS ix_allocation_workspace_brand ON marketing_allocation(workspace_id, brand_id);
CREATE INDEX IF NOT EXISTS ix_allocation_workspace_product ON marketing_allocation(workspace_id, product_id);
CREATE INDEX IF NOT EXISTS ix_allocation_workspace_channel ON marketing_allocation(workspace_id, channel);
"""


def _apply_additive_migrations(connection: sqlite3.Connection) -> None:
    """Upgrade an existing Finance DB without changing any financial rows."""
    product_columns = {row[1] for row in connection.execute("PRAGMA table_info(product)")}
    if "brand_id" not in product_columns:
        connection.execute(
            "ALTER TABLE product ADD COLUMN brand_id INTEGER REFERENCES brand(id) ON DELETE SET NULL"
        )
    connection.execute("CREATE INDEX IF NOT EXISTS ix_product_workspace_brand ON product(workspace_id, brand_id)")


def connect(path: Path | None = None) -> sqlite3.Connection:
    database_path = (path or get_finance_database_path()).resolve()
    # Re-run the central guard even when a caller passes a path explicitly.
    if database_path.name.casefold() == "tracker.db":
        raise RuntimeError("Refusing to open tracker.db from Finance")
    connection = sqlite3.connect(database_path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=10000")
    return connection


def initialize_database(path: Path | None = None) -> Path:
    database_path = (path or get_finance_database_path()).resolve()
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with connect(database_path) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript(SCHEMA_SQL)
        _apply_additive_migrations(connection)
        connection.execute("INSERT OR IGNORE INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,))
        connection.commit()
    return database_path


@contextmanager
def finance_connection() -> Iterator[sqlite3.Connection]:
    connection = connect()
    try:
        yield connection
    finally:
        connection.close()
