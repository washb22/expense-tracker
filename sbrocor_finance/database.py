"""SQLite connection and schema management for SBROCOR Finance only."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .config import get_finance_database_path


SCHEMA_VERSION = 7

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
    ad_account_connection_id INTEGER REFERENCES ad_account_connection(id) ON DELETE RESTRICT,
    brand_id INTEGER REFERENCES brand(id) ON DELETE RESTRICT,
    UNIQUE(workspace_id, date, platform, ad_id)
);
CREATE TABLE IF NOT EXISTS ad_account_connection (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    brand_id INTEGER NOT NULL REFERENCES brand(id) ON DELETE RESTRICT,
    platform TEXT NOT NULL CHECK(platform IN ('meta', 'naver')),
    account_id TEXT NOT NULL,
    account_name TEXT NOT NULL,
    currency TEXT NOT NULL,
    credential_key TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
    last_synced_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, platform, account_id)
);
CREATE TABLE IF NOT EXISTS marketing_spend (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    ad_account_connection_id INTEGER NOT NULL REFERENCES ad_account_connection(id) ON DELETE RESTRICT,
    brand_id INTEGER NOT NULL REFERENCES brand(id) ON DELETE RESTRICT,
    product_id INTEGER REFERENCES product(id) ON DELETE RESTRICT,
    date TEXT NOT NULL,
    channel TEXT NOT NULL,
    original_amount REAL NOT NULL,
    currency TEXT NOT NULL,
    fx_rate REAL,
    amount_krw INTEGER,
    source TEXT NOT NULL,
    external_key TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, source, external_key)
);
CREATE TABLE IF NOT EXISTS manual_marketing_spend (
    id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    brand_id INTEGER NOT NULL REFERENCES brand(id) ON DELETE RESTRICT,
    product_id INTEGER REFERENCES product(id) ON DELETE RESTRICT,
    date TEXT NOT NULL,
    channel TEXT NOT NULL,
    amount_krw INTEGER NOT NULL CHECK(amount_krw >= 0),
    memo TEXT,
    allocation_mode TEXT NOT NULL CHECK(allocation_mode IN ('single','range')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS naver_account_connection (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    customer_id TEXT NOT NULL,
    account_name TEXT NOT NULL,
    credential_key TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
    legacy_ad_account_connection_id INTEGER REFERENCES ad_account_connection(id) ON DELETE RESTRICT,
    last_campaign_synced_at TEXT,
    last_spend_synced_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, customer_id),
    UNIQUE(workspace_id, legacy_ad_account_connection_id)
);
CREATE TABLE IF NOT EXISTS naver_campaign (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    naver_account_connection_id INTEGER NOT NULL REFERENCES naver_account_connection(id) ON DELETE RESTRICT,
    campaign_id TEXT NOT NULL,
    campaign_name TEXT NOT NULL,
    status TEXT,
    brand_id INTEGER REFERENCES brand(id) ON DELETE RESTRICT,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
    archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0, 1)),
    archived_at TEXT,
    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, naver_account_connection_id, campaign_id)
);
CREATE TABLE IF NOT EXISTS naver_campaign_spend (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    naver_account_connection_id INTEGER NOT NULL REFERENCES naver_account_connection(id) ON DELETE RESTRICT,
    campaign_id TEXT NOT NULL,
    brand_id INTEGER REFERENCES brand(id) ON DELETE RESTRICT,
    date TEXT NOT NULL,
    amount_krw INTEGER NOT NULL CHECK(amount_krw >= 0),
    external_key TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, external_key)
);
CREATE TABLE IF NOT EXISTS naver_adgroup (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    naver_account_connection_id INTEGER NOT NULL REFERENCES naver_account_connection(id) ON DELETE RESTRICT,
    campaign_id TEXT NOT NULL,
    adgroup_id TEXT NOT NULL,
    adgroup_name TEXT NOT NULL,
    status TEXT,
    allocation_mode TEXT NOT NULL DEFAULT 'unassigned' CHECK(allocation_mode IN ('unassigned','brand_common','product')),
    product_id INTEGER REFERENCES product(id) ON DELETE RESTRICT,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
    archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0, 1)),
    archived_at TEXT,
    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, naver_account_connection_id, adgroup_id),
    CHECK((allocation_mode='product' AND product_id IS NOT NULL) OR (allocation_mode!='product' AND product_id IS NULL))
);
CREATE TABLE IF NOT EXISTS naver_adgroup_spend (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    naver_account_connection_id INTEGER NOT NULL REFERENCES naver_account_connection(id) ON DELETE RESTRICT,
    campaign_id TEXT NOT NULL,
    adgroup_id TEXT NOT NULL,
    brand_id INTEGER REFERENCES brand(id) ON DELETE RESTRICT,
    product_id INTEGER REFERENCES product(id) ON DELETE RESTRICT,
    allocation_mode TEXT NOT NULL CHECK(allocation_mode IN ('unassigned','brand_common','product')),
    date TEXT NOT NULL,
    amount_krw INTEGER NOT NULL CHECK(amount_krw >= 0),
    external_key TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, external_key),
    CHECK((allocation_mode='product' AND product_id IS NOT NULL) OR (allocation_mode!='product' AND product_id IS NULL))
);
CREATE TABLE IF NOT EXISTS naver_account_sync_day (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
    naver_account_connection_id INTEGER NOT NULL REFERENCES naver_account_connection(id) ON DELETE RESTRICT,
    date TEXT NOT NULL,
    total_amount_krw INTEGER NOT NULL CHECK(total_amount_krw >= 0),
    campaign_count INTEGER NOT NULL DEFAULT 0,
    unmapped_amount_krw INTEGER NOT NULL DEFAULT 0 CHECK(unmapped_amount_krw >= 0),
    unmapped_campaign_count INTEGER NOT NULL DEFAULT 0,
    adgroup_count INTEGER NOT NULL DEFAULT 0,
    product_attributed_amount_krw INTEGER NOT NULL DEFAULT 0 CHECK(product_attributed_amount_krw >= 0),
    brand_common_amount_krw INTEGER NOT NULL DEFAULT 0 CHECK(brand_common_amount_krw >= 0),
    unassigned_product_amount_krw INTEGER NOT NULL DEFAULT 0 CHECK(unassigned_product_amount_krw >= 0),
    unassigned_adgroup_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, naver_account_connection_id, date)
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
CREATE INDEX IF NOT EXISTS ix_ad_account_workspace_brand ON ad_account_connection(workspace_id, brand_id, active);
CREATE INDEX IF NOT EXISTS ix_marketing_spend_workspace_date ON marketing_spend(workspace_id, date);
CREATE INDEX IF NOT EXISTS ix_marketing_spend_brand_date ON marketing_spend(workspace_id, brand_id, date);
CREATE INDEX IF NOT EXISTS ix_manual_spend_workspace_date ON manual_marketing_spend(workspace_id, date);
CREATE INDEX IF NOT EXISTS ix_manual_spend_workspace_batch ON manual_marketing_spend(workspace_id, batch_id);
CREATE INDEX IF NOT EXISTS ix_manual_spend_brand_product_date ON manual_marketing_spend(workspace_id, brand_id, product_id, date);
CREATE INDEX IF NOT EXISTS ix_naver_account_workspace_active ON naver_account_connection(workspace_id, active);
CREATE INDEX IF NOT EXISTS ix_naver_campaign_account_active ON naver_campaign(workspace_id, naver_account_connection_id, active);
CREATE INDEX IF NOT EXISTS ix_naver_campaign_brand ON naver_campaign(workspace_id, brand_id, active);
CREATE INDEX IF NOT EXISTS ix_naver_campaign_spend_date ON naver_campaign_spend(workspace_id, date);
CREATE INDEX IF NOT EXISTS ix_naver_campaign_spend_brand_date ON naver_campaign_spend(workspace_id, brand_id, date);
CREATE INDEX IF NOT EXISTS ix_naver_adgroup_account_active ON naver_adgroup(workspace_id, naver_account_connection_id, active);
CREATE INDEX IF NOT EXISTS ix_naver_adgroup_campaign ON naver_adgroup(workspace_id, naver_account_connection_id, campaign_id);
CREATE INDEX IF NOT EXISTS ix_naver_adgroup_product ON naver_adgroup(workspace_id, product_id, active);
CREATE INDEX IF NOT EXISTS ix_naver_adgroup_spend_date ON naver_adgroup_spend(workspace_id, date);
CREATE INDEX IF NOT EXISTS ix_naver_adgroup_spend_brand_date ON naver_adgroup_spend(workspace_id, brand_id, date);
CREATE INDEX IF NOT EXISTS ix_naver_adgroup_spend_product_date ON naver_adgroup_spend(workspace_id, product_id, date);
CREATE INDEX IF NOT EXISTS ix_naver_sync_day_date ON naver_account_sync_day(workspace_id, date);
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
    ad_spend_columns = {row[1] for row in connection.execute("PRAGMA table_info(ad_spend)")}
    if "ad_account_connection_id" not in ad_spend_columns:
        connection.execute(
            "ALTER TABLE ad_spend ADD COLUMN ad_account_connection_id INTEGER REFERENCES ad_account_connection(id) ON DELETE RESTRICT"
        )
    if "brand_id" not in ad_spend_columns:
        connection.execute(
            "ALTER TABLE ad_spend ADD COLUMN brand_id INTEGER REFERENCES brand(id) ON DELETE RESTRICT"
        )


def _schema_statements(sql: str) -> list[str]:
    return [statement.strip() for statement in sql.split(";") if statement.strip()]


def _is_v5_statement(statement: str) -> bool:
    normalized = " ".join(statement.lower().split())
    is_naver = normalized.startswith("create table if not exists naver_") or normalized.startswith(
        "create index if not exists ix_naver_"
    )
    return is_naver and not normalized.startswith("create table if not exists naver_adgroup") and not normalized.startswith(
        "create index if not exists ix_naver_adgroup"
    )


def _v5_migration_hook(_stage: str) -> None:
    """Fault-injection seam used by migration tests."""


def _migrate_v5(connection: sqlite3.Connection) -> None:
    current = int(connection.execute("SELECT COALESCE(MAX(version),0) FROM schema_version").fetchone()[0])
    if current >= 5:
        return
    try:
        connection.execute("BEGIN IMMEDIATE")
        for statement in _schema_statements(SCHEMA_SQL):
            if _is_v5_statement(statement):
                connection.execute(statement)
        _v5_migration_hook("after_ddl")
        _v5_migration_hook("before_metadata")
        # Copy connection metadata only. Legacy financial rows remain untouched.
        connection.execute(
            """INSERT OR IGNORE INTO naver_account_connection
               (workspace_id,customer_id,account_name,credential_key,active,legacy_ad_account_connection_id,
                last_spend_synced_at,created_at,updated_at)
               SELECT workspace_id,account_id,account_name,credential_key,active,id,last_synced_at,created_at,updated_at
               FROM ad_account_connection WHERE platform='naver'"""
        )
        _v5_migration_hook("before_version")
        connection.execute("INSERT OR IGNORE INTO schema_version(version) VALUES (5)")
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _is_v6_statement(statement: str) -> bool:
    normalized = " ".join(statement.lower().split())
    return normalized.startswith("create table if not exists naver_adgroup") or normalized.startswith(
        "create index if not exists ix_naver_adgroup"
    )


def _v6_migration_hook(_stage: str) -> None:
    """Fault-injection seam used by migration tests."""


def _migrate_v6(connection: sqlite3.Connection) -> None:
    current = int(connection.execute("SELECT COALESCE(MAX(version),0) FROM schema_version").fetchone()[0])
    if current >= 6:
        return
    try:
        connection.execute("BEGIN IMMEDIATE")
        for statement in _schema_statements(SCHEMA_SQL):
            if _is_v6_statement(statement):
                connection.execute(statement)
        columns = {row[1] for row in connection.execute("PRAGMA table_info(naver_account_sync_day)")}
        additions = {
            "adgroup_count": "INTEGER NOT NULL DEFAULT 0",
            "product_attributed_amount_krw": "INTEGER NOT NULL DEFAULT 0 CHECK(product_attributed_amount_krw >= 0)",
            "brand_common_amount_krw": "INTEGER NOT NULL DEFAULT 0 CHECK(brand_common_amount_krw >= 0)",
            "unassigned_product_amount_krw": "INTEGER NOT NULL DEFAULT 0 CHECK(unassigned_product_amount_krw >= 0)",
            "unassigned_adgroup_count": "INTEGER NOT NULL DEFAULT 0",
        }
        for name, definition in additions.items():
            if name not in columns:
                connection.execute(f"ALTER TABLE naver_account_sync_day ADD COLUMN {name} {definition}")
        _v6_migration_hook("after_ddl")
        _v6_migration_hook("before_version")
        connection.execute("INSERT OR IGNORE INTO schema_version(version) VALUES (6)")
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _v7_migration_hook(_stage: str) -> None:
    """Fault-injection seam used by migration tests."""


def _migrate_v7(connection: sqlite3.Connection) -> None:
    current = int(connection.execute("SELECT COALESCE(MAX(version),0) FROM schema_version").fetchone()[0])
    if current >= 7:
        return
    try:
        connection.execute("BEGIN IMMEDIATE")
        for table in ("naver_campaign", "naver_adgroup"):
            columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
            if "archived" not in columns:
                connection.execute(
                    f"ALTER TABLE {table} ADD COLUMN archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0, 1))"
                )
            if "archived_at" not in columns:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN archived_at TEXT")
        _v7_migration_hook("after_ddl")
        _v7_migration_hook("before_version")
        connection.execute("INSERT OR IGNORE INTO schema_version(version) VALUES (7)")
        connection.commit()
    except Exception:
        connection.rollback()
        raise


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
    with closing(connect(database_path)) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        existing = bool(connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone())
        if existing:
            base_schema = ";\n".join(
                statement for statement in _schema_statements(SCHEMA_SQL)
                if not _is_v5_statement(statement) and not _is_v6_statement(statement)
            ) + ";"
            connection.executescript(base_schema)
        else:
            connection.executescript(SCHEMA_SQL)
        _apply_additive_migrations(connection)
        connection.commit()
        if existing:
            _migrate_v5(connection)
            _migrate_v6(connection)
            _migrate_v7(connection)
        else:
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

