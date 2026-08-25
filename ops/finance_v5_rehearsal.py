import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

PRODUCTION = "/var/data/render/sbrocor_finance.db"
if len(sys.argv) != 2 or os.path.realpath(sys.argv[1]) != PRODUCTION:
    raise SystemExit("usage: finance_v5_rehearsal.py /var/data/render/sbrocor_finance.db")
if os.path.basename(sys.argv[1]) == "tracker.db":
    raise SystemExit("tracker.db refused")

stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
copy_path = f"/var/data/render/backups/sbrocor_finance-v5-rehearsal-{stamp}.db"
source = sqlite3.connect(f"file:{PRODUCTION}?mode=ro", uri=True)
copy = sqlite3.connect(copy_path)
source.backup(copy)
copy.close()

def aggregates(connection):
    result = {}
    for table, columns in {
        "finance_transaction": ["amount"],
        "sale": ["total_selling_amount", "total_cost_amount", "commission_amount", "net_profit"],
        "ad_spend": ["spend"],
        "marketing_spend": ["amount_krw"],
        "product": [],
    }.items():
        row = connection.execute(f"SELECT COUNT(*) count{''.join(',COALESCE(SUM('+c+'),0) '+c for c in columns)} FROM {table}").fetchone()
        result[table] = list(row)
    return result

pre = aggregates(source)
legacy = source.execute(
    "SELECT ac.workspace_id,ac.account_id customer_id,ac.account_name,ms.brand_id,COUNT(*) rows,COALESCE(SUM(ms.amount_krw),0) amount,MIN(ms.date),MAX(ms.date) "
    "FROM marketing_spend ms JOIN ad_account_connection ac ON ac.id=ms.ad_account_connection_id AND ac.workspace_id=ms.workspace_id "
    "WHERE ms.source='naver_api' AND ac.platform='naver' GROUP BY ac.workspace_id,ac.account_id,ac.account_name,ms.brand_id ORDER BY ac.workspace_id,ac.account_id,ms.brand_id"
).fetchall()
source.close()

db = sqlite3.connect(copy_path)
schema = """
CREATE TABLE IF NOT EXISTS naver_account_connection (
 id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT, customer_id TEXT NOT NULL, account_name TEXT NOT NULL,
 credential_key TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), legacy_ad_account_connection_id INTEGER REFERENCES ad_account_connection(id) ON DELETE RESTRICT,
 last_campaign_synced_at TEXT, last_spend_synced_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(workspace_id,customer_id), UNIQUE(workspace_id,legacy_ad_account_connection_id));
CREATE TABLE IF NOT EXISTS naver_campaign (
 id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT, naver_account_connection_id INTEGER NOT NULL REFERENCES naver_account_connection(id) ON DELETE RESTRICT,
 campaign_id TEXT NOT NULL, campaign_name TEXT NOT NULL, status TEXT, brand_id INTEGER REFERENCES brand(id) ON DELETE RESTRICT, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
 last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(workspace_id,naver_account_connection_id,campaign_id));
CREATE TABLE IF NOT EXISTS naver_campaign_spend (
 id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT, naver_account_connection_id INTEGER NOT NULL REFERENCES naver_account_connection(id) ON DELETE RESTRICT,
 campaign_id TEXT NOT NULL, brand_id INTEGER REFERENCES brand(id) ON DELETE RESTRICT, date TEXT NOT NULL, amount_krw INTEGER NOT NULL CHECK(amount_krw>=0), external_key TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(workspace_id,external_key));
CREATE TABLE IF NOT EXISTS naver_account_sync_day (
 id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT, naver_account_connection_id INTEGER NOT NULL REFERENCES naver_account_connection(id) ON DELETE RESTRICT,
 date TEXT NOT NULL, total_amount_krw INTEGER NOT NULL CHECK(total_amount_krw>=0), campaign_count INTEGER NOT NULL DEFAULT 0,
 unmapped_amount_krw INTEGER NOT NULL DEFAULT 0 CHECK(unmapped_amount_krw>=0), unmapped_campaign_count INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(workspace_id,naver_account_connection_id,date));
CREATE INDEX IF NOT EXISTS ix_naver_account_workspace_active ON naver_account_connection(workspace_id,active);
CREATE INDEX IF NOT EXISTS ix_naver_campaign_account_active ON naver_campaign(workspace_id,naver_account_connection_id,active);
CREATE INDEX IF NOT EXISTS ix_naver_campaign_brand ON naver_campaign(workspace_id,brand_id,active);
CREATE INDEX IF NOT EXISTS ix_naver_campaign_spend_date ON naver_campaign_spend(workspace_id,date);
CREATE INDEX IF NOT EXISTS ix_naver_campaign_spend_brand_date ON naver_campaign_spend(workspace_id,brand_id,date);
CREATE INDEX IF NOT EXISTS ix_naver_sync_day_date ON naver_account_sync_day(workspace_id,date);
INSERT OR IGNORE INTO naver_account_connection(workspace_id,customer_id,account_name,credential_key,active,legacy_ad_account_connection_id,last_spend_synced_at,created_at,updated_at)
 SELECT workspace_id,account_id,account_name,credential_key,active,id,last_synced_at,created_at,updated_at FROM ad_account_connection WHERE platform='naver';
INSERT OR IGNORE INTO schema_version(version) VALUES (5);
"""
db.executescript(schema)
db.commit()
post = aggregates(db)
result = {
 "rehearsal_path": copy_path,
 "pre_integrity": db.execute("PRAGMA integrity_check").fetchone()[0],
 "schema_version": db.execute("SELECT MAX(version) FROM schema_version").fetchone()[0],
 "tables": {name: bool(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone()) for name in ("naver_account_connection","naver_campaign","naver_campaign_spend","naver_account_sync_day")},
 "new_counts": {name: db.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in ("naver_account_connection","naver_campaign","naver_campaign_spend","naver_account_sync_day")},
 "pre_post_match": pre == post,
 "pre": pre, "post": post,
 "integrity": db.execute("PRAGMA integrity_check").fetchone()[0],
 "foreign_key_check": db.execute("PRAGMA foreign_key_check").fetchall(),
 "legacy_naver_preview": [list(row) for row in legacy],
}
db.executescript(schema); db.commit()
result["idempotent"] = aggregates(db) == post and db.execute("SELECT COUNT(*) FROM naver_campaign_spend").fetchone()[0] == 0
db.close()
print(json.dumps(result, ensure_ascii=False, sort_keys=True))
