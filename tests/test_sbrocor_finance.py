import hashlib
import json
import os
import sqlite3
import tempfile
import time
import unittest
import uuid
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from flask import Flask

from sbrocor_finance import finance_blueprint
from sbrocor_finance.auth import sign_request
from sbrocor_finance.config import FinanceConfigurationError, get_finance_database_path
from sbrocor_finance.database import connect, initialize_database
from sbrocor_finance.repository import FinanceRepository
from sbrocor_finance.service import FinanceService


SECRET_TEXT = "fixture-secret-that-is-at-least-thirty-two-bytes"
SECRET = SECRET_TEXT.encode()


class FinanceApiTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "finance-fixture.db"
        self.environment = patch.dict(
            os.environ,
            {
                "SBROCOR_FINANCE_DB_PATH": str(self.db_path),
                "SBROCOR_FINANCE_HMAC_KEY_ID": "fixture-key",
                "SBROCOR_FINANCE_HMAC_SECRET": SECRET_TEXT,
                "SBROCOR_FINANCE_HMAC_MAX_SKEW_SECONDS": "300",
                "DATABASE_URL": f"sqlite:///{(Path(self.tempdir.name) / 'moneylog-fixture.db').as_posix()}",
            },
            clear=False,
        )
        self.environment.start()
        initialize_database()
        app = Flask(__name__)
        app.register_blueprint(finance_blueprint)
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def tearDown(self):
        self.environment.stop()
        self.tempdir.cleanup()

    def headers(self, method, path, body=b"", nonce=None, timestamp=None):
        timestamp = str(timestamp or int(time.time()))
        nonce = nonce or uuid.uuid4().hex
        return {
            "X-SBROCOR-Key-Id": "fixture-key",
            "X-SBROCOR-Timestamp": timestamp,
            "X-SBROCOR-Nonce": nonce,
            "X-SBROCOR-Signature": sign_request(SECRET, method, path, timestamp, nonce, body),
            "Content-Type": "application/json",
        }

    def request(self, method, path, payload=None, nonce=None, timestamp=None):
        body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        return self.client.open(
            path,
            method=method,
            data=body,
            headers=self.headers(method, path, body, nonce=nonce, timestamp=timestamp),
        )

    def create_workspace(self, workspace_id, name="Workspace"):
        response = self.request("POST", "/api/sbrocor/finance/v1/workspaces", {"id": workspace_id, "name": name})
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))

    def test_schema_pragmas_and_foreign_keys(self):
        connection = connect()
        self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(connection.execute("PRAGMA busy_timeout").fetchone()[0], 10000)
        self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"workspace", "finance_transaction", "rule", "product", "platform", "sale", "workspace_settings", "ad_spend", "auth_nonce"}.issubset(tables))
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO finance_transaction(id,workspace_id,date,merchant,amount,category) VALUES ('x',999,'2026-01-01','x',1,'x')"
            )
        connection.close()

    def test_restricts_workspace_product_and_platform_deletes(self):
        self.create_workspace(1)
        self.request("POST", "/api/sbrocor/finance/v1/transactions?workspace_id=1", {"id": "t1", "date": "2026-01-01", "merchant": "M", "amount": 1, "category": "C"})
        self.assertEqual(self.request("DELETE", "/api/sbrocor/finance/v1/workspaces/1").status_code, 409)

        self.create_workspace(2)
        self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=2", {"id": 21, "name": "P", "cost_price": 1})
        self.request("POST", "/api/sbrocor/finance/v1/platforms?workspace_id=2", {"id": 22, "name": "C", "commission_rate": 1})
        sale = {"id": "s2", "date": "2026-01-01", "product_id": 21, "platform_id": 22, "selling_price": 1, "quantity": 1, "total_selling_amount": 1, "total_cost_amount": 1, "commission_amount": 0, "net_profit": 0}
        self.request("POST", "/api/sbrocor/finance/v1/sales?workspace_id=2", sale)
        self.assertEqual(self.request("DELETE", "/api/sbrocor/finance/v1/workspaces/2").status_code, 409)
        self.assertEqual(self.request("DELETE", "/api/sbrocor/finance/v1/products/21?workspace_id=2").status_code, 409)
        self.assertEqual(self.request("DELETE", "/api/sbrocor/finance/v1/platforms/22?workspace_id=2").status_code, 409)

    def test_tracker_db_is_fail_closed(self):
        with patch.dict(os.environ, {"SBROCOR_FINANCE_DB_PATH": str(Path(self.tempdir.name) / "tracker.db")}, clear=False):
            with self.assertRaises(FinanceConfigurationError):
                get_finance_database_path()
            with self.assertRaises(RuntimeError):
                connect(Path(self.tempdir.name) / "tracker.db")
        legacy = Path(self.tempdir.name) / "legacy.sqlite"
        with patch.dict(os.environ, {"SBROCOR_FINANCE_DB_PATH": str(legacy), "DATABASE_URL": f"sqlite:///{legacy.as_posix()}"}, clear=False):
            with self.assertRaises(FinanceConfigurationError):
                get_finance_database_path()

    def test_hmac_rejects_missing_tampered_expired_and_replayed_requests(self):
        path = "/api/sbrocor/finance/v1/workspaces"
        self.assertEqual(self.client.get(path).status_code, 401)
        headers = self.headers("GET", path)
        headers["X-SBROCOR-Signature"] = "0" * 64
        self.assertEqual(self.client.get(path, headers=headers).status_code, 401)
        self.assertEqual(self.request("GET", path, timestamp=int(time.time()) - 301).status_code, 401)
        nonce = uuid.uuid4().hex
        self.assertEqual(self.request("GET", path, nonce=nonce).status_code, 200)
        self.assertEqual(self.request("GET", path, nonce=nonce).status_code, 409)

    def test_crud_workspace_isolation_and_sale_amount_preservation(self):
        self.create_workspace(1, "One")
        self.create_workspace(2, "Two")
        product = {"id": 10, "name": "P", "sku": "S", "cost_price": 400, "category": "C"}
        platform = {"id": 20, "name": "Channel", "commission_rate": 12.5}
        for resource, payload in (("products", product), ("platforms", platform)):
            response = self.request("POST", f"/api/sbrocor/finance/v1/{resource}?workspace_id=1", payload)
            self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        sale = {
            "id": "sale-original", "date": "2026-08-01", "product_id": 10, "platform_id": 20,
            "selling_price": 999, "quantity": 3, "total_selling_amount": 123456,
            "total_cost_amount": 6543, "commission_amount": 2222, "net_profit": 114691,
        }
        response = self.request("POST", "/api/sbrocor/finance/v1/sales?workspace_id=1", sale)
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        self.assertEqual(response.json["total_selling_amount"], 123456)
        self.assertEqual(response.json["net_profit"], 114691)
        self.assertEqual(self.request("GET", "/api/sbrocor/finance/v1/sales?workspace_id=2").json["items"], [])
        self.assertEqual(self.request("GET", "/api/sbrocor/finance/v1/sales/sale-original?workspace_id=2").status_code, 404)
        patched = self.request("PATCH", "/api/sbrocor/finance/v1/sales/sale-original?workspace_id=1", {"net_profit": 111})
        self.assertEqual(patched.json["net_profit"], 111)
        self.assertEqual(self.request("DELETE", "/api/sbrocor/finance/v1/sales/sale-original?workspace_id=1").status_code, 204)

    def test_sale_rejects_cross_workspace_foreign_keys(self):
        self.create_workspace(1)
        self.create_workspace(2)
        self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {"id": 1, "name": "P", "cost_price": 1})
        self.request("POST", "/api/sbrocor/finance/v1/platforms?workspace_id=2", {"id": 2, "name": "C", "commission_rate": 1})
        sale = {"date": "2026-01-01", "product_id": 1, "platform_id": 2, "selling_price": 1, "quantity": 1, "total_selling_amount": 1, "total_cost_amount": 1, "commission_amount": 0, "net_profit": 0}
        self.assertEqual(self.request("POST", "/api/sbrocor/finance/v1/sales?workspace_id=1", sale).status_code, 400)

    def test_remaining_resource_crud_and_business_summary(self):
        self.create_workspace(7)
        fixtures = {
            "categories": {"id": 71, "keyword": "택배", "category": "배송비"},
            "ads": {"id": 72, "date": "2026-08-02", "platform": "meta", "spend": 500.5},
        }
        for resource, payload in fixtures.items():
            created = self.request("POST", f"/api/sbrocor/finance/v1/{resource}?workspace_id=7", payload)
            self.assertEqual(created.status_code, 201, created.get_data(as_text=True))
            item_id = str(created.json["id"])
            fetched = self.request("GET", f"/api/sbrocor/finance/v1/{resource}/{item_id}?workspace_id=7")
            self.assertEqual(fetched.status_code, 200)
            self.assertEqual(self.request("DELETE", f"/api/sbrocor/finance/v1/{resource}/{item_id}?workspace_id=7").status_code, 204)
        business = self.request("GET", "/api/sbrocor/finance/v1/business?workspace_id=7")
        self.assertEqual(business.status_code, 200)
        self.assertIn("operating_profit", business.json)

    def test_import_export_and_dashboard(self):
        self.create_workspace(1, "Original")
        self.request("POST", "/api/sbrocor/finance/v1/transactions?workspace_id=1", {"id": "t1", "date": "2026-08-01", "merchant": "M", "amount": 300, "category": "C"})
        manifest_response = self.request("GET", "/api/sbrocor/finance/v1/workspaces/1/export")
        self.assertEqual(manifest_response.status_code, 200)
        manifest = manifest_response.json
        manifest["workspace"] = {"id": 2, "name": "Imported"}
        for resource in ("transactions", "categories", "products", "platforms", "sales", "ads"):
            for item in manifest[resource]:
                item.pop("workspace_id", None)
        # Production COPY keeps globally unique source IDs. This fixture changes
        # the cloned ID only because workspace 1 remains in the same test DB.
        manifest["transactions"][0]["id"] = "t2"
        dry = self.request("POST", "/api/sbrocor/finance/v1/workspaces/2/import?dry_run=true", manifest)
        self.assertTrue(dry.json["dry_run"])
        blocked = self.request("POST", "/api/sbrocor/finance/v1/workspaces/2/import?dry_run=false", manifest)
        self.assertEqual(blocked.status_code, 403)
        with closing(connect()) as connection:
            applied = FinanceService(FinanceRepository(connection)).import_initial_manifest(2, manifest)
        self.assertFalse(applied["dry_run"])
        with closing(connect()) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                FinanceService(FinanceRepository(connection)).import_initial_manifest(2, manifest)
        self.assertEqual(self.request("GET", "/api/sbrocor/finance/v1/transactions?workspace_id=2").json["items"][0]["amount"], 300)
        dashboard = self.request("GET", "/api/sbrocor/finance/v1/dashboard?workspace_id=2")
        self.assertEqual(dashboard.json["total_expenses"], 300)
        self.assertEqual(self.request("POST", "/api/sbrocor/finance/v1/workspaces/2/import?dry_run=false", manifest).status_code, 403)

    def test_workspace_settings_round_trip_excludes_meta_token(self):
        self.create_workspace(1)
        with closing(connect()) as connection:
            connection.execute(
                "INSERT INTO workspace_settings(id,workspace_id,meta_ad_account_id,updated_at) VALUES (1,1,'act_123','2026-08-01')"
            )
            connection.commit()
        exported = self.request("GET", "/api/sbrocor/finance/v1/workspaces/1/export")
        serialized = exported.get_data(as_text=True)
        self.assertEqual(exported.json["workspace_settings"]["meta_ad_account_id"], "act_123")
        self.assertNotIn("meta_access_token", serialized)
        self.assertNotIn("secret-token-value", serialized)
        manifest = exported.json
        manifest["workspace"] = {"id": 2, "name": "Imported settings"}
        manifest["workspace_settings"]["id"] = 2
        manifest["workspace_settings"].pop("workspace_id", None)
        manifest["workspace_settings"]["meta_access_token"] = "secret-token-value"
        with closing(connect()) as connection:
            FinanceService(FinanceRepository(connection)).import_initial_manifest(2, manifest)
        imported = self.request("GET", "/api/sbrocor/finance/v1/workspaces/2/export")
        self.assertEqual(imported.json["workspace_settings"]["meta_ad_account_id"], "act_123")
        self.assertNotIn("secret-token-value", imported.get_data(as_text=True))
        self.assertNotIn("meta_access_token", imported.get_data(as_text=True))
        with closing(connect()) as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(workspace_settings)")}
        self.assertNotIn("meta_access_token", columns)

    def test_dashboard_excludes_unclassified_and_business_matches_moneylog(self):
        self.create_workspace(1)
        for item in (
            {"id": "classified", "date": "2026-01-01", "merchant": "A", "amount": 100000, "category": "광고비"},
            {"id": "unclassified", "date": "2026-01-01", "merchant": "B", "amount": 500000, "category": "미분류"},
        ):
            self.request("POST", "/api/sbrocor/finance/v1/transactions?workspace_id=1", item)
        self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {"id": 1, "name": "P", "cost_price": 1})
        self.request("POST", "/api/sbrocor/finance/v1/platforms?workspace_id=1", {"id": 1, "name": "C", "commission_rate": 1})
        sale = {"id": "sale", "date": "2026-01-01", "product_id": 1, "platform_id": 1, "selling_price": 1, "quantity": 1, "total_selling_amount": 900000, "total_cost_amount": 1, "commission_amount": 0, "net_profit": 700000}
        self.request("POST", "/api/sbrocor/finance/v1/sales?workspace_id=1", sale)
        dashboard = self.request("GET", "/api/sbrocor/finance/v1/dashboard?workspace_id=1").json
        business = self.request("GET", "/api/sbrocor/finance/v1/business?workspace_id=1").json
        self.assertEqual(dashboard["total_expenses"], 100000)
        self.assertEqual(business["operating_profit"], 600000)


if __name__ == "__main__":
    unittest.main()
