import hashlib
import base64
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

    def headers(self, method, path, body=b"", nonce=None, timestamp=None, context=None):
        timestamp = str(timestamp or int(time.time()))
        nonce = nonce or uuid.uuid4().hex
        context = context or {"actor_uid": "admin-uid", "role": "admin", "workspace_ids": [1, 2, 6, 7], "permissions": []}
        encoded_context = base64.urlsafe_b64encode(json.dumps(context, separators=(",", ":")).encode()).decode().rstrip("=")
        return {
            "X-SBROCOR-Key-Id": "fixture-key",
            "X-SBROCOR-Timestamp": timestamp,
            "X-SBROCOR-Nonce": nonce,
            "X-SBROCOR-Context": encoded_context,
            "X-SBROCOR-Signature": sign_request(SECRET, method, path, timestamp, nonce, body, encoded_context),
            "Content-Type": "application/json",
        }

    def request(self, method, path, payload=None, nonce=None, timestamp=None, context=None):
        body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        return self.client.open(
            path,
            method=method,
            data=body,
            headers=self.headers(method, path, body, nonce=nonce, timestamp=timestamp, context=context),
        )

    def request_bytes(self, method, path, body, content_type, context=None):
        headers = self.headers(method, path, body, context=context)
        headers["Content-Type"] = content_type
        return self.client.open(path, method=method, data=body, headers=headers)

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

    def test_signed_employee_context_enforces_workspace_and_menu(self):
        self.create_workspace(1, "One")
        self.create_workspace(2, "Two")
        context = {"actor_uid": "employee", "role": "employee", "workspace_ids": [1], "permissions": ["products", "workspaces"]}
        self.assertEqual(self.request("GET", "/api/sbrocor/finance/v1/products?workspace_id=1", context=context).status_code, 200)
        self.assertEqual(self.request("GET", "/api/sbrocor/finance/v1/sales?workspace_id=1", context=context).status_code, 403)
        self.assertEqual(self.request("GET", "/api/sbrocor/finance/v1/products?workspace_id=2", context=context).status_code, 403)
        items = self.request("GET", "/api/sbrocor/finance/v1/workspaces", context=context).json["items"]
        self.assertEqual([item["id"] for item in items], [1])
        self.assertEqual(self.request("DELETE", "/api/sbrocor/finance/v1/workspaces/1", context=context).status_code, 403)

    def test_context_is_covered_by_signature(self):
        path = "/api/sbrocor/finance/v1/workspaces"
        headers = self.headers("GET", path)
        forged = base64.urlsafe_b64encode(json.dumps({"actor_uid":"x","role":"admin","workspace_ids":[],"permissions":[]}).encode()).decode().rstrip("=")
        headers["X-SBROCOR-Context"] = forged
        self.assertEqual(self.client.get(path, headers=headers).status_code, 401)

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

    def test_server_pagination_filters_and_analytics(self):
        self.create_workspace(1)
        for index in range(5):
            self.request("POST", "/api/sbrocor/finance/v1/transactions?workspace_id=1", {
                "id": f"t{index}", "date": f"2026-0{8 if index < 4 else 7}-0{index + 1}",
                "merchant": "네이버" if index % 2 == 0 else "택배", "amount": 100 * (index + 1),
                "category": "광고비" if index % 2 == 0 else "배송비",
            })
        page = self.request("GET", "/api/sbrocor/finance/v1/transactions?workspace_id=1&month=2026-08&page=1&page_size=2")
        self.assertEqual(page.status_code, 200)
        self.assertEqual(len(page.json["items"]), 2)
        self.assertEqual(page.json["pagination"]["total"], 4)
        self.assertEqual(page.json["pagination"]["pages"], 2)
        self.assertEqual(page.json["available_months"], ["2026-08", "2026-07"])
        searched = self.request("GET", "/api/sbrocor/finance/v1/transactions?workspace_id=1&search=네이버")
        self.assertEqual(searched.json["pagination"]["total"], 3)
        dashboard = self.request("GET", "/api/sbrocor/finance/v1/dashboard?workspace_id=1&month=2026-08")
        self.assertEqual(sum(item["amount"] for item in dashboard.json["categories"]), 1000)
        self.assertTrue(dashboard.json["merchants"])

    def test_direct_date_range_filters_all_read_endpoints(self):
        self.create_workspace(1)
        for suffix, date_value, amount in (
            ("jun", "2026-06-15", 100),
            ("jul", "2026-07-31 12:30:00", 200),
            ("aug", "2026-08-05", 300),
        ):
            self.request("POST", "/api/sbrocor/finance/v1/transactions?workspace_id=1", {
                "id": f"transaction-{suffix}", "date": date_value, "merchant": suffix,
                "amount": amount, "category": "광고비",
            })

        self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {
            "id": 1, "name": "기간 테스트 제품", "cost_price": 10,
        })
        self.request("POST", "/api/sbrocor/finance/v1/platforms?workspace_id=1", {
            "id": 1, "name": "기간 테스트 채널", "commission_rate": 0,
        })
        for suffix, date_value, total in (
            ("jun", "2026-06-15", 1000),
            ("jul", "2026-07-31 12:30:00", 2000),
            ("aug", "2026-08-05", 3000),
        ):
            ad_spend = {"jun": 100, "jul": 200, "aug": 300}[suffix]
            self.request("POST", "/api/sbrocor/finance/v1/sales?workspace_id=1", {
                "id": f"sale-{suffix}", "date": date_value, "product_id": 1, "platform_id": 1,
                "selling_price": total, "quantity": 1, "total_selling_amount": total,
                "total_cost_amount": 10, "commission_amount": 0, "net_profit": total - 10,
            })
            self.request("POST", "/api/sbrocor/finance/v1/ads?workspace_id=1", {
                "id": {"jun": 1, "jul": 2, "aug": 3}[suffix], "date": date_value,
                "campaign_id": "campaign", "campaign_name": "기간 테스트", "spend": ad_spend,
                "impressions": ad_spend * 10, "clicks": ad_spend, "conversions": 1,
                "conversion_value": total,
            })

        period = "workspace_id=1&start_date=2026-07-01&end_date=2026-07-31"
        dashboard = self.request("GET", f"/api/sbrocor/finance/v1/dashboard?{period}")
        business = self.request("GET", f"/api/sbrocor/finance/v1/business?{period}")
        transactions = self.request("GET", f"/api/sbrocor/finance/v1/transactions?{period}")
        sales = self.request("GET", f"/api/sbrocor/finance/v1/sales?{period}")
        ads = self.request("GET", f"/api/sbrocor/finance/v1/ads/analytics?{period}")

        for response in (dashboard, business, transactions, sales, ads):
            self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(dashboard.json["total_expenses"], 200)
        self.assertEqual(business.json["total_expenses"], 200)
        self.assertEqual(business.json["total_sales"], 2000)
        self.assertEqual([row["id"] for row in transactions.json["items"]], ["transaction-jul"])
        self.assertEqual([row["id"] for row in sales.json["items"]], ["sale-jul"])
        self.assertEqual(ads.json["summary"]["spend"], 200)

    def test_ad_hierarchy_analytics(self):
        self.create_workspace(1)
        self.request("POST", "/api/sbrocor/finance/v1/ads?workspace_id=1", {
            "id": 1, "date": "2026-08-01", "campaign_id": "c1", "campaign_name": "캠페인",
            "adset_id": "set1", "adset_name": "세트", "ad_id": "ad1", "ad_name": "소재",
            "spend": 100, "impressions": 1000, "clicks": 20, "conversions": 2, "conversion_value": 400,
        })
        response = self.request("GET", "/api/sbrocor/finance/v1/ads/analytics?workspace_id=1&month=2026-08")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["summary"]["roas"], 4)
        self.assertEqual(response.json["campaigns"][0]["campaign_name"], "캠페인")
        self.assertEqual(response.json["adsets"][0]["adset_name"], "세트")
        self.assertEqual(response.json["creatives"][0]["ad_name"], "소재")

    def test_dashboard_drilldown_excel_and_bulk_delete(self):
        self.create_workspace(1)
        for item in (
            {"id": "t1", "date": "2026-08-01", "merchant": "택배사", "amount": 100, "category": "배송비"},
            {"id": "t2", "date": "2026-08-02", "merchant": "택배사", "amount": 200, "category": "배송비"},
        ):
            self.request("POST", "/api/sbrocor/finance/v1/transactions?workspace_id=1", item)
        dashboard = self.request("GET", "/api/sbrocor/finance/v1/dashboard?workspace_id=1&month=2026-08")
        self.assertEqual([row["id"] for row in dashboard.json["transactions"]], ["t2", "t1"])
        exported = self.request("GET", "/api/sbrocor/finance/v1/exports/expenses?workspace_id=1&month=2026-08")
        self.assertEqual(exported.status_code, 200)
        self.assertTrue(exported.data.startswith(b"PK"))
        deleted = self.request("POST", "/api/sbrocor/finance/v1/transactions/bulk-delete?workspace_id=1", {"ids": ["t1", "t2"]})
        self.assertEqual(deleted.json["deleted"], 2)

    def test_rule_reclassification_and_product_recalculation_are_confirmed(self):
        self.create_workspace(1)
        self.request("POST", "/api/sbrocor/finance/v1/categories?workspace_id=1", {"id": 1, "keyword": "택배", "category": "배송비"})
        self.request("POST", "/api/sbrocor/finance/v1/transactions?workspace_id=1", {"id": "t1", "date": "2026-08-01", "merchant": "대한택배", "amount": 100, "category": "미분류"})
        preview = self.request("POST", "/api/sbrocor/finance/v1/categories/reclassify?workspace_id=1", {"apply": False})
        self.assertEqual(preview.json["changed"], 1)
        self.assertEqual(self.request("POST", "/api/sbrocor/finance/v1/categories/reclassify?workspace_id=1", {"apply": True}).status_code, 400)
        applied = self.request("POST", "/api/sbrocor/finance/v1/categories/reclassify?workspace_id=1", {"apply": True, "confirmation": "RECLASSIFY ALL"})
        self.assertEqual(applied.json["changed"], 1)

        self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {"id": 1, "name": "P", "cost_price": 400})
        self.request("POST", "/api/sbrocor/finance/v1/platforms?workspace_id=1", {"id": 1, "name": "C", "commission_rate": 10})
        sale = {"id": "s1", "date": "2026-08-01", "product_id": 1, "platform_id": 1, "selling_price": 1000, "quantity": 2, "total_selling_amount": 1000, "total_cost_amount": 100, "commission_amount": 100, "net_profit": 800}
        self.request("POST", "/api/sbrocor/finance/v1/sales?workspace_id=1", sale)
        impact = self.request("POST", "/api/sbrocor/finance/v1/products/1/recalculate?workspace_id=1", {"apply": False})
        self.assertEqual(impact.json["affected"], 1)
        self.assertEqual(self.request("POST", "/api/sbrocor/finance/v1/products/1/recalculate?workspace_id=1", {"apply": True}).status_code, 400)

    def test_transaction_import_dry_run_and_replace_confirmation(self):
        self.create_workspace(1)
        self.request("POST", "/api/sbrocor/finance/v1/categories?workspace_id=1", {"id": 1, "keyword": "택배", "category": "배송비"})
        boundary = "----financefixture"
        csv = "날짜,거래처명,금액\r\n2026-08-01,대한택배,1200\r\n"
        def multipart(dry_run, confirmation=None):
            fields = [("mode", "replace"), ("dry_run", str(dry_run).lower())]
            if confirmation: fields.append(("confirmation", confirmation))
            parts = []
            for name, value in fields:
                parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"transactions.csv\"\r\nContent-Type: text/csv\r\n\r\n{csv}\r\n--{boundary}--\r\n")
            return "".join(parts).encode("utf-8")
        content_type = f"multipart/form-data; boundary={boundary}"
        preview = self.request_bytes("POST", "/api/sbrocor/finance/v1/transactions/import?workspace_id=1", multipart(True), content_type)
        self.assertEqual(preview.status_code, 200, preview.get_data(as_text=True))
        self.assertEqual(preview.json["add"], 1)
        blocked = self.request_bytes("POST", "/api/sbrocor/finance/v1/transactions/import?workspace_id=1", multipart(False), content_type)
        self.assertEqual(blocked.status_code, 400)
        applied = self.request_bytes("POST", "/api/sbrocor/finance/v1/transactions/import?workspace_id=1", multipart(False, "REPLACE TRANSACTIONS"), content_type)
        self.assertEqual(applied.status_code, 200, applied.get_data(as_text=True))
        imported = self.request("GET", "/api/sbrocor/finance/v1/transactions?workspace_id=1")
        self.assertEqual(imported.json["items"][0]["category"], "배송비")

    def test_meta_settings_never_persist_or_return_token(self):
        self.create_workspace(1)
        with patch.dict(os.environ, {"SBROCOR_META_ACCESS_TOKEN_WORKSPACE_1": "server-only-token"}, clear=False):
            saved = self.request("PATCH", "/api/sbrocor/finance/v1/meta/settings?workspace_id=1", {"meta_ad_account_id": "act_fixture", "meta_access_token": "must-ignore"})
            self.assertEqual(saved.json["meta_ad_account_id"], "act_fixture")
            self.assertTrue(saved.json["token_configured"])
            self.assertNotIn("server-only-token", saved.get_data(as_text=True))
            self.assertNotIn("must-ignore", saved.get_data(as_text=True))
        with closing(connect()) as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(workspace_settings)")}
        self.assertNotIn("meta_access_token", columns)

    def test_additive_brand_migration_preserves_existing_product(self):
        legacy_path = Path(self.tempdir.name) / "legacy-finance-v1.db"
        connection = sqlite3.connect(legacy_path)
        connection.executescript("""
            CREATE TABLE workspace(id INTEGER PRIMARY KEY,name TEXT NOT NULL);
            CREATE TABLE product(id INTEGER PRIMARY KEY,workspace_id INTEGER NOT NULL,name TEXT NOT NULL,sku TEXT,cost_price INTEGER NOT NULL,category TEXT,created_at TEXT);
            INSERT INTO workspace(id,name) VALUES (1,'기존 사업장');
            INSERT INTO product(id,workspace_id,name,cost_price) VALUES (10,1,'기존 제품',5000);
        """)
        connection.close()
        initialize_database(legacy_path)
        with closing(connect(legacy_path)) as migrated:
            columns = {row[1] for row in migrated.execute("PRAGMA table_info(product)")}
            product = migrated.execute("SELECT id,name,cost_price,brand_id FROM product WHERE id=10").fetchone()
            tables = {row[0] for row in migrated.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("brand_id", columns)
        self.assertEqual(dict(product), {"id": 10, "name": "기존 제품", "cost_price": 5000, "brand_id": None})
        self.assertTrue({"brand", "marketing_allocation"}.issubset(tables))

    def test_brand_product_and_marketing_allocation_crud_and_summary(self):
        self.create_workspace(1)
        brand_a = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "등원한끼"})
        brand_b = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "NOTE'O"})
        self.assertEqual(brand_a.status_code, 201, brand_a.get_data(as_text=True))
        self.assertEqual(brand_a.json["active"], 1)
        product = self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {
            "id": 10, "name": "바디워시", "cost_price": 1000, "brand_id": brand_b.json["id"],
        })
        self.assertEqual(product.status_code, 201, product.get_data(as_text=True))
        products = self.request("GET", "/api/sbrocor/finance/v1/products?workspace_id=1")
        self.assertEqual(products.json["items"][0]["brand_name"], "NOTE'O")

        for item in (
            {"id": "old-ad", "date": "2026-08-01", "merchant": "과거 광고", "amount": 1000, "category": "광고비"},
            {"id": "single-ad", "date": "2026-08-02", "merchant": "단일 광고", "amount": 2000, "category": "광고비"},
            {"id": "split-ad", "date": "2026-08-03", "merchant": "분할 광고", "amount": 5000, "category": "광고비"},
        ):
            self.assertEqual(self.request("POST", "/api/sbrocor/finance/v1/transactions?workspace_id=1", item).status_code, 201)

        single = self.request("PUT", "/api/sbrocor/finance/v1/transactions/single-ad/marketing-allocations?workspace_id=1", {
            "allocations": [{"brand_id": brand_a.json["id"], "channel": "Meta", "amount": 2000}],
        })
        self.assertEqual(single.status_code, 200, single.get_data(as_text=True))
        self.assertEqual(len(single.json["items"]), 1)

        mismatch = self.request("PUT", "/api/sbrocor/finance/v1/transactions/split-ad/marketing-allocations?workspace_id=1", {
            "allocations": [{"brand_id": brand_a.json["id"], "channel": "Meta", "amount": 4999}],
        })
        self.assertEqual(mismatch.status_code, 400)
        self.assertEqual(self.request("GET", "/api/sbrocor/finance/v1/transactions/split-ad/marketing-allocations?workspace_id=1").json["items"], [])

        split = self.request("PUT", "/api/sbrocor/finance/v1/transactions/split-ad/marketing-allocations?workspace_id=1", {
            "allocations": [
                {"brand_id": brand_a.json["id"], "channel": "Meta", "amount": 3000, "memo": "브랜드 공통"},
                {"brand_id": brand_b.json["id"], "product_id": 10, "channel": "Meta", "amount": 1500},
                {"channel": "기타", "amount": 500},
            ],
        })
        self.assertEqual(split.status_code, 200, split.get_data(as_text=True))
        self.assertEqual(sum(item["amount"] for item in split.json["items"]), 5000)

        summary = self.request("GET", "/api/sbrocor/finance/v1/marketing-allocations/summary?workspace_id=1&month=2026-08")
        self.assertEqual(summary.status_code, 200, summary.get_data(as_text=True))
        self.assertEqual(summary.json["total_advertising_cost"], 8000)
        self.assertEqual(summary.json["allocated_amount"], 7000)
        self.assertEqual(summary.json["unallocated_amount"], 1000)
        self.assertEqual(next(item["amount"] for item in summary.json["brands"] if item["name"] == "등원한끼"), 5000)
        self.assertEqual(next(item["amount"] for item in summary.json["channels"] if item["name"] == "Meta"), 6500)
        self.assertTrue(any(item["name"] == "미지정" and item["amount"] == 1500 for item in summary.json["brands"]))
        self.assertTrue(any(item["name"] == "바디워시" and item["amount"] == 1500 for item in summary.json["products"]))

        deactivated = self.request("PATCH", f"/api/sbrocor/finance/v1/brands/{brand_a.json['id']}?workspace_id=1", {"active": False})
        self.assertEqual(deactivated.json["active"], 0)
        self.assertEqual(self.request("DELETE", f"/api/sbrocor/finance/v1/brands/{brand_a.json['id']}?workspace_id=1").status_code, 400)

    def test_brand_mutation_is_admin_only_and_ad_spend_remains_separate(self):
        self.create_workspace(1)
        employee = {"actor_uid": "employee", "role": "employee", "workspace_ids": [1], "permissions": ["products", "transactions", "dashboard", "ads"]}
        self.assertEqual(self.request("GET", "/api/sbrocor/finance/v1/brands?workspace_id=1", context=employee).status_code, 200)
        self.assertEqual(self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "차단"}, context=employee).status_code, 403)
        self.request("POST", "/api/sbrocor/finance/v1/transactions?workspace_id=1", {"id": "cost", "date": "2026-08-01", "merchant": "Meta", "amount": 1000, "category": "광고비"})
        self.request("POST", "/api/sbrocor/finance/v1/ads?workspace_id=1", {"id": 1, "date": "2026-08-01", "platform": "meta", "spend": 777})
        summary = self.request("GET", "/api/sbrocor/finance/v1/marketing-allocations/summary?workspace_id=1")
        ads = self.request("GET", "/api/sbrocor/finance/v1/ads/analytics?workspace_id=1")
        self.assertEqual(summary.json["total_advertising_cost"], 1000)
        self.assertEqual(ads.json["summary"]["spend"], 777)

    def test_marketing_allocation_requires_product_brand_consistency(self):
        self.create_workspace(1)
        brand_a = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "등원한끼"}).json
        brand_b = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "NOTE'O"}).json
        product_a = self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {
            "id": 21, "name": "등원한끼 제품", "cost_price": 1000, "brand_id": brand_a["id"],
        }).json
        product_b = self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {
            "id": 22, "name": "NOTE'O 제품", "cost_price": 1000, "brand_id": brand_b["id"],
        }).json
        product_without_brand = self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {
            "id": 23, "name": "기존 미지정 제품", "cost_price": 1000,
        }).json

        for transaction_id in ("same-brand", "different-brand", "brandless-product", "brand-common"):
            response = self.request("POST", "/api/sbrocor/finance/v1/transactions?workspace_id=1", {
                "id": transaction_id, "date": "2026-08-24", "merchant": transaction_id,
                "amount": 1000, "category": "광고비",
            })
            self.assertEqual(response.status_code, 201, response.get_data(as_text=True))

        same_brand = self.request("PUT", "/api/sbrocor/finance/v1/transactions/same-brand/marketing-allocations?workspace_id=1", {
            "allocations": [{"brand_id": brand_a["id"], "product_id": product_a["id"], "channel": "Meta", "amount": 1000}],
        })
        self.assertEqual(same_brand.status_code, 200, same_brand.get_data(as_text=True))

        different_brand = self.request("PUT", "/api/sbrocor/finance/v1/transactions/different-brand/marketing-allocations?workspace_id=1", {
            "allocations": [{"brand_id": brand_a["id"], "product_id": product_b["id"], "channel": "Meta", "amount": 1000}],
        })
        self.assertEqual(different_brand.status_code, 400)

        brandless_product = self.request("PUT", "/api/sbrocor/finance/v1/transactions/brandless-product/marketing-allocations?workspace_id=1", {
            "allocations": [{"brand_id": brand_a["id"], "product_id": product_without_brand["id"], "channel": "Meta", "amount": 1000}],
        })
        self.assertEqual(brandless_product.status_code, 400)

        brand_common = self.request("PUT", "/api/sbrocor/finance/v1/transactions/brand-common/marketing-allocations?workspace_id=1", {
            "allocations": [{"brand_id": brand_a["id"], "product_id": None, "channel": "Meta", "amount": 1000}],
        })
        self.assertEqual(brand_common.status_code, 200, brand_common.get_data(as_text=True))

    def test_additive_reinitialize_preserves_transaction_sale_and_ad_spend(self):
        self.create_workspace(1)
        self.request("POST", "/api/sbrocor/finance/v1/transactions?workspace_id=1", {"id": "tx", "date": "2026-08-01", "merchant": "Meta", "amount": 1234, "category": "광고비"})
        self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {"id": 1, "name": "제품", "cost_price": 50})
        self.request("POST", "/api/sbrocor/finance/v1/platforms?workspace_id=1", {"id": 1, "name": "채널", "commission_rate": 10})
        self.request("POST", "/api/sbrocor/finance/v1/sales?workspace_id=1", {"id": "sale", "date": "2026-08-01", "product_id": 1, "platform_id": 1, "selling_price": 500, "quantity": 2, "total_selling_amount": 500, "total_cost_amount": 100, "commission_amount": 50, "net_profit": 350})
        self.request("POST", "/api/sbrocor/finance/v1/ads?workspace_id=1", {"id": 1, "date": "2026-08-01", "platform": "meta", "spend": 777})
        with closing(connect()) as connection:
            before = {
                "transaction": tuple(connection.execute("SELECT amount,category FROM finance_transaction WHERE id='tx'").fetchone()),
                "sale": tuple(connection.execute("SELECT total_selling_amount,total_cost_amount,commission_amount,net_profit FROM sale WHERE id='sale'").fetchone()),
                "ad_spend": tuple(connection.execute("SELECT spend FROM ad_spend WHERE id=1").fetchone()),
            }
        initialize_database()
        with closing(connect()) as connection:
            after = {
                "transaction": tuple(connection.execute("SELECT amount,category FROM finance_transaction WHERE id='tx'").fetchone()),
                "sale": tuple(connection.execute("SELECT total_selling_amount,total_cost_amount,commission_amount,net_profit FROM sale WHERE id='sale'").fetchone()),
                "ad_spend": tuple(connection.execute("SELECT spend FROM ad_spend WHERE id=1").fetchone()),
            }
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM marketing_allocation").fetchone()[0], 0)
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()

