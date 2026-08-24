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

    def multipart_import(self, filename, content, mode, dry_run, confirmation=None):
        boundary = f"----financefixture{uuid.uuid4().hex}"
        fields = [("mode", mode), ("dry_run", str(dry_run).lower())]
        if confirmation:
            fields.append(("confirmation", confirmation))
        parts = []
        for name, value in fields:
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
            f"Content-Type: text/csv\r\n\r\n{content}\r\n--{boundary}--\r\n"
        )
        return "".join(parts).encode("utf-8"), f"multipart/form-data; boundary={boundary}"

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

    def test_business_daily_sales_aggregates_products_channels_and_workspace(self):
        self.create_workspace(1)
        self.create_workspace(2)
        for product in (
            {"workspace": 1, "id": 11, "name": "식이섬균", "cost_price": 100},
            {"workspace": 1, "id": 12, "name": "배도라지즙", "cost_price": 200},
            {"workspace": 2, "id": 21, "name": "다른 사업장 제품", "cost_price": 300},
        ):
            self.request("POST", f"/api/sbrocor/finance/v1/products?workspace_id={product['workspace']}", {
                "id": product["id"], "name": product["name"], "cost_price": product["cost_price"],
            })
        for platform in (
            {"workspace": 1, "id": 11, "name": "스마트스토어"},
            {"workspace": 1, "id": 12, "name": "카페24"},
            {"workspace": 2, "id": 21, "name": "다른 채널"},
        ):
            self.request("POST", f"/api/sbrocor/finance/v1/platforms?workspace_id={platform['workspace']}", {
                "id": platform["id"], "name": platform["name"], "commission_rate": 0,
            })
        sales = (
            {"id": "a", "workspace": 1, "date": "2026-08-24", "product_id": 11, "platform_id": 11, "quantity": 2, "amount": 2000, "profit": 1600},
            {"id": "b", "workspace": 1, "date": "2026-08-24", "product_id": 11, "platform_id": 12, "quantity": 3, "amount": 3300, "profit": 2700},
            {"id": "c", "workspace": 1, "date": "2026-08-24", "product_id": 12, "platform_id": 11, "quantity": 1, "amount": 1500, "profit": 1200},
            {"id": "older", "workspace": 1, "date": "2026-08-23", "product_id": 11, "platform_id": 11, "quantity": 9, "amount": 9000, "profit": 7000},
            {"id": "isolated", "workspace": 2, "date": "2026-08-24", "product_id": 21, "platform_id": 21, "quantity": 99, "amount": 99000, "profit": 90000},
        )
        for sale in sales:
            self.request("POST", f"/api/sbrocor/finance/v1/sales?workspace_id={sale['workspace']}", {
                "id": sale["id"], "date": sale["date"], "product_id": sale["product_id"], "platform_id": sale["platform_id"],
                "selling_price": sale["amount"], "quantity": sale["quantity"], "total_selling_amount": sale["amount"],
                "total_cost_amount": 0, "commission_amount": 0, "net_profit": sale["profit"],
            })

        details = self.request("GET", "/api/sbrocor/finance/v1/business/date-details?workspace_id=1&date=2026-08-24")
        self.assertEqual(details.status_code, 200, details.get_data(as_text=True))
        self.assertEqual(len(details.json["items"]), 3)
        self.assertEqual((details.json["total_quantity"], details.json["total_sales"], details.json["total_profit"]), (6, 6800, 5500))
        self.assertEqual([row["product_name"] for row in details.json["products"]], ["식이섬균", "배도라지즙"])
        self.assertEqual(details.json["products"][0]["quantity"], 5)
        self.assertEqual(details.json["products"][0]["sales"], 5300)
        self.assertEqual(details.json["products"][0]["net_profit"], 4300)
        self.assertEqual([row["platform_name"] for row in details.json["products"][0]["channels"]], ["카페24", "스마트스토어"])
        self.assertEqual(sum(row["quantity"] for row in details.json["products"][0]["channels"]), 5)

        period = self.request("GET", "/api/sbrocor/finance/v1/business?workspace_id=1&start_date=2026-08-23&end_date=2026-08-24")
        self.assertEqual(period.json["total_quantity"], 15)
        self.assertEqual([row["date"] for row in period.json["daily_sales"]], ["2026-08-23", "2026-08-24"])
        isolated = self.request("GET", "/api/sbrocor/finance/v1/business/date-details?workspace_id=2&date=2026-08-24")
        self.assertEqual((isolated.json["total_quantity"], isolated.json["total_sales"]), (99, 99000))
        self.assertNotIn("식이섬균", isolated.get_data(as_text=True))

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

    def test_transaction_import_append_replace_and_admin_safety(self):
        self.create_workspace(1)
        self.request("POST", "/api/sbrocor/finance/v1/categories?workspace_id=1", {"id": 1, "keyword": "택배", "category": "배송비"})
        self.request("POST", "/api/sbrocor/finance/v1/transactions?workspace_id=1", {
            "id": "existing", "date": "2026-07-31", "merchant": "기존 거래", "amount": 500, "category": "기타",
        })
        csv = "날짜,거래처명,금액\r\n2026-08-01,대한택배,1200\r\n"
        path = "/api/sbrocor/finance/v1/transactions/import?workspace_id=1"

        body, content_type = self.multipart_import("transactions.csv", csv, "append", True)
        preview = self.request_bytes("POST", path, body, content_type)
        self.assertEqual(preview.status_code, 200, preview.get_data(as_text=True))
        self.assertEqual(preview.json["existing"], 1)
        self.assertEqual(preview.json["add"], 1)
        self.assertEqual(len(self.request("GET", "/api/sbrocor/finance/v1/transactions?workspace_id=1").json["items"]), 1)

        body, content_type = self.multipart_import("transactions.csv", csv, "append", False)
        applied_append = self.request_bytes("POST", path, body, content_type)
        self.assertEqual(applied_append.status_code, 200, applied_append.get_data(as_text=True))
        self.assertEqual(len(self.request("GET", "/api/sbrocor/finance/v1/transactions?workspace_id=1").json["items"]), 2)

        employee = {"actor_uid": "employee", "role": "employee", "workspace_ids": [1], "permissions": ["transactions"]}
        body, content_type = self.multipart_import("transactions.csv", csv, "replace", True)
        denied = self.request_bytes("POST", path, body, content_type, context=employee)
        self.assertEqual(denied.status_code, 403)

        body, content_type = self.multipart_import("transactions.csv", csv, "replace", True)
        replace_preview = self.request_bytes("POST", path, body, content_type)
        self.assertEqual(replace_preview.status_code, 200, replace_preview.get_data(as_text=True))
        self.assertEqual((replace_preview.json["existing"], replace_preview.json["delete"], replace_preview.json["add"]), (2, 2, 1))

        body, content_type = self.multipart_import("transactions.csv", csv, "replace", False)
        blocked = self.request_bytes("POST", path, body, content_type)
        self.assertEqual(blocked.status_code, 400)
        self.assertEqual(len(self.request("GET", "/api/sbrocor/finance/v1/transactions?workspace_id=1").json["items"]), 2)

        body, content_type = self.multipart_import("transactions.csv", csv, "replace", False, "REPLACE TRANSACTIONS")
        applied = self.request_bytes("POST", path, body, content_type)
        self.assertEqual(applied.status_code, 200, applied.get_data(as_text=True))
        imported = self.request("GET", "/api/sbrocor/finance/v1/transactions?workspace_id=1")
        self.assertEqual(len(imported.json["items"]), 1)
        self.assertEqual(imported.json["items"][0]["category"], "배송비")

    def test_sale_import_append_replace_and_admin_safety(self):
        self.create_workspace(1)
        self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {"id": 1, "name": "제품", "cost_price": 400})
        self.request("POST", "/api/sbrocor/finance/v1/platforms?workspace_id=1", {"id": 1, "name": "채널", "commission_rate": 10})
        self.request("POST", "/api/sbrocor/finance/v1/sales?workspace_id=1", {
            "id": "existing", "date": "2026-07-31", "product_id": 1, "platform_id": 1,
            "selling_price": 1000, "quantity": 1, "total_selling_amount": 1000,
            "total_cost_amount": 400, "commission_amount": 100, "net_profit": 500,
        })
        csv = "판매일,제품명,판매채널,실제판매가,수량\r\n2026-08-02,제품,채널,2000,2\r\n"
        path = "/api/sbrocor/finance/v1/sales/import?workspace_id=1"

        body, content_type = self.multipart_import("sales.csv", csv, "append", True)
        preview = self.request_bytes("POST", path, body, content_type)
        self.assertEqual(preview.status_code, 200, preview.get_data(as_text=True))
        self.assertEqual((preview.json["existing"], preview.json["add"]), (1, 1))
        self.assertEqual(len(self.request("GET", "/api/sbrocor/finance/v1/sales?workspace_id=1").json["items"]), 1)

        body, content_type = self.multipart_import("sales.csv", csv, "append", False)
        applied_append = self.request_bytes("POST", path, body, content_type)
        self.assertEqual(applied_append.status_code, 200, applied_append.get_data(as_text=True))
        self.assertEqual(len(self.request("GET", "/api/sbrocor/finance/v1/sales?workspace_id=1").json["items"]), 2)

        employee = {"actor_uid": "employee", "role": "employee", "workspace_ids": [1], "permissions": ["sales"]}
        body, content_type = self.multipart_import("sales.csv", csv, "replace", True)
        denied = self.request_bytes("POST", path, body, content_type, context=employee)
        self.assertEqual(denied.status_code, 403)

        body, content_type = self.multipart_import("sales.csv", csv, "replace", True)
        replace_preview = self.request_bytes("POST", path, body, content_type)
        self.assertEqual(replace_preview.status_code, 200, replace_preview.get_data(as_text=True))
        self.assertEqual((replace_preview.json["existing"], replace_preview.json["delete"], replace_preview.json["add"]), (2, 2, 1))

        body, content_type = self.multipart_import("sales.csv", csv, "replace", False)
        blocked = self.request_bytes("POST", path, body, content_type)
        self.assertEqual(blocked.status_code, 400)
        self.assertEqual(len(self.request("GET", "/api/sbrocor/finance/v1/sales?workspace_id=1").json["items"]), 2)

        body, content_type = self.multipart_import("sales.csv", csv, "replace", False, "REPLACE SALES")
        applied = self.request_bytes("POST", path, body, content_type)
        self.assertEqual(applied.status_code, 200, applied.get_data(as_text=True))
        imported = self.request("GET", "/api/sbrocor/finance/v1/sales?workspace_id=1")
        self.assertEqual(len(imported.json["items"]), 1)
        self.assertEqual(imported.json["items"][0]["total_selling_amount"], 2000)

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

    def test_sales_analysis_compares_periods_attribution_and_workspace_scope(self):
        self.create_workspace(1); self.create_workspace(2, "Other")
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "등원한끼"}).json
        for product_id, name in ((11, "제품 A"), (12, "제품 B")):
            self.assertEqual(self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {
                "id": product_id, "name": name, "cost_price": 10, "brand_id": brand["id"],
            }).status_code, 201)
        self.request("POST", "/api/sbrocor/finance/v1/platforms?workspace_id=1", {"id": 21, "name": "자사몰", "commission_rate": 0})
        sales = (
            ("a1", "2026-08-01", 11, 10, 1000, 400), ("a2", "2026-08-02", 12, 5, 500, 200),
            ("b1", "2026-08-10", 11, 15, 1800, 700), ("b2", "2026-08-13", 12, 4, 400, 150),
        )
        for sale_id, day, product_id, quantity, revenue, profit in sales:
            response = self.request("POST", "/api/sbrocor/finance/v1/sales?workspace_id=1", {
                "id": sale_id, "date": day, "product_id": product_id, "platform_id": 21,
                "selling_price": revenue // quantity, "quantity": quantity,
                "total_selling_amount": revenue, "total_cost_amount": revenue - profit,
                "commission_amount": 0, "net_profit": profit,
            })
            self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        ads = (
            ("a-direct", "2026-08-01", 100, 11, "Meta"), ("a-common", "2026-08-02", 50, None, "네이버"),
            ("a-unallocated", "2026-08-02", 30, "none", None),
            ("b-direct", "2026-08-10", 200, 11, "Meta"), ("b-common", "2026-08-11", 100, None, "네이버"),
            ("b-unallocated", "2026-08-12", 50, "none", None),
        )
        for transaction_id, day, amount, product_id, channel in ads:
            self.request("POST", "/api/sbrocor/finance/v1/transactions?workspace_id=1", {
                "id": transaction_id, "date": day, "merchant": transaction_id, "amount": amount, "category": "광고비",
            })
            if product_id != "none":
                allocation = {"brand_id": brand["id"], "product_id": product_id, "channel": channel, "amount": amount}
                saved = self.request("PUT", f"/api/sbrocor/finance/v1/transactions/{transaction_id}/marketing-allocations?workspace_id=1", {"allocations": [allocation]})
                self.assertEqual(saved.status_code, 200, saved.get_data(as_text=True))
        with closing(connect()) as connection:
            account_id = connection.execute(
                """INSERT INTO ad_account_connection
                   (workspace_id,brand_id,platform,account_id,account_name,currency,credential_key,active)
                   VALUES (1,?,'meta','act-analysis','분석 계정','KRW','ANALYSIS',1)""",
                (brand["id"],),
            ).lastrowid
            for external_key, day, amount, product_id, channel in (
                ("a-direct", "2026-08-01", 100, 11, "Meta"),
                ("a-common", "2026-08-02", 50, None, "네이버"),
                ("b-direct", "2026-08-10", 200, 11, "Meta"),
                ("b-common", "2026-08-11", 100, None, "네이버"),
                ("b-zero-12", "2026-08-12", 0, None, "Meta"),
                ("b-zero-13", "2026-08-13", 0, None, "Meta"),
            ):
                connection.execute(
                    """INSERT INTO marketing_spend
                       (workspace_id,ad_account_connection_id,brand_id,product_id,date,channel,
                        original_amount,currency,fx_rate,amount_krw,source,external_key)
                       VALUES (1,?,?,?,?,?,?, 'KRW',1,?,'meta',?)""",
                    (account_id, brand["id"], product_id, day, channel, amount, amount, external_key),
                )
            connection.commit()
        # Large rows in another workspace must never leak into workspace 1.
        self.request("POST", "/api/sbrocor/finance/v1/transactions?workspace_id=2", {
            "id": "other-ad", "date": "2026-08-01", "merchant": "other", "amount": 999999, "category": "광고비",
        })

        path = ("/api/sbrocor/finance/v1/sales-analysis/compare?workspace_id=1"
                "&a_start=2026-08-01&a_end=2026-08-02&b_start=2026-08-10&b_end=2026-08-13"
                f"&brand_id={brand['id']}")
        response = self.request("GET", path)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.json; a = payload["periods"]["a"]["totals"]; b = payload["periods"]["b"]["totals"]
        self.assertEqual((a["revenue"], b["revenue"]), (1500, 2200))
        self.assertEqual((a["quantity"], b["quantity"]), (15, 19))
        self.assertEqual((a["sales_profit"], b["sales_profit"]), (600, 850))
        self.assertEqual((a["advertising_cost"], b["advertising_cost"]), (150, 300))
        self.assertEqual((a["paid_advertising_cost"], b["paid_advertising_cost"]), (150, 300))
        self.assertEqual((a["direct_advertising_cost"], a["brand_common_advertising_cost"]), (100, 50))
        self.assertEqual((a["profit_after_advertising"], b["profit_after_advertising"]), (450, 550))
        self.assertEqual((a["unallocated_advertising_cost"], b["unallocated_advertising_cost"]), (30, 50))
        self.assertAlmostEqual(a["classification_rate"], 150 / 180 * 100)
        self.assertEqual((a["days"], b["days"]), (2, 4))
        self.assertEqual((a["daily_average_revenue"], b["daily_average_revenue"]), (750, 550))
        self.assertEqual(len(payload["periods"]["b"]["daily"]), 4)
        self.assertEqual({item["name"]: item["amount"] for item in payload["periods"]["a"]["channels"]}, {"Meta": 100, "네이버": 50})
        product_a = next(item for item in payload["products"] if item["id"] == 11)
        product_b = next(item for item in payload["products"] if item["id"] == 12)
        self.assertEqual(product_a["periods"]["a"]["direct_advertising_cost"], 100)
        self.assertEqual(product_a["periods"]["b"]["profit_after_advertising"], 500)
        self.assertFalse(product_b["periods"]["a"]["direct_advertising_available"])
        self.assertIsNone(product_b["periods"]["a"]["profit_after_advertising"])

        product_path = path + "&product_id=11"
        product_payload = self.request("GET", product_path).json
        product_a_totals = product_payload["periods"]["a"]["totals"]
        self.assertEqual(product_a_totals["advertising_cost"], 100)
        self.assertEqual(product_a_totals["brand_common_advertising_cost"], 50)
        self.assertEqual(product_a_totals["profit_after_advertising"], 300)
        product_b_payload = self.request("GET", path + "&product_id=12").json
        self.assertFalse(product_b_payload["periods"]["a"]["totals"]["spend_analysis_ready"])
        self.assertIsNone(product_b_payload["periods"]["a"]["totals"]["profit_after_advertising"])

        employee = {"actor_uid": "employee", "role": "employee", "workspace_ids": [2], "permissions": ["business_dashboard"]}
        denied = self.request("GET", path, context=employee)
        self.assertEqual(denied.status_code, 403)

    def test_schema_v3_is_additive_idempotent_and_preserves_financial_totals(self):
        self.create_workspace(1)
        self.request("POST", "/api/sbrocor/finance/v1/transactions?workspace_id=1", {"id": "tx-v3", "date": "2026-08-01", "merchant": "광고 결제", "amount": 1234, "category": "광고비"})
        self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {"id": 91, "name": "제품", "cost_price": 100})
        self.request("POST", "/api/sbrocor/finance/v1/platforms?workspace_id=1", {"id": 92, "name": "채널", "commission_rate": 0})
        self.request("POST", "/api/sbrocor/finance/v1/sales?workspace_id=1", {"id": "sale-v3", "date": "2026-08-01", "product_id": 91, "platform_id": 92, "selling_price": 1000, "quantity": 1, "total_selling_amount": 1000, "total_cost_amount": 100, "commission_amount": 0, "net_profit": 900})
        self.request("POST", "/api/sbrocor/finance/v1/ads?workspace_id=1", {"id": 93, "date": "2026-08-01", "platform": "meta", "spend": 777})
        with closing(connect()) as connection:
            before = tuple(connection.execute("SELECT (SELECT COUNT(*) FROM finance_transaction),(SELECT COUNT(*) FROM sale),(SELECT COUNT(*) FROM ad_spend),(SELECT COUNT(*) FROM product),(SELECT SUM(amount) FROM finance_transaction),(SELECT SUM(total_selling_amount) FROM sale),(SELECT SUM(net_profit) FROM sale)").fetchone())
            # Rehearse the real additive path from a v2-shaped database: retain
            # every financial row while removing only the v3 schema additions.
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.executescript("""
                DROP INDEX IF EXISTS ix_marketing_spend_workspace_date;
                DROP INDEX IF EXISTS ix_marketing_spend_brand_date;
                DROP INDEX IF EXISTS ix_ad_account_workspace_brand;
                DROP TABLE marketing_spend;
                CREATE TABLE ad_spend_v2 (
                    id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspace(id) ON DELETE RESTRICT,
                    date TEXT NOT NULL, platform TEXT NOT NULL DEFAULT 'meta', campaign_id TEXT, campaign_name TEXT,
                    adset_id TEXT, adset_name TEXT, ad_id TEXT, ad_name TEXT, spend REAL NOT NULL DEFAULT 0,
                    impressions INTEGER NOT NULL DEFAULT 0, clicks INTEGER NOT NULL DEFAULT 0, ctr REAL NOT NULL DEFAULT 0,
                    cpc REAL NOT NULL DEFAULT 0, cpm REAL NOT NULL DEFAULT 0, conversions INTEGER NOT NULL DEFAULT 0,
                    conversion_value REAL NOT NULL DEFAULT 0, roas REAL NOT NULL DEFAULT 0, created_at TEXT,
                    UNIQUE(workspace_id, date, platform, ad_id)
                );
                INSERT INTO ad_spend_v2
                    (id,workspace_id,date,platform,campaign_id,campaign_name,adset_id,adset_name,ad_id,ad_name,
                     spend,impressions,clicks,ctr,cpc,cpm,conversions,conversion_value,roas,created_at)
                SELECT id,workspace_id,date,platform,campaign_id,campaign_name,adset_id,adset_name,ad_id,ad_name,
                       spend,impressions,clicks,ctr,cpc,cpm,conversions,conversion_value,roas,created_at
                FROM ad_spend;
                DROP TABLE ad_spend;
                ALTER TABLE ad_spend_v2 RENAME TO ad_spend;
                DROP TABLE ad_account_connection;
                DELETE FROM schema_version WHERE version=3;
                INSERT OR IGNORE INTO schema_version(version) VALUES (2);
            """)
            connection.commit()
        initialize_database(); initialize_database()
        with closing(connect()) as connection:
            after = tuple(connection.execute("SELECT (SELECT COUNT(*) FROM finance_transaction),(SELECT COUNT(*) FROM sale),(SELECT COUNT(*) FROM ad_spend),(SELECT COUNT(*) FROM product),(SELECT SUM(amount) FROM finance_transaction),(SELECT SUM(total_selling_amount) FROM sale),(SELECT SUM(net_profit) FROM sale)").fetchone())
            self.assertEqual(connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 3)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            ad_columns = {row[1] for row in connection.execute("PRAGMA table_info(ad_spend)")}
        self.assertEqual(before, after)
        self.assertTrue({"ad_account_connection", "marketing_spend"}.issubset(tables))
        self.assertTrue({"ad_account_connection_id", "brand_id"}.issubset(ad_columns))

    def test_multi_ad_account_sync_is_idempotent_and_drives_actual_spend_analysis(self):
        self.create_workspace(1)
        brand_a = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "파파랑"}).json
        brand_b = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "건강비서"}).json
        with patch.dict(os.environ, {
            "SBROCOR_META_ACCESS_TOKEN_META_MAIN": "shared-server-secret",
            "SBROCOR_META_ACCESS_TOKEN_META_HEALTH": "different-server-secret",
        }, clear=False):
            account_a = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {"brand_id": brand_a["id"], "platform": "meta", "account_id": "act_111", "account_name": "파파랑 Meta", "currency": "KRW", "credential_key": "META_MAIN"})
            account_b = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {"brand_id": brand_b["id"], "platform": "meta", "account_id": "act_222", "account_name": "건강비서 Meta", "currency": "KRW", "credential_key": "META_MAIN"})
            self.assertTrue(account_a.json["credential_configured"])
            self.assertTrue(account_b.json["credential_configured"])
            self.assertNotIn("shared-server-secret", account_a.get_data(as_text=True))
            renamed = self.request("PATCH", f"/api/sbrocor/finance/v1/ad-accounts/{account_b.json['id']}?workspace_id=1", {"account_name": "건강비서 Meta 수정"})
            self.assertEqual(renamed.status_code, 200)
            self.assertEqual(renamed.json["account_name"], "건강비서 Meta 수정")

            responses = {
                "act_111": [
                    {"date_start": "2026-08-01", "ad_id": "a-1", "spend": "100000"},
                    {"date_start": "2026-08-02", "ad_id": "a-2", "spend": "200000"},
                ],
                "act_222": [
                    {"date_start": "2026-08-01", "ad_id": "b-1", "spend": "300000"},
                    {"date_start": "2026-08-02", "ad_id": "b-2", "spend": "400000"},
                ],
            }
            class FakeResponse:
                def __init__(self, items): self.items = items
                def raise_for_status(self): return None
                def json(self): return {"data": self.items}
            def fake_get(url, **_kwargs):
                account_id = next(key for key in responses if key in url)
                return FakeResponse(responses[account_id])
            payload = {"start_date": "2026-08-01", "end_date": "2026-08-02"}
            with patch("sbrocor_finance.routes.requests.get", side_effect=fake_get):
                first = self.request("POST", f"/api/sbrocor/finance/v1/ad-accounts/{account_a.json['id']}/sync?workspace_id=1", payload)
                repeated = self.request("POST", f"/api/sbrocor/finance/v1/ad-accounts/{account_a.json['id']}/sync?workspace_id=1", payload)
                second = self.request("POST", f"/api/sbrocor/finance/v1/ad-accounts/{account_b.json['id']}/sync?workspace_id=1", payload)
            self.assertEqual((first.status_code, repeated.status_code, second.status_code), (200, 200, 200))

        self.request("POST", "/api/sbrocor/finance/v1/transactions?workspace_id=1", {"id": "paid", "date": "2026-08-01", "merchant": "Meta 결제", "amount": 123000, "category": "광고비"})
        with closing(connect()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM marketing_spend").fetchone()[0], 4)
            self.assertEqual(connection.execute("SELECT SUM(amount_krw) FROM marketing_spend").fetchone()[0], 1000000)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM ad_spend").fetchone()[0], 4)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM marketing_spend WHERE original_amount=0").fetchone()[0], 0)
        base = "/api/sbrocor/finance/v1/sales-analysis/compare?workspace_id=1&a_start=2026-08-01&a_end=2026-08-02&b_start=2026-08-01&b_end=2026-08-02"
        workspace = self.request("GET", base).json["periods"]["a"]["totals"]
        a = self.request("GET", base + f"&brand_id={brand_a['id']}").json["periods"]["a"]["totals"]
        b = self.request("GET", base + f"&brand_id={brand_b['id']}").json["periods"]["a"]["totals"]
        self.assertEqual(workspace["actual_advertising_spend"], 1000000)
        self.assertEqual(a["actual_advertising_spend"], 300000)
        self.assertEqual(b["actual_advertising_spend"], 700000)
        self.assertEqual(workspace["paid_advertising_cost"], 123000)
        self.assertEqual(workspace["spend_coverage"], {
            "account_days_expected": 4, "account_days_synced": 4,
            "days_expected": 4, "days_synced": 4, "complete": True, "account_count": 2,
        })
        self.assertTrue(workspace["spend_analysis_ready"])
        self.assertEqual(workspace["revenue_per_ad_won"], 0)
        self.assertEqual(workspace["quantity_per_10000_ad_spend"], 0)

    def test_zero_spend_coverage_non_krw_and_ad_account_permissions(self):
        self.create_workspace(1)
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "등원한끼"}).json
        employee = {"actor_uid": "employee", "role": "employee", "workspace_ids": [1], "permissions": ["ads"]}
        denied = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {"brand_id": brand["id"], "platform": "meta", "account_id": "act_denied", "account_name": "denied", "currency": "KRW", "credential_key": "META_MAIN"}, context=employee)
        self.assertEqual(denied.status_code, 403)
        self.create_workspace(2, "다른 사업장")
        other_brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=2", {"name": "다른 브랜드"}).json
        mismatch = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {"brand_id": other_brand["id"], "platform": "meta", "account_id": "act_mismatch", "account_name": "mismatch", "currency": "KRW", "credential_key": "META_MAIN"})
        self.assertEqual(mismatch.status_code, 400)
        with patch.dict(os.environ, {"SBROCOR_META_ACCESS_TOKEN_META_USD": "server-secret"}, clear=False):
            account = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {"brand_id": brand["id"], "platform": "meta", "account_id": "act_usd", "account_name": "USD Meta", "currency": "USD", "credential_key": "META_USD"}).json
            class EmptyResponse:
                def raise_for_status(self): return None
                def json(self): return {"data": []}
            with patch("sbrocor_finance.routes.requests.get", return_value=EmptyResponse()):
                synced = self.request("POST", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/sync?workspace_id=1", {"start_date": "2026-08-01", "end_date": "2026-08-02"})
        self.assertEqual(synced.status_code, 200)
        with closing(connect()) as connection:
            rows = connection.execute("SELECT original_amount,currency,amount_krw FROM marketing_spend ORDER BY date").fetchall()
        self.assertEqual([tuple(row) for row in rows], [(0.0, "USD", None), (0.0, "USD", None)])
        path = "/api/sbrocor/finance/v1/sales-analysis/compare?workspace_id=1&a_start=2026-08-01&a_end=2026-08-02&b_start=2026-08-01&b_end=2026-08-02"
        totals = self.request("GET", path).json["periods"]["a"]["totals"]
        self.assertTrue(totals["spend_coverage"]["complete"])
        self.assertFalse(totals["currency_complete"])
        self.assertFalse(totals["spend_analysis_ready"])
        self.assertIsNone(totals["actual_advertising_spend"])
        self.assertIsNone(totals["profit_after_advertising"])
        self.assertEqual(totals["unconverted_currencies"], ["USD"])

    def test_sales_analysis_is_unavailable_without_accounts_or_complete_coverage(self):
        self.create_workspace(1)
        path = ("/api/sbrocor/finance/v1/sales-analysis/compare?workspace_id=1"
                "&a_start=2026-08-01&a_end=2026-08-02&b_start=2026-08-01&b_end=2026-08-02")
        no_account = self.request("GET", path).json["periods"]["a"]["totals"]
        self.assertFalse(no_account["spend_analysis_ready"])
        self.assertFalse(no_account["spend_coverage"]["complete"])
        self.assertIsNone(no_account["actual_advertising_spend"])
        self.assertIsNone(no_account["profit_after_advertising"])

        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "브랜드"}).json
        with patch.dict(os.environ, {"SBROCOR_META_ACCESS_TOKEN_INCOMPLETE": "server-secret"}, clear=False):
            account = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {
                "brand_id": brand["id"], "platform": "meta", "account_id": "act_incomplete",
                "account_name": "불완전", "currency": "KRW", "credential_key": "INCOMPLETE",
            }).json
        with closing(connect()) as connection:
            connection.execute(
                "INSERT INTO marketing_spend(workspace_id,ad_account_connection_id,brand_id,date,channel,original_amount,currency,amount_krw,source,external_key) VALUES (1,?,?,?,'Meta',100,'KRW',100,'test','partial')",
                (account["id"], brand["id"], "2026-08-01"),
            )
            connection.commit()
        incomplete = self.request("GET", path).json["periods"]["a"]["totals"]
        self.assertEqual(incomplete["spend_coverage"]["account_days_expected"], 2)
        self.assertEqual(incomplete["spend_coverage"]["account_days_synced"], 1)
        self.assertFalse(incomplete["spend_analysis_ready"])
        self.assertIsNone(incomplete["actual_advertising_spend"])

    def test_meta_sync_follows_all_pages_and_remains_idempotent(self):
        self.create_workspace(1)
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "페이지 브랜드"}).json
        with patch.dict(os.environ, {"SBROCOR_META_ACCESS_TOKEN_PAGED": "server-secret"}, clear=False):
            account = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {
                "brand_id": brand["id"], "platform": "meta", "account_id": "act_paged",
                "account_name": "페이지 계정", "currency": "KRW", "credential_key": "PAGED",
            }).json
            class FakeResponse:
                def __init__(self, payload): self.payload = payload
                def raise_for_status(self): return None
                def json(self): return self.payload
            def fake_get(url, **_kwargs):
                if url == "https://meta.example/page-2":
                    return FakeResponse({"data": [{"date_start": "2026-08-01", "ad_id": "page-2", "spend": "200000"}]})
                return FakeResponse({
                    "data": [{"date_start": "2026-08-01", "ad_id": "page-1", "spend": "100000"}],
                    "paging": {"next": "https://meta.example/page-2"},
                })
            payload = {"start_date": "2026-08-01", "end_date": "2026-08-01"}
            with patch("sbrocor_finance.routes.requests.get", side_effect=fake_get):
                first = self.request("POST", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/sync?workspace_id=1", payload)
                second = self.request("POST", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/sync?workspace_id=1", payload)
        self.assertEqual((first.status_code, second.status_code), (200, 200))
        self.assertEqual(first.json["raw_saved"], 2)
        with closing(connect()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM ad_spend").fetchone()[0], 2)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM marketing_spend").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT SUM(amount_krw) FROM marketing_spend").fetchone()[0], 300000)

    def test_meta_sync_page_failure_does_not_record_partial_completion(self):
        self.create_workspace(1)
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "실패 브랜드"}).json
        with patch.dict(os.environ, {"SBROCOR_META_ACCESS_TOKEN_FAILPAGE": "server-secret"}, clear=False):
            account = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {
                "brand_id": brand["id"], "platform": "meta", "account_id": "act_failpage",
                "account_name": "실패 계정", "currency": "KRW", "credential_key": "FAILPAGE",
            }).json
            class FirstPage:
                def raise_for_status(self): return None
                def json(self): return {"data": [{"date_start": "2026-08-01", "ad_id": "partial", "spend": "100000"}], "paging": {"next": "https://meta.example/fail"}}
            def fake_get(url, **_kwargs):
                if url == "https://meta.example/fail":
                    raise RuntimeError("simulated page failure")
                return FirstPage()
            with patch("sbrocor_finance.routes.requests.get", side_effect=fake_get):
                with self.assertRaisesRegex(RuntimeError, "simulated page failure"):
                    self.request("POST", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/sync?workspace_id=1", {"start_date": "2026-08-01", "end_date": "2026-08-01"})
        with closing(connect()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM ad_spend").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM marketing_spend").fetchone()[0], 0)
            self.assertIsNone(connection.execute("SELECT last_synced_at FROM ad_account_connection WHERE id=?", (account["id"],)).fetchone()[0])


if __name__ == "__main__":
    unittest.main()

