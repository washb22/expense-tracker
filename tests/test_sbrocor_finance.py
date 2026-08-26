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

import requests
from flask import Flask

from sbrocor_finance import finance_blueprint
from sbrocor_finance import database as finance_database
from sbrocor_finance.auth import sign_request
from sbrocor_finance.config import FinanceConfigurationError, get_finance_database_path
from sbrocor_finance.database import connect, initialize_database
from sbrocor_finance.repository import FinanceRepository
from sbrocor_finance.service import FinanceService
from sbrocor_finance.naver_search_ads import Credentials, NaverApiError, NaverSearchAdsClient, generate_signature, parse_ad_report_cost, parse_ad_report_campaign_costs, parse_ad_report_adgroup_costs
from ops import cleanup_legacy_naver_spend


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
                DELETE FROM schema_version WHERE version>2;
                INSERT OR IGNORE INTO schema_version(version) VALUES (2);
            """)
            connection.commit()
        initialize_database(); initialize_database()
        with closing(connect()) as connection:
            after = tuple(connection.execute("SELECT (SELECT COUNT(*) FROM finance_transaction),(SELECT COUNT(*) FROM sale),(SELECT COUNT(*) FROM ad_spend),(SELECT COUNT(*) FROM product),(SELECT SUM(amount) FROM finance_transaction),(SELECT SUM(total_selling_amount) FROM sale),(SELECT SUM(net_profit) FROM sale)").fetchone())
            self.assertEqual(connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 8)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            ad_columns = {row[1] for row in connection.execute("PRAGMA table_info(ad_spend)")}
        self.assertEqual(before, after)
        self.assertTrue({"ad_account_connection", "marketing_spend"}.issubset(tables))
        self.assertTrue({"ad_account_connection_id", "brand_id"}.issubset(ad_columns))

    def test_schema_v4_rehearsal_from_v3_is_idempotent_and_preserves_all_rows(self):
        self.create_workspace(1)
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "v4"}).json
        account = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {"brand_id": brand["id"], "platform": "meta", "account_id": "act_v4", "account_name": "v4", "currency": "KRW", "credential_key": "V4"}).json
        with closing(connect()) as connection:
            connection.execute("INSERT INTO marketing_spend(workspace_id,ad_account_connection_id,brand_id,date,channel,original_amount,currency,amount_krw,source,external_key) VALUES (1,?,?,?,'Meta',10,'KRW',10,'fixture','v4')", (account["id"], brand["id"], "2026-08-01"))
            before = tuple(connection.execute("SELECT (SELECT COUNT(*) FROM finance_transaction),(SELECT COUNT(*) FROM sale),(SELECT COUNT(*) FROM ad_spend),(SELECT COUNT(*) FROM marketing_spend),(SELECT COUNT(*) FROM product),(SELECT COALESCE(SUM(amount_krw),0) FROM marketing_spend)").fetchone())
            connection.executescript("DROP INDEX ix_manual_spend_workspace_date; DROP INDEX ix_manual_spend_workspace_batch; DROP INDEX ix_manual_spend_brand_product_date; DROP TABLE manual_marketing_spend; DELETE FROM schema_version WHERE version>3;")
            connection.commit()
        initialize_database(); initialize_database()
        with closing(connect()) as connection:
            after = tuple(connection.execute("SELECT (SELECT COUNT(*) FROM finance_transaction),(SELECT COUNT(*) FROM sale),(SELECT COUNT(*) FROM ad_spend),(SELECT COUNT(*) FROM marketing_spend),(SELECT COUNT(*) FROM product),(SELECT COALESCE(SUM(amount_krw),0) FROM marketing_spend)").fetchone())
            self.assertEqual(before, after)
            self.assertEqual(connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 8)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM manual_marketing_spend").fetchone()[0], 0)
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_schema_v5_rehearsal_from_v4_is_idempotent_and_preserves_legacy_naver(self):
        self.create_workspace(1)
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "legacy"}).json
        legacy = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {"brand_id": brand["id"], "platform": "naver", "account_id": "999569", "account_name": "Legacy Naver", "currency": "KRW", "credential_key": "NAVER_MAIN"}).json
        with closing(connect()) as connection:
            connection.execute("INSERT INTO marketing_spend(workspace_id,ad_account_connection_id,brand_id,date,channel,original_amount,currency,amount_krw,source,external_key) VALUES (1,?,?,?,'네이버',123,'KRW',123,'naver_api','legacy')", (legacy["id"], brand["id"], "2026-08-24"))
            before = tuple(connection.execute("SELECT (SELECT COUNT(*) FROM finance_transaction),(SELECT COUNT(*) FROM sale),(SELECT COUNT(*) FROM ad_spend),(SELECT COUNT(*) FROM marketing_spend),(SELECT COALESCE(SUM(amount_krw),0) FROM marketing_spend),(SELECT COUNT(*) FROM manual_marketing_spend),(SELECT COUNT(*) FROM product)").fetchone())
            connection.executescript("""
                DROP INDEX ix_naver_sync_day_date;
                DROP INDEX ix_naver_campaign_spend_brand_date;
                DROP INDEX ix_naver_campaign_spend_date;
                DROP INDEX ix_naver_campaign_brand;
                DROP INDEX ix_naver_campaign_account_active;
                DROP INDEX ix_naver_account_workspace_active;
                DROP TABLE naver_account_sync_day;
                DROP TABLE naver_campaign_spend;
                DROP TABLE naver_campaign;
                DROP TABLE naver_account_connection;
                DELETE FROM schema_version WHERE version>=5;
                INSERT OR IGNORE INTO schema_version(version) VALUES (4);
            """)
            connection.commit()
        initialize_database(); initialize_database()
        with closing(connect()) as connection:
            after = tuple(connection.execute("SELECT (SELECT COUNT(*) FROM finance_transaction),(SELECT COUNT(*) FROM sale),(SELECT COUNT(*) FROM ad_spend),(SELECT COUNT(*) FROM marketing_spend),(SELECT COALESCE(SUM(amount_krw),0) FROM marketing_spend),(SELECT COUNT(*) FROM manual_marketing_spend),(SELECT COUNT(*) FROM product)").fetchone())
            self.assertEqual(before, after)
            self.assertEqual(connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 8)
            copied = connection.execute("SELECT * FROM naver_account_connection WHERE workspace_id=1 AND customer_id='999569'").fetchone()
            self.assertEqual(copied["legacy_ad_account_connection_id"], legacy["id"])
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM marketing_spend WHERE source='naver_api'").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM naver_campaign_spend").fetchone()[0], 0)
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_v4_to_v5_migration_failure_is_atomic_and_rerunnable(self):
        for failure_stage in ("after_ddl", "before_metadata", "before_version"):
            with self.subTest(stage=failure_stage):
                path = Path(self.tempdir.name) / f"atomic-{failure_stage}.db"
                initialize_database(path)
                with closing(connect(path)) as connection:
                    connection.execute("INSERT INTO workspace(id,name) VALUES (1,'W')")
                    connection.execute("INSERT INTO brand(id,workspace_id,name) VALUES (1,1,'B')")
                    connection.execute("INSERT INTO finance_transaction(id,workspace_id,date,merchant,amount,category) VALUES ('t',1,'2026-08-01','m',123,'광고비')")
                    connection.executescript("""
                        DROP INDEX ix_naver_sync_day_date;
                        DROP INDEX ix_naver_campaign_spend_brand_date;
                        DROP INDEX ix_naver_campaign_spend_date;
                        DROP INDEX ix_naver_campaign_brand;
                        DROP INDEX ix_naver_campaign_account_active;
                        DROP INDEX ix_naver_account_workspace_active;
                        DROP TABLE naver_account_sync_day;
                        DROP TABLE naver_campaign_spend;
                        DROP TABLE naver_campaign;
                        DROP TABLE naver_account_connection;
                        DELETE FROM schema_version WHERE version>=5;
                        INSERT OR IGNORE INTO schema_version(version) VALUES (4);
                    """)
                    connection.commit()
                def fail(stage):
                    if stage == failure_stage:
                        raise RuntimeError("injected migration failure")
                with patch("sbrocor_finance.database._v5_migration_hook", side_effect=fail):
                    with self.assertRaisesRegex(RuntimeError, "injected migration failure"):
                        initialize_database(path)
                with closing(connect(path)) as connection:
                    self.assertEqual(connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 4)
                    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    self.assertFalse({"naver_account_connection", "naver_campaign", "naver_campaign_spend", "naver_account_sync_day"} & tables)
                    self.assertEqual(tuple(connection.execute("SELECT COUNT(*),SUM(amount) FROM finance_transaction").fetchone()), (1, 123))
                initialize_database(path)
                initialize_database(path)
                with closing(connect(path)) as connection:
                    self.assertEqual(connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 8)
                    self.assertEqual(tuple(connection.execute("SELECT COUNT(*),SUM(amount) FROM finance_transaction").fetchone()), (1, 123))
                    self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_schema_v6_rehearsal_from_v5_is_idempotent_and_preserves_financial_rows(self):
        self.create_workspace(1)
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "v6"}).json
        naver = self.request("POST", "/api/sbrocor/finance/v1/naver-accounts?workspace_id=1", {"customer_id": "999569", "account_name": "N", "credential_key": "N"}).json
        with closing(connect()) as connection:
            connection.execute("INSERT INTO finance_transaction(id,workspace_id,date,merchant,amount,category) VALUES ('t',1,'2026-08-01','m',123,'광고비')")
            connection.execute("INSERT INTO naver_campaign(workspace_id,naver_account_connection_id,campaign_id,campaign_name,status,brand_id) VALUES (1,?,'C','Campaign','ELIGIBLE',?)", (naver["id"], brand["id"]))
            before = tuple(connection.execute("SELECT (SELECT COUNT(*) FROM finance_transaction),(SELECT SUM(amount) FROM finance_transaction),(SELECT COUNT(*) FROM sale),(SELECT COUNT(*) FROM product),(SELECT COUNT(*) FROM ad_spend),(SELECT COUNT(*) FROM marketing_spend),(SELECT COUNT(*) FROM manual_marketing_spend),(SELECT COUNT(*) FROM naver_account_connection),(SELECT COUNT(*) FROM naver_campaign),(SELECT COUNT(*) FROM naver_campaign_spend)").fetchone())
            connection.executescript("""
                DROP INDEX ix_naver_adgroup_spend_product_date;
                DROP INDEX ix_naver_adgroup_spend_brand_date;
                DROP INDEX ix_naver_adgroup_spend_date;
                DROP INDEX ix_naver_adgroup_product;
                DROP INDEX ix_naver_adgroup_campaign;
                DROP INDEX ix_naver_adgroup_account_active;
                DROP TABLE naver_adgroup_spend;
                DROP TABLE naver_adgroup;
                ALTER TABLE naver_account_sync_day DROP COLUMN unassigned_adgroup_count;
                ALTER TABLE naver_account_sync_day DROP COLUMN unassigned_product_amount_krw;
                ALTER TABLE naver_account_sync_day DROP COLUMN brand_common_amount_krw;
                ALTER TABLE naver_account_sync_day DROP COLUMN product_attributed_amount_krw;
                ALTER TABLE naver_account_sync_day DROP COLUMN adgroup_count;
                DELETE FROM schema_version WHERE version>=6;
            """)
            connection.commit()
        initialize_database(); initialize_database()
        with closing(connect()) as connection:
            after = tuple(connection.execute("SELECT (SELECT COUNT(*) FROM finance_transaction),(SELECT SUM(amount) FROM finance_transaction),(SELECT COUNT(*) FROM sale),(SELECT COUNT(*) FROM product),(SELECT COUNT(*) FROM ad_spend),(SELECT COUNT(*) FROM marketing_spend),(SELECT COUNT(*) FROM manual_marketing_spend),(SELECT COUNT(*) FROM naver_account_connection),(SELECT COUNT(*) FROM naver_campaign),(SELECT COUNT(*) FROM naver_campaign_spend)").fetchone())
            self.assertEqual(before, after)
            self.assertEqual(connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 8)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM naver_adgroup").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM naver_adgroup_spend").fetchone()[0], 0)
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_v5_to_v6_migration_failure_is_atomic_and_rerunnable(self):
        for failure_stage in ("after_ddl", "before_version"):
            with self.subTest(stage=failure_stage):
                path = Path(self.tempdir.name) / f"v6-atomic-{failure_stage}.db"
                initialize_database(path)
                with closing(connect(path)) as connection:
                    connection.execute("INSERT INTO workspace(id,name) VALUES (1,'W')")
                    connection.execute("INSERT INTO finance_transaction(id,workspace_id,date,merchant,amount,category) VALUES ('t',1,'2026-08-01','m',123,'광고비')")
                    connection.executescript("""
                        DROP INDEX ix_naver_adgroup_spend_product_date; DROP INDEX ix_naver_adgroup_spend_brand_date; DROP INDEX ix_naver_adgroup_spend_date;
                        DROP INDEX ix_naver_adgroup_product; DROP INDEX ix_naver_adgroup_campaign; DROP INDEX ix_naver_adgroup_account_active;
                        DROP TABLE naver_adgroup_spend; DROP TABLE naver_adgroup;
                        ALTER TABLE naver_account_sync_day DROP COLUMN unassigned_adgroup_count;
                        ALTER TABLE naver_account_sync_day DROP COLUMN unassigned_product_amount_krw;
                        ALTER TABLE naver_account_sync_day DROP COLUMN brand_common_amount_krw;
                        ALTER TABLE naver_account_sync_day DROP COLUMN product_attributed_amount_krw;
                        ALTER TABLE naver_account_sync_day DROP COLUMN adgroup_count;
                        DELETE FROM schema_version WHERE version>=6;
                    """)
                    connection.commit()
                def fail(stage):
                    if stage == failure_stage: raise RuntimeError("injected v6 migration failure")
                with patch("sbrocor_finance.database._v6_migration_hook", side_effect=fail):
                    with self.assertRaisesRegex(RuntimeError, "injected v6 migration failure"):
                        initialize_database(path)
                with closing(connect(path)) as connection:
                    self.assertEqual(connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 5)
                    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    self.assertNotIn("naver_adgroup", tables); self.assertNotIn("naver_adgroup_spend", tables)
                    self.assertEqual(tuple(connection.execute("SELECT COUNT(*),SUM(amount) FROM finance_transaction").fetchone()), (1, 123))
                initialize_database(path); initialize_database(path)
                with closing(connect(path)) as connection:
                    self.assertEqual(connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 8)
                    self.assertEqual(tuple(connection.execute("SELECT COUNT(*),SUM(amount) FROM finance_transaction").fetchone()), (1, 123))

    def test_legacy_naver_cleanup_is_exact_fail_closed_and_rolls_back(self):
        self.create_workspace(1)
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "Legacy"}).json
        account = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {"brand_id": brand["id"], "platform": "naver", "account_id": "999569", "account_name": "Legacy", "currency": "KRW", "credential_key": "N"}).json
        amounts = [18_000] * 23 + [20_846]
        with closing(connect()) as connection:
            for day, amount in enumerate(amounts, 1):
                connection.execute(
                    "INSERT INTO marketing_spend(workspace_id,ad_account_connection_id,brand_id,date,channel,original_amount,currency,amount_krw,source,external_key) VALUES (1,?,?,?,'네이버',?,'KRW',?,'naver_api',?)",
                    (account["id"], brand["id"], f"2026-08-{day:02d}", amount, amount, f"legacy-{day}"),
                )
            connection.commit()
        preview = cleanup_legacy_naver_spend.cleanup(self.db_path, expected_target=self.db_path)
        self.assertEqual((preview["row_count"], preview["total_amount"], preview["min_date"], preview["max_date"], preview["customer_id"]), (24, 434846, "2026-08-01", "2026-08-24", "999569"))
        with patch("ops.cleanup_legacy_naver_spend._after_delete_hook", side_effect=RuntimeError("rollback")):
            with self.assertRaisesRegex(RuntimeError, "rollback"):
                cleanup_legacy_naver_spend.cleanup(self.db_path, apply=True, confirmation=cleanup_legacy_naver_spend.CONFIRMATION, expected_target=self.db_path)
        with closing(connect()) as connection:
            self.assertEqual(tuple(connection.execute("SELECT COUNT(*),SUM(amount_krw) FROM marketing_spend WHERE source='naver_api'").fetchone()), (24, 434846))
            connection.execute("UPDATE marketing_spend SET amount_krw=amount_krw+1 WHERE external_key='legacy-1'")
            connection.commit()
        with self.assertRaises(cleanup_legacy_naver_spend.CleanupRefused):
            cleanup_legacy_naver_spend.cleanup(self.db_path, apply=True, confirmation=cleanup_legacy_naver_spend.CONFIRMATION, expected_target=self.db_path)
        with closing(connect()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM marketing_spend WHERE source='naver_api'").fetchone()[0], 24)
            connection.execute("UPDATE marketing_spend SET amount_krw=amount_krw-1 WHERE external_key='legacy-1'")
            connection.execute("UPDATE ad_account_connection SET account_id='wrong' WHERE id=?", (account["id"],))
            connection.commit()
        with self.assertRaises(cleanup_legacy_naver_spend.CleanupRefused):
            cleanup_legacy_naver_spend.cleanup(self.db_path, expected_target=self.db_path)
        with closing(connect()) as connection:
            connection.execute("UPDATE ad_account_connection SET account_id='999569' WHERE id=?", (account["id"],))
            connection.execute("UPDATE marketing_spend SET date='2026-07-31' WHERE external_key='legacy-1'")
            connection.commit()
        with self.assertRaises(cleanup_legacy_naver_spend.CleanupRefused):
            cleanup_legacy_naver_spend.cleanup(self.db_path, expected_target=self.db_path)
        with closing(connect()) as connection:
            connection.execute("UPDATE marketing_spend SET date='2026-08-01' WHERE external_key='legacy-1'")
            connection.execute("DELETE FROM marketing_spend WHERE external_key='legacy-24'")
            connection.commit()
        with self.assertRaises(cleanup_legacy_naver_spend.CleanupRefused):
            cleanup_legacy_naver_spend.cleanup(self.db_path, expected_target=self.db_path)
        with closing(connect()) as connection:
            connection.execute(
                "INSERT INTO marketing_spend(workspace_id,ad_account_connection_id,brand_id,date,channel,original_amount,currency,amount_krw,source,external_key) VALUES (1,?,?,?,'네이버',?,'KRW',?,'naver_api','legacy-24')",
                (account["id"], brand["id"], "2026-08-24", 20846, 20846),
            )
            connection.commit()
        applied = cleanup_legacy_naver_spend.cleanup(self.db_path, apply=True, confirmation=cleanup_legacy_naver_spend.CONFIRMATION, expected_target=self.db_path)
        self.assertEqual((applied["deleted_rows"], applied["post_count"]), (24, 0))
        with closing(connect()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM marketing_spend WHERE source='naver_api'").fetchone()[0], 0)
        tracker = Path(self.tempdir.name) / "tracker.db"
        tracker.touch()
        with self.assertRaises(cleanup_legacy_naver_spend.CleanupRefused):
            cleanup_legacy_naver_spend.cleanup(tracker, expected_target=tracker)

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
        self.assertEqual(workspace["spend_coverage"]["account_days_expected"], 4)
        self.assertEqual(workspace["spend_coverage"]["account_days_synced"], 4)
        self.assertTrue(workspace["spend_coverage"]["complete"])
        self.assertTrue(workspace["spend_coverage"]["api_coverage_required"])
        self.assertTrue(workspace["spend_coverage"]["api_complete"])
        self.assertEqual(workspace["spend_coverage"]["account_count"], 2)
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

    def test_meta_json_error_is_structured_and_credentials_are_never_in_url_or_logs(self):
        self.create_workspace(1)
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "오류 브랜드"}).json
        fake_token = "fake-production-shaped-token-never-use-real-values"
        with patch.dict(os.environ, {"SBROCOR_META_ACCESS_TOKEN_ERROR": fake_token}, clear=False):
            account = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {
                "brand_id": brand["id"], "platform": "meta", "account_id": "act_error",
                "account_name": "오류 계정", "currency": "KRW", "credential_key": "ERROR",
            }).json

            class ErrorResponse:
                status_code = 400
                def json(self):
                    return {"error": {
                        "message": "Unsupported get request",
                        "type": "GraphMethodException", "code": 100, "error_subcode": 33,
                    }}

            calls = []
            def fake_get(url, **kwargs):
                calls.append((url, kwargs))
                return ErrorResponse()

            with self.assertLogs("sbrocor_finance.routes", level="WARNING") as captured:
                with patch("sbrocor_finance.routes.requests.get", side_effect=fake_get):
                    response = self.request(
                        "POST", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/sync?workspace_id=1",
                        {"start_date": "2026-08-01", "end_date": "2026-08-01"},
                    )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json, {
            "error": "meta_api_error", "detail": "Meta API: Unsupported get request",
            "meta_code": 100, "meta_subcode": 33,
        })
        self.assertEqual(len(calls), 1)
        requested_url, requested = calls[0]
        self.assertNotIn("access_token", requested_url.lower())
        self.assertNotIn("access_token", (requested.get("params") or {}))
        self.assertEqual(requested["headers"], {"Authorization": f"Bearer {fake_token}"})
        self.assertNotIn(fake_token, "\n".join(captured.output))
        self.assertNotIn(fake_token, response.get_data(as_text=True))
        with closing(connect()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM ad_spend").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM marketing_spend").fetchone()[0], 0)
            self.assertIsNone(connection.execute(
                "SELECT last_synced_at FROM ad_account_connection WHERE id=?", (account["id"],)
            ).fetchone()[0])

    def test_meta_paging_token_is_removed_and_middle_page_error_is_safe(self):
        self.create_workspace(1)
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "페이지 오류"}).json
        fake_token = "fake-paging-token-never-use-real-values"
        with patch.dict(os.environ, {"SBROCOR_META_ACCESS_TOKEN_PAGEERROR": fake_token}, clear=False):
            account = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {
                "brand_id": brand["id"], "platform": "meta", "account_id": "act_page_error",
                "account_name": "페이지 오류", "currency": "KRW", "credential_key": "PAGEERROR",
            }).json

            class FirstPage:
                status_code = 200
                def json(self):
                    return {
                        "data": [{"date_start": "2026-08-01", "ad_id": "partial", "spend": "100000"}],
                        "paging": {"next": f"https://meta.example/fail?after=cursor&access_token={fake_token}"},
                    }

            calls = []
            def fake_get(url, **kwargs):
                calls.append((url, kwargs))
                if len(calls) == 2:
                    raise requests.ConnectionError("simulated safe network failure")
                return FirstPage()

            with self.assertLogs("sbrocor_finance.routes", level="WARNING") as captured:
                with patch("sbrocor_finance.routes.requests.get", side_effect=fake_get):
                    response = self.request(
                        "POST", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/sync?workspace_id=1",
                        {"start_date": "2026-08-01", "end_date": "2026-08-01"},
                    )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json, {"error": "meta_api_error", "detail": "Meta API 요청에 실패했습니다."})
        self.assertEqual(len(calls), 2)
        self.assertNotIn("access_token", calls[1][0].lower())
        self.assertEqual(calls[1][1]["headers"], {"Authorization": f"Bearer {fake_token}"})
        self.assertNotIn(fake_token, "\n".join(captured.output))
        with closing(connect()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM ad_spend").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM marketing_spend").fetchone()[0], 0)
            self.assertIsNone(connection.execute(
                "SELECT last_synced_at FROM ad_account_connection WHERE id=?", (account["id"],)
            ).fetchone()[0])

    def test_meta_non_json_and_timeout_errors_are_safe(self):
        self.create_workspace(1)
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "안전 오류"}).json
        fake_token = "fake-safe-error-token-never-use-real-values"
        with patch.dict(os.environ, {"SBROCOR_META_ACCESS_TOKEN_SAFEERROR": fake_token}, clear=False):
            account = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {
                "brand_id": brand["id"], "platform": "meta", "account_id": "act_safe_error",
                "account_name": "안전 오류", "currency": "KRW", "credential_key": "SAFEERROR",
            }).json
            path = f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/sync?workspace_id=1"
            payload = {"start_date": "2026-08-01", "end_date": "2026-08-01"}

            class NonJsonResponse:
                status_code = 503
                def json(self): raise ValueError("not json")

            with self.assertLogs("sbrocor_finance.routes", level="WARNING") as non_json_logs:
                with patch("sbrocor_finance.routes.requests.get", return_value=NonJsonResponse()):
                    non_json = self.request("POST", path, payload)
            with self.assertLogs("sbrocor_finance.routes", level="WARNING") as timeout_logs:
                with patch("sbrocor_finance.routes.requests.get", side_effect=requests.Timeout("do not expose request")):
                    timeout = self.request("POST", path, payload)

        for response in (non_json, timeout):
            self.assertEqual(response.status_code, 502)
            self.assertEqual(response.json, {"error": "meta_api_error", "detail": "Meta API 요청에 실패했습니다."})
            self.assertNotIn(fake_token, response.get_data(as_text=True))
        self.assertNotIn(fake_token, "\n".join(non_json_logs.output + timeout_logs.output))

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
                    raise requests.ConnectionError("simulated page failure")
                return FirstPage()
            with patch("sbrocor_finance.routes.requests.get", side_effect=fake_get):
                response = self.request("POST", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/sync?workspace_id=1", {"start_date": "2026-08-01", "end_date": "2026-08-01"})
                self.assertEqual(response.status_code, 502)
        with closing(connect()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM ad_spend").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM marketing_spend").fetchone()[0], 0)
            self.assertIsNone(connection.execute("SELECT last_synced_at FROM ad_account_connection WHERE id=?", (account["id"],)).fetchone()[0])

    def test_inactive_account_preserves_historical_spend_and_identity(self):
        self.create_workspace(1)
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "역사 브랜드"}).json
        other_brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "다른 브랜드"}).json
        with patch.dict(os.environ, {
            "SBROCOR_META_ACCESS_TOKEN_HISTORY": "server-secret",
            "SBROCOR_META_ACCESS_TOKEN_HISTORY_NEW": "new-server-secret",
        }, clear=False):
            account = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {
                "brand_id": brand["id"], "platform": "meta", "account_id": "act_history",
                "account_name": "역사 계정", "currency": "KRW", "credential_key": "HISTORY",
            }).json
            class HistoryResponse:
                def raise_for_status(self): return None
                def json(self): return {"data": [
                    {"date_start": "2026-08-01", "ad_id": "history-1", "spend": "100000"},
                    {"date_start": "2026-08-02", "ad_id": "history-2", "spend": "200000"},
                ]}
            with patch("sbrocor_finance.routes.requests.get", return_value=HistoryResponse()):
                synced = self.request("POST", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/sync?workspace_id=1", {"start_date": "2026-08-01", "end_date": "2026-08-02"})
            self.assertEqual(synced.status_code, 200)

            for field, value in (
                ("account_id", "act_changed"), ("platform", "naver"),
                ("brand_id", other_brand["id"]), ("currency", "USD"),
            ):
                blocked = self.request("PATCH", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}?workspace_id=1", {field: value})
                self.assertEqual(blocked.status_code, 400, (field, blocked.get_data(as_text=True)))

            allowed = self.request("PATCH", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}?workspace_id=1", {
                "account_name": "역사 계정 수정", "credential_key": "HISTORY_NEW", "active": False,
            })
            self.assertEqual(allowed.status_code, 200, allowed.get_data(as_text=True))
            self.assertEqual(allowed.json["account_name"], "역사 계정 수정")
            self.assertEqual(allowed.json["credential_key"], "HISTORY_NEW")
            self.assertEqual(allowed.json["active"], 0)
            self.assertTrue(allowed.json["identity_locked"])

        historical_path = ("/api/sbrocor/finance/v1/sales-analysis/compare?workspace_id=1"
                           "&a_start=2026-08-01&a_end=2026-08-02&b_start=2026-08-01&b_end=2026-08-02")
        historical = self.request("GET", historical_path).json["periods"]["a"]["totals"]
        self.assertTrue(historical["spend_analysis_ready"])
        self.assertTrue(historical["spend_coverage"]["complete"])
        self.assertEqual(historical["actual_advertising_spend"], 300000)

        future_path = ("/api/sbrocor/finance/v1/sales-analysis/compare?workspace_id=1"
                       "&a_start=2026-09-01&a_end=2026-09-02&b_start=2026-09-01&b_end=2026-09-02")
        future = self.request("GET", future_path).json["periods"]["a"]["totals"]
        self.assertFalse(future["spend_analysis_ready"])
        self.assertEqual(future["spend_coverage"]["account_count"], 0)
        self.assertIsNone(future["actual_advertising_spend"])

    def test_naver_is_sync_supported_but_requires_naver_credentials(self):
        self.create_workspace(1)
        with patch.dict(os.environ, {"SBROCOR_META_ACCESS_TOKEN_WORKSPACE_1": "meta-only-secret"}, clear=False):
            created = self.request("POST", "/api/sbrocor/finance/v1/naver-accounts?workspace_id=1", {
                "customer_id": "999569", "account_name": "네이버 계정", "credential_key": "NAVER_MAIN",
            })
            self.assertEqual(created.status_code, 201, created.get_data(as_text=True))
            self.assertFalse(created.json["credential_configured"])
            listed = self.request("GET", "/api/sbrocor/finance/v1/naver-accounts?workspace_id=1").json["items"][0]
            self.assertFalse(listed["credential_configured"])
            sync = self.request("POST", f"/api/sbrocor/finance/v1/naver-accounts/{created.json['id']}/sync?workspace_id=1", {"start_date": "2026-08-01", "end_date": "2026-08-01"})
            self.assertEqual(sync.status_code, 503)

    def test_naver_signature_cost_sync_zero_day_and_idempotency(self):
        self.assertEqual(generate_signature("1", "GET", "/stats", "secret"), "TE1nc7kY4Nu7dMxdSNHN/tTaKyvYzTUzNPfjOjPd1Os=")
        self.assertEqual(parse_ad_report_cost(("20260801\t1\ta\tb\tc\td\te\tf\tg\t1\t2\t50,000\n" "20260801\t1\ta\tb\tc\td\te\tf\tg\t3\t4\t25,000\n").encode()), 75000)
        self.assertEqual(parse_ad_report_campaign_costs(("20260801\t1\tA\tb\tc\td\te\tf\tg\t1\t2\t100,000\n" "20260801\t1\tA\tb\tc\td\te\tf\tg\t3\t4\t50,000\n" "20260801\t1\tB\tb\tc\td\te\tf\tg\t3\t4\t80,000\n").encode()), {"A": 150000, "B": 80000})
        self.assertEqual(parse_ad_report_adgroup_costs(("20260801\t1\tA\tGA\tc\td\te\tf\tg\t1\t2\t7,910\n" "20260801\t1\tA\tGB\tc\td\te\tf\tg\t3\t4\t91,840\n" "20260801\t1\tA\tGC\tc\td\te\tf\tg\t3\t4\t77\n").encode()), {("A", "GA"): 7910, ("A", "GB"): 91840, ("A", "GC"): 77})
        self.create_workspace(1)
        health = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "건강비서"}).json
        papa = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "파파랑"}).json
        with patch.dict(os.environ, {"SBROCOR_NAVER_API_KEY_MAIN": "api-secret", "SBROCOR_NAVER_SECRET_KEY_MAIN": "sign-secret"}, clear=False):
            account = self.request("POST", "/api/sbrocor/finance/v1/naver-accounts?workspace_id=1", {"customer_id": "999569", "account_name": "N", "credential_key": "MAIN"}).json
            self.assertTrue(account["credential_configured"])
            self.assertNotIn("api-secret", json.dumps(account))
            discovered = [
                {"campaign_id": "A", "campaign_name": "A", "status": "ELIGIBLE"},
                {"campaign_id": "B", "campaign_name": "B", "status": "ELIGIBLE"},
                {"campaign_id": "C", "campaign_name": "C", "status": "ELIGIBLE"},
                {"campaign_id": "D", "campaign_name": "D", "status": "ELIGIBLE"},
            ]
            with patch("sbrocor_finance.routes.NaverSearchAdsClient.campaigns", return_value=discovered):
                self.assertEqual(self.request("POST", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/campaigns/refresh?workspace_id=1").status_code, 200)
            campaigns = self.request("GET", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/campaigns?workspace_id=1").json["items"]
            by_id = {item["campaign_id"]: item for item in campaigns}
            for campaign_id, brand_id in (("A", health["id"]), ("B", health["id"]), ("C", papa["id"])):
                mapping_path = f"/api/sbrocor/finance/v1/naver-campaigns/{by_id[campaign_id]['id']}/mapping?workspace_id=1"
                preview = self.request("POST", mapping_path, {"brand_id": brand_id}).json
                applied = self.request("POST", mapping_path, {"brand_id": brand_id, "apply": True, "from_brand_id": preview["from_brand_id"], "preview_token": preview["preview_token"]})
                self.assertEqual(applied.status_code, 200, applied.get_data(as_text=True))
            costs = {("A", "GA"): 150000, ("B", "GB"): 80000, ("C", "GC"): 70000, ("D", "GD"): 40000}
            for _ in range(2):
                with patch("sbrocor_finance.routes.NaverSearchAdsClient.daily_adgroup_costs", return_value=costs):
                    response = self.request("POST", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/sync?workspace_id=1", {"start_date": "2026-08-01", "end_date": "2026-08-01"})
                self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
                self.assertEqual(response.json["account_total"], 340000)
                self.assertEqual(response.json["unmapped_amount"], 40000)
        with closing(connect()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM naver_adgroup_spend").fetchone()[0], 4)
            self.assertEqual(connection.execute("SELECT SUM(amount_krw) FROM naver_adgroup_spend").fetchone()[0], 340000)
            self.assertEqual(connection.execute("SELECT SUM(amount_krw) FROM naver_adgroup_spend WHERE brand_id=?", (health["id"],)).fetchone()[0], 230000)
            self.assertEqual(connection.execute("SELECT SUM(amount_krw) FROM naver_adgroup_spend WHERE brand_id=?", (papa["id"],)).fetchone()[0], 70000)
            self.assertEqual(connection.execute("SELECT SUM(amount_krw) FROM naver_adgroup_spend WHERE brand_id IS NULL").fetchone()[0], 40000)
        analysis = "/api/sbrocor/finance/v1/sales-analysis/compare?workspace_id=1&a_start=2026-08-01&a_end=2026-08-01&b_start=2026-08-01&b_end=2026-08-01"
        workspace_totals = self.request("GET", analysis).json["periods"]["a"]["totals"]
        self.assertEqual(workspace_totals["actual_advertising_spend"], 340000)
        self.assertFalse(workspace_totals["naver_attribution"]["complete"])
        self.assertEqual(workspace_totals["naver_attribution"]["unmapped_amount"], 40000)
        health_totals = self.request("GET", analysis + f"&brand_id={health['id']}").json["periods"]["a"]["totals"]
        self.assertEqual(health_totals["actual_advertising_spend"], 230000)
        papa_totals = self.request("GET", analysis + f"&brand_id={papa['id']}").json["periods"]["a"]["totals"]
        self.assertEqual(papa_totals["actual_advertising_spend"], 70000)
        preview = self.request("POST", f"/api/sbrocor/finance/v1/naver-campaigns/{by_id['C']['id']}/mapping?workspace_id=1", {"brand_id": health["id"], "apply": False}).json
        self.assertEqual((preview["historical_affected_rows"], preview["historical_affected_amount"]), (1, 70000))

    def test_naver_adgroup_product_attribution_refresh_sync_and_guards(self):
        self.create_workspace(1)
        health = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "건강비서"}).json
        other = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "파파랑"}).json
        pomegranate = self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {"id": 101, "name": "석류정", "cost_price": 1, "brand_id": health["id"]}).json
        probiotic = self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {"id": 102, "name": "식이섬균", "cost_price": 1, "brand_id": health["id"]}).json
        foreign = self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {"id": 103, "name": "파파랑 제품", "cost_price": 1, "brand_id": other["id"]}).json
        with patch.dict(os.environ, {"SBROCOR_NAVER_API_KEY_MAIN": "api", "SBROCOR_NAVER_SECRET_KEY_MAIN": "secret"}, clear=False):
            account = self.request("POST", "/api/sbrocor/finance/v1/naver-accounts?workspace_id=1", {"customer_id": "999569", "account_name": "N", "credential_key": "MAIN"}).json
            with closing(connect()) as connection:
                cursor = connection.execute("INSERT INTO naver_campaign(workspace_id,naver_account_connection_id,campaign_id,campaign_name,status,brand_id) VALUES (1,?,'CAMP','건강비서 자사몰 파워링크','ELIGIBLE',?)", (account["id"], health["id"]))
                campaign_row_id = cursor.lastrowid
                connection.commit()
            groups = [
                {"campaign_id": "CAMP", "adgroup_id": "GA", "adgroup_name": "석류정 파워링크", "status": "ELIGIBLE"},
                {"campaign_id": "CAMP", "adgroup_id": "GB", "adgroup_name": "자사몰 식이섬균 파워링크", "status": "ELIGIBLE"},
            ]
            with patch("sbrocor_finance.routes.NaverSearchAdsClient.adgroups", return_value=groups):
                refreshed = self.request("POST", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/adgroups/refresh?workspace_id=1")
            self.assertEqual(refreshed.status_code, 200, refreshed.get_data(as_text=True))
            adgroups = self.request("GET", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/adgroups?workspace_id=1").json["items"]
            by_id = {row["adgroup_id"]: row for row in adgroups}
            self.assertTrue(all(row["allocation_mode"] == "unassigned" and row["product_id"] is None for row in adgroups))
            employee = {"actor_uid": "employee", "role": "employee", "workspace_ids": [1], "permissions": ["ads"]}
            self.assertEqual(self.request("GET", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/adgroups?workspace_id=1", context=employee).status_code, 200)
            self.assertEqual(self.request("POST", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/adgroups/refresh?workspace_id=1", context=employee).status_code, 403)
            self.assertEqual(self.request("POST", f"/api/sbrocor/finance/v1/naver-adgroups/{by_id['GA']['id']}/allocation?workspace_id=1", {"allocation_mode": "brand_common"}, context=employee).status_code, 403)

            cross = self.request("POST", f"/api/sbrocor/finance/v1/naver-adgroups/{by_id['GA']['id']}/allocation?workspace_id=1", {"allocation_mode": "product", "product_id": foreign["id"]})
            self.assertEqual(cross.status_code, 400)
            for group_id, product in (("GA", pomegranate), ("GB", probiotic)):
                path = f"/api/sbrocor/finance/v1/naver-adgroups/{by_id[group_id]['id']}/allocation?workspace_id=1"
                preview = self.request("POST", path, {"allocation_mode": "product", "product_id": product["id"]}).json
                applied = self.request("POST", path, {"allocation_mode": "product", "product_id": product["id"], "apply": True, "from_allocation_mode": preview["from_allocation_mode"], "from_product_id": preview["from_product_id"], "preview_token": preview["preview_token"]})
                self.assertEqual(applied.status_code, 200, applied.get_data(as_text=True))
            with patch("sbrocor_finance.routes.NaverSearchAdsClient.adgroups", return_value=groups[:1]):
                repeated_refresh = self.request("POST", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/adgroups/refresh?workspace_id=1")
            self.assertEqual(repeated_refresh.status_code, 200, repeated_refresh.get_data(as_text=True))
            refreshed_groups = {row["adgroup_id"]: row for row in self.request("GET", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/adgroups?workspace_id=1").json["items"]}
            self.assertEqual((refreshed_groups["GA"]["allocation_mode"], refreshed_groups["GA"]["product_id"]), ("product", pomegranate["id"]))
            self.assertEqual((refreshed_groups["GB"]["active"], refreshed_groups["GB"]["allocation_mode"], refreshed_groups["GB"]["product_id"]), (0, "product", probiotic["id"]))

            with closing(connect()) as connection:
                connection.execute("INSERT INTO naver_campaign(workspace_id,naver_account_connection_id,campaign_id,campaign_name,status,brand_id) VALUES (1,?,'UNMAPPED','미지정 캠페인','ELIGIBLE',NULL)", (account["id"],))
                cursor = connection.execute("INSERT INTO naver_adgroup(workspace_id,naver_account_connection_id,campaign_id,adgroup_id,adgroup_name,status,allocation_mode,active,last_seen_at) VALUES (1,?,'UNMAPPED','GU','미지정 광고그룹','ELIGIBLE','unassigned',1,CURRENT_TIMESTAMP)", (account["id"],))
                unmapped_group_id = cursor.lastrowid
                connection.commit()
            campaign_unmapped = self.request("POST", f"/api/sbrocor/finance/v1/naver-adgroups/{unmapped_group_id}/allocation?workspace_id=1", {"allocation_mode": "product", "product_id": pomegranate["id"]})
            self.assertEqual(campaign_unmapped.status_code, 400)
            campaign_unmapped_common = self.request("POST", f"/api/sbrocor/finance/v1/naver-adgroups/{unmapped_group_id}/allocation?workspace_id=1", {"allocation_mode": "brand_common"})
            self.assertEqual(campaign_unmapped_common.status_code, 400)
            with closing(connect()) as connection:
                inactive_without_spend_id = connection.execute(
                    "INSERT INTO naver_adgroup(workspace_id,naver_account_connection_id,campaign_id,adgroup_id,adgroup_name,status,allocation_mode,active) VALUES (1,?,'CAMP','NO_HISTORY','과거 비용 없음','REPORT_ONLY','unassigned',0)",
                    (account["id"],),
                ).lastrowid
                connection.commit()
            inactive_without_spend = self.request("POST", f"/api/sbrocor/finance/v1/naver-adgroups/{inactive_without_spend_id}/allocation?workspace_id=1", {"allocation_mode": "brand_common"})
            self.assertEqual(inactive_without_spend.status_code, 400)
            stale_path = f"/api/sbrocor/finance/v1/naver-adgroups/{by_id['GA']['id']}/allocation?workspace_id=1"
            stale_preview = self.request("POST", stale_path, {"allocation_mode": "brand_common", "product_id": None}).json
            with closing(connect()) as connection:
                connection.execute("UPDATE naver_adgroup SET updated_at='changed' WHERE id=?", (by_id["GA"]["id"],)); connection.commit()
            stale_apply = self.request("POST", stale_path, {"allocation_mode": "brand_common", "product_id": None, "apply": True, "from_allocation_mode": stale_preview["from_allocation_mode"], "from_product_id": stale_preview["from_product_id"], "preview_token": stale_preview["preview_token"]})
            self.assertEqual(stale_apply.status_code, 409)
            self.assertEqual(stale_apply.json["error"], "stale_preview")
            blocked = self.request("POST", f"/api/sbrocor/finance/v1/naver-campaigns/{campaign_row_id}/mapping?workspace_id=1", {"brand_id": other["id"]})
            self.assertEqual(blocked.status_code, 400)
            self.assertIn("제품 매핑을 먼저 해제", blocked.json["detail"])

            costs = {("CAMP", "GA"): 7910, ("CAMP", "GB"): 91840, ("CAMP", "GC"): 77}
            with patch("sbrocor_finance.routes.NaverSearchAdsClient.daily_adgroup_costs", return_value=costs):
                synced = self.request("POST", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/sync?workspace_id=1", {"start_date": "2026-08-01", "end_date": "2026-08-01"})
            self.assertEqual(synced.status_code, 200, synced.get_data(as_text=True))
            self.assertEqual(synced.json["account_total"], 99827)
            self.assertEqual(synced.json["product_attributed_amount"], 99750)
            self.assertEqual(synced.json["unassigned_product_amount"], 77)
            with closing(connect()) as connection:
                self.assertEqual(connection.execute("SELECT SUM(amount_krw) FROM naver_adgroup_spend").fetchone()[0], 99827)
                report_only = connection.execute("SELECT * FROM naver_adgroup WHERE adgroup_id='GC'").fetchone()
                self.assertEqual((report_only["active"], report_only["allocation_mode"], report_only["product_id"]), (0, "unassigned", None))
                report_only_id = report_only["id"]
                self.assertEqual(connection.execute("SELECT SUM(amount_krw) FROM naver_adgroup_spend WHERE product_id=101").fetchone()[0], 7910)
                self.assertEqual(connection.execute("SELECT SUM(amount_krw) FROM naver_adgroup_spend WHERE product_id=102").fetchone()[0], 91840)
            listed_groups = {row["adgroup_id"]: row for row in self.request("GET", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/adgroups?workspace_id=1").json["items"]}
            self.assertEqual((listed_groups["GC"]["historical_spend_count"], listed_groups["GC"]["historical_spend_amount"]), (1, 77))
            analysis = self.request("GET", f"/api/sbrocor/finance/v1/sales-analysis/compare?workspace_id=1&brand_id={health['id']}&a_start=2026-08-01&a_end=2026-08-01&b_start=2026-08-01&b_end=2026-08-01").json
            totals = analysis["periods"]["a"]["totals"]
            self.assertEqual(totals["actual_advertising_spend"], 99827)
            self.assertEqual(totals["naver_product_attribution"], {"complete": False, "unassigned_amount": 77, "brand_common_amount": 0, "direct_product_amount": 99750})
            product_rows = {row["id"]: row for row in analysis["products"]}
            self.assertEqual(product_rows[101]["periods"]["a"]["direct_naver_advertising_spend"], 7910)
            self.assertEqual(product_rows[102]["periods"]["a"]["direct_naver_advertising_spend"], 91840)

            historical_path = f"/api/sbrocor/finance/v1/naver-adgroups/{report_only_id}/allocation?workspace_id=1"
            self.assertEqual(self.request("POST", historical_path, {"allocation_mode": "brand_common"}, context=employee).status_code, 403)
            historical_preview = self.request("POST", historical_path, {"allocation_mode": "brand_common"}).json
            historical_applied = self.request("POST", historical_path, {"allocation_mode": "brand_common", "apply": True, "from_allocation_mode": historical_preview["from_allocation_mode"], "from_product_id": historical_preview["from_product_id"], "preview_token": historical_preview["preview_token"]})
            self.assertEqual(historical_applied.status_code, 200, historical_applied.get_data(as_text=True))
            brand_common_totals = self.request("GET", f"/api/sbrocor/finance/v1/sales-analysis/compare?workspace_id=1&brand_id={health['id']}&a_start=2026-08-01&a_end=2026-08-01&b_start=2026-08-01&b_end=2026-08-01").json["periods"]["a"]["totals"]
            self.assertEqual(brand_common_totals["naver_product_attribution"], {"complete": True, "unassigned_amount": 0, "brand_common_amount": 77, "direct_product_amount": 99750})

            product_preview = self.request("POST", historical_path, {"allocation_mode": "product", "product_id": pomegranate["id"]}).json
            product_applied = self.request("POST", historical_path, {"allocation_mode": "product", "product_id": pomegranate["id"], "apply": True, "from_allocation_mode": product_preview["from_allocation_mode"], "from_product_id": product_preview["from_product_id"], "preview_token": product_preview["preview_token"]})
            self.assertEqual(product_applied.status_code, 200, product_applied.get_data(as_text=True))
            product_analysis = self.request("GET", f"/api/sbrocor/finance/v1/sales-analysis/compare?workspace_id=1&brand_id={health['id']}&a_start=2026-08-01&a_end=2026-08-01&b_start=2026-08-01&b_end=2026-08-01").json
            self.assertEqual({row["id"]: row for row in product_analysis["products"]}[pomegranate["id"]]["periods"]["a"]["direct_naver_advertising_spend"], 7987)
            with closing(connect()) as connection:
                self.assertEqual(connection.execute("SELECT amount_krw FROM naver_adgroup_spend WHERE adgroup_id='GC'").fetchone()[0], 77)
                connection.execute("UPDATE naver_adgroup SET archived=1 WHERE id=?", (report_only_id,)); connection.commit()
            self.assertEqual(self.request("POST", historical_path, {"allocation_mode": "brand_common"}).status_code, 400)

            # API/parser failure occurs before replacement; DB failure rolls back the deleted day.
            with patch("sbrocor_finance.routes.NaverSearchAdsClient.daily_adgroup_costs", side_effect=NaverApiError("fixture failure")):
                failed = self.request("POST", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/sync?workspace_id=1", {"start_date": "2026-08-01", "end_date": "2026-08-01"})
            self.assertEqual(failed.status_code, 502)
            with patch("sbrocor_finance.routes.NaverSearchAdsClient.daily_adgroup_costs", return_value={("CAMP", "GA"): 1}), patch("sbrocor_finance.routes._naver_adgroup_sync_hook", side_effect=lambda stage: (_ for _ in ()).throw(RuntimeError("db failure")) if stage == "after_delete" else None):
                with self.assertRaisesRegex(RuntimeError, "db failure"):
                    self.request("POST", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/sync?workspace_id=1", {"start_date": "2026-08-01", "end_date": "2026-08-01"})
            with closing(connect()) as connection:
                self.assertEqual(connection.execute("SELECT SUM(amount_krw) FROM naver_adgroup_spend WHERE date='2026-08-01'").fetchone()[0], 99827)

    def test_naver_mapping_preview_rejects_stale_spend_and_campaign_snapshots(self):
        self.create_workspace(1)
        first = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "First"}).json
        second = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "Second"}).json
        account = self.request("POST", "/api/sbrocor/finance/v1/naver-accounts?workspace_id=1", {"customer_id": "999569", "account_name": "N", "credential_key": "N"}).json
        with closing(connect()) as connection:
            cursor = connection.execute("INSERT INTO naver_campaign(workspace_id,naver_account_connection_id,campaign_id,campaign_name,status,brand_id) VALUES (1,?,'A','A','ELIGIBLE',?)", (account["id"], first["id"]))
            campaign_row_id = cursor.lastrowid
            connection.execute("INSERT INTO naver_campaign_spend(workspace_id,naver_account_connection_id,campaign_id,brand_id,date,amount_krw,external_key) VALUES (1,?,'A',?,'2026-08-01',100,'one')", (account["id"], first["id"]))
            connection.commit()
        path = f"/api/sbrocor/finance/v1/naver-campaigns/{campaign_row_id}/mapping?workspace_id=1"
        preview = self.request("POST", path, {"brand_id": second["id"]}).json
        valid = self.request("POST", path, {"brand_id": second["id"], "apply": True, "from_brand_id": preview["from_brand_id"], "preview_token": preview["preview_token"]})
        self.assertEqual(valid.status_code, 200, valid.get_data(as_text=True))

        preview = self.request("POST", path, {"brand_id": first["id"]}).json
        with closing(connect()) as connection:
            connection.execute("INSERT INTO naver_campaign_spend(workspace_id,naver_account_connection_id,campaign_id,brand_id,date,amount_krw,external_key) VALUES (1,?,'A',?,'2026-08-02',200,'two')", (account["id"], second["id"]))
            connection.commit()
        stale = self.request("POST", path, {"brand_id": first["id"], "apply": True, "from_brand_id": preview["from_brand_id"], "preview_token": preview["preview_token"]})
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.json["error"], "stale_preview")
        with closing(connect()) as connection:
            self.assertEqual(connection.execute("SELECT brand_id FROM naver_campaign WHERE id=?", (campaign_row_id,)).fetchone()[0], second["id"])

        preview = self.request("POST", path, {"brand_id": first["id"]}).json
        with closing(connect()) as connection:
            connection.execute("UPDATE naver_campaign SET brand_id=?,updated_at='changed' WHERE id=?", (first["id"], campaign_row_id))
            connection.commit()
        stale = self.request("POST", path, {"brand_id": first["id"], "apply": True, "from_brand_id": preview["from_brand_id"], "preview_token": preview["preview_token"]})
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.json["error"], "stale_preview")

    def test_naver_backend_rejects_multi_day_sync(self):
        self.create_workspace(1)
        account = self.request("POST", "/api/sbrocor/finance/v1/naver-accounts?workspace_id=1", {"customer_id": "321", "account_name": "N", "credential_key": "N"}).json
        response = self.request("POST", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/sync?workspace_id=1", {"start_date": "2026-08-01", "end_date": "2026-08-02"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["detail"], "Naver sync는 현재 1일 단위로 실행해주세요.")

    def test_manual_spend_single_range_exact_update_delete_and_workspace_isolation(self):
        self.create_workspace(1); self.create_workspace(2)
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "B"}).json
        single = self.request("POST", "/api/sbrocor/finance/v1/manual-marketing-spend?workspace_id=1", {"date": "2026-08-01", "brand_id": brand["id"], "channel": "인플루언서", "amount_krw": 30000})
        self.assertEqual(single.status_code, 201, single.get_data(as_text=True))
        ranged = self.request("POST", "/api/sbrocor/finance/v1/manual-marketing-spend?workspace_id=1", {"start_date": "2026-08-02", "end_date": "2026-08-04", "brand_id": brand["id"], "channel": "바이럴", "amount_krw": 100})
        self.assertEqual(ranged.json["amount_krw"], 100)
        with closing(connect()) as connection:
            values = [row[0] for row in connection.execute("SELECT amount_krw FROM manual_marketing_spend WHERE batch_id=? ORDER BY date", (ranged.json["batch_id"],))]
            self.assertEqual(values, [34, 33, 33])
        updated = self.request("PATCH", f"/api/sbrocor/finance/v1/manual-marketing-spend/{ranged.json['batch_id']}?workspace_id=1", {"start_date": "2026-08-02", "end_date": "2026-08-03", "brand_id": brand["id"], "channel": "기타", "amount_krw": 9})
        self.assertEqual(updated.json["days"], 2)
        isolated = self.request("GET", "/api/sbrocor/finance/v1/manual-marketing-spend?workspace_id=2")
        self.assertEqual(isolated.json["items"], [])
        deleted = self.request("DELETE", f"/api/sbrocor/finance/v1/manual-marketing-spend/{ranged.json['batch_id']}?workspace_id=1")
        self.assertEqual(deleted.status_code, 204)

    def test_meta_naver_manual_are_combined_without_affecting_api_coverage(self):
        self.create_workspace(1)
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "파파랑"}).json
        meta = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {"brand_id": brand["id"], "platform": "meta", "account_id": "act_mix", "account_name": "Meta", "currency": "KRW", "credential_key": "M"}).json
        naver = self.request("POST", "/api/sbrocor/finance/v1/naver-accounts?workspace_id=1", {"customer_id": "999", "account_name": "Naver", "credential_key": "N"}).json
        with closing(connect()) as connection:
            connection.execute("INSERT INTO marketing_spend(workspace_id,ad_account_connection_id,brand_id,date,channel,original_amount,currency,amount_krw,source,external_key) VALUES (1,?,?,? ,'Meta',?, 'KRW',?,'meta_api','meta:1')", (meta["id"], brand["id"], "2026-08-01", 100000, 100000))
            connection.execute("INSERT INTO naver_adgroup_spend(workspace_id,naver_account_connection_id,campaign_id,adgroup_id,brand_id,product_id,allocation_mode,date,amount_krw,external_key) VALUES (1,?,'C','G',?,NULL,'brand_common','2026-08-01',50000,'naver:999:C:G:2026-08-01')", (naver["id"], brand["id"]))
            connection.execute("INSERT INTO naver_account_sync_day(workspace_id,naver_account_connection_id,date,total_amount_krw,campaign_count,unmapped_amount_krw,unmapped_campaign_count) VALUES (1,?,'2026-08-01',50000,1,0,0)", (naver["id"],))
            connection.commit()
        self.request("POST", "/api/sbrocor/finance/v1/manual-marketing-spend?workspace_id=1", {"date": "2026-08-01", "brand_id": brand["id"], "channel": "인플루언서", "amount_krw": 30000})
        path = "/api/sbrocor/finance/v1/sales-analysis/compare?workspace_id=1&a_start=2026-08-01&a_end=2026-08-01&b_start=2026-08-01&b_end=2026-08-01"
        totals = self.request("GET", path).json["periods"]["a"]["totals"]
        self.assertEqual(totals["actual_advertising_spend"], 180000)
        self.assertEqual(totals["spend_coverage"]["account_days_expected"], 2)
        self.assertEqual(totals["spend_coverage"]["account_days_synced"], 2)

    def test_manual_only_analysis_and_missing_api_coverage_rules(self):
        self.create_workspace(1)
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "Manual"}).json
        path = f"/api/sbrocor/finance/v1/sales-analysis/compare?workspace_id=1&brand_id={brand['id']}&a_start=2026-08-01&a_end=2026-08-01&b_start=2026-08-01&b_end=2026-08-01"
        empty = self.request("GET", path).json["periods"]["a"]["totals"]
        self.assertFalse(empty["spend_analysis_ready"])
        self.request("POST", "/api/sbrocor/finance/v1/manual-marketing-spend?workspace_id=1", {"date": "2026-08-01", "brand_id": brand["id"], "channel": "바이럴", "amount_krw": 300000})
        manual = self.request("GET", path).json["periods"]["a"]["totals"]
        self.assertTrue(manual["spend_analysis_ready"])
        self.assertEqual(manual["actual_advertising_spend"], 300000)
        self.assertFalse(manual["spend_coverage"]["api_coverage_required"])
        self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {"brand_id": brand["id"], "platform": "meta", "account_id": "act_missing", "account_name": "Missing", "currency": "KRW", "credential_key": "MISSING"})
        missing = self.request("GET", path).json["periods"]["a"]["totals"]
        self.assertFalse(missing["spend_analysis_ready"])
        self.assertTrue(missing["spend_coverage"]["api_coverage_required"])

    def test_naver_error_sanitization_and_download_url_validation(self):
        api_key, secret = "fake-api-key-never-leak", "fake-secret-never-leak"
        class Response:
            def __init__(self, status=200, payload=None, content=b""): self.status_code=status; self._payload=payload; self.content=content
            def json(self): return self._payload
        class ErrorSession:
            def request(self, *_args, **_kwargs): return Response(400, {"code": 12345, "message": f"bad {api_key} X-Signature={secret}"})
        client = NaverSearchAdsClient(Credentials(api_key, secret, "111"), session=ErrorSession())
        with self.assertRaises(NaverApiError) as caught:
            client.daily_cost("2026-08-01")
        text = str(caught.exception)
        self.assertIn("Naver API:", text); self.assertNotIn(api_key, text); self.assertNotIn(secret, text)

        class ReportSession:
            def __init__(self, url): self.url=url; self.downloaded=None; self.calls=0
            def request(self, *_args, **_kwargs):
                self.calls += 1
                return Response(payload={"reportJobId": 1, "status": "REGIST"} if self.calls == 1 else {"reportJobId": 1, "status": "BUILT", "downloadUrl": self.url})
            def get(self, url, **_kwargs): self.downloaded=url; return Response(content=b"20260801\t1\ta\tb\tc\td\te\tf\tg\t1\t2\t500\n")
        bad = ReportSession("https://evil.example/report-download?authtoken=x")
        with self.assertRaises(NaverApiError): NaverSearchAdsClient(Credentials("a","b","1"), session=bad, poll_seconds=0).daily_cost("2026-08-01")
        official = "https://api.searchad.naver.com/report-download?authtoken=token&fileVersion=v2"
        good = ReportSession(official)
        self.assertEqual(NaverSearchAdsClient(Credentials("a","b","1"), session=good, poll_seconds=0).daily_cost("2026-08-01"), 500)
        self.assertEqual(good.downloaded, official)

    def test_naver_official_adgroup_response_fields_are_normalized(self):
        class Response:
            status_code = 200
            def json(self):
                return [{"nccAdgroupId": "grp-1", "nccCampaignId": "cmp-1", "name": "석류정 파워링크", "status": "ELIGIBLE", "statusReason": "none"}]
        class Session:
            def request(self, method, url, **kwargs):
                self.method, self.url, self.kwargs = method, url, kwargs
                return Response()
        session = Session()
        result = NaverSearchAdsClient(Credentials("api", "secret", "999569"), session=session).adgroups()
        self.assertEqual(session.method, "GET")
        self.assertEqual(session.url, "https://api.searchad.naver.com/ncc/adgroups")
        self.assertEqual(result, [{"adgroup_id": "grp-1", "campaign_id": "cmp-1", "adgroup_name": "석류정 파워링크", "status": "ELIGIBLE"}])

    def test_schema_v7_rehearsal_is_atomic_idempotent_and_preserves_naver_mappings(self):
        self.create_workspace(1)
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "건강비서"}).json
        product = self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {"id": 701, "name": "식이섬균", "cost_price": 1, "brand_id": brand["id"]}).json
        account = self.request("POST", "/api/sbrocor/finance/v1/naver-accounts?workspace_id=1", {"customer_id": "999569", "account_name": "N", "credential_key": "N"}).json
        with closing(connect()) as connection:
            connection.execute("INSERT INTO finance_transaction(id,workspace_id,date,merchant,amount,category) VALUES ('v7-t',1,'2026-08-01','m',123,'광고비')")
            connection.execute("INSERT INTO naver_campaign(workspace_id,naver_account_connection_id,campaign_id,campaign_name,status,brand_id) VALUES (1,?,'C','Campaign','ELIGIBLE',?)", (account["id"], brand["id"]))
            connection.execute("INSERT INTO naver_adgroup(workspace_id,naver_account_connection_id,campaign_id,adgroup_id,adgroup_name,status,allocation_mode,product_id) VALUES (1,?,'C','G','Group','ELIGIBLE','product',?)", (account["id"], product["id"]))
            before = tuple(connection.execute("SELECT (SELECT COUNT(*) FROM finance_transaction),(SELECT SUM(amount) FROM finance_transaction),(SELECT COUNT(*) FROM sale),(SELECT COUNT(*) FROM product),(SELECT COUNT(*) FROM ad_spend),(SELECT COUNT(*) FROM marketing_spend),(SELECT COUNT(*) FROM manual_marketing_spend),(SELECT COUNT(*) FROM naver_account_connection),(SELECT COUNT(*) FROM naver_campaign),(SELECT COUNT(*) FROM naver_adgroup),(SELECT COUNT(*) FROM naver_adgroup_spend)").fetchone())
            connection.executescript("""
                ALTER TABLE naver_campaign DROP COLUMN archived_at;
                ALTER TABLE naver_campaign DROP COLUMN archived;
                ALTER TABLE naver_adgroup DROP COLUMN archived_at;
                ALTER TABLE naver_adgroup DROP COLUMN archived;
                DELETE FROM schema_version WHERE version>=7;
            """)
            connection.commit()
        with patch("sbrocor_finance.database._v7_migration_hook", side_effect=lambda stage: (_ for _ in ()).throw(RuntimeError("v7 failure")) if stage == "after_ddl" else None):
            with self.assertRaisesRegex(RuntimeError, "v7 failure"):
                initialize_database()
        with closing(connect()) as connection:
            self.assertEqual(connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 6)
            self.assertNotIn("archived", {row[1] for row in connection.execute("PRAGMA table_info(naver_campaign)")})
            self.assertNotIn("archived", {row[1] for row in connection.execute("PRAGMA table_info(naver_adgroup)")})
        initialize_database(); initialize_database()
        with closing(connect()) as connection:
            after = tuple(connection.execute("SELECT (SELECT COUNT(*) FROM finance_transaction),(SELECT SUM(amount) FROM finance_transaction),(SELECT COUNT(*) FROM sale),(SELECT COUNT(*) FROM product),(SELECT COUNT(*) FROM ad_spend),(SELECT COUNT(*) FROM marketing_spend),(SELECT COUNT(*) FROM manual_marketing_spend),(SELECT COUNT(*) FROM naver_account_connection),(SELECT COUNT(*) FROM naver_campaign),(SELECT COUNT(*) FROM naver_adgroup),(SELECT COUNT(*) FROM naver_adgroup_spend)").fetchone())
            self.assertEqual(before, after)
            self.assertEqual(connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 8)
            self.assertEqual(tuple(connection.execute("SELECT brand_id,archived,archived_at FROM naver_campaign WHERE campaign_id='C'").fetchone()), (brand["id"], 0, None))
            self.assertEqual(tuple(connection.execute("SELECT allocation_mode,product_id,archived,archived_at FROM naver_adgroup WHERE adgroup_id='G'").fetchone()), ("product", product["id"], 0, None))
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_naver_archive_restore_refresh_and_spend_safety(self):
        self.create_workspace(1); self.create_workspace(2)
        brand = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "건강비서"}).json
        product = self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {"id": 711, "name": "식이섬균", "cost_price": 1, "brand_id": brand["id"]}).json
        employee = {"actor_uid": "employee", "role": "employee", "workspace_ids": [1], "permissions": ["ads"]}
        with patch.dict(os.environ, {"SBROCOR_NAVER_API_KEY_MAIN": "api", "SBROCOR_NAVER_SECRET_KEY_MAIN": "secret"}, clear=False):
            account = self.request("POST", "/api/sbrocor/finance/v1/naver-accounts?workspace_id=1", {"customer_id": "999569", "account_name": "N", "credential_key": "MAIN"}).json
            with closing(connect()) as connection:
                campaign_id = connection.execute("INSERT INTO naver_campaign(workspace_id,naver_account_connection_id,campaign_id,campaign_name,status,brand_id) VALUES (1,?,'C','건강비서 자사몰','ELIGIBLE',?)", (account["id"], brand["id"])).lastrowid
                product_group_id = connection.execute("INSERT INTO naver_adgroup(workspace_id,naver_account_connection_id,campaign_id,adgroup_id,adgroup_name,status,allocation_mode,product_id) VALUES (1,?,'C','GP','식이섬균','ELIGIBLE','product',?)", (account["id"], product["id"])).lastrowid
                unassigned_group_id = connection.execute("INSERT INTO naver_adgroup(workspace_id,naver_account_connection_id,campaign_id,adgroup_id,adgroup_name,status,allocation_mode,product_id) VALUES (1,?,'C','GU','미사용 광고그룹','ELIGIBLE','unassigned',NULL)", (account["id"],)).lastrowid
                hidden_unmapped_id = connection.execute("INSERT INTO naver_campaign(workspace_id,naver_account_connection_id,campaign_id,campaign_name,status,brand_id,archived) VALUES (1,?,'U','보관 미지정','ELIGIBLE',NULL,1)", (account["id"],)).lastrowid
                connection.commit()

            campaign_path = f"/api/sbrocor/finance/v1/naver-campaigns/{campaign_id}/archive?workspace_id=1"
            group_path = f"/api/sbrocor/finance/v1/naver-adgroups/{product_group_id}/archive?workspace_id=1"
            self.assertEqual(self.request("PATCH", campaign_path, {"archived": True}, context=employee).status_code, 403)
            self.assertEqual(self.request("PATCH", group_path, {"archived": True}, context=employee).status_code, 403)
            self.assertEqual(self.request("PATCH", f"/api/sbrocor/finance/v1/naver-campaigns/{campaign_id}/archive?workspace_id=2", {"archived": True}).status_code, 404)
            self.assertEqual(self.request("PATCH", f"/api/sbrocor/finance/v1/naver-adgroups/{product_group_id}/archive?workspace_id=2", {"archived": True}).status_code, 404)

            archived_campaign = self.request("PATCH", campaign_path, {"archived": True})
            archived_product = self.request("PATCH", group_path, {"archived": True})
            archived_unassigned = self.request("PATCH", f"/api/sbrocor/finance/v1/naver-adgroups/{unassigned_group_id}/archive?workspace_id=1", {"archived": True})
            self.assertEqual((archived_campaign.json["archived"], archived_campaign.json["brand_id"]), (1, brand["id"]))
            self.assertEqual((archived_product.json["archived"], archived_product.json["allocation_mode"], archived_product.json["product_id"]), (1, "product", product["id"]))
            self.assertEqual((archived_unassigned.json["archived"], archived_unassigned.json["allocation_mode"], archived_unassigned.json["product_id"]), (1, "unassigned", None))
            archived_allocation = self.request("POST", f"/api/sbrocor/finance/v1/naver-adgroups/{product_group_id}/allocation?workspace_id=1", {"allocation_mode": "brand_common"})
            self.assertEqual(archived_allocation.status_code, 400)
            account_item = self.request("GET", "/api/sbrocor/finance/v1/naver-accounts?workspace_id=1").json["items"][0]
            self.assertEqual(account_item["unmapped_campaign_count"], 0)

            campaigns = [{"campaign_id": "C", "campaign_name": "건강비서 자사몰 변경", "status": "ELIGIBLE"}, {"campaign_id": "U", "campaign_name": "보관 미지정", "status": "ELIGIBLE"}]
            groups = [{"campaign_id": "C", "adgroup_id": "GP", "adgroup_name": "식이섬균 변경", "status": "ELIGIBLE"}, {"campaign_id": "C", "adgroup_id": "GU", "adgroup_name": "미사용 광고그룹", "status": "ELIGIBLE"}]
            with patch("sbrocor_finance.routes.NaverSearchAdsClient.campaigns", return_value=campaigns):
                self.assertEqual(self.request("POST", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/campaigns/refresh?workspace_id=1").status_code, 200)
            with patch("sbrocor_finance.routes.NaverSearchAdsClient.adgroups", return_value=groups):
                self.assertEqual(self.request("POST", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/adgroups/refresh?workspace_id=1").status_code, 200)
            with closing(connect()) as connection:
                self.assertEqual(tuple(connection.execute("SELECT brand_id,archived FROM naver_campaign WHERE id=?", (campaign_id,)).fetchone()), (brand["id"], 1))
                self.assertEqual(connection.execute("SELECT archived FROM naver_campaign WHERE id=?", (hidden_unmapped_id,)).fetchone()[0], 1)
                self.assertEqual(tuple(connection.execute("SELECT allocation_mode,product_id,archived FROM naver_adgroup WHERE id=?", (product_group_id,)).fetchone()), ("product", product["id"], 1))
                self.assertEqual(tuple(connection.execute("SELECT allocation_mode,product_id,archived FROM naver_adgroup WHERE id=?", (unassigned_group_id,)).fetchone()), ("unassigned", None, 1))

            costs = {("C", "GP"): 5000, ("C", "GU"): 5000}
            with patch("sbrocor_finance.routes.NaverSearchAdsClient.daily_adgroup_costs", return_value=costs):
                synced = self.request("POST", f"/api/sbrocor/finance/v1/naver-accounts/{account['id']}/sync?workspace_id=1", {"start_date": "2026-08-01", "end_date": "2026-08-01"})
            self.assertEqual(synced.status_code, 200, synced.get_data(as_text=True))
            self.assertEqual((synced.json["account_total"], synced.json["product_attributed_amount"], synced.json["unassigned_product_amount"]), (10000, 5000, 5000))
            with closing(connect()) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*),SUM(amount_krw) FROM naver_adgroup_spend").fetchone()[:], (2, 10000))
                self.assertEqual(connection.execute("SELECT SUM(amount_krw) FROM naver_adgroup_spend WHERE product_id=?", (product["id"],)).fetchone()[0], 5000)
            analysis_path = f"/api/sbrocor/finance/v1/sales-analysis/compare?workspace_id=1&brand_id={brand['id']}&a_start=2026-08-01&a_end=2026-08-01&b_start=2026-08-01&b_end=2026-08-01"
            analysis = self.request("GET", analysis_path).json
            totals = analysis["periods"]["a"]["totals"]
            self.assertEqual(totals["actual_advertising_spend"], 10000)
            self.assertEqual(totals["naver_product_attribution"], {"complete": False, "unassigned_amount": 5000, "brand_common_amount": 0, "direct_product_amount": 5000})
            self.assertEqual({row["id"]: row for row in analysis["products"]}[product["id"]]["periods"]["a"]["direct_naver_advertising_spend"], 5000)

            restored_campaign = self.request("PATCH", campaign_path, {"archived": False})
            restored_group = self.request("PATCH", group_path, {"archived": False})
            self.assertEqual((restored_campaign.json["archived"], restored_campaign.json["archived_at"]), (0, None))
            self.assertEqual((restored_group.json["archived"], restored_group.json["archived_at"]), (0, None))

    def test_v8_meta_product_allocation_exact_and_brand_scoped_naver_completeness(self):
        self.create_workspace(1); self.create_workspace(2)
        brand_a = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "건강비서"}).json
        brand_b = self.request("POST", "/api/sbrocor/finance/v1/brands?workspace_id=1", {"name": "파파랑"}).json
        product_a = self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {"id": 801, "name": "식이섬균", "cost_price": 1, "brand_id": brand_a["id"]}).json
        product_b = self.request("POST", "/api/sbrocor/finance/v1/products?workspace_id=1", {"id": 802, "name": "뽀글솔", "cost_price": 1, "brand_id": brand_b["id"]}).json
        platform = self.request("POST", "/api/sbrocor/finance/v1/platforms?workspace_id=1", {"name": "자사몰", "commission_rate": 0}).json
        account = self.request("POST", "/api/sbrocor/finance/v1/ad-accounts?workspace_id=1", {"brand_id": brand_a["id"], "platform": "meta", "account_id": "act_v8", "account_name": "Meta", "currency": "KRW", "credential_key": "M"}).json
        with closing(connect()) as connection:
            for ad_id in ("A", "B", "C"):
                connection.execute(
                    "INSERT INTO ad_spend(workspace_id,date,platform,campaign_id,campaign_name,adset_id,adset_name,ad_id,ad_name,spend,ad_account_connection_id,brand_id) VALUES (1,'2026-08-01','meta','C','Campaign','S','Set',?,?,1,?,?)",
                    (ad_id, f"Ad {ad_id}", account["id"], brand_a["id"]),
                )
            connection.execute("INSERT INTO marketing_spend(workspace_id,ad_account_connection_id,brand_id,date,channel,original_amount,currency,amount_krw,source,external_key) VALUES (1,?,?, '2026-08-01','Meta',3,'KRW',100,'meta_api','meta:v8')", (account["id"], brand_a["id"]))
            connection.execute("INSERT INTO sale(id,workspace_id,date,product_id,platform_id,selling_price,quantity,total_selling_amount,total_cost_amount,commission_amount,net_profit) VALUES ('v8-sale',1,'2026-08-01',801,?,1000000,1,1000000,0,0,1000000)", (platform["id"],))
            naver_id = connection.execute("INSERT INTO naver_account_connection(workspace_id,customer_id,account_name,credential_key,active) VALUES (1,'v8-naver','Naver','N',0)").lastrowid
            connection.execute("INSERT INTO naver_account_sync_day(workspace_id,naver_account_connection_id,date,total_amount_krw) VALUES (1,?,'2026-08-01',190000)", (naver_id,))
            for external_key, current_brand, mode, selected_product, amount in (
                ('na-direct', brand_a['id'], 'product', product_a['id'], 100000),
                ('na-common', brand_a['id'], 'brand_common', None, 30000),
                ('nb-direct', brand_b['id'], 'product', product_b['id'], 50000),
                ('nb-unassigned', brand_b['id'], 'unassigned', None, 10000),
            ):
                connection.execute("INSERT INTO naver_adgroup_spend(workspace_id,naver_account_connection_id,campaign_id,adgroup_id,brand_id,product_id,allocation_mode,date,amount_krw,external_key) VALUES (1,?,'C',?,?,?,?, '2026-08-01',?,?)", (naver_id, external_key, current_brand, selected_product, mode, amount, external_key))
            connection.commit()
        listing = self.request("GET", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/meta-ads?workspace_id=1")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual({item["allocation_mode"] for item in listing.json["items"]}, {"unassigned"})
        employee = {"actor_uid": "employee", "role": "employee", "workspace_ids": [1], "permissions": ["ads"]}
        self.assertEqual(self.request("POST", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/meta-ads/A/allocation?workspace_id=1", {"allocation_mode": "product", "product_id": product_a["id"]}, context=employee).status_code, 403)
        self.assertEqual(self.request("POST", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/meta-ads/A/allocation?workspace_id=1", {"allocation_mode": "product", "product_id": product_b["id"]}).status_code, 400)
        self.assertEqual(self.request("POST", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/meta-ads/A/allocation?workspace_id=2", {"allocation_mode": "brand_common", "product_id": None}).status_code, 404)
        for ad_id, mode, selected in (("A", "product", product_a["id"]), ("B", "brand_common", None), ("C", "unassigned", None)):
            response = self.request("POST", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/meta-ads/{ad_id}/allocation?workspace_id=1", {"allocation_mode": mode, "product_id": selected})
            self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        path = f"/api/sbrocor/finance/v1/sales-analysis/compare?workspace_id=1&a_start=2026-08-01&a_end=2026-08-01&b_start=2026-08-01&b_end=2026-08-01"
        first = self.request("GET", path).json
        meta = first["periods"]["a"]["totals"]["meta_product_attribution"]
        self.assertEqual(meta["direct_product_amount"] + meta["brand_common_amount"] + meta["unassigned_amount"], 100)
        self.assertEqual((meta["direct_product_amount"], meta["brand_common_amount"], meta["unassigned_amount"], meta["complete"]), (34, 33, 33, False))
        self.request("POST", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/meta-ads/C/allocation?workspace_id=1", {"allocation_mode": "product", "product_id": product_a["id"]})
        second = self.request("GET", path).json
        meta = second["periods"]["a"]["totals"]["meta_product_attribution"]
        self.assertEqual((meta["direct_product_amount"], meta["brand_common_amount"], meta["unassigned_amount"], meta["complete"]), (67, 33, 0, True))
        product_period = {row["id"]: row for row in second["products"]}[product_a["id"]]["periods"]["a"]
        self.assertEqual(product_period["direct_meta_advertising_spend"], 67)
        self.assertEqual(product_period["direct_naver_advertising_spend"], 100000)
        self.assertEqual(product_period["direct_advertising_cost"], 100067)
        self.assertEqual(product_period["profit_after_direct_advertising"], 899933)
        self.assertTrue(product_period["attribution_complete"])
        unrelated = {row["id"]: row for row in second["products"]}[product_b["id"]]["periods"]["a"]
        self.assertFalse(unrelated["attribution_complete"])
        self.assertEqual(unrelated["naver_unassigned_amount"], 10000)
        with closing(connect()) as connection:
            self.assertEqual(connection.execute("SELECT SUM(amount_krw) FROM marketing_spend WHERE source='meta_api'").fetchone()[0], 100)
            self.assertEqual(connection.execute("SELECT SUM(spend) FROM ad_spend WHERE ad_account_connection_id=? AND date='2026-08-01'", (account["id"],)).fetchone()[0], 3)
            allocation_before = tuple(connection.execute("SELECT allocation_mode,product_id FROM meta_ad_allocation WHERE workspace_id=1 AND ad_account_connection_id=? AND ad_id='A'", (account["id"],)).fetchone())
            connection.execute(
                "INSERT INTO ad_spend(workspace_id,date,platform,campaign_id,campaign_name,adset_id,adset_name,ad_id,ad_name,spend,ad_account_connection_id,brand_id) VALUES (1,'2026-08-02','meta','C','Campaign','S','Set','A','Ad A',180000,?,?)",
                (account["id"], brand_a["id"]),
            )
            connection.execute("INSERT INTO marketing_spend(workspace_id,ad_account_connection_id,brand_id,date,channel,original_amount,currency,amount_krw,source,external_key) VALUES (1,?,?,'2026-08-02','Meta',180000,'KRW',180000,'meta_api','meta:v8:2')", (account["id"], brand_a["id"]))
            connection.execute("INSERT INTO naver_account_sync_day(workspace_id,naver_account_connection_id,date,total_amount_krw) VALUES (1,?,'2026-08-02',36082)", (naver_id,))
            connection.execute("INSERT INTO naver_adgroup_spend(workspace_id,naver_account_connection_id,campaign_id,adgroup_id,brand_id,product_id,allocation_mode,date,amount_krw,external_key) VALUES (1,?,'C','na-direct-2',?,?,'product','2026-08-02',36082,'na-direct-2')", (naver_id, brand_a["id"], product_a["id"]))
            connection.execute("INSERT INTO manual_marketing_spend(id,batch_id,workspace_id,brand_id,product_id,date,channel,amount_krw,memo,allocation_mode) VALUES ('manual-v8','batch-v8',1,?,?,'2026-08-02','기타',20000,'fixture','single')", (brand_a["id"], product_a["id"]))
            connection.execute("INSERT INTO sale(id,workspace_id,date,product_id,platform_id,selling_price,quantity,total_selling_amount,total_cost_amount,commission_amount,net_profit) VALUES ('v8-sale-2',1,'2026-08-02',801,?,1000000,1,1000000,0,0,1000000)", (platform["id"],))
            connection.commit()
            self.assertEqual(tuple(connection.execute("SELECT allocation_mode,product_id FROM meta_ad_allocation WHERE workspace_id=1 AND ad_account_connection_id=? AND ad_id='A'", (account["id"],)).fetchone()), allocation_before)
        combined_path = f"/api/sbrocor/finance/v1/sales-analysis/compare?workspace_id=1&a_start=2026-08-02&a_end=2026-08-02&b_start=2026-08-02&b_end=2026-08-02"
        combined = self.request("GET", combined_path).json
        combined_product = {row["id"]: row for row in combined["products"]}[product_a["id"]]["periods"]["a"]
        self.assertEqual(combined_product["direct_meta_advertising_spend"], 180000)
        self.assertEqual(combined_product["direct_naver_advertising_spend"], 36082)
        self.assertEqual(combined_product["direct_other_advertising_spend"], 20000)
        self.assertEqual(combined_product["direct_advertising_cost"], 236082)
        self.assertEqual(combined_product["profit_after_direct_advertising"], 763918)
        self.request("POST", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/meta-ads/C/allocation?workspace_id=1", {"allocation_mode": "unassigned", "product_id": None})
        with closing(connect()) as connection:
            for ad_id, spend in (("A", 50), ("B", 30), ("C", 20)):
                connection.execute(
                    "INSERT INTO ad_spend(workspace_id,date,platform,campaign_id,campaign_name,adset_id,adset_name,ad_id,ad_name,spend,ad_account_connection_id,brand_id) VALUES (1,'2026-08-03','meta','C','Campaign','S','Set',?,?,?, ?,?)",
                    (ad_id, f"Ad {ad_id}", spend, account["id"], brand_a["id"]),
                )
            connection.execute("INSERT INTO marketing_spend(workspace_id,ad_account_connection_id,brand_id,date,channel,original_amount,currency,amount_krw,source,external_key) VALUES (1,?,?,'2026-08-03','Meta',100000,'KRW',100000,'meta_api','meta:v8:3')", (account["id"], brand_a["id"]))
            connection.commit()
        fixture_path = f"/api/sbrocor/finance/v1/sales-analysis/compare?workspace_id=1&a_start=2026-08-03&a_end=2026-08-03&b_start=2026-08-03&b_end=2026-08-03"
        fixture = self.request("GET", fixture_path).json["periods"]["a"]["totals"]["meta_product_attribution"]
        self.assertEqual((fixture["direct_product_amount"], fixture["brand_common_amount"], fixture["unassigned_amount"], fixture["complete"]), (50000, 30000, 20000, False))
        self.assertEqual(fixture["direct_product_amount"] + fixture["brand_common_amount"] + fixture["unassigned_amount"], 100000)
        self.request("POST", f"/api/sbrocor/finance/v1/ad-accounts/{account['id']}/meta-ads/C/allocation?workspace_id=1", {"allocation_mode": "product", "product_id": product_a["id"]})
        fixture = self.request("GET", fixture_path).json["periods"]["a"]["totals"]["meta_product_attribution"]
        self.assertEqual((fixture["direct_product_amount"], fixture["brand_common_amount"], fixture["unassigned_amount"], fixture["complete"]), (70000, 30000, 0, True))
        self.assertEqual(fixture["direct_product_amount"] + fixture["brand_common_amount"] + fixture["unassigned_amount"], 100000)

    def test_v8_migration_is_atomic_idempotent_and_preserves_financial_rows(self):
        self.create_workspace(1)
        with closing(connect()) as connection:
            connection.execute("INSERT INTO finance_transaction(id,workspace_id,date,merchant,amount,category) VALUES ('v8',1,'2026-08-01','fixture',123,'광고비')")
            connection.execute("DROP INDEX IF EXISTS ix_meta_ad_allocation_connection")
            connection.execute("DROP INDEX IF EXISTS ix_meta_ad_allocation_product")
            connection.execute("DROP TABLE IF EXISTS meta_ad_allocation")
            connection.execute("DELETE FROM schema_version WHERE version=8")
            connection.commit()
        before = None
        with closing(connect()) as connection:
            before = tuple(connection.execute("SELECT COUNT(*),SUM(amount) FROM finance_transaction").fetchone())
        with patch("sbrocor_finance.database._v8_migration_hook", side_effect=RuntimeError("v8 failure")):
            with self.assertRaisesRegex(RuntimeError, "v8 failure"):
                initialize_database()
        with closing(connect()) as connection:
            self.assertEqual(connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 7)
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='meta_ad_allocation'").fetchone())
            self.assertEqual(tuple(connection.execute("SELECT COUNT(*),SUM(amount) FROM finance_transaction").fetchone()), before)
        initialize_database(); initialize_database()
        with closing(connect()) as connection:
            self.assertEqual(connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 8)
            self.assertEqual(tuple(connection.execute("SELECT COUNT(*),SUM(amount) FROM finance_transaction").fetchone()), before)
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])


if __name__ == "__main__":
    unittest.main()


