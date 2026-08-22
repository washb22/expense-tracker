"""SQLite repository. All data access is explicitly workspace-scoped."""

from __future__ import annotations

import sqlite3
import uuid
import math
from typing import Any, Iterable


RESOURCE_CONFIG = {
    "transactions": {
        "table": "finance_transaction",
        "fields": ("id", "date", "merchant", "amount", "category"),
        "required": ("date", "merchant", "amount"),
        "string_id": True,
    },
    "categories": {
        "table": "rule",
        "fields": ("id", "keyword", "category"),
        "required": ("keyword", "category"),
    },
    "products": {
        "table": "product",
        "fields": ("id", "name", "sku", "cost_price", "category", "created_at"),
        "required": ("name", "cost_price"),
    },
    "platforms": {
        "table": "platform",
        "fields": ("id", "name", "commission_rate", "created_at"),
        "required": ("name", "commission_rate"),
    },
    "sales": {
        "table": "sale",
        "fields": (
            "id", "date", "product_id", "platform_id", "selling_price", "quantity",
            "total_selling_amount", "total_cost_amount", "commission_amount", "net_profit", "created_at",
        ),
        "required": (
            "date", "product_id", "platform_id", "selling_price", "quantity",
            "total_selling_amount", "total_cost_amount", "commission_amount", "net_profit",
        ),
        "string_id": True,
    },
    "ads": {
        "table": "ad_spend",
        "fields": (
            "id", "date", "platform", "campaign_id", "campaign_name", "adset_id", "adset_name",
            "ad_id", "ad_name", "spend", "impressions", "clicks", "ctr", "cpc", "cpm",
            "conversions", "conversion_value", "roas", "created_at",
        ),
        "required": ("date",),
    },
}


class FinanceRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def list_workspaces(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute("SELECT id, name FROM workspace ORDER BY id")]

    def get_workspace(self, workspace_id: int) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT id, name FROM workspace WHERE id=?", (workspace_id,)).fetchone()
        return dict(row) if row else None

    def create_workspace(self, payload: dict[str, Any]) -> dict[str, Any]:
        if "id" not in payload or not payload.get("name"):
            raise ValueError("workspace id and name are required")
        self.connection.execute("INSERT INTO workspace(id, name) VALUES (?, ?)", (payload["id"], payload["name"]))
        self.connection.commit()
        return self.get_workspace(int(payload["id"]))  # type: ignore[return-value]

    def update_workspace(self, workspace_id: int, payload: dict[str, Any]) -> dict[str, Any] | None:
        if "name" in payload:
            self.connection.execute("UPDATE workspace SET name=? WHERE id=?", (payload["name"], workspace_id))
            self.connection.commit()
        return self.get_workspace(workspace_id)

    def delete_workspace(self, workspace_id: int) -> bool:
        if any(self.counts(workspace_id).values()):
            raise sqlite3.IntegrityError("workspace contains financial records")
        settings = self.connection.execute(
            "SELECT 1 FROM workspace_settings WHERE workspace_id=?", (workspace_id,)
        ).fetchone()
        if settings:
            raise sqlite3.IntegrityError("workspace contains financial settings")
        cursor = self.connection.execute("DELETE FROM workspace WHERE id=?", (workspace_id,))
        self.connection.commit()
        return cursor.rowcount == 1

    def list_resource(self, resource: str, workspace_id: int, month: str | None = None) -> list[dict[str, Any]]:
        table = RESOURCE_CONFIG[resource]["table"]
        if month and "date" in RESOURCE_CONFIG[resource]["fields"]:
            return [dict(row) for row in self.connection.execute(
                f"SELECT * FROM {table} WHERE workspace_id=? AND substr(date,1,7)=? ORDER BY date DESC, id",
                (workspace_id, month),
            )]
        return [dict(row) for row in self.connection.execute(
            f"SELECT * FROM {table} WHERE workspace_id=? ORDER BY id", (workspace_id,)
        )]

    def available_months(self, workspace_id: int, resource: str) -> list[str]:
        config = RESOURCE_CONFIG[resource]
        if "date" not in config["fields"]:
            return []
        rows = self.connection.execute(
            f"SELECT DISTINCT substr(date,1,7) month FROM {config['table']} "
            "WHERE workspace_id=? AND date IS NOT NULL ORDER BY month DESC",
            (workspace_id,),
        )
        return [row[0] for row in rows if row[0]]

    def query_resource(
        self, resource: str, workspace_id: int, *, page: int = 1, page_size: int = 50,
        month: str | None = None, start_date: str | None = None, end_date: str | None = None,
        search: str | None = None, filters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        config = RESOURCE_CONFIG[resource]
        table = config["table"]
        clauses = ["workspace_id=?"]
        params: list[Any] = [workspace_id]
        if "date" in config["fields"]:
            if month:
                clauses.append("substr(date,1,7)=?")
                params.append(month)
            if start_date:
                clauses.append("date>=?")
                params.append(start_date)
            if end_date:
                clauses.append("date<=?")
                params.append(end_date)
        searchable = [field for field in ("merchant", "category", "keyword", "name", "sku", "campaign_name", "adset_name", "ad_name") if field in config["fields"]]
        if search and searchable:
            clauses.append("(" + " OR ".join(f"{field} LIKE ?" for field in searchable) + ")")
            params.extend([f"%{search}%"] * len(searchable))
        for field, value in (filters or {}).items():
            if value not in (None, "") and field in config["fields"]:
                clauses.append(f"{field}=?")
                params.append(value)
        where = " AND ".join(clauses)
        total = int(self.connection.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", params).fetchone()[0])
        page_size = max(1, min(int(page_size), 200))
        page = max(1, int(page))
        order = "date DESC, id DESC" if "date" in config["fields"] else "id DESC"
        rows = self.connection.execute(
            f"SELECT * FROM {table} WHERE {where} ORDER BY {order} LIMIT ? OFFSET ?",
            [*params, page_size, (page - 1) * page_size],
        )
        return {
            "items": [dict(row) for row in rows],
            "pagination": {"page": page, "page_size": page_size, "total": total, "pages": math.ceil(total / page_size) if total else 0},
            "available_months": self.available_months(workspace_id, resource),
        }

    def get_resource(self, resource: str, workspace_id: int, item_id: str) -> dict[str, Any] | None:
        table = RESOURCE_CONFIG[resource]["table"]
        row = self.connection.execute(
            f"SELECT * FROM {table} WHERE id=? AND workspace_id=?", (item_id, workspace_id)
        ).fetchone()
        return dict(row) if row else None

    def create_resource(self, resource: str, workspace_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        config = RESOURCE_CONFIG[resource]
        missing = [field for field in config["required"] if payload.get(field) is None]
        if missing:
            raise ValueError(f"missing required fields: {', '.join(missing)}")
        values = dict(payload)
        if config.get("string_id") and not values.get("id"):
            values["id"] = str(uuid.uuid4())
        fields = [field for field in config["fields"] if field in values]
        columns = ["workspace_id", *fields]
        params = [workspace_id, *(values[field] for field in fields)]
        placeholders = ",".join("?" for _ in columns)
        cursor = self.connection.execute(
            f"INSERT INTO {config['table']} ({','.join(columns)}) VALUES ({placeholders})", params
        )
        item_id = values.get("id", cursor.lastrowid)
        self.connection.commit()
        return self.get_resource(resource, workspace_id, str(item_id))  # type: ignore[return-value]

    def update_resource(self, resource: str, workspace_id: int, item_id: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        config = RESOURCE_CONFIG[resource]
        fields = [field for field in config["fields"] if field != "id" and field in payload]
        if fields:
            assignments = ",".join(f"{field}=?" for field in fields)
            self.connection.execute(
                f"UPDATE {config['table']} SET {assignments} WHERE id=? AND workspace_id=?",
                [*(payload[field] for field in fields), item_id, workspace_id],
            )
            self.connection.commit()
        return self.get_resource(resource, workspace_id, item_id)

    def delete_resource(self, resource: str, workspace_id: int, item_id: str) -> bool:
        table = RESOURCE_CONFIG[resource]["table"]
        cursor = self.connection.execute(
            f"DELETE FROM {table} WHERE id=? AND workspace_id=?", (item_id, workspace_id)
        )
        self.connection.commit()
        return cursor.rowcount == 1

    def import_if_empty(self, workspace_id: int, data: dict[str, Any]) -> dict[str, int]:
        if int(data["workspace"]["id"]) != workspace_id:
            raise ValueError("manifest workspace does not match URL workspace")
        if any(self.counts(workspace_id).values()):
            raise sqlite3.IntegrityError("destination workspace already contains financial data")
        settings_exists = self.connection.execute(
            "SELECT 1 FROM workspace_settings WHERE workspace_id=?", (workspace_id,)
        ).fetchone()
        if settings_exists:
            raise sqlite3.IntegrityError("destination workspace already contains settings")
        counts: dict[str, int] = {}
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            self.connection.execute(
                "INSERT INTO workspace(id,name) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name",
                (workspace_id, data["workspace"]["name"]),
            )
            for resource in ("transactions", "categories", "products", "platforms", "sales", "ads"):
                for item in data.get(resource, []):
                    self.create_resource_uncommitted(resource, workspace_id, item)
                counts[resource] = len(data.get(resource, []))
            settings = data.get("workspace_settings")
            if settings:
                self.connection.execute(
                    "INSERT INTO workspace_settings(id,workspace_id,meta_ad_account_id,updated_at) VALUES (?,?,?,?)",
                    (settings.get("id"), workspace_id, settings.get("meta_ad_account_id"), settings.get("updated_at")),
                )
            self.connection.commit()
            return counts
        except Exception:
            self.connection.rollback()
            raise

    def create_resource_uncommitted(self, resource: str, workspace_id: int, payload: dict[str, Any]) -> None:
        config = RESOURCE_CONFIG[resource]
        fields = [field for field in config["fields"] if field in payload]
        columns = ["workspace_id", *fields]
        self.connection.execute(
            f"INSERT INTO {config['table']} ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            [workspace_id, *(payload[field] for field in fields)],
        )

    def export_workspace(self, workspace_id: int) -> dict[str, Any] | None:
        workspace = self.get_workspace(workspace_id)
        if not workspace:
            return None
        payload: dict[str, Any] = {"manifest_version": 1, "workspace": workspace}
        for resource in ("transactions", "categories", "products", "platforms", "sales", "ads"):
            payload[resource] = self.list_resource(resource, workspace_id)
        row = self.connection.execute("SELECT * FROM workspace_settings WHERE workspace_id=?", (workspace_id,)).fetchone()
        payload["workspace_settings"] = dict(row) if row else None
        return payload

    def counts(self, workspace_id: int) -> dict[str, int]:
        result = {}
        for resource, config in RESOURCE_CONFIG.items():
            result[resource] = self.connection.execute(
                f"SELECT COUNT(*) FROM {config['table']} WHERE workspace_id=?", (workspace_id,)
            ).fetchone()[0]
        return result

    def dashboard(self, workspace_id: int, month: str | None = None, start_date: str | None = None, end_date: str | None = None) -> dict[str, Any]:
        conditions: list[str] = []
        values: list[Any] = [workspace_id]
        if month:
            conditions.append("substr(date,1,7)=?"); values.append(month)
        if start_date:
            conditions.append("date>=?"); values.append(start_date)
        if end_date:
            conditions.append("date<=?"); values.append(end_date)
        date_clause = "".join(f" AND {condition}" for condition in conditions)
        params = tuple(values)
        expenses = self.connection.execute(
            "SELECT COALESCE(SUM(amount),0) FROM finance_transaction WHERE workspace_id=? AND category <> '미분류'" + date_clause, params
        ).fetchone()[0]
        sale_row = self.connection.execute(
            "SELECT COALESCE(SUM(total_selling_amount),0), COALESCE(SUM(net_profit),0) FROM sale WHERE workspace_id=?" + date_clause,
            params,
        ).fetchone()
        ad_spend = self.connection.execute(
            "SELECT COALESCE(SUM(spend),0) FROM ad_spend WHERE workspace_id=?" + date_clause, params
        ).fetchone()[0]
        categories = [dict(row) for row in self.connection.execute(
            "SELECT category, COUNT(*) count, COALESCE(SUM(amount),0) amount "
            "FROM finance_transaction WHERE workspace_id=? AND category <> '미분류'" + date_clause +
            " GROUP BY category ORDER BY amount DESC", params,
        )]
        merchants = [dict(row) for row in self.connection.execute(
            "SELECT category, merchant, COUNT(*) count, COALESCE(SUM(amount),0) amount "
            "FROM finance_transaction WHERE workspace_id=? AND category <> '미분류'" + date_clause +
            " GROUP BY category, merchant ORDER BY amount DESC", params,
        )]
        daily_expenses = [dict(row) for row in self.connection.execute(
            "SELECT date, COALESCE(SUM(amount),0) amount FROM finance_transaction "
            "WHERE workspace_id=? AND category <> '미분류'" + date_clause + " GROUP BY date ORDER BY date", params,
        )]
        recent_sales = [dict(row) for row in self.connection.execute(
            "SELECT s.*, p.name product_name, pl.name platform_name FROM sale s "
            "JOIN product p ON p.id=s.product_id JOIN platform pl ON pl.id=s.platform_id "
            "WHERE s.workspace_id=?" + date_clause.replace("date", "s.date") + " ORDER BY s.date DESC, s.id DESC LIMIT 10", params,
        )]
        return {
            "workspace_id": workspace_id,
            "total_expenses": expenses,
            "total_sales": sale_row[0],
            "total_net_profit": sale_row[1],
            "total_ad_spend": ad_spend,
            "month": month,
            "available_months": sorted(set(self.available_months(workspace_id, "transactions") + self.available_months(workspace_id, "sales") + self.available_months(workspace_id, "ads")), reverse=True),
            "categories": categories,
            "merchants": merchants,
            "daily_expenses": daily_expenses,
            "recent_sales": recent_sales,
            "counts": self.counts(workspace_id),
        }

    def business_analytics(self, workspace_id: int, month: str | None = None, start_date: str | None = None, end_date: str | None = None) -> dict[str, Any]:
        result = self.dashboard(workspace_id, month, start_date, end_date)
        conditions: list[str] = []
        values: list[Any] = [workspace_id]
        if month:
            conditions.append("substr(s.date,1,7)=?"); values.append(month)
        if start_date:
            conditions.append("s.date>=?"); values.append(start_date)
        if end_date:
            conditions.append("s.date<=?"); values.append(end_date)
        clause = "".join(f" AND {condition}" for condition in conditions)
        params = tuple(values)
        result["daily_sales"] = [dict(row) for row in self.connection.execute(
            "SELECT s.date, SUM(s.total_selling_amount) sales, SUM(s.net_profit) net_profit, SUM(s.quantity) quantity "
            "FROM sale s WHERE s.workspace_id=?" + clause + " GROUP BY s.date ORDER BY s.date", params,
        )]
        result["products"] = [dict(row) for row in self.connection.execute(
            "SELECT p.id, p.name, COUNT(*) count, SUM(s.quantity) quantity, SUM(s.total_selling_amount) sales, SUM(s.net_profit) net_profit "
            "FROM sale s JOIN product p ON p.id=s.product_id WHERE s.workspace_id=?" + clause +
            " GROUP BY p.id,p.name ORDER BY sales DESC", params,
        )]
        result["platforms"] = [dict(row) for row in self.connection.execute(
            "SELECT p.id, p.name, COUNT(*) count, SUM(s.quantity) quantity, SUM(s.total_selling_amount) sales, SUM(s.net_profit) net_profit "
            "FROM sale s JOIN platform p ON p.id=s.platform_id WHERE s.workspace_id=?" + clause +
            " GROUP BY p.id,p.name ORDER BY sales DESC", params,
        )]
        result["operating_profit"] = result["total_net_profit"] - result["total_expenses"]
        result["operating_margin"] = (result["operating_profit"] / result["total_sales"] * 100) if result["total_sales"] else 0
        return result

    def ad_analytics(self, workspace_id: int, month: str | None = None, start_date: str | None = None, end_date: str | None = None) -> dict[str, Any]:
        conditions: list[str] = []
        values: list[Any] = [workspace_id]
        if month:
            conditions.append("substr(date,1,7)=?"); values.append(month)
        if start_date:
            conditions.append("date>=?"); values.append(start_date)
        if end_date:
            conditions.append("date<=?"); values.append(end_date)
        clause = "".join(f" AND {condition}" for condition in conditions)
        params = tuple(values)
        summary = dict(self.connection.execute(
            "SELECT COALESCE(SUM(spend),0) spend, COALESCE(SUM(impressions),0) impressions, "
            "COALESCE(SUM(clicks),0) clicks, COALESCE(SUM(conversions),0) conversions, "
            "COALESCE(SUM(conversion_value),0) conversion_value FROM ad_spend WHERE workspace_id=?" + clause, params,
        ).fetchone())
        summary["ctr"] = summary["clicks"] / summary["impressions"] * 100 if summary["impressions"] else 0
        summary["cpc"] = summary["spend"] / summary["clicks"] if summary["clicks"] else 0
        summary["roas"] = summary["conversion_value"] / summary["spend"] if summary["spend"] else 0
        def grouped(columns: str) -> list[dict[str, Any]]:
            return [dict(row) for row in self.connection.execute(
                f"SELECT {columns}, SUM(spend) spend, SUM(impressions) impressions, SUM(clicks) clicks, "
                "SUM(conversions) conversions, SUM(conversion_value) conversion_value "
                "FROM ad_spend WHERE workspace_id=?" + clause + f" GROUP BY {columns} ORDER BY spend DESC", params,
            )]
        return {"summary": summary, "daily": grouped("date"), "campaigns": grouped("campaign_id,campaign_name"), "adsets": grouped("campaign_id,adset_id,adset_name"), "creatives": grouped("campaign_id,adset_id,ad_id,ad_name"), "available_months": self.available_months(workspace_id, "ads")}

