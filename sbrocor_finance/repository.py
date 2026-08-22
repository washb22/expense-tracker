"""SQLite repository. All data access is explicitly workspace-scoped."""

from __future__ import annotations

import sqlite3
import uuid
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

    def list_resource(self, resource: str, workspace_id: int) -> list[dict[str, Any]]:
        table = RESOURCE_CONFIG[resource]["table"]
        return [dict(row) for row in self.connection.execute(
            f"SELECT * FROM {table} WHERE workspace_id=? ORDER BY id", (workspace_id,)
        )]

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

    def dashboard(self, workspace_id: int) -> dict[str, Any]:
        expenses = self.connection.execute(
            "SELECT COALESCE(SUM(amount),0) FROM finance_transaction WHERE workspace_id=? AND category <> '미분류'", (workspace_id,)
        ).fetchone()[0]
        sale_row = self.connection.execute(
            "SELECT COALESCE(SUM(total_selling_amount),0), COALESCE(SUM(net_profit),0) FROM sale WHERE workspace_id=?",
            (workspace_id,),
        ).fetchone()
        ad_spend = self.connection.execute(
            "SELECT COALESCE(SUM(spend),0) FROM ad_spend WHERE workspace_id=?", (workspace_id,)
        ).fetchone()[0]
        return {
            "workspace_id": workspace_id,
            "total_expenses": expenses,
            "total_sales": sale_row[0],
            "total_net_profit": sale_row[1],
            "total_ad_spend": ad_spend,
            "counts": self.counts(workspace_id),
        }
