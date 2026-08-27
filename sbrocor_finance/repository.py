"""SQLite repository. All data access is explicitly workspace-scoped."""

from __future__ import annotations

import sqlite3
import uuid
import math
from decimal import Decimal
from fractions import Fraction
from datetime import date, datetime, timedelta
from typing import Any, Iterable
from zoneinfo import ZoneInfo

MARKETING_CHANNELS = ("Meta", "네이버", "Google", "카카오", "바이럴", "인플루언서", "체험단", "대행사", "기타")


def _kst_today() -> date:
    return datetime.now(ZoneInfo("Asia/Seoul")).date()

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
    "brands": {
        "table": "brand",
        "fields": ("id", "name", "active", "created_at"),
        "required": ("name",),
    },
    "product-groups": {
        "table": "product_group",
        "fields": ("id", "brand_id", "name", "active", "created_at", "updated_at"),
        "required": ("brand_id", "name"),
    },
    "products": {
        "table": "product",
        "fields": ("id", "name", "sku", "cost_price", "category", "brand_id", "product_group_id", "created_at"),
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
    "ad-accounts": {
        "table": "ad_account_connection",
        "fields": (
            "id", "brand_id", "platform", "account_id", "account_name", "currency",
            "credential_key", "active", "last_synced_at", "created_at", "updated_at",
        ),
        "required": ("brand_id", "platform", "account_id", "account_name", "currency", "credential_key"),
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
        clauses = [f"{table}.workspace_id=?"]
        params: list[Any] = [workspace_id]
        if "date" in config["fields"]:
            if month:
                clauses.append("substr(date,1,7)=?")
                params.append(month)
            if start_date:
                clauses.append("substr(date,1,10)>=?")
                params.append(start_date)
            if end_date:
                clauses.append("substr(date,1,10)<=?")
                params.append(end_date)
        searchable = [field for field in ("merchant", "category", "keyword", "name", "sku", "campaign_name", "adset_name", "ad_name") if field in config["fields"]]
        if search and searchable:
            clauses.append("(" + " OR ".join(f"{table}.{field} LIKE ?" for field in searchable) + ")")
            params.extend([f"%{search}%"] * len(searchable))
        for field, value in (filters or {}).items():
            if value not in (None, "") and field in config["fields"]:
                clauses.append(f"{table}.{field}=?")
                params.append(value)
        where = " AND ".join(clauses)
        total = int(self.connection.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", params).fetchone()[0])
        page_size = max(1, min(int(page_size), 200))
        page = max(1, int(page))
        order = "date DESC, id DESC" if "date" in config["fields"] else "id DESC"
        select = "*"
        if resource == "products":
            select = "product.*, brand.name brand_name, product_group.name product_group_name, (SELECT COUNT(*) FROM sale WHERE sale.workspace_id=product.workspace_id AND sale.product_id=product.id) sale_count"
            table = "product LEFT JOIN brand ON brand.id=product.brand_id AND brand.workspace_id=product.workspace_id LEFT JOIN product_group ON product_group.id=product.product_group_id AND product_group.workspace_id=product.workspace_id"
        elif resource == "product-groups":
            select = "product_group.*, brand.name brand_name"
            table = "product_group JOIN brand ON brand.id=product_group.brand_id AND brand.workspace_id=product_group.workspace_id"
        elif resource == "platforms":
            select = "platform.*, (SELECT COUNT(*) FROM sale WHERE sale.workspace_id=platform.workspace_id AND sale.platform_id=platform.id) sale_count"
        rows = self.connection.execute(
            f"SELECT {select} FROM {table} WHERE {where} ORDER BY {order} LIMIT ? OFFSET ?",
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
            if resource == "product-groups" and "updated_at" not in fields:
                assignments += ",updated_at=CURRENT_TIMESTAMP"
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

    def get_marketing_allocations(self, workspace_id: int, transaction_id: str) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute(
            "SELECT a.*, b.name brand_name, p.name product_name "
            "FROM marketing_allocation a "
            "LEFT JOIN brand b ON b.id=a.brand_id AND b.workspace_id=a.workspace_id "
            "LEFT JOIN product p ON p.id=a.product_id AND p.workspace_id=a.workspace_id "
            "WHERE a.workspace_id=? AND a.transaction_id=? ORDER BY a.created_at,a.id",
            (workspace_id, transaction_id),
        )]

    def replace_marketing_allocations(
        self, workspace_id: int, transaction_id: str, allocations: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        transaction = self.connection.execute(
            "SELECT id,amount,category FROM finance_transaction WHERE id=? AND workspace_id=?",
            (transaction_id, workspace_id),
        ).fetchone()
        if not transaction:
            raise LookupError("transaction not found")
        if transaction["category"] != "광고비":
            raise ValueError("marketing allocation is only available for 광고비 transactions")
        if not allocations:
            self.connection.execute(
                "DELETE FROM marketing_allocation WHERE workspace_id=? AND transaction_id=?",
                (workspace_id, transaction_id),
            )
            self.connection.commit()
            return []
        prepared: list[dict[str, Any]] = []
        for allocation in allocations:
            amount = int(allocation.get("amount", 0))
            if amount <= 0:
                raise ValueError("allocation amount must be greater than zero")
            brand_id = int(allocation["brand_id"]) if allocation.get("brand_id") not in (None, "") else None
            product_id = int(allocation["product_id"]) if allocation.get("product_id") not in (None, "") else None
            channel = str(allocation.get("channel", "")).strip()
            if not channel:
                raise ValueError("allocation channel is required")
            if channel not in MARKETING_CHANNELS:
                raise ValueError("unsupported marketing channel")
            brand = None
            if brand_id is not None:
                brand = self.connection.execute(
                    "SELECT id FROM brand WHERE id=? AND workspace_id=? AND active=1", (brand_id, workspace_id)
                ).fetchone()
                if not brand:
                    raise ValueError("allocation brand must be active and belong to the workspace")
            if product_id is not None:
                product = self.connection.execute(
                    "SELECT id,brand_id FROM product WHERE id=? AND workspace_id=?", (product_id, workspace_id)
                ).fetchone()
                if not product:
                    raise ValueError("allocation product must belong to the workspace")
                if brand_id is None:
                    raise ValueError("allocation brand is required when a product is selected")
                if product["brand_id"] is None:
                    raise ValueError("allocation product must have a brand before it can be selected")
                if int(product["brand_id"]) != brand_id:
                    raise ValueError("allocation product does not belong to the selected brand")
            prepared.append({
                "id": str(allocation.get("id") or uuid.uuid4()),
                "brand_id": brand_id,
                "product_id": product_id,
                "channel": channel,
                "amount": amount,
                "memo": str(allocation.get("memo", "")).strip() or None,
            })
        if sum(item["amount"] for item in prepared) != int(transaction["amount"]):
            raise ValueError("allocation amount total must equal the transaction amount")
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            self.connection.execute(
                "DELETE FROM marketing_allocation WHERE workspace_id=? AND transaction_id=?",
                (workspace_id, transaction_id),
            )
            self.connection.executemany(
                "INSERT INTO marketing_allocation(id,workspace_id,transaction_id,brand_id,product_id,channel,amount,memo) "
                "VALUES (:id,:workspace_id,:transaction_id,:brand_id,:product_id,:channel,:amount,:memo)",
                [{**item, "workspace_id": workspace_id, "transaction_id": transaction_id} for item in prepared],
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return self.get_marketing_allocations(workspace_id, transaction_id)

    def marketing_summary(
        self, workspace_id: int, month: str | None = None,
        start_date: str | None = None, end_date: str | None = None,
    ) -> dict[str, Any]:
        conditions = ["t.workspace_id=?", "t.category='광고비'"]
        params: list[Any] = [workspace_id]
        if month:
            conditions.append("substr(t.date,1,7)=?"); params.append(month)
        if start_date:
            conditions.append("substr(t.date,1,10)>=?"); params.append(start_date)
        if end_date:
            conditions.append("substr(t.date,1,10)<=?"); params.append(end_date)
        where = " AND ".join(conditions)
        total = int(self.connection.execute(
            f"SELECT COALESCE(SUM(t.amount),0) FROM finance_transaction t WHERE {where}", params
        ).fetchone()[0])
        allocated = int(self.connection.execute(
            f"SELECT COALESCE(SUM(a.amount),0) FROM marketing_allocation a "
            f"JOIN finance_transaction t ON t.id=a.transaction_id AND t.workspace_id=a.workspace_id WHERE {where}", params
        ).fetchone()[0])
        brands = [dict(row) for row in self.connection.execute(
            f"SELECT a.brand_id,COALESCE(b.name,'미지정') name,SUM(a.amount) amount "
            f"FROM marketing_allocation a JOIN finance_transaction t ON t.id=a.transaction_id AND t.workspace_id=a.workspace_id "
            f"LEFT JOIN brand b ON b.id=a.brand_id AND b.workspace_id=a.workspace_id WHERE {where} "
            "GROUP BY a.brand_id,b.name ORDER BY amount DESC", params,
        )]
        if total > allocated:
            unassigned = next((item for item in brands if item["brand_id"] is None), None)
            if unassigned:
                unassigned["amount"] += total - allocated
            else:
                brands.append({"brand_id": None, "name": "미지정", "amount": total - allocated})
        channels = [dict(row) for row in self.connection.execute(
            f"SELECT a.channel name,SUM(a.amount) amount FROM marketing_allocation a "
            f"JOIN finance_transaction t ON t.id=a.transaction_id AND t.workspace_id=a.workspace_id WHERE {where} "
            "GROUP BY a.channel ORDER BY amount DESC", params,
        )]
        if total > allocated:
            channels.append({"name": "미지정", "amount": total - allocated})
        products = [dict(row) for row in self.connection.execute(
            f"SELECT a.brand_id,a.product_id,COALESCE(p.name,'브랜드 공통') name,SUM(a.amount) amount "
            f"FROM marketing_allocation a JOIN finance_transaction t ON t.id=a.transaction_id AND t.workspace_id=a.workspace_id "
            f"LEFT JOIN product p ON p.id=a.product_id AND p.workspace_id=a.workspace_id WHERE {where} "
            "GROUP BY a.brand_id,a.product_id,p.name ORDER BY amount DESC", params,
        )]
        return {
            "workspace_id": workspace_id,
            "total_advertising_cost": total,
            "allocated_amount": allocated,
            "unallocated_amount": total - allocated,
            "brands": brands,
            "channels": channels,
            "products": products,
        }

    def _meta_product_attribution(
        self, workspace_id: int, start_date: str, end_date: str, brand_id: int | None = None
    ) -> dict[str, Any]:
        """Allocate each Meta account/day total exactly across its raw ads.

        ``marketing_spend`` remains the only source of the account total. Raw
        ``ad_spend`` rows provide weights only, so this cannot double-count the
        total Meta spend.
        """
        scope = " AND ms.brand_id=?" if brand_id is not None else ""
        totals = self.connection.execute(
            "SELECT ms.ad_account_connection_id,ms.brand_id,substr(ms.date,1,10) date,ms.amount_krw "
            "FROM marketing_spend ms JOIN ad_account_connection ac ON ac.id=ms.ad_account_connection_id "
            "AND ac.workspace_id=ms.workspace_id WHERE ms.workspace_id=? AND ac.platform='meta' "
            "AND ms.source='meta_api' AND substr(ms.date,1,10)>=? AND substr(ms.date,1,10)<=?" + scope,
            [workspace_id, start_date, end_date, *( [brand_id] if brand_id is not None else [] )],
        ).fetchall()
        allocations = {
            (int(row["ad_account_connection_id"]), str(row["ad_id"])): dict(row)
            for row in self.connection.execute(
                "SELECT ad_account_connection_id,ad_id,allocation_mode,product_id,product_group_id FROM meta_ad_allocation "
                "WHERE workspace_id=?", (workspace_id,),
            )
        }
        direct_by_product: dict[int, int] = {}
        direct_by_product_group: dict[int, int] = {}
        unassigned_by_brand: dict[int, int] = {}
        brand_common = unassigned = unavailable = 0
        for total in totals:
            amount_value = total["amount_krw"]
            if amount_value is None:
                continue
            amount = int(amount_value)
            connection_id = int(total["ad_account_connection_id"])
            current_brand = int(total["brand_id"])
            raw_rows = self.connection.execute(
                "SELECT ad_id,SUM(spend) raw_spend FROM ad_spend WHERE workspace_id=? "
                "AND ad_account_connection_id=? AND platform='meta' AND substr(date,1,10)=? "
                "AND ad_id IS NOT NULL GROUP BY ad_id HAVING SUM(spend)>0 ORDER BY ad_id",
                (workspace_id, connection_id, total["date"]),
            ).fetchall()
            weights = [(str(row["ad_id"]), Fraction(Decimal(str(row["raw_spend"])))) for row in raw_rows]
            weight_total = sum((weight for _, weight in weights), Fraction(0))
            if not weights or weight_total <= 0:
                unavailable += amount
                unassigned += amount
                unassigned_by_brand[current_brand] = unassigned_by_brand.get(current_brand, 0) + amount
                continue
            floors: list[list[Any]] = []
            assigned = 0
            for ad_id, weight in weights:
                exact = Fraction(amount) * weight / weight_total
                base = exact.numerator // exact.denominator
                floors.append([ad_id, base, exact - base])
                assigned += base
            for entry in sorted(floors, key=lambda value: (-value[2], value[0]))[: amount - assigned]:
                entry[1] += 1
            for ad_id, allocated, _remainder in floors:
                mapping = allocations.get((connection_id, ad_id), {"allocation_mode": "unassigned", "product_id": None, "product_group_id": None})
                mode = mapping["allocation_mode"]
                if mode == "product" and mapping["product_id"] is not None:
                    product_key = int(mapping["product_id"])
                    direct_by_product[product_key] = direct_by_product.get(product_key, 0) + int(allocated)
                elif mode == "product_group" and mapping["product_group_id"] is not None:
                    group_key = int(mapping["product_group_id"])
                    direct_by_product_group[group_key] = direct_by_product_group.get(group_key, 0) + int(allocated)
                elif mode == "brand_common":
                    brand_common += int(allocated)
                else:
                    unassigned += int(allocated)
                    unassigned_by_brand[current_brand] = unassigned_by_brand.get(current_brand, 0) + int(allocated)
        return {
            "direct_by_product": direct_by_product,
            "direct_product_amount": sum(direct_by_product.values()),
            "direct_by_product_group": direct_by_product_group,
            "direct_product_group_amount": sum(direct_by_product_group.values()),
            "brand_common_amount": brand_common,
            "unassigned_amount": unassigned,
            "unassigned_by_brand": unassigned_by_brand,
            "unavailable_amount": unavailable,
            "complete": unassigned == 0,
        }

    def _product_group_analysis(
        self, workspace_id: int, periods: dict[str, tuple[str, str]], brand_id: int | None
    ) -> list[dict[str, Any]]:
        groups = [dict(row) for row in self.connection.execute(
            "SELECT pg.id,pg.name,pg.brand_id,pg.active,b.name brand_name FROM product_group pg "
            "JOIN brand b ON b.id=pg.brand_id AND b.workspace_id=pg.workspace_id "
            "WHERE pg.workspace_id=?" + (" AND pg.brand_id=?" if brand_id is not None else "") +
            " ORDER BY pg.name,pg.id", [workspace_id, *( [brand_id] if brand_id is not None else [] )],
        )]
        for group in groups:
            group["periods"] = {}
            group_id = int(group["id"])
            group_brand_id = int(group["brand_id"])
            product_ids = [int(row[0]) for row in self.connection.execute(
                "SELECT id FROM product WHERE workspace_id=? AND product_group_id=?", (workspace_id, group_id)
            )]
            for key, (start_date, end_date) in periods.items():
                sales = dict(self.connection.execute(
                    "SELECT COALESCE(SUM(s.total_selling_amount),0) revenue,COALESCE(SUM(s.quantity),0) quantity,"
                    "COALESCE(SUM(s.net_profit),0) sales_profit FROM sale s JOIN product p ON p.id=s.product_id "
                    "AND p.workspace_id=s.workspace_id WHERE s.workspace_id=? AND p.product_group_id=? "
                    "AND substr(s.date,1,10)>=? AND substr(s.date,1,10)<=?",
                    (workspace_id, group_id, start_date, end_date),
                ).fetchone())
                meta = self._meta_product_attribution(workspace_id, start_date, end_date, group_brand_id)
                meta_group = int(meta["direct_by_product_group"].get(group_id, 0))
                meta_product = sum(int(meta["direct_by_product"].get(pid, 0)) for pid in product_ids)
                naver_product = int(self.connection.execute(
                    "SELECT COALESCE(SUM(ns.amount_krw),0) FROM naver_adgroup_spend ns JOIN product p "
                    "ON p.id=ns.product_id AND p.workspace_id=ns.workspace_id WHERE ns.workspace_id=? "
                    "AND ns.allocation_mode='product' AND p.product_group_id=? AND ns.date>=? AND ns.date<=?",
                    (workspace_id, group_id, start_date, end_date),
                ).fetchone()[0])
                other_product = int(self.connection.execute(
                    "SELECT COALESCE(SUM(ms.amount_krw),0) FROM marketing_spend ms JOIN product p "
                    "ON p.id=ms.product_id AND p.workspace_id=ms.workspace_id WHERE ms.workspace_id=? "
                    "AND ms.source NOT IN ('meta_api','naver_api') AND p.product_group_id=? "
                    "AND substr(ms.date,1,10)>=? AND substr(ms.date,1,10)<=?",
                    (workspace_id, group_id, start_date, end_date),
                ).fetchone()[0])
                other_product += int(self.connection.execute(
                    "SELECT COALESCE(SUM(m.amount_krw),0) FROM manual_marketing_spend m JOIN product p "
                    "ON p.id=m.product_id AND p.workspace_id=m.workspace_id WHERE m.workspace_id=? "
                    "AND p.product_group_id=? AND substr(m.date,1,10)>=? AND substr(m.date,1,10)<=?",
                    (workspace_id, group_id, start_date, end_date),
                ).fetchone()[0])
                direct = meta_group + meta_product + naver_product + other_product
                group["periods"][key] = {
                    **sales,
                    "direct_meta_group_spend": meta_group,
                    "direct_meta_product_spend": meta_product,
                    "direct_naver_product_spend": naver_product,
                    "direct_other_product_spend": other_product,
                    "direct_advertising_cost": direct,
                    "profit_after_advertising": int(sales["sales_profit"]) - direct,
                }
        return groups

    def sales_analysis_compare(
        self, workspace_id: int, periods: dict[str, tuple[str, str]],
        brand_id: int | None = None, product_id: int | None = None,
    ) -> dict[str, Any]:
        """Aggregate sales against actual daily marketing spend for two periods."""
        brand = None
        if brand_id is not None:
            brand = self.connection.execute(
                "SELECT id,name FROM brand WHERE id=? AND workspace_id=?", (brand_id, workspace_id)
            ).fetchone()
            if not brand:
                raise ValueError("brand must belong to the workspace")
        product = None
        if product_id is not None:
            product = self.connection.execute(
                "SELECT id,name,brand_id FROM product WHERE id=? AND workspace_id=?", (product_id, workspace_id)
            ).fetchone()
            if not product:
                raise ValueError("product must belong to the workspace")
            if product["brand_id"] is None:
                raise ValueError("analysis product must have a brand")
            if brand_id is not None and int(product["brand_id"]) != brand_id:
                raise ValueError("product does not belong to the selected brand")
            if brand_id is None:
                brand_id = int(product["brand_id"])
                brand = self.connection.execute(
                    "SELECT id,name FROM brand WHERE id=? AND workspace_id=?", (brand_id, workspace_id)
                ).fetchone()

        product_scope = ""
        scope_params: list[Any] = []
        if product_id is not None:
            product_scope = " AND s.product_id=?"; scope_params.append(product_id)
        elif brand_id is not None:
            product_scope = " AND p.brand_id=?"; scope_params.append(brand_id)

        spend_scope = ""
        spend_params: list[Any] = []
        if product_id is not None:
            spend_scope = " AND ms.product_id=?"; spend_params.append(product_id)
        elif brand_id is not None:
            spend_scope = " AND ms.brand_id=?"; spend_params.append(brand_id)
        manual_scope = spend_scope.replace("ms.", "m.")

        paid_scope = ""
        paid_params: list[Any] = []
        if product_id is not None:
            paid_scope = " AND a.product_id=?"; paid_params.append(product_id)
        elif brand_id is not None:
            paid_scope = " AND a.brand_id=?"; paid_params.append(brand_id)

        product_rows = [dict(row) for row in self.connection.execute(
            "SELECT p.id,p.name,p.brand_id,b.name brand_name,p.product_group_id,pg.name product_group_name FROM product p "
            "LEFT JOIN brand b ON b.id=p.brand_id AND b.workspace_id=p.workspace_id "
            "LEFT JOIN product_group pg ON pg.id=p.product_group_id AND pg.workspace_id=p.workspace_id "
            "WHERE p.workspace_id=?" +
            (" AND p.id=?" if product_id is not None else " AND p.brand_id=?" if brand_id is not None else "") +
            " ORDER BY p.name,p.id", (workspace_id, *( [product_id] if product_id is not None else [brand_id] if brand_id is not None else [] )),
        )]
        products_by_id = {int(row["id"]): {**row, "periods": {}} for row in product_rows}
        result_periods: dict[str, Any] = {}

        for key, (start_date, end_date) in periods.items():
            sale_params = [workspace_id, start_date, end_date, *scope_params]
            total_row = dict(self.connection.execute(
                "SELECT COALESCE(SUM(s.total_selling_amount),0) revenue,COALESCE(SUM(s.quantity),0) quantity,"
                "COALESCE(SUM(s.net_profit),0) sales_profit FROM sale s JOIN product p ON p.id=s.product_id AND p.workspace_id=s.workspace_id "
                "WHERE s.workspace_id=? AND substr(s.date,1,10)>=? AND substr(s.date,1,10)<=?" + product_scope,
                sale_params,
            ).fetchone())
            paid_allocated = int(self.connection.execute(
                "SELECT COALESCE(SUM(a.amount),0) FROM marketing_allocation a "
                "JOIN finance_transaction t ON t.id=a.transaction_id AND t.workspace_id=a.workspace_id "
                "WHERE t.workspace_id=? AND t.category='광고비' AND substr(t.date,1,10)>=? AND substr(t.date,1,10)<=?" + paid_scope,
                [workspace_id, start_date, end_date, *paid_params],
            ).fetchone()[0])
            actual_ad = int(self.connection.execute(
                "SELECT COALESCE(SUM(ms.amount_krw),0) FROM marketing_spend ms "
                "JOIN ad_account_connection ac ON ac.id=ms.ad_account_connection_id AND ac.workspace_id=ms.workspace_id "
                "WHERE ms.workspace_id=? AND ms.source!='naver_api' AND substr(ms.date,1,10)>=? AND substr(ms.date,1,10)<=?" + spend_scope,
                [workspace_id, start_date, end_date, *spend_params],
            ).fetchone()[0])
            if product_id is None:
                actual_ad += int(self.connection.execute(
                    "SELECT COALESCE(SUM(ns.amount_krw),0) FROM naver_adgroup_spend ns WHERE ns.workspace_id=? "
                    "AND substr(ns.date,1,10)>=? AND substr(ns.date,1,10)<=?" + (" AND ns.brand_id=?" if brand_id is not None else ""),
                    [workspace_id, start_date, end_date, *( [brand_id] if brand_id is not None else [] )],
                ).fetchone()[0])
            actual_ad += int(self.connection.execute(
                "SELECT COALESCE(SUM(m.amount_krw),0) FROM manual_marketing_spend m WHERE m.workspace_id=? "
                "AND substr(m.date,1,10)>=? AND substr(m.date,1,10)<=?" + manual_scope,
                [workspace_id, start_date, end_date, *spend_params],
            ).fetchone()[0])
            meta_product_attribution = self._meta_product_attribution(workspace_id, start_date, end_date, brand_id)
            if product_id is not None:
                direct_ad = int(meta_product_attribution["direct_by_product"].get(product_id, 0))
            else:
                direct_ad = int(meta_product_attribution["direct_product_amount"])
            direct_ad += int(self.connection.execute(
                "SELECT COALESCE(SUM(ms.amount_krw),0) FROM marketing_spend ms WHERE ms.workspace_id=? "
                "AND ms.source NOT IN ('meta_api','naver_api') AND substr(ms.date,1,10)>=? AND substr(ms.date,1,10)<=? "
                "AND ms.product_id IS NOT NULL" +
                (" AND ms.product_id=?" if product_id is not None else " AND ms.brand_id=?" if brand_id is not None else ""),
                [workspace_id, start_date, end_date, *( [product_id] if product_id is not None else [brand_id] if brand_id is not None else [] )],
            ).fetchone()[0])
            direct_ad += int(self.connection.execute(
                "SELECT COALESCE(SUM(m.amount_krw),0) FROM manual_marketing_spend m WHERE m.workspace_id=? "
                "AND substr(m.date,1,10)>=? AND substr(m.date,1,10)<=? AND m.product_id IS NOT NULL" +
                (" AND m.product_id=?" if product_id is not None else " AND m.brand_id=?" if brand_id is not None else ""),
                [workspace_id, start_date, end_date, *( [product_id] if product_id is not None else [brand_id] if brand_id is not None else [] )],
            ).fetchone()[0])
            direct_ad += int(self.connection.execute(
                "SELECT COALESCE(SUM(ns.amount_krw),0) FROM naver_adgroup_spend ns WHERE ns.workspace_id=? "
                "AND substr(ns.date,1,10)>=? AND substr(ns.date,1,10)<=? AND ns.product_id IS NOT NULL" +
                (" AND ns.product_id=?" if product_id is not None else " AND ns.brand_id=?" if brand_id is not None else ""),
                [workspace_id, start_date, end_date, *( [product_id] if product_id is not None else [brand_id] if brand_id is not None else [] )],
            ).fetchone()[0])
            brand_common_ad = int(meta_product_attribution["brand_common_amount"])
            brand_common_ad += int(self.connection.execute(
                "SELECT COALESCE(SUM(ms.amount_krw),0) FROM marketing_spend ms WHERE ms.workspace_id=? "
                "AND ms.source NOT IN ('meta_api','naver_api') AND substr(ms.date,1,10)>=? AND substr(ms.date,1,10)<=? "
                "AND ms.product_id IS NULL" + (" AND ms.brand_id=?" if brand_id is not None else ""),
                [workspace_id, start_date, end_date, *( [brand_id] if brand_id is not None else [] )],
            ).fetchone()[0])
            brand_common_ad += int(self.connection.execute(
                "SELECT COALESCE(SUM(m.amount_krw),0) FROM manual_marketing_spend m WHERE m.workspace_id=? "
                "AND substr(m.date,1,10)>=? AND substr(m.date,1,10)<=? AND m.product_id IS NULL" +
                (" AND m.brand_id=?" if brand_id is not None else ""),
                [workspace_id, start_date, end_date, *( [brand_id] if brand_id is not None else [] )],
            ).fetchone()[0])
            if product_id is None:
                brand_common_ad += int(self.connection.execute(
                    "SELECT COALESCE(SUM(ns.amount_krw),0) FROM naver_adgroup_spend ns WHERE ns.workspace_id=? "
                    "AND substr(ns.date,1,10)>=? AND substr(ns.date,1,10)<=? AND ns.allocation_mode='brand_common'" + (" AND ns.brand_id=?" if brand_id is not None else ""),
                    [workspace_id, start_date, end_date, *( [brand_id] if brand_id is not None else [] )],
                ).fetchone()[0])
            if product_id is not None:
                actual_ad = direct_ad
            manual_spend_rows = int(self.connection.execute(
                "SELECT COUNT(*) FROM manual_marketing_spend m WHERE m.workspace_id=? AND substr(m.date,1,10)>=? AND substr(m.date,1,10)<=?" + manual_scope,
                [workspace_id, start_date, end_date, *spend_params],
            ).fetchone()[0])
            total_ad = int(self.connection.execute(
                "SELECT COALESCE(SUM(amount),0) FROM finance_transaction WHERE workspace_id=? AND category='광고비' "
                "AND substr(date,1,10)>=? AND substr(date,1,10)<=?", (workspace_id, start_date, end_date),
            ).fetchone()[0])
            all_allocated = int(self.connection.execute(
                "SELECT COALESCE(SUM(a.amount),0) FROM marketing_allocation a JOIN finance_transaction t "
                "ON t.id=a.transaction_id AND t.workspace_id=a.workspace_id WHERE t.workspace_id=? AND t.category='광고비' "
                "AND substr(t.date,1,10)>=? AND substr(t.date,1,10)<=?", (workspace_id, start_date, end_date),
            ).fetchone()[0])
            days = (date.fromisoformat(end_date) - date.fromisoformat(start_date)).days + 1
            meta_accounts = int(self.connection.execute(
                "SELECT COUNT(*) FROM ad_account_connection ac WHERE ac.workspace_id=? AND ac.platform='meta'" +
                (" AND ac.brand_id=?" if brand_id is not None else "") +
                " AND (ac.active=1 OR EXISTS(SELECT 1 FROM marketing_spend ms WHERE ms.workspace_id=ac.workspace_id "
                "AND ms.ad_account_connection_id=ac.id AND ms.source!='naver_api' AND substr(ms.date,1,10)>=? AND substr(ms.date,1,10)<=?))",
                [workspace_id, *( [brand_id] if brand_id is not None else [] ), start_date, end_date],
            ).fetchone()[0])
            coverage_today = _kst_today().isoformat()
            meta_synced_rows = int(self.connection.execute(
                "SELECT COUNT(*) FROM (SELECT ms.ad_account_connection_id,substr(ms.date,1,10) sync_date "
                "FROM marketing_spend ms JOIN ad_account_connection ac ON ac.id=ms.ad_account_connection_id "
                "WHERE ms.workspace_id=? AND ac.platform='meta' AND ms.source!='naver_api' AND substr(ms.date,1,10)>=? AND substr(ms.date,1,10)<=?" +
                " AND substr(ms.date,1,10)<>?" +
                (" AND ms.brand_id=?" if brand_id is not None else "") +
                " GROUP BY ms.ad_account_connection_id,substr(ms.date,1,10))",
                [workspace_id, start_date, end_date, coverage_today, *( [brand_id] if brand_id is not None else [] )],
            ).fetchone()[0])
            naver_accounts = int(self.connection.execute(
                "SELECT COUNT(*) FROM naver_account_connection na WHERE na.workspace_id=? AND "
                "(na.active=1 OR EXISTS(SELECT 1 FROM naver_account_sync_day sd WHERE sd.workspace_id=na.workspace_id "
                "AND sd.naver_account_connection_id=na.id AND sd.date>=? AND sd.date<=?))",
                (workspace_id, start_date, end_date),
            ).fetchone()[0])
            naver_synced_rows = int(self.connection.execute(
                "SELECT COUNT(*) FROM naver_account_sync_day sd JOIN naver_account_connection na ON na.id=sd.naver_account_connection_id "
                "AND na.workspace_id=sd.workspace_id WHERE sd.workspace_id=? AND sd.date>=? AND sd.date<=? AND sd.date<>?",
                (workspace_id, start_date, end_date, coverage_today),
            ).fetchone()[0])
            period_dates = []
            coverage_cursor = date.fromisoformat(start_date)
            coverage_end = date.fromisoformat(end_date)
            while coverage_cursor <= coverage_end:
                if coverage_cursor.isoformat() != coverage_today:
                    period_dates.append(coverage_cursor.isoformat())
                coverage_cursor += timedelta(days=1)
            meta_account_rows = [dict(row) for row in self.connection.execute(
                "SELECT ac.id,ac.account_name FROM ad_account_connection ac WHERE ac.workspace_id=? AND ac.platform='meta'" +
                (" AND ac.brand_id=?" if brand_id is not None else "") +
                " AND (ac.active=1 OR EXISTS(SELECT 1 FROM marketing_spend ms WHERE ms.workspace_id=ac.workspace_id "
                "AND ms.ad_account_connection_id=ac.id AND ms.source!='naver_api' AND substr(ms.date,1,10)>=? AND substr(ms.date,1,10)<=?))",
                [workspace_id, *( [brand_id] if brand_id is not None else [] ), start_date, end_date],
            )]
            meta_synced_keys = {
                (int(row[0]), str(row[1])) for row in self.connection.execute(
                    "SELECT ms.ad_account_connection_id,substr(ms.date,1,10) sync_date "
                    "FROM marketing_spend ms JOIN ad_account_connection ac ON ac.id=ms.ad_account_connection_id "
                    "WHERE ms.workspace_id=? AND ac.platform='meta' AND ms.source!='naver_api' "
                    "AND substr(ms.date,1,10)>=? AND substr(ms.date,1,10)<=? AND substr(ms.date,1,10)<>?" +
                    (" AND ms.brand_id=?" if brand_id is not None else "") +
                    " GROUP BY ms.ad_account_connection_id,substr(ms.date,1,10)",
                    [workspace_id, start_date, end_date, coverage_today, *( [brand_id] if brand_id is not None else [] )],
                )
            }
            naver_account_rows = [dict(row) for row in self.connection.execute(
                "SELECT na.id,na.account_name FROM naver_account_connection na WHERE na.workspace_id=? AND "
                "(na.active=1 OR EXISTS(SELECT 1 FROM naver_account_sync_day sd WHERE sd.workspace_id=na.workspace_id "
                "AND sd.naver_account_connection_id=na.id AND sd.date>=? AND sd.date<=?))",
                (workspace_id, start_date, end_date),
            )]
            naver_synced_keys = {
                (int(row[0]), str(row[1])) for row in self.connection.execute(
                    "SELECT sd.naver_account_connection_id,sd.date FROM naver_account_sync_day sd "
                    "JOIN naver_account_connection na ON na.id=sd.naver_account_connection_id "
                    "AND na.workspace_id=sd.workspace_id WHERE sd.workspace_id=? AND sd.date>=? AND sd.date<=? AND sd.date<>?",
                    (workspace_id, start_date, end_date, coverage_today),
                )
            }
            missing_account_days = [
                {"platform": platform, "account_id": int(account["id"]), "account_name": str(account["account_name"]), "date": day}
                for platform, accounts, synced_keys in (
                    ("meta", meta_account_rows, meta_synced_keys),
                    ("naver", naver_account_rows, naver_synced_keys),
                )
                for account in accounts
                for day in period_dates
                if (int(account["id"]), day) not in synced_keys
            ]
            naver_unmapped = self.connection.execute(
                "SELECT COALESCE(SUM(amount_krw),0) amount,COUNT(DISTINCT campaign_id) campaigns "
                "FROM naver_adgroup_spend WHERE workspace_id=? AND date>=? AND date<=? AND brand_id IS NULL",
                (workspace_id, start_date, end_date),
            ).fetchone()
            naver_product_attribution = self.connection.execute(
                "SELECT COALESCE(SUM(CASE WHEN allocation_mode='product' THEN amount_krw ELSE 0 END),0) direct_product_amount,"
                "COALESCE(SUM(CASE WHEN allocation_mode='brand_common' THEN amount_krw ELSE 0 END),0) brand_common_amount,"
                "COALESCE(SUM(CASE WHEN allocation_mode='unassigned' AND brand_id IS NOT NULL THEN amount_krw ELSE 0 END),0) unassigned_amount "
                "FROM naver_adgroup_spend WHERE workspace_id=? AND date>=? AND date<=?" +
                (" AND brand_id=?" if brand_id is not None else ""),
                [workspace_id, start_date, end_date, *( [brand_id] if brand_id is not None else [] )],
            ).fetchone()
            unconverted = [row[0] for row in self.connection.execute(
                "SELECT DISTINCT ms.currency FROM marketing_spend ms JOIN ad_account_connection ac ON ac.id=ms.ad_account_connection_id "
                "WHERE ms.workspace_id=? AND ms.source!='naver_api' AND substr(ms.date,1,10)>=? AND substr(ms.date,1,10)<=? AND ms.amount_krw IS NULL" +
                (" AND ms.brand_id=?" if brand_id is not None else ""),
                [workspace_id, start_date, end_date, *( [brand_id] if brand_id is not None else [] )],
            )]
            direct_spend_rows = int(self.connection.execute(
                "SELECT COUNT(*) FROM marketing_spend ms JOIN ad_account_connection ac ON ac.id=ms.ad_account_connection_id "
                "WHERE ms.workspace_id=? AND ms.source!='naver_api' AND substr(ms.date,1,10)>=? AND substr(ms.date,1,10)<=? AND ms.product_id=?",
                [workspace_id, start_date, end_date, product_id],
            ).fetchone()[0]) if product_id is not None else None
            if product_id is not None:
                direct_spend_rows += int(self.connection.execute(
                    "SELECT COUNT(*) FROM manual_marketing_spend WHERE workspace_id=? AND substr(date,1,10)>=? AND substr(date,1,10)<=? AND product_id=?",
                    [workspace_id, start_date, end_date, product_id],
                ).fetchone()[0])
                direct_spend_rows += int(self.connection.execute(
                    "SELECT COUNT(*) FROM naver_adgroup_spend WHERE workspace_id=? AND date>=? AND date<=? "
                    "AND allocation_mode='product' AND product_id=?",
                    [workspace_id, start_date, end_date, product_id],
                ).fetchone()[0])
            coverage_days = len(period_dates)
            meta_expected = coverage_days * meta_accounts
            naver_expected = coverage_days * naver_accounts
            expected_sync_rows = meta_expected + naver_expected
            synced_rows = meta_synced_rows + naver_synced_rows
            analysis_accounts = meta_accounts + naver_accounts
            api_coverage_required = analysis_accounts > 0
            meta_complete = meta_accounts == 0 or meta_synced_rows == meta_expected
            naver_complete = naver_accounts == 0 or naver_synced_rows == naver_expected
            api_coverage_complete = api_coverage_required and meta_complete and naver_complete
            manual_only_ready = not api_coverage_required and manual_spend_rows > 0
            coverage_complete = api_coverage_complete or manual_only_ready
            currency_complete = not unconverted
            product_attribution_ready = product_id is None or (
                int(meta_product_attribution["unassigned_amount"] or 0) == 0
                and int(naver_product_attribution["unassigned_amount"] or 0) == 0
            )
            product_has_direct_spend = product_id is None or bool(
                direct_spend_rows or meta_product_attribution["direct_by_product"].get(product_id, 0)
            )
            spend_analysis_ready = coverage_complete and currency_complete and product_attribution_ready and product_has_direct_spend
            available_actual_ad = actual_ad if spend_analysis_ready else None
            available_direct_ad = direct_ad if spend_analysis_ready else None
            available_brand_common_ad = brand_common_ad if spend_analysis_ready else None
            total_row.update({
                "advertising_cost": available_actual_ad,
                "actual_advertising_spend": available_actual_ad,
                "paid_advertising_cost": paid_allocated if (brand_id is not None or product_id is not None) else total_ad,
                "direct_advertising_cost": available_direct_ad,
                "brand_common_advertising_cost": available_brand_common_ad,
                "profit_after_advertising": int(total_row["sales_profit"]) - actual_ad if spend_analysis_ready else None,
                "total_advertising_cost": total_ad,
                "allocated_advertising_cost": all_allocated,
                "unallocated_advertising_cost": max(total_ad - all_allocated, 0),
                "classification_rate": (all_allocated / total_ad * 100) if total_ad else 100.0,
                "days": days,
                "daily_average_revenue": total_row["revenue"] / days,
                "daily_average_quantity": total_row["quantity"] / days,
                "daily_average_advertising_cost": actual_ad / days if spend_analysis_ready else None,
                "revenue_per_ad_won": (total_row["revenue"] / actual_ad) if spend_analysis_ready and actual_ad else None,
                "quantity_per_10000_ad_spend": (total_row["quantity"] / actual_ad * 10000) if spend_analysis_ready and actual_ad else None,
                "spend_analysis_ready": spend_analysis_ready,
                "spend_coverage": {
                    "account_days_expected": expected_sync_rows,
                    "account_days_synced": synced_rows,
                    "days_expected": expected_sync_rows,
                    "days_synced": synced_rows,
                    "complete": coverage_complete,
                    "api_coverage_required": api_coverage_required,
                    "api_complete": api_coverage_complete,
                    "account_count": analysis_accounts,
                    "meta": {"account_count": meta_accounts, "account_days_expected": meta_expected, "account_days_synced": meta_synced_rows, "complete": meta_complete},
                    "naver": {"account_count": naver_accounts, "account_days_expected": naver_expected, "account_days_synced": naver_synced_rows, "complete": naver_complete},
                    "missing_account_days": missing_account_days,
                },
                "naver_attribution": {
                    "complete": int(naver_unmapped["amount"] or 0) == 0,
                    "unmapped_amount": int(naver_unmapped["amount"] or 0),
                    "unmapped_campaign_count": int(naver_unmapped["campaigns"] or 0),
                },
                "naver_product_attribution": {
                    "complete": int(naver_product_attribution["unassigned_amount"] or 0) == 0,
                    "unassigned_amount": int(naver_product_attribution["unassigned_amount"] or 0),
                    "brand_common_amount": int(naver_product_attribution["brand_common_amount"] or 0),
                    "direct_product_amount": int(naver_product_attribution["direct_product_amount"] or 0),
                },
                "meta_product_attribution": {
                    "complete": bool(meta_product_attribution["complete"]),
                    "unassigned_amount": int(meta_product_attribution["unassigned_amount"]),
                    "brand_common_amount": int(meta_product_attribution["brand_common_amount"]),
                    "direct_product_amount": int(meta_product_attribution["direct_product_amount"]),
                    "direct_product_group_amount": int(meta_product_attribution["direct_product_group_amount"]),
                    "unavailable_amount": int(meta_product_attribution["unavailable_amount"]),
                },
                "currency_complete": currency_complete,
                "unconverted_currencies": unconverted,
            })

            grouped_sales = {int(row["product_id"]): dict(row) for row in self.connection.execute(
                "SELECT s.product_id,COALESCE(SUM(s.total_selling_amount),0) revenue,COALESCE(SUM(s.quantity),0) quantity,"
                "COALESCE(SUM(s.net_profit),0) sales_profit FROM sale s JOIN product p ON p.id=s.product_id AND p.workspace_id=s.workspace_id "
                "WHERE s.workspace_id=? AND substr(s.date,1,10)>=? AND substr(s.date,1,10)<=?" + product_scope + " GROUP BY s.product_id",
                sale_params,
            )}
            grouped_ads = {
                int(meta_product_id): {
                    "product_id": int(meta_product_id), "amount": int(amount), "spend_rows": 1,
                    "meta_amount": int(amount), "naver_amount": 0, "other_amount": 0,
                }
                for meta_product_id, amount in meta_product_attribution["direct_by_product"].items()
                if product_id is None or int(meta_product_id) == product_id
            }
            for row in self.connection.execute(
                "SELECT ms.product_id,SUM(ms.amount_krw) amount,COUNT(*) spend_rows FROM marketing_spend ms "
                "WHERE ms.workspace_id=? AND ms.source NOT IN ('meta_api','naver_api') AND substr(ms.date,1,10)>=? "
                "AND substr(ms.date,1,10)<=? AND ms.product_id IS NOT NULL" +
                (" AND ms.product_id=?" if product_id is not None else " AND ms.brand_id=?" if brand_id is not None else "") +
                " GROUP BY ms.product_id",
                [workspace_id, start_date, end_date, *( [product_id] if product_id is not None else [brand_id] if brand_id is not None else [] )],
            ):
                current = grouped_ads.setdefault(int(row["product_id"]), {"product_id": row["product_id"], "amount": 0, "spend_rows": 0, "meta_amount": 0, "naver_amount": 0, "other_amount": 0})
                current["amount"] = int(current["amount"] or 0) + int(row["amount"] or 0)
                current["spend_rows"] = int(current["spend_rows"] or 0) + int(row["spend_rows"] or 0)
                current["other_amount"] = int(current.get("other_amount", 0)) + int(row["amount"] or 0)
            for row in self.connection.execute(
                "SELECT m.product_id,SUM(m.amount_krw) amount,COUNT(*) spend_rows FROM manual_marketing_spend m "
                "WHERE m.workspace_id=? AND substr(m.date,1,10)>=? AND substr(m.date,1,10)<=? AND m.product_id IS NOT NULL" +
                (" AND m.product_id=?" if product_id is not None else " AND m.brand_id=?" if brand_id is not None else "") + " GROUP BY m.product_id",
                [workspace_id, start_date, end_date, *( [product_id] if product_id is not None else [brand_id] if brand_id is not None else [] )],
            ):
                current = grouped_ads.setdefault(int(row["product_id"]), {"product_id": row["product_id"], "amount": 0, "spend_rows": 0, "meta_amount": 0, "naver_amount": 0, "other_amount": 0})
                current["amount"] = int(current["amount"] or 0) + int(row["amount"] or 0)
                current["spend_rows"] = int(current["spend_rows"] or 0) + int(row["spend_rows"] or 0)
                current["other_amount"] = int(current.get("other_amount", 0)) + int(row["amount"] or 0)
            for row in self.connection.execute(
                "SELECT ns.product_id,SUM(ns.amount_krw) amount,COUNT(*) spend_rows FROM naver_adgroup_spend ns "
                "WHERE ns.workspace_id=? AND ns.date>=? AND ns.date<=? AND ns.allocation_mode='product' AND ns.product_id IS NOT NULL" +
                (" AND ns.product_id=?" if product_id is not None else " AND ns.brand_id=?" if brand_id is not None else "") +
                " GROUP BY ns.product_id",
                [workspace_id, start_date, end_date, *( [product_id] if product_id is not None else [brand_id] if brand_id is not None else [] )],
            ):
                current = grouped_ads.setdefault(int(row["product_id"]), {"product_id": row["product_id"], "amount": 0, "spend_rows": 0, "meta_amount": 0, "naver_amount": 0, "other_amount": 0})
                current["amount"] = int(current["amount"] or 0) + int(row["amount"] or 0)
                current["spend_rows"] = int(current["spend_rows"] or 0) + int(row["spend_rows"] or 0)
                current["naver_amount"] = int(row["amount"] or 0)
            naver_unassigned_by_brand = {
                int(row["brand_id"]): int(row["amount"] or 0)
                for row in self.connection.execute(
                    "SELECT brand_id,SUM(amount_krw) amount FROM naver_adgroup_spend WHERE workspace_id=? "
                    "AND date>=? AND date<=? AND allocation_mode='unassigned' AND brand_id IS NOT NULL GROUP BY brand_id",
                    (workspace_id, start_date, end_date),
                )
            }
            for item_id, item in products_by_id.items():
                values = grouped_sales.get(item_id, {"revenue": 0, "quantity": 0, "sales_profit": 0})
                spend = grouped_ads.get(item_id)
                direct = int(spend["amount"] or 0) if spend else 0
                item_brand_id = int(item["brand_id"]) if item["brand_id"] is not None else None
                meta_unassigned = int(meta_product_attribution["unassigned_by_brand"].get(item_brand_id, 0)) if item_brand_id is not None else 0
                naver_unassigned = int(naver_unassigned_by_brand.get(item_brand_id, 0)) if item_brand_id is not None else 0
                attribution_complete = item_brand_id is not None and meta_unassigned == 0 and naver_unassigned == 0
                direct_available = spend_analysis_ready and attribution_complete
                product_group_id = int(item["product_group_id"]) if item["product_group_id"] is not None else None
                product_group_direct_meta_spend = int(
                    meta_product_attribution["direct_by_product_group"].get(product_group_id, 0)
                ) if product_group_id is not None else 0
                item["periods"][key] = {
                    **values,
                    "direct_advertising_cost": direct if direct_available else None,
                    "direct_advertising_available": direct_available,
                    "direct_meta_advertising_spend": int(spend.get("meta_amount", 0)) if spend else 0,
                    "direct_naver_advertising_spend": int(spend.get("naver_amount", 0)) if spend else 0,
                    "direct_other_advertising_spend": int(spend.get("other_amount", 0)) if spend else 0,
                    "product_group_direct_meta_spend": product_group_direct_meta_spend,
                    "profit_after_direct_advertising": int(values["sales_profit"]) - direct if direct_available else None,
                    "profit_after_advertising": int(values["sales_profit"]) - direct if direct_available else None,
                    "attribution_complete": attribution_complete,
                    "brand_unassigned": item_brand_id is None,
                    "meta_unassigned_amount": meta_unassigned,
                    "naver_unassigned_amount": naver_unassigned,
                }

            daily_sales = {row["date"]: dict(row) for row in self.connection.execute(
                "SELECT substr(s.date,1,10) date,SUM(s.total_selling_amount) revenue,SUM(s.quantity) quantity "
                "FROM sale s JOIN product p ON p.id=s.product_id AND p.workspace_id=s.workspace_id WHERE s.workspace_id=? "
                "AND substr(s.date,1,10)>=? AND substr(s.date,1,10)<=?" + product_scope + " GROUP BY substr(s.date,1,10)", sale_params,
            )}
            daily_ads = {row["date"]: int(row["amount"] or 0) for row in self.connection.execute(
                "SELECT substr(ms.date,1,10) date,SUM(ms.amount_krw) amount FROM marketing_spend ms "
                "JOIN ad_account_connection ac ON ac.id=ms.ad_account_connection_id AND ac.workspace_id=ms.workspace_id "
                "WHERE ms.workspace_id=? AND ms.source!='naver_api' AND substr(ms.date,1,10)>=? AND substr(ms.date,1,10)<=?" + spend_scope + " GROUP BY substr(ms.date,1,10)",
                [workspace_id, start_date, end_date, *spend_params],
            )}
            if product_id is None:
                for row in self.connection.execute(
                    "SELECT date,SUM(amount_krw) amount FROM naver_adgroup_spend WHERE workspace_id=? AND date>=? AND date<=?" +
                    (" AND brand_id=?" if brand_id is not None else "") + " GROUP BY date",
                    [workspace_id, start_date, end_date, *( [brand_id] if brand_id is not None else [] )],
                ):
                    daily_ads[row["date"]] = daily_ads.get(row["date"], 0) + int(row["amount"] or 0)
            else:
                for row in self.connection.execute(
                    "SELECT date,SUM(amount_krw) amount FROM naver_adgroup_spend WHERE workspace_id=? AND date>=? AND date<=? "
                    "AND allocation_mode='product' AND product_id=? GROUP BY date",
                    [workspace_id, start_date, end_date, product_id],
                ):
                    daily_ads[row["date"]] = daily_ads.get(row["date"], 0) + int(row["amount"] or 0)
            for row in self.connection.execute(
                "SELECT substr(m.date,1,10) date,SUM(m.amount_krw) amount FROM manual_marketing_spend m WHERE m.workspace_id=? "
                "AND substr(m.date,1,10)>=? AND substr(m.date,1,10)<=?" + manual_scope + " GROUP BY substr(m.date,1,10)",
                [workspace_id, start_date, end_date, *spend_params],
            ):
                daily_ads[row["date"]] = daily_ads.get(row["date"], 0) + int(row["amount"] or 0)
            daily = []
            cursor = date.fromisoformat(start_date); final = date.fromisoformat(end_date)
            while cursor <= final:
                day = cursor.isoformat(); sales = daily_sales.get(day, {})
                daily.append({"date": day, "revenue": int(sales.get("revenue", 0)), "quantity": int(sales.get("quantity", 0)), "advertising_cost": daily_ads.get(day, 0) if spend_analysis_ready else None})
                cursor += timedelta(days=1)
            channels = [dict(row) for row in self.connection.execute(
                "SELECT ms.channel name,SUM(ms.amount_krw) amount FROM marketing_spend ms "
                "JOIN ad_account_connection ac ON ac.id=ms.ad_account_connection_id AND ac.workspace_id=ms.workspace_id "
                "WHERE ms.workspace_id=? AND ms.source!='naver_api' AND substr(ms.date,1,10)>=? AND substr(ms.date,1,10)<=?" + spend_scope + " GROUP BY ms.channel ORDER BY amount DESC",
                [workspace_id, start_date, end_date, *spend_params],
            )]
            channel_map = {row["name"]: int(row["amount"] or 0) for row in channels}
            if product_id is None:
                naver_channel = int(self.connection.execute(
                    "SELECT COALESCE(SUM(amount_krw),0) FROM naver_adgroup_spend WHERE workspace_id=? AND date>=? AND date<=?" +
                    (" AND brand_id=?" if brand_id is not None else ""),
                    [workspace_id, start_date, end_date, *( [brand_id] if brand_id is not None else [] )],
                ).fetchone()[0])
                if naver_channel:
                    channel_map["네이버"] = channel_map.get("네이버", 0) + naver_channel
            else:
                naver_channel = int(self.connection.execute(
                    "SELECT COALESCE(SUM(amount_krw),0) FROM naver_adgroup_spend WHERE workspace_id=? AND date>=? AND date<=? "
                    "AND allocation_mode='product' AND product_id=?",
                    [workspace_id, start_date, end_date, product_id],
                ).fetchone()[0])
                if naver_channel:
                    channel_map["네이버"] = channel_map.get("네이버", 0) + naver_channel
            for row in self.connection.execute(
                "SELECT m.channel name,SUM(m.amount_krw) amount FROM manual_marketing_spend m WHERE m.workspace_id=? "
                "AND substr(m.date,1,10)>=? AND substr(m.date,1,10)<=?" + manual_scope + " GROUP BY m.channel",
                [workspace_id, start_date, end_date, *spend_params],
            ):
                channel_map[row["name"]] = channel_map.get(row["name"], 0) + int(row["amount"] or 0)
            channels = [{"name": name, "amount": amount} for name, amount in sorted(channel_map.items(), key=lambda item: item[1], reverse=True)]
            if not spend_analysis_ready:
                channels = []
            result_periods[key] = {"start_date": start_date, "end_date": end_date, "totals": total_row, "daily": daily, "channels": channels}

        return {
            "workspace_id": workspace_id,
            "filters": {"brand_id": brand_id, "brand_name": brand["name"] if brand else None, "product_id": product_id, "product_name": product["name"] if product else None},
            "periods": result_periods,
            "products": list(products_by_id.values()),
            "product_groups": self._product_group_analysis(workspace_id, periods, brand_id),
        }

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
            for resource in ("transactions", "categories", "brands", "products", "platforms", "sales", "ads"):
                for item in data.get(resource, []):
                    self.create_resource_uncommitted(resource, workspace_id, item)
                counts[resource] = len(data.get(resource, []))
            for item in data.get("marketing_allocations", []):
                fields = ("id", "transaction_id", "brand_id", "product_id", "channel", "amount", "memo", "created_at", "updated_at")
                present = [field for field in fields if field in item]
                self.connection.execute(
                    f"INSERT INTO marketing_allocation(workspace_id,{','.join(present)}) VALUES ({','.join('?' for _ in range(len(present) + 1))})",
                    [workspace_id, *(item[field] for field in present)],
                )
            counts["marketing_allocations"] = len(data.get("marketing_allocations", []))
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
        for resource in ("transactions", "categories", "brands", "products", "platforms", "sales", "ads"):
            payload[resource] = self.list_resource(resource, workspace_id)
        payload["marketing_allocations"] = [dict(row) for row in self.connection.execute(
            "SELECT * FROM marketing_allocation WHERE workspace_id=? ORDER BY transaction_id,id", (workspace_id,)
        )]
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
            conditions.append("substr(date,1,10)>=?"); values.append(start_date)
        if end_date:
            conditions.append("substr(date,1,10)<=?"); values.append(end_date)
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
        detail_rows = [dict(row) for row in self.connection.execute(
            "SELECT id,date,merchant,amount,category FROM finance_transaction WHERE workspace_id=? AND category <> '미분류'" + date_clause + " ORDER BY date DESC,id", params,
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
            "transactions": detail_rows,
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
            conditions.append("substr(s.date,1,10)>=?"); values.append(start_date)
        if end_date:
            conditions.append("substr(s.date,1,10)<=?"); values.append(end_date)
        clause = "".join(f" AND {condition}" for condition in conditions)
        params = tuple(values)
        result["daily_sales"] = [dict(row) for row in self.connection.execute(
            "SELECT s.date, SUM(s.total_selling_amount) sales, SUM(s.net_profit) net_profit, SUM(s.quantity) quantity "
            "FROM sale s WHERE s.workspace_id=?" + clause + " GROUP BY s.date ORDER BY s.date", params,
        )]
        result["total_quantity"] = sum(int(row["quantity"] or 0) for row in result["daily_sales"])
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

    def business_date_details(self, workspace_id: int, selected_date: str) -> dict[str, Any]:
        items = [dict(row) for row in self.connection.execute(
            "SELECT s.*,p.name product_name,pl.name platform_name FROM sale s "
            "JOIN product p ON p.id=s.product_id JOIN platform pl ON pl.id=s.platform_id "
            "WHERE s.workspace_id=? AND substr(s.date,1,10)=? ORDER BY p.name,pl.name,s.id",
            (workspace_id, selected_date),
        )]
        products = [dict(row) for row in self.connection.execute(
            "SELECT p.id product_id,p.name product_name,SUM(s.quantity) quantity,"
            "SUM(s.total_selling_amount) sales,SUM(s.net_profit) net_profit "
            "FROM sale s JOIN product p ON p.id=s.product_id "
            "WHERE s.workspace_id=? AND substr(s.date,1,10)=? "
            "GROUP BY p.id,p.name ORDER BY quantity DESC,sales DESC,p.name",
            (workspace_id, selected_date),
        )]
        channels = [dict(row) for row in self.connection.execute(
            "SELECT s.product_id,pl.id platform_id,pl.name platform_name,SUM(s.quantity) quantity,"
            "SUM(s.total_selling_amount) sales,SUM(s.net_profit) net_profit "
            "FROM sale s JOIN platform pl ON pl.id=s.platform_id "
            "WHERE s.workspace_id=? AND substr(s.date,1,10)=? "
            "GROUP BY s.product_id,pl.id,pl.name ORDER BY quantity DESC,sales DESC,pl.name",
            (workspace_id, selected_date),
        )]
        for product in products:
            product["channels"] = [row for row in channels if row["product_id"] == product["product_id"]]
        return {
            "date": selected_date,
            "items": items,
            "total_quantity": sum(int(row["quantity"] or 0) for row in products),
            "total_sales": sum(int(row["sales"] or 0) for row in products),
            "total_profit": sum(int(row["net_profit"] or 0) for row in products),
            "products": products,
        }

    def ad_analytics(self, workspace_id: int, month: str | None = None, start_date: str | None = None, end_date: str | None = None) -> dict[str, Any]:
        conditions: list[str] = []
        values: list[Any] = [workspace_id]
        if month:
            conditions.append("substr(date,1,7)=?"); values.append(month)
        if start_date:
            conditions.append("substr(date,1,10)>=?"); values.append(start_date)
        if end_date:
            conditions.append("substr(date,1,10)<=?"); values.append(end_date)
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
            rows = [dict(row) for row in self.connection.execute(
                f"SELECT {columns}, SUM(spend) spend, SUM(impressions) impressions, SUM(clicks) clicks, "
                "SUM(conversions) conversions, SUM(conversion_value) conversion_value "
                "FROM ad_spend WHERE workspace_id=?" + clause + f" GROUP BY {columns} ORDER BY spend DESC", params,
            )]
            for row in rows:
                row["ctr"] = row["clicks"] / row["impressions"] * 100 if row["impressions"] else 0
                row["cpc"] = row["spend"] / row["clicks"] if row["clicks"] else 0
                row["cpm"] = row["spend"] / row["impressions"] * 1000 if row["impressions"] else 0
                row["cpa"] = row["spend"] / row["conversions"] if row["conversions"] else 0
                row["roas"] = row["conversion_value"] / row["spend"] if row["spend"] else 0
            return rows
        daily = grouped("date"); campaigns = grouped("campaign_id,campaign_name"); adsets = grouped("campaign_id,adset_id,adset_name"); creatives = grouped("campaign_id,adset_id,ad_id,ad_name")
        alerts = [{"level": "campaign", "id": row["campaign_id"], "name": row["campaign_name"], "spend": row["spend"], "reason": "전환 0건 · 중단 검토"} for row in campaigns if row["conversions"] == 0 and row["spend"] > 50000]
        return {"summary": summary, "daily": daily, "campaigns": campaigns, "adsets": adsets, "creatives": creatives, "alerts": alerts, "available_months": self.available_months(workspace_id, "ads")}


