"""Finance business rules independent of Flask and legacy MoneyLog models."""

from __future__ import annotations

from typing import Any

from .repository import FinanceRepository


class FinanceService:
    def __init__(self, repository: FinanceRepository):
        self.repository = repository

    def require_workspace(self, workspace_id: int) -> dict[str, Any]:
        workspace = self.repository.get_workspace(workspace_id)
        if not workspace:
            raise LookupError("workspace not found")
        return workspace

    def create_resource(self, resource: str, workspace_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        self.require_workspace(workspace_id)
        if resource in {"brands", "product-groups"}:
            payload = {**payload, "active": 1 if payload.get("active", True) else 0}
        if resource == "product-groups":
            brand = self.repository.get_resource("brands", workspace_id, str(payload.get("brand_id", "")))
            if not brand:
                raise ValueError("product group brand must belong to the same workspace")
        if resource == "products":
            brand = None
            if payload.get("brand_id") not in (None, ""):
                brand = self.repository.get_resource("brands", workspace_id, str(payload["brand_id"]))
                if not brand:
                    raise ValueError("product brand must belong to the same workspace")
            if payload.get("product_group_id") not in (None, ""):
                group = self.repository.get_resource("product-groups", workspace_id, str(payload["product_group_id"]))
                if not group or not brand or int(group["brand_id"]) != int(brand["id"]):
                    raise ValueError("product group must belong to the product brand")
        if resource == "ad-accounts":
            brand = self.repository.get_resource("brands", workspace_id, str(payload.get("brand_id", "")))
            if not brand:
                raise ValueError("ad account brand must belong to the same workspace")
            platform = str(payload.get("platform", "")).lower().strip()
            if platform not in {"meta", "naver"}:
                raise ValueError("unsupported ad account platform")
            credential_key = str(payload.get("credential_key", "")).strip().upper()
            if not credential_key or not credential_key.replace("_", "").isalnum():
                raise ValueError("credential_key must contain only letters, numbers, and underscores")
            payload = {
                **payload,
                "platform": platform,
                "currency": str(payload.get("currency", "")).strip().upper(),
                "credential_key": credential_key,
                "active": 1 if payload.get("active", True) else 0,
            }
        if resource == "sales":
            product = self.repository.get_resource("products", workspace_id, str(payload.get("product_id", "")))
            platform = self.repository.get_resource("platforms", workspace_id, str(payload.get("platform_id", "")))
            if not product or not platform:
                raise ValueError("sale product and platform must belong to the same workspace")
            # Historical financial values are accepted verbatim and are never recalculated.
        return self.repository.create_resource(resource, workspace_id, payload)

    def import_manifest(self, workspace_id: int, manifest: dict[str, Any], dry_run: bool) -> dict[str, Any]:
        required = {"manifest_version", "workspace"}
        if not required.issubset(manifest) or manifest["manifest_version"] != 1:
            raise ValueError("unsupported or incomplete manifest")
        if int(manifest["workspace"].get("id", -1)) != workspace_id:
            raise ValueError("workspace mismatch")
        product_ids = {int(item["id"]) for item in manifest.get("products", [])}
        platform_ids = {int(item["id"]) for item in manifest.get("platforms", [])}
        brand_ids = {int(item["id"]) for item in manifest.get("brands", [])}
        transaction_ids = {str(item["id"]) for item in manifest.get("transactions", [])}
        for product in manifest.get("products", []):
            if product.get("brand_id") is not None and int(product["brand_id"]) not in brand_ids:
                raise ValueError("product references a brand outside the manifest workspace")
        for sale in manifest.get("sales", []):
            if int(sale["product_id"]) not in product_ids or int(sale["platform_id"]) not in platform_ids:
                raise ValueError("sale references a product/platform outside the manifest workspace")
        allocation_totals: dict[str, int] = {}
        for allocation in manifest.get("marketing_allocations", []):
            transaction_id = str(allocation.get("transaction_id", ""))
            if transaction_id not in transaction_ids:
                raise ValueError("allocation references a transaction outside the manifest workspace")
            if allocation.get("brand_id") is not None and int(allocation["brand_id"]) not in brand_ids:
                raise ValueError("allocation references a brand outside the manifest workspace")
            if allocation.get("product_id") is not None and int(allocation["product_id"]) not in product_ids:
                raise ValueError("allocation references a product outside the manifest workspace")
            allocation_totals[transaction_id] = allocation_totals.get(transaction_id, 0) + int(allocation["amount"])
        transaction_amounts = {str(item["id"]): int(item["amount"]) for item in manifest.get("transactions", [])}
        if any(total != transaction_amounts[transaction_id] for transaction_id, total in allocation_totals.items()):
            raise ValueError("allocation totals must match their transaction amounts")
        counts = {key: len(manifest.get(key, [])) for key in ("transactions", "categories", "brands", "products", "platforms", "sales", "ads", "marketing_allocations")}
        if not dry_run:
            raise PermissionError("destructive import is disabled on the Finance API")
        return {"dry_run": True, "counts": counts}

    def import_initial_manifest(self, workspace_id: int, manifest: dict[str, Any]) -> dict[str, Any]:
        self.import_manifest(workspace_id, manifest, dry_run=True)
        return {"dry_run": False, "counts": self.repository.import_if_empty(workspace_id, manifest)}
