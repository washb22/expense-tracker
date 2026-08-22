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
        for sale in manifest.get("sales", []):
            if int(sale["product_id"]) not in product_ids or int(sale["platform_id"]) not in platform_ids:
                raise ValueError("sale references a product/platform outside the manifest workspace")
        counts = {key: len(manifest.get(key, [])) for key in ("transactions", "categories", "products", "platforms", "sales", "ads")}
        if not dry_run:
            raise PermissionError("destructive import is disabled on the Finance API")
        return {"dry_run": True, "counts": counts}

    def import_initial_manifest(self, workspace_id: int, manifest: dict[str, Any]) -> dict[str, Any]:
        self.import_manifest(workspace_id, manifest, dry_run=True)
        return {"dry_run": False, "counts": self.repository.import_if_empty(workspace_id, manifest)}
