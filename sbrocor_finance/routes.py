"""Versioned HTTP routes for server-to-server SBROCOR Finance access."""

from __future__ import annotations

import sqlite3

from flask import Blueprint, g, jsonify, request

from .auth import require_server_hmac
from .database import finance_connection
from .repository import FinanceRepository, RESOURCE_CONFIG
from .service import FinanceService


finance_blueprint = Blueprint("sbrocor_finance", __name__, url_prefix="/api/sbrocor/finance/v1")

RESOURCE_PERMISSION = {
    "transactions": "transactions", "categories": "categories", "products": "products",
    "platforms": "products", "sales": "sales", "ads": "ads",
}


def _authorize(permission: str, workspace_id: int | None = None, *, admin_only: bool = False) -> None:
    context = g.finance_context
    if context["role"] == "admin":
        return
    if admin_only or permission not in context["permissions"]:
        raise PermissionError("finance permission denied")
    if workspace_id is not None and workspace_id not in context["workspace_ids"]:
        raise PermissionError("finance workspace denied")


def _workspace_id() -> int:
    value = request.args.get("workspace_id")
    if value is None and request.is_json:
        value = (request.get_json(silent=True) or {}).get("workspace_id")
    if value is None:
        raise ValueError("workspace_id is required")
    return int(value)


def _json_payload() -> dict:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise ValueError("JSON object body is required")
    return payload


def _month() -> str | None:
    value = request.args.get("month")
    if value and (len(value) != 7 or value[4] != "-" or not value.replace("-", "").isdigit()):
        raise ValueError("month must be YYYY-MM")
    return value


def _query_options(resource: str) -> dict:
    filters = {}
    for field in ("category", "product_id", "platform_id", "campaign_id", "adset_id"):
        if request.args.get(field) not in (None, ""):
            filters[field] = request.args[field]
    return {
        "page": request.args.get("page", 1, type=int),
        "page_size": request.args.get("page_size", 50, type=int),
        "month": _month(),
        "start_date": request.args.get("start_date"),
        "end_date": request.args.get("end_date"),
        "search": request.args.get("search"),
        "filters": filters,
    }


@finance_blueprint.errorhandler(ValueError)
def _bad_request(error):
    return jsonify(error="invalid_request", detail=str(error)), 400


@finance_blueprint.errorhandler(LookupError)
def _not_found(error):
    return jsonify(error="not_found", detail=str(error)), 404


@finance_blueprint.errorhandler(sqlite3.IntegrityError)
def _conflict(error):
    return jsonify(error="integrity_error", detail=str(error)), 409


@finance_blueprint.errorhandler(PermissionError)
def _forbidden(error):
    return jsonify(error="forbidden", detail=str(error)), 403


@finance_blueprint.route("/workspaces", methods=["GET", "POST"])
@require_server_hmac
def workspaces():
    _authorize("workspaces", admin_only=request.method != "GET")
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        if request.method == "GET":
            items = repository.list_workspaces()
            if g.finance_context["role"] != "admin":
                allowed = set(g.finance_context["workspace_ids"])
                items = [item for item in items if item["id"] in allowed]
            return jsonify(items=items)
        return jsonify(repository.create_workspace(_json_payload())), 201


@finance_blueprint.route("/workspaces/<int:workspace_id>", methods=["GET", "PATCH", "DELETE"])
@require_server_hmac
def workspace_item(workspace_id: int):
    _authorize("workspaces", workspace_id, admin_only=request.method != "GET")
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        if request.method == "GET":
            item = repository.get_workspace(workspace_id)
        elif request.method == "PATCH":
            item = repository.update_workspace(workspace_id, _json_payload())
        else:
            return ("", 204) if repository.delete_workspace(workspace_id) else (jsonify(error="not_found"), 404)
        return jsonify(item) if item else (jsonify(error="not_found"), 404)


@finance_blueprint.get("/dashboard")
@require_server_hmac
def dashboard():
    workspace_id = _workspace_id()
    _authorize("dashboard", workspace_id)
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        FinanceService(repository).require_workspace(workspace_id)
        return jsonify(repository.dashboard(workspace_id, _month(), request.args.get("start_date"), request.args.get("end_date")))


@finance_blueprint.get("/business")
@require_server_hmac
def business():
    workspace_id = _workspace_id()
    _authorize("business_dashboard", workspace_id)
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        FinanceService(repository).require_workspace(workspace_id)
        return jsonify(repository.business_analytics(workspace_id, _month(), request.args.get("start_date"), request.args.get("end_date")))


@finance_blueprint.get("/ads/analytics")
@require_server_hmac
def ads_analytics():
    workspace_id = _workspace_id()
    _authorize("ads", workspace_id)
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        FinanceService(repository).require_workspace(workspace_id)
        return jsonify(repository.ad_analytics(workspace_id, _month(), request.args.get("start_date"), request.args.get("end_date")))


def _resource_collection(resource: str):
    workspace_id = _workspace_id()
    _authorize(RESOURCE_PERMISSION[resource], workspace_id)
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        service = FinanceService(repository)
        service.require_workspace(workspace_id)
        if request.method == "GET":
            return jsonify(repository.query_resource(resource, workspace_id, **_query_options(resource)))
        payload = _json_payload()
        return jsonify(service.create_resource(resource, workspace_id, payload)), 201


def _resource_item(resource: str, item_id: str):
    workspace_id = _workspace_id()
    _authorize(RESOURCE_PERMISSION[resource], workspace_id)
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        FinanceService(repository).require_workspace(workspace_id)
        if request.method == "GET":
            item = repository.get_resource(resource, workspace_id, item_id)
        elif request.method == "PATCH":
            item = repository.update_resource(resource, workspace_id, item_id, _json_payload())
        else:
            return ("", 204) if repository.delete_resource(resource, workspace_id, item_id) else (jsonify(error="not_found"), 404)
        return jsonify(item) if item else (jsonify(error="not_found"), 404)


for _resource in RESOURCE_CONFIG:
    finance_blueprint.add_url_rule(
        f"/{_resource}",
        endpoint=f"{_resource}_collection",
        view_func=require_server_hmac(lambda resource=_resource: _resource_collection(resource)),
        methods=["GET", "POST"],
    )
    finance_blueprint.add_url_rule(
        f"/{_resource}/<item_id>",
        endpoint=f"{_resource}_item",
        view_func=require_server_hmac(lambda item_id, resource=_resource: _resource_item(resource, item_id)),
        methods=["GET", "PATCH", "DELETE"],
    )


@finance_blueprint.get("/workspaces/<int:workspace_id>/export")
@require_server_hmac
def export_workspace(workspace_id: int):
    _authorize("workspaces", workspace_id, admin_only=True)
    with finance_connection() as connection:
        manifest = FinanceRepository(connection).export_workspace(workspace_id)
        return jsonify(manifest) if manifest else (jsonify(error="not_found"), 404)


@finance_blueprint.post("/workspaces/<int:workspace_id>/import")
@require_server_hmac
def import_workspace(workspace_id: int):
    _authorize("workspaces", workspace_id, admin_only=True)
    payload = _json_payload()
    dry_run = request.args.get("dry_run", "true").lower() != "false"
    if not dry_run:
        return jsonify(error="destructive_import_disabled"), 403
    with finance_connection() as connection:
        result = FinanceService(FinanceRepository(connection)).import_manifest(workspace_id, payload, dry_run)
        return jsonify(result)

