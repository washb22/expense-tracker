"""Versioned HTTP routes for server-to-server SBROCOR Finance access."""

from __future__ import annotations

import sqlite3

from flask import Blueprint, jsonify, request

from .auth import require_server_hmac
from .database import finance_connection
from .repository import FinanceRepository, RESOURCE_CONFIG
from .service import FinanceService


finance_blueprint = Blueprint("sbrocor_finance", __name__, url_prefix="/api/sbrocor/finance/v1")


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


@finance_blueprint.errorhandler(ValueError)
def _bad_request(error):
    return jsonify(error="invalid_request", detail=str(error)), 400


@finance_blueprint.errorhandler(LookupError)
def _not_found(error):
    return jsonify(error="not_found", detail=str(error)), 404


@finance_blueprint.errorhandler(sqlite3.IntegrityError)
def _conflict(error):
    return jsonify(error="integrity_error", detail=str(error)), 409


@finance_blueprint.route("/workspaces", methods=["GET", "POST"])
@require_server_hmac
def workspaces():
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        if request.method == "GET":
            return jsonify(items=repository.list_workspaces())
        return jsonify(repository.create_workspace(_json_payload())), 201


@finance_blueprint.route("/workspaces/<int:workspace_id>", methods=["GET", "PATCH", "DELETE"])
@require_server_hmac
def workspace_item(workspace_id: int):
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
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        FinanceService(repository).require_workspace(workspace_id)
        return jsonify(repository.dashboard(workspace_id))


@finance_blueprint.get("/business")
@require_server_hmac
def business():
    workspace_id = _workspace_id()
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        FinanceService(repository).require_workspace(workspace_id)
        dashboard_data = repository.dashboard(workspace_id)
        dashboard_data["operating_profit"] = dashboard_data["total_net_profit"] - dashboard_data["total_expenses"]
        return jsonify(dashboard_data)


def _resource_collection(resource: str):
    workspace_id = _workspace_id()
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        service = FinanceService(repository)
        service.require_workspace(workspace_id)
        if request.method == "GET":
            return jsonify(items=repository.list_resource(resource, workspace_id))
        payload = _json_payload()
        return jsonify(service.create_resource(resource, workspace_id, payload)), 201


def _resource_item(resource: str, item_id: str):
    workspace_id = _workspace_id()
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
    with finance_connection() as connection:
        manifest = FinanceRepository(connection).export_workspace(workspace_id)
        return jsonify(manifest) if manifest else (jsonify(error="not_found"), 404)


@finance_blueprint.post("/workspaces/<int:workspace_id>/import")
@require_server_hmac
def import_workspace(workspace_id: int):
    payload = _json_payload()
    dry_run = request.args.get("dry_run", "true").lower() != "false"
    if not dry_run:
        return jsonify(error="destructive_import_disabled"), 403
    with finance_connection() as connection:
        result = FinanceService(FinanceRepository(connection)).import_manifest(workspace_id, payload, dry_run)
        return jsonify(result)
