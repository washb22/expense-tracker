"""Versioned HTTP routes for server-to-server SBROCOR Finance access."""

from __future__ import annotations

import sqlite3
import io
import logging
import os
import re
import uuid
from datetime import date, datetime, timedelta
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pandas as pd
import requests
from flask import Blueprint, g, jsonify, request, send_file

from .auth import require_server_hmac
from .database import finance_connection
from .repository import FinanceRepository, MARKETING_CHANNELS, RESOURCE_CONFIG
from .service import FinanceService
from .naver_search_ads import Credentials, NaverApiError, NaverSearchAdsClient


finance_blueprint = Blueprint("sbrocor_finance", __name__, url_prefix="/api/sbrocor/finance/v1")
logger = logging.getLogger(__name__)


class MetaApiError(Exception):
    """A safe, public representation of an upstream Meta API failure."""

    def __init__(self, detail: str, *, meta_code=None, meta_subcode=None):
        super().__init__(detail)
        self.detail = detail
        self.meta_code = meta_code
        self.meta_subcode = meta_subcode


def _without_access_token(url: str) -> str:
    """Remove credentials Meta may include in a paging.next URL."""
    parts = urlsplit(url)
    query = urlencode(
        [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True) if key.lower() != "access_token"]
    )
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _safe_meta_message(value: object, token: str) -> str:
    message = str(value or "").strip()
    if token:
        message = message.replace(token, "[REDACTED]")
    message = re.sub(r"(?i)(access_token=)[^&\s]+", r"\1[REDACTED]", message)
    return message[:500]


def _meta_get(
    url: str,
    *,
    token: str,
    params: dict | None,
    workspace_id: int,
    connection_id: int | str,
    account_id: str,
) -> dict:
    safe_url = _without_access_token(url)
    try:
        response = requests.get(
            safe_url,
            params=params,
            headers={"Authorization": f"Bearer {token}"},
            timeout=60,
        )
    except requests.Timeout:
        logger.warning(
            "Meta sync failed workspace_id=%s connection_id=%s account_id=%s failure_kind=timeout",
            workspace_id, connection_id, account_id,
        )
        raise MetaApiError("Meta API 요청에 실패했습니다.") from None
    except requests.RequestException:
        logger.warning(
            "Meta sync failed workspace_id=%s connection_id=%s account_id=%s failure_kind=network",
            workspace_id, connection_id, account_id,
        )
        raise MetaApiError("Meta API 요청에 실패했습니다.") from None

    status = int(getattr(response, "status_code", 200))
    try:
        payload = response.json()
    except (TypeError, ValueError):
        payload = None
    if not 200 <= status < 300:
        meta_error = payload.get("error", {}) if isinstance(payload, dict) else {}
        message = _safe_meta_message(meta_error.get("message"), token)
        meta_code = meta_error.get("code")
        meta_subcode = meta_error.get("error_subcode")
        logger.warning(
            "Meta sync failed workspace_id=%s connection_id=%s account_id=%s status=%s "
            "meta_code=%s meta_subcode=%s message=%s",
            workspace_id, connection_id, account_id, status, meta_code, meta_subcode,
            message or "non_json_error",
        )
        detail = f"Meta API: {message}" if message else "Meta API 요청에 실패했습니다."
        raise MetaApiError(detail, meta_code=meta_code, meta_subcode=meta_subcode)
    if not isinstance(payload, dict):
        logger.warning(
            "Meta sync failed workspace_id=%s connection_id=%s account_id=%s status=%s failure_kind=invalid_json",
            workspace_id, connection_id, account_id, status,
        )
        raise MetaApiError("Meta API 요청에 실패했습니다.")
    return payload

RESOURCE_PERMISSION = {
    "transactions": "transactions", "categories": "categories", "products": "products",
    "platforms": "products", "brands": "products", "sales": "sales", "ads": "ads",
    "ad-accounts": "ads",
}


def _credential_token(account: sqlite3.Row | dict, workspace_id: int) -> str | None:
    if str(account["platform"] or "").lower() != "meta":
        return None
    key = str(account["credential_key"] or "").strip().upper()
    return os.getenv(f"SBROCOR_META_ACCESS_TOKEN_{key}") or os.getenv(f"SBROCOR_META_ACCESS_TOKEN_WORKSPACE_{workspace_id}")


def _naver_credentials(account: sqlite3.Row | dict) -> Credentials | None:
    if str(account["platform"] or "").lower() != "naver":
        return None
    key = str(account["credential_key"] or "").strip().upper()
    api_key = os.getenv(f"SBROCOR_NAVER_API_KEY_{key}")
    secret_key = os.getenv(f"SBROCOR_NAVER_SECRET_KEY_{key}")
    return Credentials(api_key, secret_key, str(account["account_id"])) if api_key and secret_key else None


def _naver_account_credentials(account: sqlite3.Row | dict) -> Credentials | None:
    key = str(account["credential_key"] or "").strip().upper()
    api_key = os.getenv(f"SBROCOR_NAVER_API_KEY_{key}")
    secret_key = os.getenv(f"SBROCOR_NAVER_SECRET_KEY_{key}")
    return Credentials(api_key, secret_key, str(account["customer_id"])) if api_key and secret_key else None


def _public_naver_account(account: sqlite3.Row | dict, connection: sqlite3.Connection) -> dict:
    item = dict(account)
    item["credential_configured"] = bool(_naver_account_credentials(account))
    latest = connection.execute(
        "SELECT date,total_amount_krw FROM naver_account_sync_day WHERE workspace_id=? AND naver_account_connection_id=? ORDER BY date DESC LIMIT 1",
        (item["workspace_id"], item["id"]),
    ).fetchone()
    item["latest_spend_date"] = latest["date"] if latest else None
    item["latest_spend_amount"] = int(latest["total_amount_krw"] or 0) if latest else None
    item["last_7d_amount"] = int(connection.execute(
        "SELECT COALESCE(SUM(total_amount_krw),0) FROM naver_account_sync_day WHERE workspace_id=? AND naver_account_connection_id=? AND date BETWEEN date(?,'-6 days') AND ?",
        (item["workspace_id"], item["id"], latest["date"], latest["date"]),
    ).fetchone()[0]) if latest else None
    item["campaign_count"] = int(connection.execute(
        "SELECT COUNT(*) FROM naver_campaign WHERE workspace_id=? AND naver_account_connection_id=?",
        (item["workspace_id"], item["id"]),
    ).fetchone()[0])
    item["unmapped_campaign_count"] = int(connection.execute(
        "SELECT COUNT(*) FROM naver_campaign WHERE workspace_id=? AND naver_account_connection_id=? AND brand_id IS NULL AND active=1",
        (item["workspace_id"], item["id"]),
    ).fetchone()[0])
    return item


def _public_ad_account(item: dict, workspace_id: int, connection: sqlite3.Connection) -> dict:
    identity_locked = bool(connection.execute(
        "SELECT EXISTS(SELECT 1 FROM marketing_spend WHERE workspace_id=? AND ad_account_connection_id=?) "
        "OR EXISTS(SELECT 1 FROM ad_spend WHERE workspace_id=? AND ad_account_connection_id=?)",
        (workspace_id, item["id"], workspace_id, item["id"]),
    ).fetchone()[0])
    platform = str(item.get("platform") or "").lower()
    sync_supported = platform in {"meta", "naver"}
    configured = bool(_credential_token(item, workspace_id)) if platform == "meta" else bool(_naver_credentials(item))
    latest = connection.execute(
        "SELECT substr(date,1,10) spend_date,amount_krw FROM marketing_spend WHERE workspace_id=? AND ad_account_connection_id=? ORDER BY substr(date,1,10) DESC,id DESC LIMIT 1",
        (workspace_id, item["id"]),
    ).fetchone()
    brand_name_row = connection.execute("SELECT name FROM brand WHERE id=? AND workspace_id=?", (item["brand_id"], workspace_id)).fetchone()
    last_7d_amount = int(connection.execute(
        "SELECT COALESCE(SUM(amount_krw),0) FROM marketing_spend WHERE workspace_id=? AND ad_account_connection_id=? "
        "AND substr(date,1,10) >= COALESCE((SELECT date(MAX(substr(date,1,10)),'-6 days') FROM marketing_spend WHERE workspace_id=? AND ad_account_connection_id=?),'9999-12-31')",
        (workspace_id, item["id"], workspace_id, item["id"]),
    ).fetchone()[0])
    return {
        **item,
        "credential_configured": configured,
        "sync_supported": sync_supported,
        "identity_locked": identity_locked,
        "latest_spend_date": latest["spend_date"] if latest else None,
        "latest_spend_amount": int(latest["amount_krw"] or 0) if latest else None,
        "last_7d_amount": last_7d_amount if latest else None,
        "brand_name": brand_name_row["name"] if brand_name_row else None,
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


def _is_admin() -> bool:
    return g.finance_context["role"] == "admin"


def _uploaded_frame() -> pd.DataFrame:
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        raise ValueError("CSV 또는 XLSX 파일이 필요합니다")
    name = uploaded.filename.lower()
    if name.endswith(".csv"):
        return pd.read_csv(uploaded)
    if name.endswith(".xlsx"):
        return pd.read_excel(uploaded, engine="openpyxl")
    raise ValueError("CSV 또는 XLSX 형식만 지원합니다")


def _normalized_merchant(value: object) -> str:
    return re.sub(r"\(주\)|（주）|\(유\)|（유）|[(){}\[\].,]", "", str(value).lower()).strip()


def _classify(merchant: object, rules: list[sqlite3.Row]) -> str:
    normalized = _normalized_merchant(merchant)
    for rule in rules:
        if str(rule["keyword"]).lower().strip() in normalized:
            return str(rule["category"])
    return "미분류"


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


@finance_blueprint.errorhandler(MetaApiError)
def _meta_api_error(error):
    payload = {"error": "meta_api_error", "detail": error.detail}
    if error.meta_code is not None:
        payload["meta_code"] = error.meta_code
    if error.meta_subcode is not None:
        payload["meta_subcode"] = error.meta_subcode
    return jsonify(payload), 502


@finance_blueprint.errorhandler(NaverApiError)
def _naver_api_error(error):
    payload = {"error": "naver_api_error", "detail": error.detail}
    if error.code is not None:
        payload["naver_code"] = error.code
    return jsonify(payload), 502


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


@finance_blueprint.get("/business/date-details")
@require_server_hmac
def business_date_details():
    workspace_id = _workspace_id(); _authorize("business_dashboard", workspace_id); selected = request.args.get("date")
    if not selected: raise ValueError("date is required")
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        FinanceService(repository).require_workspace(workspace_id)
        return jsonify(repository.business_date_details(workspace_id, selected))


@finance_blueprint.get("/ads/analytics")
@require_server_hmac
def ads_analytics():
    workspace_id = _workspace_id()
    _authorize("ads", workspace_id)
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        FinanceService(repository).require_workspace(workspace_id)
        start_date = request.args.get("start_date"); end_date = request.args.get("end_date")
        period = request.args.get("period")
        if period in {"7", "30", "90"} and not start_date and not end_date and not _month():
            end = date.today() - timedelta(days=1); start = end - timedelta(days=int(period) - 1); start_date = start.isoformat(); end_date = end.isoformat()
        return jsonify(repository.ad_analytics(workspace_id, _month(), start_date, end_date))


def _resource_collection(resource: str):
    workspace_id = _workspace_id()
    _authorize(RESOURCE_PERMISSION[resource], workspace_id, admin_only=resource in {"brands", "ad-accounts"} and request.method != "GET")
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        service = FinanceService(repository)
        service.require_workspace(workspace_id)
        if request.method == "GET":
            result = repository.query_resource(resource, workspace_id, **_query_options(resource))
            if resource == "ad-accounts":
                result["items"] = [_public_ad_account(item, workspace_id, connection) for item in result["items"]]
            return jsonify(result)
        payload = _json_payload()
        created = service.create_resource(resource, workspace_id, payload)
        if resource == "ad-accounts": created = _public_ad_account(created, workspace_id, connection)
        return jsonify(created), 201


def _resource_item(resource: str, item_id: str):
    workspace_id = _workspace_id()
    _authorize(RESOURCE_PERMISSION[resource], workspace_id, admin_only=resource in {"brands", "ad-accounts"} and request.method != "GET")
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        FinanceService(repository).require_workspace(workspace_id)
        if request.method == "GET":
            item = repository.get_resource(resource, workspace_id, item_id)
        elif request.method == "PATCH":
            payload = _json_payload()
            if resource == "products" and payload.get("brand_id") not in (None, ""):
                if not repository.get_resource("brands", workspace_id, str(payload["brand_id"])):
                    raise ValueError("product brand must belong to the same workspace")
            if resource == "transactions":
                current = repository.get_resource(resource, workspace_id, item_id)
                allocations = repository.get_marketing_allocations(workspace_id, item_id)
                if allocations and (
                    ("category" in payload and payload["category"] != "광고비")
                    or ("amount" in payload and int(payload["amount"]) != int(current["amount"] if current else 0))
                ):
                    raise ValueError("remove or update marketing allocations before changing category or amount")
            if resource == "brands" and "active" in payload:
                payload["active"] = 1 if payload["active"] else 0
            if resource == "ad-accounts":
                current = repository.get_resource(resource, workspace_id, item_id)
                if not current:
                    raise LookupError("ad account connection not found")
                identity_fields = {"platform", "account_id", "brand_id", "currency"}
                identity_changes = {
                    field for field in identity_fields
                    if field in payload and str(payload[field]).strip().lower() != str(current[field]).strip().lower()
                }
                if identity_changes:
                    has_synced_data = connection.execute(
                        "SELECT EXISTS(SELECT 1 FROM marketing_spend WHERE workspace_id=? AND ad_account_connection_id=?) "
                        "OR EXISTS(SELECT 1 FROM ad_spend WHERE workspace_id=? AND ad_account_connection_id=?)",
                        (workspace_id, item_id, workspace_id, item_id),
                    ).fetchone()[0]
                    if has_synced_data:
                        raise ValueError("synced ad account identity fields cannot be changed")
                if payload.get("brand_id") not in (None, "") and not repository.get_resource("brands", workspace_id, str(payload["brand_id"])):
                    raise ValueError("ad account brand must belong to the same workspace")
                if "credential_key" in payload:
                    payload["credential_key"] = str(payload["credential_key"]).strip().upper()
                    if not payload["credential_key"].replace("_", "").isalnum():
                        raise ValueError("invalid credential_key")
                if "currency" in payload: payload["currency"] = str(payload["currency"]).strip().upper()
                if "active" in payload: payload["active"] = 1 if payload["active"] else 0
            item = repository.update_resource(resource, workspace_id, item_id, payload)
        else:
            if resource == "brands":
                raise ValueError("brands must be deactivated instead of deleted")
            return ("", 204) if repository.delete_resource(resource, workspace_id, item_id) else (jsonify(error="not_found"), 404)
        if item and resource == "ad-accounts": item = _public_ad_account(item, workspace_id, connection)
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


@finance_blueprint.route("/naver-accounts", methods=["GET", "POST"])
@require_server_hmac
def naver_accounts():
    workspace_id = _workspace_id(); _authorize("ads", workspace_id, admin_only=request.method == "POST")
    with finance_connection() as connection:
        FinanceService(FinanceRepository(connection)).require_workspace(workspace_id)
        if request.method == "GET":
            rows = connection.execute(
                "SELECT * FROM naver_account_connection WHERE workspace_id=? ORDER BY active DESC,account_name,id",
                (workspace_id,),
            ).fetchall()
            return jsonify(items=[_public_naver_account(row, connection) for row in rows])
        payload = _json_payload()
        customer_id = str(payload.get("customer_id") or "").strip()
        account_name = str(payload.get("account_name") or "").strip()
        credential_key = str(payload.get("credential_key") or "").strip().upper()
        if not customer_id or not account_name or not credential_key:
            raise ValueError("customer_id, account_name and credential_key are required")
        if not customer_id.isdigit(): raise ValueError("customer_id must contain digits only")
        if not credential_key.replace("_", "").isalnum(): raise ValueError("invalid credential_key")
        cursor = connection.execute(
            "INSERT INTO naver_account_connection(workspace_id,customer_id,account_name,credential_key,active) VALUES (?,?,?,?,?)",
            (workspace_id, customer_id, account_name, credential_key, 1 if payload.get("active", True) else 0),
        )
        connection.commit()
        row = connection.execute("SELECT * FROM naver_account_connection WHERE id=?", (cursor.lastrowid,)).fetchone()
        return jsonify(_public_naver_account(row, connection)), 201


@finance_blueprint.patch("/naver-accounts/<int:account_id>")
@require_server_hmac
def update_naver_account(account_id: int):
    workspace_id = _workspace_id(); _authorize("ads", workspace_id, admin_only=True); payload = _json_payload()
    allowed = {"account_name", "credential_key", "active"}
    if any(key not in allowed for key in payload): raise ValueError("unsupported Naver account field")
    values = dict(payload)
    if "credential_key" in values:
        values["credential_key"] = str(values["credential_key"]).strip().upper()
        if not values["credential_key"].replace("_", "").isalnum(): raise ValueError("invalid credential_key")
    if "active" in values: values["active"] = 1 if values["active"] else 0
    if not values: raise ValueError("no fields to update")
    assignments = ",".join(f"{field}=?" for field in values)
    with finance_connection() as connection:
        cursor = connection.execute(
            f"UPDATE naver_account_connection SET {assignments},updated_at=CURRENT_TIMESTAMP WHERE id=? AND workspace_id=?",
            [*values.values(), account_id, workspace_id],
        )
        if not cursor.rowcount: raise LookupError("Naver account connection not found")
        connection.commit()
        row = connection.execute("SELECT * FROM naver_account_connection WHERE id=?", (account_id,)).fetchone()
        return jsonify(_public_naver_account(row, connection))


@finance_blueprint.get("/naver-accounts/<int:account_id>/campaigns")
@require_server_hmac
def naver_campaigns(account_id: int):
    workspace_id = _workspace_id(); _authorize("ads", workspace_id)
    with finance_connection() as connection:
        if not connection.execute("SELECT 1 FROM naver_account_connection WHERE id=? AND workspace_id=?", (account_id, workspace_id)).fetchone():
            raise LookupError("Naver account connection not found")
        rows = connection.execute(
            "SELECT c.*,b.name brand_name FROM naver_campaign c LEFT JOIN brand b ON b.id=c.brand_id AND b.workspace_id=c.workspace_id "
            "WHERE c.workspace_id=? AND c.naver_account_connection_id=? ORDER BY c.active DESC,c.campaign_name,c.id",
            (workspace_id, account_id),
        ).fetchall()
        return jsonify(items=[dict(row) for row in rows])


@finance_blueprint.post("/naver-accounts/<int:account_id>/campaigns/refresh")
@require_server_hmac
def refresh_naver_campaigns(account_id: int):
    workspace_id = _workspace_id(); _authorize("ads", workspace_id, admin_only=True)
    with finance_connection() as connection:
        account = connection.execute("SELECT * FROM naver_account_connection WHERE id=? AND workspace_id=?", (account_id, workspace_id)).fetchone()
        if not account: raise LookupError("Naver account connection not found")
        credentials = _naver_account_credentials(account)
        if not credentials: return jsonify(error="naver_credentials_not_configured"), 503
        discovered = NaverSearchAdsClient(credentials).campaigns()
        seen = []
        try:
            connection.execute("BEGIN IMMEDIATE")
            for item in discovered:
                seen.append(item["campaign_id"])
                connection.execute(
                    "INSERT INTO naver_campaign(workspace_id,naver_account_connection_id,campaign_id,campaign_name,status,active,last_seen_at) "
                    "VALUES (?,?,?,?,?,1,CURRENT_TIMESTAMP) ON CONFLICT(workspace_id,naver_account_connection_id,campaign_id) DO UPDATE SET "
                    "campaign_name=excluded.campaign_name,status=excluded.status,active=1,last_seen_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP",
                    (workspace_id, account_id, item["campaign_id"], item["campaign_name"], item["status"]),
                )
            if seen:
                placeholders = ",".join("?" for _ in seen)
                connection.execute(
                    f"UPDATE naver_campaign SET active=0,updated_at=CURRENT_TIMESTAMP WHERE workspace_id=? AND naver_account_connection_id=? AND campaign_id NOT IN ({placeholders})",
                    [workspace_id, account_id, *seen],
                )
            else:
                connection.execute("UPDATE naver_campaign SET active=0,updated_at=CURRENT_TIMESTAMP WHERE workspace_id=? AND naver_account_connection_id=?", (workspace_id, account_id))
            connection.execute("UPDATE naver_account_connection SET last_campaign_synced_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?", (account_id,))
            connection.commit()
        except Exception:
            connection.rollback(); raise
        return jsonify(discovered=len(discovered), preserved_mappings=True)


@finance_blueprint.route("/naver-campaigns/<int:campaign_row_id>/mapping", methods=["POST"])
@require_server_hmac
def map_naver_campaign(campaign_row_id: int):
    workspace_id = _workspace_id(); _authorize("ads", workspace_id, admin_only=True); payload = _json_payload()
    brand_id = payload.get("brand_id")
    if brand_id in ("", None): brand_id = None
    else: brand_id = int(brand_id)
    apply = payload.get("apply") is True
    with finance_connection() as connection:
        campaign = connection.execute("SELECT * FROM naver_campaign WHERE id=? AND workspace_id=?", (campaign_row_id, workspace_id)).fetchone()
        if not campaign: raise LookupError("Naver campaign not found")
        if brand_id is not None and not connection.execute("SELECT 1 FROM brand WHERE id=? AND workspace_id=?", (brand_id, workspace_id)).fetchone():
            raise ValueError("campaign brand must belong to the same workspace")
        affected = connection.execute(
            "SELECT COUNT(*) row_count,COALESCE(SUM(amount_krw),0) amount FROM naver_campaign_spend WHERE workspace_id=? AND naver_account_connection_id=? AND campaign_id=? AND brand_id IS NOT ?",
            (workspace_id, campaign["naver_account_connection_id"], campaign["campaign_id"], brand_id),
        ).fetchone()
        preview = {"campaign_id": campaign["campaign_id"], "from_brand_id": campaign["brand_id"], "to_brand_id": brand_id, "historical_affected_rows": int(affected["row_count"]), "historical_affected_amount": int(affected["amount"])}
        if not apply: return jsonify(dry_run=True, **preview)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("UPDATE naver_campaign SET brand_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND workspace_id=?", (brand_id, campaign_row_id, workspace_id))
            connection.execute("UPDATE naver_campaign_spend SET brand_id=?,updated_at=CURRENT_TIMESTAMP WHERE workspace_id=? AND naver_account_connection_id=? AND campaign_id=?", (brand_id, workspace_id, campaign["naver_account_connection_id"], campaign["campaign_id"]))
            connection.commit()
        except Exception:
            connection.rollback(); raise
        return jsonify(dry_run=False, **preview)


@finance_blueprint.post("/naver-accounts/<int:account_id>/sync")
@require_server_hmac
def sync_naver_account(account_id: int):
    workspace_id = _workspace_id(); _authorize("ads", workspace_id, admin_only=True); payload = _json_payload()
    start = payload.get("start_date") or payload.get("target_date"); end = payload.get("end_date") or payload.get("target_date")
    if not start or not end: raise ValueError("target_date or start/end date is required")
    if start != end: raise ValueError("Naver sync는 현재 1일 단위로 실행해주세요.")
    date.fromisoformat(start)
    with finance_connection() as connection:
        account = connection.execute("SELECT * FROM naver_account_connection WHERE id=? AND workspace_id=?", (account_id, workspace_id)).fetchone()
        if not account: raise LookupError("Naver account connection not found")
        if not account["active"]: raise ValueError("Naver account connection is inactive")
        credentials = _naver_account_credentials(account)
        if not credentials: return jsonify(error="naver_credentials_not_configured"), 503
        costs = NaverSearchAdsClient(credentials).daily_campaign_costs(start)
        report_total = sum(costs.values())
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM naver_campaign_spend WHERE workspace_id=? AND naver_account_connection_id=? AND date=?", (workspace_id, account_id, start))
            unmapped_amount = 0; unmapped_count = 0
            for campaign_id, amount in costs.items():
                campaign = connection.execute(
                    "SELECT * FROM naver_campaign WHERE workspace_id=? AND naver_account_connection_id=? AND campaign_id=?",
                    (workspace_id, account_id, campaign_id),
                ).fetchone()
                if not campaign:
                    cursor = connection.execute(
                        "INSERT INTO naver_campaign(workspace_id,naver_account_connection_id,campaign_id,campaign_name,status,brand_id,active) VALUES (?,?,?,?,'REPORT_ONLY',NULL,0)",
                        (workspace_id, account_id, campaign_id, f"미발견 캠페인 {campaign_id}"),
                    )
                    campaign = connection.execute("SELECT * FROM naver_campaign WHERE id=?", (cursor.lastrowid,)).fetchone()
                brand_id = campaign["brand_id"]
                if brand_id is None: unmapped_amount += amount; unmapped_count += 1
                external_key = f"naver:{account['customer_id']}:{campaign_id}:{start}"
                connection.execute(
                    "INSERT INTO naver_campaign_spend(workspace_id,naver_account_connection_id,campaign_id,brand_id,date,amount_krw,external_key) VALUES (?,?,?,?,?,?,?)",
                    (workspace_id, account_id, campaign_id, brand_id, start, amount, external_key),
                )
            saved_total = int(connection.execute("SELECT COALESCE(SUM(amount_krw),0) FROM naver_campaign_spend WHERE workspace_id=? AND naver_account_connection_id=? AND date=?", (workspace_id, account_id, start)).fetchone()[0])
            if saved_total != report_total: raise ValueError("Naver account total reconciliation failed")
            connection.execute(
                "INSERT INTO naver_account_sync_day(workspace_id,naver_account_connection_id,date,total_amount_krw,campaign_count,unmapped_amount_krw,unmapped_campaign_count) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(workspace_id,naver_account_connection_id,date) DO UPDATE SET total_amount_krw=excluded.total_amount_krw,campaign_count=excluded.campaign_count,unmapped_amount_krw=excluded.unmapped_amount_krw,unmapped_campaign_count=excluded.unmapped_campaign_count,updated_at=CURRENT_TIMESTAMP",
                (workspace_id, account_id, start, report_total, len(costs), unmapped_amount, unmapped_count),
            )
            connection.execute("UPDATE naver_account_connection SET last_spend_synced_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?", (account_id,))
            connection.commit()
        except Exception:
            connection.rollback(); raise
        return jsonify(date=start, account_total=report_total, campaign_count=len(costs), unmapped_amount=unmapped_amount, unmapped_campaign_count=unmapped_count, reconciled=True)


@finance_blueprint.get("/naver-legacy-cleanup/preview")
@require_server_hmac
def naver_legacy_cleanup_preview():
    workspace_id = _workspace_id(); _authorize("ads", workspace_id, admin_only=True)
    with finance_connection() as connection:
        rows = connection.execute(
            "SELECT ms.id,ms.date,ms.brand_id,ms.amount_krw,ms.external_key,ms.ad_account_connection_id,ac.account_id customer_id,ac.account_name "
            "FROM marketing_spend ms JOIN ad_account_connection ac ON ac.id=ms.ad_account_connection_id AND ac.workspace_id=ms.workspace_id "
            "WHERE ms.workspace_id=? AND ms.source='naver_api' AND ac.platform='naver' ORDER BY ms.date,ms.id",
            (workspace_id,),
        ).fetchall()
        amounts = [int(row["amount_krw"] or 0) for row in rows]
        return jsonify(dry_run=True, row_count=len(rows), total_amount=sum(amounts), min_date=rows[0]["date"] if rows else None, max_date=rows[-1]["date"] if rows else None, items=[dict(row) for row in rows])
@finance_blueprint.get("/marketing/channels")
@require_server_hmac
def marketing_channels():
    workspace_id = _workspace_id(); _authorize("transactions", workspace_id)
    return jsonify(items=list(MARKETING_CHANNELS))


@finance_blueprint.route("/transactions/<transaction_id>/marketing-allocations", methods=["GET", "PUT"])
@require_server_hmac
def transaction_marketing_allocations(transaction_id: str):
    workspace_id = _workspace_id(); _authorize("transactions", workspace_id)
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        FinanceService(repository).require_workspace(workspace_id)
        if request.method == "GET":
            transaction = repository.get_resource("transactions", workspace_id, transaction_id)
            if not transaction:
                raise LookupError("transaction not found")
            return jsonify(items=repository.get_marketing_allocations(workspace_id, transaction_id))
        allocations = _json_payload().get("allocations")
        if not isinstance(allocations, list):
            raise ValueError("allocations must be a list")
        return jsonify(items=repository.replace_marketing_allocations(workspace_id, transaction_id, allocations))


@finance_blueprint.get("/marketing-allocations/summary")
@require_server_hmac
def marketing_allocation_summary():
    workspace_id = _workspace_id(); _authorize("dashboard", workspace_id)
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        FinanceService(repository).require_workspace(workspace_id)
        return jsonify(repository.marketing_summary(
            workspace_id, _month(), request.args.get("start_date"), request.args.get("end_date")
        ))


MANUAL_SPEND_CHANNELS = ("인플루언서", "바이럴", "체험단", "대행사", "콘텐츠제작", "오프라인", "기타")


def _manual_spend_values(connection, workspace_id: int, payload: dict):
    brand_id = int(payload.get("brand_id") or 0)
    brand = connection.execute("SELECT id FROM brand WHERE id=? AND workspace_id=?", (brand_id, workspace_id)).fetchone()
    if not brand:
        raise ValueError("brand must belong to the workspace")
    product_id = int(payload["product_id"]) if payload.get("product_id") not in (None, "") else None
    if product_id is not None:
        product = connection.execute("SELECT brand_id FROM product WHERE id=? AND workspace_id=?", (product_id, workspace_id)).fetchone()
        if not product or product["brand_id"] is None or int(product["brand_id"]) != brand_id:
            raise ValueError("product must belong to the selected brand")
    channel = str(payload.get("channel") or "").strip()
    if channel not in MANUAL_SPEND_CHANNELS:
        raise ValueError("unsupported manual marketing channel")
    start = date.fromisoformat(str(payload.get("start_date") or payload.get("date")))
    end = date.fromisoformat(str(payload.get("end_date") or payload.get("date")))
    if start > end or (end - start).days > 366:
        raise ValueError("invalid manual spend date range")
    amount = int(payload.get("amount_krw") or 0)
    if amount <= 0:
        raise ValueError("amount_krw must be positive")
    count = (end - start).days + 1
    base, remainder = divmod(amount, count)
    rows = []
    cursor = start
    for offset in range(count):
        rows.append((cursor.isoformat(), base + (1 if offset < remainder else 0)))
        cursor += timedelta(days=1)
    return brand_id, product_id, channel, str(payload.get("memo") or "").strip() or None, rows


@finance_blueprint.route("/manual-marketing-spend", methods=["GET", "POST"])
@require_server_hmac
def manual_marketing_spend():
    workspace_id = _workspace_id(); _authorize("ads", workspace_id)
    with finance_connection() as connection:
        FinanceService(FinanceRepository(connection)).require_workspace(workspace_id)
        if request.method == "GET":
            rows = [dict(row) for row in connection.execute(
                "SELECT m.batch_id,MIN(m.date) start_date,MAX(m.date) end_date,SUM(m.amount_krw) amount_krw,"
                "m.brand_id,m.product_id,m.channel,m.memo,m.allocation_mode,MIN(m.created_at) created_at,b.name brand_name,p.name product_name "
                "FROM manual_marketing_spend m JOIN brand b ON b.id=m.brand_id AND b.workspace_id=m.workspace_id "
                "LEFT JOIN product p ON p.id=m.product_id AND p.workspace_id=m.workspace_id WHERE m.workspace_id=? "
                "GROUP BY m.batch_id,m.brand_id,m.product_id,m.channel,m.memo,m.allocation_mode,b.name,p.name ORDER BY start_date DESC,created_at DESC",
                (workspace_id,),
            )]
            return jsonify(items=rows)
        payload = _json_payload(); brand_id, product_id, channel, memo, rows = _manual_spend_values(connection, workspace_id, payload)
        batch_id = str(uuid.uuid4()); mode = "single" if len(rows) == 1 else "range"
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.executemany(
                "INSERT INTO manual_marketing_spend(id,batch_id,workspace_id,brand_id,product_id,date,channel,amount_krw,memo,allocation_mode) VALUES (?,?,?,?,?,?,?,?,?,?)",
                [(str(uuid.uuid4()), batch_id, workspace_id, brand_id, product_id, day, channel, amount, memo, mode) for day, amount in rows],
            )
            connection.commit()
        except Exception:
            connection.rollback(); raise
        return jsonify(batch_id=batch_id, days=len(rows), amount_krw=sum(amount for _, amount in rows)), 201


@finance_blueprint.route("/manual-marketing-spend/<batch_id>", methods=["PATCH", "DELETE"])
@require_server_hmac
def manual_marketing_spend_batch(batch_id: str):
    workspace_id = _workspace_id(); _authorize("ads", workspace_id)
    with finance_connection() as connection:
        exists = connection.execute("SELECT 1 FROM manual_marketing_spend WHERE workspace_id=? AND batch_id=?", (workspace_id, batch_id)).fetchone()
        if not exists: raise LookupError("manual spend batch not found")
        if request.method == "DELETE":
            connection.execute("DELETE FROM manual_marketing_spend WHERE workspace_id=? AND batch_id=?", (workspace_id, batch_id)); connection.commit()
            return "", 204
        brand_id, product_id, channel, memo, rows = _manual_spend_values(connection, workspace_id, _json_payload())
        mode = "single" if len(rows) == 1 else "range"
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM manual_marketing_spend WHERE workspace_id=? AND batch_id=?", (workspace_id, batch_id))
            connection.executemany(
                "INSERT INTO manual_marketing_spend(id,batch_id,workspace_id,brand_id,product_id,date,channel,amount_krw,memo,allocation_mode) VALUES (?,?,?,?,?,?,?,?,?,?)",
                [(str(uuid.uuid4()), batch_id, workspace_id, brand_id, product_id, day, channel, amount, memo, mode) for day, amount in rows],
            ); connection.commit()
        except Exception:
            connection.rollback(); raise
        return jsonify(batch_id=batch_id, days=len(rows), amount_krw=sum(amount for _, amount in rows))


@finance_blueprint.get("/sales-analysis/compare")
@require_server_hmac
def sales_analysis_compare():
    workspace_id = _workspace_id(); _authorize("business_dashboard", workspace_id)
    periods = {}
    for key in ("a", "b"):
        start_value = request.args.get(f"{key}_start")
        end_value = request.args.get(f"{key}_end")
        if not start_value or not end_value:
            raise ValueError(f"period {key.upper()} start and end are required")
        try:
            start = date.fromisoformat(start_value); end = date.fromisoformat(end_value)
        except ValueError as error:
            raise ValueError("comparison dates must be YYYY-MM-DD") from error
        if start > end:
            raise ValueError(f"period {key.upper()} start must be on or before end")
        periods[key] = (start.isoformat(), end.isoformat())
    brand_id = request.args.get("brand_id", type=int)
    product_id = request.args.get("product_id", type=int)
    with finance_connection() as connection:
        repository = FinanceRepository(connection)
        FinanceService(repository).require_workspace(workspace_id)
        return jsonify(repository.sales_analysis_compare(workspace_id, periods, brand_id, product_id))


@finance_blueprint.post("/transactions/import")
@require_server_hmac
def import_transactions():
    workspace_id = _workspace_id()
    _authorize("transactions", workspace_id)
    mode = request.form.get("mode", "append")
    if mode not in {"append", "replace"}:
        raise ValueError("mode must be append or replace")
    if mode == "replace" and not _is_admin():
        raise PermissionError("replace import is admin only")
    frame = _uploaded_frame().rename(columns={
        "거래일시": "날짜", "거래일자": "날짜", "사용일": "날짜", "거래처": "거래처명",
        "거래내용": "거래처명", "내용": "거래처명", "가맹점명": "거래처명",
        "출금액": "금액", "사용금액": "금액", "거래금액": "금액",
    })
    missing = [name for name in ("날짜", "거래처명", "금액") if name not in frame.columns]
    if missing:
        raise ValueError("missing columns: " + ", ".join(missing))
    frame["날짜"] = pd.to_datetime(frame["날짜"], errors="coerce")
    frame["금액"] = pd.to_numeric(frame["금액"].astype(str).str.replace(",", ""), errors="coerce")
    frame = frame.dropna(subset=["날짜", "금액"])
    with finance_connection() as connection:
        rules = list(connection.execute("SELECT id,keyword,category FROM rule WHERE workspace_id=? ORDER BY id", (workspace_id,)))
        existing = int(connection.execute("SELECT COUNT(*) FROM finance_transaction WHERE workspace_id=?", (workspace_id,)).fetchone()[0])
        rows = [{"id": str(uuid.uuid4()), "date": row["날짜"].strftime("%Y-%m-%d"), "merchant": str(row["거래처명"]), "amount": int(row["금액"]), "category": _classify(row["거래처명"], rules)} for _, row in frame.iterrows()]
        preview = {"mode": mode, "existing": existing, "delete": existing if mode == "replace" else 0, "add": len(rows), "result": len(rows) if mode == "replace" else existing + len(rows)}
        if request.form.get("dry_run", "true").lower() != "false":
            return jsonify(dry_run=True, **preview)
        if mode == "replace" and request.form.get("confirmation") != "REPLACE TRANSACTIONS":
            raise ValueError("explicit replacement confirmation is required")
        try:
            connection.execute("BEGIN IMMEDIATE")
            if mode == "replace":
                connection.execute("DELETE FROM finance_transaction WHERE workspace_id=?", (workspace_id,))
            connection.executemany("INSERT INTO finance_transaction(id,workspace_id,date,merchant,amount,category) VALUES (:id,:workspace_id,:date,:merchant,:amount,:category)", [{**row, "workspace_id": workspace_id} for row in rows])
            connection.commit()
        except Exception:
            connection.rollback(); raise
    return jsonify(dry_run=False, **preview)


@finance_blueprint.post("/sales/import")
@require_server_hmac
def import_sales():
    workspace_id = _workspace_id(); _authorize("sales", workspace_id)
    mode = request.form.get("mode", "append")
    if mode not in {"append", "replace"} or (mode == "replace" and not _is_admin()):
        raise PermissionError("replace import is admin only")
    frame = _uploaded_frame()
    with finance_connection() as connection:
        products = {row["name"]: dict(row) for row in connection.execute("SELECT * FROM product WHERE workspace_id=?", (workspace_id,))}
        platforms = {row["name"]: dict(row) for row in connection.execute("SELECT * FROM platform WHERE workspace_id=?", (workspace_id,))}
        rows = []
        errors = []
        for index, row in frame.iterrows():
            product = products.get(str(row.get("제품명", "")).strip()); platform = platforms.get(str(row.get("판매채널", "")).strip())
            try:
                if not product or not platform: raise ValueError("제품/판매채널 없음")
                selling = int(str(row.get("실제판매가", 0)).replace(",", "")); quantity = int(row.get("수량", 1)); sold_at = pd.to_datetime(row.get("판매일")).strftime("%Y-%m-%d")
                cost = int(product["cost_price"]) * quantity; commission = int(selling * float(platform["commission_rate"]) / 100)
                rows.append((str(uuid.uuid4()), workspace_id, sold_at, product["id"], platform["id"], selling, quantity, selling, cost, commission, selling - cost - commission))
            except Exception:
                errors.append({"row": int(index) + 2, "message": "날짜·숫자·제품·판매채널을 확인해주세요"})
        if errors: return jsonify(error="invalid_rows", errors=errors), 400
        existing = int(connection.execute("SELECT COUNT(*) FROM sale WHERE workspace_id=?", (workspace_id,)).fetchone()[0])
        preview = {"mode": mode, "existing": existing, "delete": existing if mode == "replace" else 0, "add": len(rows), "result": len(rows) if mode == "replace" else existing + len(rows)}
        if request.form.get("dry_run", "true").lower() != "false": return jsonify(dry_run=True, **preview)
        if mode == "replace" and request.form.get("confirmation") != "REPLACE SALES": raise ValueError("explicit replacement confirmation is required")
        try:
            connection.execute("BEGIN IMMEDIATE")
            if mode == "replace": connection.execute("DELETE FROM sale WHERE workspace_id=?", (workspace_id,))
            connection.executemany("INSERT INTO sale(id,workspace_id,date,product_id,platform_id,selling_price,quantity,total_selling_amount,total_cost_amount,commission_amount,net_profit) VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
            connection.commit()
        except Exception: connection.rollback(); raise
    return jsonify(dry_run=False, **preview)


@finance_blueprint.post("/<resource>/bulk-delete")
@require_server_hmac
def bulk_delete(resource: str):
    if resource not in {"transactions", "sales"}: raise ValueError("unsupported bulk delete resource")
    workspace_id = _workspace_id(); _authorize(RESOURCE_PERMISSION[resource], workspace_id)
    ids = _json_payload().get("ids", [])
    if not isinstance(ids, list) or not ids: raise ValueError("ids are required")
    table = RESOURCE_CONFIG[resource]["table"]
    with finance_connection() as connection:
        placeholders = ",".join("?" for _ in ids)
        cursor = connection.execute(f"DELETE FROM {table} WHERE workspace_id=? AND id IN ({placeholders})", [workspace_id, *ids]); connection.commit()
        return jsonify(deleted=cursor.rowcount)


@finance_blueprint.post("/categories/reclassify")
@require_server_hmac
def reclassify_transactions():
    workspace_id = _workspace_id(); _authorize("categories", workspace_id)
    payload = _json_payload(); apply = payload.get("apply") is True
    with finance_connection() as connection:
        rules = list(connection.execute("SELECT id,keyword,category FROM rule WHERE workspace_id=? ORDER BY id", (workspace_id,)))
        rows = list(connection.execute("SELECT id,merchant,category FROM finance_transaction WHERE workspace_id=?", (workspace_id,)))
        changes = [( _classify(row["merchant"], rules), row["id"], row["category"]) for row in rows]
        changed = [item for item in changes if item[0] != item[2]]
        if apply:
            if payload.get("confirmation") != "RECLASSIFY ALL": raise ValueError("explicit reclassification confirmation is required")
            connection.executemany("UPDATE finance_transaction SET category=? WHERE id=? AND workspace_id=?", [(category, item_id, workspace_id) for category, item_id, _ in changed]); connection.commit()
        return jsonify(dry_run=not apply, total=len(rows), changed=len(changed), sample=[{"id": item_id, "before": before, "after": after} for after, item_id, before in changed[:20]])


@finance_blueprint.get("/exports/<report>")
@require_server_hmac
def export_report(report: str):
    if report not in {"expenses", "business", "sales"}: raise ValueError("unsupported report")
    workspace_id = _workspace_id(); permission = "dashboard" if report == "expenses" else ("business_dashboard" if report == "business" else "sales"); _authorize(permission, workspace_id)
    month = _month(); start_date = request.args.get("start_date"); end_date = request.args.get("end_date")
    with finance_connection() as connection:
        repo = FinanceRepository(connection)
        def all_rows(resource: str) -> list[dict]:
            first = repo.query_resource(resource, workspace_id, page=1, page_size=200, month=month, start_date=start_date, end_date=end_date)
            rows = list(first["items"])
            for page in range(2, first["pagination"]["pages"] + 1):
                rows.extend(repo.query_resource(resource, workspace_id, page=page, page_size=200, month=month, start_date=start_date, end_date=end_date)["items"])
            return rows
        tx = all_rows("transactions")
        sales = all_rows("sales")
        products = {row["id"]: row["name"] for row in connection.execute("SELECT id,name FROM product WHERE workspace_id=?", (workspace_id,))}
        platforms = {row["id"]: row["name"] for row in connection.execute("SELECT id,name FROM platform WHERE workspace_id=?", (workspace_id,))}
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        if report in {"expenses", "business"}:
            expense_frame = pd.DataFrame(tx)
            classified = expense_frame[expense_frame["category"] != "미분류"] if not expense_frame.empty else expense_frame
            pd.DataFrame([{"항목": "총 지출", "금액": int(classified["amount"].sum()) if not classified.empty else 0}]).to_excel(writer, sheet_name="비용 요약", index=False)
            if not classified.empty:
                classified.groupby("category", as_index=False)["amount"].sum().to_excel(writer, sheet_name="카테고리별", index=False)
                classified.to_excel(writer, sheet_name="비용 상세", index=False)
        if report in {"business", "sales"}:
            sale_frame = pd.DataFrame(sales)
            if not sale_frame.empty:
                sale_frame["product_name"] = sale_frame["product_id"].map(products); sale_frame["platform_name"] = sale_frame["platform_id"].map(platforms)
            pd.DataFrame([{"항목": "총 매출", "금액": int(sale_frame["total_selling_amount"].sum()) if not sale_frame.empty else 0}, {"항목": "판매이익", "금액": int(sale_frame["net_profit"].sum()) if not sale_frame.empty else 0}]).to_excel(writer, sheet_name="매출 요약", index=False)
            if not sale_frame.empty:
                sale_frame.groupby("product_name", as_index=False).agg({"quantity":"sum","total_selling_amount":"sum","net_profit":"sum"}).to_excel(writer, sheet_name="제품별", index=False)
                sale_frame.to_excel(writer, sheet_name="매출 상세", index=False)
    output.seek(0)
    return send_file(output, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", as_attachment=True, download_name=f"{report}_report.xlsx")


@finance_blueprint.post("/products/<int:product_id>/recalculate")
@require_server_hmac
def recalculate_product(product_id: int):
    workspace_id = _workspace_id(); _authorize("products", workspace_id); payload = _json_payload()
    with finance_connection() as connection:
        product = connection.execute("SELECT * FROM product WHERE id=? AND workspace_id=?", (product_id, workspace_id)).fetchone()
        if not product: raise LookupError("product not found")
        count = int(connection.execute("SELECT COUNT(*) FROM sale WHERE workspace_id=? AND product_id=?", (workspace_id, product_id)).fetchone()[0])
        if payload.get("apply") is not True: return jsonify(dry_run=True, affected=count, new_cost=product["cost_price"])
        if payload.get("confirmation") != "RECALCULATE HISTORICAL SALES": raise ValueError("explicit recalculation confirmation is required")
        connection.execute("UPDATE sale SET total_cost_amount=? * quantity, net_profit=total_selling_amount-(? * quantity)-commission_amount WHERE workspace_id=? AND product_id=?", (product["cost_price"], product["cost_price"], workspace_id, product_id)); connection.commit()
        return jsonify(dry_run=False, affected=count)


@finance_blueprint.route("/meta/settings", methods=["GET", "PATCH"])
@require_server_hmac
def meta_settings():
    workspace_id = _workspace_id(); _authorize("ads", workspace_id, admin_only=request.method == "PATCH")
    with finance_connection() as connection:
        if request.method == "PATCH":
            account_id = str(_json_payload().get("meta_ad_account_id", "")).strip() or None
            connection.execute("INSERT INTO workspace_settings(workspace_id,meta_ad_account_id,updated_at) VALUES (?,?,CURRENT_TIMESTAMP) ON CONFLICT(workspace_id) DO UPDATE SET meta_ad_account_id=excluded.meta_ad_account_id,updated_at=CURRENT_TIMESTAMP", (workspace_id, account_id)); connection.commit()
        row = connection.execute("SELECT meta_ad_account_id,updated_at FROM workspace_settings WHERE workspace_id=?", (workspace_id,)).fetchone()
    token_present = bool(os.getenv(f"SBROCOR_META_ACCESS_TOKEN_WORKSPACE_{workspace_id}"))
    return jsonify(meta_ad_account_id=row["meta_ad_account_id"] if row else None, updated_at=row["updated_at"] if row else None, token_configured=token_present)


@finance_blueprint.post("/meta/fetch")
@require_server_hmac
def meta_fetch():
    workspace_id = _workspace_id(); _authorize("ads", workspace_id, admin_only=True); payload = _json_payload()
    token = os.getenv(f"SBROCOR_META_ACCESS_TOKEN_WORKSPACE_{workspace_id}")
    if not token: return jsonify(error="meta_token_not_configured"), 503
    start = payload.get("start_date") or payload.get("target_date"); end = payload.get("end_date") or payload.get("target_date")
    if not start or not end: raise ValueError("target_date or start/end date is required")
    if (datetime.fromisoformat(end).date() - datetime.fromisoformat(start).date()).days > 370: raise ValueError("range is too large")
    with finance_connection() as connection:
        row = connection.execute("SELECT meta_ad_account_id FROM workspace_settings WHERE workspace_id=?", (workspace_id,)).fetchone()
        if not row or not row[0]: raise ValueError("Meta ad account is not configured")
        page = _meta_get(
            f"https://graph.facebook.com/v23.0/{row[0]}/insights",
            token=token,
            params={"level":"ad", "time_range":f'{{"since":"{start}","until":"{end}"}}', "time_increment":1, "fields":"date_start,campaign_id,campaign_name,adset_id,adset_name,ad_id,ad_name,spend,impressions,clicks,ctr,cpc,cpm,actions,action_values", "limit":5000},
            workspace_id=workspace_id,
            connection_id="legacy",
            account_id=str(row[0]),
        )
        items = page.get("data", [])
        saved = 0
        try:
            connection.execute("BEGIN IMMEDIATE")
            for item in items:
                actions = {entry.get("action_type"): float(entry.get("value",0)) for entry in item.get("actions",[])}; values = {entry.get("action_type"): float(entry.get("value",0)) for entry in item.get("action_values",[])}
                conversions = actions.get("purchase",0); revenue = values.get("purchase",0); spend = float(item.get("spend",0))
                connection.execute("INSERT INTO ad_spend(workspace_id,date,platform,campaign_id,campaign_name,adset_id,adset_name,ad_id,ad_name,spend,impressions,clicks,ctr,cpc,cpm,conversions,conversion_value,roas) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(workspace_id,date,platform,ad_id) DO UPDATE SET campaign_name=excluded.campaign_name,adset_name=excluded.adset_name,ad_name=excluded.ad_name,spend=excluded.spend,impressions=excluded.impressions,clicks=excluded.clicks,ctr=excluded.ctr,cpc=excluded.cpc,cpm=excluded.cpm,conversions=excluded.conversions,conversion_value=excluded.conversion_value,roas=excluded.roas", (workspace_id,item.get("date_start"),"meta",item.get("campaign_id"),item.get("campaign_name"),item.get("adset_id"),item.get("adset_name"),item.get("ad_id"),item.get("ad_name"),spend,int(item.get("impressions",0)),int(item.get("clicks",0)),float(item.get("ctr",0)),float(item.get("cpc",0)),float(item.get("cpm",0)),conversions,revenue,revenue/spend if spend else 0)); saved += 1
            connection.commit()
        except Exception: connection.rollback(); raise
    return jsonify(saved=saved,start_date=start,end_date=end)


@finance_blueprint.post("/ad-accounts/<int:connection_id>/sync")
@require_server_hmac
def sync_ad_account(connection_id: int):
    workspace_id = _workspace_id(); _authorize("ads", workspace_id, admin_only=True); payload = _json_payload()
    start = payload.get("start_date") or payload.get("target_date"); end = payload.get("end_date") or payload.get("target_date")
    if not start or not end: raise ValueError("target_date or start/end date is required")
    start_day = date.fromisoformat(start); end_day = date.fromisoformat(end)
    if start_day > end_day: raise ValueError("start_date must be on or before end_date")
    if (end_day - start_day).days > 370: raise ValueError("range is too large")
    with finance_connection() as connection:
        account = connection.execute(
            "SELECT ac.*,b.name brand_name FROM ad_account_connection ac JOIN brand b ON b.id=ac.brand_id AND b.workspace_id=ac.workspace_id "
            "WHERE ac.id=? AND ac.workspace_id=?", (connection_id, workspace_id),
        ).fetchone()
        if not account: raise LookupError("ad account connection not found")
        if not account["active"]: raise ValueError("ad account connection is inactive")
        if account["platform"] == "naver":
            raise ValueError("Naver legacy account sync is disabled. Use the campaign attribution endpoint.")
        if account["platform"] != "meta": raise ValueError("sync is not implemented for this platform")
        token = _credential_token(account, workspace_id)
        if not token: return jsonify(error="meta_token_not_configured"), 503
        next_url = f"https://graph.facebook.com/v23.0/{account['account_id']}/insights"
        next_params = {
            "level": "ad", "time_range": f'{{"since":"{start}","until":"{end}"}}',
            "time_increment": 1, "fields": "date_start,campaign_id,campaign_name,adset_id,adset_name,ad_id,ad_name,spend,impressions,clicks,ctr,cpc,cpm,actions,action_values", "limit": 5000,
        }
        items: list[dict] = []
        visited_pages: set[str] = set()
        for _page_number in range(100):
            if next_url in visited_pages:
                raise ValueError("Meta pagination loop detected")
            visited_pages.add(next_url)
            page = _meta_get(
                next_url,
                token=token,
                params=next_params,
                workspace_id=workspace_id,
                connection_id=connection_id,
                account_id=str(account["account_id"]),
            )
            page_items = page.get("data", [])
            if not isinstance(page_items, list):
                raise ValueError("Meta response data must be a list")
            items.extend(page_items)
            if len(items) > 100000:
                raise ValueError("Meta sync row limit exceeded")
            next_page = page.get("paging", {}).get("next")
            if not next_page:
                break
            if not isinstance(next_page, str):
                raise ValueError("Meta pagination URL is invalid")
            next_url = next_page
            next_params = None
        else:
            raise ValueError("Meta pagination page limit exceeded")
        daily_spend: dict[str, float] = {}
        try:
            connection.execute("BEGIN IMMEDIATE")
            for item in items:
                day = str(item.get("date_start")); spend = float(item.get("spend", 0)); daily_spend[day] = daily_spend.get(day, 0) + spend
                actions = {entry.get("action_type"): float(entry.get("value",0)) for entry in item.get("actions",[])}
                values = {entry.get("action_type"): float(entry.get("value",0)) for entry in item.get("action_values",[])}
                conversions = actions.get("purchase",0); revenue = values.get("purchase",0)
                connection.execute(
                    "INSERT INTO ad_spend(workspace_id,date,platform,campaign_id,campaign_name,adset_id,adset_name,ad_id,ad_name,spend,impressions,clicks,ctr,cpc,cpm,conversions,conversion_value,roas,ad_account_connection_id,brand_id) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(workspace_id,date,platform,ad_id) DO UPDATE SET "
                    "campaign_name=excluded.campaign_name,adset_name=excluded.adset_name,ad_name=excluded.ad_name,spend=excluded.spend,impressions=excluded.impressions,clicks=excluded.clicks,ctr=excluded.ctr,cpc=excluded.cpc,cpm=excluded.cpm,conversions=excluded.conversions,conversion_value=excluded.conversion_value,roas=excluded.roas,ad_account_connection_id=excluded.ad_account_connection_id,brand_id=excluded.brand_id",
                    (workspace_id,day,"meta",item.get("campaign_id"),item.get("campaign_name"),item.get("adset_id"),item.get("adset_name"),item.get("ad_id"),item.get("ad_name"),spend,int(item.get("impressions",0)),int(item.get("clicks",0)),float(item.get("ctr",0)),float(item.get("cpc",0)),float(item.get("cpm",0)),conversions,revenue,revenue/spend if spend else 0,connection_id,account["brand_id"]),
                )
            cursor = start_day; synced_days = 0
            while cursor <= end_day:
                day = cursor.isoformat(); original = daily_spend.get(day, 0.0); currency = str(account["currency"]).upper()
                amount_krw = round(original) if currency == "KRW" else None
                external_key = f"meta:{account['account_id']}:{day}:account"
                connection.execute(
                    "INSERT INTO marketing_spend(workspace_id,ad_account_connection_id,brand_id,product_id,date,channel,original_amount,currency,fx_rate,amount_krw,source,external_key) "
                    "VALUES (?,?,?,NULL,?,'Meta',?,?,NULL,?,'meta_api',?) ON CONFLICT(workspace_id,source,external_key) DO UPDATE SET "
                    "ad_account_connection_id=excluded.ad_account_connection_id,brand_id=excluded.brand_id,original_amount=excluded.original_amount,currency=excluded.currency,fx_rate=excluded.fx_rate,amount_krw=excluded.amount_krw,updated_at=CURRENT_TIMESTAMP",
                    (workspace_id,connection_id,account["brand_id"],day,original,currency,amount_krw,external_key),
                ); synced_days += 1; cursor += timedelta(days=1)
            connection.execute("UPDATE ad_account_connection SET last_synced_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=? AND workspace_id=?", (connection_id,workspace_id))
            connection.commit()
        except Exception: connection.rollback(); raise
    return jsonify(
        connection_id=connection_id,
        raw_saved=len(items),
        days_synced=synced_days,
        zero_spend_days=synced_days - len(daily_spend),
        start_date=start,
        end_date=end,
        currency=account["currency"],
        currency_converted=str(account["currency"]).upper()=="KRW",
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


