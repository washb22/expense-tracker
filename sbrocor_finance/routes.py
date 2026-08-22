"""Versioned HTTP routes for server-to-server SBROCOR Finance access."""

from __future__ import annotations

import sqlite3
import io
import os
import re
import uuid
from datetime import date, datetime, timedelta

import pandas as pd
import requests
from flask import Blueprint, g, jsonify, request, send_file

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
        items = [dict(row) for row in connection.execute("SELECT s.*,p.name product_name,pl.name platform_name FROM sale s JOIN product p ON p.id=s.product_id JOIN platform pl ON pl.id=s.platform_id WHERE s.workspace_id=? AND s.date=? ORDER BY p.name,pl.name", (workspace_id, selected))]
        return jsonify(date=selected, items=items, total_quantity=sum(int(row["quantity"]) for row in items), total_sales=sum(int(row["total_selling_amount"]) for row in items), total_profit=sum(int(row["net_profit"]) for row in items))


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
        response = requests.get(f"https://graph.facebook.com/v23.0/{row[0]}/insights", params={"access_token": token, "level":"ad", "time_range":f'{{"since":"{start}","until":"{end}"}}', "time_increment":1, "fields":"date_start,campaign_id,campaign_name,adset_id,adset_name,ad_id,ad_name,spend,impressions,clicks,ctr,cpc,cpm,actions,action_values", "limit":5000}, timeout=60)
        response.raise_for_status(); items = response.json().get("data", [])
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

