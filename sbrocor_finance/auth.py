"""HMAC request authentication with timestamp, nonce and replay protection."""

from __future__ import annotations

import hashlib
import hmac
import time
import base64
import json
from functools import wraps

from flask import g, jsonify, request

from .config import FinanceConfigurationError, get_hmac_settings
from .database import finance_connection


HEADER_KEY_ID = "X-SBROCOR-Key-Id"
HEADER_TIMESTAMP = "X-SBROCOR-Timestamp"
HEADER_NONCE = "X-SBROCOR-Nonce"
HEADER_SIGNATURE = "X-SBROCOR-Signature"
HEADER_CONTEXT = "X-SBROCOR-Context"


def canonical_request(method: str, path_with_query: str, timestamp: str, nonce: str, body: bytes, context: str = "") -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join((method.upper(), path_with_query, timestamp, nonce, body_hash, context)).encode("utf-8")


def sign_request(secret: bytes, method: str, path_with_query: str, timestamp: str, nonce: str, body: bytes, context: str = "") -> str:
    return hmac.new(secret, canonical_request(method, path_with_query, timestamp, nonce, body, context), hashlib.sha256).hexdigest()


def _decode_context(encoded: str) -> dict:
    try:
        padding = "=" * (-len(encoded) % 4)
        value = json.loads(base64.urlsafe_b64decode(encoded + padding))
    except Exception as exc:
        raise ValueError("invalid signed context") from exc
    if not isinstance(value, dict) or not isinstance(value.get("actor_uid"), str):
        raise ValueError("invalid signed context")
    role = value.get("role")
    if role not in ("admin", "employee"):
        raise ValueError("invalid signed role")
    if not isinstance(value.get("workspace_ids"), list) or not all(isinstance(v, int) for v in value["workspace_ids"]):
        raise ValueError("invalid signed workspace scope")
    if not isinstance(value.get("permissions"), list) or not all(isinstance(v, str) for v in value["permissions"]):
        raise ValueError("invalid signed permission scope")
    return value


def require_server_hmac(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        try:
            expected_key_id, secret, max_skew = get_hmac_settings()
        except FinanceConfigurationError as exc:
            return jsonify(error="finance_auth_not_configured", detail=str(exc)), 503

        key_id = request.headers.get(HEADER_KEY_ID, "")
        timestamp_raw = request.headers.get(HEADER_TIMESTAMP, "")
        nonce = request.headers.get(HEADER_NONCE, "")
        supplied = request.headers.get(HEADER_SIGNATURE, "")
        encoded_context = request.headers.get(HEADER_CONTEXT, "")
        if key_id != expected_key_id or not nonce or len(nonce) < 16:
            return jsonify(error="unauthorized"), 401
        try:
            timestamp = int(timestamp_raw)
        except ValueError:
            return jsonify(error="invalid_timestamp"), 401
        now = int(time.time())
        if abs(now - timestamp) > max_skew:
            return jsonify(error="expired_request"), 401

        body = request.get_data(cache=True)
        expected = sign_request(secret, request.method, request.full_path.rstrip("?"), timestamp_raw, nonce, body, encoded_context)
        if not hmac.compare_digest(expected, supplied):
            return jsonify(error="invalid_signature"), 401
        try:
            g.finance_context = _decode_context(encoded_context)
        except ValueError:
            return jsonify(error="invalid_context"), 401

        with finance_connection() as connection:
            connection.execute("DELETE FROM auth_nonce WHERE seen_at < ?", (now - max_skew,))
            try:
                connection.execute(
                    "INSERT INTO auth_nonce(key_id, nonce, seen_at) VALUES (?, ?, ?)",
                    (key_id, nonce, now),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                return jsonify(error="replayed_request"), 409
        return view(*args, **kwargs)

    return wrapped

