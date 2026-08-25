"""Minimal, credential-safe Naver Search Ads STAT-REPORT client."""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import time
from dataclasses import dataclass

import requests


BASE_URL = "https://api.searchad.naver.com"


class NaverApiError(Exception):
    """Safe upstream error whose text never contains request credentials."""

    def __init__(self, detail: str = "Naver Search Ads API 요청에 실패했습니다.", *, code=None):
        super().__init__(detail)
        self.detail = detail[:300]
        self.code = code


def generate_signature(timestamp: str, method: str, uri: str, secret_key: str) -> str:
    """Follow naver/searchad-apidoc: Base64(HMAC-SHA256(timestamp.method.uri))."""
    message = f"{timestamp}.{method.upper()}.{uri}".encode()
    digest = hmac.new(secret_key.encode(), message, hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


@dataclass(frozen=True)
class Credentials:
    api_key: str
    secret_key: str
    customer_id: str


class NaverSearchAdsClient:
    def __init__(self, credentials: Credentials, *, session=requests, poll_seconds: float = 1.0, max_polls: int = 90):
        self.credentials = credentials
        self.session = session
        self.poll_seconds = poll_seconds
        self.max_polls = max_polls

    def _headers(self, method: str, uri: str) -> dict[str, str]:
        timestamp = str(round(time.time() * 1000))
        return {
            "Content-Type": "application/json; charset=UTF-8",
            "X-Timestamp": timestamp,
            "X-API-KEY": self.credentials.api_key,
            "X-Customer": self.credentials.customer_id,
            "X-Signature": generate_signature(timestamp, method, uri, self.credentials.secret_key),
        }

    def _request(self, method: str, uri: str, **kwargs):
        try:
            response = self.session.request(method, BASE_URL + uri, headers=self._headers(method, uri), timeout=60, **kwargs)
        except requests.RequestException:
            raise NaverApiError() from None
        if not 200 <= int(response.status_code) < 300:
            try:
                payload = response.json()
                code = payload.get("code") if isinstance(payload, dict) else None
            except (TypeError, ValueError):
                code = None
            raise NaverApiError(code=code)
        return response

    def daily_cost(self, day: str) -> int:
        """Build official AD report and sum its Cost column for the whole customer."""
        created = self._request("POST", "/stat-reports", json={"reportTp": "AD", "statDt": day.replace("-", "")}).json()
        job_id = created.get("reportJobId")
        if not job_id:
            raise NaverApiError("Naver 보고서 생성 결과가 올바르지 않습니다.")
        status = created.get("status")
        report = created
        for _ in range(self.max_polls):
            if status in {"BUILT", "NONE", "ERROR", "AGGREGATING"}:
                break
            if self.poll_seconds:
                time.sleep(self.poll_seconds)
            report = self._request("GET", f"/stat-reports/{job_id}").json()
            status = report.get("status")
        if status == "NONE":
            return 0
        if status != "BUILT" or not report.get("downloadUrl"):
            raise NaverApiError("Naver 보고서를 완료하지 못했습니다.")
        try:
            downloaded = self.session.get(report["downloadUrl"], headers=self._headers("GET", "/report-download"), timeout=120)
        except requests.RequestException:
            raise NaverApiError("Naver 보고서를 다운로드하지 못했습니다.") from None
        if not 200 <= int(downloaded.status_code) < 300:
            raise NaverApiError("Naver 보고서를 다운로드하지 못했습니다.")
        return parse_ad_report_cost(downloaded.content)


def parse_ad_report_cost(content: bytes) -> int:
    """Sum the documented AD-report Cost column (12th column, zero-based 11)."""
    text = content.decode("utf-8-sig", errors="strict")
    total = 0.0
    for row in csv.reader(io.StringIO(text), delimiter="\t"):
        if not row or all(not value.strip() for value in row):
            continue
        if len(row) <= 11:
            raise NaverApiError("Naver 광고효과보고서 형식이 올바르지 않습니다.")
        try:
            total += float(row[11].replace(",", ""))
        except ValueError as error:
            raise NaverApiError("Naver 광고효과보고서 Cost 값이 올바르지 않습니다.") from error
    return round(total)

