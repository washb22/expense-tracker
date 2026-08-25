"""Minimal, credential-safe Naver Search Ads STAT-REPORT client."""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import time
from dataclasses import dataclass
import re
from urllib.parse import urlsplit

import requests


BASE_URL = "https://api.searchad.naver.com"
# Official AD STAT-REPORT order: Date, CUSTOMER ID, Campaign ID, AD Group ID,
# Keyword ID, AD ID, Business Channel ID, Media code, PC/Mobile, Impression,
# Click, Cost, View count. Keep named indexes so campaign attribution never
# relies on an unexplained positional guess.
AD_REPORT_CAMPAIGN_ID_INDEX = 2
AD_REPORT_ADGROUP_ID_INDEX = 3
AD_REPORT_COST_INDEX = 11


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
                message = payload.get("message") if isinstance(payload, dict) else None
            except (TypeError, ValueError):
                code = None
                message = None
            safe_message = self._safe_message(message)
            raise NaverApiError(f"Naver API: {safe_message}" if safe_message else "Naver Search Ads API 요청에 실패했습니다.", code=code)
        return response

    def _safe_message(self, value: object) -> str:
        message = str(value or "").strip()
        for secret in (self.credentials.api_key, self.credentials.secret_key):
            if secret:
                message = message.replace(secret, "[REDACTED]")
        message = re.sub(r"(?i)(X-(?:API-KEY|Signature)\s*[:=]\s*)\S+", r"\1[REDACTED]", message)
        return message[:300]

    def campaigns(self) -> list[dict[str, object]]:
        """Return the official /ncc/campaigns response in a stable shape."""
        payload = self._request("GET", "/ncc/campaigns").json()
        if not isinstance(payload, list):
            raise NaverApiError("Naver 캠페인 목록 형식이 올바르지 않습니다.")
        campaigns = []
        for item in payload:
            if not isinstance(item, dict) or not item.get("nccCampaignId") or not item.get("name"):
                raise NaverApiError("Naver 캠페인 항목 형식이 올바르지 않습니다.")
            campaigns.append({
                "campaign_id": str(item["nccCampaignId"]),
                "campaign_name": str(item["name"]),
                "status": str(item.get("status") or ""),
            })
        return campaigns

    def adgroups(self) -> list[dict[str, object]]:
        """Return official /ncc/adgroups fields in a stable internal shape."""
        payload = self._request("GET", "/ncc/adgroups").json()
        if not isinstance(payload, list):
            raise NaverApiError("Naver 광고그룹 목록 형식이 올바르지 않습니다.")
        groups = []
        for item in payload:
            if not isinstance(item, dict) or not item.get("nccAdgroupId") or not item.get("nccCampaignId") or not item.get("name"):
                raise NaverApiError("Naver 광고그룹 항목 형식이 올바르지 않습니다.")
            groups.append({
                "adgroup_id": str(item["nccAdgroupId"]),
                "campaign_id": str(item["nccCampaignId"]),
                "adgroup_name": str(item["name"]),
                "status": str(item.get("status") or ""),
            })
        return groups

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
        download_url = str(report["downloadUrl"])
        parts = urlsplit(download_url)
        if parts.scheme != "https" or parts.hostname != "api.searchad.naver.com" or parts.path != "/report-download":
            raise NaverApiError("Naver 보고서 다운로드 URL이 올바르지 않습니다.")
        try:
            # Use the official URL verbatim so authtoken, fileVersion and future query fields survive.
            downloaded = self.session.get(download_url, headers=self._headers("GET", "/report-download"), timeout=120)
        except requests.RequestException:
            raise NaverApiError("Naver 보고서를 다운로드하지 못했습니다.") from None
        if not 200 <= int(downloaded.status_code) < 300:
            raise NaverApiError("Naver 보고서를 다운로드하지 못했습니다.")
        return parse_ad_report_cost(downloaded.content)

    def daily_campaign_costs(self, day: str) -> dict[str, int]:
        """Build one official AD report and aggregate exact Cost by Campaign ID."""
        return self._download_ad_report(day, parse_ad_report_campaign_costs)

    def daily_adgroup_costs(self, day: str) -> dict[tuple[str, str], int]:
        """Build one official AD report and aggregate Cost by campaign and ad group."""
        return self._download_ad_report(day, parse_ad_report_adgroup_costs)

    def _download_ad_report(self, day: str, parser):
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
            return {}
        if status != "BUILT" or not report.get("downloadUrl"):
            raise NaverApiError("Naver 보고서를 완료하지 못했습니다.")
        download_url = str(report["downloadUrl"])
        parts = urlsplit(download_url)
        if parts.scheme != "https" or parts.hostname != "api.searchad.naver.com" or parts.path != "/report-download":
            raise NaverApiError("Naver 보고서 다운로드 URL이 올바르지 않습니다.")
        try:
            downloaded = self.session.get(download_url, headers=self._headers("GET", "/report-download"), timeout=120)
        except requests.RequestException:
            raise NaverApiError("Naver 보고서를 다운로드하지 못했습니다.") from None
        if not 200 <= int(downloaded.status_code) < 300:
            raise NaverApiError("Naver 보고서를 다운로드하지 못했습니다.")
        return parser(downloaded.content)


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


def parse_ad_report_campaign_costs(content: bytes) -> dict[str, int]:
    """Aggregate the documented AD report Campaign ID and exact Cost columns."""
    text = content.decode("utf-8-sig", errors="strict")
    totals: dict[str, float] = {}
    for row in csv.reader(io.StringIO(text), delimiter="\t"):
        if not row or all(not value.strip() for value in row):
            continue
        if len(row) <= AD_REPORT_COST_INDEX:
            raise NaverApiError("Naver 광고효과보고서 형식이 올바르지 않습니다.")
        campaign_id = row[AD_REPORT_CAMPAIGN_ID_INDEX].strip()
        if not campaign_id:
            raise NaverApiError("Naver 광고효과보고서 Campaign ID가 올바르지 않습니다.")
        try:
            cost = float(row[AD_REPORT_COST_INDEX].replace(",", ""))
        except ValueError as error:
            raise NaverApiError("Naver 광고효과보고서 Cost 값이 올바르지 않습니다.") from error
        totals[campaign_id] = totals.get(campaign_id, 0.0) + cost
    rounded = {campaign_id: round(amount) for campaign_id, amount in totals.items()}
    if sum(rounded.values()) != round(sum(totals.values())):
        raise NaverApiError("Naver 캠페인 비용 합계가 계정 비용과 일치하지 않습니다.")
    return rounded


def parse_ad_report_adgroup_costs(content: bytes) -> dict[tuple[str, str], int]:
    """Aggregate official Campaign ID, AD Group ID and exact Cost columns."""
    text = content.decode("utf-8-sig", errors="strict")
    totals: dict[tuple[str, str], float] = {}
    raw_total = 0.0
    for row in csv.reader(io.StringIO(text), delimiter="\t"):
        if not row or all(not value.strip() for value in row):
            continue
        if len(row) <= AD_REPORT_COST_INDEX:
            raise NaverApiError("Naver 광고효과보고서 형식이 올바르지 않습니다.")
        campaign_id = row[AD_REPORT_CAMPAIGN_ID_INDEX].strip()
        adgroup_id = row[AD_REPORT_ADGROUP_ID_INDEX].strip()
        if not campaign_id or not adgroup_id:
            raise NaverApiError("Naver 광고효과보고서 Campaign/AD Group ID가 올바르지 않습니다.")
        try:
            cost = float(row[AD_REPORT_COST_INDEX].replace(",", ""))
        except ValueError as error:
            raise NaverApiError("Naver 광고효과보고서 Cost 값이 올바르지 않습니다.") from error
        key = (campaign_id, adgroup_id)
        totals[key] = totals.get(key, 0.0) + cost
        raw_total += cost
    rounded = {key: round(amount) for key, amount in totals.items()}
    if sum(rounded.values()) != round(raw_total):
        raise NaverApiError("Naver 광고그룹 비용 합계가 계정 비용과 일치하지 않습니다.")
    return rounded

