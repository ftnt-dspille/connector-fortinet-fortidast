"""Copyright start
Copyright (C) 2008 - 2026 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end

HTTP client for the FortiDAST REST API.

Every FortiDAST response is wrapped as ``{"Status": <payload or message
string>}``, and error payloads carry their human-readable text in that same
``Status`` key ("Invalid args", "Api Key expired.", "API Key not found.", ...).
The transport unwraps the envelope and each typed method validates the payload
against its pydantic model (see :mod:`.models`) before returning it, so a
shape change in the API fails loudly here instead of quietly downstream.

Endpoint map (the /v1.0 prefix is part of every path):

  POST /v1.0/cmdb/scan/start                     start_scan(url, uuid, scan_type)
  POST /v1.0/cmdb/scan/stop                      stop_scan(url, uuid)
  POST /v1.0/cmdb/scanconfig/<section>           update_scan_config(section, ...)
  GET  /v1.0/query/allassets?user=               assets(user)
  GET  /v1.0/query/authstatus?url=&uuid=         auth_status(url, uuid)
  GET  /v1.0/query/results?url=&uuid=            results(url, uuid)
  GET  /v1.0/query/scanstatus?url=&uuid=         scan_status(url, uuid)
  GET  /v1.0/query/scansummaryresults            scan_summary(url, uuid)
  GET  /v1.0/query/uriscansummary[/apiresult]    uri_scan_summary(url, uuid, api)
  GET  /v1.0/query/recon_results                 recon_results(url, uuid)
  GET  /v1.0/query/jsonreport                    json_report(url, uuid)
  GET  /v1.0/query/xmlreport                     xml_report(url, uuid)
  GET  /v1.0/query/scanschedule                  scan_schedule(url, uuid)
  POST /v1.0/cmdb/scanconfig/scanschedule        set_scan_schedule(body)
  GET  /v1.0/query/owaspcategorylist             owasp_categories(url, uuid)
  GET  /v1.0/query/{scanresulturl|scanconfigurl|
       cvssseverityurl|owaspcaturl|owaspcatsevrurl}   ui_link(...)

Auth is an API key header (X-API-Key); "basic" keys may only read, "privileged"
keys may also write (start/stop, schedules, configuration)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

import requests
from connectors.core.connector import ConnectorError
from pydantic import BaseModel, ValidationError

from .models import (
    Asset,
    CompletedScan,  # re-exported for operations' convenience
    OwaspCategories,
    ReconResults,
    ScanResults,
    ScanSchedule,
    ScanScheduleRequest,
    ScanStartRequest,
    ScanStatusRow,
    ScanStopRequest,
    ScanSummaryRow,
    SimpleStatus,
    StartScanResponse,
    UiLinkRow,
    UriScanSummaryRow,
    XmlReport,
    parse_epoch,
)

__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT",
    "SCANCONFIG_SECTIONS",
    "CompletedScan",
    "FortiDASTClient",
    "FortiDASTError",
    "parse_epoch",
]

DEFAULT_BASE_URL: str = "https://fortidast.forticloud.com/api"
DEFAULT_TIMEOUT: int = 60

# Sections of POST /v1.0/cmdb/scanconfig/<section>, as the API names them.
SCANCONFIG_SECTIONS: Mapping[str, str] = {
    "authentication": "authentication",
    "coverage": "coverage",
    "exploit_engine": "exploitengine",
    "forced_browsing": "forcedbrowsingconfig",
    "http": "httpconfig",
    "waf": "wafconfig",
}

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class FortiDASTError(ConnectorError):
    """Raised for any FortiDAST API failure (HTTP, auth, shape, or server
    message)."""


def _parse(model_cls: type[_ModelT], payload: Any, path: str) -> _ModelT:
    """Validate an unwrapped response payload against its model."""
    try:
        return model_cls.model_validate(payload)
    except ValidationError as err:
        raise FortiDASTError(f"Unexpected FortiDAST response shape from {path}: {err}") from err


def _parse_list(model_cls: type[_ModelT], payload: Any, path: str) -> list[_ModelT]:
    """Validate a list payload; a bare object is tolerated as a one-element list."""
    rows = payload if isinstance(payload, list) else [payload]
    try:
        return [model_cls.model_validate(row) for row in rows]
    except ValidationError as err:
        raise FortiDASTError(f"Unexpected FortiDAST response shape from {path}: {err}") from err


def _error_text(resp: requests.Response) -> str:
    """Extract the server's message from a FortiDAST error response."""
    try:
        body: Any = resp.json()
    except ValueError:
        body = None
    status = body.get("Status") if isinstance(body, dict) else None
    if isinstance(status, dict):
        status = status.get("status") or status.get("message") or str(status)
    message = status or (resp.text[:300] if resp.text else "")
    detail = {
        401: " (check the API key: expired, revoked, or a basic key used for a write operation)",
        403: " (API key not found or not authorized for this operation)",
    }.get(resp.status_code, "")
    return f"FortiDAST API error (HTTP {resp.status_code}): {message}{detail}"


class FortiDASTClient:
    """Typed transport for the FortiDAST REST API."""

    def __init__(
        self,
        api_key: str,
        base_url: str | None = None,
        verify_ssl: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        if not api_key:
            raise FortiDASTError("API Key is required.")
        self.base_url: str = (base_url or DEFAULT_BASE_URL).strip().rstrip("/")
        if "://" not in self.base_url:
            self.base_url = f"https://{self.base_url}"
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-API-Key": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json; charset=utf-8",
            }
        )
        self.session.verify = bool(verify_ssl)

    # ------------------------------------------------------------------
    # transport
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        params: Mapping[str, Any] | None = None,
        json_body: Any = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.request(
                method,
                url,
                params=params,
                json=json_body,
                timeout=self.timeout,
            )
        except requests.exceptions.SSLError as err:
            raise FortiDASTError(
                f"TLS certificate verification failed for {self.base_url}: {err}. "
                "Disable Verify SSL in the connector configuration for "
                "self-signed deployments."
            ) from err
        except requests.exceptions.ConnectionError as err:
            raise FortiDASTError(
                f"Could not connect to FortiDAST at {self.base_url}: {err}"
            ) from err
        except requests.exceptions.Timeout as err:
            raise FortiDASTError(
                f"FortiDAST request timed out after {self.timeout}s: {err}"
            ) from err
        except requests.exceptions.RequestException as err:
            raise FortiDASTError(f"FortiDAST request failed: {err}") from err
        except Exception as err:
            # Never let a transport-layer surprise escape raw: FortiSOAR shows
            # the ConnectorError message to the analyst.
            raise FortiDASTError(f"Unexpected error calling FortiDAST: {err}") from err

        if resp.status_code >= 400:
            raise FortiDASTError(_error_text(resp))
        try:
            body = resp.json()
        except ValueError as err:
            raise FortiDASTError(
                f"FortiDAST returned a non-JSON response (HTTP {resp.status_code}) from {path}"
            ) from err
        # Every documented response wraps its payload in "Status"; be lenient
        # with servers that omit the wrapper so callers always see the payload.
        if isinstance(body, dict) and set(body.keys()) == {"Status"}:
            return body["Status"]
        return body

    def get(self, path: str, params: Mapping[str, Any] | None = None) -> Any:
        """Raw GET, envelope unwrapped; prefer the typed methods."""
        return self._request("GET", path, params=params)

    def post(
        self,
        path: str,
        json_body: Any = None,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        """Raw POST, envelope unwrapped; prefer the typed methods."""
        return self._request("POST", path, params=params, json_body=json_body)

    # ------------------------------------------------------------------
    # cmdb (write) endpoints -- privileged key required
    # ------------------------------------------------------------------

    def start_scan(
        self,
        url: str,
        uuid: str,
        scan_type: int = 1,
    ) -> StartScanResponse:
        body = ScanStartRequest(url=url, uuid=uuid, scan_type=scan_type)
        return _parse(
            StartScanResponse,
            self.post("/v1.0/cmdb/scan/start", json_body=body.model_dump(exclude_none=True)),
            "/v1.0/cmdb/scan/start",
        )

    def stop_scan(self, url: str, uuid: str) -> SimpleStatus:
        body = ScanStopRequest(url=url, uuid=uuid)
        return _parse(
            SimpleStatus,
            self.post("/v1.0/cmdb/scan/stop", json_body=body.model_dump(exclude_none=True)),
            "/v1.0/cmdb/scan/stop",
        )

    def set_scan_schedule(self, body: ScanScheduleRequest) -> SimpleStatus:
        return _parse(
            SimpleStatus,
            self.post(
                "/v1.0/cmdb/scanconfig/scanschedule", json_body=body.model_dump(exclude_none=True)
            ),
            "/v1.0/cmdb/scanconfig/scanschedule",
        )

    def update_scan_config(
        self,
        section: str,
        url: str,
        uuid: str,
        config: Mapping[str, Any],
    ) -> SimpleStatus:
        api_section = SCANCONFIG_SECTIONS.get(section)
        if not api_section:
            raise FortiDASTError(
                f"Unknown scan config section {section!r}. Expected one of: "
                f"{', '.join(sorted(SCANCONFIG_SECTIONS))}."
            )
        body: dict[str, Any] = dict(config)
        body.setdefault("url", url)
        body.setdefault("uuid", uuid)
        return _parse(
            SimpleStatus,
            self.post(f"/v1.0/cmdb/scanconfig/{api_section}", json_body=body),
            f"/v1.0/cmdb/scanconfig/{api_section}",
        )

    # ------------------------------------------------------------------
    # query (read) endpoints -- basic key suffices
    # ------------------------------------------------------------------

    def assets(self, user: str) -> list[Asset]:
        return _parse_list(
            Asset, self.get("/v1.0/query/allassets", params={"user": user}), "/v1.0/query/allassets"
        )

    def scan_status(self, url: str, uuid: str) -> list[ScanStatusRow]:
        return _parse_list(
            ScanStatusRow,
            self.get("/v1.0/query/scanstatus", params={"url": url, "uuid": uuid}),
            "/v1.0/query/scanstatus",
        )

    def auth_status(self, url: str, uuid: str) -> list[ScanStatusRow]:
        return _parse_list(
            ScanStatusRow,
            self.get("/v1.0/query/authstatus", params={"url": url, "uuid": uuid}),
            "/v1.0/query/authstatus",
        )

    def results(self, url: str, uuid: str) -> ScanResults:
        return _parse(
            ScanResults,
            self.get("/v1.0/query/results", params={"url": url, "uuid": uuid}),
            "/v1.0/query/results",
        )

    def scan_summary(self, url: str, uuid: str) -> list[ScanSummaryRow]:
        return _parse_list(
            ScanSummaryRow,
            self.get("/v1.0/query/scansummaryresults", params={"url": url, "uuid": uuid}),
            "/v1.0/query/scansummaryresults",
        )

    def uri_scan_summary(
        self,
        url: str,
        uuid: str,
        api: bool = False,
    ) -> list[UriScanSummaryRow]:
        path = "/v1.0/query/uriscansummary/apiresult" if api else "/v1.0/query/uriscansummary"
        return _parse_list(
            UriScanSummaryRow, self.get(path, params={"url": url, "uuid": uuid}), path
        )

    def recon_results(self, url: str, uuid: str) -> ReconResults:
        return _parse(
            ReconResults,
            self.get("/v1.0/query/recon_results", params={"url": url, "uuid": uuid}),
            "/v1.0/query/recon_results",
        )

    def json_report(self, url: str, uuid: str) -> dict[str, Any]:
        payload = self.get("/v1.0/query/jsonreport", params={"url": url, "uuid": uuid})
        if not isinstance(payload, dict):
            raise FortiDASTError(
                "Unexpected FortiDAST response shape from /v1.0/query/jsonreport: "
                "expected a JSON object report."
            )
        return payload

    def xml_report(self, url: str, uuid: str) -> XmlReport:
        return _parse(
            XmlReport,
            self.get("/v1.0/query/xmlreport", params={"url": url, "uuid": uuid}),
            "/v1.0/query/xmlreport",
        )

    def scan_schedule(self, url: str, uuid: str) -> ScanSchedule:
        return _parse(
            ScanSchedule,
            self.get("/v1.0/query/scanschedule", params={"url": url, "uuid": uuid}),
            "/v1.0/query/scanschedule",
        )

    def owasp_categories(self, url: str, uuid: str) -> OwaspCategories:
        return _parse(
            OwaspCategories,
            self.get("/v1.0/query/owaspcategorylist", params={"url": url, "uuid": uuid}),
            "/v1.0/query/owaspcategorylist",
        )

    # UI link generators: scanresulturl / scanconfigurl / cvssseverityurl /
    # owaspcaturl / owaspcatsevrurl. Each returns a one-key row; url_for()
    # picks the key for the requested link type.
    def ui_link(
        self,
        url: str,
        uuid: str,
        link_type: str,
        severity: str | None = None,
        category: str | None = None,
    ) -> UiLinkRow:
        endpoints: Mapping[str, tuple[str, bool]] = {
            "scan_result": ("scanresulturl", False),
            "scan_config": ("scanconfigurl", False),
            "cvss_severity": ("cvssseverityurl", True),
            "owasp_category": ("owaspcaturl", True),
            "owasp_severity": ("owaspcatsevrurl", True),
        }
        entry = endpoints.get(link_type)
        if entry is None:
            raise FortiDASTError(
                f"Unknown link_type {link_type!r}. Expected one of: {', '.join(sorted(endpoints))}."
            )
        endpoint, wants_severity = entry
        params: dict[str, str] = {"url": url, "uuid": uuid}
        if wants_severity:
            if not severity:
                raise FortiDASTError(f"Severity is required for the {link_type!r} link type.")
            params["severity"] = severity
            if link_type == "owasp_severity":
                if not category:
                    raise FortiDASTError(f"Category is required for the {link_type!r} link type.")
                params["category"] = category
        return _parse(
            UiLinkRow, self.get(f"/v1.0/query/{endpoint}", params=params), f"/v1.0/query/{endpoint}"
        )

    # ------------------------------------------------------------------
    # health
    # ------------------------------------------------------------------

    def healthcheck(self) -> bool:
        """Cheap authenticated canary.

        GET allassets without its required ``user`` parameter: a working key
        gets past authentication and the server answers 400 "Invalid args"; a
        bad or expired key answers 401/403 with the key error. Anything else
        is a connectivity or license problem.
        """
        url = f"{self.base_url}/v1.0/query/allassets"
        try:
            resp = self.session.get(url, timeout=self.timeout)
        except requests.exceptions.RequestException as err:
            raise FortiDASTError(f"Could not reach FortiDAST at {self.base_url}: {err}") from err
        if resp.status_code in (200, 400, 405):
            return True
        raise FortiDASTError(_error_text(resp))
