"""Copyright start
Copyright (C) 2008 - 2026 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end

FortiDAST connector operations.

Thin FortiSOAR-shaped wrappers over :mod:`.lib.fortidast.client`: validate the
connector config and the operation parameters through pydantic, call the typed
client methods, and return JSON-serializable payloads (``model_dump``) shaped
to match info.json's output schemas. No business logic lives here."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, TypeAlias

from connectors.core.connector import ConnectorError, get_logger

from .lib.fortidast.client import FortiDASTClient, FortiDASTError
from .lib.fortidast.models import (
    Asset,
    AssetParams,
    AssetRefParams,
    CompletedScan,
    CompletedScansParams,
    Finding,
    ScanResults,
    ScanSchedule,
    ScanScheduleRequest,
    ScanStatusRow,
    SetScanScheduleParams,
    SimpleStatus,
    StartScanParams,
    StartScanResponse,
    UiLinkParams,
    UiLinkRow,
    UpdateScanConfigParams,
    UriScanSummaryParams,
    XmlReport,
)

logger = get_logger("fortinet-fortidast")

#: What FortiSOAR hands an operation: the connector configuration and the
#: operation params (both dicts, values usually strings).
ConnectorConfig: TypeAlias = Mapping[str, Any]
OperationParams: TypeAlias = Mapping[str, Any]
OpHandler: TypeAlias = Callable[[ConnectorConfig, OperationParams | None], Any]


class FortiDASTConfigError(ConnectorError):
    """Raised when the connector configuration is missing required fields."""


def _client(config: ConnectorConfig) -> FortiDASTClient:
    """Build a client from the connector configuration."""
    api_key = str(config.get("api_key") or "").strip()
    if not api_key:
        raise FortiDASTConfigError("The 'API Key' configuration field is required.")
    base_url = str(config.get("base_url") or "").strip() or None
    verify_ssl = config.get("verify_ssl", True)
    if isinstance(verify_ssl, str):
        verify_ssl = verify_ssl.strip().lower() not in ("false", "0", "no")
    return FortiDASTClient(api_key=api_key, base_url=base_url, verify_ssl=bool(verify_ssl))


def _params(params_cls: type, params: OperationParams | None) -> Any:
    """Validate operation params through their pydantic model, mapping
    validation failures onto ConnectorError (FortiSOAR shows the message)."""
    try:
        return params_cls.model_validate(dict(params or {}))
    except Exception as err:  # pydantic.ValidationError, or a ValueError raised by a validator
        raise ConnectorError(f"Invalid operation parameters: {err}") from err


# ---------------------------------------------------------------------------
# scans (write)
# ---------------------------------------------------------------------------


def start_scan(config: ConnectorConfig, params: OperationParams | None) -> dict[str, Any]:
    """Start a scan for an asset. scan_type: Quick Scan=0, Full Scan=1."""
    p = _params(StartScanParams, params)
    try:
        result: StartScanResponse = _client(config).start_scan(
            p.url, p.uuid, scan_type=p.scan_type_value
        )
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err
    return result.model_dump(mode="json")


def stop_scan(config: ConnectorConfig, params: OperationParams | None) -> dict[str, Any]:
    """Stop the running scan for an asset."""
    p = _params(AssetRefParams, params)
    try:
        result: SimpleStatus = _client(config).stop_scan(p.url, p.uuid)
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err
    return result.model_dump(mode="json")


def set_scan_schedule(config: ConnectorConfig, params: OperationParams | None) -> dict[str, Any]:
    """Create or update the scheduled scan for an asset."""
    p = _params(SetScanScheduleParams, params)
    body = ScanScheduleRequest(
        url=p.url,
        uuid=p.uuid,
        enable=p.enable,
        scandate=p.scandate,
        scantime=p.scantime,
        frequency=p.frequency,
        interval=p.interval,
    )
    try:
        result: SimpleStatus = _client(config).set_scan_schedule(body)
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err
    return result.model_dump(mode="json")


def update_scan_config(config: ConnectorConfig, params: OperationParams | None) -> dict[str, Any]:
    """Update one scan configuration tab for an asset.

    ``config`` arrives as a JSON object string (or an already-parsed dict) and
    is validated by the params model; the client injects url/uuid unless the
    caller already provided them.
    """
    p = _params(UpdateScanConfigParams, params)
    try:
        result: SimpleStatus = _client(config).update_scan_config(
            p.section, p.url, p.uuid, p.config
        )
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err
    return result.model_dump(mode="json")


# ---------------------------------------------------------------------------
# queries (read)
# ---------------------------------------------------------------------------


def get_assets(config: ConnectorConfig, params: OperationParams | None) -> list[dict[str, Any]]:
    """List all assets (scan URLs) for a FortiDAST user."""
    p = _params(AssetParams, params)
    try:
        assets: list[Asset] = _client(config).assets(p.user)
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err
    return [asset.model_dump(mode="json", exclude_none=True) for asset in assets]


def get_scan_status(
    config: ConnectorConfig, params: OperationParams | None
) -> list[dict[str, Any]]:
    """Scan status rows for an asset (state, times, owner, threat level)."""
    p = _params(AssetRefParams, params)
    try:
        rows: list[ScanStatusRow] = _client(config).scan_status(p.url, p.uuid)
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err
    return [row.model_dump(mode="json", exclude_none=True) for row in rows]


def get_auth_status(
    config: ConnectorConfig, params: OperationParams | None
) -> list[dict[str, Any]]:
    """Per-asset scan status with authentication state."""
    p = _params(AssetRefParams, params)
    try:
        rows: list[ScanStatusRow] = _client(config).auth_status(p.url, p.uuid)
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err
    return [row.model_dump(mode="json", exclude_none=True) for row in rows]


def get_scan_results(config: ConnectorConfig, params: OperationParams | None) -> dict[str, Any]:
    """Findings for an asset's scan: severity, CVSS, CWE, FortiGuard id,
    payload, impact and remediation."""
    p = _params(AssetRefParams, params)
    try:
        results: ScanResults = _client(config).results(p.url, p.uuid)
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err
    return results.model_dump(mode="json", exclude_none=True)


def get_scan_summary(
    config: ConnectorConfig, params: OperationParams | None
) -> list[dict[str, Any]]:
    """Per-vulnerability-type severity counts for an asset's scan."""
    p = _params(AssetRefParams, params)
    try:
        rows = _client(config).scan_summary(p.url, p.uuid)
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err
    return [row.model_dump(mode="json", exclude_none=True) for row in rows]


def get_uri_scan_summary(
    config: ConnectorConfig, params: OperationParams | None
) -> list[dict[str, Any]]:
    """Per-URI scan timing and severity counts (api=True for REST API scans)."""
    p = _params(UriScanSummaryParams, params)
    try:
        rows = _client(config).uri_scan_summary(p.url, p.uuid, api=(p.summary_type == "api"))
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err
    return [row.model_dump(mode="json", exclude_none=True) for row in rows]


def get_recon_results(config: ConnectorConfig, params: OperationParams | None) -> dict[str, Any]:
    """Reconnaissance data for an asset: technologies and fingerprinting."""
    p = _params(AssetRefParams, params)
    try:
        results = _client(config).recon_results(p.url, p.uuid)
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err
    return results.model_dump(mode="json", exclude_none=True)


def get_json_report(config: ConnectorConfig, params: OperationParams | None) -> dict[str, Any]:
    """Full JSON scan report, organized by vulnerability type and CVSS score."""
    p = _params(AssetRefParams, params)
    try:
        return _client(config).json_report(p.url, p.uuid)
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err


def get_xml_report(config: ConnectorConfig, params: OperationParams | None) -> dict[str, Any]:
    """Raw XML scan report as a string."""
    p = _params(AssetRefParams, params)
    try:
        report: XmlReport = _client(config).xml_report(p.url, p.uuid)
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err
    return report.model_dump(mode="json", exclude_none=True)


def get_scan_schedule(config: ConnectorConfig, params: OperationParams | None) -> dict[str, Any]:
    """Scheduled scan configuration for an asset."""
    p = _params(AssetRefParams, params)
    try:
        schedule: ScanSchedule = _client(config).scan_schedule(p.url, p.uuid)
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err
    return schedule.model_dump(mode="json", exclude_none=True)


def get_owasp_categories(config: ConnectorConfig, params: OperationParams | None) -> dict[str, Any]:
    """OWASP category list FortiDAST scans for."""
    p = _params(AssetRefParams, params)
    try:
        categories = _client(config).owasp_categories(p.url, p.uuid)
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err
    return categories.model_dump(mode="json", exclude_none=True)


def get_ui_link(config: ConnectorConfig, params: OperationParams | None) -> dict[str, Any]:
    """FortiDAST console URL fragment for an asset's results or configuration."""
    p = _params(UiLinkParams, params)
    try:
        row: UiLinkRow = _client(config).ui_link(
            p.url, p.uuid, p.link_type, severity=p.severity, category=p.category
        )
        return {"url": row.url_for(p.link_type)}
    except (FortiDASTError, ValueError) as err:
        raise ConnectorError(str(err)) from err


# ---------------------------------------------------------------------------
# ingestion source
# ---------------------------------------------------------------------------


def get_completed_scans(
    config: ConnectorConfig, params: OperationParams | None
) -> list[dict[str, Any]]:
    """Enumerate a user's assets and return the ones whose scan is complete.

    One record per asset: scan metadata, a severity rollup over its findings,
    a plain-text summary for the alert description, and (when include_findings
    is on) the findings themselves. Records carry ``detected_ts`` (epoch from
    the scan timestamp) so playbooks can map it to alertDetectionDate, and the
    asset uuid doubles as the alert sourceId so re-runs upsert instead of
    duplicating.
    """
    p = _params(CompletedScansParams, params)
    client = _client(config)
    try:
        assets: list[Asset] = client.assets(p.user)
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err

    scans: list[CompletedScan] = []
    for asset in assets:
        try:
            rows: list[ScanStatusRow] = client.scan_status(asset.asset_name, asset.uuid)
        except FortiDASTError as err:
            logger.warning("scanstatus failed for %s: %s", asset.asset_name, err)
            continue
        for row in rows:
            if (row.scan_status or "").strip().lower() != "scan complete":
                continue
            findings: list[Finding] = []
            vulnhash_url = ""
            if p.include_findings:
                try:
                    results: ScanResults = client.results(asset.asset_name, asset.uuid)
                    findings = results.results
                    vulnhash_url = results.vulnhash_url or ""
                except FortiDASTError as err:
                    logger.warning("results failed for %s: %s", asset.asset_name, err)
            scans.append(CompletedScan.from_row(row, asset, findings, vulnhash_url))

    scans.sort(key=lambda scan: scan.detected_ts or 0)
    if len(scans) > p.max_scans:
        logger.info(
            "get_completed_scans: %d completed scans, capped at %d", len(scans), p.max_scans
        )
        scans = scans[: p.max_scans]
    return [scan.model_dump(mode="json") for scan in scans]


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------


def _check_health(config: ConnectorConfig) -> bool:
    try:
        return _client(config).healthcheck()
    except FortiDASTError as err:
        raise ConnectorError(str(err)) from err


operations: dict[str, OpHandler] = {
    "start_scan": start_scan,
    "stop_scan": stop_scan,
    "get_assets": get_assets,
    "get_scan_status": get_scan_status,
    "get_auth_status": get_auth_status,
    "get_scan_results": get_scan_results,
    "get_scan_summary": get_scan_summary,
    "get_uri_scan_summary": get_uri_scan_summary,
    "get_recon_results": get_recon_results,
    "get_json_report": get_json_report,
    "get_xml_report": get_xml_report,
    "get_scan_schedule": get_scan_schedule,
    "set_scan_schedule": set_scan_schedule,
    "update_scan_config": update_scan_config,
    "get_owasp_categories": get_owasp_categories,
    "get_ui_link": get_ui_link,
    "get_completed_scans": get_completed_scans,
}
