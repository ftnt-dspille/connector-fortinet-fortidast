# -*- coding: utf-8 -*-
""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

"""FortiDAST connector operations.

Thin FortiSOAR-shaped wrappers over lib/fortidast/client.py: translate the
connector config and operation params into client calls, unwrap the API's
"Status" envelope (the client already does), and add the small amount of
shaping the ingestion op needs (severity rollup, epoch timestamps, summary
text). No business logic lives here.
"""

from connectors.core.connector import ConnectorError, get_logger

from .lib.fortidast.client import (
    FortiDASTClient,
    FortiDASTError,
    max_severity,
    parse_epoch,
    severity_counts,
)

logger = get_logger("fortinet-fortidast")

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

_SCAN_TYPE_MAP = {"Quick Scan": 0, "Full Scan": 1}


def _client(config):
    return FortiDASTClient(
        api_key=(config.get("api_key") or "").strip(),
        base_url=(config.get("base_url") or "").strip() or None,
        verify_ssl=config.get("verify_ssl", True),
    )


def _require(params, *names):
    """Return cleaned values for required params, raising on the first miss."""
    out = []
    for name in names:
        value = (params or {}).get(name)
        if value is None or str(value).strip() == "":
            raise ConnectorError(
                "The '{0}' parameter is required.".format(name))
        out.append(str(value).strip())
    return out


def _as_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if value in (None, ""):
        return default
    return str(value).strip().lower() in ("true", "1", "yes", "y")


# ---------------------------------------------------------------------------
# scans (write)
# ---------------------------------------------------------------------------

def start_scan(config, params):
    """Start a scan for an asset. scan_type: Quick Scan=0, Full Scan=1."""
    url, uuid = _require(params, "url", "uuid")
    scan_type = _SCAN_TYPE_MAP.get(params.get("scan_type") or "Full Scan", 1)
    return _client(config).start_scan(url, uuid, scan_type=scan_type)


def stop_scan(config, params):
    """Stop the running scan for an asset."""
    url, uuid = _require(params, "url", "uuid")
    return _client(config).stop_scan(url, uuid)


def set_scan_schedule(config, params):
    """Create or update the scheduled scan for an asset."""
    url, uuid = _require(params, "url", "uuid")
    body = {
        "url": url,
        "uuid": uuid,
        "enable": _as_bool(params.get("enable"), True),
    }
    for key in ("scandate", "scantime", "frequency", "interval"):
        value = (params or {}).get(key)
        if value not in (None, ""):
            body[key] = value
    return _client(config).set_scan_schedule(body)


def update_scan_config(config, params):
    """Update one scan configuration tab for an asset.

    `config` is a JSON object string or dict with the tab's fields; the
    client injects url/uuid unless the caller already provided them.
    """
    url, uuid = _require(params, "url", "uuid")
    section = (params or {}).get("section")
    raw = (params or {}).get("config")
    if isinstance(raw, str) and raw.strip():
        import json as _json
        try:
            config_dict = _json.loads(raw)
        except ValueError as e:
            raise ConnectorError(
                "Config must be a valid JSON object: {0}".format(e))
    elif isinstance(raw, dict):
        config_dict = raw
    else:
        raise ConnectorError(
            "The 'config' parameter is required and must be a JSON object.")
    if not isinstance(config_dict, dict):
        raise ConnectorError("Config must be a JSON object.")
    try:
        return _client(config).update_scan_config(section, url, uuid, config_dict)
    except FortiDASTError as e:
        raise ConnectorError(str(e))


# ---------------------------------------------------------------------------
# queries (read)
# ---------------------------------------------------------------------------

def get_assets(config, params):
    """List all assets (scan URLs) for a FortiDAST user."""
    (user,) = _require(params, "user")
    return _client(config).assets(user)


def get_scan_status(config, params):
    """Scan status rows for an asset (state, times, owner, threat level)."""
    url, uuid = _require(params, "url", "uuid")
    return _client(config).scan_status(url, uuid)


def get_auth_status(config, params):
    """Per-asset scan status with authentication state."""
    url, uuid = _require(params, "url", "uuid")
    return _client(config).auth_status(url, uuid)


def get_scan_results(config, params):
    """Findings for an asset's scan: severity, CVSS, CWE, FortiGuard id,
    payload, impact and remediation."""
    url, uuid = _require(params, "url", "uuid")
    return _client(config).results(url, uuid)


def get_scan_summary(config, params):
    """Per-vulnerability-type severity counts for an asset's scan."""
    url, uuid = _require(params, "url", "uuid")
    return _client(config).scan_summary(url, uuid)


def get_uri_scan_summary(config, params):
    """Per-URI scan timing and severity counts (api=True for REST API scans)."""
    url, uuid = _require(params, "url", "uuid")
    api = _as_bool((params or {}).get("summary_type") == "api", False)
    return _client(config).uri_scan_summary(url, uuid, api=api)


def get_recon_results(config, params):
    """Reconnaissance data for an asset: technologies and fingerprinting."""
    url, uuid = _require(params, "url", "uuid")
    return _client(config).recon_results(url, uuid)


def get_json_report(config, params):
    """Full JSON scan report, organized by vulnerability type and CVSS score."""
    url, uuid = _require(params, "url", "uuid")
    return _client(config).json_report(url, uuid)


def get_xml_report(config, params):
    """Raw XML scan report as a string."""
    url, uuid = _require(params, "url", "uuid")
    return _client(config).xml_report(url, uuid)


def get_scan_schedule(config, params):
    """Scheduled scan configuration for an asset."""
    url, uuid = _require(params, "url", "uuid")
    return _client(config).scan_schedule(url, uuid)


def get_owasp_categories(config, params):
    """OWASP category list FortiDAST scans for."""
    url, uuid = _require(params, "url", "uuid")
    return _client(config).owasp_categories(url, uuid)


def get_ui_link(config, params):
    """FortiDAST console URL fragment for an asset's results or configuration."""
    url, uuid = _require(params, "url", "uuid")
    link_type = (params or {}).get("link_type")
    return _client(config).ui_link(
        url, uuid, link_type,
        severity=(params or {}).get("severity") or None,
        category=(params or {}).get("category") or None,
    )


# ---------------------------------------------------------------------------
# ingestion source
# ---------------------------------------------------------------------------

def get_completed_scans(config, params):
    """Enumerate a user's assets and return the ones whose scan is complete.

    One record per asset: scan metadata, a severity rollup over its findings,
    a plain-text summary for the alert description, and (when include_findings
    is on) the findings themselves. Records carry `detected_ts` (epoch from
    the scan timestamp) so playbooks can map it to alertDetectionDate, and the
    asset uuid doubles as the alert sourceId so re-runs upsert instead of
    duplicating.
    """
    (user,) = _require(params, "user")
    include_findings = _as_bool((params or {}).get("include_findings"), True)
    try:
        max_scans = int((params or {}).get("max_scans") or 100)
    except (TypeError, ValueError):
        max_scans = 100
    max_scans = max(1, max_scans)

    client = _client(config)
    try:
        assets = client.assets(user) or []
    except FortiDASTError as e:
        raise ConnectorError(str(e))
    if not isinstance(assets, list):
        logger.warning("allassets returned a non-list payload: %r", type(assets))
        assets = []

    scans = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        asset_url = asset.get("asset_name")
        asset_uuid = asset.get("uuid")
        if not asset_url or not asset_uuid:
            continue
        try:
            rows = client.scan_status(asset_url, asset_uuid) or []
        except FortiDASTError as e:
            logger.warning("scanstatus failed for %s: %s", asset_url, e)
            continue
        if isinstance(rows, dict):
            rows = [rows]
        for row in rows:
            if not isinstance(row, dict):
                continue
            if str(row.get("scan_status", "")).strip().lower() != "scan complete":
                continue
            scan = dict(row)
            scan.setdefault("asset_name", asset_url)
            scan.setdefault("uuid", asset_uuid)
            scan["detected_ts"] = parse_epoch(
                row.get("scan_at") or row.get("scan_started_at")
                or row.get("created_at"))
            scan["findings"] = []
            scan["result_count"] = 0
            scan["max_severity"] = None
            scan["summary_text"] = "Scan completed with no findings recorded."
            scan["vulnhash_url"] = ""
            scans.append(scan)

    scans.sort(key=lambda s: s.get("detected_ts") or 0)
    if len(scans) > max_scans:
        logger.info("get_completed_scans: %d completed scans, capped at %d",
                    len(scans), max_scans)
        scans = scans[:max_scans]

    if include_findings:
        for scan in scans:
            try:
                payload = client.results(scan["asset_name"], scan["uuid"]) or {}
            except FortiDASTError as e:
                logger.warning("results failed for %s: %s", scan["asset_name"], e)
                continue
            findings = payload.get("results") if isinstance(payload, dict) else None
            findings = findings if isinstance(findings, list) else []
            scan["findings"] = findings
            scan["result_count"] = len(findings)
            scan["max_severity"] = max_severity(findings)
            scan["vulnhash_url"] = payload.get("vulnhash_url", "") \
                if isinstance(payload, dict) else ""
            scan["summary_text"] = _summary_text(scan)

    for scan in scans:
        if not scan.get("summary_text"):
            scan["summary_text"] = _summary_text(scan)
    return scans


def _summary_text(scan):
    """Plain-text scan summary for the alert description field."""
    counts = severity_counts(scan.get("findings"))
    parts = ["{0}: {1}".format(level, counts[level])
             for level in SEVERITY_ORDER if counts.get(level)]
    heading = "FortiDAST scan of {0} completed".format(scan.get("asset_name", ""))
    if not parts:
        return "{0}. No findings recorded.".format(heading)
    return "{0}. Findings by severity: {1}.".format(heading, ", ".join(parts))


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------

def _check_health(config):
    try:
        _client(config).healthcheck()
        return True
    except FortiDASTError as e:
        raise ConnectorError(str(e))


operations = {
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
