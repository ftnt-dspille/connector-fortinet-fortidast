"""Copyright start
Copyright (C) 2008 - 2026 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end

Pydantic models for the FortiDAST REST API.

Response models document the shape each endpoint returns and validate it on
arrival; input models validate the operation parameters FortiSOAR hands the
connector (which arrive as strings, often as empty strings for "unset").

FortiDAST payloads are sloppy in documented ways, so the base model is
deliberately lenient:

- unknown keys are kept (``extra="allow"``) -- the ingestion chain stores the
  raw scan row in the alert's sourcedata, so extras must survive;
- whitespace is stripped;
- everything the spec shows as nullable-or-absent in practice is optional;
- timestamps are kept as raw strings (the API has been seen emitting lowercase
  ``t``/``z`` -- see :func:`parse_epoch`), never reshaped into something the
  API did not send."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, Any, ClassVar, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

#: Strongest-first severity ladder used for rollups. "None" (FortiDAST's
#: no-severity spelling) canonicalizes to "Informational".
SEVERITY_ORDER: tuple[str, ...] = ("Critical", "High", "Medium", "Low", "Informational")

SEVERITY_CANON: Mapping[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "low": "Low",
    "informational": "Informational",
    "info": "Informational",
    "none": "Informational",
}

ScanType = Literal["Quick Scan", "Full Scan"]
ScanConfigSection = Literal[
    "authentication",
    "coverage",
    "exploit_engine",
    "forced_browsing",
    "http",
    "waf",
]
UiLinkType = Literal[
    "scan_result",
    "scan_config",
    "cvss_severity",
    "owasp_category",
    "owasp_severity",
]
ScheduleFrequency = Literal["O", "W", "M"]


def _empty_to_none(value: Any) -> Any:
    """FortiSOAR sends unset optional params as empty strings; treat them as
    absent so field defaults apply."""
    if isinstance(value, str) and not value.strip():
        return None
    return value


def _truthy(value: Any) -> Any:
    """Accept the spellings a FortiSOAR select/checkbox can deliver for bools."""
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "y")
    return value


def _epoch_or_none(value: Any) -> Any:
    """An empty/blank watermark means "no filter", not a coercion error."""
    if isinstance(value, str) and not value.strip():
        return None
    return value


def _none_to_list(value: Any) -> Any:
    """Tolerate a null where the spec promises a list."""
    return value if isinstance(value, list) else []


def parse_epoch(value: Any) -> int | None:
    """Best-effort ISO-8601 -> epoch seconds.

    FortiDAST timestamps have been seen with lowercase ``t``/``z``
    ("2021-06-03t14:21:29.811522z"), which ``datetime.fromisoformat`` rejects
    before 3.11, so normalize first. Returns None when the value is missing or
    unparseable.
    """
    if not value:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    try:
        normalized = text.replace("t", "T", 1).replace("z", "Z")
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        return int(datetime.fromisoformat(normalized).timestamp())
    except (ValueError, OverflowError):
        return None


# ---------------------------------------------------------------------------
# bases
# ---------------------------------------------------------------------------


class _Sloppy(BaseModel):
    """Base for API payloads: keep unknown keys, strip whitespace."""

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)


class _Params(BaseModel):
    """Base for operation parameters.

    FortiSOAR delivers unset optionals as empty strings; those keys are
    dropped before validation so field defaults apply, while a dropped
    required field surfaces as a proper "Field required" error naming it.
    """

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    @model_validator(mode="before")
    @classmethod
    def _drop_unset(cls, data: Any) -> Any:
        if isinstance(data, Mapping):
            return {k: v for k, v in data.items() if not (isinstance(v, str) and not v.strip())}
        return data


# ---------------------------------------------------------------------------
# request bodies (what we send)
# ---------------------------------------------------------------------------


class ScanStartRequest(_Sloppy):
    """POST /v1.0/cmdb/scan/start body."""

    url: str
    uuid: str
    scan_type: int = 1  # Quick Scan=0, Full Scan=1


class ScanStopRequest(_Sloppy):
    """POST /v1.0/cmdb/scan/stop body."""

    url: str
    uuid: str


class ScanScheduleRequest(_Sloppy):
    """POST /v1.0/cmdb/scanconfig/scanschedule body."""

    url: str
    uuid: str
    enable: bool = True
    scandate: str | None = None  # YYYY-MM-DD
    scantime: str | None = None  # HH:MM:SS
    frequency: ScheduleFrequency | None = None  # O=once, W=weekly, M=monthly
    interval: int | None = None  # weekly: 1-7 (Sunday-Saturday)


# ---------------------------------------------------------------------------
# operation parameters (what FortiSOAR sends us)
# ---------------------------------------------------------------------------


class StartScanParams(_Params):
    url: str
    uuid: str
    scan_type: ScanType = "Full Scan"

    @property
    def scan_type_value(self) -> int:
        """The wire value: Quick Scan=0, Full Scan=1."""
        return 0 if self.scan_type == "Quick Scan" else 1


class AssetParams(_Params):
    user: str


class AssetRefParams(_Params):
    """url + uuid, the two parameters every per-asset operation takes."""

    url: str
    uuid: str


class UriScanSummaryParams(AssetRefParams):
    summary_type: Literal["uri", "api"] = "uri"


class SetScanScheduleParams(AssetRefParams):
    enable: Annotated[bool, BeforeValidator(_truthy)] = True
    scandate: str | None = None
    scantime: str | None = None
    frequency: ScheduleFrequency | None = None
    interval: int | None = None


class UpdateScanConfigParams(AssetRefParams):
    section: ScanConfigSection
    config: str | dict[str, Any]

    @field_validator("config", mode="before")
    @classmethod
    def _parse_config(cls, value: Any) -> Any:
        if isinstance(value, str) and value.strip():
            import json

            try:
                return json.loads(value)
            except ValueError as e:
                raise ValueError(f"Config must be a valid JSON object: {e}") from e
        return value

    @field_validator("config")
    @classmethod
    def _config_is_object(cls, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("Config must be a JSON object.")
        return value


class UiLinkParams(AssetRefParams):
    link_type: UiLinkType
    severity: str | None = None
    category: str | None = None


class CompletedScansParams(_Params):
    user: str
    include_findings: Annotated[bool, BeforeValidator(_truthy)] = True
    max_scans: int = Field(default=100, ge=1)
    since_epoch: Annotated[int | None, BeforeValidator(_epoch_or_none)] = None
    """Only scans whose completion timestamp is at or after this epoch second
    are returned; the ingestion watermark writes it. Findings are fetched only
    for the scans that survive the filter, so an old watermark bounds the API
    load too."""


# ---------------------------------------------------------------------------
# response payloads (what the API sends back)
# ---------------------------------------------------------------------------


class StartScanResponse(_Sloppy):
    """ScanStartSuccessResponse | ActiveScanResponse."""

    status: str
    complete: int | None = None


class SimpleStatus(_Sloppy):
    """Stop scan, schedule set, and scanconfig tab updates."""

    status: str
    statuscode: int | None = None


class Asset(_Sloppy):
    asset_name: str
    uuid: str


class ScanStatusRow(_Sloppy):
    asset_name: str | None = None
    uuid: str | None = None
    created_at: str | None = None
    scan_owner: str | None = None
    scan_started_at: str | None = None
    scan_at: str | None = None
    scan_status: str | None = None
    threat_level: float | None = None
    scan_type: int | None = None


class Finding(_Sloppy):
    uuid: str | None = None
    url: str | None = None
    vulnerabilitytype: str | None = None
    severity: str | None = None
    scanstarttime: str | None = None
    scanendtime: str | None = None
    cvssscore: float | None = None
    cvssvector: str | None = None
    cweid: int | None = None
    fortiguard_id: int | None = None
    payload: list[Any] | None = None
    scanstatus: str | None = None
    vulnerabilitydescription: str | None = None
    impact: str | None = None
    remediation: str | None = None


class ScanResults(_Sloppy):
    """GET /v1.0/query/results."""

    vulnhash_url: str | None = None
    results: Annotated[list[Finding], BeforeValidator(_none_to_list)] = Field(default_factory=list)


class ScanSummaryRow(_Sloppy):
    """GET /v1.0/query/scansummaryresults row."""

    vulnerabilitytype: str | None = None
    severitycount: dict[str, str | int | float] | None = None
    categortyenabled: bool | None = None


class UriScanSummaryRow(_Sloppy):
    """GET /v1.0/query/uriscansummary[/apiresult] row."""

    uri: str | None = None
    severitycount: list[int] | None = None
    starttime: str | None = None
    endtime: str | None = None
    fuzztype: list[str] | None = None
    fuzzererror: list[int] | None = None


class ReconResults(_Sloppy):
    """GET /v1.0/query/recon_results."""

    status: str | None = None
    recon_data: dict[str, Any] | None = None


class XmlReport(_Sloppy):
    """GET /v1.0/query/xmlreport."""

    scanresult: str = ""


class ScanSchedule(_Sloppy):
    """GET /v1.0/query/scanschedule."""

    enabled: bool | None = None
    scandate: str | None = None
    scantime: str | None = None
    frequency: str | None = None
    interval: int | None = None


class OwaspCategories(_Sloppy):
    """GET /v1.0/query/owaspcategorylist."""

    owasp_category: Annotated[list[str], BeforeValidator(_none_to_list)] = Field(
        default_factory=list
    )


class UiLinkRow(_Sloppy):
    """The UI link generators; each endpoint fills exactly one key."""

    _KEY_BY_TYPE: ClassVar[Mapping[str, str]] = {
        "scan_result": "scanresult_url",
        "scan_config": "scanconfig_url",
        "cvss_severity": "cvssseverity_url",
        "owasp_category": "owaspcat_url",
        "owasp_severity": "owaspcatsevr_url",
    }

    scanresult_url: str | None = None
    scanconfig_url: str | None = None
    cvssseverity_url: str | None = None
    owaspcat_url: str | None = None
    owaspcatsevr_url: str | None = None

    def url_for(self, link_type: str) -> str:
        """The URL for a link type, raising when that key is absent."""
        key = self._KEY_BY_TYPE.get(link_type)
        url = getattr(self, key) if key else None
        if not url:
            raise ValueError(f"no URL for link_type {link_type!r}")
        return url


# ---------------------------------------------------------------------------
# ingestion record (connector-shaped, not API-shaped)
# ---------------------------------------------------------------------------


class CompletedScan(BaseModel):
    """One completed asset scan, shaped for the ingestion playbook.

    The asset uuid doubles as the alert sourceId (upsert key), detected_ts is
    the epoch of the scan timestamp for alertDetectionDate, and the severity
    rollup drives the alert severity picklist.
    """

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    asset_name: str
    uuid: str
    scan_owner: str | None = None
    scan_started_at: str | None = None
    scan_at: str | None = None
    detected_ts: int | None = None
    scan_status: str | None = None
    threat_level: float | None = None
    result_count: int = 0
    max_severity: str | None = None
    summary_text: str = ""
    vulnhash_url: str = ""
    findings: list[Finding] = Field(default_factory=list)

    @classmethod
    def from_row(cls, row: ScanStatusRow, asset: Asset) -> CompletedScan:
        """Build the scan shell from a scanstatus row; findings attach later.

        The findings-dependent rollup fields (result_count, max_severity,
        summary_text, vulnhash_url) stay at their defaults until
        :meth:`attach_findings` runs, so get_completed_scans can filter and
        cap on ``detected_ts`` BEFORE paying for any findings fetches.
        """
        # detected_ts is the LATEST timestamp the row carries: FortiDAST does
        # not document whether scan_at is the completion time or a start-side
        # stamp, and the ingestion watermark filters on this value -- a scan
        # that completes late must not fall behind the watermark forever.
        stamps = [
            parse_epoch(row.scan_at),
            parse_epoch(row.scan_started_at),
            parse_epoch(row.created_at),
        ]
        known = [s for s in stamps if s is not None]
        scan = cls(
            asset_name=row.asset_name or asset.asset_name,
            uuid=row.uuid or asset.uuid,
            scan_owner=row.scan_owner,
            scan_started_at=row.scan_started_at,
            scan_at=row.scan_at,
            scan_status=row.scan_status,
            threat_level=row.threat_level,
            detected_ts=max(known) if known else None,
        )
        # preserve any extra keys the row carried (kept for sourcedata)
        for key, value in row.model_dump(mode="json").items():
            if key not in cls.model_fields and key not in ("asset_name", "uuid"):
                setattr(scan, key, value)
        return scan

    def attach_findings(self, findings: list[Finding], vulnhash_url: str) -> None:
        """Fill the findings-dependent rollup fields on a shell record."""
        self.findings = findings
        self.result_count = len(findings)
        self.max_severity = max_severity(findings)
        self.vulnhash_url = vulnhash_url
        self.summary_text = _summary_text(self.asset_name, findings)


def max_severity(findings: list[Finding]) -> str | None:
    """Strongest severity across findings; None when there are none."""
    found: set[str] = set()
    for finding in findings:
        canon = SEVERITY_CANON.get((finding.severity or "").strip().lower())
        if canon:
            found.add(canon)
    for level in SEVERITY_ORDER:
        if level in found:
            return level
    return None


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = dict.fromkeys(SEVERITY_ORDER, 0)
    for finding in findings:
        canon = SEVERITY_CANON.get((finding.severity or "").strip().lower())
        if canon:
            counts[canon] += 1
    return counts


def _summary_text(asset_name: str, findings: list[Finding]) -> str:
    """Plain-text scan summary for the alert description field."""
    counts = severity_counts(findings)
    parts = [f"{level}: {counts[level]}" for level in SEVERITY_ORDER if counts[level]]
    heading = f"FortiDAST scan of {asset_name} completed"
    if not parts:
        return f"{heading}. No findings recorded."
    return f"{heading}. Findings by severity: {', '.join(parts)}."
