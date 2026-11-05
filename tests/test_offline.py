"""Offline tests for the FortiDAST connector.

No network: the transport is a fake requests session, and the composite
ingestion op runs against a fake client with canned responses. The model
shapes under test come from the FortiDAST OpenAPI spec's own examples
(including its documented sloppiness: lowercase t/z timestamps, nulls).
"""

from __future__ import annotations

import ast
import json
import pathlib
from typing import Any

import pytest
from fortidast import operations
from fortidast.lib.fortidast.client import FortiDASTClient, FortiDASTError
from fortidast.lib.fortidast.models import (
    Asset,
    CompletedScan,
    Finding,
    ScanResults,
    ScanStatusRow,
    SimpleStatus,
    StartScanResponse,
    max_severity,
    parse_epoch,
    severity_counts,
)
from fortidast.operations import (
    get_completed_scans,
    start_scan,
    stop_scan,
    update_scan_config,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

CONFIG: dict[str, Any] = {
    "base_url": "https://fortidast.example.com/api",
    "api_key": "test-key",
    "verify_ssl": True,
}


class FakeResponse:
    def __init__(self, status_code: int = 200, body: Any = None, text: str = "") -> None:
        self.status_code = status_code
        self._body = body
        self.text = text or (json.dumps(body) if body is not None else "")

    def json(self) -> Any:
        if self._body is None:
            raise ValueError("no body")
        return self._body


class FakeSession:
    """Records requests and answers them from a {(method, path_suffix): resp} map."""

    def __init__(self, routes: dict[tuple[str, str], FakeResponse]) -> None:
        self.routes = routes
        self.calls: list[dict[str, Any]] = []

    def request(
        self, method: str, url: str, params: Any = None, json: Any = None, timeout: Any = None
    ) -> FakeResponse:
        self.calls.append({"method": method, "url": url, "params": params, "json": json})
        for (want_method, suffix), resp in self.routes.items():
            if want_method == method and url.rstrip("/").endswith(suffix):
                return resp
        return FakeResponse(404, {"Status": "Not found"})

    def get(self, url: str, timeout: Any = None) -> FakeResponse:
        return self.request("GET", url)


def make_client(routes: dict[tuple[str, str], FakeResponse]) -> FortiDASTClient:
    client = FortiDASTClient(api_key="k", base_url="https://fortidast.example.com/api")
    client.session = FakeSession(routes)  # type: ignore[assignment]
    return client


def use_client(monkeypatch: pytest.MonkeyPatch, fake: Any) -> None:
    """Point operations._client at a fake for the duration of a test."""
    monkeypatch.setattr(operations, "_client", lambda config: fake)


# ---------------------------------------------------------------------------
# transport: envelope unwrapping, models, and error mapping
# ---------------------------------------------------------------------------


def test_client_sends_api_key_header() -> None:
    client = FortiDASTClient(api_key="k", base_url="https://fortidast.example.com/api")
    assert client.session.headers["X-API-Key"] == "k"
    assert client.session.headers["Content-Type"] == "application/json; charset=utf-8"


def test_client_unwraps_envelope_and_returns_models() -> None:
    client = make_client(
        {
            ("GET", "/v1.0/query/allassets"): FakeResponse(
                200, {"Status": [{"asset_name": "http://testphp.com", "uuid": "u-1"}]}
            ),
        }
    )
    assets = client.assets("someuser")
    assert isinstance(assets, list) and isinstance(assets[0], Asset)
    assert assets[0].asset_name == "http://testphp.com"
    call = client.session.calls[0]
    assert call["params"] == {"user": "someuser"}
    assert call["url"].startswith("https://fortidast.example.com/api/")


def test_client_error_carries_server_message() -> None:
    for code, message in (
        (401, "Api Key expired."),
        (403, "API Key not found."),
        (400, "Invalid args"),
    ):
        client = make_client(
            {
                ("GET", "/v1.0/query/allassets"): FakeResponse(code, {"Status": message}),
            }
        )
        with pytest.raises(FortiDASTError) as err:
            client.assets("someuser")
        assert message in str(err.value)


def test_client_wraps_connection_errors() -> None:
    client = make_client({})

    class Exploding:
        def request(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("boom")

    client.session = Exploding()  # type: ignore[assignment]
    # a non-requests exception from the transport must not escape raw
    with pytest.raises(FortiDASTError):
        client.assets("u")


def test_client_flags_response_shape_drift() -> None:
    # a payload that does not match the model fails loudly, not silently
    client = make_client(
        {
            ("GET", "/v1.0/query/results"): FakeResponse(
                200, {"Status": ["a string, not a results object"]}
            ),
        }
    )
    with pytest.raises(FortiDASTError) as err:
        client.results("http://testphp.com", "u-1")
    assert "response shape" in str(err.value)


def test_healthcheck_passes_on_invalid_args() -> None:
    # 400 "Invalid args" means authentication succeeded and only the missing
    # `user` parameter tripped the server.
    client = make_client(
        {
            ("GET", "/v1.0/query/allassets"): FakeResponse(400, {"Status": "Invalid args"}),
        }
    )
    assert client.healthcheck() is True


def test_healthcheck_fails_on_bad_key() -> None:
    client = make_client(
        {
            ("GET", "/v1.0/query/allassets"): FakeResponse(403, {"Status": "API Key not found."}),
        }
    )
    with pytest.raises(FortiDASTError):
        client.healthcheck()


# ---------------------------------------------------------------------------
# models: spec-example payloads, including the API's documented sloppiness
# ---------------------------------------------------------------------------

SLOPPY_STATUS_ROW: dict[str, Any] = {
    "asset_name": "http://testphp.com",
    "uuid": "bb0ed915-d184-4d0f-b364-e5e18d44ea40",
    "created_at": "2021-06-03t14:21:29.811522z",  # lowercase t/z, as shipped
    "scan_owner": "xyz@somemail",
    "scan_started_at": "2021-06-15T02:56:19.047067Z",
    "scan_at": "2021-06-15T02:56:51.279590Z",
    "scan_status": "Scan Complete",
    "threat_level": 5.7,
    "scan_type": 0,
}


def test_models_parse_spec_example_shapes() -> None:
    row = ScanStatusRow.model_validate(SLOPPY_STATUS_ROW)
    assert row.scan_status == "Scan Complete"
    assert row.threat_level == 5.7

    results = ScanResults.model_validate(
        {
            "vulnhash_url": "https://fortidast.example.com/sso?scanresult/x",
            "results": [
                {
                    "uuid": "u-1",
                    "url": "http://testphp.com",
                    "vulnerabilitytype": "A9 - Using Components with Known Vulnerabilities",
                    "severity": "High",
                    "cvssscore": 9.8,
                    "cweid": 0,
                    "fortiguard_id": 0,
                    "payload": None,
                    "vulnerabilitydescription": "CVE-2020-11993",
                }
            ],
        }
    )
    assert results.results[0].severity == "High"
    assert results.results[0].payload is None

    # nulls where the spec promises lists, extras that must survive
    lax = ScanResults.model_validate({"vulnhash_url": None, "results": None})
    assert lax.results == []
    finding = Finding.model_validate({"severity": "Low", "futureField": "x"})
    assert finding.model_dump()["futureField"] == "x"


def test_completed_scan_from_row_rolls_up() -> None:
    row = ScanStatusRow.model_validate(SLOPPY_STATUS_ROW)
    asset = Asset(asset_name="http://testphp.com", uuid="bb0ed915-d184-4d0f-b364-e5e18d44ea40")
    findings = [
        Finding(severity="High", vulnerabilitytype="A1 - Injection"),
        Finding(severity="Low", vulnerabilitytype="A5 - Misconfiguration"),
        Finding(severity="None"),
    ]
    scan = CompletedScan.from_row(row, asset, findings, "https://x/sso?scanresult/1")
    assert scan.max_severity == "High"
    assert scan.result_count == 3
    assert scan.detected_ts is not None
    assert "High: 1" in scan.summary_text and "Low: 1" in scan.summary_text
    assert "Informational: 1" in scan.summary_text
    # the raw row's extra keys survive for sourcedata
    assert scan.model_dump()["scan_type"] == 0
    # and the dump is JSON-serializable for FortiSOAR
    json.dumps(scan.model_dump(mode="json"))


def test_max_severity_and_counts() -> None:
    findings = [
        Finding(severity="Low"),
        Finding(severity="Critical"),
        Finding(severity="High"),
        Finding(severity="High"),
    ]
    assert max_severity(findings) == "Critical"
    counts = severity_counts(findings)
    assert counts["High"] == 2 and counts["Critical"] == 1
    assert max_severity([]) is None
    assert max_severity([Finding(severity="weird")]) is None


def test_parse_epoch_handles_sloppy_timestamps() -> None:
    assert parse_epoch("2021-06-03t14:21:29.811522z") is not None
    assert parse_epoch("2021-06-15T02:56:19.047067Z") is not None
    assert parse_epoch("") is None
    assert parse_epoch("not-a-date") is None
    assert parse_epoch(1700000000) == 1700000000


# ---------------------------------------------------------------------------
# operation parameter shaping
# ---------------------------------------------------------------------------


def test_start_scan_maps_scan_type(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class FakeClient:
        def start_scan(self, url: str, uuid: str, scan_type: int = 1) -> StartScanResponse:
            captured.update(url=url, uuid=uuid, scan_type=scan_type)
            return StartScanResponse(status="ok")

    use_client(monkeypatch, FakeClient())
    start_scan(CONFIG, {"url": "http://testphp.com", "uuid": "u-1", "scan_type": "Quick Scan"})
    assert captured == {"url": "http://testphp.com", "uuid": "u-1", "scan_type": 0}


def test_start_scan_defaults_scan_type_and_tolerates_empty_strings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeClient:
        def start_scan(self, url: str, uuid: str, scan_type: int = 1) -> StartScanResponse:
            captured.update(scan_type=scan_type)
            return StartScanResponse(status="ok")

    use_client(monkeypatch, FakeClient())
    # FortiSOAR delivers unset optionals as empty strings
    start_scan(CONFIG, {"url": "http://testphp.com", "uuid": "u-1", "scan_type": ""})
    assert captured["scan_type"] == 1  # Full Scan default


def test_start_scan_requires_params() -> None:
    with pytest.raises(Exception) as err:
        start_scan(CONFIG, {"url": "http://testphp.com"})
    assert "uuid" in str(err.value)


def test_stop_scan_posts_url_and_uuid(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class FakeClient:
        def stop_scan(self, url: str, uuid: str) -> SimpleStatus:
            captured.update(url=url, uuid=uuid)
            return SimpleStatus(status="stopped")

    use_client(monkeypatch, FakeClient())
    stop_scan(CONFIG, {"url": "http://testphp.com", "uuid": "u-1"})
    assert captured == {"url": "http://testphp.com", "uuid": "u-1"}


def test_update_scan_config_maps_section_and_injects_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeClient:
        def update_scan_config(
            self, section: str, url: str, uuid: str, config: dict[str, Any]
        ) -> SimpleStatus:
            captured.update(section=section, url=url, uuid=uuid, config=config)
            return SimpleStatus(status="ok")

    use_client(monkeypatch, FakeClient())
    update_scan_config(
        CONFIG,
        {
            "url": "http://testphp.com",
            "uuid": "u-1",
            "section": "exploit_engine",
            "config": json.dumps({"exploitengine": True}),
        },
    )
    assert captured["section"] == "exploit_engine"
    assert captured["config"] == {"exploitengine": True}


def test_update_scan_config_rejects_bad_json() -> None:
    with pytest.raises(Exception) as err:
        update_scan_config(
            CONFIG, {"url": "u", "uuid": "i", "section": "waf", "config": "{not json"}
        )
    assert "JSON" in str(err.value)


# ---------------------------------------------------------------------------
# ingestion composite
# ---------------------------------------------------------------------------


class FakeIngestClient:
    """Canned allassets -> scanstatus -> results chain, model-shaped."""

    def __init__(
        self,
        assets: list[Asset],
        statuses: dict[tuple[str, str], list[ScanStatusRow]],
        results: dict[tuple[str, str], ScanResults],
    ) -> None:
        self._assets = assets
        self._statuses = statuses
        self._results = results

    def assets(self, user: str) -> list[Asset]:
        return list(self._assets)

    def scan_status(self, url: str, uuid: str) -> list[ScanStatusRow]:
        return self._statuses.get((url, uuid), [])

    def results(self, url: str, uuid: str) -> ScanResults:
        return self._results.get((url, uuid), ScanResults())


def test_get_completed_scans_filters_and_rolls_up(monkeypatch: pytest.MonkeyPatch) -> None:
    assets = [
        Asset(asset_name="http://done.com", uuid="uuid-done"),
        Asset(asset_name="http://running.com", uuid="uuid-run"),
        Asset(asset_name="http://broken.com", uuid="uuid-broken"),
    ]
    statuses = {
        ("http://done.com", "uuid-done"): [
            ScanStatusRow(
                asset_name="http://done.com",
                uuid="uuid-done",
                scan_status="Scan Complete",
                scan_at="2021-06-15T02:56:51.279590Z",
                threat_level=7,
            ),
        ],
        ("http://running.com", "uuid-run"): [
            ScanStatusRow(
                asset_name="http://running.com", uuid="uuid-run", scan_status="In Progress"
            ),
        ],
    }
    results = {
        ("http://done.com", "uuid-done"): ScanResults(
            vulnhash_url="https://fortidast.example.com/sso?scanresult/x",
            results=[
                Finding(severity="High", vulnerabilitytype="A1 - Injection"),
                Finding(severity="Low", vulnerabilitytype="A5 - Misconfiguration"),
            ],
        ),
    }

    class Flaky(FakeIngestClient):
        def scan_status(self, url: str, uuid: str) -> list[ScanStatusRow]:
            if uuid == "uuid-broken":
                raise FortiDASTError("asset gone")
            return super().scan_status(url, uuid)

    use_client(monkeypatch, Flaky(assets, statuses, results))
    out = get_completed_scans(CONFIG, {"user": "someuser"})

    assert len(out) == 1
    scan = out[0]
    assert scan["uuid"] == "uuid-done"
    assert scan["result_count"] == 2
    assert scan["max_severity"] == "High"
    assert scan["detected_ts"] is not None
    assert "High: 1" in scan["summary_text"]
    assert "Low: 1" in scan["summary_text"]
    assert scan["vulnhash_url"].endswith("scanresult/x")
    assert len(scan["findings"]) == 2
    json.dumps(scan)  # the op output must be JSON-serializable for FortiSOAR


def test_get_completed_scans_without_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    assets = [Asset(asset_name="http://done.com", uuid="uuid-done")]
    statuses = {
        ("http://done.com", "uuid-done"): [
            ScanStatusRow(
                asset_name="http://done.com",
                uuid="uuid-done",
                scan_status="Scan Complete",
                scan_at="2021-06-15T02:56:51.279590Z",
            ),
        ],
    }
    use_client(monkeypatch, FakeIngestClient(assets, statuses, {}))
    out = get_completed_scans(CONFIG, {"user": "u", "include_findings": "false"})
    assert len(out) == 1
    assert out[0]["result_count"] == 0
    assert out[0]["max_severity"] is None
    assert "no findings" in out[0]["summary_text"].lower()


def test_get_completed_scans_caps_results(monkeypatch: pytest.MonkeyPatch) -> None:
    assets = [Asset(asset_name="http://a.com", uuid=f"u{i}") for i in range(5)]
    statuses = {
        ("http://a.com", f"u{i}"): [
            ScanStatusRow(
                asset_name="http://a.com",
                uuid=f"u{i}",
                scan_status="Scan Complete",
                scan_at=f"2021-06-15T02:56:{i:02d}.0Z",
            ),
        ]
        for i in range(5)
    }
    use_client(monkeypatch, FakeIngestClient(assets, statuses, {}))
    out = get_completed_scans(CONFIG, {"user": "u", "max_scans": 2})
    assert len(out) == 2
    # oldest first
    assert out[0]["scan_at"].endswith("00.0Z")


# ---------------------------------------------------------------------------
# release gate: every client call in operations.py exists on the client
# ---------------------------------------------------------------------------


def test_operations_only_call_real_client_methods() -> None:
    """AST guard: a renamed client method otherwise surfaces only on a live box."""
    source = (REPO_ROOT / "operations.py").read_text()
    tree = ast.parse(source)
    called: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "client"
        ):
            called.add(node.func.attr)
    client_methods = {name for name in dir(FortiDASTClient) if not name.startswith("_")}
    missing = called - client_methods
    assert not missing, f"operations call methods missing on FortiDASTClient: {sorted(missing)}"
