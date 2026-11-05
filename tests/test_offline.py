# -*- coding: utf-8 -*-
"""Offline tests for the FortiDAST connector.

No network: the transport is a fake requests session, and the composite
ingestion op runs against a fake client with canned responses.
"""
import ast
import json
import pathlib

import pytest

from fortidast import operations
from fortidast.lib.fortidast.client import (
    FortiDASTClient,
    FortiDASTError,
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

CONFIG = {
    "base_url": "https://fortidast.example.com/api",
    "api_key": "test-key",
    "verify_ssl": True,
}


class FakeResponse(object):
    def __init__(self, status_code=200, body=None, text=""):
        self.status_code = status_code
        self._body = body
        self.text = text or (json.dumps(body) if body is not None else "")

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


class FakeSession(object):
    """Records requests and answers them from a {(method, path_suffix): resp} map."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def request(self, method, url, params=None, json=None, timeout=None):
        self.calls.append({"method": method, "url": url, "params": params,
                           "json": json})
        for (want_method, suffix), resp in self.routes.items():
            if want_method == method and url.rstrip("/").endswith(suffix):
                return resp
        return FakeResponse(404, {"Status": "Not found"})

    def get(self, url, timeout=None):
        return self.request("GET", url)


def make_client(routes):
    client = FortiDASTClient(api_key="k", base_url="https://fortidast.example.com/api")
    client.session = FakeSession(routes)
    return client


def use_client(monkeypatch, fake):
    """Point operations._client at a fake for the duration of a test."""
    monkeypatch.setattr(operations, "_client", lambda config: fake)


# ---------------------------------------------------------------------------
# transport: envelope unwrapping and error mapping
# ---------------------------------------------------------------------------

def test_client_sends_api_key_header():
    client = FortiDASTClient(api_key="k", base_url="https://fortidast.example.com/api")
    assert client.session.headers["X-API-Key"] == "k"
    assert client.session.headers["Content-Type"] == "application/json; charset=utf-8"


def test_client_unwraps_status_envelope():
    client = make_client({
        ("GET", "/v1.0/query/allassets"):
            FakeResponse(200, {"Status": [{"asset_name": "http://testphp.com",
                                           "uuid": "u-1"}]}),
    })
    assert client.assets("someuser") == [{"asset_name": "http://testphp.com",
                                          "uuid": "u-1"}]
    call = client.session.calls[0]
    assert call["params"] == {"user": "someuser"}
    assert call["url"].startswith("https://fortidast.example.com/api/")


def test_client_error_carries_server_message():
    for code, message in ((401, "Api Key expired."),
                          (403, "API Key not found."),
                          (400, "Invalid args")):
        client = make_client({
            ("GET", "/v1.0/query/allassets"):
                FakeResponse(code, {"Status": message}),
        })
        with pytest.raises(FortiDASTError) as err:
            client.assets("someuser")
        assert message in str(err.value)


def test_client_wraps_connection_errors():
    client = make_client({})

    class Exploding(object):
        def request(self, *a, **k):
            raise RuntimeError("boom")

    client.session = Exploding()
    # a non-requests exception from the transport must not escape raw
    with pytest.raises(FortiDASTError):
        client.assets("u")


def test_healthcheck_passes_on_invalid_args():
    # 400 "Invalid args" means authentication succeeded and only the missing
    # `user` parameter tripped the server.
    client = make_client({
        ("GET", "/v1.0/query/allassets"): FakeResponse(400, {"Status": "Invalid args"}),
    })
    assert client.healthcheck() is True


def test_healthcheck_fails_on_bad_key():
    client = make_client({
        ("GET", "/v1.0/query/allassets"):
            FakeResponse(403, {"Status": "API Key not found."}),
    })
    with pytest.raises(FortiDASTError):
        client.healthcheck()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def test_max_severity_and_counts():
    findings = [{"severity": "Low"}, {"severity": "Critical"},
                {"severity": "High"}, {"severity": "High"}]
    assert max_severity(findings) == "Critical"
    counts = severity_counts(findings)
    assert counts["High"] == 2 and counts["Critical"] == 1
    assert max_severity([]) is None
    assert max_severity([{"severity": "weird"}]) is None


def test_parse_epoch_handles_sloppy_timestamps():
    # FortiDAST has been seen emitting lowercase t/z timestamps.
    assert parse_epoch("2021-06-03t14:21:29.811522z") is not None
    assert parse_epoch("2021-06-15T02:56:19.047067Z") is not None
    assert parse_epoch("") is None
    assert parse_epoch("not-a-date") is None
    assert parse_epoch(1700000000) == 1700000000


# ---------------------------------------------------------------------------
# operation parameter shaping
# ---------------------------------------------------------------------------

def test_start_scan_maps_scan_type(monkeypatch):
    captured = {}

    class FakeClient(object):
        def start_scan(self, url, uuid, scan_type=1):
            captured.update(url=url, uuid=uuid, scan_type=scan_type)
            return {"status": "ok"}

    use_client(monkeypatch, FakeClient())
    start_scan(CONFIG, {"url": "http://testphp.com", "uuid": "u-1",
                        "scan_type": "Quick Scan"})
    assert captured == {"url": "http://testphp.com", "uuid": "u-1",
                        "scan_type": 0}


def test_start_scan_requires_params():
    with pytest.raises(Exception) as err:
        start_scan(CONFIG, {"url": "http://testphp.com"})
    assert "uuid" in str(err.value)


def test_stop_scan_posts_url_and_uuid(monkeypatch):
    captured = {}

    class FakeClient(object):
        def stop_scan(self, url, uuid):
            captured.update(url=url, uuid=uuid)
            return {"status": "stopped"}

    use_client(monkeypatch, FakeClient())
    stop_scan(CONFIG, {"url": "http://testphp.com", "uuid": "u-1"})
    assert captured == {"url": "http://testphp.com", "uuid": "u-1"}


def test_update_scan_config_maps_section_and_injects_identity(monkeypatch):
    captured = {}

    class FakeClient(object):
        def update_scan_config(self, section, url, uuid, config):
            captured.update(section=section, url=url, uuid=uuid, config=config)
            return {"status": "ok"}

    use_client(monkeypatch, FakeClient())
    update_scan_config(CONFIG, {
        "url": "http://testphp.com", "uuid": "u-1",
        "section": "exploit_engine",
        "config": json.dumps({"exploitengine": True}),
    })
    assert captured["section"] == "exploit_engine"
    assert captured["config"] == {"exploitengine": True}


def test_update_scan_config_rejects_bad_json():
    with pytest.raises(Exception) as err:
        update_scan_config(CONFIG, {"url": "u", "uuid": "i",
                                    "section": "waf", "config": "{not json"})
    assert "JSON" in str(err.value)


# ---------------------------------------------------------------------------
# ingestion composite
# ---------------------------------------------------------------------------

class FakeIngestClient(object):
    """Canned allassets -> scanstatus -> results chain."""

    def __init__(self, assets, statuses, results):
        self.assets_map = assets
        self.statuses = statuses
        self.results_map = results

    def assets(self, user):
        return list(self.assets_map)

    def scan_status(self, url, uuid):
        return self.statuses.get((url, uuid), [])

    def results(self, url, uuid):
        return self.results_map.get((url, uuid), {})


def test_get_completed_scans_filters_and_rolls_up(monkeypatch):
    assets = [
        {"asset_name": "http://done.com", "uuid": "uuid-done"},
        {"asset_name": "http://running.com", "uuid": "uuid-run"},
        {"asset_name": "http://broken.com", "uuid": "uuid-broken"},
    ]
    statuses = {
        ("http://done.com", "uuid-done"): [
            {"asset_name": "http://done.com", "uuid": "uuid-done",
             "scan_status": "Scan Complete",
             "scan_at": "2021-06-15T02:56:51.279590Z", "threat_level": 7},
        ],
        ("http://running.com", "uuid-run"): [
            {"asset_name": "http://running.com", "uuid": "uuid-run",
             "scan_status": "In Progress"},
        ],
    }
    results = {
        ("http://done.com", "uuid-done"): {
            "vulnhash_url": "https://fortidast.example.com/sso?scanresult/x",
            "results": [
                {"severity": "High", "vulnerabilitytype": "A1 - Injection"},
                {"severity": "Low", "vulnerabilitytype": "A5 - Misconfiguration"},
            ],
        },
    }

    class Flaky(FakeIngestClient):
        def scan_status(self, url, uuid):
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


def test_get_completed_scans_without_findings(monkeypatch):
    assets = [{"asset_name": "http://done.com", "uuid": "uuid-done"}]
    statuses = {
        ("http://done.com", "uuid-done"): [
            {"asset_name": "http://done.com", "uuid": "uuid-done",
             "scan_status": "Scan Complete",
             "scan_at": "2021-06-15T02:56:51.279590Z"},
        ],
    }
    use_client(monkeypatch, FakeIngestClient(assets, statuses, {}))
    out = get_completed_scans(CONFIG, {"user": "u", "include_findings": "false"})
    assert len(out) == 1
    assert out[0]["result_count"] == 0
    assert out[0]["max_severity"] is None
    assert "no findings" in out[0]["summary_text"].lower()


def test_get_completed_scans_caps_results(monkeypatch):
    assets = [{"asset_name": "http://a.com", "uuid": "u{0}".format(i)}
              for i in range(5)]
    statuses = {
        ("http://a.com", "u{0}".format(i)): [
            {"asset_name": "http://a.com", "uuid": "u{0}".format(i),
             "scan_status": "Scan Complete",
             "scan_at": "2021-06-15T02:56:{0:02d}.0Z".format(i)},
        ] for i in range(5)
    }
    use_client(monkeypatch, FakeIngestClient(assets, statuses, {}))
    out = get_completed_scans(CONFIG, {"user": "u", "max_scans": 2})
    assert len(out) == 2
    # oldest first
    assert out[0]["scan_at"].endswith("00.0Z")


# ---------------------------------------------------------------------------
# release gate: every client call in operations.py exists on the client
# ---------------------------------------------------------------------------

def test_operations_only_call_real_client_methods():
    """AST guard: a renamed client method otherwise surfaces only on a live box."""
    source = (REPO_ROOT / "operations.py").read_text()
    tree = ast.parse(source)
    called = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "client"):
            called.add(node.func.attr)
    client_methods = {name for name in dir(FortiDASTClient)
                      if not name.startswith("_")}
    missing = called - client_methods
    assert not missing, (
        "operations call methods missing on FortiDASTClient: {0}".format(
            sorted(missing)))
