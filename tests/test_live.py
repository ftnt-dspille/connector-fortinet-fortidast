"""Live tests for the FortiDAST connector against a real FortiDAST.

Opt-in: requires FORTIDAST_BASE_URL / FORTIDAST_API_KEY (copy tests/.env.example
to tests/.env). Everything here is read-only except the start/stop scan test,
which additionally requires FORTIDAST_ALLOW_MUTATE=true and runs only against
an asset you registered in FortiDAST.

FortiSOAR is NOT required: the tests drive lib.fortidast.client directly.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fortidast import operations
from fortidast.lib.fortidast.client import FortiDASTClient
from fortidast.lib.fortidast.models import CompletedScansParams

pytestmark = pytest.mark.live


def _load_env() -> dict[str, str]:
    """tests/.env values (process environment wins when both define a key)."""
    env_path = Path(__file__).resolve().parent / ".env"
    values: dict[str, str] = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[key.strip()] = value
    return values


ENV = _load_env()


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name) or ENV.get(name) or default


@pytest.fixture(scope="module")
def client() -> Iterator[FortiDASTClient]:
    base_url = _env("FORTIDAST_BASE_URL", "https://fortidast.forticloud.com/api")
    api_key = _env("FORTIDAST_API_KEY")
    if not api_key or api_key.startswith("PASTE_YOUR"):
        pytest.skip("FORTIDAST_API_KEY not configured (copy tests/.env.example to tests/.env)")
    verify_ssl = _env("FORTIDAST_VERIFY_SSL", "true").lower() not in ("false", "0", "no")
    yield FortiDASTClient(api_key=api_key, base_url=base_url, verify_ssl=verify_ssl)


@pytest.fixture(scope="module")
def first_asset(client: FortiDASTClient) -> Iterator[dict[str, Any]]:
    """The first registered asset, or skip when the tenant has none."""
    user = _env("FORTIDAST_USER")
    assets = client.assets(user) if user else _any_user_assets(client)
    if not assets:
        pytest.skip("no assets registered in FortiDAST; register one first")
    asset = assets[0]
    yield {"url": asset.asset_name, "uuid": asset.uuid}


def _any_user_assets(client: FortiDASTClient) -> list[Any]:
    """allassets requires a username; try the common ones when unset."""
    for user in ("admin", "administrator"):
        try:
            assets = client.assets(user)
        except Exception:
            continue
        if assets:
            return assets
    return []


def test_healthcheck(client: FortiDASTClient) -> None:
    assert client.healthcheck() is True


def test_get_assets(client: FortiDASTClient) -> None:
    user = _env("FORTIDAST_USER")
    assets = client.assets(user) if user else _any_user_assets(client)
    assert isinstance(assets, list)
    for asset in assets:
        assert asset.asset_name, "asset_name must not be empty"
        assert asset.uuid, "uuid must not be empty"


def test_scan_status(client: FortiDASTClient, first_asset: dict[str, Any]) -> None:
    rows = client.scan_status(**first_asset)
    assert isinstance(rows, list)
    for row in rows:
        assert row.scan_status is None or isinstance(row.scan_status, str)


def test_scan_results_shape(client: FortiDASTClient, first_asset: dict[str, Any]) -> None:
    results = client.results(**first_asset)
    assert results.results is not None
    for finding in results.results:
        assert finding.severity is None or isinstance(finding.severity, str)


def test_get_completed_scans_smoke(client: FortiDASTClient) -> None:
    """The ingestion source operation, end to end against the live API."""
    user = _env("FORTIDAST_USER")
    for candidate in [user] if user else ["admin", "administrator"]:
        try:
            assets = client.assets(candidate)
        except Exception:
            continue
        if not assets:
            continue
        params = CompletedScansParams(user=candidate, max_scans=5)
        # call the operation layer the way the playbook does
        config = {
            "base_url": client.base_url,
            "api_key": client.session.headers["X-API-Key"],
            "verify_ssl": client.session.verify,
        }
        out = operations.get_completed_scans(config, params.model_dump())
        assert isinstance(out, list) and len(out) <= 5
        for scan in out:
            assert scan["uuid"] and scan["asset_name"]
            assert scan["scan_status"] == "Scan Complete"
        return
    pytest.skip("no assets found for any candidate user")


def test_start_and_stop_scan(client: FortiDASTClient, first_asset: dict[str, Any]) -> None:
    """Mutating: starts a Quick Scan then stops it. Opt-in via
    FORTIDAST_ALLOW_MUTATE=true."""
    if _env("FORTIDAST_ALLOW_MUTATE").lower() != "true":
        pytest.skip("FORTIDAST_ALLOW_MUTATE!=true; not mutating a real tenant")
    start = client.start_scan(first_asset["url"], first_asset["uuid"], scan_type=0)
    assert start.status, "start response must carry a status"
    stop = client.stop_scan(first_asset["url"], first_asset["uuid"])
    assert stop.status, "stop response must carry a status"
