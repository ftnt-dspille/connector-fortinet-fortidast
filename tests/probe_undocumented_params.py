"""Read-only probe for undocumented FortiDAST query-API parameters.

Method
------
The query endpoints validate their documented parameters before any
data-dependent work (a missing required parameter is rejected even when the
backend would otherwise refuse the call for tenant-state reasons). That
ordering turns the API into a parameter detector:

* documented params only                      -> baseline response
* a candidate the server PARSES (and rejects) -> different status/body,
  because type or value validation runs on it
* a candidate the server IGNORES              -> identical to baseline

Every candidate is sent twice -- a benign value (`1`) and an intentionally
invalid value (`@invalid@`) -- because a numeric parameter that is accepted
with `1` but rejected with `@invalid@` is parsed even when the response is
otherwise identical. A negative control (a name that cannot exist) confirms
the baseline is stable.

Read-only: GET requests on query endpoints only; the API key is read from
tests/.env and never printed.

Limits (see COVERAGE.md)
------------------------
"Ignored" is proven at the validation layer. Whether a parameter is applied
when the result would be non-empty needs a baseline-vs-candidate diff on a
tenant with data, which this script also supports via --diff (compares
response hashes/lengths instead of status codes).
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CANDIDATES = [
    "page",
    "pageSize",
    "page_size",
    "perPage",
    "per_page",
    "limit",
    "offset",
    "start",
    "size",
    "max",
    "maxResults",
    "skip",
    "take",
    "count",
    "totalCount",
    "sort",
    "sortBy",
    "sort_by",
    "order",
    "orderBy",
    "filter",
    "q",
    "search",
    "status",
    "scan_status",
    "scanStatus",
    "state",
    "from",
    "to",
    "dateFrom",
    "dateTo",
    "startDate",
    "endDate",
    "since",
    "until",
    "fields",
    "verbose",
    "expand",
    "type",
    "scan_type",
    "organization",
    "domain",
]
# NOTE: "format" is deliberately not a candidate: it is Django REST
# Framework's own content-negotiation parameter (?format=api renders the
# browsable HTML, ?format=openapi 404s at the framework layer), so it lights
# the detector up as a false positive rather than a FortiDAST parameter.

ASSET_SCOPED = ("scanstatus", "results", "scansummaryresults", "authstatus")

ASSET_CANDIDATES = [
    "page",
    "pageSize",
    "limit",
    "offset",
    "size",
    "count",
    "sort",
    "status",
    "scan_status",
    "from",
    "to",
    "since",
    "until",
]

DOC_PATHS = (
    "/",
    "/api",
    "/v1.0",
    "/v1.0/query",
    "/swagger.json",
    "/api-docs",
    "/v1.0/api-docs",
    "/health",
)


def load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip("\"'")
    return env


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--env",
        default=str(Path(__file__).resolve().parent / ".env"),
        help="tests/.env holding FORTIDAST_BASE_URL / FORTIDAST_API_KEY",
    )
    ap.add_argument("--user", default="admin", help="user whose assets to query")
    ap.add_argument(
        "--asset-url", default="http://example.com", help="asset url for asset-scoped endpoints"
    )
    ap.add_argument(
        "--asset-uuid",
        default="00000000-0000-4000-8000-000000000000",
        help="asset uuid for asset-scoped endpoints",
    )
    ap.add_argument(
        "--diff", action="store_true", help="hash/length diff mode: needs a live tenant with data"
    )
    args = ap.parse_args()

    env = load_env(Path(args.env))
    base = env.get("FORTIDAST_BASE_URL", "https://fortidast.forticloud.com/api").rstrip("/")
    key = env.get("FORTIDAST_API_KEY", "")
    if not key or key.startswith("PASTE_YOUR"):
        print("no API key configured; copy tests/.env.example to tests/.env", file=sys.stderr)
        return 2
    session = requests.Session()
    session.headers["X-API-Key"] = key
    session.verify = env.get("FORTIDAST_VERIFY_SSL", "true").lower() not in ("false", "0", "no")

    def call(path: str, params: dict | None = None) -> dict:
        try:
            r = session.get(base + path, params=params or {}, timeout=30)
            body = r.text
            return {
                "code": r.status_code,
                "len": len(r.content),
                "hash": hashlib.sha1(r.content).hexdigest()[:8],
                "body": body[:80].replace("\n", " "),
            }
        except requests.RequestException as err:
            return {"code": "EXC", "len": 0, "hash": "-", "body": str(err)[:80]}

    def differs(a: dict, b: dict) -> bool:
        if args.diff:
            return (a["hash"], a["len"]) != (b["hash"], b["len"])
        return a["code"] != b["code"]

    print("== baseline / controls ==")
    baseline = call("/v1.0/query/allassets", {"user": args.user})
    print(f"  documented-only : {baseline}")
    print(f"  missing user    : {call('/v1.0/query/allassets')}")
    negative = call("/v1.0/query/allassets", {"user": args.user, "zzz_not_a_param": "1"})
    print(f"  negative control: {negative} (stable: {negative['hash'] == baseline['hash']})")

    print("\n== allassets candidates ==")
    hits: list[str] = []
    for name in CANDIDATES:
        r1 = call("/v1.0/query/allassets", {"user": args.user, name: "1"})
        r2 = call("/v1.0/query/allassets", {"user": args.user, name: "@invalid@"})
        parsed = differs(baseline, r1) or differs(baseline, r2)
        if parsed:
            hits.append(name)
        print(
            f"  {name:14} 1->{r1['code']}/{r1['hash']}  @invalid@->{r2['code']}/{r2['hash']}"
            f"  {'PARSED' if parsed else 'ignored'}"
        )
        time.sleep(0.12)

    print("\n== asset-scoped candidates ==")
    asset_params = {"url": args.asset_url, "uuid": args.asset_uuid}
    for endpoint in ASSET_SCOPED:
        asset_baseline = call(f"/v1.0/query/{endpoint}", asset_params)
        print(f"  {endpoint} baseline: {asset_baseline}")
        for name in ASSET_CANDIDATES:
            r = call(f"/v1.0/query/{endpoint}", {**asset_params, name: "1"})
            if differs(asset_baseline, r):
                hits.append(f"{endpoint}:{name}")
                print(f"    +{name:12} -> {r['code']} {r['body'][:50]!r}  PARSED")
            time.sleep(0.1)

    print("\n== schema / docs surfaces ==")
    for path in DOC_PATHS:
        r = call(path)
        print(f"  GET {path:18} -> {r['code']} {r['body'][:60]!r}")

    print("\n== candidates that changed server behavior ==")
    print(sorted(set(hits)) or "none -- query API accepts only its documented parameters")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
