# Test coverage and known gaps

What the offline and live suites cover, what they cannot, and how to probe
the rest.

## Offline suite

`test_offline.py` fakes the HTTP transport entirely, so it verifies mapping
logic, error handling, and model shapes -- but it cannot catch a FortiDAST
API change. Everything below is about the live side.

## Live suite coverage

`test_live.py` (opt-in via `tests/.env`) drives the real API:

| Test | Needs |
|---|---|
| `test_healthcheck` | API key only |
| `test_get_assets` | API key; returns whatever the tenant has |
| `test_scan_status`, `test_scan_results_shape` | >= 1 registered asset |
| `test_get_completed_scans_smoke` | >= 1 asset with a completed scan |
| `test_start_and_stop_scan` | asset + `FORTIDAST_ALLOW_MUTATE=true` |

Everything asset-scoped skips cleanly while the tenant has no assets, so a
green offline run plus `2 passed, N skipped` live says: auth works, nothing
else was verifiable.

## API facts established by probing

A read-only parameter probe (see `probe_undocumented_params.py`) checked
every plausible undocumented parameter on the query endpoints -- paging
(`page`, `pageSize`, `per_page`, `limit`, `offset`, `size`, `max`, ...),
shaping (`count`, `sort`, `orderBy`), filtering (`filter`, `q`, `search`,
`status`, `scan_status`), date windowing (`from`, `to`, `since`, `until`),
and misc (`fields`, `expand`, `organization`) -- each with a benign and an
intentionally invalid value:

- The query API validates **only its documented parameters**; unknown
  parameters are silently dropped (there is no "unknown parameter" error,
  which is why discovery has to be behavioral -- see the limits below).
- No paging, count, filter, or date-window parameter exists, in the spec or
  at the validation layer. An ingestion run therefore cannot page the API;
  whatever the fetch operation returns in one call is the whole window.
- Asset-scoped endpoints (`scanstatus`, `results`, ...) validate asset
  existence before any parameter handling.
- The backend is Django REST Framework. `?format=api` renders the browsable
  HTML for a single endpoint; there is no schema/OpenAPI surface, and
  `/v1.0/api-docs` is a per-scan endpoint (needs `url` + `uuid`), not a
  global listing.

## What remains untested against a live backend

1. **Parameter behavior on non-empty data.** "Ignored" is proven at the
   validation layer (invalid values would be rejected if parsed). Whether
   the server applies any of these parameters when rows exist needs a
   baseline-vs-candidate diff with >= 1 asset present.
2. **Asset-scoped parameter surface.** With no real (url, uuid), the asset
   lookup short-circuits everything; candidate parameters showed no signal.
3. **`get_completed_scans` end to end on real findings**: the severity
   rollup, `summary_text`, max-of-timestamps `detected_ts`, and the
   `since_epoch` watermark filter (old scan dropped, boundary-inclusive,
   undated dropped) are covered offline only.
4. **Real payload shapes vs the spec.** Models are built from the vendor
   spec; a live row can carry fields the spec omits (extra keys are
   preserved by design, but the shapes themselves are unverified live).
5. **The mutating path** (`start_scan` / `stop_scan`): gated behind
   `FORTIDAST_ALLOW_MUTATE=true` and a registered asset; never exercised.
6. **Per-scan `/v1.0/api-docs` content** with a real asset's url/uuid.
7. **Exhaustiveness of the probed name list.** The API never enumerates its
   parameters, so discovery is guesswork; a parameter outside the probed
   list could exist undetected. Re-check whenever a newer vendor spec is
   available.

## Re-test procedure

With an API key in `tests/.env` and at least one registered asset (plus one
completed scan for the ingestion smoke):

```bash
python -m pytest tests/test_live.py -v
python tests/probe_undocumented_params.py
```

For the parameter diff: capture the documented-only response hash per
endpoint, then re-request with each candidate parameter and compare hashes
and row counts; any change means the parameter is honored and the ingestion
design can be revisited (in-run pagination becomes possible).
