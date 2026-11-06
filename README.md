# Fortinet FortiDAST Connector for FortiSOAR

Integrates [Fortinet FortiDAST](https://www.fortinet.com/products/fortidast)
(Dynamic Application Security Testing) with FortiSOAR. The connector drives
FortiDAST scans over its REST API and ingests completed scan results as
FortiSOAR alerts.

Fortinet's public FortiSOAR connector repos use the same layout; this
connector follows the `fortinet-*` naming used by the published Fortinet
connectors.

## About FortiDAST

FortiDAST scans web applications and REST APIs for vulnerabilities (OWASP
categories, CVEs via its Exploit Engine, WAF bypass checks) and exposes a REST
API for asset and scan management. The API surface this connector covers:

| Area | Endpoints |
|---|---|
| Scanning | start/stop a scan, scan status, authentication status, schedules |
| Configuration | authentication, coverage, exploit engine, forced browsing, HTTP, WAF tabs |
| Results | findings, per-vulnerability-type severity summary, per-URI and API scan summaries, recon data |
| Reports | JSON report, XML report |
| Console links | scan result/config, CVSS severity, OWASP category/severity URLs |

Full request/response schemas: the OpenAPI spec downloadable from the
FortiDAST console (Vulnerability Assessment > REST API), also indexed on the
Fortinet Developer Network (FNDN) as `1519-fortidast`.

## Requirements

- FortiSOAR 7.x / 8.x on a Python 3.10+ appliance (the connector uses pydantic v2)
- FortiDAST with REST API access
- A FortiDAST API key:
  - **basic** keys may only call the read (query) operations;
  - **privileged** keys can also start/stop scans, set schedules and update
    scan configuration.

## Configuration

| Field | Required | Description |
|---|---|---|
| Base URL | yes | FortiDAST API base including `/api`, default `https://fortidast.forticloud.com/api`. Override for on-premises deployments. |
| API Key | yes | Generated in the FortiDAST console; shown only once. Sent as the `X-API-Key` header. |
| Verify SSL | no | Disable for self-signed certificates (the FortiDAST guide documents skipping validation in labs). |

## Operations

| Operation | Description | Key |
|---|---|---|
| Start Scan | Start a scan for an asset (Quick/Full). | privileged |
| Stop Scan | Stop a running scan. | privileged |
| Get Assets | List a user's registered assets (url + uuid). | basic |
| Get Scan Status | Scan state, start times, owner, threat level. | basic |
| Get Auth Status | Scan status with authentication state. | basic |
| Get Scan Results | Findings with severity, CVSS, CWE, FortiGuard id, payload, impact, remediation. | basic |
| Get Scan Summary | Severity counts per vulnerability type. | basic |
| Get URI Scan Summary | Per-URI timing and severity counts (URI or API variant). | basic |
| Get Recon Results | Technologies and fingerprinting data. | basic |
| Get JSON Report | Full JSON report by vulnerability type and CVSS score. | basic |
| Get XML Report | Raw XML report string. | basic |
| Get Scan Schedule | Scheduled scan for an asset. | basic |
| Set Scan Schedule | Create/update a schedule. | privileged |
| Update Scan Config | Update one scan config tab (authentication, coverage, exploit engine, forced browsing, HTTP, WAF). | privileged |
| Get OWASP Categories | OWASP category list. | basic |
| Get UI Link | FortiDAST console URL fragments for results/config views. | basic |
| Get Completed Scans | Ingestion source: assets whose latest scan is complete, with severity rollup and summary. | basic |

Every operation takes the asset as `url` + `uuid` (both come from
**Get Assets**); Get Assets takes the FortiDAST `user` whose assets to list.

## Data ingestion

The connector ships a Data-Ingestion-Wizard-compatible chain
(`Sample - Fortinet FortiDAST - <version>` collection):

- **> FortiDAST > Fetch** (`#fetch`) - enumerates a FortiDAST user's assets,
  returns the completed scans with a severity rollup. The wizard's
  configuration form (FortiDAST user, max scans per run, include findings)
  lives on this playbook's start step.
- **FortiDAST > Ingest** (`#ingest`, `#create`) - calls Fetch and creates one
  **alert per asset scan**, upserted on `sourceId` = asset uuid:

  - a re-run refreshes the existing alert instead of duplicating it;
  - a rescan of the same asset updates the same alert with the newest
    findings;
  - severity comes from the strongest finding of the scan (Informational when
    none);
  - the raw scan row and findings are kept as JSON in `sourcedata`, and the
    description carries the severity counts plus a deep link into the
    FortiDAST console.

There is deliberately no last-pull-time watermark: FortiDAST has no
"list scans since T" endpoint, so each run enumerates assets regardless;
**Maximum Scans Per Run** bounds the work, and the upsert makes re-runs
idempotent.

Configure it through the Data Ingestion Wizard (Ingestion > Configure), or run
`FortiDAST > Ingest` on demand from the Alerts module's Execute menu.

## Health check

The health probe sends `GET /v1.0/query/allassets` without its `user`
parameter. A valid key reaches authentication and gets the API's "Invalid
args" (HTTP 400); a bad or expired key gets 401/403 with the key error, which
the connector surfaces verbatim.

## Testing

```bash
python3 -m pytest tests/ -q
ruff format . && ruff check .
```

Offline only: the transport is faked, so the tests cannot catch a FortiDAST
API change.

### Live tests

`tests/test_live.py` drives the real API (no FortiSOAR needed): copy
`tests/.env.example` to `tests/.env`, paste your API key, then

```bash
pytest tests/test_live.py
```

Read-only by default (health check, assets, scan status/results, the
`get_completed_scans` ingestion source); the start/stop scan test additionally
requires `FORTIDAST_ALLOW_MUTATE=true` in `tests/.env`. `FORTIDAST_USER` names
the FortiDAST user whose assets the tests enumerate (admin/administrator are
tried when unset).

See `tests/COVERAGE.md` for what the live suite does and does not verify
(and `tests/probe_undocumented_params.py` for the read-only API-parameter
probe behind it).

The API surface is typed end to end: `lib/fortidast/models.py` holds the
pydantic request/response models (validated against the FNDN OpenAPI spec's
shapes, lenient about the API's documented sloppiness -- nulls, lowercase
timestamps, unknown keys), the client returns model instances, and operation
parameters are validated through pydantic input models before any call is
made. A response that drifts from the documented shape fails loudly at the
client boundary instead of surfacing as a broken playbook downstream.

## Release

Tag `v<version>` (matching `info.json`) triggers the GitHub release workflow,
which recompiles the playbooks, runs the offline tests, checks the sources are
latin-1 clean, and attaches the `.tgz` bundle.
