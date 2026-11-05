# fortinet-fortidast release notes

## 1.0.0

First release.

- Connector for the FortiDAST REST API (FNDN topic `1519-fortidast`, handler
  `1523`, product `1519`): 17 operations covering scan start/stop, scan
  status/auth status, schedules, the six scan configuration tabs, findings and
  summaries (scan, URI, API), recon data, JSON/XML reports, OWASP categories,
  and the console URL fragment generators.
- Auth is the FortiDAST API key sent as `X-API-Key`; basic keys get the read
  operations, privileged keys the write operations. Base URL defaults to
  `https://fortidast.forticloud.com/api`; the OpenAPI spec's
  `https://fortipentest.com/api` is the legacy product host.
- Data ingestion chain (Data Ingestion Wizard compatible): Fetch enumerates a
  user's assets and returns completed scans with a severity rollup; Ingest
  creates one alert per asset scan, upserted on sourceId (asset uuid) so
  re-runs refresh instead of duplicating and a rescan updates its alert.
- Health check probes authentication with a parameterless allassets call
  (400 means the key is valid, 401/403 carries the key error).
- Pydantic v2 throughout: typed request/response models per endpoint,
  operation params validated through input models (empty-string optionals
  treated as unset), and response-shape drift raised as a loud
  ConnectorError at the client boundary. Sources are ruff-format clean and
  the release workflow lints them.
