# -*- coding: utf-8 -*-
""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

"""HTTP client for the FortiDAST REST API.

Every FortiDAST response is wrapped as {"Status": <payload or message string>},
and error payloads carry their human-readable text in that same "Status" key
("Invalid args", "Api Key expired.", "API Key not found.", ...). The client
unwraps success payloads and turns non-2xx responses into ConnectorError with
the server's message.

Endpoint map (the /v1.0 prefix is part of every path):

  POST /v1.0/cmdb/scan/start                     start_scan(url, uuid, scan_type)
  POST /v1.0/cmdb/scan/stop                      stop_scan(url, uuid)
  POST /v1.0/cmdb/scanconfig/<section>           update_scan_config(section, ...)
  GET  /v1.0/query/allassets?user=               assets(user)
  GET  /v1.0/query/authstatus?url=&uuid=         auth_status(url, uuid)
  GET  /v1.0/query/results?url=&uuid=            results(url, uuid)
  GET  /v1.0/query/scanstatus?url=&uuid=         scan_status(url, uuid)
  GET  /v1.0/query/scansummaryresults            scan_summary(url, uuid)
  GET  /v1.0/query/uriscansummary[&type=api]     uri_scan_summary(url, uuid, api)
  GET  /v1.0/query/recon_results                 recon_results(url, uuid)
  GET  /v1.0/query/jsonreport                    json_report(url, uuid)
  GET  /v1.0/query/xmlreport                     xml_report(url, uuid)
  GET  /v1.0/query/scanschedule                  scan_schedule(url, uuid)
  POST /v1.0/cmdb/scanconfig/scanschedule        set_scan_schedule(body)
  GET  /v1.0/query/owaspcategorylist             owasp_categories(url, uuid)
  GET  /v1.0/query/{scanresulturl|scanconfigurl|
       cvssseverityurl|owaspcaturl|owaspcatsevrurl}   ui_link(...)

Auth is an API key header (X-API-Key); "basic" keys may only read, "privileged"
keys may also write (start/stop, schedules, configuration).
"""

from datetime import datetime

import requests

from connectors.core.connector import ConnectorError

DEFAULT_BASE_URL = "https://fortidast.forticloud.com/api"
DEFAULT_TIMEOUT = 60

# Sections of POST /v1.0/cmdb/scanconfig/<section>, as the API names them.
SCANCONFIG_SECTIONS = {
    "authentication": "authentication",
    "coverage": "coverage",
    "exploit_engine": "exploitengine",
    "forced_browsing": "forcedbrowsingconfig",
    "http": "httpconfig",
    "waf": "wafconfig",
}

# Severity rollup order, strongest first. FortiDAST also emits "None" and
# informational-ish spellings; anything unknown sorts below "Informational".
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational", "None"]
SEVERITY_CANON = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "low": "Low",
    "informational": "Informational",
    "info": "Informational",
    "none": "Informational",
}


class FortiDASTError(ConnectorError):
    """Raised for any FortiDAST API failure (HTTP, auth, or server message)."""


class FortiDASTClient(object):
    def __init__(self, api_key, base_url=DEFAULT_BASE_URL, verify_ssl=True,
                 timeout=DEFAULT_TIMEOUT):
        if not api_key:
            raise FortiDASTError("API Key is required.")
        self.base_url = (base_url or DEFAULT_BASE_URL).strip().rstrip("/")
        if "://" not in self.base_url:
            self.base_url = "https://{0}".format(self.base_url)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "X-API-Key": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
        })
        self.session.verify = bool(verify_ssl)

    # ------------------------------------------------------------------
    # transport
    # ------------------------------------------------------------------

    def _request(self, method, path, params=None, json_body=None):
        url = "{0}{1}".format(self.base_url, path)
        try:
            resp = self.session.request(
                method, url, params=params, json=json_body, timeout=self.timeout,
            )
        except requests.exceptions.SSLError as e:
            raise FortiDASTError(
                "TLS certificate verification failed for {0}: {1}. "
                "Disable Verify SSL in the connector configuration for "
                "self-signed deployments.".format(self.base_url, e))
        except requests.exceptions.ConnectionError as e:
            raise FortiDASTError(
                "Could not connect to FortiDAST at {0}: {1}".format(self.base_url, e))
        except requests.exceptions.Timeout as e:
            raise FortiDASTError(
                "FortiDAST request timed out after {0}s: {1}".format(self.timeout, e))
        except requests.exceptions.RequestException as e:
            raise FortiDASTError("FortiDAST request failed: {0}".format(e))
        except Exception as e:
            # Never let a transport-layer surprise escape raw: FortiSOAR shows
            # the ConnectorError message to the analyst.
            raise FortiDASTError(
                "Unexpected error calling FortiDAST: {0}".format(e))

        if resp.status_code >= 400:
            raise FortiDASTError(_error_text(resp))
        try:
            body = resp.json()
        except ValueError:
            raise FortiDASTError(
                "FortiDAST returned a non-JSON response (HTTP {0}) from {1}".format(
                    resp.status_code, path))
        # Every documented response wraps its payload in "Status"; be lenient
        # with servers that omit the wrapper so callers always see the payload.
        if isinstance(body, dict) and set(body.keys()) == {"Status"}:
            return body["Status"]
        return body

    def get(self, path, params=None):
        return self._request("GET", path, params=params)

    def post(self, path, json_body=None, params=None):
        return self._request("POST", path, params=params, json_body=json_body)

    # ------------------------------------------------------------------
    # cmdb (write) endpoints -- privileged key required
    # ------------------------------------------------------------------

    def start_scan(self, url, uuid, scan_type=1):
        body = {"url": url, "uuid": uuid, "scan_type": int(scan_type)}
        return self.post("/v1.0/cmdb/scan/start", json_body=body)

    def stop_scan(self, url, uuid):
        return self.post("/v1.0/cmdb/scan/stop", json_body={"url": url, "uuid": uuid})

    def set_scan_schedule(self, body):
        return self.post("/v1.0/cmdb/scanconfig/scanschedule", json_body=body)

    def update_scan_config(self, section, url, uuid, config):
        api_section = SCANCONFIG_SECTIONS.get(section)
        if not api_section:
            raise FortiDASTError(
                "Unknown scan config section '{0}'. Expected one of: {1}.".format(
                    section, ", ".join(sorted(SCANCONFIG_SECTIONS))))
        body = dict(config or {})
        body.setdefault("url", url)
        body.setdefault("uuid", uuid)
        return self.post("/v1.0/cmdb/scanconfig/{0}".format(api_section),
                         json_body=body)

    # ------------------------------------------------------------------
    # query (read) endpoints -- basic key suffices
    # ------------------------------------------------------------------

    def assets(self, user):
        return self.get("/v1.0/query/allassets", params={"user": user})

    def scan_status(self, url, uuid):
        return self.get("/v1.0/query/scanstatus", params={"url": url, "uuid": uuid})

    def auth_status(self, url, uuid):
        return self.get("/v1.0/query/authstatus", params={"url": url, "uuid": uuid})

    def results(self, url, uuid):
        return self.get("/v1.0/query/results", params={"url": url, "uuid": uuid})

    def scan_summary(self, url, uuid):
        return self.get("/v1.0/query/scansummaryresults",
                        params={"url": url, "uuid": uuid})

    def uri_scan_summary(self, url, uuid, api=False):
        return self.get("/v1.0/query/uriscansummary/apiresult" if api
                        else "/v1.0/query/uriscansummary",
                        params={"url": url, "uuid": uuid})

    def recon_results(self, url, uuid):
        return self.get("/v1.0/query/recon_results", params={"url": url, "uuid": uuid})

    def json_report(self, url, uuid):
        return self.get("/v1.0/query/jsonreport", params={"url": url, "uuid": uuid})

    def xml_report(self, url, uuid):
        return self.get("/v1.0/query/xmlreport", params={"url": url, "uuid": uuid})

    def scan_schedule(self, url, uuid):
        return self.get("/v1.0/query/scanschedule", params={"url": url, "uuid": uuid})

    def owasp_categories(self, url, uuid):
        return self.get("/v1.0/query/owaspcategorylist",
                        params={"url": url, "uuid": uuid})

    # UI link generators: scanresulturl / scanconfigurl / cvssseverityurl /
    # owaspcaturl / owaspcatsevrurl.
    def ui_link(self, url, uuid, link_type, severity=None, category=None):
        endpoints = {
            "scan_result": ("scanresulturl", False),
            "scan_config": ("scanconfigurl", False),
            "cvss_severity": ("cvssseverityurl", True),
            "owasp_category": ("owaspcaturl", True),
            "owasp_severity": ("owaspcatsevrurl", True),
        }
        entry = endpoints.get(link_type)
        if entry is None:
            raise FortiDASTError(
                "Unknown link_type '{0}'. Expected one of: {1}.".format(
                    link_type, ", ".join(sorted(endpoints))))
        endpoint, wants_severity = entry
        params = {"url": url, "uuid": uuid}
        if wants_severity:
            if not severity:
                raise FortiDASTError(
                    "Severity is required for the '{0}' link type.".format(link_type))
            params["severity"] = severity
            if link_type == "owasp_severity":
                if not category:
                    raise FortiDASTError(
                        "Category is required for the 'owasp_severity' link type.")
                params["category"] = category
        return self.get("/v1.0/query/{0}".format(endpoint), params=params)

    # ------------------------------------------------------------------
    # health
    # ------------------------------------------------------------------

    def healthcheck(self):
        """Cheap authenticated canary.

        GET allassets without its required `user` parameter: a working key gets
        past authentication and the server answers 400 "Invalid args"; a bad or
        expired key answers 401/403 with the key error. Anything else is a
        connectivity or license problem.
        """
        url = "{0}/v1.0/query/allassets".format(self.base_url)
        try:
            resp = self.session.get(url, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            raise FortiDASTError(
                "Could not reach FortiDAST at {0}: {1}".format(self.base_url, e))
        if resp.status_code in (200, 400, 405):
            return True
        raise FortiDASTError(_error_text(resp))


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------

def _error_text(resp):
    """Extract the server's message from a FortiDAST error response."""
    try:
        body = resp.json()
    except ValueError:
        body = None
    status = body.get("Status") if isinstance(body, dict) else None
    if isinstance(status, dict):
        status = status.get("status") or status.get("message") or str(status)
    message = status or (resp.text[:300] if resp.text else "")
    detail = {
        401: " (check the API key: expired, revoked, or a basic key used for a "
             "write operation)",
        403: " (API key not found or not authorized for this operation)",
    }.get(resp.status_code, "")
    return "FortiDAST API error (HTTP {0}): {1}{2}".format(
        resp.status_code, message, detail)


def max_severity(findings):
    """Strongest severity across findings; None when there are none."""
    found = set()
    for f in findings or []:
        canon = SEVERITY_CANON.get(str((f or {}).get("severity", "")).strip().lower())
        if canon:
            found.add(canon)
    for level in SEVERITY_ORDER:
        if level in found:
            return level
    return None


def severity_counts(findings):
    """{Critical: n, High: n, ...} over a findings list."""
    counts = dict((level, 0) for level in SEVERITY_ORDER)
    for f in findings or []:
        canon = SEVERITY_CANON.get(str((f or {}).get("severity", "")).strip().lower())
        if canon:
            counts[canon] += 1
    return counts


def parse_epoch(value):
    """Best-effort ISO-8601 -> epoch seconds. FortiDAST timestamps have been
    seen with lowercase 't'/'z' ("2021-06-03t14:21:29.811522z"), which
    datetime.fromisoformat rejects before 3.11, so normalize first.
    Returns None when the value is missing or unparseable."""
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
