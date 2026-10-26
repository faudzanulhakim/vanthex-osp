"""Server actions for the VANTHEX front-end — Python port of the artifact's
TypeScript actions module (server/src/actions.ts).

This module stores nothing itself (except transient mobile-upload
staging, see below): it is a live client of the VANTHEX service running
on this machine at http://127.0.0.1:<port>. Every action calls that
service over HTTP; the admin password is read from the PTK_ADMIN_PW
environment variable only and is never included in any response, so it
never reaches the client.

Wire contract (handled by the integrator):
    handle_action(name, args, port) -> (http_status, envelope)
    success:  (200, {"data": <result>})
    unknown:  (404, {"error": "unknown action"})
    handler exception: (500, {"error": str(exc)[:300]})

Service-access semantics mirror the TypeScript original exactly:
redirects are never auto-followed (the service answers an expired
session with a 302 to /login, not a 401 — following it would land on
the HTML login page with status 200 and make every action wrongly
report the service as down); a 401 or a redirect to /login drops the
cached session, re-logs in once, and retries once; a non-login
redirect is followed once manually and only when same-origin, because
the session cookie is a credential and must never be forwarded to
another origin.

The TypeScript original staged chunked mobile uploads in the artifact
database (ctx.db tables mobile_uploads / mobile_upload_chunks). Here
that staging lives on the filesystem instead:
    <app dir>/uploads_apk/.staging/<upload_id>/meta.json
    <app dir>/uploads_apk/.staging/<upload_id>/chunk-NNNN.b64
with identical client-visible protocol and result shapes, including
the 1-hour prune of abandoned uploads on startMobileUpload, per-index
idempotent chunk replacement, reassembly size verification on finish,
and cleanup on finish/cancel.

Contract notes (verified against app2.py / store.py / vulnscan2.py /
passive.py):
  - Scan types: vulnscan | ports | subdomains | dirs | ssl | headers |
    passive (non-intrusive public-lookup reconnaissance — the service
    does NOT require authorized: true for type "passive", but the
    target allowlist still applies) | udp | vhost | hybrid | syn
    (UDP protocol probes, virtual-host enum, passive->active hybrid,
    raw-socket SYN — all four are ACTIVE scans and require
    authorized: true; a SYN scan without raw-socket privilege returns
    available: false + an INFO finding instead of pretending ports
    are filtered).
  - Jobs may sit in status "queued" (jobgate priority queue: global
    limit 3, per-user 2) before "running"; terminal states stay
    done | error | cancelled.
  - Finding suppressions: GET/POST /api/suppressions and
    POST /api/suppressions/delete; NVD cache + sync state via
    GET /api/nvd/status and POST /api/nvd/sync; job queue snapshot
    via GET /api/metrics (jobs.active / jobs.waiting / limits).
  - Target secrets (service v3.18): GET/POST /api/secrets and
    POST /api/secrets/delete — admin-only and WRITE-ONLY: the list
    returns metadata only ({id, name, host, kind, username,
    created_by, ts}); secret values are encrypted at rest on the
    service and never returned. POST /api/scan accepts an optional
    secret_id that the service decrypts in memory to apply the
    credential — forwarded here only for the vulnscan and hybrid
    types; this module never sees or stores any secret value.
  - Mobile analysis runs in a sandbox subprocess on the service; the
    result meta carries sandbox {enabled, timeout_s, mem_mb, cpu_s},
    surfaced verbatim by the client.
  - Findings carry an `origin` field ("passive" | "active"):
    vulnscan2 defaults to "active", passive.py tags "passive". Since
    service v3.18.1 the findings table persists the origin column, so
    saved scans return it per row and map_finding passes it through;
    for any row still missing it, getScanDetail recovers it from the
    stored full result (tool_result.findings) as a fallback.
  - Profiles: passive-quick, passive-full, active-standard,
    active-deep, enterprise-full. Active scans (and every
    non-vulnscan tool except "passive") are rejected by the service
    unless the body carries authorized: true.
  - Reports: GET /report/<id> (HTML), GET /report/<id>?fmt=docx (DOCX).
  - Job polling: GET /api/job/<id> -> {status, log[], result, elapsed}.
"""

from __future__ import annotations

import base64
import json
import math
import os
import pathlib
import re
import shutil
import threading
import time
import urllib.parse
import uuid

import requests

# --- Service access ---------------------------------------------------------

# The error strings below keep the literal port 5000 exactly as the
# TypeScript original writes them, whatever port is actually in use.
FETCH_TIMEOUT_S = 12.0

# Globe layers on a cold cache refresh synchronously (sats: CelesTrak
# download + SGP4 propagation of thousands of objects; fires: FIRMS
# fetch) and exceed the 12 s default — the client then gets
# error/serviceDown and shows 0, even though the server-side refresh
# still completes. Globe handlers pass this budget instead. It matches
# the artifact worker's 120 s cap, which remains the ceiling for any
# single globe read (2026-10-26, diagnosed 12 s timeout race).
GLOBE_TIMEOUT_MS = 120000

_session_cookie = ""
_session_exp = 0.0  # epoch milliseconds, like Date.now()
_login_stage_error = ""
_session_lock = threading.RLock()

_NO_BODY = object()  # distinguishes "no body" from an explicit {} body


def _down_result(error: str) -> dict:
    return {
        "down": True,
        "status": 0,
        "json": None,
        "text": "",
        "base64": "",
        "contentType": "",
        "error": error,
    }


def _err_text(exc: BaseException) -> str:
    return str(exc)


def _extract_session_cookie(resp: "requests.Response") -> str:
    """First ptk_session value found in the response's Set-Cookie
    headers (mirrors getSetCookie()[0] ?? headers.get('set-cookie'))."""
    candidates: list[str] = []
    try:
        raw_headers = resp.raw.headers  # urllib3 HTTPHeaderDict
        get_list = getattr(raw_headers, "getlist", None) or getattr(
            raw_headers, "get_all", None
        )
        if get_list is not None:
            candidates.extend(get_list("Set-Cookie") or [])
    except Exception:
        pass
    combined = resp.headers.get("set-cookie")
    if combined:
        candidates.append(combined)
    for cand in candidates:
        m = re.search(r"ptk_session=([^;]+)", cand)
        if m and m.group(1):
            return m.group(1)
    try:
        value = resp.cookies.get("ptk_session")
        if value:
            return value
    except Exception:
        pass
    return ""


def _svc_login(port: int) -> bool:
    """Log in to the service as admin and cache the session cookie for
    6 hours. Caller holds _session_lock (an RLock)."""
    global _session_cookie, _session_exp, _login_stage_error
    _login_stage_error = ""
    password = os.environ.get("PTK_ADMIN_PW", "")
    if not password:
        _login_stage_error = (
            "Service admin password not found in the service env file."
        )
        return False
    try:
        resp = requests.post(
            f"http://127.0.0.1:{port}/api/login",
            json={"username": "admin", "password": password},
            # allow_redirects=False — this request carries the admin
            # password in its body; a 307/308 must never be allowed to
            # resend that body to another origin. The login endpoint
            # answers 200 directly, so any redirect here is an error,
            # handled by the not-ok branch below.
            allow_redirects=False,
            timeout=FETCH_TIMEOUT_S,
        )
    except requests.RequestException as exc:
        _login_stage_error = (
            f"VANTHEX service at 127.0.0.1:5000 is unreachable "
            f"({_err_text(exc)})."
        )
        return False
    if not (200 <= resp.status_code < 300):
        _login_stage_error = f"Service login rejected (HTTP {resp.status_code})."
        return False
    value = _extract_session_cookie(resp)
    if not value:
        _login_stage_error = "The service did not return a session cookie."
        return False
    _session_cookie = f"ptk_session={value}"
    _session_exp = time.time() * 1000.0 + 6 * 3600 * 1000
    return True


def _ensure_session(port: int) -> bool:
    with _session_lock:
        if _session_cookie and time.time() * 1000.0 < _session_exp:
            return True
        return _svc_login(port)


def _relogin(port: int) -> bool:
    """Drop the cached session and log in again (stale-session path)."""
    global _session_cookie, _session_exp
    with _session_lock:
        _session_cookie = ""
        _session_exp = 0.0
        return _svc_login(port)


def _is_session_rejected(status: int, location: str) -> bool:
    # A session is rejected either as a bare 401 or as a redirect to
    # the login page; both mean "log in again", never "service is down".
    if status == 401:
        return True
    if 300 <= status < 400:
        return "/login" in (location or "")
    return False


def _is_redirect(status: int, location: str) -> bool:
    return 300 <= status < 400 and bool(location)


def _origin_of(url: str) -> tuple:
    parts = urllib.parse.urlparse(url)
    try:
        port = parts.port
    except ValueError:
        port = None
    return (parts.scheme, parts.hostname, port)


def call_service(
    port: int,
    method: str,
    path: str,
    body=_NO_BODY,
    binary: bool = False,
    timeout_ms: int | None = None,
) -> dict:
    """Call the VANTHEX service with the cached admin session.

    Returns a CallResult-shaped dict:
        {"down", "status", "json", "text", "base64", "contentType",
         "error"}
    """
    # Forwarding a full mobile package (tens of MB of base64 JSON over
    # loopback) can take longer than the default API budget; callers
    # that carry such payloads pass a larger timeout_ms.
    if timeout_ms is not None:
        timeout_s = timeout_ms / 1000.0
    elif binary:
        timeout_s = 30.0
    else:
        timeout_s = FETCH_TIMEOUT_S
    base = f"http://127.0.0.1:{port}"

    if not _ensure_session(port):
        return _down_result(
            _login_stage_error or "Could not log in to the VANTHEX service."
        )

    def do_fetch() -> "requests.Response":
        headers = {"Cookie": _session_cookie}
        kwargs: dict = {}
        if body is not _NO_BODY:
            headers["Content-Type"] = "application/json"
            kwargs["json"] = body
        return requests.request(
            method,
            base + path,
            headers=headers,
            allow_redirects=False,
            timeout=timeout_s,
            **kwargs,
        )

    try:
        resp = do_fetch()
        location = resp.headers.get("location") or ""
        if _is_session_rejected(resp.status_code, location):
            # Stale cached session (e.g. the service restarted and
            # forgot it): drop it, log in again, and retry the request
            # once with the fresh cookie instead of declaring the
            # service unreachable.
            if _relogin(port):
                resp = do_fetch()
                location = resp.headers.get("location") or ""
                if _is_session_rejected(resp.status_code, location):
                    return _down_result(
                        "The service session was rejected even after "
                        "re-login. Please try again shortly."
                    )
            else:
                return _down_result(
                    _login_stage_error
                    or "Re-login to the VANTHEX service failed."
                )
        location = resp.headers.get("location") or ""
        if _is_redirect(resp.status_code, location):
            # A non-login redirect (none of the API routes are expected
            # to send one, but follow it manually once, as auto-follow
            # did before, so behavior for any legitimate redirect is
            # unchanged). Only same-origin targets are followed: the
            # session cookie is a credential and must never be
            # forwarded to another origin, whatever Location claims.
            target = urllib.parse.urljoin(base, location)
            if _origin_of(target) != _origin_of(base):
                return _down_result(
                    "The service returned a redirect to an unexpected "
                    "address; the request was aborted."
                )
            resp = requests.get(
                target,
                headers={"Cookie": _session_cookie},
                allow_redirects=False,
                timeout=timeout_s,
            )
            location = resp.headers.get("location") or ""
            if _is_session_rejected(resp.status_code, location):
                return _down_result(
                    "The service session was rejected. Please try "
                    "again shortly."
                )
    except requests.RequestException as exc:
        return _down_result(
            f"VANTHEX service at 127.0.0.1:5000 is unreachable "
            f"({_err_text(exc)})."
        )

    status = resp.status_code
    content_type = resp.headers.get("content-type") or ""
    if binary:
        return {
            "down": False,
            "status": status,
            "json": None,
            "text": "",
            "base64": base64.b64encode(resp.content).decode("ascii")
            if 200 <= status < 300
            else "",
            "contentType": content_type,
            "error": "" if 200 <= status < 300 else f"Service menjawab HTTP {status}",
        }
    resp.encoding = "utf-8"
    text = resp.text
    parsed = _json_parse(text)
    error = ""
    if status >= 400:
        if is_record(parsed) and isinstance(parsed.get("error"), str):
            error = parsed["error"]
        else:
            error = f"Service menjawab HTTP {status}"
    return {
        "down": False,
        "status": status,
        "json": parsed,
        "text": text,
        "base64": "",
        "contentType": content_type,
        "error": error,
    }


# --- Mapping helpers (JS coercion semantics) --------------------------------


def is_record(v) -> bool:
    return isinstance(v, dict)


def _json_parse(text: str):
    """JSON.parse equivalent: strict (NaN/Infinity literals rejected),
    returns None on any parse failure."""

    def _bad_constant(_name: str):
        raise ValueError("invalid JSON constant")

    try:
        return json.loads(text, parse_constant=_bad_constant)
    except Exception:
        return None


def _js_number_str(n: float) -> str:
    if math.isnan(n):
        return "NaN"
    if math.isinf(n):
        return "Infinity" if n > 0 else "-Infinity"
    if n == int(n) and abs(n) < 1e21:
        return str(int(n))
    r = repr(n)
    # Python pads exponents ("1e-07"); JS does not ("1e-7").
    if "e" in r or "E" in r:
        mantissa, _, exp = r.replace("E", "e").partition("e")
        sign = ""
        if exp.startswith(("+", "-")):
            sign, exp = exp[0], exp[1:]
        exp = exp.lstrip("0") or "0"
        r = f"{mantissa}e{sign}{exp}"
    return r


def as_str(v) -> str:
    if isinstance(v, str):
        return v
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return _js_number_str(v)
    if isinstance(v, list):
        return ",".join("" if item is None else as_str(item) for item in v)
    if isinstance(v, dict):
        return "[object Object]"
    return str(v)


def _js_number(v) -> float:
    """JS Number(v) for the JSON-shaped values seen here."""
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        return float(v)
    if v is None:
        return 0.0
    if isinstance(v, str):
        s = v.strip()
        if s == "":
            return 0.0
        if s in ("Infinity", "+Infinity"):
            return math.inf
        if s == "-Infinity":
            return -math.inf
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", s):
            return float(int(s, 16))
        if re.fullmatch(r"0[bB][01]+", s):
            return float(int(s[2:], 2))
        if re.fullmatch(r"0[oO][0-7]+", s):
            return float(int(s[2:], 8))
        if re.fullmatch(r"[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?", s):
            return float(s)
        return math.nan
    return math.nan


def _num_out(n: float):
    if n == int(n) and abs(n) < 1e21:
        return int(n)
    return n


def as_num(v):
    n = v if isinstance(v, (int, float)) and not isinstance(v, bool) else _js_number(v)
    n = float(n)
    return _num_out(n) if math.isfinite(n) else 0


def as_num_or_null(v):
    if v is None:
        return None
    n = v if isinstance(v, (int, float)) and not isinstance(v, bool) else _js_number(v)
    n = float(n)
    return _num_out(n) if math.isfinite(n) else None


def num_record(v) -> dict:
    out: dict = {}
    if is_record(v):
        for k, val in v.items():
            out[k] = as_num(val)
    return out


def parse_summary(v) -> dict:
    if isinstance(v, str):
        parsed = _json_parse(v)
        return num_record(parsed) if parsed is not None else {}
    return num_record(v)


def js_truthy(v) -> bool:
    """JS truthiness: null/undefined, false, 0, NaN and "" are falsy;
    empty objects and arrays are truthy."""
    if v is None or v is False:
        return False
    if isinstance(v, bool):
        return True
    if isinstance(v, (int, float)):
        return v != 0 and v == v
    if isinstance(v, str):
        return len(v) > 0
    return True


def js_stringify(v, pretty: bool = False) -> str:
    """JSON.stringify equivalent (compact, or 2-space pretty)."""
    if pretty:
        return json.dumps(v, ensure_ascii=False, indent=2)
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def _enc(s) -> str:
    """encodeURIComponent equivalent."""
    return urllib.parse.quote(str(s), safe="-_.!~*'()")


def map_finding(raw) -> dict:
    r = raw if is_record(raw) else {}
    return {
        "id": as_num(r.get("id")),
        "scanId": as_str(r.get("scan_id")),
        "severity": as_str(r.get("severity")) or "INFO",
        "title": as_str(r.get("title")),
        "description": as_str(r.get("description")),
        "evidence": as_str(r.get("evidence")),
        "cwe": as_str(r.get("cwe")),
        "owasp": as_str(r.get("owasp")),
        "cvss": as_num(r.get("cvss")),
        "remediation": as_str(r.get("remediation")),
        "confidence": as_str(r.get("confidence")) or "probable",
        "status": as_str(r.get("status")) or "open",
        "location": as_str(r.get("location")),
        "param": as_str(r.get("param")),
        "target": as_str(r.get("target")),
        "assignee": as_str(r.get("assignee")),
        "dueDate": as_str(r.get("due_date")),
        "origin": as_str(r.get("origin")),
    }


def map_tech(raw) -> dict:
    empty = {
        "category": "",
        "version": "",
        "evidence": "",
        "source": "",
        "confidence": "",
        "verified": False,
        "evidenceList": [],
        "sources": [],
        "detail": "",
        "cves": [],
    }
    if isinstance(raw, str):
        return {"name": raw, **empty}
    r = raw if is_record(raw) else {}

    def str_list(v) -> list:
        if isinstance(v, list):
            return [s for s in (as_str(item) for item in v) if len(s) > 0]
        return []

    category = r.get("category")
    if not js_truthy(category):
        category = r.get("cat")
    cves = []
    for c in r.get("cves") if isinstance(r.get("cves"), list) else []:
        rec = c if is_record(c) else {}
        cves.append(
            {
                "id": as_str(rec.get("id")),
                "cvss": as_num(rec.get("cvss")),
                "severity": as_str(rec.get("severity")),
                "source": as_str(rec.get("source")),
            }
        )
    return {
        "name": as_str(r.get("name")),
        "category": as_str(category),
        "version": as_str(r.get("version")),
        "evidence": as_str(r.get("evidence")),
        "source": as_str(r.get("source")),
        "confidence": as_str(r.get("confidence")),
        "verified": r.get("verified") is True,
        "evidenceList": str_list(r.get("evidence_list")),
        "sources": str_list(r.get("sources")),
        "detail": as_str(r.get("detail")),
        "cves": cves,
    }


def map_scan_row(raw) -> dict:
    r = raw if is_record(raw) else {}
    return {
        "id": as_str(r.get("id")),
        "target": as_str(r.get("target")),
        "scanType": as_str(r.get("scan_type")) or "vulnscan",
        "profile": as_str(r.get("profile")),
        "startedAt": as_num(r.get("started_at")),
        "status": as_str(r.get("status")),
        "overallRisk": as_str(r.get("overall_risk")) or "-",
        "summary": parse_summary(r.get("summary")),
    }


def _empty_stats() -> dict:
    return {
        "totalScans": 0,
        "totalTargets": 0,
        "bySeverity": {},
        "byConfidence": {},
        "byOwasp": {},
        "recent": [],
        "trend": [],
        "topTargets": [],
        "recentFindings": [],
        "postureScore": None,
        "postureTrend": [],
        "crosscheckMatrix": {},
        "byTriageStatus": {},
        "system": {
            "available": False,
            "appUptimeS": 0,
            "appMemMb": 0,
            "hostCpuPercent": 0,
            "hostMemPercent": 0,
            "jobsActive": 0,
        },
    }


def _empty_engine() -> dict:
    return {
        "version": "",
        "engine": "",
        "libraries": {},
        "htmlParser": "",
        "profiles": {},
        "scanTypes": [],
        "verificationLayers": [],
        "mobile": {
            "analyzer": "",
            "parser": "",
            "available": False,
            "maxApkMb": 0,
            "scopeNote": "",
        },
    }


def _service_error_result(res: dict) -> dict:
    """The serviceErrorSchema shape shared by the simple POST actions:
    {serviceDown, error} where error is only non-empty when the
    service is down or answered with an HTTP error."""
    if res["down"]:
        error = res["error"]
    elif res["status"] >= 400:
        error = res["error"]
    else:
        error = ""
    return {"serviceDown": res["down"], "error": error}


def _arg_str(args: dict, key: str, default: str = "") -> str:
    v = args.get(key, default)
    return v if isinstance(v, str) else default



# --- Actions -----------------------------------------------------------------


def _a_get_stats(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/stats")
    if res["down"] or not is_record(res["json"]):
        return {
            **_empty_stats(),
            "serviceDown": True,
            "error": res["error"] or "Service unreachable.",
        }
    j = res["json"]
    recent = j.get("recent") if isinstance(j.get("recent"), list) else []
    trend = j.get("trend") if isinstance(j.get("trend"), list) else []
    top = j.get("top_targets") if isinstance(j.get("top_targets"), list) else []
    feed = (
        j.get("recent_findings")
        if isinstance(j.get("recent_findings"), list)
        else []
    )
    crosscheck: dict = {}
    matrix = j.get("crosscheck_matrix")
    if is_record(matrix):
        for k, v in matrix.items():
            crosscheck[k] = num_record(v)
    sys_rec = j.get("system") if is_record(j.get("system")) else {}
    return {
        "totalScans": as_num(j.get("total_scans")),
        "totalTargets": as_num(j.get("total_targets")),
        "bySeverity": num_record(j.get("by_severity")),
        "byConfidence": num_record(j.get("by_confidence")),
        "byOwasp": num_record(j.get("by_owasp")),
        "recent": [
            {
                "target": as_str((r if is_record(r) else {}).get("target")),
                "overallRisk": as_str((r if is_record(r) else {}).get("overall_risk")) or "-",
                "startedAt": as_num((r if is_record(r) else {}).get("started_at")),
                "profile": as_str((r if is_record(r) else {}).get("profile")),
            }
            for r in recent
        ],
        "trend": [
            {
                "date": as_str((r if is_record(r) else {}).get("date")),
                "scans": as_num((r if is_record(r) else {}).get("scans")),
            }
            for r in trend
        ],
        "topTargets": [
            {
                "target": as_str((r if is_record(r) else {}).get("target")),
                "latestRisk": as_str((r if is_record(r) else {}).get("latest_risk")) or "-",
                "latestScore": as_num_or_null((r if is_record(r) else {}).get("latest_score")),
                "openFindings": as_num((r if is_record(r) else {}).get("open_findings")),
                "lastScan": as_num((r if is_record(r) else {}).get("last_scan")),
                "latestScanId": as_str((r if is_record(r) else {}).get("latest_scan_id")),
            }
            for r in top
        ],
        "recentFindings": [
            {
                "severity": as_str((r if is_record(r) else {}).get("severity")) or "INFO",
                "title": as_str((r if is_record(r) else {}).get("title")),
                "confidence": as_str((r if is_record(r) else {}).get("confidence")) or "probable",
                "cvss": as_num((r if is_record(r) else {}).get("cvss")),
                "target": as_str((r if is_record(r) else {}).get("target")),
                "startedAt": as_num((r if is_record(r) else {}).get("started_at")),
            }
            for r in feed
        ],
        "postureScore": as_num_or_null(j.get("posture_score")),
        "postureTrend": [
            {
                "scanId": as_str((r if is_record(r) else {}).get("scan_id")),
                "target": as_str((r if is_record(r) else {}).get("target")),
                "scanType": as_str((r if is_record(r) else {}).get("scan_type")),
                "profile": as_str((r if is_record(r) else {}).get("profile")),
                "startedAt": as_num((r if is_record(r) else {}).get("started_at")),
                "overallRisk": as_str((r if is_record(r) else {}).get("overall_risk")) or "-",
                "score": as_num((r if is_record(r) else {}).get("score")),
            }
            for r in (
                j.get("posture_trend")
                if isinstance(j.get("posture_trend"), list)
                else []
            )
        ],
        "crosscheckMatrix": crosscheck,
        "byTriageStatus": num_record(j.get("by_triage_status")),
        "system": {
            "available": len(sys_rec) > 0,
            "appUptimeS": as_num(sys_rec.get("app_uptime_s")),
            "appMemMb": as_num(sys_rec.get("app_mem_mb")),
            "hostCpuPercent": as_num(sys_rec.get("host_cpu_percent")),
            "hostMemPercent": as_num(sys_rec.get("host_mem_percent")),
            "jobsActive": as_num(sys_rec.get("jobs_active")),
        },
        "serviceDown": False,
        "error": "",
    }


def _a_get_engine(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/engine")
    if res["down"] or not is_record(res["json"]):
        return {
            **_empty_engine(),
            "serviceDown": True,
            "error": res["error"] or "Service unreachable.",
        }
    j = res["json"]
    profiles: dict = {}
    if is_record(j.get("profiles")):
        for k, v in j["profiles"].items():
            rec = v if is_record(v) else {}
            profiles[k] = {
                "checks": as_num(rec.get("checks")),
                "checkNames": [
                    as_str(s)
                    for s in (
                        rec.get("check_names")
                        if isinstance(rec.get("check_names"), list)
                        else []
                    )
                ],
            }
    libs: dict = {}
    if is_record(j.get("libraries")):
        for k, v in j["libraries"].items():
            libs[k] = v is True
    mob = j.get("mobile") if is_record(j.get("mobile")) else {}
    return {
        "version": as_str(j.get("version")),
        "engine": as_str(j.get("engine")),
        "libraries": libs,
        "htmlParser": as_str(j.get("html_parser")),
        "profiles": profiles,
        "scanTypes": [
            as_str(s)
            for s in (j.get("scan_types") if isinstance(j.get("scan_types"), list) else [])
        ],
        "verificationLayers": [
            {
                "name": as_str((r if is_record(r) else {}).get("name")),
                "detail": as_str((r if is_record(r) else {}).get("detail")),
            }
            for r in (
                j.get("verification_layers")
                if isinstance(j.get("verification_layers"), list)
                else []
            )
        ],
        "mobile": {
            "analyzer": as_str(mob.get("analyzer")),
            "parser": as_str(mob.get("parser")),
            "available": mob.get("available") is True,
            "maxApkMb": as_num(mob.get("max_apk_mb")),
            "scopeNote": as_str(mob.get("scope_note")),
        },
        "serviceDown": False,
        "error": "",
    }


def _a_get_scans(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/scans")
    if res["down"] or not isinstance(res["json"], list):
        return {
            "scans": [],
            "serviceDown": True,
            "error": res["error"] or "Service unreachable.",
        }
    return {
        "scans": [map_scan_row(r) for r in res["json"]],
        "serviceDown": False,
        "error": "",
    }


def _a_get_scan_detail(args: dict, port: int) -> dict:
    scan_id = args.get("scanId")
    res = call_service(port, "GET", f"/api/scan/{_enc(scan_id)}")
    base = {
        "findings": [],
        "technologies": [],
        "techProfile": [],
        "riskScore": None,
        "durationS": None,
        "summaryByConfidence": {},
        "toolResultJson": "",
        "engineJson": "",
        "metaJson": "",
        "warnings": [],
        "endpoints": [],
    }
    if res["down"]:
        return {
            "found": False,
            "scan": None,
            **base,
            "serviceDown": True,
            "error": res["error"] or "Service unreachable.",
        }
    if res["status"] == 404 or not is_record(res["json"]):
        return {
            "found": False,
            "scan": None,
            **base,
            "serviceDown": False,
            "error": res["error"] or "Scan not found.",
        }
    j = res["json"]
    findings = j.get("findings") if isinstance(j.get("findings"), list) else []
    # Origin ("passive" | "active"): since service v3.18.1 the findings
    # table persists an origin column and map_finding reads it directly
    # from each row. For any row that still arrives without one, fall
    # back to recovering it from the stored full result (returned as
    # tool_result for non-vulnscan scans, which includes passive
    # recon), keyed like store._key. A finding with no origin anywhere
    # stays empty and renders no label.
    origin_by_key: dict = {}
    tool_res = j.get("tool_result") if is_record(j.get("tool_result")) else None
    if tool_res is not None and isinstance(tool_res.get("findings"), list):
        for rf in tool_res["findings"]:
            rr = rf if is_record(rf) else {}
            o = as_str(rr.get("origin"))
            if o:
                key = (
                    f"{as_str(rr.get('title'))}|{as_str(rr.get('location'))}"
                    f"|{as_str(rr.get('param'))}"
                )
                origin_by_key[key] = o
    mapped_findings = []
    for f in findings:
        mf = map_finding(f)
        if not mf["origin"]:
            o = origin_by_key.get(
                f"{mf['title']}|{mf['location']}|{mf['param']}"
            )
            if o:
                mf["origin"] = o
        mapped_findings.append(mf)
    # Honest lookup-failure warnings live in the stored full result and
    # are mirrored by the service into engine.warnings for every type.
    engine_rec = j.get("engine") if is_record(j.get("engine")) else {}
    warnings = [
        w
        for w in (
            as_str(w)
            for w in (
                engine_rec.get("warnings")
                if isinstance(engine_rec.get("warnings"), list)
                else []
            )
        )
        if len(w) > 0
    ]
    # v3.5: the technology profile is read from the `tech_profile`
    # field of the same scan detail response; the legacy `technologies`
    # field is an alias with identical content, used as a fallback when
    # `tech_profile` is absent/empty (older scans / older service).
    # v3.13: passive recon keeps its profile inside meta.tech_profile.
    if isinstance(j.get("tech_profile"), list) and len(j["tech_profile"]) > 0:
        raw_profile = j["tech_profile"]
    elif isinstance(j.get("technologies"), list):
        raw_profile = j["technologies"]
    else:
        raw_profile = []
    if len(raw_profile) == 0:
        meta_rec = j.get("meta") if is_record(j.get("meta")) else {}
        if isinstance(meta_rec.get("tech_profile"), list):
            raw_profile = meta_rec["tech_profile"]
    tech_items = [map_tech(t) for t in raw_profile]
    return {
        "found": True,
        "scan": map_scan_row(j.get("scan")),
        "findings": mapped_findings,
        "technologies": tech_items,
        "techProfile": tech_items,
        "riskScore": as_num_or_null(j.get("risk_score")),
        "durationS": as_num_or_null(j.get("duration_s")),
        "summaryByConfidence": num_record(j.get("summary_by_confidence")),
        "toolResultJson": js_stringify(j["tool_result"], pretty=True)
        if js_truthy(j.get("tool_result"))
        else "",
        "engineJson": js_stringify(j["engine"]) if js_truthy(j.get("engine")) else "",
        "metaJson": js_stringify(j["meta"]) if js_truthy(j.get("meta")) else "",
        "warnings": warnings,
        "endpoints": [
            {
                "url": as_str((e if is_record(e) else {}).get("url")),
                "host": as_str((e if is_record(e) else {}).get("host")),
                "scheme": as_str((e if is_record(e) else {}).get("scheme")),
            }
            for e in (j.get("endpoints") if isinstance(j.get("endpoints"), list) else [])
        ],
        "serviceDown": False,
        "error": "",
    }


def _a_get_scan_diff(args: dict, port: int) -> dict:
    scan_id = args.get("scanId")
    res = call_service(port, "GET", f"/api/scan/{_enc(scan_id)}/diff")
    if res["down"] or not is_record(res["json"]):
        return {
            "found": False,
            "previousScanId": None,
            "previousStartedAt": None,
            "newTitles": [],
            "resolvedTitles": [],
            "unchanged": 0,
            "serviceDown": res["down"],
            "error": res["error"] or "Diff not available.",
        }
    j = res["json"]
    return {
        "found": True,
        "previousScanId": j.get("previous_scan_id")
        if isinstance(j.get("previous_scan_id"), str)
        else None,
        "previousStartedAt": as_num_or_null(j.get("previous_started_at")),
        "newTitles": [
            as_str(s) for s in (j.get("new") if isinstance(j.get("new"), list) else [])
        ],
        "resolvedTitles": [
            as_str(s)
            for s in (j.get("resolved") if isinstance(j.get("resolved"), list) else [])
        ],
        "unchanged": as_num(j.get("unchanged")),
        "serviceDown": False,
        "error": "",
    }


def _a_export_scan(args: dict, port: int) -> dict:
    scan_id = args.get("scanId")
    fmt = args.get("format")
    res = call_service(
        port, "GET", f"/api/scan/{_enc(scan_id)}/export?fmt={fmt}"
    )
    if res["down"] or res["status"] >= 400:
        return {
            "content": "",
            "filename": "",
            "serviceDown": res["down"],
            "error": res["error"] if res["down"] else "Failed to export the scan.",
        }
    return {
        "content": js_stringify(res["json"], pretty=True)
        if fmt == "json" and js_truthy(res["json"])
        else res["text"],
        "filename": f"findings_{scan_id}.{fmt}",
        "serviceDown": False,
        "error": "",
    }


def _a_analyze_mobile(args: dict, port: int) -> dict:
    # Legacy single-shot upload, kept for small packages only. Real
    # APKs/IPAs exceed the action transport's payload limit when sent
    # as one base64 string (the request is rejected with HTTP 422
    # before this handler runs), so the client now uses the chunked
    # flow below (startMobileUpload / uploadMobileChunk /
    # finishMobileUpload); this action remains for API compatibility.
    res = call_service(
        port,
        "POST",
        "/api/mobile/analyze",
        {"filename": args.get("filename"), "data_base64": args.get("dataBase64")},
        timeout_ms=60000,
    )
    if res["down"]:
        return {"jobId": "", "serviceDown": True, "error": res["error"]}
    if res["status"] >= 400 or not is_record(res["json"]):
        return {
            "jobId": "",
            "serviceDown": False,
            "error": res["error"] or "Failed to start the mobile package analysis.",
        }
    return {
        "jobId": as_str(res["json"].get("job_id")),
        "serviceDown": False,
        "error": "",
    }


# --- Chunked mobile upload ---------------------------------------------------
# The client splits the package into 768 KiB raw slices (chosen so the
# size is a multiple of 3: each slice's base64 has no padding and the
# chunk strings concatenate into the exact whole-file base64) and sends
# one action call per slice (~1 MB of base64 per request, far below the
# transport limit that rejected the single-shot upload).
# finishMobileUpload reassembles the chunks, verifies the decoded size
# against the declared total, forwards the package to the service over
# loopback HTTP (not subject to the action transport limit), and
# deletes the stored chunks.
#
# The TypeScript original stored uploads in the artifact database
# (mobile_uploads / mobile_upload_chunks tables); this port stages them
# on the filesystem under uploads_apk/.staging/<upload_id>/ instead —
# meta.json plus one chunk-NNNN.b64 file per slice — with identical
# client-visible behavior.

_STAGING_ROOT = pathlib.Path(__file__).resolve().parent / "uploads_apk" / ".staging"
_UPLOAD_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_CHUNK_FILE_RE = re.compile(r"^chunk-(\d{4})\.b64$")


def _staging_dir(upload_id) -> pathlib.Path | None:
    if not isinstance(upload_id, str) or not _UPLOAD_ID_RE.fullmatch(upload_id):
        return None
    return _STAGING_ROOT / upload_id


def _load_upload(upload_id):
    """(dir, meta) for a staged upload, or None if there is none."""
    d = _staging_dir(upload_id)
    if d is None or not d.is_dir():
        return None
    meta_file = d / "meta.json"
    if not meta_file.is_file():
        return None
    try:
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not is_record(meta):
        return None
    return d, meta


def _chunk_path(d: pathlib.Path, idx: int) -> pathlib.Path:
    return d / f"chunk-{idx:04d}.b64"


def _chunk_indices(d: pathlib.Path) -> list[int]:
    out = []
    for f in d.iterdir():
        m = _CHUNK_FILE_RE.match(f.name)
        if m:
            out.append(int(m.group(1)))
    return sorted(out)


def _cleanup_upload(upload_id) -> None:
    d = _staging_dir(upload_id)
    if d is not None and d.is_dir():
        shutil.rmtree(d, ignore_errors=True)


def _a_start_mobile_upload(args: dict, port: int) -> dict:
    filename = args.get("filename")
    lower = filename.lower() if isinstance(filename, str) else ""
    if not lower.endswith(".apk") and not lower.endswith(".ipa"):
        return {
            "uploadId": "",
            "serviceDown": False,
            "error": "The file must have an .apk or .ipa extension.",
        }
    # Prune abandoned uploads (older than 1 hour) so failed attempts
    # never accumulate package data in the staging area.
    cutoff = time.time() * 1000.0 - 3600 * 1000
    if _STAGING_ROOT.is_dir():
        for child in _STAGING_ROOT.iterdir():
            if not child.is_dir():
                continue
            try:
                meta = json.loads((child / "meta.json").read_text(encoding="utf-8"))
            except Exception:
                continue
            created = meta.get("createdAt") if is_record(meta) else None
            if isinstance(created, (int, float)) and created < cutoff:
                shutil.rmtree(child, ignore_errors=True)
    # Validate the declared shape up front: the chunk writer and the
    # finisher do arithmetic/comparisons on these values, so they are
    # coerced to bounded ints here instead of trusting the client.
    # (512 chunks x 768 KiB and 60 MB both sit far above the real
    # client's needs and match the service's own package cap.)
    try:
        total_chunks = int(args.get("totalChunks"))
        total_size = int(args.get("totalSize"))
    except (TypeError, ValueError):
        total_chunks, total_size = 0, -1
    if not (1 <= total_chunks <= 512) \
            or not (0 <= total_size <= 60 * 1024 * 1024):
        return {
            "uploadId": "",
            "serviceDown": False,
            "error": "Invalid upload declaration (chunk count or total size out of range).",
        }
    upload_id = str(uuid.uuid4())
    d = _STAGING_ROOT / upload_id
    d.mkdir(parents=True, exist_ok=True)
    meta = {
        "filename": filename,
        "totalChunks": total_chunks,
        "totalSize": total_size,
        "createdAt": int(time.time() * 1000),
    }
    (d / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return {"uploadId": upload_id, "serviceDown": False, "error": ""}


def _a_upload_mobile_chunk(args: dict, port: int) -> dict:
    loaded = _load_upload(args.get("uploadId"))
    if loaded is None:
        return {
            "received": 0,
            "serviceDown": False,
            "error": "Upload session not found or expired. Please start the upload again.",
        }
    d, meta = loaded
    index = args.get("index")
    try:
        total_chunks = int(meta.get("totalChunks", 0))
    except (TypeError, ValueError):
        total_chunks = 0
    try:
        idx = int(index) if isinstance(index, (int, float)) \
            and not isinstance(index, bool) else -1
    except (TypeError, ValueError, OverflowError):
        idx = -1
    # Reject negative/fractional indices: a negative index used to pass
    # this check and write a chunk file the finisher could never count.
    if idx < 0 or idx != index or idx >= total_chunks:
        return {
            "received": 0,
            "serviceDown": False,
            "error": "Chunk index out of range for this upload.",
        }
    data = args.get("dataBase64")
    if (
        not isinstance(data, str)
        or len(data) > 2_000_000
        or len(data) % 4 != 0
        or not re.fullmatch(r"[A-Za-z0-9+/=]+", data)
    ):
        return {
            "received": 0,
            "serviceDown": False,
            "error": "Chunk data is not valid base64.",
        }
    # Idempotent per index: a retried chunk replaces the stored one.
    _chunk_path(d, idx).write_text(data, encoding="utf-8")
    received = len(_chunk_indices(d))
    return {"received": received, "serviceDown": False, "error": ""}


def _a_finish_mobile_upload(args: dict, port: int) -> dict:
    upload_id = args.get("uploadId")
    loaded = _load_upload(upload_id)
    if loaded is None:
        return {
            "jobId": "",
            "serviceDown": False,
            "error": "Upload session not found or expired. Please start the upload again.",
        }
    d, meta = loaded
    indices = _chunk_indices(d)
    total = meta.get("totalChunks")
    if len(indices) != total:
        return {
            "jobId": "",
            "serviceDown": False,
            "error": (
                f"Upload incomplete: received {len(indices)} of {total} "
                "chunks. Please try the upload again."
            ),
        }
    # Chunks must be exactly indices 0..totalChunks-1 with no gaps.
    for i in range(len(indices)):
        if indices[i] != i:
            return {
                "jobId": "",
                "serviceDown": False,
                "error": f"Upload is missing chunk {i}. Please try the upload again.",
            }
    data_base64 = "".join(
        _chunk_path(d, i).read_text(encoding="utf-8") for i in indices
    )
    # Verify the reassembled payload decodes to the declared size so a
    # corrupted transfer never reaches the analyzer as a broken zip.
    padding = 2 if data_base64.endswith("==") else 1 if data_base64.endswith("=") else 0
    decoded_size = (len(data_base64) * 3) // 4 - padding
    if decoded_size != meta.get("totalSize"):
        _cleanup_upload(upload_id)
        return {
            "jobId": "",
            "serviceDown": False,
            "error": "The uploaded package failed its size check after reassembly. Please try the upload again.",
        }
    res = call_service(
        port,
        "POST",
        "/api/mobile/analyze",
        {"filename": meta.get("filename"), "data_base64": data_base64},
        timeout_ms=60000,
    )
    # The package has been handed to the service (or definitively
    # rejected by it): the stored chunks are no longer needed. When the
    # service is unreachable the chunks are kept briefly so a retry of
    # finish can succeed without re-uploading; the 1-hour prune in
    # startMobileUpload removes them otherwise.
    if not res["down"]:
        _cleanup_upload(upload_id)
    if res["down"]:
        return {"jobId": "", "serviceDown": True, "error": res["error"]}
    if res["status"] >= 400 or not is_record(res["json"]):
        return {
            "jobId": "",
            "serviceDown": False,
            "error": res["error"] or "Failed to start the mobile package analysis.",
        }
    return {
        "jobId": as_str(res["json"].get("job_id")),
        "serviceDown": False,
        "error": "",
    }


def _a_cancel_mobile_upload(args: dict, port: int) -> dict:
    _cleanup_upload(args.get("uploadId"))
    return {"serviceDown": False, "error": ""}


def _a_get_schedules(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/schedules")
    if res["down"] or not isinstance(res["json"], list):
        return {
            "schedules": [],
            "serviceDown": True,
            "error": res["error"] or "Service unreachable.",
        }
    schedules = []
    for r in res["json"]:
        rec = r if is_record(r) else {}
        schedules.append(
            {
                "id": as_str(rec.get("id")),
                "target": as_str(rec.get("target")),
                "profile": as_str(rec.get("profile")),
                "intervalH": as_num(rec.get("interval_h")),
                "nextRun": as_num(rec.get("next_run")),
                "enabled": as_num(rec.get("enabled")) == 1,
                "createdBy": as_str(rec.get("created_by")),
            }
        )
    return {"schedules": schedules, "serviceDown": False, "error": ""}


def _a_create_schedule(args: dict, port: int) -> dict:
    res = call_service(
        port,
        "POST",
        "/api/schedules",
        {
            "target": args.get("target"),
            "profile": args.get("profile"),
            "interval_h": args.get("intervalH"),
            "authorized": args.get("authorized"),
        },
    )
    return _service_error_result(res)


def _a_delete_schedule(args: dict, port: int) -> dict:
    res = call_service(
        port, "POST", "/api/schedules/delete", {"schedule_id": args.get("scheduleId")}
    )
    return _service_error_result(res)


def _a_toggle_schedule(args: dict, port: int) -> dict:
    res = call_service(
        port,
        "POST",
        "/api/schedules/toggle",
        {"schedule_id": args.get("scheduleId"), "enabled": args.get("enabled")},
    )
    return _service_error_result(res)


def _a_get_audit(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/audit")
    if res["down"] or not isinstance(res["json"], list):
        return {
            "entries": [],
            "serviceDown": True,
            "error": res["error"] or "Service unreachable.",
        }
    entries = []
    for r in res["json"]:
        rec = r if is_record(r) else {}
        entries.append(
            {
                "id": as_num(rec.get("id")),
                "ts": as_num(rec.get("ts")),
                "username": as_str(rec.get("username")),
                "action": as_str(rec.get("action")),
                "detail": as_str(rec.get("detail")),
            }
        )
    return {"entries": entries, "serviceDown": False, "error": ""}


def _a_get_users(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/users")
    if res["down"] or not isinstance(res["json"], list):
        return {
            "users": [],
            "serviceDown": True,
            "error": res["error"] or "Service unreachable.",
        }
    users = []
    for r in res["json"]:
        rec = r if is_record(r) else {}
        users.append(
            {"username": as_str(rec.get("username")), "role": as_str(rec.get("role"))}
        )
    return {"users": users, "serviceDown": False, "error": ""}


def _a_create_user(args: dict, port: int) -> dict:
    res = call_service(
        port,
        "POST",
        "/api/users",
        {"username": args.get("username"), "password": args.get("password")},
    )
    return _service_error_result(res)


def _a_get_findings(args: dict, port: int) -> dict:
    severity = _arg_str(args, "severity")
    status = _arg_str(args, "status")
    q = _arg_str(args, "q")
    params: list[tuple[str, str]] = [("limit", "200")]
    if severity:
        params.append(("severity", severity))
    if status:
        params.append(("status", status))
    if q:
        params.append(("q", q))
    qs = urllib.parse.urlencode(params)
    res = call_service(port, "GET", f"/api/findings?{qs}")
    if res["down"] or not isinstance(res["json"], list):
        return {
            "findings": [],
            "serviceDown": True,
            "error": res["error"] or "Service unreachable.",
        }
    return {
        "findings": [map_finding(f) for f in res["json"]],
        "serviceDown": False,
        "error": "",
    }


def _a_get_assets(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/assets")
    if res["down"] or not isinstance(res["json"], list):
        return {
            "assets": [],
            "serviceDown": True,
            "error": res["error"] or "Service unreachable.",
        }
    assets = []
    for r in res["json"]:
        rec = r if is_record(r) else {}
        assets.append(
            {
                "target": as_str(rec.get("target")),
                "scans": as_num(rec.get("scans")),
                "lastScan": as_num(rec.get("last_scan")),
                "latestRisk": as_str(rec.get("latest_risk")) or "-",
                "latestScore": as_num_or_null(rec.get("latest_score")),
                "latestScanId": as_str(rec.get("latest_scan_id")),
                "profile": as_str(rec.get("profile")),
                "openFindings": as_num(rec.get("open_findings")),
                "criticality": as_str(rec.get("criticality")) or "medium",
                "owner": as_str(rec.get("owner")),
            }
        )
    return {"assets": assets, "serviceDown": False, "error": ""}


def _a_start_scan(args: dict, port: int) -> dict:
    scan_type = args.get("type")
    body: dict = {"type": scan_type, "target": args.get("target")}
    profile = _arg_str(args, "profile", "passive-full")
    authorized = args.get("authorized") is True
    ports = _arg_str(args, "ports")
    subs = args.get("subs") if isinstance(args.get("subs"), list) else []
    words = args.get("words") if isinstance(args.get("words"), list) else []
    cookie = _arg_str(args, "cookie")
    headers_json = _arg_str(args, "headersJson")
    timeout = as_num(args.get("timeout", 0))
    max_pages = as_num(args.get("maxPages", 0))
    proxy = _arg_str(args, "proxy")
    if scan_type in ("vulnscan", "hybrid"):
        body["profile"] = profile
        # Optional stored target credential(s) (Settings -> Target
        # Secrets): only the ids are forwarded; the service decrypts
        # the values in memory. They are forwarded only for the
        # vulnscan and hybrid types.
        if js_truthy(args.get("secretId")):
            body["secret_id"] = args.get("secretId")
        if js_truthy(args.get("secretId2")):
            body["secret_id2"] = args.get("secretId2")
        if js_truthy(args.get("headless")):
            body["headless"] = True
        if cookie:
            body["cookie"] = cookie
        if headers_json:
            parsed = _json_parse(headers_json)
            if parsed is None and _json_parse_error(headers_json):
                return {
                    "jobId": "",
                    "serviceDown": False,
                    "error": "Extra headers are not valid JSON.",
                }
            if is_record(parsed):
                body["headers"] = parsed
        if timeout > 0:
            body["timeout"] = args.get("timeout")
        if max_pages > 0:
            body["max_pages"] = args.get("maxPages")
        if proxy:
            body["proxy"] = proxy
    elif scan_type in ("ports", "udp", "syn"):
        if ports:
            body["ports"] = ports
    elif scan_type == "subdomains":
        if len(subs) > 0:
            body["subs"] = subs
    elif scan_type == "dirs":
        if len(words) > 0:
            body["words"] = words
    if authorized:
        body["authorized"] = True
    res = call_service(port, "POST", "/api/scan", body)
    if res["down"]:
        return {"jobId": "", "serviceDown": True, "error": res["error"]}
    if res["status"] >= 400 or not is_record(res["json"]):
        return {
            "jobId": "",
            "serviceDown": False,
            "error": res["error"] or "Failed to start the scan.",
        }
    return {
        "jobId": as_str(res["json"].get("job_id")),
        "serviceDown": False,
        "error": "",
    }


def _json_parse_error(text: str) -> bool:
    """True when `text` is not valid JSON at all (JSON.parse throws);
    distinct from valid JSON that parses to a non-record (e.g. "5"),
    which the spec accepts silently."""

    def _bad_constant(_name: str):
        raise ValueError("invalid JSON constant")

    try:
        json.loads(text, parse_constant=_bad_constant)
        return False
    except Exception:
        return True


def _a_get_job(args: dict, port: int) -> dict:
    res = call_service(port, "GET", f"/api/job/{_enc(args.get('jobId'))}")
    if res["down"] or not is_record(res["json"]):
        return {
            "status": "unknown",
            "log": [],
            "elapsed": 0,
            "resultJson": "",
            "serviceDown": True,
            "error": res["error"] or "Service unreachable.",
        }
    j = res["json"]
    log = j.get("log") if isinstance(j.get("log"), list) else []
    return {
        "status": as_str(j.get("status")) or "unknown",
        "log": [as_str(line) for line in log],
        "elapsed": as_num(j.get("elapsed")),
        "resultJson": js_stringify(j["result"]) if js_truthy(j.get("result")) else "",
        "serviceDown": False,
        "error": "",
    }


def _a_cancel_job(args: dict, port: int) -> dict:
    res = call_service(
        port, "POST", f"/api/job/{_enc(args.get('jobId'))}/cancel", {}
    )
    return _service_error_result(res)


def _a_delete_scan(args: dict, port: int) -> dict:
    res = call_service(
        port, "POST", "/api/scan/delete", {"scan_id": args.get("scanId")}
    )
    return _service_error_result(res)


def _a_set_finding_status(args: dict, port: int) -> dict:
    res = call_service(
        port,
        "POST",
        "/api/finding/status",
        {"finding_id": args.get("findingId"), "status": args.get("status")},
    )
    return _service_error_result(res)


_REPORT_LANGS = {"en", "id", "es", "fr", "de", "pt",
                 "ru", "ja", "ko", "zh", "ar", "hi"}


def _report_lang(args: dict) -> str:
    """Bahasa laporan dari argumen action `lang` (bahasa UI peminta).
    Absen/tidak valid -> '' (service default ke English)."""
    code = str(args.get("lang") or "").strip().lower().replace("_", "-").split("-")[0]
    return code if code in _REPORT_LANGS else ""


def _a_get_report_docx(args: dict, port: int) -> dict:
    scan_id = args.get("scanId")
    lang = _report_lang(args)
    res = call_service(
        port, "GET",
        f"/report/{_enc(scan_id)}?fmt=docx" + (f"&lang={lang}" if lang else ""),
        binary=True,
    )
    if res["down"] or res["status"] >= 400 or not res["base64"]:
        return {
            "base64": "",
            "filename": "",
            "serviceDown": res["down"],
            "error": res["error"]
            if res["down"]
            else "Failed to fetch the DOCX report from the service.",
        }
    return {
        "base64": res["base64"],
        "filename": f"pentest_report_{scan_id}.docx",
        "serviceDown": False,
        "error": "",
    }


def _a_get_report_html(args: dict, port: int) -> dict:
    scan_id = args.get("scanId")
    lang = _report_lang(args)
    res = call_service(
        port, "GET",
        f"/report/{_enc(scan_id)}" + (f"?lang={lang}" if lang else ""),
    )
    if res["down"] or res["status"] >= 400:
        return {
            "html": "",
            "serviceDown": res["down"],
            "error": res["error"] if res["down"] else "Failed to fetch the HTML report.",
        }
    return {"html": res["text"], "serviceDown": False, "error": ""}


# --- v3.4 enterprise: insights (SLA/MTTR), advanced triage, assets, admin ----


def _a_get_insights(args: dict, port: int) -> dict:
    empty = {
        "slaDays": {},
        "overdueCounts": {},
        "overdue": [],
        "mttrDays": {},
        "trendByTarget": {},
    }
    res = call_service(port, "GET", "/api/insights")
    if res["down"] or not is_record(res["json"]):
        return {
            **empty,
            "serviceDown": True,
            "error": res["error"] or "Service unreachable.",
        }
    j = res["json"]
    trend: dict = {}
    if is_record(j.get("trend_by_target")):
        for k, v in j["trend_by_target"].items():
            points = v if isinstance(v, list) else []
            mapped = []
            for p in points:
                rec = p if is_record(p) else {}
                mapped.append(
                    {
                        "t": as_num(rec.get("t")),
                        "risk": as_str(rec.get("risk")) or "-",
                        "score": as_num_or_null(rec.get("score")),
                    }
                )
            trend[k] = mapped
    overdue = []
    for r in j.get("overdue") if isinstance(j.get("overdue"), list) else []:
        rec = r if is_record(r) else {}
        overdue.append(
            {
                "id": as_num(rec.get("id")),
                "severity": as_str(rec.get("severity")) or "INFO",
                "title": as_str(rec.get("title")),
                "target": as_str(rec.get("target")),
                "ageDays": as_num(rec.get("age_days")),
                "overdueDays": as_num(rec.get("overdue_days")),
                "assignee": as_str(rec.get("assignee")),
                "dueDate": as_str(rec.get("due_date")),
            }
        )
    return {
        "slaDays": num_record(j.get("sla_days")),
        "overdueCounts": num_record(j.get("overdue_counts")),
        "overdue": overdue,
        "mttrDays": num_record(j.get("mttr_days")),
        "trendByTarget": trend,
        "serviceDown": False,
        "error": "",
    }


def _a_update_finding(args: dict, port: int) -> dict:
    body: dict = {"finding_id": args.get("findingId")}
    if args.get("assignee") is not None:
        body["assignee"] = args.get("assignee")
    if args.get("dueDate") is not None:
        body["due_date"] = args.get("dueDate")
    res = call_service(port, "POST", "/api/finding/update", body)
    return _service_error_result(res)


def _a_set_asset_meta(args: dict, port: int) -> dict:
    res = call_service(
        port,
        "POST",
        "/api/assets/meta",
        {
            "host": args.get("target"),
            "criticality": args.get("criticality"),
            "owner": args.get("owner"),
        },
    )
    return _service_error_result(res)


def _a_delete_asset(args: dict, port: int) -> dict:
    # Asset deletion (service v1.9.0): POST /api/assets/delete is
    # admin-only and removes every scan of the target plus all their
    # findings, the asset meta, and host suppressions; it returns the
    # deleted counts. Stored vault credentials (Target Secrets) are
    # independent entries and are NOT deleted by the service.
    res = call_service(
        port, "POST", "/api/assets/delete", {"host": args.get("host")}
    )
    if res["down"] or res["status"] >= 400 or not is_record(res["json"]):
        return {
            "ok": False,
            "scans": 0,
            "findings": 0,
            "suppressions": 0,
            "serviceDown": res["down"],
            "error": res["error"]
            if res["down"]
            else (res["error"] or "Failed to delete the asset."),
        }
    j = res["json"]
    return {
        "ok": j.get("ok") is True,
        "scans": as_num(j.get("scans")),
        "findings": as_num(j.get("findings")),
        "suppressions": as_num(j.get("suppressions")),
        "serviceDown": False,
        "error": "",
    }


def _a_get_me(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/me")
    if res["down"] or not is_record(res["json"]):
        return {
            "user": "",
            "role": "",
            "serviceDown": True,
            "error": res["error"] or "Service unreachable.",
        }
    return {
        "user": as_str(res["json"].get("user")),
        "role": as_str(res["json"].get("role")),
        "serviceDown": False,
        "error": "",
    }


def _a_logout(args: dict, port: int) -> dict:
    """Sign the dashboard out. Drops the actions layer's cached internal
    admin session (best-effort service logout with it). When the UI is
    served by the service itself, the /actions handler in app2.py
    additionally invalidates the caller's own browser session and clears
    its cookie, so the sign-out is real there too."""
    global _session_cookie, _session_exp
    with _session_lock:
        cookie = _session_cookie
        _session_cookie = ""
        _session_exp = 0.0
    if cookie:
        try:
            requests.post(
                f"http://127.0.0.1:{port}/api/logout",
                headers={"Cookie": cookie},
                timeout=FETCH_TIMEOUT_S,
            )
        except requests.RequestException:
            pass
    return {"loggedOut": True, "serviceDown": False, "error": ""}


def _a_get_settings(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/settings")
    if res["down"] or not is_record(res["json"]):
        return {
            "webhookUrl": "",
            "serviceDown": res["down"],
            "error": res["error"] or "Failed to load settings.",
        }
    return {
        "webhookUrl": as_str(res["json"].get("webhook_url")),
        "serviceDown": False,
        "error": "",
    }


def _a_save_settings(args: dict, port: int) -> dict:
    res = call_service(
        port, "POST", "/api/settings", {"webhook_url": args.get("webhookUrl")}
    )
    return _service_error_result(res)


def _a_get_tokens(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/tokens")
    if res["down"] or not isinstance(res["json"], list):
        return {
            "tokens": [],
            "serviceDown": res["down"],
            "error": res["error"] or "Failed to load API tokens.",
        }
    tokens = []
    for r in res["json"]:
        rec = r if is_record(r) else {}
        tokens.append(
            {
                "id": as_num(rec.get("id")),
                "name": as_str(rec.get("name")),
                "createdBy": as_str(rec.get("created_by")),
                "createdAt": as_num(rec.get("created_at")),
                "lastUsed": as_num_or_null(rec.get("last_used")),
            }
        )
    return {"tokens": tokens, "serviceDown": False, "error": ""}


def _a_create_token(args: dict, port: int) -> dict:
    res = call_service(port, "POST", "/api/tokens", {"name": args.get("name")})
    if res["down"] or res["status"] >= 400 or not is_record(res["json"]):
        return {
            "token": "",
            "note": "",
            "serviceDown": res["down"],
            "error": res["error"]
            if res["down"]
            else (res["error"] or "Failed to create the token."),
        }
    return {
        "token": as_str(res["json"].get("token")),
        "note": as_str(res["json"].get("note")),
        "serviceDown": False,
        "error": "",
    }


def _a_delete_token(args: dict, port: int) -> dict:
    res = call_service(
        port, "POST", "/api/tokens/delete", {"id": args.get("tokenId")}
    )
    return _service_error_result(res)


# --- Finding suppressions -----------------------------------------------------
# Persistent per-target false-positive rules: a finding whose title
# contains the rule's title text (and whose host matches, when the
# rule names one) is dropped from future scan results and counted
# transparently in result.suppressed_count.


def _a_get_suppressions(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/suppressions")
    if res["down"] or not is_record(res["json"]):
        return {
            "suppressions": [],
            "serviceDown": res["down"],
            "error": res["error"] or "Failed to load suppression rules.",
        }
    rows = (
        res["json"].get("suppressions")
        if isinstance(res["json"].get("suppressions"), list)
        else []
    )
    suppressions = []
    for r in rows:
        rec = r if is_record(r) else {}
        suppressions.append(
            {
                "id": as_num(rec.get("id")),
                "host": as_str(rec.get("host")),
                "title": as_str(rec.get("title")),
                "createdBy": as_str(rec.get("created_by")),
                "ts": as_str(rec.get("ts")),
            }
        )
    return {"suppressions": suppressions, "serviceDown": False, "error": ""}


def _a_add_suppression(args: dict, port: int) -> dict:
    res = call_service(
        port,
        "POST",
        "/api/suppressions",
        {
            "host": _arg_str(args, "host").strip(),
            "title": _arg_str(args, "title").strip(),
        },
    )
    return _service_error_result(res)


def _a_delete_suppression(args: dict, port: int) -> dict:
    res = call_service(
        port, "POST", "/api/suppressions/delete", {"id": args.get("ruleId")}
    )
    return _service_error_result(res)


# --- NVD cache & job queue status ---------------------------------------------


def _a_get_nvd_status(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/nvd/status")
    if res["down"] or not is_record(res["json"]):
        return {
            "cacheCount": 0,
            "cacheLastFetched": "",
            "syncState": "",
            "syncMessage": "",
            "serviceDown": res["down"],
            "error": res["error"] or "Failed to load NVD status.",
        }
    cache = res["json"].get("cache") if is_record(res["json"].get("cache")) else {}
    sync = res["json"].get("sync") if is_record(res["json"].get("sync")) else {}
    return {
        "cacheCount": as_num(cache.get("count")),
        "cacheLastFetched": as_str(cache.get("last_fetched")),
        "syncState": as_str(sync.get("state")),
        "syncMessage": as_str(sync.get("message")),
        "serviceDown": False,
        "error": "",
    }


def _a_sync_nvd(args: dict, port: int) -> dict:
    res = call_service(port, "POST", "/api/nvd/sync", {})
    return _service_error_result(res)


def _a_get_metrics(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/metrics")
    if res["down"] or not is_record(res["json"]):
        return {
            "jobsActive": 0,
            "jobsWaiting": 0,
            "globalLimit": 0,
            "userLimit": 0,
            "canaryPresent": False,
            "canaryMode": "",
            "canaryBase": "",
            "canaryHits": 0,
            "serviceDown": res["down"],
            "error": res["error"] or "Failed to load queue metrics.",
        }
    jobs = res["json"].get("jobs") if is_record(res["json"].get("jobs")) else {}
    # Out-of-band canary status from the service metrics payload
    # ({mode, base, hits}). canaryPresent is false when the service
    # does not report a canary object — the client hides the line
    # instead of inventing values.
    canary = res["json"].get("canary") if is_record(res["json"].get("canary")) else None
    return {
        "jobsActive": as_num(jobs.get("active")),
        "jobsWaiting": as_num(jobs.get("waiting")),
        "globalLimit": as_num(jobs.get("global_limit")),
        "userLimit": as_num(jobs.get("user_limit")),
        "canaryPresent": canary is not None,
        "canaryMode": as_str(canary.get("mode")) if canary else "",
        "canaryBase": as_str(canary.get("base")) if canary else "",
        "canaryHits": as_num(canary.get("hits")) if canary else 0,
        "serviceDown": False,
        "error": "",
    }


# --- Target secrets -------------------------------------------------------------
# Encrypted-at-rest credential vault for authenticated scans. The
# service API is write-only: GET returns metadata only, and no action
# here ever receives a stored secret value back.


def _a_get_secrets(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/secrets")
    if res["down"] or not is_record(res["json"]):
        return {
            "secrets": [],
            "serviceDown": res["down"],
            "error": res["error"] or "Failed to load target secrets.",
        }
    rows = (
        res["json"].get("secrets")
        if isinstance(res["json"].get("secrets"), list)
        else []
    )
    secrets = []
    for r in rows:
        rec = r if is_record(r) else {}
        secrets.append(
            {
                "id": as_num(rec.get("id")),
                "name": as_str(rec.get("name")),
                "host": as_str(rec.get("host")),
                "kind": as_str(rec.get("kind")),
                "username": as_str(rec.get("username")),
                "createdBy": as_str(rec.get("created_by")),
                "ts": as_str(rec.get("ts")),
            }
        )
    return {"secrets": secrets, "serviceDown": False, "error": ""}


def _a_create_secret(args: dict, port: int) -> dict:
    body: dict = {
        "name": _arg_str(args, "name").strip(),
        "host": _arg_str(args, "host").strip(),
        "kind": args.get("kind"),
        "secret": args.get("secret"),
    }
    if args.get("kind") == "basic":
        body["username"] = _arg_str(args, "username").strip()
    res = call_service(port, "POST", "/api/secrets", body)
    return _service_error_result(res)


def _a_delete_secret(args: dict, port: int) -> dict:
    res = call_service(
        port, "POST", "/api/secrets/delete", {"id": args.get("secretId")}
    )
    return _service_error_result(res)


# --- Globe / baseline / NVD-schedule actions (2026-10-26 artifact-UI port) --
# Thin handlers over existing app2.py routes, same call_service pattern
# as the 47 handlers above. No new service endpoint is created here.
# getglobefingerprint deliberately has NO handler: it is a direct
# NDJSON route (GET /api/osint/globe/fingerprint) that an /actions
# JSON envelope cannot stream. getglobeticker is DERIVED (see below):
# it has no dedicated service route, so it is computed from the
# /api/osint/globe/markets payload (design hypothesis #1) and flagged
# as derived/assumed in every response — the bundle call-site check at
# integration time decides whether this derivation matches the client.


def _globe_passthrough(res: dict) -> dict:
    """Return a globe route's JSON payload verbatim, plus the honest
    serviceDown/error flags the client uses for its empty states."""
    if res["down"] or not is_record(res["json"]):
        return {
            "serviceDown": res["down"],
            "error": res["error"] or "Service unreachable.",
        }
    out = dict(res["json"])
    out["serviceDown"] = False
    out["error"] = ""
    return out


def _globe_qs(params: dict) -> str:
    return urllib.parse.urlencode(
        {k: v for k, v in params.items() if v not in (None, "")})


def _a_get_globe_status(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/osint/globe/status",
                       timeout_ms=GLOBE_TIMEOUT_MS)
    return _globe_passthrough(res)


def _a_get_globe_cam(args: dict, port: int) -> dict:
    # Cam media must reach the client base64-encoded (the platform
    # client's base64 expectation); binary=True does exactly that.
    qs = _globe_qs({"cid": _arg_str(args, "cid") or _arg_str(args, "id"),
                    "kind": _arg_str(args, "kind", "img")})
    res = call_service(
        port, "GET", "/api/osint/globe/cam" + ("?" + qs if qs else ""),
        binary=True)
    if res["down"] or res["status"] >= 400:
        return {"base64": "", "contentType": "",
                "serviceDown": res["down"],
                "error": res["error"] or "Cam preview unavailable."}
    return {"base64": res["base64"], "contentType": res["contentType"],
            "serviceDown": False, "error": ""}


def _a_get_globe_layer(args: dict, port: int) -> dict:
    layer_id = _arg_str(args, "layerId") or _arg_str(args, "id")
    res = call_service(port, "GET",
                       f"/api/osint/globe/layer/{_enc(layer_id)}",
                       timeout_ms=GLOBE_TIMEOUT_MS)
    return _globe_passthrough(res)


def _a_get_globe_entities(args: dict, port: int) -> dict:
    qs = _globe_qs({"scan": _arg_str(args, "scanId") or _arg_str(args, "scan")})
    res = call_service(
        port, "GET", "/api/osint/globe/entities" + ("?" + qs if qs else ""),
        timeout_ms=GLOBE_TIMEOUT_MS)
    return _globe_passthrough(res)


def _a_get_globe_search(args: dict, port: int) -> dict:
    qs = _globe_qs({"q": _arg_str(args, "q") or _arg_str(args, "query")})
    res = call_service(
        port, "GET", "/api/osint/globe/search" + ("?" + qs if qs else ""),
        timeout_ms=GLOBE_TIMEOUT_MS)
    return _globe_passthrough(res)


def _a_get_globe_route(args: dict, port: int) -> dict:
    wps = args.get("wp") or args.get("waypoints") or ""
    if isinstance(wps, list):
        wps = ";".join(
            f"{p[0]},{p[1]}" if isinstance(p, (list, tuple)) and len(p) >= 2
            else str(p) for p in wps)
    qs = _globe_qs({"profile": _arg_str(args, "profile", "driving"),
                    "wp": str(wps)})
    res = call_service(
        port, "GET", "/api/osint/globe/route" + ("?" + qs if qs else ""),
        timeout_ms=GLOBE_TIMEOUT_MS)
    return _globe_passthrough(res)


def _a_get_globe_github(args: dict, port: int) -> dict:
    qs = _globe_qs({"u": _arg_str(args, "u") or _arg_str(args, "username")})
    res = call_service(
        port, "GET", "/api/osint/globe/github" + ("?" + qs if qs else ""),
        timeout_ms=GLOBE_TIMEOUT_MS)
    return _globe_passthrough(res)


def _a_get_globe_launches(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/osint/globe/launches",
                       timeout_ms=GLOBE_TIMEOUT_MS)
    return _globe_passthrough(res)


def _a_get_globe_news(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/osint/globe/news",
                       timeout_ms=GLOBE_TIMEOUT_MS)
    return _globe_passthrough(res)


def _a_get_globe_markets(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/osint/globe/markets",
                       timeout_ms=GLOBE_TIMEOUT_MS)
    return _globe_passthrough(res)


def _a_get_globe_cloudmeta(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/osint/globe/cloudmeta",
                       timeout_ms=GLOBE_TIMEOUT_MS)
    return _globe_passthrough(res)


def _a_get_globe_windgrid(args: dict, port: int) -> dict:
    qs = _globe_qs({"cycle": _arg_str(args, "cycle"),
                    "fhour": str(args.get("fhour", ""))})
    res = call_service(
        port, "GET", "/api/osint/globe/windgrid" + ("?" + qs if qs else ""),
        timeout_ms=GLOBE_TIMEOUT_MS)
    return _globe_passthrough(res)


def _a_get_globe_iss_telemetry(args: dict, port: int) -> dict:
    res = call_service(port, "GET", "/api/osint/globe/iss_telemetry",
                       timeout_ms=GLOBE_TIMEOUT_MS)
    return _globe_passthrough(res)


def _a_get_globe_recon(args: dict, port: int) -> dict:
    bbox = args.get("bbox") or ""
    if isinstance(bbox, list):
        bbox = ",".join(str(v) for v in bbox)
    qs = _globe_qs({
        "tool": _arg_str(args, "tool"),
        "target": _arg_str(args, "target"),
        "optin": "1" if args.get("optin") else "",
        "keyword": _arg_str(args, "keyword"),
        "bbox": str(bbox),
    })
    res = call_service(
        port, "GET", "/api/osint/globe/recon" + ("?" + qs if qs else ""),
        timeout_ms=GLOBE_TIMEOUT_MS)
    return _globe_passthrough(res)


def _a_get_globe_ticker(args: dict, port: int) -> dict:
    # DERIVED / ASSUMED (K6, design hypothesis #1): there is no
    # /api/osint/globe/ticker route, and Stooq was dropped as a market
    # source in v1.20.0, so no new route is invented. This handler
    # derives the ticker from the /api/osint/globe/markets basket
    # payload instead. Every response carries derived=True so the
    # coordinator can verify it against the real bundle call site at
    # integration time and replace it if the client expects more.
    symbol = (_arg_str(args, "symbol") or _arg_str(args, "ticker")
              or _arg_str(args, "id"))
    res = call_service(port, "GET", "/api/osint/globe/markets",
                       timeout_ms=GLOBE_TIMEOUT_MS)
    if res["down"] or not is_record(res["json"]):
        return {"symbol": symbol, "derived": True,
                "derivedFrom": "/api/osint/globe/markets",
                "derivedAssumed": True, "found": False,
                "serviceDown": res["down"],
                "error": res["error"] or "Service unreachable."}
    rows = res["json"].get("rows")
    if not isinstance(rows, list):
        rows = []
    match = None
    if symbol:
        want = symbol.strip().lower()
        for row in rows:
            rec = row if is_record(row) else {}
            if str(rec.get("symbol", "")).lower() == want \
                    or str(rec.get("id", "")).lower() == want:
                match = rec
                break
    if match is None:
        return {"symbol": symbol, "derived": True,
                "derivedFrom": "/api/osint/globe/markets",
                "derivedAssumed": True, "found": False,
                "serviceDown": False, "error": ""}
    return {"symbol": match.get("symbol", symbol),
            "name": match.get("name", ""),
            "value": match.get("value"),
            "changePct": match.get("change_pct"),
            "spark": match.get("spark", []),
            "asOf": match.get("as_of", ""),
            "source": match.get("source", ""),
            "derived": True,
            "derivedFrom": "/api/osint/globe/markets",
            "derivedAssumed": True, "found": True,
            "serviceDown": False, "error": ""}


def _a_add_secret_baseline(args: dict, port: int) -> dict:
    res = call_service(port, "POST", "/api/settings/baseline", {
        "value": args.get("value"),
        "kind": args.get("kind"),
        "label": args.get("label"),
        "reason": args.get("reason"),
    })
    if res["down"] or res["status"] >= 400 or not is_record(res["json"]):
        return _service_error_result(res)
    out = dict(res["json"])
    out["serviceDown"] = False
    out["error"] = ""
    return out


def _a_remove_secret_baseline(args: dict, port: int) -> dict:
    res = call_service(port, "POST", "/api/settings/baseline/remove", {
        "hash": args.get("hash"),
    })
    if res["down"] or res["status"] >= 400 or not is_record(res["json"]):
        return _service_error_result(res)
    out = dict(res["json"])
    out["serviceDown"] = False
    out["error"] = ""
    return out


def _a_save_nvd_schedule(args: dict, port: int) -> dict:
    # K7 confirmed from the app2.py settings handler: it is a partial
    # save keyed on nvd_sync_enabled + nvd_sync_interval_h (clamped
    # 1..168 server-side). No new endpoint. Accepts both camelCase
    # and snake_case arg spellings.
    enabled = args.get("enabled")
    if enabled is None:
        enabled = args.get("nvdSyncEnabled")
    if enabled is None:
        enabled = args.get("nvd_sync_enabled")
    interval = args.get("intervalH")
    if interval is None:
        interval = args.get("interval_h")
    if interval is None:
        interval = args.get("nvdSyncIntervalH")
    if interval is None:
        interval = args.get("nvd_sync_interval_h")
    body: dict = {}
    if enabled is not None:
        body["nvd_sync_enabled"] = bool(enabled)
    if interval is not None:
        body["nvd_sync_interval_h"] = interval
    res = call_service(port, "POST", "/api/settings", body)
    return _service_error_result(res)


# --- Dispatch -------------------------------------------------------------------

_ACTIONS = {
    "getStats": _a_get_stats,
    "getEngine": _a_get_engine,
    "getScans": _a_get_scans,
    "getScanDetail": _a_get_scan_detail,
    "getScanDiff": _a_get_scan_diff,
    "exportScan": _a_export_scan,
    "analyzeMobile": _a_analyze_mobile,
    "startMobileUpload": _a_start_mobile_upload,
    "uploadMobileChunk": _a_upload_mobile_chunk,
    "finishMobileUpload": _a_finish_mobile_upload,
    "cancelMobileUpload": _a_cancel_mobile_upload,
    "getSchedules": _a_get_schedules,
    "createSchedule": _a_create_schedule,
    "deleteSchedule": _a_delete_schedule,
    "toggleSchedule": _a_toggle_schedule,
    "getAudit": _a_get_audit,
    "getUsers": _a_get_users,
    "createUser": _a_create_user,
    "getFindings": _a_get_findings,
    "getAssets": _a_get_assets,
    "startScan": _a_start_scan,
    "getJob": _a_get_job,
    "cancelJob": _a_cancel_job,
    "deleteScan": _a_delete_scan,
    "setFindingStatus": _a_set_finding_status,
    "getReportDocx": _a_get_report_docx,
    "getReportHtml": _a_get_report_html,
    "getInsights": _a_get_insights,
    "updateFinding": _a_update_finding,
    "setAssetMeta": _a_set_asset_meta,
    "deleteAsset": _a_delete_asset,
    "getMe": _a_get_me,
    "logout": _a_logout,
    "getSettings": _a_get_settings,
    "saveSettings": _a_save_settings,
    "getTokens": _a_get_tokens,
    "createToken": _a_create_token,
    "deleteToken": _a_delete_token,
    "getSuppressions": _a_get_suppressions,
    "addSuppression": _a_add_suppression,
    "deleteSuppression": _a_delete_suppression,
    "getNvdStatus": _a_get_nvd_status,
    "syncNvd": _a_sync_nvd,
    "getMetrics": _a_get_metrics,
    "getSecrets": _a_get_secrets,
    "createSecret": _a_create_secret,
    "deleteSecret": _a_delete_secret,
    # 2026-10-26 artifact-UI port: 14 globe + ticker (derived) +
    # 2 baseline + 1 NVD schedule. getglobefingerprint intentionally
    # absent (direct NDJSON route, not an /actions handler).
    "getGlobeStatus": _a_get_globe_status,
    "getGlobeCam": _a_get_globe_cam,
    "getGlobeLayer": _a_get_globe_layer,
    "getGlobeEntities": _a_get_globe_entities,
    "getGlobeSearch": _a_get_globe_search,
    "getGlobeRoute": _a_get_globe_route,
    "getGlobeGithub": _a_get_globe_github,
    "getGlobeLaunches": _a_get_globe_launches,
    "getGlobeNews": _a_get_globe_news,
    "getGlobeMarkets": _a_get_globe_markets,
    "getGlobeCloudmeta": _a_get_globe_cloudmeta,
    "getGlobeWindgrid": _a_get_globe_windgrid,
    "getGlobeIssTelemetry": _a_get_globe_iss_telemetry,
    "getGlobeRecon": _a_get_globe_recon,
    "getGlobeTicker": _a_get_globe_ticker,
    "addSecretBaseline": _a_add_secret_baseline,
    "removeSecretBaseline": _a_remove_secret_baseline,
    "saveNvdSchedule": _a_save_nvd_schedule,
}


def handle_action(name: str, args: dict, port: int) -> tuple[int, dict]:
    """Entry point for the client wire contract:
    POST {"action": name, "args": {...}} -> (status, envelope)."""
    handler = _ACTIONS.get(name)
    if handler is None and isinstance(name, str):
        # 2026-10-26 artifact-UI port: the platform normalizes action
        # names to lowercase in list_actions, while actions.py keys are
        # camelCase. The bundle's exact spelling is verified at
        # integration time; accepting either casing here means a
        # casing-only difference can never 404 a real action.
        lowered = {k.lower(): v for k, v in _ACTIONS.items()}
        handler = lowered.get(name.lower())
    if handler is None:
        return (404, {"error": "unknown action"})
    try:
        result = handler(args if isinstance(args, dict) else {}, port)
    except Exception as exc:  # noqa: BLE001 - mirrors the spec contract
        return (500, {"error": str(exc)[:300]})
    return (200, {"data": result})
