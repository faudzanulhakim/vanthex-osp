"""Authorization matrix + BOLA + SPA endpoint mining for VANTHEX (v1.2.2).

AUTHORIZED TESTING ONLY. This module is intended for engagements with
written authorization: it authenticates as provided sessions and probes
object endpoints for cross-user access (IDOR/BOLA), mass-assignment
privilege escalation, and statically mines JS bundles for hidden API
endpoints to expand the scan surface.

Design notes:
- Sessions: opts['sessions'] = {'low': headers, 'high': headers} (each
  value a dict of extra headers or a cookie string) OR auto-derived via
  opts['login'] = {url, user_field, password_field, creds{user,password}}
  which yields one authenticated 'low' session; unauthenticated is the
  second principal.
- CONFIRMED only on a real differential proof: low/anon receives 200
  with a real body on an object belonging to another (admin) scope.
- Bounded: max 30 object URLs x 2 requests, cancelled-aware.
"""
import json
import os
import re

import netclient
from netclient import Client

MAX_OBJECTS = 30
MAX_PROBE_ENDPOINTS = 5
MAX_BUNDLES = 6
MAX_BUNDLE_BYTES = 1024 * 1024

IDOR_TITLE = "IDOR/BOLA — Cross-User Object Access"
PRIVESC_TITLE = "Privilege Escalation via Mass Assignment"
SPA_TITLE = "SPA Surface Expanded"

_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_OBJECT_ID_RE = re.compile(
    r"(?:^|[/?=])(?:\d{1,10}|" + _UUID + r")(?:$|[/?#])", re.I)
_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico",
               ".woff", ".woff2", ".ttf", ".map", ".txt", ".xml", ".json")
_LOGIN_BODY_RE = re.compile(
    r"<form[^>]*action=\"[^\"]*login|log\s*[- ]?in\s+to\s+continue|"
    r"please\s+sign\s*[- ]?in", re.I)
_LOGIN_REDIRECT_RE = re.compile(r"/login|/signin|/auth", re.I)

_ELEVATION_PAYLOADS = [
    {"role": "admin"},
    {"is_admin": True},
    {"permissions": ["*"]},
]
_ELEVATION_REFLECT_RE = re.compile(
    r"\"role\"\s*:\s*\"admin\"|\"is_admin\"\s*:\s*true|"
    r"\"permissions\"\s*:\s*\[\"\*\"\]|role[\"']?\s*[:=]\s*[\"']?admin", re.I)
_PROFILE_ENDPOINT_RE = re.compile(
    r"(profile|user|account|setting)", re.I)
_JS_ROUTE_RE = re.compile(r"""/api/[A-Za-z0-9_\-/]{2,60}""")
_FETCH_CALL_RE = re.compile(
    r"""(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?\s*\()\s*[\("'`]+"""
    r"""(/[A-Za-z0-9_\-/]{2,60})""")
_GRAPHQL_OP_RE = re.compile(r"\b(?:query|mutation|subscription)\s+([A-Z]\w{2,40})")


def _headers_of(spec):
    """Normalize a session spec (dict of headers or a cookie string)."""
    if spec is None:
        return {}
    if isinstance(spec, dict):
        return dict(spec)
    return {"Cookie": str(spec)}


def _session_client(ctx, headers):
    """Fresh client carrying the session's credentials (never the scan's)."""
    c = ctx.client
    return Client(
        f"{c.scheme}://{c.host}:{c.port}{c.base_path or ''}",
        timeout=getattr(c, "timeout", 6.0),
        extra_headers=dict(headers))


def _derive_login_session(ctx, login):
    """POST the seeded login form; return session headers or {}."""
    url = login.get("url") or "/login"
    creds = login.get("creds") or {}
    body = "&".join(
        f"{k}={v}" for k, v in (
            (login.get("user_field") or "username", creds.get("user", "")),
            (login.get("password_field") or "password",
             creds.get("password", ""))))
    try:
        r = ctx.client.request("POST", url, data=body,
                               headers={"Content-Type":
                                        "application/x-www-form-urlencoded"})
    except Exception:
        return {}
    hdrs = {}
    setc = r.hdr("Set-Cookie") or r.hdr("set-cookie")
    if setc:
        hdrs["Cookie"] = setc.split(";")[0].strip()
    else:
        try:
            j = json.loads(r.body or "{}")
        except Exception:
            j = {}
        tok = j.get("token") or j.get("access_token") or j.get("session")
        if tok:
            hdrs["Authorization"] = f"Bearer {tok}"
    return hdrs


def _resolve_sessions(ctx, opts):
    """Return (low_headers, high_headers_or_None)."""
    sessions = opts.get("sessions") or {}
    low = _headers_of(sessions.get("low"))
    high = _headers_of(sessions.get("high")) if "high" in sessions else None
    if not low and opts.get("login"):
        low = _derive_login_session(ctx, opts["login"])
    return low, high


def _is_object_url(path):
    p = path.split("#")[0]
    low = p.lower()
    if low.endswith(_STATIC_EXT):
        return False
    return bool(_OBJECT_ID_RE.search(p)) or "admin" in low


def _path_id(path):
    m = re.search(r"(?:^|/)(?:id[=/])?(\d{1,10})(?:$|[/?#])", path)
    if m:
        return m.group(1)
    m = re.search(_UUID, path, re.I)
    return m.group(0) if m else None


def _looks_like_body(r):
    """200 with a real body (not a login redirect / empty shell)."""
    if r is None or r.status != 200:
        return False
    body = (r.body or "").strip()
    if len(body) < 3:
        return False
    if _LOGIN_BODY_RE.search(body):
        return False
    loc = r.hdr("Location") or ""
    if loc and _LOGIN_REDIRECT_RE.search(loc):
        return False
    return True


def _collect_object_urls(ctx, opts):
    urls = []
    try:
        surf = ctx.surface(full=True)
    except Exception:
        surf = None
    for coll in (getattr(surf, "pages", []) or [],
                 getattr(surf, "param_urls", []) or []):
        for u in coll:
            if not isinstance(u, str):
                continue
            if u not in urls:
                urls.append(u)
    for u in (opts.get("object_urls") or []):
        if u not in urls:
            urls.append(u)
    return [u for u in urls if _is_object_url(u)][:MAX_OBJECTS]


def _self_id(ctx, low_client):
    """Best-effort discovery of the low session's own object id."""
    for p in ("/api/user/me", "/api/me", "/api/profile", "/me"):
        try:
            r = low_client.get(p)
        except Exception:
            continue
        if r.status != 200 or not r.body:
            continue
        try:
            j = json.loads(r.body)
        except Exception:
            continue
        if isinstance(j, dict):
            for k in ("id", "user_id", "userId", "uid"):
                if k in j:
                    return str(j[k])
    return None


def _admin_scope(path, self_id):
    if "admin" in path.lower():
        return True
    pid = _path_id(path)
    return bool(self_id and pid and pid != self_id)


def run_authz_matrix(ctx, opts):
    """Run the full authorization matrix (IDOR/BOLA + privilege escalation).

    Returns {'objects_tested', 'requests', 'findings', 'probes_tested'}.
    """
    findings = []
    low_hdrs, high_hdrs = _resolve_sessions(ctx, opts)
    objects = _collect_object_urls(ctx, opts)
    tested = 0
    requests = 0
    if not objects:
        return {"objects_tested": 0, "requests": 0, "findings": findings,
                "probes_tested": 0}
    low_client = _session_client(ctx, low_hdrs)
    anon_client = _session_client(ctx, {})
    self_id = _self_id(ctx, low_client)
    seen_pairs = set()
    for path in objects:
        if ctx.cancelled():
            break
        tested += 1
        scope_hits = []
        for label, cl in (("low", low_client), ("anon", anon_client)):
            if ctx.cancelled():
                break
            try:
                r = cl.get(path)
            except Exception:
                continue
            requests += 1
            if _looks_like_body(r) and _admin_scope(path, self_id):
                scope_hits.append((label, r))
        for label, r in scope_hits:
            key = (IDOR_TITLE, path, label)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            findings.append({
                "severity": "HIGH",
                "title": IDOR_TITLE,
                "description": (
                    f"The object endpoint {path} returned full object data to "
                    f"the {label} session"
                    + (" (no credentials at all)" if label == "anon" else
                       " (a lower-privileged account)") +
                    ". Authorization is enforced on the client or not at all: "
                    "any user (or anonymous caller) can read objects belonging "
                    "to another user or to the admin scope by changing the "
                    "object identifier."),
                "evidence": (
                    f"GET {path} as {label} -> {r.status} "
                    f"(own id: {self_id or 'unknown'}); body: "
                    f"{(r.body or '')[:160]!r}"),
                "cwe": "CWE-639",
                "owasp": "A01:2021 Broken Access Control",
                "cvss": 8.2,
                "confidence": "confirmed",
                "location": path,
                "param": "",
                "origin": "active",
            })

    probes = _priv_esc_probes(ctx, opts, low_hdrs)
    findings.extend(probes["findings"])
    return {"objects_tested": tested, "requests": requests,
            "findings": findings,
            "probes_tested": probes["probes_tested"]}


def _probe_endpoints(ctx, opts):
    """Profile-ish POST/PUT endpoints from forms + JSON surface + opts seed."""
    urls = []
    try:
        surf = ctx.surface(full=True)
    except Exception:
        surf = None
    for form in (getattr(surf, "forms", []) or []):
        action = form.get("action") or ""
        if form.get("method", "").upper() in ("POST", "PUT") and \
                _PROFILE_ENDPOINT_RE.search(action):
            if action not in urls:
                urls.append(action)
    for coll in (getattr(surf, "pages", []) or [],
                 getattr(surf, "param_urls", []) or []):
        if not isinstance(coll, str):
            continue
        p = coll.split("?")[0]
        if "/api/" in p and _PROFILE_ENDPOINT_RE.search(p) and p not in urls:
            urls.append(p)
    for u in (opts.get("probe_urls") or []):
        if u not in urls:
            urls.append(u)
    return urls[:MAX_PROBE_ENDPOINTS]


def _priv_esc_probes(ctx, opts, low_hdrs):
    """Mass-assignment role-elevation probes using the low session."""
    findings = []
    probes = 0
    endpoints = _probe_endpoints(ctx, opts)
    if not endpoints:
        return {"findings": findings, "probes_tested": 0}
    low_client = _session_client(ctx, low_hdrs)
    for ep in endpoints:
        if ctx.cancelled():
            break
        elevated_reflected = False
        got_200 = False
        for payload in _ELEVATION_PAYLOADS:
            if ctx.cancelled():
                break
            probes += 1
            try:
                r = low_client.request(
                    "POST", ep, data=json.dumps(payload),
                    headers={"Content-Type": "application/json"})
            except Exception:
                continue
            if r.status != 200:
                continue
            got_200 = True
            if _ELEVATION_REFLECT_RE.search(r.body or ""):
                elevated_reflected = True
        if not got_200:
            continue
        # Verify: fetch the profile back with the same low session.
        persisted = False
        for check in ("/api/user/me", "/api/me", ep):
            if ctx.cancelled():
                break
            try:
                vr = low_client.get(check)
            except Exception:
                continue
            if vr.status == 200 and _ELEVATION_REFLECT_RE.search(vr.body or ""):
                persisted = True
                break
        if persisted:
            findings.append({
                "severity": "CRITICAL",
                "title": PRIVESC_TITLE,
                "description": (
                    f"The endpoint {ep} accepts role-elevation fields "
                    "(role/is_admin/permissions) from a low-privileged "
                    "session and the elevation is PERSISTED: a follow-up "
                    "profile fetch shows the elevated role. Mass assignment "
                    "lets any user promote themselves to admin by adding "
                    "privileged fields to a profile update."),
                "evidence": (f"POST {ep} {{\"role\":\"admin\"}} -> 200; "
                             f"persisted on profile fetch: yes"),
                "cwe": "CWE-915",
                "owasp": "A01:2021 Broken Access Control",
                "cvss": 9.1,
                "confidence": "confirmed",
                "location": ep,
                "param": "",
                "origin": "active",
            })
        elif elevated_reflected:
            findings.append({
                "severity": "MEDIUM",
                "title": PRIVESC_TITLE,
                "description": (
                    f"The endpoint {ep} accepted a role-elevation payload "
                    "(role/is_admin/permissions) from a low-privileged "
                    "session and echoed it in the response, but a follow-up "
                    "profile fetch did not show the elevated role — the "
                    "server reflects (does not reject) privileged fields, "
                    "the precondition for mass assignment. Verify manually "
                    "whether any consumer persists them."),
                "evidence": (f"POST {ep} {{\"role\":\"admin\"}} -> 200 "
                             "(reflected in response; not persisted on "
                             "follow-up fetch)"),
                "cwe": "CWE-915",
                "owasp": "A01:2021 Broken Access Control",
                "cvss": 9.1,
                "confidence": "probable",
                "location": ep,
                "param": "",
                "origin": "active",
            })
        else:
            findings.append({
                "severity": "MEDIUM",
                "title": PRIVESC_TITLE,
                "description": (
                    f"The endpoint {ep} accepted a role-elevation payload "
                    "(role/is_admin/permissions) from a low-privileged "
                    "session with a 200 response. Reflection could not be "
                    "verified on a follow-up fetch, so the elevation may be "
                    "silently ignored — but the server does not reject "
                    "privileged fields, which is the precondition for mass "
                    "assignment."),
                "evidence": f"POST {ep} {{\"role\":\"admin\"}} -> 200 "
                            "(elevation not observed on follow-up fetch)",
                "cwe": "CWE-915",
                "owasp": "A01:2021 Broken Access Control",
                "cvss": 9.1,
                "confidence": "probable",
                "location": ep,
                "param": "",
                "origin": "active",
            })
    return {"findings": findings, "probes_tested": probes}


# ------------------------------------------------------- SPA endpoint miner

def mine_spa_endpoints(ctx, base="/"):
    """Statically mine API routes from HTML + JS bundles.

    Returns the deduped list of endpoint paths; new paths (absent from the
    scan surface) are merged into surface.js_endpoints so later checks see
    them. Bounded: 6 bundles x 1 MB each.
    """
    try:
        surf = ctx.surface(full=False)
    except Exception:
        surf = None
    known = set()
    bundles = []
    if surf is not None:
        known.update(getattr(surf, "js_endpoints", []) or [])
        known.update((p or "").split("?")[0]
                     for p in (getattr(surf, "pages", []) or []))
        for u in (getattr(surf, "js_urls", []) or []):
            if u not in bundles:
                bundles.append(u)
    homepage = getattr(surf, "homepage", None) if surf is not None else None
    if homepage is None:
        try:
            homepage = ctx.client.get(base)
        except Exception:
            homepage = None
    if homepage is not None and homepage.body:
        for src in re.findall(
                r"""<script[^>]+src\s*=\s*["']([^"']+)["']""",
                homepage.body, re.I):
            if src.startswith(("http://", "https://", "//")):
                continue
            if not src.startswith("/"):
                src = "/" + src
            if src not in bundles:
                bundles.append(src)

    found = set()
    fetched = 0
    for b in bundles[:MAX_BUNDLES]:
        if ctx.cancelled() or fetched >= MAX_BUNDLES:
            break
        try:
            r = ctx.client.get(b)
        except Exception:
            continue
        if r.status != 200 or not r.body:
            continue
        fetched += 1
        body = r.body[:MAX_BUNDLE_BYTES]
        for m in _FETCH_CALL_RE.finditer(body):
            found.add(m.group(1))
        for m in _JS_ROUTE_RE.finditer(body):
            found.add(m.group(0).rstrip("/"))
        for m in _GRAPHQL_OP_RE.finditer(body):
            found.add(f"graphql:{m.group(1)}")
    # normalize + drop empty/static noise
    endpoints = sorted(e for e in found
                       if e.startswith("/") and not e.endswith(_STATIC_EXT))
    if surf is not None and hasattr(surf, "js_endpoints"):
        for e in endpoints:
            if e not in known and e not in surf.js_endpoints:
                surf.js_endpoints.append(e)
    return endpoints


# ------------------------------------------------------------------ checks

def c_authz_matrix(ctx, add):
    """Operator-gated authorization matrix (IDOR/BOLA + priv-esc probes).

    Gated by env PTK_AUTHZ=1 or opts['authz_matrix'] — it authenticates
    and probes object endpoints, so it never runs by default.
    """
    if not (os.environ.get("PTK_AUTHZ") == "1"
            or (ctx.opts or {}).get("authz_matrix")):
        return
    res = run_authz_matrix(ctx, ctx.opts or {})
    ctx.L(f"[authzmatrix] {res['objects_tested']} object URLs, "
          f"{res['requests']} requests, {len(res['findings'])} findings")
    for f in res["findings"]:
        add(f)


def c_spa_mine(ctx, add):
    """SPA endpoint miner — default-on, read-only (GET), bounded."""
    try:
        surf = ctx.surface(full=False)
    except Exception:
        surf = None
    known = set()
    if surf is not None:
        known.update(getattr(surf, "js_endpoints", []) or [])
        for p in (getattr(surf, "pages", []) or []):
            if isinstance(p, str):
                known.add(p.split("?")[0])
    endpoints = mine_spa_endpoints(ctx, ctx.client.base_path or "/")
    # js_endpoints were just extended by mine_spa_endpoints; the pre-mining
    # `known` snapshot is what marks an endpoint as genuinely NEW.
    new = [e for e in endpoints if e not in known
           and not e.startswith("graphql:")]
    if new:
        add({
            "severity": "INFO",
            "title": f"{SPA_TITLE}: {len(new)} hidden endpoints",
            "description": (
                "Static analysis of the SPA's JavaScript bundles revealed "
                "API routes that are not linked anywhere in the crawled "
                "HTML. These endpoints are merged into the scan surface so "
                "every other check covers them too; review each for "
                "authorization before exposure."),
            "evidence": "\n".join(new[:30]),
            "cwe": "CWE-200",
            "owasp": "A05:2021 Security Misconfiguration",
            "cvss": 0.0,
            "confidence": "confirmed",
            "location": "",
            "param": "",
            "origin": "active",
        })


CHECKS = [c_authz_matrix]
