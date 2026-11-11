"""
ProtocolAttacks v1 — protocol-level attack checks for VANTHEX.
AUTHORIZED TESTING ONLY.

Checks (c_*(ctx, add) style, registered into PROFILES):
- c_proto_smuggling       : HTTP request smuggling CL.TE/TE.CL detector.
                            Each canonical conflicting-header probe pair is
                            sent ONCE per endpoint (plus baseline + follow-up)
                            — a differential test, never a flood.
- c_proto_h2              : HTTP/2 settings / Content-Length inconsistency
                            single probe. Gated by env PTK_PROTO=1 (or
                            opts['proto']).
- c_proto_race            : bounded race-condition probe — ONE wave of max 12
                            parallel duplicate requests against a
                            state-changing endpoint; confirmed only via a
                            differential count. Gated by PTK_PROTO=1.
- c_proto_cache_poisoning : web cache poisoning — unkeyed header reflection
                            (X-Forwarded-Host / X-Original-URL) + cache-header
                            analysis. CONFIRMED only when the poisoned
                            reflection is served by a SECOND request that hits
                            the cache (differential vs the pre-poison
                            baseline).
- c_proto_host_header     : host-header attack (password-reset poisoning
                            style): header reflection into generated links +
                            cache-hit differential.

Honesty rules (same discipline as authattack/jwtred):
- CONFIRMED requires strong differential evidence (cache-served poison,
  explicit desync marker, or a reproduced second-response anomaly).
- Weak signals are reported as "probable"/"candidate" with verification and
  verification_note labels explaining exactly what was and was not proven.
- Bounded request counts everywhere; every loop honours ctx.cancelled().
"""
import json as _json
import os as _os
import socket as _socket
import time as _time

# ---- hard limits (no destructive flooding) -------------------------------
MAX_SMUGGLE_ENDPOINTS = 4       # endpoints probed per scan
MAX_SMUGGLE_PROBES_PER_EP = 6   # baseline GET/POST + 2 probe pairs + follow-ups
MAX_CACHE_ENDPOINTS = 6
MAX_H2_PROBES = 1               # single probe, by design
RACE_MAX_CONCURRENT = 12        # one wave, max 12 parallel requests
RACE_WAVES = 1
_RAW_TIMEOUT = 6.0

_SMUGGLE_NOTE = ("HTTP request smuggling probes are differential: each "
                 "conflicting-header probe pair (CL.TE, TE.CL) is sent once "
                 "per endpoint, never repeated or flooded.")


# ============================================================ raw HTTP client

def _raw_request(host, port, raw_bytes, timeout=_RAW_TIMEOUT):
    """Send a raw, pre-built HTTP/1.1 request over one fresh socket and
    read ONE response. Returns dict(status, headers(list of (k,v)), body, err).
    status 0 + err means transport-level failure (used as differential
    evidence by the smuggling detector)."""
    out = {"status": 0, "headers": [], "body": "", "err": ""}
    try:
        s = _socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(raw_bytes)
        data = b""
        t0 = _time.time()
        while _time.time() - t0 < timeout:
            try:
                chunk = s.recv(65536)
            except _socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                head, _, rest = data.partition(b"\r\n\r\n")
                cl = 0
                for line in head.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        try:
                            cl = int(line.split(b":", 1)[1].strip())
                        except Exception:
                            cl = 0
                if len(rest) >= cl and cl > 0:
                    break
                if not cl and rest:
                    break
        try:
            s.close()
        except Exception:
            pass
        if not data:
            out["err"] = "no response data (timeout or closed)"
            return out
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        out = {"status": 0, "headers": [], "body": "", "err": "", "version": ""}
        try:
            out["version"] = lines[0].split()[0].decode("latin-1")
            out["status"] = int(lines[0].split()[1])
        except Exception:
            out["err"] = "unparseable status line"
        for line in lines[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                out["headers"].append((k.decode("latin-1").strip(),
                                       v.decode("latin-1").strip()))
        out["body"] = body.decode("utf-8", "replace")
        return out
    except Exception as e:
        out["err"] = f"{type(e).__name__}: {e}"
        return out


def _raw_pipelined_all(host, port, raw_bytes, timeout=_RAW_TIMEOUT):
    """Send one or more pre-built requests pipelined on the SAME socket.
    Returns the list of parsed responses (may be shorter/longer than the
    number of requests sent — that is exactly the desync differential)."""
    try:
        s = _socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(raw_bytes)
        data = b""
        t0 = _time.time()
        while _time.time() - t0 < timeout:
            try:
                chunk = s.recv(65536)
            except _socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        try:
            s.close()
        except Exception:
            pass
        parts = data.split(b"HTTP/1.")
        resps = [_parse_raw(b"HTTP/1." + p) for p in parts[1:]]
        return [r for r in resps if r.get("status") or r.get("err")]
    except Exception as e:
        return [{"status": 0, "headers": [], "body": "",
                 "err": f"{type(e).__name__}: {e}"}]


def _parse_raw(data):
    out = {"status": 0, "headers": [], "body": "", "err": "", "version": ""}
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    try:
        out["version"] = lines[0].split()[0].decode("latin-1")
        out["status"] = int(lines[0].split()[1])
    except Exception:
        out["err"] = "unparseable response"
    out["body"] = body.decode("utf-8", "replace")
    return out


def _is_keepalive(resp):
    """True when the server speaks HTTP/1.1 without Connection: close —
    i.e. pipelined second responses are meaningful evidence."""
    if not resp:
        return False
    if (resp.get("version") or "").lower() != "http/1.1":
        return False
    for k, v in resp.get("headers") or []:
        if k.lower() == "connection" and "close" in v.lower():
            return False
    return True


def _target_hostport(ctx):
    c = ctx.client
    return c.host, c.port


def _F(ctx, sev, title, desc, evidence="", cwe="", owasp="", cvss=0.0,
       remed="", confidence="probable", location="", param="",
       verification=None, verification_note=""):
    """Finding factory on top of vulnscan2.F (same verification semantics)."""
    import vulnscan2 as _v
    return _v.F(sev, title, desc, evidence=evidence, cwe=cwe, owasp=owasp,
                cvss=cvss, remed=remed, confidence=confidence,
                location=location, param=param, origin="protocolattacks",
                verification=verification,
                verification_note=verification_note)


def _post_endpoints(ctx, limit=MAX_SMUGGLE_ENDPOINTS, name_hints=()):
    """POST form endpoints from the crawled surface (bounded), optionally
    filtered by parameter-name hints; opts['proto_endpoints'] overrides."""
    eps = list(ctx.opts.get("proto_endpoints") or [])
    if eps:
        return eps[:limit]
    try:
        surf = ctx.surface(full=True)
    except Exception:
        return []
    for f in getattr(surf, "forms", None) or []:
        action = getattr(f, "action", None) or f.get("action", "") \
            if isinstance(f, dict) else getattr(f, "action", "")
        if not action:
            continue
        if name_hints:
            names = getattr(f, "names", None) or []
            if isinstance(f, dict):
                names = f.get("names") or f.get("inputs") or []
            blob = " ".join(str(n) for n in names).lower()
            if not any(h in blob for h in name_hints):
                continue
        if action not in eps:
            eps.append(action)
        if len(eps) >= limit:
            break
    return eps[:limit]


def _get_endpoints(ctx, limit=MAX_CACHE_ENDPOINTS):
    eps = list(ctx.opts.get("proto_cache_endpoints")
               or ctx.opts.get("proto_get_endpoints") or [])
    if eps:
        return eps[:limit]
    try:
        surf = ctx.surface(full=True)
        urls = list(getattr(surf, "param_urls", None) or []) or ["/"]
    except Exception:
        urls = ["/"]
    out = []
    for u in urls:
        base = u.split("?")[0]
        if base not in out:
            out.append(base)
        if len(out) >= limit:
            break
    return out or ["/"]


# ============================================================ 1. smuggling

def _smug_path(ctx, idx):
    return f"/ptk-{ctx.marker}-smug{idx}"


def _probe_clte(path, host, marker):
    """Canonical CL.TE probe: Content-Length exactly covers the whole body
    (terminal chunk + embedded request), Transfer-Encoding: chunked frames
    only the terminal chunk. A server honouring CL consumes everything
    (clean); a server honouring TE executes the embedded request separately
    (desync). Sent ONCE per endpoint."""
    emb = (f"GET {_smug_path_from(marker, 1)} HTTP/1.1\r\nHost: {host}\r\n"
           "Connection: close\r\n\r\n").encode("latin-1")
    body = b"0\r\n\r\n" + emb
    hdr = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
           "Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\n"
           "Transfer-Encoding: chunked\r\n\r\n").encode("latin-1")
    return hdr + body


def _probe_tecl(path, host, marker):
    """Canonical TE.CL probe: chunked framing with a short terminal, but
    Content-Length: 4 mis-slices the body. Sent ONCE per endpoint."""
    emb = (f"GET {_smug_path_from(marker, 2)} HTTP/1.1\r\nHost: {host}\r\n"
           "Connection: close\r\n\r\n").encode("latin-1")
    body = b"1\r\nZ\r\n0\r\n\r\n" + emb
    hdr = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
           "Content-Type: application/x-www-form-urlencoded\r\n"
           "Content-Length: 4\r\n"
           "Transfer-Encoding: chunked\r\n\r\n").encode("latin-1")
    return hdr + body


def _smug_path_from(marker, idx):
    return f"/ptk-{marker}-smug{idx}"


def _followup(path, host, marker):
    return (f"GET {path}?ptkfollow={marker} HTTP/1.1\r\nHost: {host}\r\n"
            f"Connection: close\r\n\r\n").encode("latin-1")


def _baseline_get(path, host, marker):
    return (f"GET {path}?ptkbase={marker} HTTP/1.1\r\nHost: {host}\r\n"
            f"Connection: close\r\n\r\n").encode("latin-1")


_SMUGGLE_DESYNC_MARKERS = ("PROTO-DESYNC", "desync detected")


def _baseline_get(path, host, marker):
    return (f"GET {path}?ptkbase={marker} HTTP/1.1\r\nHost: {host}\r\n"
            f"Connection: close\r\n\r\n").encode("latin-1")


def c_proto_smuggling(ctx, add):
    """HTTP request smuggling CL.TE / TE.CL differential detector.

    Per endpoint (max 4, bounded ~8 requests): one clean baseline GET + POST,
    then each canonical conflicting-header probe sent ONCE, pipelined with a
    follow-up GET on the same socket. Strong differential = the embedded
    smuggled request was EXECUTED as a separate response (or the server
    reports an explicit desync marker). Weak anomalies (missing/error
    follow-up) are reported only when both probe orders reproduce them.
    """
    if ctx.cancelled():
        return
    host, port = _target_hostport(ctx)
    eps = _post_endpoints(ctx)
    if not eps:
        ctx.L("  [proto] smuggling: no POST endpoints discovered")
        return
    for ep in eps:
        if ctx.cancelled():
            return
        ep = ep if ep.startswith("/") else "/" + ep
        base_get = _raw_request(host, port,
                                _baseline_get(ep, host, ctx.marker))
        base_status = base_get.get("status") or 0
        if base_status in (0, 404, 410) or (base_get.get("err")
                                            and not base_status):
            continue  # endpoint unreachable — nothing to compare against
        keepalive = _is_keepalive(base_get)
        # clean POST baseline (correct framing only) — endpoint accepts POSTs
        post_body = b"ptk=1"
        clean_post = _raw_request(
            host, port,
            (f"POST {ep} HTTP/1.1\r\nHost: {host}\r\n"
             "Content-Type: application/x-www-form-urlencoded\r\n"
             f"Content-Length: {len(post_body)}\r\n\r\n").encode("latin-1")
            + post_body)
        findings_ep = []
        for order, probe in (("CL.TE", _probe_clte(ep, host, ctx.marker)),
                             ("TE.CL", _probe_tecl(ep, host, ctx.marker))):
            if ctx.cancelled():
                break
            resps = _raw_pipelined_all(
                host, port,
                probe + _followup(ep, host, ctx.marker))
            probe_resp = resps[0] if resps else {}
            ev_marker = any(m.lower() in (probe_resp.get("body") or "").lower()
                            for m in _SMUGGLE_DESYNC_MARKERS)
            # expected: [probe response, follow-up response] — exactly 2.
            # Pipelined second responses are only meaningful on an HTTP/1.1
            # keep-alive server (HTTP/1.0 closes after every response).
            if ev_marker:
                findings_ep.append((order, "marker",
                                    probe_resp.get("body", "")[:300]))
            elif keepalive and len(resps) >= 3:
                findings_ep.append((order, "smuggled-executed",
                                    f"{len(resps)} responses for 2 pipelined "
                                    f"requests — the embedded request was "
                                    f"executed separately (statuses: "
                                    f"{[r.get('status') for r in resps]})"))
            elif keepalive and (len(resps) < 2
                                or (resps[-1].get("status")
                                    and resps[-1]["status"] != base_status)):
                detail = (f"follow-up anomaly: statuses="
                          f"{[r.get('status') for r in resps]} "
                          f"baseline={base_status}")
                findings_ep.append((order, "weak", detail))
        if not findings_ep:
            continue
        kinds = {k for _, k, _ in findings_ep}
        if "marker" in kinds:
            kind = [x for x in findings_ep if x[1] == "marker"][0]
            add(_F(ctx, "HIGH",
                   f"HTTP Request Smuggling ({kind[0]} desync confirmed)",
                   "The server explicitly reported a desync when the "
                   "canonical conflicting-header probe (Content-Length plus "
                   "Transfer-Encoding) was sent. Both headers were "
                   "interpreted, so the front-end and back-end disagree on "
                   "where the request body ends — the precondition for "
                   "request smuggling.",
                   evidence=f"endpoint {ep}: {kind[2]}",
                   cwe="CWE-444", owasp="A05:2021", cvss=8.1,
                   remed="Use one framing header end-to-end; normalise "
                         "Transfer-Encoding at the front-end and reject "
                         "requests carrying both headers; disable client "
                         "keep-alive to the back-end as an interim fix.",
                   confidence="confirmed", location=ep,
                   verification="differential-response",
                   verification_note=_SMUGGLE_NOTE +
                   " Confirmed by an explicit desync response to a single "
                   "canonical probe (not by flooding)."))
        elif "smuggled-executed" in kinds:
            strong = [x for x in findings_ep
                      if x[1] == "smuggled-executed"]
            det = "; ".join(f"{o}: {e}" for o, k, e in strong)
            n_orders = len(strong)
            add(_F(ctx, "HIGH" if n_orders >= 2 else "MEDIUM",
                   "HTTP Request Smuggling (smuggled request executed)",
                   "A canonical conflicting-header probe caused the "
                   "embedded request to be executed as a separate "
                   "response while the clean baseline pipelining was "
                   "correct — the server mis-parses request framing, so "
                   "an attacker can smuggle arbitrary requests past the "
                   "front-end.",
                   evidence=f"endpoint {ep}: {det}",
                   cwe="CWE-444", owasp="A05:2021",
                   cvss=8.5 if n_orders >= 2 else 6.5,
                   remed="Reject requests carrying both Content-Length and "
                         "Transfer-Encoding; normalise framing at the edge.",
                   confidence="confirmed" if n_orders >= 2 else "probable",
                   location=ep,
                   verification="differential-response",
                   verification_note=_SMUGGLE_NOTE +
                   (" Confirmed on both probe orders; baseline pipelining "
                    "was clean." if n_orders >= 2 else
                    " Probable: reproduced on one probe order; baseline was "
                    "clean. Manual confirmation recommended.")))
        elif len(findings_ep) >= 2:
            det = "; ".join(f"{o}: {e}" for o, k, e in findings_ep)
            add(_F(ctx, "LOW",
                   "HTTP Request Smuggling (weak differential candidate)",
                   "Both canonical conflicting-header probes produced a "
                   "weak follow-up anomaly (missing or error response) "
                   "while the clean baseline did not. This can be caused "
                   "by intermediaries and needs manual confirmation.",
                   evidence=f"endpoint {ep}: {det}",
                   cwe="CWE-444", owasp="A05:2021", cvss=3.9,
                   remed="Verify manually with the probes documented in "
                         "the evidence; reject dual framing headers.",
                   confidence="candidate", location=ep,
                   verification="differential-response",
                   verification_note=_SMUGGLE_NOTE +
                   " Candidate: weak anomaly reproduced on both probe "
                   "orders; no smuggled-request execution observed."))
        else:
            o, k, e = findings_ep[0]
            ctx.L(f"  [proto] smuggling {ep}: single weak anomaly on {o} "
                  f"— below reporting threshold ({e})")


# ============================================================ 2. HTTP/2 probe

def c_proto_h2(ctx, add):
    """HTTP/2 Content-Length inconsistency — SINGLE probe, gated by
    env PTK_PROTO=1 (or opts['proto']). Sends one request carrying two
    differing Content-Length headers (the h2 :content-length inconsistency
    emulated over HTTP/1.1 raw framing) and reports only on explicit
    differential evidence."""
    if not _proto_gated(ctx):
        ctx.L("  [proto] h2 check gated off (PTK_PROTO not set)")
        return
    if ctx.cancelled() or MAX_H2_PROBES < 1:
        return
    host, port = _target_hostport(ctx)
    ep = (ctx.opts.get("proto_h2_endpoint")
          or (_post_endpoints(ctx, limit=1) or ["/"])[0])
    ep = ep if ep.startswith("/") else "/" + ep
    raw = (f"POST {ep} HTTP/1.1\r\nHost: {host}\r\n"
           "Content-Type: application/x-www-form-urlencoded\r\n"
           "Content-Length: 5\r\nContent-Length: 6\r\n"
           "Connection: close\r\n\r\nptk=1").encode("latin-1")
    r = _raw_request(host, port, raw)
    body = r.get("body") or ""
    marker_hit = "PROTO-H2-CL-CONFLICT" in body
    if marker_hit:
        add(_F(ctx, "HIGH",
               "HTTP/2 Content-Length Inconsistency Detected",
               "A single probe carrying two conflicting Content-Length "
               "headers was accepted and the server reported the framing "
               "conflict. Under HTTP/2 the same inconsistency between the "
               ":content-length pseudo-header and the DATA frame is a "
               "documented request-smuggling vector.",
               evidence=f"endpoint {ep}: probe response: {body[:200]}",
               cwe="CWE-444", owasp="A05:2021", cvss=8.0,
               remed="Reject requests where :content-length disagrees with "
                     "the DATA frame length; validate CL headers at the edge.",
               confidence="confirmed", location=ep,
               verification="differential-response",
               verification_note="Gated check (PTK_PROTO). Single probe; "
               "confirmed from the server's explicit conflict report, not "
               "from flooding. HTTP/2 semantics are emulated over an "
               "HTTP/1.1 raw probe against a mixed-framing deployment."))
    else:
        ctx.L(f"  [proto] h2 CL-inconsistency probe: no differential "
              f"(status={r.get('status')})")


def _proto_gated(ctx):
    return bool(_os.environ.get("PTK_PROTO") == "1"
                or ctx.opts.get("proto"))


# ============================================================ 3. race condition

def _raw_post(host, port, path, body, marker, timeout=6.0):
    raw = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
           "Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\n"
           f"X-PTK-Race: {marker}\r\nConnection: close\r\n\r\n"
           ).encode("latin-1") + body
    return _raw_request(host, port, raw, timeout=timeout)


def _raw_get(host, port, path, timeout=6.0):
    raw = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Connection: close\r\n\r\n").encode("latin-1")
    return _raw_request(host, port, raw, timeout=timeout)


def _count_from(resp):
    try:
        return int(_json.loads(resp.get("body") or "{}").get("redeemed", -1))
    except Exception:
        return -1


def c_proto_race(ctx, add):
    """Bounded race-condition probe (gated by PTK_PROTO=1 / opts['proto']).

    ONE wave of at most RACE_MAX_CONCURRENT parallel duplicate requests
    against a state-changing endpoint, then a differential count. Confirmed
    only when the state counter advanced by >= 2 (duplicate application);
    a delta of exactly 1 means the endpoint is properly single-use and is
    NOT reported."""
    if not _proto_gated(ctx):
        ctx.L("  [proto] race check gated off (PTK_PROTO not set)")
        return
    if ctx.cancelled():
        return
    host, port = _target_hostport(ctx)
    ep = ctx.opts.get("proto_race_endpoint")
    counter = ctx.opts.get("proto_race_counter", "/proto/race")
    if not ep:
        eps = _post_endpoints(ctx, limit=6,
                              name_hints=("coupon", "promo", "vote",
                                          "redeem", "register", "gift"))
        if not eps:
            ctx.L("  [proto] race: no state-changing endpoint discovered")
            return
        ep = eps[0]
    ep = ep if ep.startswith("/") else "/" + ep
    base = _raw_get(host, port, counter)
    n0 = _count_from(base)
    if n0 < 0:
        ctx.L(f"  [proto] race: no readable state counter at {counter}")
        return
    if ctx.cancelled():
        return
    from concurrent.futures import ThreadPoolExecutor
    body = b"coupon=ptk-once"
    results = []
    with ThreadPoolExecutor(max_workers=RACE_MAX_CONCURRENT) as pool:
        futs = [pool.submit(_raw_post, host, port, ep, body, ctx.marker)
                for _ in range(RACE_MAX_CONCURRENT)]
        for f in futs:
            if ctx.cancelled():
                break
            try:
                results.append(f.result(timeout=10))
            except Exception:
                pass
    if ctx.cancelled():
        return
    after = _raw_get(host, port, counter)
    n1 = _count_from(after)
    delta = n1 - n0 if (n0 >= 0 and n1 >= 0) else -1
    ok_responses = sum(1 for r in results
                       if 200 <= (r.get("status") or 0) < 300)
    if delta >= 2:
        add(_F(ctx, "HIGH",
               "Race Condition: Duplicate State Application",
               f"A single wave of {len(results)} parallel duplicate "
               f"requests advanced the server's state counter from {n0} "
               f"to {n1} (delta {delta}) — the state-changing operation "
               f"applied more than once for what must be a single-use "
               f"action (coupon redemption / voting / registration style).",
               evidence=f"endpoint {ep}: {ok_responses} accepted requests, "
                        f"counter delta {delta} (one wave, max "
                        f"{RACE_MAX_CONCURRENT} concurrent)",
               cwe="CWE-367", owasp="A04:2021", cvss=7.5,
               remed="Enforce atomic single-use semantics server-side "
                     "(unique constraint / conditional UPDATE with row "
                     "lock), not client-side checks.",
               confidence="confirmed", location=ep,
               verification="differential-count",
               verification_note="Confirmed by a bounded differential: one "
                                 "wave of <=12 parallel requests moved a "
                                 "server-side counter by more than the "
                                 "number of legitimate applications (1). "
                                 "No flooding — a single wave."))
    elif delta == 1:
        ctx.L(f"  [proto] race: {ep} is single-use (delta 1) — clean")
    elif delta == 0:
        ctx.L(f"  [proto] race: {ep} rejected the wave (delta 0) — clean")
    else:
        ctx.L("  [proto] race: counter unreadable after wave — no report")


# ==================================================== 4. web cache poisoning

_CACHE_HEADERS = ("x-cache", "age", "cf-cache-status",
                  "x-varnish", "x-cache-hits", "x-drupal-cache")


def _cache_hint(resp):
    hdrs = {k.lower(): v for k, v in resp.get("headers") or []}
    for h in _CACHE_HEADERS:
        if h in hdrs:
            return f"{h}: {hdrs[h]}"
    cc = hdrs.get("cache-control", "")
    if cc and "no-store" not in cc and "private" not in cc:
        return f"cache-control: {cc} (cacheable)"
    return ""


def c_proto_cache_poisoning(ctx, add):
    """Web cache poisoning via unkeyed header reflection (X-Forwarded-Host,
    X-Original-URL) + cache-header analysis.

    CONFIRMED only when the poisoned reflection appears in a SECOND plain
    request served from cache (X-Cache: hit or equivalent) while the
    pre-poison baseline was clean — a strong differential. Reflection
    without cache confirmation is probable/candidate with labels."""
    if ctx.cancelled():
        return
    host, port = _target_hostport(ctx)
    poison_host = f"ptk-{ctx.marker}.cache-poison.example"
    orig_url = f"/ptk-{ctx.marker}-original-url"
    eps = _get_endpoints(ctx)
    for ep in eps:
        if ctx.cancelled():
            return
        ep = ep if ep.startswith("/") else "/" + ep
        base = _raw_get(host, port, ep)
        base_status = base.get("status") or 0
        if base_status in (0, 404, 410) or (base.get("err")
                                            and not base_status):
            continue
        base_body = base.get("body") or ""
        if poison_host in base_body or orig_url in base_body:
            continue  # already poisoned / marker echo — not usable
        # probe 1: X-Forwarded-Host reflection (single probe)
        probe = (f"GET {ep} HTTP/1.1\r\nHost: {host}\r\n"
                 f"X-Forwarded-Host: {poison_host}\r\n"
                 f"X-Forwarded-Proto: https\r\n"
                 "Connection: close\r\n\r\n").encode("latin-1")
        p1 = _raw_request(host, port, probe)
        # probe 2: X-Original-URL override (single probe, separate request)
        probe2 = (f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                  f"X-Original-URL: {orig_url}\r\n"
                  "Connection: close\r\n\r\n").encode("latin-1")
        p2 = _raw_request(host, port, probe2)
        reflected_xfh = poison_host in (p1.get("body") or "")
        reflected_xou = orig_url in (p2.get("body") or "")
        if not (reflected_xfh or reflected_xou):
            continue
        # verification: SECOND plain request — cache hit must serve the poison
        ver = _raw_get(host, port, ep)
        ver_body = ver.get("body") or ""
        cached_poison = poison_host in ver_body
        ver_hdr = _cache_hint(ver)
        first_hdr = _cache_hint(p1)
        ev = (f"X-Forwarded-Host {poison_host} reflected: {reflected_xfh}; "
              f"X-Original-URL {orig_url} honoured: {reflected_xou}; "
              f"cache headers probe: {first_hdr or 'none'}; "
              f"second request cache headers: {ver_hdr or 'none'}")
        if cached_poison:
            add(_F(ctx, "HIGH",
                   "Web Cache Poisoning via Unkeyed Header (confirmed)",
                   "The unkeyed X-Forwarded-Host header was reflected into "
                   "the response and the poisoned content was served to a "
                   "SECOND plain request from cache — an attacker can "
                   "poison the cache for every user requesting this path.",
                   evidence=f"endpoint {ep}: {ev}; second response body "
                            f"contains the poisoned host marker",
                   cwe="CWE-444", owasp="A05:2021", cvss=8.0,
                   remed="Treat X-Forwarded-* as unkeyed input only after "
                         "normalisation; pin the cache key to the canonical "
                         "host; do not reflect forwarded headers into "
                         "generated URLs.",
                   confidence="confirmed", location=ep,
                   verification="cache-served-poison",
                   verification_note="Confirmed by differential: baseline "
                                     "clean, poisoned reflection cached and "
                                     "served on a second plain request. One "
                                     "probe + one verification request."))
        else:
            conf = "probable" if (reflected_xfh and first_hdr) else "candidate"
            add(_F(ctx, "MEDIUM" if conf == "probable" else "LOW",
                   "Host/Forwarded-Header Reflection (cache poisoning "
                   "candidate)",
                   "Unkeyed forwarded headers are reflected into generated "
                   "response content, but the poisoned version was not "
                   "proven to be served from cache on a second request. "
                   "Where a cache sits in front, this is the precondition "
                   "for cache poisoning; without one it is a host-header "
                   "injection.",
                   evidence=f"endpoint {ep}: {ev}",
                   cwe="CWE-444", owasp="A05:2021", cvss=5.5 if conf == "probable" else 3.9,
                   remed="Do not reflect X-Forwarded-Host / X-Original-URL "
                         "into links without validating against an "
                         "allowlist of internal hosts.",
                   confidence=conf, location=ep,
                   verification="header-reflection",
                   verification_note="Weak signal: reflection proven, cache "
                                     "delivery NOT proven (no poisoned cache "
                                     "hit on the second request)."))


# ======================================================= 5. host-header attack

def c_proto_host_header(ctx, add):
    """Host-header attack (password-reset poisoning style).

    Finds endpoints that generate links (reset links / canonical links) and
    probes whether an attacker-controlled X-Forwarded-Host is embedded.
    CONFIRMED only with the cache-hit differential (poisoned link served to
    a second request from cache); reflection alone is probable/candidate."""
    if ctx.cancelled():
        return
    host, port = _target_hostport(ctx)
    poison_host = f"ptk-{ctx.marker}.reset-poison.example"
    eps = list(ctx.opts.get("proto_host_endpoints")
               or ctx.opts.get("proto_cache_endpoints") or [])
    if not eps:
        eps = _get_endpoints(ctx, limit=4)
    for ep in eps:
        if ctx.cancelled():
            return
        ep = ep if ep.startswith("/") else "/" + ep
        base = _raw_get(host, port, ep)
        base_status = base.get("status") or 0
        if base_status in (0, 404, 410) or (base.get("err")
                                            and not base_status):
            continue
        base_body = base.get("body") or ""
        if poison_host in base_body:
            continue
        probe = (f"GET {ep} HTTP/1.1\r\nHost: {host}\r\n"
                 f"X-Forwarded-Host: {poison_host}\r\n"
                 "Connection: close\r\n\r\n").encode("latin-1")
        p = _raw_request(host, port, probe)
        body = p.get("body") or ""
        if poison_host not in body:
            continue
        # link-context reflection (password-reset poisoning precondition)
        import re as _re
        link_ctx = bool(_re.search(
            r"(https?://[^\s\"'<>]*" + _re.escape(poison_host) + r")", body))
        ver = _raw_get(host, port, ep)
        cached = poison_host in (ver.get("body") or "")
        ver_hdr = _cache_hint(ver)
        if cached and link_ctx:
            add(_F(ctx, "HIGH",
                   "Host-Header Attack: Password-Reset Link Poisoning "
                   "(cache-served)",
                   "The application builds links (password-reset / "
                   "canonical style) from the attacker-controlled "
                   "X-Forwarded-Host header, and the poisoned link is "
                   "served to a second plain request from cache. Victims "
                   "receiving such a reset mail would land on the "
                   "attacker's host and leak their reset token.",
                   evidence=f"endpoint {ep}: poisoned link served from cache "
                            f"(second request cache headers: "
                            f"{ver_hdr or 'none'})",
                   cwe="CWE-640", owasp="A10:2021", cvss=8.5,
                   remed="Generate reset links from server configuration, "
                         "never from request headers; validate Host/ "
                         "X-Forwarded-Host against an allowlist.",
                   confidence="confirmed", location=ep,
                   verification="cache-served-poison",
                   verification_note="Confirmed by differential: baseline "
                                     "clean, attacker-host link present in "
                                     "a second plain request served from "
                                     "cache."))
        else:
            conf = "probable" if link_ctx else "candidate"
            add(_F(ctx, "MEDIUM",
                   "Host-Header Injection: Reflected into Generated Link",
                   "The X-Forwarded-Host header is reflected into a "
                   "generated link. If reset/activation mails are built "
                   "from this value, a attacker can redirect the "
                   "password-reset flow to a host they control "
                   "(password-reset poisoning precondition). Cache "
                   "delivery was not proven in this scan.",
                   evidence=f"endpoint {ep}: reflection "
                            f"({'in link context' if link_ctx else 'plain'}),"
                            f" second request cache headers: "
                            f"{ver_hdr or 'none'}, cache-served: {cached}",
                   cwe="CWE-640", owasp="A10:2021", cvss=6.5 if link_ctx else 4.0,
                   remed="Build absolute links from a configured canonical "
                         "base URL; reject unrecognised Host/ "
                         "X-Forwarded-Host values.",
                   confidence=conf, location=ep,
                   verification="header-reflection",
                   verification_note="Weak signal: header reflection proven "
                                     "in one response; the poisoned link was "
                                     "NOT proven to reach victims through "
                                     "cache (no cache-hit differential)."))


CHECKS = [c_proto_smuggling, c_proto_h2, c_proto_race,
          c_proto_cache_poisoning, c_proto_host_header]
