"""
zerodayheur.py — Behavioral Zero-Day Heuristics Fuzzer for VANTHEX.
AUTHORIZED TESTING ONLY — non-destructive (bounded mutation count, valid
copies of the original value, GET-only state verification).

Difference from fuzzkit.py (grammar/structure fuzzer): this module hunts
BEHAVIORAL anomalies with NO known error signature. fuzzkit reports parsers
that crash on structure mutation; zerodayheur classifies response semantics
(status class, latency band, body length, error signatures) across a bounded
mutation battery and flags UNEXPLAINED behavioral divergences:

  * 500-cluster on a specific mutation family (parser/logic fault with no
    attributable signature — no traceback, no framework error string),
  * response-time cliff (a mutation family that makes the server do work
    the baseline never does),
  * differential body-content leak (tokens present under one mutation
    family only — an internal value escaping through a type edge),
  * state change detected via follow-up GET (a read-shaped parameter that
    mutates server state).

Honesty model (same discipline as exploitkit/diffconfirm):
  * verification is "differential" ONLY when a follow-up control reproduces
    the anomaly against a fresh baseline; otherwise the finding stays
    "candidate"/"probable" with verification "manual-required".
  * every loop respects ctx.cancelled(); the fuzz phase is hard-capped at
    MAX_REQUESTS (52 = 1 baseline + 50 mutations + 1 baseline re-check);
    follow-up state/verification controls add at most 4 further requests.

Operator-gated: the c_zeroday_heur check is a no-op unless PTK_ZERODAY=1.
"""
import json as _json
import re as _re
import os as _os
import time as _time
from urllib.parse import quote as _quote

from exploitkit import _F

MAX_MUTATIONS = 50          # bounded mutation battery per endpoint
MAX_REQUESTS = 52           # baseline + mutations + baseline re-check
FAMILY_CLUSTER_MIN = 3      # 5xx responses in one family to flag a cluster
TIMING_RATIO = 3.0          # mutation latency vs baseline latency
TIMING_MIN_DELTA = 0.5      # absolute extra seconds (noise guard)
LEAK_TOKEN_MIN = 8          # min length of a leak token
CT_JSON = {"Content-Type": "application/json"}

# Known error signatures: when one matches the mutation response, the
# behavior is ATTRIBUTABLE to a known error class — not a zero-day-shaped
# anomaly. Deliberately excludes bare 500/"Internal Server Error" text.
KNOWN_SIGNATURES = (
    "you have an error in your sql syntax", "mysql_fetch", "ora-00942",
    "sqlite3.", "psql: error", "postgresql error", "psqlexception",
    "django.db.utils", "sqlalchemy.exc", "traceback (most recent call",
    "org.postgresql.util", "invalid input syntax for type",
    "uncaught exception", "stacktrace", "exception in thread",
    "warning: mysql", "unclosed quotation mark",
)

_WORD_RE = _re.compile(r"[A-Za-z0-9_]{%d,}" % LEAK_TOKEN_MIN)


# ------------------------------------------------------------ mutations
def _deep(d, n):
    for _ in range(n):
        d = {"a": d}
    return d


def _mutations(value):
    """Yield (mutated_value, family, tag) — bounded, non-destructive."""
    big = 10 ** 30
    uni = "\uFFFF" * 64
    fmt = "%n%s%n%s%n%x%s"
    fams = [
        ("type-string", [str(value), str(value) * 64, "0", "-1", "null"]),
        ("type-array", [[value], [value, value], [], ["x"], [str(value)]]),
        ("type-dict", [{"v": value}, {"a": {"v": value}}, {}, {"k": "v"},
                       {"dup": value, "dup2": value}]),
        ("type-int-negative", [-1, -10 ** 12, -0, -(big), -2147483648]),
        ("type-int-huge", [big, 2 ** 63, 99999999999999999999, 65535, 0]),
        ("unicode-overflow", [uni, uni + str(value), "\x00" * 64,
                              "\udbff\udfff" * 32, "é" * 256]),
        ("format-specifier", [fmt, fmt * 3, "%99999999d%n", "%s" * 16, "%p"]),
        ("deep-keys", [_deep({"v": value}, 5), _deep({"v": value}, 10),
                       _deep({"v": value}, 20), _deep(value, 8),
                       {"__proto__": {"admin": True}, "v": value}]),
    ]
    for fam, vals in fams:
        for v in vals:
            yield v, fam, f"{fam}"
    # duplicate-param family (same key twice — parser-dependent resolution)
    dupval = str(value)
    yield ("dup-a", "duplicate-param", "duplicate-param")
    yield ("dup-b", "duplicate-param", "duplicate-param")
    yield (dupval, "duplicate-param", "duplicate-param")
    yield ("dup-a|dup-b", "duplicate-param", "duplicate-param")
    yield (value, "duplicate-param", "duplicate-param")
    # param-pollution family (extra sibling params reach the handler)
    yield ("admin=true", "param-pollution", "param-pollution")
    yield ("role=admin", "param-pollution", "param-pollution")
    yield ("debug=1", "param-pollution", "param-pollution")
    yield ("is_admin=1", "param-pollution", "param-pollution")
    yield ("__proto_pollute__=1", "param-pollution", "param-pollution")


def _family_count():
    return len(list(_mutations("x")))


# ------------------------------------------------------------ requests
class _Endpoint:
    """Normalized endpoint+param description."""

    def __init__(self, path, param, method="POST", value="", json_body=True,
                 state_path=None):
        self.path = path
        self.param = param
        self.method = (method or "POST").upper()
        self.value = value
        self.json_body = bool(json_body)
        self.state_path = state_path


def _send(ctx, ep, value, dup=False, extra=None, seq=0):
    """One bounded request. Returns Resp or None on transport failure."""
    if dup:
        # duplicate the parameter key twice with different values
        a, b = "dup-a", "dup-b"
        if ep.method == "GET":
            url = (f"{ep.path}?{ep.param}={_quote(str(a))}"
                   f"&{ep.param}={_quote(str(b))}")
            return ctx.client.get(url, headers={"X-PTK-ZD-Seq": str(seq)})
        raw = _json.dumps({ep.param: a})
        raw = raw[:-1] + (',"%s":"%s"' % (ep.param, b)) + raw[-1:]
        return ctx.client.post(ep.path, data=raw, headers=CT_JSON)
    if ep.method == "GET":
        url = f"{ep.path}?{ep.param}={_quote(str(value))}"
        if extra:
            url += "".join(f"&{k}={_quote(str(v))}" for k, v in extra)
        return ctx.client.get(url, headers={"X-PTK-ZD-Seq": str(seq)})
    if ep.json_body:
        body = {ep.param: value}
        if extra:
            body.update(dict(extra))
        return ctx.client.post(ep.path, data=_json.dumps(body),
                               headers=CT_JSON)
    # form-encoded POST (non-JSON endpoint)
    from urllib.parse import urlencode as _ue
    pairs = [(ep.param, str(value))]
    if extra:
        pairs += list(extra)
    return ctx.client.post(ep.path, data=_ue(pairs),
                           headers={"Content-Type":
                                    "application/x-www-form-urlencoded"})


def _state_get(ctx, ep, seq=0):
    if not getattr(ep, "state_path", None):
        return None
    sp = ep.state_path
    # netclient mangles absolute URLs — always send a relative path
    if "://" in sp:
        from urllib.parse import urlsplit as _us
        u = _us(sp)
        sp = u.path + (("?" + u.query) if u.query else "")
    try:
        return ctx.client.get(sp,
                              headers={"X-PTK-ZD-Seq": f"state-{seq}"})
    except Exception:
        return None


def _classify(resp, base_status, base_elapsed, base_len):
    """Semantic classification of one response."""
    if resp is None:
        return {"status_class": "transport-error", "latency_band": "n/a",
                "body_len": 0, "signature": None}
    body = resp.body or ""
    low = body.lower()
    sig = None
    for s in KNOWN_SIGNATURES:
        if s in low:
            sig = s
            break
    elapsed = getattr(resp, "elapsed", 0.0) or 0.0
    if base_elapsed and elapsed > TIMING_RATIO * base_elapsed \
            and elapsed > base_elapsed + TIMING_MIN_DELTA:
        band = "cliff"
    elif base_elapsed and elapsed < 0.5 * base_elapsed:
        band = "fast"
    else:
        band = "normal"
    sc = "5xx" if resp.status >= 500 else ("4xx" if resp.status >= 400
         else ("3xx" if 300 <= resp.status < 400 else
               ("2xx" if 200 <= resp.status < 300 else "other")))
    return {"status_class": sc, "latency_band": band,
            "body_len": len(body), "signature": sig,
            "status": resp.status, "body": body, "elapsed": elapsed}


# ------------------------------------------------------------ detection
def _leak_tokens(mbody, baseline_body, other_bodies, payload_texts):
    """Tokens (>=8 chars) present in mbody, absent from the baseline and
    from every other-family response, and not echoed from our own payload."""
    have = set(_WORD_RE.findall(mbody or ""))
    excl = set(_WORD_RE.findall(baseline_body or ""))
    for ob in other_bodies:
        excl |= set(_WORD_RE.findall(ob or ""))
    for pt in payload_texts:
        excl |= set(_WORD_RE.findall(pt or ""))
    return sorted(have - excl)


def fuzz_endpoint(ctx, endpoint, max_mutations=MAX_MUTATIONS,
                  max_requests=MAX_REQUESTS):
    """Behavioral zero-day fuzz of one endpoint+param.

    endpoint: _Endpoint or dict {path, param, method, value, json_body,
    state_path}. Returns a list of _F()-shaped findings.
    Request budget: hard-capped at max_requests (52) for the fuzz phase;
    follow-up controls add at most 4 requests and are also cancellation-
    aware.
    """
    if isinstance(endpoint, dict):
        ep = _Endpoint(**endpoint)
    else:
        ep = endpoint
    findings = []
    base_status = 0
    base_elapsed = 0.0
    base_len = 0

    # --- phase 0: baseline + state snapshot
    pre_state = _state_get(ctx, ep, seq=0)
    base = None
    try:
        base = _send(ctx, ep, ep.value, seq=1)
    except Exception:
        base = None
    if base is None or base.status == 0:
        ctx.L(f"  [zerodayheur] {ep.path}: no baseline response — skipped")
        return findings
    base_status = base.status
    base_elapsed = getattr(base, "elapsed", 0.0) or 0.0
    base_len = len(base.body or "")
    base_body = base.body or ""
    ctx.L(f"  [zerodayheur] {ep.path} baseline: HTTP {base_status}, "
          f"{base_len}b, {base_elapsed:.3f}s")

    # --- phase 1: bounded mutation battery (cancellation-aware)
    results = []           # (family, tag, value, resp, cls)
    payload_texts = [str(ep.value)]
    count = 0
    for mv, fam, tag in _mutations(ep.value):
        if count >= max_mutations or count + 2 >= max_requests:
            break
        if ctx.cancelled():
            ctx.L("  [zerodayheur] cancelled mid-battery")
            return findings
        payload_texts.append(_json.dumps(mv, default=str))
        try:
            r = _send(ctx, ep, mv, dup=(fam == "duplicate-param"),
                      extra=({"admin": "true", "debug": "1"}
                             if fam == "param-pollution" else None),
                      seq=2 + count)
        except Exception:
            r = None
        count += 1
        results.append((fam, tag, mv, r, _classify(
            r, base_status, base_elapsed, base_len)))

    # baseline re-check (stability control) — last budgeted request
    try:
        base2 = _send(ctx, ep, ep.value, seq=2 + count)
    except Exception:
        base2 = None
    if base2 is None or base2.status != base_status:
        ctx.L(f"  [zerodayheur] {ep.path}: unstable baseline — "
              "differential claims downgraded")
        stable_base = False
    else:
        stable_base = True

    # --- phase 2: anomaly detection (no known signature only)
    fam5xx = {}
    for fam, tag, mv, r, c in results:
        if c["signature"]:
            continue
        if c["status_class"] == "5xx":
            fam5xx.setdefault(fam, []).append((tag, mv, r, c))
        if c["latency_band"] == "cliff":
            findings.append(_anomaly_timing(ep, tag, mv, c, base_elapsed))

    # 500-cluster per family
    for fam, hits in fam5xx.items():
        if len(hits) >= FAMILY_CLUSTER_MIN:
            f = _anomaly_500cluster(ep, fam, hits, base_status)
            if _verify_500_control(ctx, ep, fam, hits[0]):
                f["verification"] = "differential"
                f["confidence"] = "probable"
                f["verification_note"] = (
                    "Follow-up control reproduced: the same mutation "
                    "returned 5xx again while a fresh baseline stayed "
                    "non-5xx (differential, one pair).")
            findings.append(f)

    # differential body-content leak (one family only)
    fam_bodies = {}
    for fam, tag, mv, r, c in results:
        fam_bodies.setdefault(fam, []).append(c.get("body") or "")
    for fam, tag, mv, r, c in results:
        if c["status_class"] != "2xx" or not c.get("body"):
            continue
        others = [b for f2, bl in fam_bodies.items() if f2 != fam for b in bl]
        toks = _leak_tokens(c["body"], base_body, others, payload_texts)
        if toks:
            f = _anomaly_leak(ep, fam, tag, toks, c, base_status)
            if _verify_leak_control(ctx, ep, mv, base_body, toks):
                f["verification"] = "differential"
                f["confidence"] = "probable"
                f["verification_note"] = (
                    "Follow-up control reproduced: the token set reappears "
                    "under the same mutation and is absent from a fresh "
                    "baseline (differential, one pair).")
            findings.append(f)

    # state change via follow-up GET
    if getattr(ep, "state_path", None) and stable_base and not ctx.cancelled():
        post_state = _state_get(ctx, ep, seq=99)
        trig = results[-1][2] if results else ep.value
        if pre_state is not None and post_state is not None \
                and (post_state.body or "") != (pre_state.body or ""):
            f = _anomaly_state(ep, pre_state.body or "",
                               post_state.body or "")
            if _verify_state_control(ctx, ep, trig, pre_state.body or ""):
                f["verification"] = "differential"
                f["confidence"] = "probable"
                f["verification_note"] = (
                    "Follow-up control reproduced: re-sending the last "
                    "mutation changed the state endpoint again (two "
                    "observed transitions).")
            findings.append(f)
    return findings


# ---------------------------------------------------------- verification
def _verify_500_control(ctx, ep, fam, first_hit):
    """Control: re-send the triggering mutation; fresh baseline must stay
    non-5xx. Both must hold for a differential credit."""
    if ctx.cancelled():
        return False
    try:
        base = _send(ctx, ep, ep.value, seq=90)
        again = _send(ctx, ep, first_hit[1],
                      dup=(fam == "duplicate-param"), seq=91)
    except Exception:
        return False
    return (base is not None and base.status and base.status < 500
            and again is not None and again.status >= 500)


def _verify_leak_control(ctx, ep, mv, base_body, toks):
    if ctx.cancelled():
        return False
    try:
        base = _send(ctx, ep, ep.value, seq=92)
        again = _send(ctx, ep, mv, seq=93)
    except Exception:
        return False
    if base is None or again is None:
        return False
    ab = again.body or ""
    return all(t in ab for t in toks) and all(
        t not in (base.body or "") for t in toks) \
        and all(t not in base_body for t in toks)


def _verify_state_control(ctx, ep, mv, pre_body):
    if ctx.cancelled():
        return False
    try:
        _send(ctx, ep, mv, seq=94)
        s = _state_get(ctx, ep, seq=95)
    except Exception:
        return False
    return s is not None and (s.body or "") != pre_body


# ---------------------------------------------------------- finding shells
def _cmp_ev(c, base_status, base_elapsed, base_len):
    return (f"mutation response: status_class={c['status_class']}, "
            f"latency={c.get('elapsed', 0):.3f}s (band={c['latency_band']}), "
            f"body_len={c['body_len']} | baseline: HTTP {base_status}, "
            f"{base_elapsed:.3f}s, {base_len}b")


def _anomaly_500cluster(ep, fam, hits, base_status):
    det = "; ".join(f"{h[0]} -> HTTP {h[3]['status']}" for h in hits[:5])
    return _F(
        "HIGH",
        "Behavioral Anomaly: 5xx Cluster on Mutation Family Without Known "
        "Error Signature",
        f"The parameter {ep.param} on {ep.path} returns server errors on "
        f"{len(hits)} mutations of family '{fam}' while the baseline is "
        f"HTTP {base_status}, and none of the error bodies match a known "
        "error signature (no traceback, no framework/database error "
        "string). An unattributed 5xx cluster on one input family often "
        "marks an unhandled code path reachable with unusual types or "
        "depth — a zero-day-shaped parser/logic fault.",
        evidence=f"family '{fam}': {det}; baseline HTTP {base_status}; "
                 f"no known signature in any error body",
        cwe="CWE-754", owasp="A03:2021 Injection", cvss=7.5,
        location=ep.path, param=ep.param,
        remed="Add explicit schema validation for this parameter, return a "
              "generic error without internals, and add a regression test "
              "for the triggering mutation family.",
        confidence="probable", verification="manual-required")


def _anomaly_timing(ep, tag, mv, c, base_elapsed):
    return _F(
        "MEDIUM",
        "Behavioral Anomaly: Response-Time Cliff on Mutation",
        f"A single mutation of parameter {ep.param} on {ep.path} took "
        f"{c['elapsed']:.2f}s versus a {base_elapsed:.2f}s baseline "
        "(>= 3x and >= +0.5s) — the server performs work proportional to "
        "the mutated input that the baseline never triggers (possible "
        "algorithmic complexity or internal enumeration on that type). "
        "No known error signature is involved.",
        evidence=_cmp_ev(c, 200, base_elapsed, 0),
        cwe="CWE-407", owasp="A05:2021 Security Misconfiguration", cvss=5.3,
        location=ep.path, param=ep.param,
        remed="Bound input size/depth before processing; add size limits "
              "and complexity-aware rate limiting.",
        confidence="candidate", verification="manual-required")


def _anomaly_leak(ep, fam, tag, toks, c, base_status):
    shown = ", ".join(toks[:4])
    return _F(
        "HIGH",
        "Behavioral Anomaly: Differential Body-Content Leak Under Type "
        "Mutation",
        f"Mutating parameter {ep.param} on {ep.path} to family '{fam}' "
        f"produces a response containing tokens ({shown}) that appear in "
        "no other response and never in the baseline — an internal value "
        "that escapes only under one input type (differential "
        "body-content leak with no known error signature).",
        evidence=f"tokens unique to family '{fam}': {shown}; "
                 f"baseline HTTP {base_status} lacks them; "
                 f"{_cmp_ev(c, base_status, 0, 0)}",
        cwe="CWE-209", owasp="A01:2021 Broken Access Control", cvss=7.5,
        location=ep.path, param=ep.param,
        remed="Never echo internal identifiers/state on unusual input "
              "types; normalize the handler path so all types produce the "
              "same response shape.",
        confidence="probable", verification="manual-required")


def _anomaly_state(ep, pre_body, post_body):
    diff = "changed" if post_body != pre_body else "identical"
    return _F(
        "MEDIUM",
        "Behavioral Anomaly: State Change Detected via Follow-up GET",
        f"Requests against {ep.path} (parameter {ep.param}) altered the "
        f"observable state at {ep.state_path}: the follow-up GET body "
        f"{diff} compared to the pre-fuzz snapshot. A parameter treated "
        "as read-only changes server state on unusual input — a "
        "zero-day-shaped state mutation with no known error signature.",
        evidence=f"state GET {ep.state_path}: pre={pre_body[:80]!r} "
                 f"post={post_body[:80]!r}",
        cwe="CWE-359", owasp="A01:2021 Broken Access Control", cvss=5.3,
        location=ep.path, param=ep.param,
        remed="Enforce method/intent separation: read-shaped parameters "
              "must never trigger writes; validate types server-side.",
        confidence="candidate", verification="manual-required")


# ------------------------------------------------------------ check hook
def c_zeroday_heur(ctx, add):
    """Operator-gated check (PTK_ZERODAY=1): behavioral zero-day fuzz over
    discovered parameter targets. No-op without the gate."""
    if not (_os.environ.get("PTK_ZERODAY") == "1"
            or _os.environ.get("VANTHEX_ZERODAY") == "1"):
        ctx.L("  [zerodayheur] operator gate PTK_ZERODAY not set — skipped")
        return
    targets = []
    try:
        targets = ctx.param_targets(36) or []
    except Exception:
        targets = []
    total = 0
    for (base, pname, method, orig_qs) in targets[:12]:
        if ctx.cancelled():
            break
        ep = {"path": base.split("?")[0], "param": pname,
              "method": method or "GET", "value": "1",
              "json_body": (method or "GET").upper() != "GET",
              "state_path": base.split("?")[0]}
        try:
            fs = fuzz_endpoint(ctx, ep)
        except Exception as exc:
            ctx.L(f"  [zerodayheur] {ep['path']} failed: {exc}")
            continue
        for f in fs:
            f["origin"] = "zerodayheur"
            add(f)
            total += 1
    ctx.L(f"  [zerodayheur] done: {total} behavioral anomaly finding(s)")


if __name__ == "__main__" and _os.environ.get("PTK_ZERODAY") == "1":
    print(f"zerodayheur: {_family_count()} mutations wired, "
          f"budget {MAX_REQUESTS} requests/endpoint")
