"""
chaosfault.py — Chaos Fault-Injection Scanner for VANTHEX (v1.9.0).
AUTHORIZED TESTING ONLY — non-destructive (ONE fault injection per family
probe, every raw-socket fault under a 5 s timeout and closed cleanly, one
control replay per observed anomaly, no floods, no request storms).

Difference from fuzzkit.py (grammar/structure mutation) and zerodayheur.py
(behavioral semantic classification): this module injects ENVIRONMENT faults
around an otherwise-valid request and asks whether the server's contract
with the client is fragile:

  * delayed-response   — client-side timeout budget per request (no server
    control needed): the same request is duplicated over a raw socket with a
    deliberately tight read timeout derived from the measured baseline; a
    server that exceeds the baseline-derived budget fails the budget,
  * truncated-response — Range/If headers that ask for partial content,
  * corrupted-content  — Accept-Encoding lie (asks for gzip the parser may
    not expect), Expect: 100-continue, and an early client close mid-stream
    on HTTP/1.1 keep-alive endpoints (raw socket, SHUT_WR after send),
  * header-order-shuffle — the captured request rebuilt with its headers
    reordered (raw socket),
  * oversized-header   — ONE header just over 8 KB, once (not a flood).

Evaluation is differential against a 2x baseline:
  * 5xx that never appears in the baseline,
  * connection reset / truncated body mid-stream,
  * required headers present in the baseline missing from the fault response,
  * status-class flip (2xx -> 4xx/5xx or the reverse),
  * delayed-response budget overrun (timeout where the baseline completes).

Honesty model (same discipline as zerodayheur/diffconfirm):
  * a finding is probable with verification "differential" ONLY when the
    anomaly reproduces on a second identical fault injection after a fresh
    clean baseline; otherwise it stays candidate ("chaos-anomaly") with
    verification "manual-required".
  * every loop respects ctx.cancelled(); per endpoint the budget is
    2 baselines + probes (5 families, 1-3 probes each) + at most
    1 fresh baseline + 1 control replay per observed anomaly.

Operator-gated: the c_chaos check is a no-op unless PTK_CHAOS=1.
"""
import os as _os
import socket as _socket
import ssl as _ssl
import time as _time
from urllib.parse import urlsplit as _urlsplit

from exploitkit import _F

MAX_ENDPOINTS = 6            # endpoints per c_chaos run
MAX_FAULTS_PER_ENDPOINT = 2  # fault families per endpoint (c_chaos)
RAW_TIMEOUT = 4.0            # hard ceiling for EVERY raw-socket fault (<5 s)
DELAY_BUDGET_MIN = 0.75      # floor for the delayed-response budget
DELAY_BUDGET_MAX = RAW_TIMEOUT
READ_CAP = 262144            # 256 KB per fault response, like netclient
OVERSIZE_BYTES = 8192 + 64   # one header just over 8 KB, sent ONCE

UA_CHAOS = "VANTHEX/1.9.0 (chaos fault-injection; authorized testing only)"

FAMILIES = ("delayed-response", "truncated-response", "corrupted-content",
            "header-order-shuffle", "oversized-header")

# headers whose PRESENCE is not a contract (hop-by-hop / volatile)
_VOLATILE_HEADERS = {"date", "connection", "keep-alive", "transfer-encoding",
                     "content-length", "set-cookie", "proxy-connection",
                     "x-ptk-chaos-fresh"}

_GZIP_MAGIC = b"\x1f\x8b"


# ------------------------------------------------------------ raw transport
class RawResp:
    """Minimal raw-socket response (status, headers, body bytes, error)."""

    __slots__ = ("status", "headers", "body", "error", "declared_len",
                 "complete", "elapsed")

    def __init__(self, status=0, headers=None, body=b"", error="",
                 declared_len=None, complete=True, elapsed=0.0):
        self.status = status
        self.headers = headers or []      # list[(k, v)] wire order
        self.body = body
        self.error = error
        self.declared_len = declared_len
        self.complete = complete
        self.elapsed = elapsed

    def hdr(self, name, default=""):
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return default


def _base_headers(hostport):
    return [("Host", hostport), ("User-Agent", UA_CHAOS),
            ("Accept", "*/*"), ("Connection", "keep-alive")]


def _recv_more(sock):
    try:
        return sock.recv(4096)
    except _socket.timeout:
        raise
    except OSError:
        return b""


def _read_response(sock, deadline):
    """Read one HTTP/1.1 response. Never blocks past deadline (<5 s)."""
    t0 = _time.time()
    data = b""
    while True:
        while b"\r\n\r\n" not in data and len(data) < READ_CAP:
            if _time.time() > deadline:
                raise _socket.timeout("read deadline exceeded")
            chunk = _recv_more(sock)
            if not chunk:
                break
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status = 0
        if lines and lines[0].startswith(b"HTTP/"):
            try:
                status = int(lines[0].split(b" ")[1])
            except Exception:
                status = 0
        if 100 <= status < 200:
            # interim response (e.g. 100 Continue for Expect:) — the real
            # response follows on the same stream; discard and keep reading
            data = body
            continue
        break
    headers = []
    for ln in lines[1:]:
        if b":" in ln:
            k, _, v = ln.decode("latin-1").partition(":")
            headers.append((k.strip(), v.strip()))
    cl = None
    chunked = False
    for k, v in headers:
        lk = k.lower()
        if lk == "content-length":
            try:
                cl = int(v.split(",")[0].strip())
            except Exception:
                cl = None
        elif lk == "transfer-encoding" and "chunked" in v.lower():
            chunked = True
    complete = True
    if chunked:
        # minimal chunked drain: stop at terminator chunk
        while len(body) < READ_CAP:
            if _time.time() > deadline:
                raise _socket.timeout("read deadline exceeded")
            if body.rstrip().endswith(b"0\r\n\r\n"):
                break
            c = _recv_more(sock)
            if not c:
                break
            body += c
    elif cl is not None:
        while len(body) < cl:
            if _time.time() > deadline:
                raise _socket.timeout("read deadline exceeded")
            c = _recv_more(sock)
            if not c:
                complete = False   # truncated before Content-Length
                break
            body += c
    else:
        # close-framed: read until EOF or cap
        while len(body) < READ_CAP:
            if _time.time() > deadline:
                break
            c = _recv_more(sock)
            if not c:
                break
            body += c
    return RawResp(status, headers, body[:READ_CAP], "",
                   cl, complete, _time.time() - t0)


def _raw_get(ctx, full_path, hdrs, timeout=RAW_TIMEOUT, half_close=False,
             host=None, port=None, scheme="http"):
    """ONE raw-socket GET with a short timeout, closed cleanly in finally."""
    t0 = _time.time()
    sock = None
    try:
        if scheme == "https":
            raw = _socket.create_connection((host, port), timeout=timeout)
            ctxg = _ssl.create_default_context()
            ctxg.check_hostname = False
            ctxg.verify_mode = _ssl.CERT_NONE
            sock = ctxg.wrap_socket(raw, server_hostname=host)
        else:
            sock = _socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        lines = [f"GET {full_path} HTTP/1.1"]
        for k, v in hdrs:
            lines.append(f"{k}: {v}")
        req = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        sock.sendall(req)
        if half_close:
            try:
                sock.shutdown(_socket.SHUT_WR)
            except OSError:
                pass
        resp = _read_response(sock, _time.time() + timeout)
        return resp
    except _socket.timeout:
        return RawResp(0, [], b"", "timeout", None, False,
                       _time.time() - t0)
    except ConnectionResetError:
        return RawResp(0, [], b"", "reset", None, False, _time.time() - t0)
    except OSError as e:
        msg = str(e).lower()
        if "reset" in msg:
            return RawResp(0, [], b"", "reset", None, False,
                           _time.time() - t0)
        return RawResp(0, [], b"", f"transport: {e}", None, False,
                       _time.time() - t0)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _resolve(ctx, endpoint):
    """endpoint: str or {'path': ...} -> (full_path, host, port, scheme)."""
    path = endpoint.get("path") if isinstance(endpoint, dict) else endpoint
    cl = getattr(ctx, "client", None)
    scheme = getattr(cl, "scheme", "http") or "http"
    host = getattr(cl, "host", "127.0.0.1") or "127.0.0.1"
    port = getattr(cl, "port", 80) or 80
    if "://" in path:
        u = _urlsplit(path)
        scheme = u.scheme or scheme
        host = u.hostname or host
        port = u.port or (443 if scheme == "https" else 80)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
    elif not path.startswith("/"):
        path = "/" + path
    return path, host, port, scheme


# ------------------------------------------------------------ fault families
def _delay_budget(baseline_elapsed):
    b = max(baseline_elapsed or 0.0, 0.0)
    return min(max(2.0 * b, DELAY_BUDGET_MIN), DELAY_BUDGET_MAX)


def _probes(ctx, family, full_path, hostport, baseline_elapsed):
    """Yield (tag, spec, kwargs) — ONE request each, bounded."""
    base = _base_headers(hostport)
    if family == "delayed-response":
        budget = _delay_budget(baseline_elapsed)
        yield ("timeout-budget",
               f"duplicated baseline request, client read timeout budget "
               f"{budget:.2f}s derived from baseline (no server control)",
               {"hdrs": base, "timeout": budget})
    elif family == "truncated-response":
        h = base + [("Range", "bytes=0-99"),
                    ("If-Range", '"ptk-chaos-bogus-etag"')]
        yield ("range-if",
               "Range: bytes=0-99 with a bogus If-Range tag to elicit "
               "partial content", {"hdrs": h})
    elif family == "corrupted-content":
        yield ("accept-encoding-lie",
               "Accept-Encoding: gzip, deflate, br on a raw socket (response "
               "bytes are NOT auto-decoded — a lying encoder breaks parsers)",
               {"hdrs": base + [("Accept-Encoding", "gzip, deflate, br")]})
        yield ("expect-100-continue",
               "Expect: 100-continue header injected on a plain GET",
               {"hdrs": base + [("Expect", "100-continue")]})
        yield ("early-close",
               "HTTP/1.1 keep-alive request, client closes the write side "
               "immediately after send (mid-stream close)",
               {"hdrs": base, "half_close": True})
    elif family == "header-order-shuffle":
        rev = list(reversed(base))
        yield ("headers-reversed",
               "captured request rebuilt with headers in reversed wire order",
               {"hdrs": rev})
    elif family == "oversized-header":
        h = base + [("X-PTK-Chaos-Oversize", "A" * OVERSIZE_BYTES)]
        yield ("single-8k-header",
               f"ONE header of {OVERSIZE_BYTES} bytes (>8 KB), sent once — "
               "not a flood", {"hdrs": h})


def _send_probe(ctx, full_path, host, port, scheme, kwargs):
    return _raw_get(ctx, full_path, kwargs.get("hdrs") or [],
                    timeout=kwargs.get("timeout", RAW_TIMEOUT),
                    half_close=bool(kwargs.get("half_close")),
                    host=host, port=port, scheme=scheme)


# ------------------------------------------------------------ evaluation
def _status_class(status):
    if status >= 500:
        return "5xx"
    if status >= 400:
        return "4xx"
    if status >= 300:
        return "3xx"
    if status >= 200:
        return "2xx"
    return "other"


def _anomalies(resp, base, tag):
    """Compare one fault response to the stable baseline -> anomaly kinds."""
    anoms = []
    if resp is None:
        return anoms
    if resp.status == 0:
        if resp.error == "timeout":
            anoms.append("delayed-response-budget-overrun")
        elif resp.error == "reset":
            anoms.append("connection-reset-mid-body")
        return anoms
    if resp.status >= 500 and base.status < 500:
        anoms.append("5xx-never-in-baseline")
    if (resp.declared_len is not None
            and len(resp.body) < resp.declared_len) or not resp.complete:
        anoms.append("connection-reset-mid-body")
    if tag == "accept-encoding-lie" and resp.body.startswith(_GZIP_MAGIC) \
            and not (base.body or "").startswith("data:"):
        # baseline (auto-decoded by netclient) was plain; raw body is gzip
        anoms.append("corrupted-content-encoding")
    base_names = {k.lower() for k, _ in getattr(base, "headers", []) or []}
    required = {n for n in base_names if n not in _VOLATILE_HEADERS}
    resp_names = {k.lower() for k, _ in resp.headers}
    missing = sorted(required - resp_names)
    if missing:
        anoms.append("missing-required-headers:" + ",".join(missing[:4]))
    if _status_class(resp.status) != _status_class(base.status):
        anoms.append("status-class-flip")
    return anoms


def _stable_baseline(b1, b2):
    return (b1 is not None and b2 is not None and b1.status
            and b2.status == b1.status and b1.status < 500)


# ------------------------------------------------------------ runner
def run_chaos(ctx, endpoint, families=None):
    """Chaos fault-injection of one endpoint.

    endpoint: str path or {'path': ...}. Returns a list of _F()-shaped
    findings. Budget: 2 baselines + probes + at most one fresh baseline and
    one identical control replay per observed anomaly. No floods.
    """
    findings = []
    full_path, host, port, scheme = _resolve(ctx, endpoint)
    fams = list(families or FAMILIES)
    # phase 0: baseline 2x
    try:
        b1 = ctx.client.get(full_path)
        b2 = ctx.client.get(full_path)
    except Exception:
        b1 = b2 = None
    if not _stable_baseline(b1, b2):
        ctx.L(f"  [chaosfault] {full_path}: no stable baseline "
              "(transport error, 5xx, or divergent pair) — skipped")
        return findings
    base_elapsed = getattr(b1, "elapsed", 0.0) or 0.0
    hostport = f"{host}:{port}" if port not in (80, 443) else host
    ctx.L(f"  [chaosfault] {full_path} baseline: HTTP {b1.status} x2, "
          f"{base_elapsed:.3f}s")
    seq = 0
    for family in fams:
        if ctx.cancelled():
            ctx.L("  [chaosfault] cancelled mid-run")
            return findings
        for tag, spec, kwargs in _probes(ctx, family, full_path, hostport,
                                         base_elapsed):
            seq += 1
            inj = _send_probe(ctx, full_path, host, port, scheme, kwargs)
            anoms = _anomalies(inj, b1, tag)
            if not anoms:
                continue
            # fresh clean baseline, then ONE identical control replay
            seq += 1
            try:
                fb = ctx.client.get(full_path, headers={
                    "X-PTK-Chaos-Fresh": f"{seq}"})
            except Exception:
                fb = None
            fresh_ok = (fb is not None and fb.status == b1.status
                        and fb.status < 500)
            if ctx.cancelled():
                return findings
            ctrl = _send_probe(ctx, full_path, host, port, scheme, kwargs)
            canoms = _anomalies(ctrl, b1, tag)
            reproduced = sorted(set(anoms) & set(canoms))
            shown = "; ".join(anoms[:4])
            if reproduced and fresh_ok:
                f = _finding(family, tag, spec, full_path, anoms, canoms,
                             b1, True)
                f["confidence"] = "probable"
                f["verification"] = "differential"
                f["verification_note"] = (
                    "Differential control reproduced: the identical fault "
                    f"re-injection reproduced {reproduced[0]} while a fresh "
                    "baseline stayed clean (one control replay, no floods).")
            else:
                f = _finding(family, tag, spec, full_path, anoms, canoms,
                             b1, False)
                f["confidence"] = "candidate"
                f["verification"] = "manual-required"
                f["verification_note"] = (
                    "chaos-anomaly: observed once under fault injection; the "
                    "identical replay did not reproduce it (or the fresh "
                    "baseline was not clean) — manual verification required.")
            f["evidence"] = (
                f"fault spec: {spec}; injection anomalies: {shown} | "
                f"baseline: HTTP {b1.status} x2 (stable) | "
                f"control replay anomalies: "
                f"{'; '.join(canoms[:4]) if canoms else 'none'} | "
                f"fresh baseline: HTTP {getattr(fb, 'status', 0)}")
            findings.append(f)
    return findings


def _finding(family, tag, spec, path, anoms, canoms, base, reproduced):
    hot = any(a.startswith(("5xx-never", "connection-reset",
                            "delayed-response-budget")) for a in anoms)
    sev = "HIGH" if hot else "MEDIUM"
    kinds = "; ".join(anoms[:4])
    return _F(
        sev,
        f"Chaos Fault-Injection: {family} Breaks Response Contract "
        f"({'differential' if reproduced else 'chaos-anomaly'})",
        f"Injecting the '{family}' fault ({tag}) on {path} produced "
        f"{kinds} while the 2x baseline is a stable HTTP {base.status}. "
        "The server's contract with the client is fragile under this "
        "environment fault: under real conditions (slow clients, proxies "
        "that reorder or oversize headers, partial content negotiation) the "
        "same divergence can surface as unhandled 5xx, truncated streams, "
        "or lost mandatory headers.",
        evidence="",   # filled by run_chaos with before/after detail
        cwe="CWE-754", owasp="A05:2021 Security Misconfiguration",
        cvss=7.5 if hot else 5.3,
        location=path, param=f"chaos:{family}:{tag}",
        remed="Treat the fault family as a contract test: return explicit, "
              "documented responses for Expect/Range/oversized-header "
              "inputs, keep mandatory headers on every response path, and "
              "bound handler latency so it stays inside sane client "
              "budgets.",
        confidence="probable", verification="manual-required")


# ------------------------------------------------------------ check hook
def c_chaos(ctx, add):
    """Operator-gated check (PTK_CHAOS=1): chaos fault-injection over the
    discovered surface. Max 6 endpoints, max 2 fault families each.
    No-op without the gate."""
    if not (_os.environ.get("PTK_CHAOS") == "1"
            or _os.environ.get("VANTHEX_CHAOS") == "1"):
        ctx.L("  [chaosfault] operator gate PTK_CHAOS not set — skipped")
        return
    targets = []
    try:
        targets = ctx.param_targets(36) or []
    except Exception:
        targets = []
    paths, seen = [], set()
    for (base, _pname, _method, _qs) in targets:
        p = (base or "").split("?")[0] or "/"
        if p in seen:
            continue
        seen.add(p)
        paths.append(p)
        if len(paths) >= MAX_ENDPOINTS:
            break
    total = 0
    for p in paths:
        if ctx.cancelled():
            break
        try:
            fs = run_chaos(ctx, {"path": p}, families=FAMILIES[:MAX_FAULTS_PER_ENDPOINT])
        except Exception as exc:
            ctx.L(f"  [chaosfault] {p} failed: {exc}")
            continue
        for f in fs:
            f["origin"] = "chaosfault"
            add(f)
            total += 1
    ctx.L(f"  [chaosfault] done: {len(paths)} endpoint(s) x max "
          f"{MAX_FAULTS_PER_ENDPOINT} faults, {total} finding(s)")


if __name__ == "__main__" and _os.environ.get("PTK_CHAOS") == "1":
    print(f"chaosfault: {len(FAMILIES)} fault families wired, "
          f"raw timeout ceiling {RAW_TIMEOUT}s, "
          f"{MAX_ENDPOINTS} endpoints x {MAX_FAULTS_PER_ENDPOINT} faults max")
