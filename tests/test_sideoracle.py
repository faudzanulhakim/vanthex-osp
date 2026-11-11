"""Hermetic tests for sideoracle.py — own http.server, no network.

Covers: TimingProbe statistics, user-enumeration probable / no-signal /
flaky honesty, token micro-timing candidate, record existence, request
cap, and the PTK_SIDEORACLE gate.
"""
import http.server
import json
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offensive import sideoracle  # noqa: E402
from netclient import Client  # noqa: E402

# hermetic: never route loopback through the environment proxy
os.environ["NO_PROXY"] = "127.0.0.1,localhost"
os.environ["no_proxy"] = "127.0.0.1,localhost"

BASE_SLEEP = 0.010
KNOWN_SLEEP = 0.090      # +80 ms over the 10 ms control baseline
TOKEN_DELTA_S = 0.002    # 2 ms micro-timing delta (< 5 ms band)
TOKEN_MAD_SPREAD = 0.0008  # keep MAD ranges disjoint


class Handler(http.server.BaseHTTPRequestHandler):
    # test-configurable, set by the fixtures below
    mode = "enum"
    known_hit = 0          # counter of known-user requests (flaky mode)

    def log_message(self, *a):    # silence
        pass

    def do_POST(self):
        self._serve()

    def do_GET(self):
        self._serve()

    def _serve(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        params = {}
        if body:
            from urllib.parse import parse_qs
            params = {k: v[0] for k, v in parse_qs(body.decode()).items()}
        elif "?" in self.path:
            from urllib.parse import parse_qs, urlparse
            params = {k: v[0] for k, v in
                      parse_qs(urlparse(self.path).query).items()}

        if self.mode in ("enum", "flaky", "constant"):
            user = params.get("username", "")
            delay = BASE_SLEEP
            # c_side_oracle probes with "ptk-probe-user"; the control is
            # always the "ptk-nonexistent-..." user generated per call.
            is_target = bool(user) and not user.startswith("ptk-nonexistent")
            if is_target:
                if self.mode == "enum":
                    delay = KNOWN_SLEEP
                elif self.mode == "flaky":
                    Handler.known_hit += 1
                    if Handler.known_hit <= 5:
                        delay = KNOWN_SLEEP
            time.sleep(delay)
            self._reply(200, {"status": "denied"})
        elif self.mode == "token":
            tok = params.get("token", "")
            delay = BASE_SLEEP + (TOKEN_DELTA_S if tok.startswith("good")
                                  else 0.0)
            time.sleep(delay)
            self._reply(200, {"valid": tok.startswith("good")})
        elif self.mode == "record":
            val = params.get("q", "")
            time.sleep(KNOWN_SLEEP if val == "present-record"
                       else BASE_SLEEP)
            self._reply(200, {"hits": 1 if val == "present-record" else 0})
        else:
            self._reply(200, {})

    def _reply(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Counter:
    def __init__(self):
        self.count = 0
        self.lock = threading.Lock()

    def bump(self):
        with self.lock:
            self.count += 1


@pytest.fixture()
def server():
    Counter.bump = Counter.bump  # noqa — kept for clarity
    counters = {"requests": Counter()}
    real_serve = Handler._serve

    def counted(self):
        counters["requests"].bump()
        real_serve(self)

    Handler._serve = counted
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv, counters["requests"]
    srv.shutdown()
    srv.server_close()
    Handler._serve = real_serve


def _client(port):
    return Client(f"http://127.0.0.1:{port}/", timeout=10.0)


def _set_mode(mode):
    Handler.mode = mode
    Handler.known_hit = 0


# ------------------------------------------------------------ TimingProbe

def test_timingprobe_median_mad_and_trimming():
    p = sideoracle.TimingProbe(9)
    p.samples = [0.10, 0.11, 0.10, 0.12, 0.10, 0.11, 0.10, 0.50, 0.01]
    med, mad, rng = sideoracle.median_mad(p.samples)
    # trimmed: top 10% (0.50) and bottom 10% (0.01) dropped
    trimmed = sideoracle.trimmed(p.samples)
    assert 0.50 not in trimmed and 0.01 not in trimmed
    assert len(trimmed) == 7
    assert med == pytest.approx(0.10, abs=1e-9)
    assert mad == pytest.approx(0.0, abs=1e-9)
    assert rng[0] <= med <= rng[1]
    assert "median=" in p.describe()


# ------------------------------------------------------------ user enum

def test_user_enum_probable(server):
    srv, _ctr = server
    port = srv.server_address[1]
    _set_mode("enum")
    res = sideoracle.oracle_user_enum(
        "http://127.0.0.1:%d/login" % port, "known-admin", _client(port))
    assert res["verdict"] == sideoracle.PROBABLE
    f = res["finding"]
    assert f is not None and f["confidence"] == "probable"
    assert f["cwe"] == "208"
    assert "target" in f["evidence"] and "control" in f["evidence"]
    assert res["target_median_ms"][0] != "n/a"
    assert res["control_median_ms"][0] != "n/a"
    assert res["mad_ms"][0] is not None
    assert res["rounds"] == sideoracle.ROUNDS


def test_user_enum_constant_time_no_finding(server):
    srv, _ctr = server
    port = srv.server_address[1]
    _set_mode("constant")
    res = sideoracle.oracle_user_enum(
        "http://127.0.0.1:%d/login" % port, "known-admin", _client(port))
    assert res["verdict"] == sideoracle.NO_SIGNAL
    assert res["finding"] is None          # honesty: no finding


def test_user_enum_flaky_delta_is_no_signal(server):
    """Delta present in round 1 only -> no finding (honesty over FP)."""
    srv, _ctr = server
    port = srv.server_address[1]
    _set_mode("flaky")
    res = sideoracle.oracle_user_enum(
        "http://127.0.0.1:%d/login" % port, "known-admin", _client(port))
    assert res["verdict"] == sideoracle.NO_SIGNAL
    assert res["finding"] is None


# ------------------------------------------------------------ token

def test_token_micro_timing_candidate(server):
    srv, _ctr = server
    port = srv.server_address[1]
    _set_mode("token")
    res = sideoracle.oracle_token_valid(
        "http://127.0.0.1:%d/validate" % port, "good-token-123",
        _client(port))
    assert res["verdict"] == sideoracle.CANDIDATE
    f = res["finding"]
    assert f["confidence"] == "candidate"
    assert "manual" in f["verification"].lower()
    assert "manual" in (f.get("verification_note") or "").lower() or \
        "manual" in f["description"].lower()


def test_token_large_delta_is_no_signal(server):
    """A large (>5 ms) delta is outside the micro-timing band."""
    srv, _ctr = server
    port = srv.server_address[1]
    _set_mode("record")   # huge delta, same shape as a token endpoint
    res = sideoracle.oracle_token_valid(
        "http://127.0.0.1:%d/validate" % port, "goodx", _client(port))
    assert res["verdict"] == sideoracle.NO_SIGNAL
    assert res["finding"] is None


# ------------------------------------------------------------ record

def test_record_exists_probable(server):
    srv, _ctr = server
    port = srv.server_address[1]
    _set_mode("record")
    res = sideoracle.oracle_record_exists(
        "http://127.0.0.1:%d/search" % port, "q", "present-record",
        _client(port))
    assert res["verdict"] == sideoracle.PROBABLE
    f = res["finding"]
    assert f["confidence"] == "probable"
    assert f["param"] == "q"


def test_record_exists_no_finding(server):
    srv, _ctr = server
    port = srv.server_address[1]
    _set_mode("constant")   # same delay for anything
    res = sideoracle.oracle_record_exists(
        "http://127.0.0.1:%d/search" % port, "q", "whatever",
        _client(port))
    assert res["verdict"] == sideoracle.NO_SIGNAL
    assert res["finding"] is None


# ------------------------------------------------------------ budget

def test_request_cap_enforced(server):
    srv, ctr = server
    port = srv.server_address[1]
    _set_mode("enum")
    # 2 rounds x 2 probes x 20 samples = 80 would-be requests; cap is 60
    res = sideoracle.oracle_user_enum(
        "http://127.0.0.1:%d/login" % port, "known-admin", _client(port),
        samples=20)
    assert ctr.count <= sideoracle.MAX_REQUESTS
    assert res["verdict"] == sideoracle.INCONCLUSIVE


def test_cancel_respected(server):
    srv, _ctr = server
    port = srv.server_address[1]
    _set_mode("enum")
    res = sideoracle.oracle_user_enum(
        "http://127.0.0.1:%d/login" % port, "known-admin", _client(port),
        cancelled=lambda: True)
    assert res["verdict"] == sideoracle.INCONCLUSIVE
    assert res["finding"] is None


# ------------------------------------------------------------ gate

class _StubCtx:
    """Minimal Ctx stand-in with a pre-populated surface cache."""

    def __init__(self, client, opts):
        self.client = client
        self.opts = opts
        self.logs = []
        self._surf = self._build_surface()
        self._surf_full = True

    def _build_surface(self):
        import crawler
        s = crawler.Surface()
        s.forms.append({"action": "/login", "method": "POST",
                        "inputs": ["username", "password"]})
        s.param_urls.append("/search?q=x")
        return s

    def surface(self, full=True):
        return self._surf

    def L(self, m):
        self.logs.append(m)

    def cancelled(self):
        return False


def test_gate_off_is_noop(server, monkeypatch):
    srv, ctr = server
    port = srv.server_address[1]
    monkeypatch.delenv("PTK_SIDEORACLE", raising=False)
    _set_mode("enum")
    ctx = _StubCtx(_client(port), {})
    added = []
    out = sideoracle.c_side_oracle(ctx, added.append)
    assert out == [] and added == []
    assert ctr.count == 0                    # no requests at all


def test_gate_on_runs_and_finds(server, monkeypatch):
    srv, ctr = server
    port = srv.server_address[1]
    monkeypatch.setenv("PTK_SIDEORACLE", "1")
    _set_mode("enum")
    ctx = _StubCtx(_client(port), {})
    added = []
    out = sideoracle.c_side_oracle(ctx, added.append)
    assert len(out) >= 1
    assert any(f["cwe"] == "208" for f in added)
    assert ctr.count <= 2 * sideoracle.MAX_REQUESTS  # 2 endpoints max


def test_gate_on_via_opts(server, monkeypatch):
    srv, ctr = server
    port = srv.server_address[1]
    monkeypatch.delenv("PTK_SIDEORACLE", raising=False)
    _set_mode("enum")
    ctx = _StubCtx(_client(port), {"sideoracle": True})
    added = []
    out = sideoracle.c_side_oracle(ctx, added.append)
    assert len(out) >= 1
