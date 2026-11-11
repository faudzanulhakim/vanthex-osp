"""
tests/test_chaosfault.py — self-contained integration tests for the chaos
fault-injection scanner (chaosfault.py).

Own HTTP fixture (module-level autostart, ThreadingHTTPServer):
  * GET /chaos/stable — always 200 with the full header set (stable baseline
    -> the chaos run must produce NO findings),
  * GET /chaos/expect — 500 whenever the Expect: 100-continue header is
    present (deterministic fault response), 200 otherwise,
  * GET /chaos/flaky  — 500 on every 2nd request (global request counter;
    the 2x baseline caches its second response, so the baseline pair is
    stable and the alternating 500s land on the fault injections),
    -> a differential (reproduced) finding.

Run: .venv/bin/python -m pytest tests/test_chaosfault.py -q
"""
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# loopback must bypass any egress proxy for netclient
os.environ.setdefault("no_proxy", "127.0.0.1,localhost")
os.environ["no_proxy"] = "127.0.0.1,localhost"
for _k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    os.environ.pop(_k, None)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netclient import Client            # noqa: E402
from offensive import chaosfault as _cf                # noqa: E402

PORT = 18501


class _Flaky:
    lock = threading.Lock()
    n = 0


class _H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):        # silence fixture noise
        pass

    def _reply(self, code, body):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path.startswith("/chaos/expect"):
            if self.headers.get("Expect", "").lower() == "100-continue":
                # deterministic fault response to the Expect header fault
                self._reply(500, '{"error": "expectation failed"}')
            else:
                self._reply(200, '{"ok": true, "ep": "expect"}')
        elif self.path.startswith("/chaos/flaky"):
            with _Flaky.lock:
                _Flaky.n += 1
                n = _Flaky.n
            # 500 on every 2nd request
            if n % 2 == 0:
                self._reply(500, '{"error": "flaky 500"}')
            else:
                self._reply(200, '{"ok": true, "ep": "flaky"}')
        elif self.path.startswith("/chaos/g"):   # extra stable surfaces
            self._reply(200, '{"ok": true, "ep": "generic"}')
        elif self.path.startswith("/chaos/stable"):
            self._reply(200, '{"ok": true, "ep": "stable"}')
        else:
            self._reply(404, "not found")


_srv = ThreadingHTTPServer(("127.0.0.1", PORT), _H)
threading.Thread(target=_srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{PORT}"


class _Ctx:
    """Minimal ctx stub matching the Ctx contract used by chaosfault."""
    def __init__(self):
        self.client = Client(BASE, timeout=10)
        self.logs = []
        self._targets = []

    def cancelled(self):
        return False

    def L(self, msg):
        self.logs.append(msg)

    def param_targets(self, limit=36):
        return list(self._targets[:limit])


def test_stable_baseline_no_findings():
    ctx = _Ctx()
    fs = _cf.run_chaos(ctx, {"path": "/chaos/stable"})
    assert fs == [], fs


def test_expect_fault_differential():
    ctx = _Ctx()
    fs = _cf.run_chaos(ctx, {"path": "/chaos/expect"})
    assert fs, "expected at least one finding on /chaos/expect"
    expect_f = [f for f in fs if "expect" in f["param"]]
    assert expect_f, fs
    f = expect_f[0]
    # the deterministic Expect: 100-continue fault reproduced on the control
    assert f["verification"] == "differential", f
    assert f["confidence"] == "probable", f
    assert "5xx" in f["evidence"] or "500" in f["evidence"], f
    assert "Expect" in f["evidence"], f


def test_flaky_differential_reproduced():
    ctx = _Ctx()
    fs = _cf.run_chaos(ctx, {"path": "/chaos/flaky"})
    diff = [f for f in fs if f["verification"] == "differential"]
    assert diff, fs
    f = diff[0]
    assert f["confidence"] == "probable"
    assert "reproduc" in f["verification_note"].lower()
    # evidence carries before/after: baseline and fault outcome
    assert "baseline" in f["evidence"] and "anomalies" in f["evidence"]


def test_raw_timeout_ceiling():
    # every raw-socket fault timeout must stay below 5 s
    assert _cf.RAW_TIMEOUT < 5.0
    budget = _cf._delay_budget(0.001)
    assert _cf.DELAY_BUDGET_MIN <= budget <= _cf.RAW_TIMEOUT
    # raw request to a dead port returns a RawResp with error, cleanly
    ctx = _Ctx()
    r = _cf._raw_get(ctx, "/chaos/stable", _cf._base_headers("127.0.0.1:1"),
                     timeout=1.0, host="127.0.0.1", port=1, scheme="http")
    assert r.status == 0 and r.error


def test_check_gate_off_is_noop():
    os.environ.pop("PTK_CHAOS", None)
    os.environ.pop("VANTHEX_CHAOS", None)
    ctx = _Ctx()
    ctx._targets = [(f"{BASE}/chaos/expect", "v", "GET", "")]
    added = []
    _cf.c_chaos(ctx, added.append)
    assert added == []
    assert any("gate" in m for m in ctx.logs)


def test_check_gate_on_bounds_endpoints_and_faults():
    os.environ["PTK_CHAOS"] = "1"
    try:
        ctx = _Ctx()
        # 8 targets -> only MAX_ENDPOINTS (6) processed
        ctx._targets = [(f"{BASE}/chaos/g{i}", "v", "GET", "")
                        for i in range(8)]
        added = []
        _cf.c_chaos(ctx, added.append)
        done = [m for m in ctx.logs if m.startswith("  [chaosfault] done:")]
        assert done and "6 endpoint(s)" in done[0]
        # max 2 fault families per endpoint on the stable surface: no findings
        assert added == []
        assert not ctx.cancelled()
    finally:
        os.environ.pop("PTK_CHAOS", None)


def test_cancelled_ctx_is_noop():
    ctx = _Ctx()
    ctx.cancelled = lambda: True
    fs = _cf.run_chaos(ctx, {"path": "/chaos/stable"})
    assert fs == []


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok {name}")
    print("all passed")
