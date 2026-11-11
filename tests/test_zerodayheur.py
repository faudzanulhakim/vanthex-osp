"""
tests/test_zerodayheur.py — self-contained integration tests for the
behavioral zero-day heuristics fuzzer (zerodayheur.py).

Own HTTP fixture (module-level autostart, ThreadingHTTPServer):
  * POST /zday/parse  {"v": ...} — 500s when a nested-dict depth > 3
    arrives (no known error signature in the body),
  * POST /zday/leak   {"v": ...} — echoes an internal flag token ONLY
    when the parameter type is an array,
  * POST /zday/clean  {"v": ...} — stable baseline, no behavioral anomaly,
  * GET  /zday/state  — observable counter changed by dict-typed input on
    POST /zday/counter.

Run: .venv/bin/python -m pytest tests/test_zerodayheur.py -q
"""
import json
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
from offensive import zerodayheur as _zd               # noqa: E402
from exploitkit import _F               # noqa: E402

PORT = 18477
FLAG_TOKEN = "INTERNAL_FLAG_ZD9K2M"


class _State:
    lock = threading.Lock()
    counter = 0


def _depth(v, d=0):
    if isinstance(v, dict):
        return max((_depth(x, d + 1) for x in v.values()), default=d + 1)
    return d


class _H(BaseHTTPRequestHandler):
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
        if self.path.startswith("/zday/state"):
            with _State.lock:
                self._reply(200, json.dumps({"counter": _State.counter}))
        else:
            self._reply(404, "not found")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            data = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            data = {}
        v = data.get("v")
        if self.path.startswith("/zday/parse"):
            if isinstance(v, dict) and _depth(v) > 3:
                # deliberate: no traceback / no known signature in the body
                self._reply(500, json.dumps({"error": "processing failed"}))
                return
            self._reply(200, json.dumps({"ok": True, "echo": v}))
        elif self.path.startswith("/zday/leak"):
            if isinstance(v, list):
                self._reply(200, json.dumps(
                    {"ok": True, "echo": v, "flag": FLAG_TOKEN}))
            else:
                self._reply(200, json.dumps({"ok": True, "echo": v}))
        elif self.path.startswith("/zday/counter"):
            with _State.lock:
                if isinstance(v, dict):
                    _State.counter += 1
                self._reply(200, json.dumps({"ok": True, "echo": v}))
        elif self.path.startswith("/zday/clean"):
            self._reply(200, json.dumps({"ok": True, "echo": v}))
        else:
            self._reply(404, "not found")


_srv = ThreadingHTTPServer(("127.0.0.1", PORT), _H)
threading.Thread(target=_srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{PORT}"


class _Ctx:
    """Minimal ctx stub matching the Ctx contract used by zerodayheur."""
    def __init__(self):
        self.client = Client(BASE, timeout=10)
        self.logs = []

    def cancelled(self):
        return False

    def L(self, msg):
        self.logs.append(msg)


def _run(path, param="v", value="1", state_path=None):
    ctx = _Ctx()
    ep = {"path": path, "param": param, "method": "POST", "value": value,
          "json_body": True,
          "state_path": state_path or path}
    fs = _zd.fuzz_endpoint(ctx, ep)
    return ctx, fs


def test_500_cluster_detected_on_parse():
    ctx, fs = _run("/zday/parse")
    titles = [f["title"] for f in fs]
    assert any("5xx Cluster" in t for t in titles), fs
    f = [f for f in fs if "5xx Cluster" in f["title"]][0]
    assert f["severity"] == "HIGH"
    # differential credit only because the follow-up control reproduced
    assert f["verification"] == "differential"
    assert f["confidence"] == "probable"
    assert "500" in f["evidence"] or "5xx" in f["evidence"]


def test_differential_leak_found():
    ctx, fs = _run("/zday/leak")
    leak = [f for f in fs if "Body-Content Leak" in f["title"]]
    assert leak, fs
    f = leak[0]
    assert FLAG_TOKEN in f["evidence"]
    assert f["verification"] == "differential"


def test_clean_baseline_no_findings():
    ctx, fs = _run("/zday/clean")
    # the clean endpoint may legitimately show a timing/noise candidate but
    # must never produce a 5xx cluster, a leak, or a state change
    assert not [f for f in fs if "5xx Cluster" in f["title"]]
    assert not [f for f in fs if "Body-Content Leak" in f["title"]]
    assert not [f for f in fs if "State Change" in f["title"]]


def test_state_change_detected():
    with _State.lock:
        _State.counter = 0
    ctx, fs = _run("/zday/counter", state_path=f"{BASE}/zday/state")
    st = [f for f in fs if "State Change" in f["title"]]
    assert st, fs
    assert st[0]["confidence"] in ("probable", "candidate")


def test_request_budget_and_cancel():
    ctx = _Ctx()
    budget = {"n": 0}

    orig_get = ctx.client.get
    orig_post = ctx.client.post

    def counting(fn, *a, **kw):
        budget["n"] += 1
        return fn(*a, **kw)

    ctx.client.get = lambda *a, **kw: counting(orig_get, *a, **kw)
    ctx.client.post = lambda *a, **kw: counting(orig_post, *a, **kw)
    ep = {"path": "/zday/clean", "param": "v", "method": "POST",
          "value": "1", "json_body": True, "state_path": None}
    _zd.fuzz_endpoint(ctx, ep)
    # fuzz phase hard cap: baseline + 50 mutations + baseline re-check <= 52
    assert budget["n"] <= _zd.MAX_REQUESTS, budget["n"]

    ctx2 = _Ctx()
    ctx2.cancelled = lambda: True
    ep2 = dict(ep)
    fs = _zd.fuzz_endpoint(ctx2, ep2)
    assert fs == []


def test_check_gate_off_is_noop():
    os.environ.pop("PTK_ZERODAY", None)
    ctx = _Ctx()
    added = []
    _zd.c_zeroday_heur(ctx, added.append)
    assert added == []


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok {name}")
    print("all passed")
