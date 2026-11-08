"""
Hermetic tests: PoC Sandbox Validation (pocbox.py) + Lateral Map
(lateralmap.py). Local fixture HTTP server only — no external network.
AUTHORIZED TESTING ONLY.
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import actions  # noqa: E402
import lateralmap  # noqa: E402
import netclient  # noqa: E402
import pocbox  # noqa: E402


# ------------------------------------------------------------- fixture server

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/search":            # raw reflection
            self._send(200, f"<html>Results for {q.get('q', '')}</html>")
        elif u.path == "/fetch":           # SSRF-ish echo of fetched url
            self._send(200, f"fetched: {q.get('url', '')}")
        elif u.path == "/safe/search":     # escaped -> probe must NOT confirm
            import html
            self._send(200, f"Results for {html.escape(q.get('q', ''))}")
        elif u.path == "/etc-hosts":       # traversal fingerprint stand-in
            self._send(200, "127.0.0.1\tlocalhost\n::1 localhost")
        else:
            self._send(404, "not found")


SRV = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
SRV_THREAD = threading.Thread(target=SRV.serve_forever, daemon=True)
SRV_THREAD.start()
BASE = f"http://127.0.0.1:{SRV.server_address[1]}"


def client(path_target=None):
    return netclient.Client(path_target or BASE, timeout=4.0,
                            proxy="none")


# ------------------------------------------------------------- pocbox

def test_pocbox_gated_by_default():
    f = {"title": "Reflected XSS in search", "description": "",
         "evidence": "marker reflected", "location": "/search",
         "param": "q", "confidence": "probable"}
    old = os.environ.pop("PTK_POCBOX", None)
    try:
        out = pocbox.validate_finding(client(), f, {})
        assert out["validated"] is False
        assert out["gated"] is True
        assert out["finding"] is None
    finally:
        if old is not None:
            os.environ["PTK_POCBOX"] = old


def test_pocbox_confirms_reflected_marker():
    f = {"title": "Reflected XSS in search", "description": "xss via q",
         "evidence": "", "location": "/search", "param": "q",
         "confidence": "probable"}
    old = os.environ.pop("PTK_POCBOX", None)
    try:
        out = pocbox.validate_finding(client(), f, {"poc_validate": True})
        assert out["validated"] is True, out
        assert "PTKPOC" in out["proof"]
        assert out["attempts"] >= 1
        upd = out["finding"]
        assert upd["confidence"] == "confirmed"
        assert "poc_proof" in upd
    finally:
        if old is not None:
            os.environ["PTK_POCBOX"] = old


def test_pocbox_env_gate_and_no_false_confirm():
    f = {"title": "Reflected XSS", "location": "/safe/search",
         "param": "q", "confidence": "probable"}
    old = os.environ.pop("PTK_POCBOX", None)
    try:
        os.environ["PTK_POCBOX"] = "1"
        out = pocbox.validate_finding(client(), f, None)
        assert out["validated"] is False
    finally:
        del os.environ["PTK_POCBOX"]
        if old is not None:
            os.environ["PTK_POCBOX"] = old


def test_pocbox_traversal_fingerprint():
    f = {"title": "Path traversal in file param", "location": "/etc-hosts",
         "param": "file", "confidence": "probable"}
    out = pocbox.validate_finding(client(), f, {"poc_validate": True})
    assert out["validated"] is True, out["proof"]
    assert out["kind"] == "traversal"


def test_pocbox_unsupported_kind_skipped():
    f = {"title": "Missing security header", "location": "/", "param": "",
         "confidence": "probable"}
    out = pocbox.validate_finding(client(), f, {"poc_validate": True})
    assert out["validated"] is False and out["kind"] is None


def test_validate_top_bounded_and_cancel():
    findings = [{"title": f"Reflected XSS #{i}", "location": "/search",
                 "param": "q", "confidence": "probable"}
                for i in range(9)]
    out, n = pocbox.validate_top(findings, client(),
                                 {"poc_validate": True}, limit=3,
                                 budget_s=10.0)
    assert n == 3
    assert len(out) == len(findings)
    confirmed = [f for f in out if f.get("poc_proof")]
    assert len(confirmed) == 3
    # cancelled -> nothing runs
    out2, n2 = pocbox.validate_top(findings, client(),
                                   {"poc_validate": True}, limit=3,
                                   cancelled=lambda: True)
    assert n2 == 0


# ------------------------------------------------------------- lateralmap

SAMPLE = [
    {"title": "AWS API key exposed in JS bundle", "description": "",
     "evidence": "api key at https://shop.example.com/static/app.js",
     "location": "/static/app.js", "param": "", "confidence": "confirmed"},
    {"title": "Exposed admin panel", "description": "",
     "evidence": "https://shop.example.com/admin/login reachable",
     "location": "/admin/login", "param": "", "confidence": "probable"},
    {"title": "Config leak: internal services", "description": "",
     "evidence": "mysql://db.internal:3306 and redis://cache.internal:6379 "
                 "in https://shop.example.com/config.json",
     "location": "/config.json", "param": "", "confidence": "confirmed"},
]


def test_lateral_map_credential_panel_edge():
    g = lateralmap.lateral_map(SAMPLE)
    kinds = {n["kind"] for n in g["nodes"]}
    assert {"credential", "panel", "service", "host"} <= kinds
    by_id = {n["id"]: n for n in g["nodes"]}
    cred = next(n["id"] for n in g["nodes"] if n["kind"] == "credential")
    panel = next(n["id"] for n in g["nodes"] if n["kind"] == "panel")
    edges = {(e["from"], e["to"]) for e in g["edges"]}
    assert (cred, panel) in edges
    # every edge references known nodes and carries a via
    for e in g["edges"]:
        assert e["from"] in by_id and e["to"] in by_id and e["via"]


def test_lateral_paths_readable():
    paths = lateralmap.lateral_paths(SAMPLE, limit=5)
    assert paths
    assert all("credential" in p for p in paths)


def test_lateral_map_node_cap():
    many = [{"title": f"Finding {i} at https://host{i}.example.com/x",
             "description": "", "evidence": f"https://host{i}.example.com/x",
             "location": f"/x{i}", "param": "", "confidence": "probable"}
            for i in range(60)]
    g = lateralmap.lateral_map(many)
    assert len(g["nodes"]) <= lateralmap.MAX_NODES == 40


def test_lateral_map_never_raises_on_garbage():
    for bad in (None, [], [None, 42, {"title": None}, {}]):
        g = lateralmap.lateral_map(bad)
        assert isinstance(g, dict) and "nodes" in g and "edges" in g


# ------------------------------------------------------------- integration

def test_pocbox_run_action_registered():
    assert "pocboxRun" in actions._ACTIONS
    assert callable(actions._ACTIONS["pocboxRun"])


def test_run_vulnscan_attaches_lateral_map_and_honors_gates():
    import vulnscan2
    # Lateral map default ON: a run_vulnscan integration is too heavy for
    # hermetic tests, so verify the wiring points directly.
    src = open(vulnscan2.__file__, encoding="utf-8").read()
    assert "PTK_LATERALMAP" in src
    assert '"lateral_map": lateral_map' in src
    assert "poc_validate" in src and "validate_top" in src
    # and the pure function on a vulnscan2.F()-shaped finding list
    f = vulnscan2.F("HIGH", "Exposed admin panel", "admin console",
                    evidence="https://shop.example.com/admin/login",
                    location="/admin/login")
    fk = vulnscan2.F("HIGH", "API key exposed", "hardcoded key",
                     evidence="api key https://shop.example.com/a.js",
                     location="/a.js")
    g = lateralmap.lateral_map([f, fk])
    assert g["node_count"] >= 2
    assert lateralmap.lateral_paths([f, fk], limit=3)
    assert json.dumps(g)  # JSON-serializable for the scan result
