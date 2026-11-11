"""Self-contained integration-style tests for chainexec.py.

Fixture: an http.server with a small vulnerable chain surface:
  /chain/secret            — internal endpoint returning PTKSECRET... token
  /chain/ssrf?u=<path>     — SSRF: proxies GET to an internal path
  /chain/cmdi?q=<cmd>      — simulated command injection: `echo X` echoes X
No real commands are executed — the fixture only simulates the echo.
"""
import http.server
import json
import os
import threading
import urllib.request

import pytest

import netclient
from offensive import chainexec

SECRET_TOKEN = "PTKSECRET" + "a41f9c77d2"


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/plain"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/chain/secret":
            self._send(200, "internal token: " + SECRET_TOKEN)
        elif self.path.startswith("/chain/ssrf"):
            qs = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query)
            target = (qs.get("url") or [""])[0]
            if target.startswith("/"):
                # simulate the server-side fetch of the internal path
                if target == "/chain/secret":
                    self._send(200, "internal token: " + SECRET_TOKEN)
                else:
                    self._send(404, "not found")
            else:
                self._send(400, "bad target")
        elif self.path.startswith("/chain/cmdi"):
            qs = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query)
            q = (qs.get("q") or [""])[0]
            # simulate `echo X`: echo back the argument after "echo "
            if q.startswith("echo "):
                self._send(200, "output: " + q[5:] + "\n")
            else:
                self._send(200, "output: (no echo)")
        elif self.path == "/chain/item/2":
            self._send(200, json.dumps({"id": 2, "uid": "admin", "email": "admin@x"}))
        else:
            self._send(404, "not found")


@pytest.fixture(scope="module")
def server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port
    srv.shutdown()


def _ctx(port, approve=None):
    os.environ["NO_PROXY"] = "127.0.0.1,localhost"
    os.environ["no_proxy"] = "127.0.0.1,localhost"

    class Ctx:
        def __init__(self):
            self.client = netclient.Client(f"http://127.0.0.1:{port}")
            self.opts = {"approve_token": approve} if approve else {}
            self.approve_token = approve

        def cancelled(self):
            return False

    return Ctx()


def _findings():
    return [
        {"severity": "HIGH", "title": "SSRF — server-side request to internal service",
         "description": "The url parameter is fetched server-side (SSRF); "
                        "internal service access possible.",
         "evidence": "GET /chain/ssrf?url=http://127.0.0.1:9/ -> 200",
         "confidence": "confirmed", "location": "/chain/ssrf", "param": "url"},
        {"severity": "CRITICAL", "title": "Command injection (RCE) in q parameter",
         "description": "OS command injection via the q parameter (command injection).",
         "evidence": "GET /chain/cmdi?q=echo test -> test",
         "confidence": "confirmed", "location": "/chain/cmdi", "param": "q"},
        {"severity": "HIGH", "title": "SQL injection — union select data extraction",
         "description": "SQL injection in the id parameter allows union select "
                        "data extraction (sql injection).",
         "evidence": "GET /chain/item?id=1' OR '1'='1 -> rows",
         "confidence": "probable", "location": "/chain/item", "param": "id"},
    ]


# ---------------------------------------------------------------- build_chains

def test_build_chains_pairs_correctly():
    plans = chainexec.build_chains(_findings())
    types = {p["type"]: p for p in plans}
    assert {"ssrf", "cmdi", "sqli"} <= set(types)
    ssrf = types["ssrf"]
    assert "etadata" in ssrf["name"] or "nternal" in ssrf["name"]
    assert ssrf["steps"], "ssrf plan must have steps"
    step = ssrf["steps"][-1]
    assert step["method"] == "GET"
    assert "169.254.169.254" not in step["url"]  # no metadata claim in finding
    assert step["url"].startswith("/chain/ssrf?url=")
    assert step["expected"]  # concrete proof regex
    # a cloud-metadata SSRF finding gets the IMDS step appended
    cloud = dict(_findings()[0])
    cloud["description"] = "SSRF to cloud metadata endpoint (IMDS)."
    cloud_plans = chainexec.build_chains([cloud])
    assert "169.254.169.254" in cloud_plans[0]["steps"][-1]["url"]
    cmdi = types["cmdi"]
    assert "echo" in cmdi["steps"][-1]["url"]
    assert cmdi["safety_class"] == "active"
    assert ssrf["safety_class"] == "safe"
    assert all(len(p["steps"]) <= chainexec.MAX_STEPS for p in plans)
    # impact ordering: cmdi (CRITICAL + 45 bonus) above ssrf
    assert types["cmdi"]["impact"] >= types["ssrf"]["impact"]
    # non-vuln input is inert
    assert chainexec.build_chains([{"title": "info banner"}]) == []
    assert chainexec.build_chains(None) == []
    assert chainexec.build_chains("junk") == []


# ---------------------------------------------------------------- execute_chain

def test_execute_chain_confirms_on_fixture(server):
    plans = chainexec.build_chains(_findings())
    ssrf = next(p for p in plans if p["type"] == "ssrf")
    res = chainexec.execute_chain(ssrf, _ctx(server, approve="operator-yes"))
    assert res["status"] == "confirmed"
    assert res["verification"] == "executed-proof"
    assert res["steps_run"] == len(ssrf["steps"])
    assert res["evidence"] and (res["evidence"][-1]["proof"] or "").startswith(SECRET_TOKEN)
    assert all(e["verification"] == "executed-proof" for e in res["evidence"])

    cmdi = next(p for p in plans if p["type"] == "cmdi")
    res2 = chainexec.execute_chain(cmdi, _ctx(server, approve="operator-yes"))
    assert res2["status"] == "confirmed"
    assert chainexec.CMD_PROOF in (res2["evidence"][-1]["proof"] or "")


def test_execute_chain_partial_reports_failed_step(server):
    # sqli fixture endpoint does not return the dump marker -> candidate
    plans = chainexec.build_chains(_findings())
    sqli = next(p for p in plans if p["type"] == "sqli")
    res = chainexec.execute_chain(sqli, _ctx(server, approve="operator-yes"))
    assert res["status"] == "partial"
    assert res["verification"] == "candidate"
    assert res["failed_step"] == 0
    assert "did not produce its expected proof" in res["note"]


def test_execute_chain_refuses_without_token(server):
    plans = chainexec.build_chains(_findings())
    res = chainexec.execute_chain(plans[0], _ctx(server, approve=None))
    assert res["status"] == "refused"
    assert res["verification"] == "refused"
    assert res["steps_run"] == 0
    assert "refused" in res["note"].lower()


def test_execute_chain_respects_cancellation(server):
    plans = chainexec.build_chains(_findings())
    ssrf = next(p for p in plans if p["type"] == "ssrf")

    class CancelCtx:
        def __init__(self, port):
            base = _ctx(port)
            self.client = base.client
            self.opts = base.opts
            self.approve_token = "operator-yes"

        def cancelled(self):
            return True

    res = chainexec.execute_chain(ssrf, CancelCtx(server))
    assert res["status"] == "cancelled"
    assert res["steps_run"] == 0


def test_execute_chain_max_steps_cap():
    plan = {"name": "over-long", "impact": 10,
            "steps": [{"method": "GET", "url": "/x", "headers": {},
                       "body": None, "expected": "X", "desc": "",
                       "final": True} for _ in range(10)]}
    ctx = _ctx(1, approve="t")  # client never used; steps are capped first
    res = chainexec.execute_chain(plan, ctx)
    # capped to MAX_STEPS; the request itself fails -> clean partial abort
    assert res["steps_run"] <= chainexec.MAX_STEPS


def test_summary_english():
    txt = chainexec.summarize([{"chain": "SSRF -> Cloud Metadata Fetch",
                                "status": "confirmed",
                                "verification": "executed-proof",
                                "steps_run": 1, "note": "all steps ok",
                                "evidence": [{"step_index": 0,
                                              "verification": "executed-proof",
                                              "proof": SECRET_TOKEN}]}])
    assert "confirmed" in txt and SECRET_TOKEN in txt
