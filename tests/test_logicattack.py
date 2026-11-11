"""Integration tests for logicattack.py — self-contained http.server fixture.

The fixture is an operator-owned TEST TARGET (flagged as such here) that
deliberately exposes the logic flaws the engine detects:
  POST /logic/order   -> creates an order per call (duplicate-apply flaw)
  POST /logic/price   -> accepts quantity=-5, returns a NEGATIVE total
  POST /logic/checkout + GET /logic/final -> final reachable w/o flow
  POST /logic/coupon  -> stacks: each apply lowers the total again
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest

from offensive import logicattack

NO_PROXY_TARGETS = "127.0.0.1,localhost"


class _Fixture(BaseHTTPRequestHandler):
    orders = []
    cart_total = 100.00
    log = []  # every (method, path) the server actually received

    def _respond(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _log(self):
        _Fixture.log.append((self.command, self.path))

    def do_GET(self):
        self._log()
        if self.path.startswith("/logic/final"):
            # FLAW: final-state page served to ANY caller (workflow bypass)
            self._respond(200, {"page": "final", "status": "complete"})
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self):
        self._log()
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        form = {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}
        if self.path.startswith("/logic/order"):
            # FLAW: every POST creates a NEW order (no idempotency)
            oid = "ORD-%04d" % (len(_Fixture.orders) + 1)
            _Fixture.orders.append(oid)
            self._respond(200, {"order_id": oid, "status": "created"})
        elif self.path.startswith("/logic/price"):
            # FLAW: quantity is not lower-bound validated
            try:
                qty = int(form.get("quantity", "1"))
            except ValueError:
                qty = 1
            total = round(qty * 10.00, 2)
            self._respond(200, {"quantity": qty, "total": total,
                                "status": "priced"})
        elif self.path.startswith("/logic/checkout"):
            self._respond(200, {"status": "success", "next": "/logic/final"})
        elif self.path.startswith("/logic/coupon"):
            # FLAW: coupon stacks — total drops on EVERY apply
            code = form.get("code", "")
            if code == "SAVE10":
                _Fixture.cart_total = round(_Fixture.cart_total - 10.00, 2)
                self._respond(200, {"code": code,
                                    "total": _Fixture.cart_total,
                                    "status": "success"})
            else:
                self._respond(400, {"error": "unknown code"})
        else:
            self._respond(404, {"error": "not found"})

    def log_message(self, *args):  # keep pytest output clean
        pass


@pytest.fixture()
def server(monkeypatch):
    # Keep the loopback fixture OFF the runtime proxy (netclient honors
    # NO_PROXY / proxy_bypass).
    monkeypatch.setenv("NO_PROXY", NO_PROXY_TARGETS)
    monkeypatch.setenv("no_proxy", NO_PROXY_TARGETS)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Fixture)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    _Fixture.orders, _Fixture.cart_total, _Fixture.log = [], 100.00, []
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def _har_entry(method, url, body=None, cookie=None):
    headers = [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}]
    if cookie:
        headers.append({"name": "Cookie", "value": cookie})
    req = {"method": method, "url": url, "headers": headers}
    if body is not None:
        req["postData"] = {"text": body}
    return {"request": req}


def _approve(base_url):
    # The target under test is this module's OWN local test fixture.
    return {"approve": True, "target_kind": "test_fixture", "target": base_url}


# ------------------------------------------------------------------ gates --

def test_fail_closed_without_approve(server):
    har = {"log": {"entries": [_har_entry(
        "POST", server + "/logic/order", "item=widget")]}}
    for ctx in (None, {}, {"approve": False}, "nope"):
        res = logicattack.run_logic_checks(har=har, ctx=ctx)
        assert res["findings"] == [] and res["skipped"]
    # zero requests reached the server
    assert _Fixture.log == []


# --------------------------------------------------------- duplicate-apply --

def test_duplicate_apply_detected(server):
    har = {"log": {"entries": [_har_entry(
        "POST", server + "/logic/order", "item=widget")]}}
    res = logicattack.run_logic_checks(har=har, ctx=_approve(server))
    dup = [f for f in res["findings"] if "Duplicate-Apply" in f["title"]]
    assert len(dup) == 1
    f = dup[0]
    assert f["confidence"] == "confirmed"
    assert f["evidence"].count("ORD-") >= 2  # differential: two distinct ids
    assert len(_Fixture.orders) >= 2  # dup-apply probes created new orders


# ------------------------------------------------------- negative quantity --

def test_negative_quantity_detected(server):
    reqs = [{"method": "POST", "url": server + "/logic/price",
             "headers": {}, "body": "item=widget&quantity=2"}]
    res = logicattack.run_logic_checks(requests=reqs, ctx=_approve(server))
    neg = [f for f in res["findings"] if "Negative Amount" in f["title"]]
    assert len(neg) == 1
    f = neg[0]
    assert f["confidence"] == "confirmed"
    assert f["param"] == "quantity"
    assert "-50.0" in f["evidence"]


def test_zero_quantity_does_not_claim_negative(server):
    # quantity=0 -> total 0 (not negative): no finding may cite quantity=0
    # as a negative amount (the -5 probe legitimately fires).
    reqs = [{"method": "POST", "url": server + "/logic/price",
             "headers": {}, "body": "quantity=1"}]
    res = logicattack.run_logic_checks(requests=reqs, ctx=_approve(server))
    assert not any("quantity=0" in f["evidence"] for f in res["findings"])


# ------------------------------------------------------------- step-skip --

def test_step_skip_detected(server):
    har = {"log": {"entries": [
        _har_entry("POST", server + "/logic/cart", "item=widget"),
        _har_entry("POST", server + "/logic/checkout", "item=widget"),
        _har_entry("GET", server + "/logic/final"),
    ]}}
    res = logicattack.run_logic_checks(har=har, ctx=_approve(server))
    skip = [f for f in res["findings"] if "Step-Skip" in f["title"]]
    assert len(skip) == 1
    assert skip[0]["confidence"] == "confirmed"
    assert "/logic/checkout" in skip[0]["evidence"]


# ------------------------------------------------------------ coupon gate --

def test_coupon_stacking_gated_and_detected(server, monkeypatch):
    reqs = [{"method": "POST", "url": server + "/logic/coupon",
             "headers": {}, "body": "code=SAVE10"}]
    # Gate closed: no coupon requests at all.
    monkeypatch.delenv("PTK_LOGIC", raising=False)
    res = logicattack.run_logic_checks(requests=reqs, ctx=_approve(server))
    assert not [f for f in res["findings"] if "Stacking" in f["title"]]
    # Unit-level: the check itself is a no-op while the gate is closed.
    assert logicattack.check_coupon_stacking(
        _approve(server), [{"method": "POST", "url": server + "/logic/coupon",
                            "body": "code=SAVE10", "headers": {},
                            "_origin": server, "_path": "/logic/coupon"}]) == []
    # Gate open: stacking differential is provable.
    monkeypatch.setenv("PTK_LOGIC", "1")
    res = logicattack.run_logic_checks(requests=reqs, ctx=_approve(server))
    stack = [f for f in res["findings"] if "Coupon" in f["title"] and "Stacking" in f["title"]]
    assert len(stack) == 1
    assert stack[0]["confidence"] == "confirmed"


# ------------------------------------------------------- workflow bypass --

def test_workflow_bypass_detected(server):
    reqs = [{"method": "GET", "url": server + "/logic/final",
             "headers": {}, "body": None}]
    res = logicattack.run_logic_checks(requests=reqs, ctx=_approve(server))
    bypass = [f for f in res["findings"] if "Workflow Bypass" in f["title"]]
    assert len(bypass) == 1
    assert bypass[0]["confidence"] == "probable"


# ------------------------------------------------------- cross-user apply --

def test_cross_user_apply_detected(server):
    reqs = [{"method": "POST", "url": server + "/logic/order",
             "headers": {"cookie": "sess=alice"}, "body": "item=widget"}]
    res = logicattack.run_logic_checks(
        requests=reqs, ctx=_approve(server),
        sessions=["sess=alice", "sess=mallory"])
    xuser = [f for f in res["findings"] if "Cross-User" in f["title"]]
    assert len(xuser) == 1
    assert xuser[0]["confidence"] == "probable"


def test_cross_user_requires_two_sessions(server):
    reqs = [{"method": "POST", "url": server + "/logic/order",
             "headers": {"cookie": "sess=alice"}, "body": "item=widget"}]
    res = logicattack.run_logic_checks(
        requests=reqs, ctx=_approve(server), sessions=["sess=alice"])
    assert not [f for f in res["findings"] if "Cross-User" in f["title"]]
