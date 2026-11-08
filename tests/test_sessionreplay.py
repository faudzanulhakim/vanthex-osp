"""Hermetic tests for Session Replay (HAR import + replay).

Nothing leaves the process: the "target" is an in-process
ThreadingHTTPServer (same style as the other engine tests, which spawn
the fixture server; here a purpose-built micro-server keeps the suite
hermetic and fast). Run:
    .venv/bin/python -m pytest tests/test_sessionreplay.py -q
AUTHORIZED TESTING ONLY.
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import actions  # noqa: E402
import sessionreplay as sr  # noqa: E402

ACCOUNTS = {
    "u1": {"owner": "alice", "iban": "NL00ALICE0001"},
    "u2": {"owner": "bob", "iban": "NL00BOB00002"},
}


def _make_handler(state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def _send(self, code, body=b"", ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path.startswith("/api/account/"):
                uid = self.path.rsplit("/", 1)[-1]
                # Deliberately broken authz: serves ANY account to ANY
                # cookie — the IDOR suspect the replay must flag.
                acct = ACCOUNTS.get(uid)
                if acct is None:
                    self._send(404, b'{"error":"not found"}')
                    return
                self._send(200, json.dumps(acct).encode())
                return
            if self.path.startswith("/api/items"):
                cookie = self.headers.get("Cookie") or ""
                user = "bob-long-username" if "u2" in cookie else "u1"
                payload = json.dumps({"items": [1, 2], "who": user,
                                      "note": "x" * (300 if user != "u1" else 0)})
                self._send(200, payload.encode())
                return
            self._send(404, b'{"error":"nf"}')

        def do_POST(self):
            if self.path.startswith("/api/admin"):
                if "role=admin" not in (self.headers.get("Cookie") or ""):
                    self._send(403, b'{"error":"forbidden"}')
                    return
                self._send(200, b'{"ok":true}')
                return
            self._send(404, b'{"error":"nf"}')

    return H


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler({}))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


def _har(base, entries):
    return {"log": {"version": "1.2", "creator": {"name": "t", "version": "1"},
                    "entries": entries}}


def _entry(method, url, cookie=None, body=None, resp_len=None):
    headers = ([{"name": "Cookie", "value": cookie}] if cookie else [])
    req = {"method": method, "url": url, "headers": headers,
           "cookies": [], "headersSize": -1, "bodySize": 0}
    if body is not None:
        req["postData"] = {"mimeType": "application/json", "text": body}
    resp = {"status": 200, "headers": [], "content": {"size": resp_len or 0,
            "mimeType": "application/json"}}
    if resp_len is not None:
        resp["headers"] = [{"name": "Content-Length", "value": str(resp_len)}]
    return {"request": req, "response": resp}


# ---------------------------------------------------------------- parse ----

def test_parse_har_wellformed():
    har = _har("http://x", [_entry("GET", "http://x/api/a", cookie="s=1"),
                            _entry("POST", "http://x/api/b", body='{"a":1}')])
    reqs = sr.parse_har(har)
    assert len(reqs) == 2
    assert reqs[0]["method"] == "GET"
    assert reqs[0]["headers"]["cookie"] == "s=1"
    assert reqs[0]["cookies"] == {"s": "1"}
    assert reqs[1]["body"] == '{"a":1}'


def test_parse_har_bytes_and_cookies_array():
    har = _har("http://x", [_entry("GET", "http://x/")])
    har["log"]["entries"][0]["request"]["cookies"] = [{"name": "k", "value": "v"}]
    reqs = sr.parse_har(json.dumps(har).encode())
    assert reqs[0]["cookies"] == {"k": "v"}


def test_parse_har_malformed_tolerant():
    assert sr.parse_har(b"not json at all") == []
    assert sr.parse_har(None) == []
    assert sr.parse_har({"log": {"entries": [None, 42, {}, "x"]}}) == []
    har = _har("http://x", [{"request": {"method": "GET"}},        # no url
                            {"nope": True},                         # no request
                            _entry("GET", "http://x/ok")])
    assert [r["url"] for r in sr.parse_har(har)] == ["http://x/ok"]


# --------------------------------------------------------------- replay ----

def test_replay_idor_suspect(server):
    har = _har("http://x", [_entry("GET", server + "/api/account/u1",
                                   cookie="session=u1tok")])
    reqs = sr.parse_har(har)
    steps = sr.replay_chain(None, reqs, mutations={"cookie": "session=u2tok"})
    assert len(steps) == 1
    st = steps[0]
    assert st["status"] == 200
    assert st["modified_identity"] is True
    assert st["interesting"] is True
    assert st["reason"] == "modified-identity-2xx"


def test_replay_negative_403_no_finding(server):
    har = _har("http://x", [_entry("POST", server + "/api/admin",
                                   cookie="role=user", body="{}")])
    reqs = sr.parse_har(har)
    steps = sr.replay_chain(None, reqs, mutations={"cookie": "role=attacker"})
    st = steps[0]
    assert st["status"] == 403
    assert st["interesting"] is False
    out = sr.analyze_capture(har, mutations={"cookie": "role=attacker"})
    assert out["findings"] == []


def test_replay_get_length_diff_state_change(server):
    # Capture as u1 (short body), replay with u2 cookie -> >30% longer.
    capture_len = len(json.dumps({"items": [1, 2], "who": "u1", "note": ""}))
    har = _har("http://x", [_entry("GET", server + "/api/items",
                                   cookie="u1", resp_len=capture_len)])
    out = sr.analyze_capture(har, mutations={"cookie": "u2"})
    st = out["steps"][0]
    assert st["status"] == 200
    assert st["interesting"] is True
    assert st["reason"].startswith("get-content-diff-")
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["title"] == "Session Replay Revealed State Change"
    assert f["severity"] == "HIGH"
    assert 7.5 <= f["cvss"] <= 8.2


def test_findings_idor_shape(server):
    har = _har("http://x", [_entry("GET", server + "/api/account/u1",
                                   cookie="session=u1tok")])
    out = sr.analyze_capture(har, mutations={"cookie": "session=u2tok"})
    f = out["findings"][0]
    assert f["title"] == "Replayed Request Bypassed Authorization (IDOR Suspect)"
    assert f["severity"] == "HIGH"
    assert f["cwe"] == "CWE-639"
    assert 7.5 <= f["cvss"] <= 8.2
    assert f["remediation"]
    assert "GET" in f["evidence"] and "200" in f["evidence"]


def test_max_steps_and_placeholder(server):
    har = _har("http://x", [_entry("GET", server + "/api/account/{{UID}}",
                                   cookie="session=u1tok")
                            for _ in range(8)])
    reqs = sr.parse_har(har)
    steps = sr.replay_chain(None, reqs,
                            mutations={"placeholders": {"UID": "u2"},
                                       "cookie": "session=u2tok"},
                            max_steps=3)
    assert len(steps) == 3
    assert all(s["status"] == 200 for s in steps)


# -------------------------------------------------------------- actions ----

def test_actions_import_and_replay(server):
    har = _har("http://x", [_entry("GET", server + "/api/account/u1",
                                   cookie="session=u1tok")])
    imp = actions._ACTIONS["importHar"](
        {"name": "lab", "data": json.dumps(har)}, 0)
    assert imp["entries"] == 1 and imp["id"].startswith("sr-")
    rep = actions._ACTIONS["replayCapture"](
        {"id": imp["id"], "mutations": {"cookie": "session=u2tok"}}, 0)
    assert rep["summary"]["steps"] == 1
    assert rep["summary"]["interesting"] == 1
    assert rep["findings"][0]["title"].startswith("Replayed Request")
    # base64 variant + unknown id error path
    import base64
    imp2 = actions._ACTIONS["importHar"](
        {"name": "b64", "dataBase64": base64.b64encode(
            json.dumps(har).encode()).decode()}, 0)
    assert imp2["entries"] == 1
    with pytest.raises(ValueError):
        actions._ACTIONS["replayCapture"]({"id": "sr-9999"}, 0)
    with pytest.raises(ValueError):
        actions._ACTIONS["importHar"]({"name": "bad", "data": "{oops"}, 0)


def test_actions_registry():
    assert actions._ACTIONS["importHar"] is not None
    assert actions._ACTIONS["replayCapture"] is not None
    assert len(actions._ACTIONS) == 54
