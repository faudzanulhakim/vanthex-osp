"""Self-contained integration tests for wafchain (AUTHORIZED TESTING ONLY
— everything runs against a local http.server WAF emulator fixture).

Emulator WAF behavior:
  * /waf/blocked?q=...  — 403 (block page) when q contains a lone
    "<script" occurrence; but a payload with TWO occurrences
    ("<scr<script>ipt...") is de-duplicated one pass (all "<script>"
    substrings removed, no re-scan) and the reassembled value is
    reflected with 200 — the classic overlap-replace bypass.
  * /waf/clean?q=...    — reflects anything, 200.
  * /waf/blank          — 200, empty body (reflects nothing).
"""

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import quote, urlsplit, parse_qs
import urllib.request

import pytest

from offensive import wafchain

MARKER = "<script>WTX7Q</script>"


# ------------------------------------------------------------ WAF emulator
class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):        # silence test output
        pass

    def _send(self, code, body, headers=()):
        data = body.encode("utf-8", "replace")
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlsplit(self.path)
        q = (parse_qs(u.query).get("q") or [""])[0]

        if u.path == "/waf/blocked":
            if "<script" in q:
                # one-pass, non-recursive strip (str.replace: no re-scan);
                # the WAF blocks only when nothing script-like survives the
                # strip. An overlap-replaced variant's residue REASSEMBLES
                # into "<script>" and slips past as the forwarded value.
                residue = q.replace("<script>", "")
                if "<script" not in residue:
                    self._send(403, "Request blocked by security policy "
                                    "(emulated WAF)",
                               [("Server", "cloudflare")])
                else:
                    self._send(200, "<html>echo:%s</html>" % residue)
            else:
                self._send(200, "<html>echo:%s</html>" % q,
                           [("Server", "cloudflare")])
        elif u.path == "/waf/decode":
            from urllib.parse import unquote
            self._send(200, "<html>echo:%s</html>" % unquote(unquote(q)))
        elif u.path == "/waf/clean":
            self._send(200, "<html>echo:%s</html>" % q)
        elif u.path == "/waf/blank":
            self._send(200, "")
        else:
            self._send(404, "not found")


@pytest.fixture(scope="module")
def waf_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


@pytest.fixture()
def gate_on(monkeypatch):
    monkeypatch.setenv(wafchain.GATE_ENV, "1")


def _builder(base, path="/waf/blocked", counter=None):
    def build(payload):
        url = "%s%s?q=%s" % (base, path, quote(payload, safe=""))
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                status, body = r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status = e.code
            body = e.read().decode("utf-8", "replace")
        if counter is not None:
            counter.append(1)
        return SimpleNamespace(status=status, body=body, headers=[])
    return build


# ------------------------------------------------------------ tests
def test_fingerprint_detects_cloudflare():
    r = wafchain.fingerprint_waf(
        [("Server", "cloudflare"), ("CF-RAY", "8f3a-EWR")],
        "Attention Required | Cloudflare Ray ID: 8f3ac0ffee", status=403)
    assert r["waf"] == "Cloudflare"
    assert r["confidence"] >= 0.9
    assert r["bank_key"] == "cloudflare"


def test_fingerprint_unknown_waf_not_guessed():
    r = wafchain.fingerprint_waf([], "you have been blocked", status=403)
    assert r["waf"] == "Unknown WAF"
    assert r["confidence"] > 0


def test_fingerprint_clean_response_is_none():
    r = wafchain.fingerprint_waf([], "<html>hello</html>", status=200)
    assert r["waf"] is None


def test_select_bypasses_ordered_and_capped():
    sel = wafchain.select_bypasses("Cloudflare")
    assert 1 <= len(sel) <= wafchain.MAX_STRATEGIES
    assert sel[0][0] == "overlap-nest"          # chain strategy leads
    names = [n for n, _ in sel]
    assert len(names) == len(set(names))
    assert all(callable(fn) for _, fn in sel)
    # generic degradation for unknown fingerprints
    assert wafchain.select_bypasses("totally-unknown-waf")[0][0] == "overlap-nest"


def test_overlap_nest_transform_form():
    t = wafchain.select_bypasses("generic")[0][1]
    v = t(MARKER)
    assert v != MARKER
    # overlap-replace: one-pass removal of the tag reassembles the marker
    assert v.replace("<script>", "") == MARKER


def test_test_bypasses_gated_makes_no_requests(waf_server):
    counter = []
    f, d = wafchain.test_bypasses(_builder(waf_server, counter=counter),
                                  MARKER, waf="Cloudflare")
    assert counter == []
    assert d["requests"] == 0
    assert f["confidence"] == "none"
    assert "PTK_WAFCHAIN" in f["description"]


def test_test_bypasses_finds_confirmed_bypass(waf_server, gate_on):
    counter = []
    f, d = wafchain.test_bypasses(
        _builder(waf_server, counter=counter), MARKER, waf="Cloudflare",
        log=lambda *a: None)
    assert d["baseline_blocked"] is True            # differential control
    assert d["winner"] and d["winner"]["strategy"] == "overlap-nest"
    assert d["confirmed"] is True
    assert d["requests"] <= wafchain.MAX_STRATEGIES + 1
    assert f["confidence"] == "confirmed"
    assert isinstance(f["description"], str) and f["description"]
    # winner payload survives the emulator's one-pass strip intact
    assert d["winner"]["payload"].replace("<script>", "") == MARKER


def test_test_bypasses_candidate_without_differential(waf_server, gate_on):
    # /waf/decode un-decodes the payload: the double-urlencode strategy
    # comes back decoded & intact, but the baseline was never blocked,
    # so there is no differential -> candidate, never CONFIRMED.
    f, d = wafchain.test_bypasses(
        _builder(waf_server, path="/waf/decode"), MARKER, waf="generic")
    assert d["winner"] and d["confirmed"] is False
    assert d["winner"]["strategy"] == "double-urlencode"
    assert f["confidence"] == "candidate"


def test_test_bypasses_no_winner_on_silent_endpoint(waf_server, gate_on):
    f, d = wafchain.test_bypasses(
        _builder(waf_server, path="/waf/blank"), MARKER, waf="generic")
    assert d["winner"] is None and f["confidence"] == "none"


def test_chain_into_check_transforms_payloads(waf_server, gate_on):
    seen = []

    def check_fn(payload, extra=None):
        seen.append((payload, extra))
        return "ran:%s" % payload

    ctx = SimpleNamespace(L=lambda *a: None)
    wrapped = wafchain.chain_into_check(
        ctx, "Cloudflare", check_fn,
        target_req_builder=_builder(waf_server), marker=MARKER)
    assert wrapped is not check_fn
    out = wrapped(MARKER, extra="x")
    assert seen[-1][1] == "x"
    # payload was transformed to the winning overlap-nest form
    assert seen[-1][0] != MARKER
    assert seen[-1][0].replace("<script>", "") == MARKER
    assert out == "ran:%s" % seen[-1][0]
    assert wrapped._wafchain["strategy"] == "overlap-nest"
    assert wrapped._wafchain["confirmed"] is True
    # winner cached on ctx — a second chain makes no new requests
    counter = []
    w2 = wafchain.chain_into_check(
        ctx, "Cloudflare", check_fn,
        target_req_builder=_builder(waf_server, counter=counter),
        marker=MARKER)
    assert counter == []
    assert w2._wafchain["strategy"] == "overlap-nest"


def test_chain_into_check_passthrough_without_winner(waf_server, gate_on):
    def check_fn(payload):
        return payload

    ctx = SimpleNamespace(L=lambda *a: None)
    wrapped = wafchain.chain_into_check(
        ctx, "generic", check_fn,
        target_req_builder=_builder(waf_server, path="/waf/blank"),
        marker=MARKER)
    assert wrapped is check_fn


def test_chain_into_check_gated_is_passthrough(waf_server):
    def check_fn(payload):
        return payload

    ctx = SimpleNamespace(L=lambda *a: None)
    wrapped = wafchain.chain_into_check(
        ctx, "Cloudflare", check_fn,
        target_req_builder=_builder(waf_server), marker=MARKER)
    assert wrapped is check_fn


def test_explicit_gate_override(waf_server):
    counter = []
    f, d = wafchain.test_bypasses(
        _builder(waf_server, counter=counter), MARKER, waf="Cloudflare",
        gate=False)
    assert counter == []                      # explicit False wins over env
    f, d = wafchain.test_bypasses(
        _builder(waf_server, counter=counter), MARKER, waf="Cloudflare",
        gate=True)
    assert d["confirmed"] is True             # explicit True without env
