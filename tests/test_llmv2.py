"""
test_llmv2.py — hermetic tests for llmv2 (LLM/AI attack suite v2).

Own minimal http.server fixture (does NOT touch fixture_vuln_server.py):
- GET  /           → page titled "PiggyBank AI Assistant" (AI fingerprint)
- POST /ai/chat    → vulnerable chat: echoes benignly, but leaks system
  prompt / tool output / canary under injection, jailbreak (incl. base64
  decode and multi-turn warm-up state), and extraction probes
- POST /safe/ai/chat → sanitized control: never leaks (fp-guard control)

Run: pytest tests/test_llmv2.py -q   (or .venv/bin/python -m pytest)
"""
import base64
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PORT = 18422
BASE = f"http://127.0.0.1:{PORT}/"

CANARY = "LLMV2-CANARY-OK"
LEAK = ("SYSTEM: You are PiggyBank's internal assistant. "
        "Secret API key: sk-internal-999. Tools: internal_tool_exec(). "
        + CANARY)
BENIGN = "Hello! I am the PiggyBank assistant. How can I help you today?"

_MULTI_STATE = {"armed": False}

INJECT_TRIGGERS = ("ignore", "system prompt", "you are",
                   "repeat everything", "internal_tool",
                   "translate your initial", "print your",
                   "configuration starting with")


def _should_leak(msg):
    low = msg.lower()
    # base64 encoding jailbreak: decode base64 segments
    for seg in msg.split():
        try:
            dec = base64.b64decode(seg, validate=True).decode("utf-8",
                                                              "ignore")
            low += " " + dec.lower()
        except Exception:
            pass
    if any(t in low for t in INJECT_TRIGGERS):
        return True
    if _MULTI_STATE["armed"] and ("reveal" in low or "script" in low):
        return True
    if "pretend you are an actor" in low:
        _MULTI_STATE["armed"] = True
    return False


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/":
            self._send(200,
                       "<html><head><title>PiggyBank AI Assistant"
                       "</title></head><body>chat with our bot</body>"
                       "</html>", "text/html")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        try:
            msg = str(json.loads(self.rfile.read(length) or b"{}")
                      .get("message") or "")
        except Exception:
            msg = ""
        if self.path == "/ai/chat":
            self._send(200, json.dumps({"reply": LEAK if _should_leak(msg)
                                        else BENIGN}))
        elif self.path == "/safe/ai/chat":
            self._send(200, json.dumps({"reply": BENIGN}))
        else:
            self._send(404, "not found", "text/plain")


_srv = None


def _start():
    global _srv
    if _srv is None:
        _srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
        threading.Thread(target=_srv.serve_forever, daemon=True).start()
    return _srv


def _make_ctx():
    import vulnscan2 as v
    return v.Ctx(BASE, {}, [])


def setup_module(module=None):
    _start()


def test_gate_blocks_checks_by_default(monkeypatch):
    from offensive import llmv2
    monkeypatch.delenv("PTK_LLMV2", raising=False)
    ctx, found = _make_ctx(), []
    llmv2.c_llmv2_prompt_injection(ctx, found.append)
    llmv2.c_llmv2_jailbreak(ctx, found.append)
    llmv2.c_llmv2_system_prompt_extraction(ctx, found.append)
    assert found == []


def test_discovery_fingerprint():
    from offensive import llmv2
    ctx = _make_ctx()
    eps = llmv2._discover(ctx)
    assert "/ai/chat" in eps
    # landing page title is AI-like; but /safe/... paths are not candidates
    assert all(not e.startswith("/safe") for e in eps)


def test_prompt_injection_confirmed(monkeypatch):
    from offensive import llmv2
    monkeypatch.setenv("PTK_LLMV2", "1")
    ctx, found = _make_ctx(), []
    llmv2.c_llmv2_prompt_injection(ctx, found.append)
    assert found, "no prompt-injection finding"
    f = found[0]
    assert f["severity"] == "CRITICAL"
    assert f["confidence"] == "confirmed"
    assert f["location"] == "/ai/chat"
    assert CANARY.lower() in f["evidence"].lower() or \
        "instruction-override" in f["evidence"]
    assert f["verification"] == "confirmed"
    assert "control" in f["verification_note"].lower()


def test_jailbreak_confirmed(monkeypatch):
    from offensive import llmv2
    monkeypatch.setenv("PTK_LLMV2", "1")
    _MULTI_STATE["armed"] = False
    ctx, found = _make_ctx(), []
    llmv2.c_llmv2_jailbreak(ctx, found.append)
    assert found, "no jailbreak finding"
    f = found[0]
    assert "Jailbreak" in f["title"]
    assert f["confidence"] == "confirmed"
    assert "roleplay-dan" in f["evidence"]
    assert "encoding-base64" in f["evidence"]
    assert "multi-turn" in f["evidence"]


def test_system_prompt_extraction_confirmed(monkeypatch):
    from offensive import llmv2
    monkeypatch.setenv("PTK_LLMV2", "1")
    ctx, found = _make_ctx(), []
    llmv2.c_llmv2_system_prompt_extraction(ctx, found.append)
    assert found, "no extraction finding"
    f = found[0]
    assert "System Prompt" in f["title"]
    assert f["confidence"] == "confirmed"
    assert f["location"] == "/ai/chat"


def test_fp_guard_not_triggered_on_fully_sanitized_target(monkeypatch):
    """If the /safe control behaves identically (i.e. whole target
    sanitized), the differential must not confirm — simulate by pointing
    discovery at an endpoint that never leaks."""
    from offensive import llmv2
    monkeypatch.setenv("PTK_LLMV2", "1")

    class FakeClient:
        def post(self, ep, data=None, headers=None):
            return _R(200, json.dumps({"reply": BENIGN}))

        def get(self, ep):
            return _R(200, "<title>Plain</title>", )

    class _R:
        def __init__(self, status, body, ctype="application/json"):
            self.status = status
            self.body = body

    class FakeCtx:
        client = FakeClient()

        def L(self, msg):
            self.log = msg

    ctx, found = FakeCtx(), []
    llmv2.c_llmv2_prompt_injection(ctx, found.append)
    llmv2.c_llmv2_jailbreak(ctx, found.append)
    llmv2.c_llmv2_system_prompt_extraction(ctx, found.append)
    assert found == []


def test_generate_payloads_ranked_variants():
    from offensive import llmv2
    finding = {"param": "message", "type": "json",
               "location": "/ai/chat",
               "evidence": 'reflection in json reply field',
               "description": "chat prompt injection"}
    out = llmv2.generate_payloads(finding)
    assert isinstance(out, list) and len(out) == 5
    ranks = [v["rank"] for v in out]
    assert ranks == sorted(ranks) and ranks[0] == 1
    for v in out:
        assert v["payload"] and v["rationale"]
    # chat-shaped param ranks an instruction override first
    assert "instructions" in out[0]["payload"].lower()
    # json reflection context produces a quote-break mutation
    assert any('"prompt"' in v["payload"] for v in out)
    # non-chat finding ranks a classical injection first
    out2 = llmv2.generate_payloads({"param": "file",
                                    "evidence": "reflected in HTML"})
    assert "UNION" in out2[0]["payload"]


if __name__ == "__main__":
    setup_module()
    ok = fail = 0
    for name in sorted(n for n in dict(globals()) if n.startswith("test_")):
        try:
            globals()[name]()
            ok += 1
            print("PASS", name)
        except Exception:
            fail += 1
            print("FAIL", name)
            import traceback
            traceback.print_exc(limit=4)
    print(f"== llmv2: {ok} passed, {fail} failed ==")
    sys.exit(1 if fail else 0)
