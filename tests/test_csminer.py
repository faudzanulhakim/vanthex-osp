"""
tests/test_csminer.py — hermetic tests for the client-side zero-day miner.
No network, no browser: the tracer is exercised on fixture HTML strings
and c_cs_mine is tested with a stub ctx and the operator gate.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offensive import csminer
from offensive.csminer import JSFlowTracer, runtime_probe_plan, sink_stats, c_cs_mine


FIXTURE_TAINTED = """<html><body>
<div id="out"></div>
<script>
  var h = location.hash.slice(1);
  document.getElementById("out").innerHTML = h;
</script>
</body></html>"""

FIXTURE_SANITIZED = """<html><body>
<div id="out"></div>
<script>
  var h = location.hash.slice(1);
  var safe = DOMPurify.sanitize(h);
  document.getElementById("out").innerHTML = safe;
</script>
</body></html>"""

FIXTURE_POSTMESSAGE = """<script>
window.addEventListener("message", function(event) {
  eval(event.data);
});
</script>"""


class _StubCtx:
    def __init__(self, pages=None):
        self.pages = pages or []
        self.logs = []
        self.findings = []

    def L(self, msg):
        self.logs.append(msg)

    def cancelled(self):
        return False

    def page_bodies(self):
        return self.pages


def test_tainted_innerhtml_flow_with_line():
    flows = JSFlowTracer().trace(FIXTURE_TAINTED, "fixture.html")
    tainted = [f for f in flows if f["taint"]]
    assert tainted, f"expected a tainted flow, got {flows}"
    f = tainted[0]
    assert f["source"] == "location.hash"
    assert f["sink"] == "innerHTML"
    # innerHTML line inside the script block (line 5 of the page)
    assert f["line"] == 5
    assert "location.hash" in f["var_chain"] or "h" in f["var_chain"]


def test_sanitizer_breaks_taint():
    flows = JSFlowTracer().trace(FIXTURE_SANITIZED, "fixture.html")
    tainted = [f for f in flows if f["taint"] and f["sink"] == "innerHTML"]
    assert not tainted, f"sanitizer must break the chain: {tainted}"
    assert any(f["sink"] == "innerHTML" for f in flows)


def test_postmessage_to_eval_flow():
    flows = JSFlowTracer().trace(FIXTURE_POSTMESSAGE, "pm.js")
    tainted = [f for f in flows if f["taint"]]
    assert tainted
    f = tainted[0]
    assert f["source"] == "postMessage event.data"
    assert f["sink"] == "eval"


def test_plan_emits_console_snippet_with_sink_name():
    flows = JSFlowTracer().trace(FIXTURE_TAINTED, "fixture.html")
    plans = runtime_probe_plan(flows)
    assert plans
    p = plans[0]
    assert "innerHTML" in p["snippet"]
    assert "console" in p["snippet"].lower() or "DevTools" in p["snippet"]
    # untainted flows produce no plan
    assert runtime_probe_plan([{"source": "location.hash",
                                "sink": "innerHTML", "taint": False,
                                "var_chain": [], "file": "x", "line": 1}]) == []


def test_c_cs_mine_gated_noop_without_env(monkeypatch):
    monkeypatch.delenv("PTK_CSMINE", raising=False)
    monkeypatch.delenv("VANTHEX_CSMINE", raising=False)
    ctx = _StubCtx(pages=[("http://t/", FIXTURE_TAINTED)])
    c_cs_mine(ctx, ctx.findings.append)
    assert ctx.findings == []
    assert any("gate" in m for m in ctx.logs)


def test_c_cs_mine_gated_run_finds_flows(monkeypatch):
    monkeypatch.setenv("PTK_CSMINE", "1")
    pages = [("http://t/a", FIXTURE_TAINTED),
             ("http://t/b", FIXTURE_POSTMESSAGE)]
    ctx = _StubCtx(pages=pages)
    c_cs_mine(ctx, ctx.findings.append)
    assert len(ctx.findings) >= 2
    f = ctx.findings[0]
    assert f["title"].startswith("Client-Side Data Flow")
    assert f["confidence"] == "candidate"
    assert f["verification"] == "static-analysis"
    assert "var_chain" in f["evidence"]
    assert f["origin"] == "csminer"


def test_c_cs_mine_caps_at_five(monkeypatch):
    monkeypatch.setenv("PTK_CSMINE", "1")
    # 8 distinct tainted pages, each one flow
    pages = []
    for i in range(8):
        pages.append((f"http://t/{i}",
                      "<script>var x=location.search;"
                      "document.write(x);</script>"))
    ctx = _StubCtx(pages=pages)
    c_cs_mine(ctx, ctx.findings.append)
    assert len(ctx.findings) == csminer.MAX_FINDINGS


def test_sink_stats():
    flows = JSFlowTracer().trace(
        FIXTURE_TAINTED + FIXTURE_POSTMESSAGE, "both.html")
    st = sink_stats(flows)
    assert st["innerHTML"]["tainted"] >= 1
    assert st["eval"]["tainted"] >= 1
    assert st["innerHTML"]["total"] >= st["innerHTML"]["tainted"]
    assert sink_stats([]) == {}
