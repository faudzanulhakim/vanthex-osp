"""
test_offensive_v7.py — AI Warfare Pack v1.9.0.
Jalankan: .venv/bin/python tests/test_offensive_v7.py (driver manual).
PORT=18216 (fixture), 18217 (listener beacon uji).
"""
import json
import os
import sys
import threading
import time
import traceback

PORT = 18216
BASE = f"http://127.0.0.1:{PORT}/"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from http.server import ThreadingHTTPServer  # noqa: E402
from fixture_vuln_server import H, CDN_CACHE  # noqa: E402
import vulnscan2 as v  # noqa: E402
import llmattack  # noqa: E402
import mcpaudit  # noqa: E402
import aisupply  # noqa: E402
import identgraph  # noqa: E402
import cacheadv  # noqa: E402
import tripwire  # noqa: E402
import insomnia  # noqa: E402
import browserkit  # noqa: E402


def make_ctx():
    return v.Ctx(BASE, {}, [])


def test_llm_check():
    ctx, found = make_ctx(), []
    llmattack.c_llm_prompt_injection(ctx, found.append)
    assert found, "llm check kosong"
    f = found[0]
    assert f["severity"] == "CRITICAL" and f["confidence"] == "confirmed"
    assert f["location"] == "/api/llm/chat"


def test_mcp_check():
    ctx, found = make_ctx(), []
    mcpaudit.c_mcp_audit(ctx, found.append)
    assert found and found[0]["severity"] == "CRITICAL"
    assert "exec" in found[0]["evidence"] or "tool" in found[0]["evidence"]


def test_ai_supply_check():
    ctx, found = make_ctx(), []
    aisupply.c_ai_supply_recon(ctx, found.append)
    titles = [f["title"] for f in found]
    assert any("Model" in t for t in titles), titles
    assert any("API Key" in t for t in titles), titles
    assert all(f["confidence"] == "confirmed" for f in found)


def test_identity_graph_check():
    ctx, found = make_ctx(), []
    identgraph.c_identity_graph(ctx, found.append)
    assert found and found[0]["confidence"] == "confirmed"
    g = identgraph.build_graph(ctx, BASE)
    assert "root.admin@fixture.local" in g["emails"]
    assert "auth0" in g["idp"]


def test_cache_poisoning_v2_check():
    CDN_CACHE.clear()
    ctx, found = make_ctx(), []
    cacheadv.c_cache_poisoning_v2(ctx, found.append)
    assert found, "cache check kosong"
    assert found[0]["confidence"] == "confirmed"


def test_tripwire():
    feed = tripwire.load_feed(None)
    assert len(feed) >= 3
    alerts = tripwire.match(["nginx", "express"], feed)
    ids = {a["cve_id"] for a in alerts}
    assert "CVE-2026-3001" in ids and "CVE-2026-3188" in ids
    alerts2 = tripwire.match({"docker": "24.0"}, feed)
    assert any(a["cve_id"] == "CVE-2026-3250" for a in alerts2)
    # urutan severity: CRITICAL dulu
    assert alerts2[0]["severity"] == "CRITICAL"


def test_insomnia_gated():
    try:
        insomnia.generate("python", "http://listener.local", authorized=False)
        raise AssertionError("harusnya ValueError tanpa authorized")
    except ValueError:
        pass
    p = insomnia.generate("python", "http://listener.local", authorized=True)
    assert "base64" in p["one_liner"] or "urlopen" in p["one_liner"]
    ind = insomnia.detection_indicators("powershell")
    assert any("IEX" in x for x in ind)
    try:
        insomnia.generate("ruby", "x", authorized=True)
        raise AssertionError("harusnya ValueError kind salah")
    except ValueError:
        pass


def test_browserkit():
    try:
        out = browserkit.render_and_probe(BASE, timeout_ms=20000)
    except browserkit.BrowserUnavailable:
        print("   (chromium tidak tersedia — skip render assertions)")
        return
    assert out["title"] or out["dom_text_len"] > 0
    assert isinstance(out["runtime_requests"], list)


def test_registry_v19():
    assert len(v.PROFILES["enterprise-full"]) == 115
    for c in ("c_llm_prompt_injection", "c_mcp_audit", "c_ai_supply_recon",
              "c_identity_graph", "c_cache_poisoning_v2"):
        assert callable(getattr(v, c, None)), c


def _autostart():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    import atexit
    atexit.register(srv.shutdown)
    time.sleep(0.3)
    return srv


_autostart()

if __name__ == "__main__":
    ok = fail = 0
    for name in sorted(n for n in globals() if n.startswith("test_")):
        try:
            globals()[name]()
            ok += 1
            print(f"PASS {name}")
        except Exception:
            fail += 1
            print(f"FAIL {name}")
            traceback.print_exc(limit=4)
    print(f"== v7: {ok} passed, {fail} failed ==")
    sys.exit(1 if fail else 0)
