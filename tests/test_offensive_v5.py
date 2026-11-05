"""Tes paket v1.7.0 (total domination) — 5 check baru + 5 engine baru.
Check: fixture port unik (18210+N). Engine pure: unit-test.
"""
import os
import sys
import subprocess
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

PORT = 18210


def _boot(port):
    p = subprocess.Popen(
        [sys.executable, "tests/fixture_vuln_server.py", str(port)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)
            return p
        except Exception:
            time.sleep(0.25)
    p.terminate()
    raise AssertionError("fixture tidak start")


def _run(check, port):
    p = _boot(port)
    try:
        import vulnscan2
        ctx = vulnscan2.Ctx(f"http://127.0.0.1:{port}/", {}, [])
        found = []
        check(ctx, found.append)
        return found, ctx
    finally:
        p.terminate()


def _assert_one(found, frag, loc=None):
    assert any(frag in f["title"] for f in found), [f["title"] for f in found]
    conf = [f for f in found if f["confidence"] == "confirmed"]
    assert conf, "tidak ada temuan confirmed"
    if loc:
        assert all(str(f["location"]) == loc for f in conf)


# ---------------- check scan ----------------

def test_session_replay():
    import dominion
    found, _ = _run(dominion.c_session_replay, PORT)
    _assert_one(found, "Stolen Session VALID", "/admin/vault")


def test_shadow_admin_hunter():
    import dominion
    found, _ = _run(dominion.c_shadow_admin_hunter, PORT + 1)
    _assert_one(found, "Shadow Admin", "/admin/panel")
    f = [x for x in found if "Shadow Admin" in x["title"]][0]
    assert "X-Original-URL" in f["evidence"]


def test_cred_reuse():
    import dominion
    found, _ = _run(dominion.c_cred_reuse, PORT + 2)
    _assert_one(found, "Credentials Reused Across Services")
    f = [x for x in found if "Credentials Reused" in x["title"]][0]
    assert "smtp-login" in f["evidence"] and "dbadmin" in f["evidence"]


def test_ws_cswsh():
    import dominion
    found, _ = _run(dominion.c_ws_cswsh, PORT + 3)
    _assert_one(found, "Cross-Site WebSocket Hijacking", "/ws")


def test_blind_orchestrate():
    import dominion
    found, _ = _run(dominion.c_blind_orchestrate, PORT + 4)
    _assert_one(found, "Blind Injection", "/blind/sleep")
    f = [x for x in found if "Blind Injection" in x["title"]][0]
    assert "baseline=" in f["evidence"]


# ---------------- engine pure ----------------

def test_chainrun_gated():
    import chainrun
    plan = [{"name": "SSTI RCE", "steps": ["s1", "s2", "s3"]}]
    approved, executed = [], []
    res = chainrun.run_chain(
        plan,
        approver=lambda s: (approved.append(s) or True) if "s2" not in s else False,
        executor=lambda s: (executed.append(s) or {"ok": True}))
    assert len(res["executed"]) == 2 and len(res["skipped"]) == 1
    assert res["failed"] is None
    # fail-closed: executor error menghentikan rantai
    res2 = chainrun.run_chain(plan, approver=lambda s: True,
                              executor=lambda s: (_ for _ in ()).throw(RuntimeError("boom")))
    assert res2["failed"] and res2["failed"]["error"] == "boom"
    # tanpa approver -> ditolak keras
    try:
        chainrun.run_chain(plan, None, lambda s: {})
        assert False, "harus menolak approver None"
    except ValueError:
        pass
    assert "dieksekusi" in chainrun.summarize(res)


def test_impact_assessment():
    import impact
    res = impact.assess({"records": 5000, "files": 120},
                        ["smtp", "db-admin"], access_level="admin")
    assert 0 < res["blast_radius"] <= 10
    assert res["data_at_risk"] == 5120
    assert "read-only" in res["notes"].lower()
    rep = impact.report(res)
    assert "records" in rep and "blast radius" in rep
    # level system lebih tinggi dari user
    r_user = impact.assess({"records": 5000}, [], access_level="user")
    assert res["blast_radius"] > r_user["blast_radius"]


def test_evolver_genetic():
    import evolver
    # WAF stub: blokir payload yang mengandung 'union select' literal
    def send(p):
        low = p.lower()
        blocked = "union select" in low or "or 1=1" in low
        return {"blocked": blocked, "echoed": not blocked}
    res = evolver.evolve("' UNION SELECT password FROM users--",
                         send, generations=5, pop_size=8)
    assert res["best_score"] == 1.0, res
    assert "union select" not in res["best"].lower()
    assert res["generations"] >= 1 and res["history"]
    # tanpa send_fn -> ditolak (operator-gated)
    try:
        evolver.evolve("x", None)
        assert False
    except ValueError:
        pass


def test_subtakeover_fingerprint():
    import subtakeover as st
    svc, conf = st.fingerprint("site.github.io", 404,
                               "There isn't a GitHub Pages site here.")
    assert svc == "github-pages" and conf == "confirmed"
    svc2, conf2 = st.fingerprint("x.azurewebsites.net", 200, "404 Web Site not found")
    assert svc2 == "azure-cdn" and conf2 == "probable"
    assert st.fingerprint("normal.example.com", 200, "welcome") == (None, "")
    # verify end-to-end dengan stub fetcher/dns
    r = st.verify("dead.example.com", "site.github.io",
                  fetcher=lambda s: (404, "There isn't a GitHub Pages site here."),
                  dns_lookup=lambda s: "site.github.io")
    assert r and r["service"] == "github-pages"
    assert st.verify("ok.example.com", None,
                     fetcher=lambda s: (200, "hello"),
                     dns_lookup=lambda s: None) is None


def test_campaign_orchestration():
    import campaign
    phases = []
    def scanner(target, opts):
        return {"findings": [{"title": "SSTI RCE", "severity": "CRITICAL"},
                             {"title": "Akses config", "severity": "HIGH"}]}
    res = campaign.run_campaign(
        "http://t.local", scanner,
        chain_planner=lambda f: [{"name": "SSTI RCE", "steps": ["a", "b"]}],
        reporter=lambda t, f, c: {"pdf": "bytes", "findings": len(f)},
        on_phase=lambda ph, info: phases.append(ph))
    assert phases == ["scan", "scan-done", "chain", "chain-done",
                      "report", "done"], phases
    assert res["elapsed_s"] >= 0 and res["report"]["findings"] == 2
    # cancel: berhenti setelah fase scan dimulai
    res2 = campaign.run_campaign("http://t.local", scanner,
                                 lambda f: [], lambda *a: {},
                                 cancel=lambda: True)
    assert res2["cancelled"] is True
