"""Hermetic tests for triageai.py — no network, no LLM, no fixtures."""
import copy
import os

from offensive import triageai


def _mk(title, severity="HIGH", **kw):
    f = {"id": "F-001", "title": title, "severity": severity,
         "confidence": "probable", "location": "http://t/x", "param": "q",
         "evidence": kw.pop("evidence", ""),
         "description": kw.pop("description", ""),
         "verification": kw.pop("verification", ""),
         "remediation": kw.pop("remediation", "")}
    f.update(kw)
    return f


# ---- 1. executed-proof finding scores high --------------------------------

def test_executed_proof_scores_high():
    f = _mk("SQL Injection", "CRITICAL",
            evidence="Boolean differential: TRUE variant returned different "
                     "size than FALSE; database error: sql syntax near "
                     "'1'''; differential differed from baseline",
            verification="Confirmed executed: sql syntax error on quote probe, "
                         "boolean true/false responses differ, confirmed")
    s = triageai.score_finding(f)
    assert s["exploitability"] >= 7, s
    assert s["fp_risk"] < 5, s
    assert s["verdict"] == "likely-exploitable", s
    assert s["reasons"]


# ---- 2. reflection-only + URL-encoded evidence -> FP + demotion ----------

def test_reflection_only_url_encoded_demoted():
    f = _mk("Reflected XSS", "HIGH",
            evidence="Marker reflected in response; payload echoed: "
                     "%3Csvg%2Fonload%3Dalert%281%29%3E was returned "
                     "url-encoded; no execution",
            verification="Payload appears in response page")
    s = triageai.score_finding(f)
    assert s["fp_risk"] >= 7, s
    assert s["verdict"] == "likely-false-positive", s
    res = triageai.triage([f])
    out = res["findings"][0]
    assert out["severity"] == "info"
    assert out["triage"]["note"]
    assert res["summary"]["demoted"] == 1
    assert res["summary"]["likely-false-positive"] == 1


def test_login_redirect_context_pushes_fp():
    f = _mk("Reflected XSS", "HIGH",
            evidence="Marker reflected in response on page; redirected to "
                     "login, 302 to login page")
    s = triageai.score_finding(f)
    assert s["fp_risk"] >= 7, s
    assert s["verdict"] == "likely-false-positive", s


# ---- 3. version-fingerprint capped ---------------------------------------

def test_version_fingerprint_capped():
    f = _mk("Server Version Disclosure", "MEDIUM",
            evidence="Server banner discloses product and version; "
                     "stack trace present; uid=0 executed")
    s = triageai.score_finding(f)
    assert s["exploitability"] <= 3, s
    res = triageai.triage([f])
    assert res["findings"][0]["triage"]["exploitability"] <= 3


# ---- 4. correlation bonus -------------------------------------------------

def test_correlation_bonus_applied():
    xss = _mk("Reflected XSS", "HIGH",
              evidence="uid=0 root: executed confirmed")
    red = _mk("Open Redirect", "HIGH",
              evidence="Callback hit confirmed; out-of-band dns hit",
              verification="Differential differed from baseline")
    xss["location"] = red["location"] = "http://t/go"
    xss["param"] = red["param"] = "url"
    solo = copy.deepcopy(xss)
    solo["location"], solo["param"] = "http://t/other", "p"
    res = triageai.triage([xss, red])
    a, b = res["findings"]
    s_solo = triageai.score_finding(solo)
    # correlated pair: exploitability raised above the solo baseline
    assert a["triage"]["exploitability"] >= min(10, s_solo["exploitability"] + 1)
    assert b["triage"]["exploitability"] >= min(10, s_solo["exploitability"] + 1)
    assert res["correlation_notes"]
    # bonus is bounded
    assert a["triage"]["exploitability"] <= 10


def test_conflicting_verdicts_noted():
    xss = _mk("Reflected XSS", "HIGH",
              evidence="uid=0 executed, confirmed differential")
    other = _mk("Open Redirect", "HIGH",
                evidence="Marker reflected in response; echoed url-encoded "
                         "%27; redirected to login")
    other["location"] = xss["location"]
    other["param"] = xss["param"]
    res = triageai.triage([xss, other])
    verdicts = {f["triage"]["verdict"] for f in res["findings"]}
    if len(verdicts) > 1:
        assert any("Conflicting" in n for n in res["correlation_notes"])
    else:
        # same verdict group still correlates
        assert any("reinforce" in n for n in res["correlation_notes"])


# ---- 5. input list never mutated ------------------------------------------

def test_input_never_mutated():
    f = _mk("Reflected XSS", "CRITICAL",
            evidence="sql syntax error; uid=0 executed")
    original = copy.deepcopy(f)
    findings = [f]
    res = triageai.triage(findings)
    assert findings[0] == original
    assert "triage" not in findings[0]
    assert findings[0]["severity"] == "CRITICAL"
    # even though the copy was demoted to info (FP path)
    res2 = triageai.triage([_mk("Reflected XSS", "HIGH",
                                evidence="echoed %3Csvg%2Fonload%3D, "
                                         "reflection only, redirected to login")])
    assert res2["findings"][0]["severity"] == "info"


# ---- 6. markdown renders ---------------------------------------------------

def test_markdown_renders():
    res = triageai.triage([
        _mk("SQL Injection", "HIGH", evidence="sql syntax; uid=0 executed"),
        _mk("Reflected XSS", "HIGH",
            evidence="echoed %3Csvg%2Fonload%3D reflection only, "
                     "redirected to login"),
    ])
    md = triageai.render_triage_summary(res)
    assert isinstance(md, str) and md.startswith("## AI Triage Summary")
    assert "| # |" in md and "|" in md
    assert "Totals:" in md
    assert "demoted" in md
    # malformed input is contained
    assert triageai.render_triage_summary(None)  # returns a string, no raise


# ---- 7. LLM hook ------------------------------------------------------------

def test_llm_hook_overrides():
    def scorer(f, rule_score):
        return {"verdict": "needs-human-look", "exploitability": 5,
                "fp_risk": 5, "reasons": ["llm says look"]}
    f = _mk("SQL Injection", "HIGH", evidence="sql syntax; uid=0 executed")
    res = triageai.triage([f], llm_scorer=scorer)
    tri = res["findings"][0]["triage"]
    assert tri["verdict"] == "needs-human-look"
    assert tri["exploitability"] == 5
    assert tri["engine"] == "llm-overrides-heuristic-v3"
    # raising scorer is contained
    def bad(f, rs):
        raise RuntimeError("boom")
    res2 = triageai.triage([f], llm_scorer=bad)
    assert any("boom" in r for r in res2["findings"][0]["triage"]["reasons"])
    assert res2["findings"][0]["triage"]["verdict"]  # still has a verdict


# ---- 8. gate ----------------------------------------------------------------

def test_gate(monkeypatch=None):
    # triage() runs WITHOUT any gate
    old = os.environ.pop("PTK_TRIAGE", None)
    try:
        res = triageai.triage([_mk("X", "LOW")])
        assert res["summary"]["total"] == 1
        # wrapper is gated
        assert triageai.run_triage_on_scan([]) is None
        os.environ["PTK_TRIAGE"] = "1"
        out = triageai.run_triage_on_scan([_mk("X", "LOW")])
        assert out is not None and "markdown" in out
    finally:
        os.environ.pop("PTK_TRIAGE", None)
        if old is not None:
            os.environ["PTK_TRIAGE"] = old


def test_score_finding_contained():
    assert triageai.score_finding({})["verdict"]
    assert triageai.score_finding(None)["verdict"] == "needs-human-look"
    assert triageai.score_finding("junk")["verdict"] == "needs-human-look"
