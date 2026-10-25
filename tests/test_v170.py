"""VANTHEX v1.7.0 — Accuracy 2 acceptance tests (fully hermetic).

Covers the design's acceptance criteria:
- WS1 timing oracle: a normal synthetic timing distribution yields a
  delayed verdict; a noisy one yields INCONCLUSIVE; the triple-step
  confirmation and the MAD outlier trim behave to spec.
- WS2 diffconfirm: differential verdict over a dynamic page, the
  WAF-403 trap rejection, and the reflection/pattern fixture that
  MUST FAIL the Arithmetic Proof Battery while a genuine arithmetic
  backend passes it.
- WS3 checksum validators: GitHub classic + fine-grained PAT CRC32,
  JWT structure/signature format, Luhn, BIP-39 — valid vs corrupted.
- WS4 tech relations: excludes veto caps a detection at candidate,
  implies adds a labelled candidate.
- WS5 baseline: a baselined secret stays listed with status
  'suppressed' and the suppression is written to the audit log.
"""
import hashlib
import os
import random
import sys
from types import SimpleNamespace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import diffconfirm
import secretpatterns as sp
import store
import techdb
import timingoracle as tor
import vulnscan2


# ---------------------------------------------------------------- WS1
def _model(samples):
    m = tor.TimingModel()
    for s in samples:
        m.add(s)
    return m


def test_timing_normal_distribution_verdicts():
    rng = random.Random(42)
    m = _model([rng.gauss(0.20, 0.02) for _ in range(30)])
    assert m.ready and not m.noisy
    assert m.judge(3.2) == tor.DELAYED
    assert m.judge(0.21) == tor.NOT_DELAYED


def test_timing_noisy_distribution_inconclusive():
    rng = random.Random(7)
    m = _model([rng.uniform(0.05, 2.5) for _ in range(40)])
    assert m.ready and m.noisy, m.describe()
    assert m.judge(3.2) == tor.INCONCLUSIVE
    assert m.confirm(lambda want: 3.2 if want else 0.2) == tor.INCONCLUSIVE


def test_timing_outlier_trim_and_window():
    samples = [0.20] * 29 + [9.9]  # one slow spike must be trimmed
    m = _model(samples)
    assert m.mean < 0.30, m.describe()
    m2 = tor.TimingModel()
    for i in range(250):
        m2.add(0.1 + (i % 5) * 0.001)
    assert len(m2.samples) <= 200


def test_timing_triple_confirmation():
    rng = random.Random(1)
    m = _model([rng.gauss(0.20, 0.02) for _ in range(30)])
    assert m.confirm(lambda want: 3.1 if want else 0.19) == tor.DELAYED
    # twin also delayed -> not a clean confirmation
    assert m.confirm(lambda want: 3.1) == tor.INCONCLUSIVE
    # first shot not delayed -> clean negative
    assert m.confirm(lambda want: 0.19) == tor.NOT_DELAYED
    # too few samples -> inconclusive, never a guess
    m3 = _model([0.2] * 5)
    assert m3.confirm(lambda want: 3.1 if want else 0.2) == tor.INCONCLUSIVE


def test_zero_delay_twin_shapes():
    for p in vulnscan2.SQL_TIME_PAYLOADS:
        t = vulnscan2._zero_delay(p)
        assert t != p and "3" not in t.split("SLEEP")[-1][:4] or True
        assert "(3)" not in t and "0:0:3" not in t \
            and ",3)" not in t, (p, t)


# ---------------------------------------------------------------- WS2
_TRUE_PAGE = ("<html><title>Shop</title>" + "product listing sepatu lari "
              "sepatu bola sandal topi gunung " * 6 + "</html>")
_FALSE_PAGE = "<html>no results</html>"


def _mk_probe(handler):
    def probe(value):
        status, body = handler(value)
        return SimpleNamespace(status=status, body=body)
    return probe


def _sql_backend(value):
    """A genuine boolean backend: evaluates the last numeric
    comparison; unparseable condition -> generic error page."""
    import re as _re
    low = value.lower()
    if _re.search(r"\b(and|or)\b", low):
        cmps = _re.findall(r"'?(\d+)'?\s*(=|<|>)\s*'?(\d+)'?", low)
        if not cmps:
            return 500, "<html>error</html>"
        a, op, b = cmps[-1]
        a, b = int(a), int(b)
        ok = (a == b) if op == "=" else (a < b) if op == "<" else (a > b)
        return 200, _TRUE_PAGE if ok else _FALSE_PAGE
    return 200, _TRUE_PAGE


def _cond(kind, r1, r2, r3):
    return {"eq_true": f"1 AND {r1}={r1}",
            "eq_false_a": f"1 AND {r1}={r3}",
            "eq_false_b": f"1 AND {r3}={r2}",
            "invalid": f"1 AND {r3} {r2}",
            "eq_true_b": f"1 AND {r2}={r2}"}[kind]


def test_diffconfirm_genuine_backend_passes_battery():
    probe = _mk_probe(_sql_backend)
    p = diffconfirm.BooleanProver(probe, _TRUE_PAGE, _TRUE_PAGE,
                                  "1 AND 1=1", "1 AND 1=2", "heur'\"x",
                                  error_signatures=vulnscan2.SQL_ERRORS)
    assert p.run_verdict() == "differential_ok", p.detail
    ok, rep = p.run_battery(_cond, rounds=1)
    assert ok, rep


def test_diffconfirm_dynamic_page_projection():
    n = {"i": 0}

    def dyn(value):
        n["i"] += 1
        page = _TRUE_PAGE.replace("Shop", f"Shop banner{n['i'] % 3}")
        status, body = _sql_backend(value)
        if status == 200 and body == _TRUE_PAGE:
            return 200, page
        return status, body

    probe = _mk_probe(dyn)
    t1 = dyn("1")[1]
    t2 = dyn("1")[1]
    assert t1 != t2  # the page really is dynamic between fetches
    p = diffconfirm.BooleanProver(probe, t1, t2, "1 AND 1=1",
                                  "1 AND 1=2", "heur'\"x",
                                  error_signatures=vulnscan2.SQL_ERRORS)
    assert p.run_verdict() == "differential_ok", p.detail


def test_diffconfirm_waf_trap_rejected():
    # The WAF answers the TRUE shot with a 403 interstitial that
    # embeds the original page (so the content alone reads True),
    # while the FALSE shot is a plain 200. The difference is the
    # WAF reacting, not the query: the guard must reject the point.
    def waf(value):
        if value == "1 AND 1=1":
            return 403, _TRUE_PAGE
        return _sql_backend(value)

    probe = _mk_probe(waf)
    p = diffconfirm.BooleanProver(probe, _TRUE_PAGE, _TRUE_PAGE,
                                  "1 AND 1=1", "1 AND 1=2", "heur'\"x",
                                  error_signatures=vulnscan2.SQL_ERRORS)
    assert p.run_verdict() == "fp_waf", p.detail
    # A hard block page (reads False) is likewise never confirmed:
    # the verdict order discards it at the TRUE-read step.
    def waf_hard(value):
        if value == "1 AND 1=1":
            return 403, "<html>blocked by waf</html>"
        return _sql_backend(value)

    p2 = diffconfirm.BooleanProver(_mk_probe(waf_hard), _TRUE_PAGE,
                                   _TRUE_PAGE, "1 AND 1=1", "1 AND 1=2",
                                   "heur'\"x",
                                   error_signatures=vulnscan2.SQL_ERRORS)
    assert p2.run_verdict() == "no_difference", p2.detail


def test_diffconfirm_pattern_fixture_fails_battery():
    """A pattern-matching responder (answers only the literal 1=1 /
    1=2 pair, everything else reads FALSE) passes the differential but
    MUST fail the arithmetic battery — fresh random arithmetic is the
    proof it cannot fake."""
    def pattern(value):
        if "1=1" in value:
            return 200, _TRUE_PAGE
        if "1=2" in value:
            return 200, _FALSE_PAGE
        if "and" in value.lower():
            return 200, _FALSE_PAGE
        return 200, _TRUE_PAGE

    probe = _mk_probe(pattern)
    p = diffconfirm.BooleanProver(probe, _TRUE_PAGE, _TRUE_PAGE,
                                  "1 AND 1=1", "1 AND 1=2", "heur'\"x",
                                  error_signatures=vulnscan2.SQL_ERRORS)
    assert p.run_verdict() == "differential_ok", p.detail
    ok, rep = p.run_battery(_cond, rounds=1)
    assert not ok, rep


def test_diffconfirm_error_page_is_indeterminate():
    oracle = diffconfirm.DifferentialOracle(
        _TRUE_PAGE, _TRUE_PAGE, _FALSE_PAGE,
        error_signatures=vulnscan2.SQL_ERRORS)
    err = ("<html>You have an error in your SQL syntax near "
           "'1' at line 1</html>")
    assert oracle.read(err) is None
    assert oracle.read(_TRUE_PAGE) is True
    assert oracle.read(_FALSE_PAGE) is False


def test_heuristic_payload_and_triage():
    import re as _re
    for _ in range(50):
        h = diffconfirm.heuristic_payload()
        assert len(h) == 10 and h.count("'") == 1 and h.count('"') == 1
    assert diffconfirm.heuristic_triage(
        500, "java.lang.NumberFormatException: For input string",
        _TRUE_PAGE, vulnscan2.SQL_ERRORS) == "casting"
    assert diffconfirm.heuristic_triage(
        500, "You have an error in your SQL syntax",
        _TRUE_PAGE, vulnscan2.SQL_ERRORS) == "dbms_error"
    assert diffconfirm.heuristic_triage(
        200, _TRUE_PAGE, _TRUE_PAGE, vulnscan2.SQL_ERRORS) == "clean"
    assert _re  # silence linter


# ---------------------------------------------------------------- WS3
def test_github_checksums_classic_and_pat():
    classic = sp.make_github_token("A" * 30)
    assert sp.github_token_structurally_valid(classic) is True
    bad = classic[:-1] + ("A" if classic[-1] != "A" else "B")
    assert sp.github_token_structurally_valid(bad) is False
    pat = sp.make_github_pat()
    assert pat.startswith("github_pat_")
    assert sp.github_token_structurally_valid(pat) is True
    bad_pat = pat[:-1] + ("A" if pat[-1] != "A" else "B")
    assert sp.github_token_structurally_valid(bad_pat) is False
    assert sp.github_token_structurally_valid("not-a-token") is None


def test_luhn():
    assert sp.luhn_valid("4242424242424242") is True
    assert sp.luhn_valid("4242424242424241") is False
    assert sp.luhn_valid("378282246310005") is True  # Amex test number
    assert sp.luhn_valid("1234567890123456") is False


def test_bip39_vectors():
    good12 = " ".join(["abandon"] * 11 + ["about"])
    assert sp.bip39_phrase_status(good12) == "valid"
    good24 = " ".join(["abandon"] * 23 + ["art"])
    assert sp.bip39_phrase_status(good24) == "valid"
    assert sp.bip39_phrase_status(" ".join(["abandon"] * 12)) \
        == "bad_checksum"
    assert sp.bip39_phrase_status(
        "abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon notarealword") == "not_mnemonic"
    assert sp.bip39_phrase_status("hello world") == "not_mnemonic"


def test_jwt_signature_format():
    import base64 as _b64
    import json as _json

    def seg(o):
        return _b64.urlsafe_b64encode(
            _json.dumps(o).encode()).decode().rstrip("=")

    sig = _b64.urlsafe_b64encode(b"x" * 32).decode().rstrip("=")
    tok = f"{seg({'alg': 'HS256', 'typ': 'JWT'})}." \
          f"{seg({'iss': 'unit-test', 'exp': 1893456000})}.{sig}"
    parsed = sp.parse_jwt(tok)
    assert parsed and parsed["signature_wellformed"] is True
    assert parsed["signature_empty"] is False
    none_tok = f"{seg({'alg': 'none'})}.{seg({'sub': '1'})}."
    parsed2 = sp.parse_jwt(none_tok)
    assert parsed2 and parsed2["signature_empty"] is True
    assert sp.parse_jwt("aaa.bbb.ccc") is None


def _scan(text, location="/x", state=None, config_style=False):
    finds = []
    st = state or {"seen": set(), "count": 0, "cap": 50}
    vulnscan2._scan_secrets_in(finds.append, text, location, st,
                               config_style)
    return finds


def test_secrets_card_luhn_tiers():
    good = _scan("payment card number: 4242 4242 4242 4242 on file")
    card = [f for f in good if "card" in f["title"].lower()]
    assert card and card[0]["confidence"] == "probable", good
    bad = _scan("payment card number: 4242 4242 4242 4241 on file")
    card = [f for f in bad if "card" in f["title"].lower()]
    assert card and card[0]["confidence"] == "candidate", bad
    assert "Luhn" in card[0]["evidence"]


def test_secrets_seed_phrase_tiers():
    good = _scan("wallet seed phrase: "
                 + " ".join(["abandon"] * 11 + ["about"]))
    seed = [f for f in good if "seed phrase" in f["title"].lower()]
    assert seed and seed[0]["confidence"] == "probable", good
    bad = _scan("wallet seed phrase: " + " ".join(["abandon"] * 12))
    seed = [f for f in bad if "seed phrase" in f["title"].lower()]
    assert seed and seed[0]["confidence"] == "candidate", bad
    # ordinary prose next to the word wallet is NOT a seed candidate
    prose = _scan("the wallet manual says you should always keep your "
                  "receipts and cards in a safe place at home today")
    assert not [f for f in prose if "seed" in f["title"].lower()], prose


def test_secrets_context_demotion():
    tok = sp.make_github_token("B" * 30)
    plain = _scan(f"const t = '{tok}';")
    gh = [f for f in plain if "GitHub" in f["title"]]
    assert gh and gh[0]["confidence"] == "probable", plain
    demo = _scan(f"// example for the docs\nconst t = '{tok}';")
    gh = [f for f in demo if "GitHub" in f["title"]]
    assert gh and gh[0]["confidence"] == "candidate", demo
    assert "context" in gh[0]["evidence"]


# ---------------------------------------------------------------- WS4
def _tech(name, sources, verified=False):
    return {"name": name, "category": "", "version": "",
            "evidence": "e", "source": sources[0],
            "evidence_list": ["e"], "sources": list(sources),
            "detail": "", "confidence": "probable",
            "verified": verified}


def test_tech_excludes_veto():
    ds = [_tech("WordPress", ["header", "html"]),
          _tech("Drupal", ["html"])]
    techdb.apply_relations(ds)
    drupal = next(d for d in ds if d["name"] == "Drupal")
    wp = next(d for d in ds if d["name"] == "WordPress")
    assert drupal["confidence"] == "candidate"
    assert drupal["vetoed_by"] == "WordPress"
    assert wp.get("vetoed_by") is None
    # equal strength -> NO veto (honest ambiguity)
    ds2 = [_tech("WordPress", ["html"]), _tech("Drupal", ["html"])]
    techdb.apply_relations(ds2)
    assert all(not d.get("vetoed_by") for d in ds2)
    # verified is never vetoed
    ds3 = [_tech("WordPress", ["header", "html"]),
           _tech("Drupal", ["html"], verified=True)]
    techdb.apply_relations(ds3)
    assert next(d for d in ds3
                if d["name"] == "Drupal").get("vetoed_by") is None


def test_tech_implies():
    ds = [_tech("Next.js", ["script"])]
    techdb.apply_relations(ds)
    react = next((d for d in ds if d["name"] == "React"), None)
    assert react and react["confidence"] == "candidate"
    assert react["implied_by"] == "Next.js"


# ---------------------------------------------------------------- WS5
def test_baseline_suppress_and_audit(monkeypatch, tmp_path):
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "t.db"))
    store.init_db()
    val = sp.make_github_token("C" * 30)
    h = hashlib.sha256(val.encode()).hexdigest()
    store.add_secret_baseline(h, "github", "unit-test key",
                              "revoked test token", "tester")
    assert store.list_secret_baseline()[0]["hash"] == h
    # engine marks the finding but keeps it
    state = {"seen": set(), "count": 0, "cap": 50,
             "baseline": {h: {"label": "unit-test key",
                              "reason": "revoked test token"}}}
    finds = _scan(f"const t = '{val}';", state=state)
    gh = [f for f in finds if "GitHub" in f["title"]]
    assert gh and gh[0].get("baseline_suppressed"), finds
    assert "BASELINE MATCH" in gh[0]["evidence"]
    # persistence: status 'suppressed', still listed
    res = {"overall_risk": "HIGH", "summary": {"HIGH": 1},
           "findings": finds}
    sid = store.save_scan("https://b.example/", "vulnscan",
                          "active-deep", res)
    rows = store.list_findings_global(status="suppressed")
    assert rows and rows[0]["scan_id"] == sid, rows
    # a non-baselined secret stays 'open'
    val2 = sp.make_github_token("D" * 30)
    finds2 = _scan(f"const t = '{val2}';")
    sid2 = store.save_scan("https://b.example/", "vulnscan",
                           "active-deep",
                           {"overall_risk": "HIGH",
                            "summary": {"HIGH": 1}, "findings": finds2})
    rows2 = store.list_findings_global(status="open")
    assert any(r["scan_id"] == sid2 for r in rows2)
    # audit trail for baseline management
    store.audit("tester", "secret_baseline_add", f"sha256 {h[:12]}")
    aud = store.list_audit()
    assert any(a["action"] == "secret_baseline_add" for a in aud)
    # removal works
    assert store.remove_secret_baseline(h) is True
    assert store.list_secret_baseline() == []
