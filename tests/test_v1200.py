"""v1.20.0 — Fase 4 program OSIRIS (service dashboard, globe view).

Design §6 + §14.4, host batch Fase 4 only (fred.stlouisfed.org,
api.coinbase.com, stooq.com KONDISIONAL), no CSP change, no AI,
no other phase item, no Shodan/MAC/BGP/FINGERPRINT:
  1. MARKETS panel via the fetch daemon: FRED daily series
     (fredgraph.csv, keyless) + Coinbase spot (keyless) + Stooq
     daily CSV (CONDITIONAL — a CAPTCHA/interstitial body drops
     Stooq entirely, K15; CoinGecko K15 fallback stays INACTIVE
     without a key from ADE and is never called).
  2. MARKETS extras (§14.4): direct-symbol ticker box + GO (no
     autocomplete; inactive when Stooq drops), category chips
     WEI/DEF/NRG/CMDTY/FX/CRYPTO/WATCH/DOW (DOW = FRED DJIA;
     DEF meaning unverified — suspected defense sector, K30,
     never stated as fact), movers ONLY in the tracked basket
     (labelled "not market-wide"), SESSIONS CLOSED weekend +
     always-on UPD stamp + per-row as-of, WATCH local-browser
     only. BREADTH STAYS DROPPED (K25: no keyless advance/decline
     source; constituent counting is fabrication).
  3. Dollar is the Fed Broad Index DTWEXBGS — NEVER labelled DXY.
  4. Bugfix (artifact v1.19.0 finding, not a feature): the service
     LAUNCHES toggle was inert (GL_SUBS/glDraw never knew the id);
     v1.20.0 wires it so the toggle really turns the layer on and
     draws pad points.

Python fetch tests are hermetic: globe_feeds._fetch_binary is
monkeypatched, so no external network is used, and markets state
is memory-only (no snapshot file, no DB writes). Live FRED/
Coinbase/Stooq proof is a deployment-time check, not part of this
suite. The markets pure-JS block is exercised with a node harness
in the v1.16.0 pattern.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import globe_feeds as gf  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "templates", "app.html"), encoding="utf-8").read()
APP2 = open(os.path.join(ROOT, "app2.py"), encoding="utf-8").read()
GF_SRC = open(os.path.join(ROOT, "globe_feeds.py"), encoding="utf-8").read()

# Amended v1.21.0 (F5): img-src + nowcoast.noaa.gov, frame-src +
# www.youtube-nocookie.com (approved §7/§14.2 diff); the CSP_1150
# name is historical.
CSP_1150 = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: "
            "https://server.arcgisonline.com https://tilecache.rainviewer.com https://nowcoast.noaa.gov https://tiles.basemaps.cartocdn.com https://s3.amazonaws.com; "
            "connect-src 'self' https://api.rainviewer.com https://basemaps.cartocdn.com https://tiles.basemaps.cartocdn.com https://tiles-a.basemaps.cartocdn.com https://tiles-b.basemaps.cartocdn.com https://tiles-c.basemaps.cartocdn.com https://tiles-d.basemaps.cartocdn.com; "
            "frame-src https://www.youtube-nocookie.com; "
            "worker-src 'self' blob:; "
            "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; "
            "form-action 'self'")
OSINT_MD5_1160 = "65ec21c31b4aad76aa304fcb411388ae"

EXTRA14_KEYS = ["Markets", "Ticker or function", "Go", "Add to watch",
                "Remove from watch", "Market data unavailable",
                "Ticker search unavailable", "Symbol not found",
                "Invalid symbol", "No change (single observation)",
                "Watchlist empty", "Refresh", "Unavailable"]
EXTRA14_LANGS = ["id", "es", "fr", "de", "pt", "ru", "ja", "ko",
                 "zh", "ar", "hi"]

FRED_FIX = {
    "SP500": b"observation_date,SP500\n2026-10-22,6590.12\n2026-10-23,6612.50\n",
    "DJIA": b"observation_date,DJIA\n2026-10-22,53500.00\n2026-10-23,53600.00\n",
    "NASDAQCOM": b"observation_date,NASDAQCOM\n2026-10-22,26000.00\n2026-10-23,26100.00\n",
    "VIXCLS": b"observation_date,VIXCLS\n2026-10-22,15.45\n2026-10-23,16.10\n",
    "DGS10": b"observation_date,DGS10\n2026-10-22,4.64\n2026-10-23,4.66\n",
    "DTWEXBGS": b"observation_date,DTWEXBGS\n2026-10-22,118.20\n2026-10-23,118.40\n",
    "DCOILWTICO": b"observation_date,DCOILWTICO\n2026-10-22,83.90\n2026-10-23,84.50\n",
    "GOLDAMGBD228NLBM": None,
    "DEXUSEU": b"observation_date,DEXUSEU\n2026-10-22,1.1673\n2026-10-23,1.1690\n",
    "DEXJPUS": b"observation_date,DEXJPUS\n2026-10-22,159.21\n2026-10-23,159.80\n",
    "DEXSZUS": b"observation_date,DEXSZUS\n2026-10-15,0.8297\n2026-10-16,0.8243\n",
}
WALL = (b'<!DOCTYPE html><html><head><meta charset="utf-8">'
        b'<meta name="robots" content="noindex,nofollow"></head><body>'
        b'<noscript>This site requires JavaScript to verify you'
        b'</noscript></body></html>')


def _reset_mk():
    gf._mk_fred.clear()
    gf._mk_cb.clear()
    gf._mk_stq.clear()
    gf._mk_stq_blocked_at = None


def _mock_fetch_factory(fred_fix=None, cb_ok=True, stooq_mode="wall",
                        fail_hosts=()):
    """Returns (fetch_fn, calls). stooq_mode: 'wall' (HTML
    interstitial), 'csv' (valid daily CSV for any symbol), '404'."""
    calls = []

    def fake(url, timeout=30.0, cap=1024 * 1024, headers=None,
             method="GET", data=None):
        calls.append(url)
        if any(h in url for h in fail_hosts):
            raise IOError("boom")
        if "fred.stlouisfed.org" in url:
            sid = url.split("id=")[1].split("&")[0]
            body = (fred_fix or FRED_FIX).get(sid)
            if body is None:
                return (404, {}, b"<html>not found</html>", False)
            return (200, {}, body, False)
        if "api.coinbase.com" in url:
            if not cb_ok:
                return (500, {}, b"", False)
            amt = "79412.14" if "BTC-USD" in url else "2294.725"
            return (200, {},
                    ('{"data":{"amount":"%s","currency":"USD"}}'
                     % amt).encode(), False)
        if "stooq.com" in url:
            if stooq_mode == "wall":
                return (200, {}, WALL, False)
            if stooq_mode == "404":
                return (404, {}, b"", False)
            sym = url.split("s=")[1].split("&")[0]
            return (200, {},
                    ("Date,Open,High,Low,Close,Volume\n"
                     "2026-10-22,100,101,99,100.50,1000\n"
                     "2026-10-23,100.50,102,100,101.20,1100\n"
                     ).encode(), False)
        raise AssertionError("unexpected host: " + url)

    return fake, calls


def test_fred_parse():
    obs = gf.parse_fred_csv(
        b"observation_date,SP500\n2026-10-21,.\n2026-10-22,6590.12\n"
        b"junk,row\n2026-10-23,6612.50\n")
    assert obs == [("2026-10-22", 6590.12), ("2026-10-23", 6612.5)]
    assert gf.parse_fred_csv(b"") == []
    assert gf.parse_fred_csv(b"observation_date,SP500\n") == []


def test_stooq_parse():
    obs, blocked = gf.parse_stooq_csv(
        b"Date,Open,High,Low,Close,Volume\n"
        b"2026-10-22,100,101,99,100.50,1000\n"
        b"2026-10-23,100.50,102,100,.,1100\n"
        b"2026-10-24,101,103,101,102.00,1200\n")
    assert obs == [("2026-10-22", 100.5), ("2026-10-24", 102.0)]
    assert blocked is False
    obs, blocked = gf.parse_stooq_csv(
        b"Date,Open,High,Low,Close,Volume\n")
    assert obs == [] and blocked is False  # header-only: not found
    obs, blocked = gf.parse_stooq_csv(WALL)
    assert obs == [] and blocked is True
    obs, blocked = gf.parse_stooq_csv(
        b"<html><body>please solve the captcha</body></html>")
    assert blocked is True


def test_coinbase_parse():
    assert gf.parse_coinbase_spot(
        b'{"data":{"amount":"79412.14","currency":"USD"}}') == 79412.14
    assert gf.parse_coinbase_spot(b"not json") is None
    assert gf.parse_coinbase_spot(b'{"data":{}}') is None


def test_mk_change():
    assert gf._mk_change([("2026-10-22", 100.0),
                          ("2026-10-23", 101.0)]) == 1.0
    assert gf._mk_change([("2026-10-23", 101.0)]) is None
    assert gf._mk_change([("2026-10-22", 0.0),
                          ("2026-10-23", 5.0)]) is None
    assert gf._mk_change([]) is None


def test_mk_change_1m_and_spark():
    obs = [("2026-09-23", 90.0), ("2026-10-22", 101.0),
           ("2026-10-23", 102.0)]
    assert abs(gf._mk_change_1m(obs) - 13.3333333) < 1e-6
    # No observation 30+ days old: falls back to the earliest one.
    assert abs(gf._mk_change_1m([("2026-10-22", 101.0),
                                 ("2026-10-23", 102.0)])
               - 0.990099) < 1e-6
    assert gf._mk_change_1m([("2026-10-23", 102.0)]) is None
    assert gf._mk_change_1m([]) is None
    assert gf._mk_change_1m([("2026-10-22", 0.0),
                             ("2026-10-23", 5.0)]) is None
    assert gf._mk_spark(obs) == [90.0, 101.0, 102.0]
    assert gf._mk_spark([("2026-10-23", 102.0)]) == []
    assert gf._mk_spark([]) == []
    many = [("2026-09-%02d" % d, float(d)) for d in range(1, 31)]
    many += [("2026-10-01", 31.0)]
    assert len(gf._mk_spark(many)) == 30  # spark capped at 30 closes


def test_parsers_sort_descending():
    # Stooq order is not guaranteed: parsers must sort date-ascending
    # so last/prev/1M arithmetic is order-independent.
    obs = gf.parse_fred_csv(
        b"observation_date,X\n2026-10-23,102\n2026-09-23,90\n"
        b"2026-10-22,101\n")
    assert obs == [("2026-09-23", 90.0), ("2026-10-22", 101.0),
                   ("2026-10-23", 102.0)]
    obs, blocked = gf.parse_stooq_csv(
        b"Date,Open,High,Low,Close,Volume\n"
        b"2026-10-23,100.50,102,100,101.20,1100\n"
        b"2026-10-22,100,101,99,100.50,1000\n")
    assert obs == [("2026-10-22", 100.5), ("2026-10-23", 101.2)]
    assert blocked is False


def test_ticker_validation_no_fetch(monkeypatch):
    _reset_mk()
    called = []
    monkeypatch.setattr(
        gf, "_fetch_binary",
        lambda *a, **k: called.append(a[0]) or (200, {}, b"", False))
    assert gf.get_ticker("a b")["reason"] == "invalid symbol"
    assert gf.get_ticker("")["reason"] == "invalid symbol"
    assert gf.get_ticker("X" * 21)["reason"] == "invalid symbol"
    assert gf.get_ticker("lmt;rm")["reason"] == "invalid symbol"
    assert called == []  # invalid input never burns a request


def test_get_markets_stooq_blocked(monkeypatch):
    _reset_mk()
    fake, calls = _mock_fetch_factory()
    monkeypatch.setattr(gf, "_fetch_binary", fake)
    m = gf.get_markets()
    syms = [r["symbol"] for r in m["rows"]]
    assert "SP500" in syms and "DJIA" in syms and "BTC-USD" in syms
    assert len(m["rows"]) == 12  # 10 FRED live + 2 Coinbase
    dollar = [r for r in m["rows"] if r["symbol"] == "DTWEXBGS"][0]
    assert dollar["name"] == "US Dollar \u2014 Fed Broad Index"
    assert "DXY" not in [r["symbol"] for r in m["rows"]]
    assert not [r for r in m["rows"]
                if "breadth" in r["name"].lower()]
    assert not [r for r in m["rows"] if r["source"] == "Stooq"]
    assert m["unavailable"] == ["Gold"]
    assert m["stooq"] == {"alive": False, "blocked": True}
    assert m["upd"] is not None and m["all_offline"] is False
    assert gf.get_ticker("LMT.US")["reason"] == "stooq unavailable"
    assert not [u for u in calls if "coingecko" in u]
    btc = [r for r in m["rows"] if r["symbol"] == "BTC-USD"][0]
    assert btc["change_pct"] is None and btc["as_of_kind"] == "spot"
    assert btc["change_1m"] is None and btc["spark"] == []
    sp = [r for r in m["rows"] if r["symbol"] == "SP500"][0]
    assert sp["change_1m"] is not None and sp["spark"] == [6590.12, 6612.5]


def test_get_markets_stooq_alive_world(monkeypatch):
    _reset_mk()
    fake, _calls = _mock_fetch_factory(stooq_mode="csv")
    monkeypatch.setattr(gf, "_fetch_binary", fake)
    m = gf.get_markets()
    world = [r for r in m["rows"] if "WEI" in r["cats"]]
    assert len(world) == 7
    assert sorted({r["region"] for r in world}) == [
        "AMERICAS", "ASIA-PACIFIC", "EMEA"]
    for r in world:
        assert r["change_1m"] is not None and r["spark"] == [100.5, 101.2]
    assert [r for r in m["rows"] if "DEF" in r["cats"]]
    assert m["stooq"] == {"alive": True, "blocked": False}
    assert m["unavailable"] == ["Gold"]


def test_get_markets_fred_series_down(monkeypatch):
    _reset_mk()
    fix = dict(FRED_FIX)
    fix["DGS10"] = None
    fake, _calls = _mock_fetch_factory(fred_fix=fix, stooq_mode="404")
    monkeypatch.setattr(gf, "_fetch_binary", fake)
    m = gf.get_markets()
    syms = [r["symbol"] for r in m["rows"]]
    assert "DGS10" not in syms and "SP500" in syms
    assert "US 10Y" in m["unavailable"]
    assert m["stooq"]["blocked"] is False  # 404 is not a wall
    assert m["all_offline"] is False


def test_get_markets_stale(monkeypatch):
    _reset_mk()
    fake, _calls = _mock_fetch_factory(stooq_mode="404")
    monkeypatch.setattr(gf, "_fetch_binary", fake)
    m1 = gf.get_markets()
    assert m1["upd"] is not None
    # Force re-attempt with failing transports: rows survive STALE.
    for st in list(gf._mk_fred.values()) + list(gf._mk_cb.values()):
        st["attempted_at"] = 0
    monkeypatch.setattr(
        gf, "_fetch_binary",
        lambda *a, **k: (_ for _ in ()).throw(IOError("down")))
    m2 = gf.get_markets()
    sp = [r for r in m2["rows"] if r["symbol"] == "SP500"][0]
    assert sp["stale"] is True and sp["value"] == 6612.5
    assert m2["upd"] == m1["upd"]  # failed attempts never move UPD


def test_get_ticker_live(monkeypatch):
    _reset_mk()
    fake, _calls = _mock_fetch_factory(stooq_mode="csv")
    monkeypatch.setattr(gf, "_fetch_binary", fake)
    d = gf.get_ticker("LMT.US")
    assert d["ok"] is True and d["symbol"] == "LMT.US"
    assert d["close"] == 101.2 and d["date"] == "2026-10-23"
    assert abs(d["change_pct"] - 0.6965) < 0.001
    fake404, _c = _mock_fetch_factory(stooq_mode="404")
    monkeypatch.setattr(gf, "_fetch_binary", fake404)
    gf._mk_stq.clear()
    assert gf.get_ticker("NOPE.US")["reason"] == "symbol not found"


def test_launches_layer_server_side(monkeypatch):
    gf._cache.pop("launches", None)
    pts = [{"la": 28.39, "lo": -80.61, "lb": "Test Launch",
            "ex": "Test Provider", "t": 1793000000000}]
    monkeypatch.setattr(
        gf, "_fetch_launches_family",
        lambda: {"launches": gf._entry(points=pts, total=1, note="")})
    payload = gf.get_layer("launches")
    assert payload["layer"] == "launches"
    assert payload["points"] == pts


def test_static_html_markets_and_launches():
    assert "launches: { g: 'space'" in HTML
    assert "launches: 'LAUNCHES'" in HTML
    assert "drawPts('launches'" in HTML
    assert 'id="gl-markets"' in HTML
    assert 'data-gt="markets"' in HTML
    assert "glMarketsToggle" in HTML
    assert "MARKET DATA — NOT SECURITY INTELLIGENCE" in HTML
    assert "NOT INVESTMENT ADVICE" in HTML
    assert "Movers in tracked basket — not market-wide" in HTML
    assert "Breadth unavailable without a licensed source." not in HTML
    assert 'id="mk-breadth"' in HTML and "glMkBreadthHtml" in HTML
    assert "TRACKED BASKET, NOT MARKET-WIDE" in HTML
    assert "vanthex-markets-watch" in HTML
    # Screenshot layout (ADE 22:39): 8 core cards, 8 numbered chips,
    # world table, footer tabs — plus the v1.25.0 breadth basket bar
    # (K31: panel's own rows only; exchange breadth stays dropped).
    assert "GL_MK_CORE" in HTML
    for sym in ["SP500", "NASDAQCOM", "VIXCLS", "DGS10", "DTWEXBGS",
                "GOLDAMGBD228NLBM", "DCOILWTICO", "BTC-USD"]:
        assert sym in HTML
    for chip in ["WEI", "DEF", "NRG", "CMDTY", "FX", "CRYPTO", "WATCH",
                 "DOW"]:
        assert ('id: \'' + chip + '\'') in HTML
    assert 'id="mk-cards"' in HTML and 'id="mk-wt"' in HTML
    assert 'id="mk-foottabs"' in HTML and 'id="mk-chips"' in HTML
    assert "WORLD EQUITY INDICES" in HTML
    for col in ["SECURITY", "LAST", "%CHG", "1M"]:
        assert col in HTML
    for grp in ["AMERICAS", "EMEA", "ASIA-PACIFIC"]:
        assert grp in HTML
    assert "data-mfoot=" in HTML
    assert "['RATES', 'VOLATILITY', 'DOLLAR']" in HTML
    assert "Ticker or function" in HTML
    assert "data-mwei" in HTML and "glMkSparkPath" in HTML
    assert "glMkWorldHtml" in HTML and "glMkCardHtml" in HTML
    block = HTML[HTML.index("/* v1.20.0 MARKETS panel (design §6 "
                            "+ §14.4 + screenshot ADE 22:39)."):
                 HTML.index("/* v1.20.0 markets-end */")]
    assert "AI OVERVIEW" not in block
    assert "All sides" not in block
    assert "OpenAI" not in block


def test_i18n_extra14():
    m = re.search(r"const I18N_EXTRA14 = (\{.*?\});\nfor \(const _lang",
                  HTML, re.S)
    assert m, "EXTRA14 table missing"
    table = json.loads(m.group(1))
    assert sorted(table.keys()) == sorted(EXTRA14_LANGS)
    for lang in EXTRA14_LANGS:
        assert sorted(table[lang].keys()) == sorted(EXTRA14_KEYS), lang
        assert all(table[lang][k].strip() for k in EXTRA14_KEYS), lang
    hi = table["hi"]
    assert any("\u0900" <= ch <= "\u097f" for v in hi.values()
               for ch in v), "Hindi EXTRA14 must be Devanagari"


def test_js_pure_markets_node():
    start = HTML.index("/* v1.20.0 markets-pure-start */")
    end = HTML.index("/* v1.20.0 markets-pure-end */")
    js = HTML[start:end]
    js += """
const out = {
  sess_wd: glMkSessionLabel(6, '2026-10-23'),
  sess_wd_empty: glMkSessionLabel(0, ''),
  sess_day: glMkSessionLabel(3, '2026-10-23'),
  sess_day_empty: glMkSessionLabel(3, ''),
  movers: glMkMovers([
    {symbol: 'A', change_pct: 1.5},
    {symbol: 'B', change_pct: -2.25},
    {symbol: 'C', change_pct: null},
    {symbol: 'D', change_pct: 0.5}]),
  movers_one: glMkMovers([{symbol: 'A', change_pct: 1.5}]),
  movers_none: glMkMovers([{symbol: 'A', change_pct: null}]),
  spark: glMkSparkPath([100, 110, 105], 100, 20),
  spark_one: glMkSparkPath([100], 100, 20),
  spark_empty: glMkSparkPath([], 100, 20)
};
console.log(JSON.stringify(out));
"""
    with tempfile.NamedTemporaryFile("w", suffix=".js",
                                     delete=False) as f:
        f.write(js)
        path = f.name
    try:
        res = subprocess.run(["node", path], capture_output=True,
                             text=True, timeout=30)
    finally:
        os.unlink(path)
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout.strip())
    assert out["sess_wd"] == "SESSIONS CLOSED — last close 2026-10-23"
    assert out["sess_wd_empty"] == "SESSIONS CLOSED"
    assert out["sess_day"] == "LAST CLOSE 2026-10-23"
    assert out["sess_day_empty"] == "LAST CLOSE"
    assert out["movers"]["gain"]["symbol"] == "A"
    assert out["movers"]["lose"]["symbol"] == "B"
    assert out["movers_one"] is None
    assert out["movers_none"] is None
    assert out["spark"] == "0.0,20.0 50.0,0.0 100.0,10.0"
    assert out["spark_one"] == ""
    assert out["spark_empty"] == ""


def test_csp_version_osint_gates():
    m = re.search(r'send_header\("Content-Security-Policy",\s*(.*?)\)',
                  APP2, re.S)
    assert m, "CSP header block not found"
    served = "".join(re.findall(r'"([^"]*)"', m.group(1)))
    assert served == CSP_1150, served
    assert 'server_version = "VANTHEX/1.25.0"' in APP2
    assert '"version": "1.25.0"' in APP2
    assert "VANTHEX 1.25.0" in HTML
    digest = hashlib.md5(
        open(os.path.join(ROOT, "osint.py"), "rb").read()).hexdigest()
    assert digest == OSINT_MD5_1160
    assert "globe/markets" in APP2 and "get_markets" in GF_SRC
    assert "get_ticker" in GF_SRC
