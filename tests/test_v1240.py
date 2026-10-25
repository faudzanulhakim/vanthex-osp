"""v1.25.0 — Globe gap closure (service dashboard, design §16.6 + §16.8).

Scope: MARKETS breadth basket (K31), submarine-cables fallback link,
nuclear 64 (OSIRIS model), alert pins, bottom ticker strip, keyboard
shortcuts F/S/L/M/R/?/ESC, pan/zoom pad, Style Studio. NO new hosts,
NO CSP change, NO AI/OI, NO DRAW, NO terrain (v1.25.0), NO REMOTE.

GATES HONESTLY RECORDED (build verification, 2026-10-25):
- Cables DROPS as a data layer: Telegeography's citation page states
  "Access to the underlying databases remains restricted to paying
  subscribers" and "TeleGeography's interactive cable map is not an
  embeddable resource. If you'd like to access the underlying data
  for a project, you may license our map data." CC BY-SA 4.0 covers
  maps/images/references/screenshots, NOT the underlying database.
  The OSIRIS repo being MIT does not transfer Telegeography's data
  rights. Per the design's fallback, the maritime panel carries an
  outbound link to submarinecablemap.com only: no lines, no fetch,
  no vendored GeoJSON, no CSP/host impact.
- Nuclear REPLACED, not merged: the service already shipped a WRI
  195-site layer (unit rows, no status/reactors/owner/source). §16.6
  orders the OSIRIS-model curated 64 with per-facility fields, so the
  WRI 195 was replaced by the OSIRIS 64 (same layer id, same card
  contract extended). The OSIRIS seismic-risk status override (USGS
  quake proximity) was deliberately NOT copied: the dataset is
  static, NOT live status. Wikipedia links render only where
  sourceUrl exists (exactly 7, Netherlands entries) — never a
  guessed slug. Capacity 0 renders as — (per OSIRIS: 0 is not an
  electrical figure for research/enrichment entries).
- Breadth BTC spot EXCLUDED: the design's conditional ("BTC spot
  only if the daemon stores >=24h of spot observations") FAILS —
  the daemon stores only the latest Coinbase spot value, so spot
  rows have change_pct None and are excluded, never flat.
- Ticker offline warnings REMOVED from the strip: per the §16.6
  strip spec (quakes + markets only); warnings remain visible in
  the layer-panel chips and the alerts footer.
- Alert pins default OFF (opt-in toggle) and MapLibre-only by
  design; the canvas fallback draws none.
- Style Studio token definitions (design leaves them open): presets
  define colors only; choosing VANTHEX GLASS clears color overrides;
  radius multiplier bases are the real defaults 6/10/14/18px; panel
  opacity default .96, border default 1, blur default 0px. The late
  CSS rules reproduce the pre-v1.25.0 rendering exactly when no
  Studio setting exists.
- Server note strings (incl. the nuclear STATIC DATASET note) are
  rendered verbatim by the layer panel, never through tr(): panel
  notes are not translated anywhere in this codebase, so the note
  has no EXTRA17 key. EXTRA17 covers client-rendered strings only.

All tests below are hermetic (no live hosts); the live-server class
only checks the served header, CSP, and served-HTML markers.
"""

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

HTML = open(os.path.join(ROOT, "templates", "app.html"),
             encoding="utf-8").read()
APP2 = open(os.path.join(ROOT, "app2.py"), encoding="utf-8").read()
FEEDS = open(os.path.join(ROOT, "globe_feeds.py"), encoding="utf-8").read()
STATIC = json.load(open(os.path.join(ROOT, "globe_static.json"),
                        encoding="utf-8"))

import globe_feeds as gf  # noqa: E402

CSP_1240 = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: "
            "https://server.arcgisonline.com https://tilecache.rainviewer.com "
            "https://nowcoast.noaa.gov https://tiles.basemaps.cartocdn.com https://s3.amazonaws.com; "
            "connect-src 'self' https://api.rainviewer.com "
            "https://basemaps.cartocdn.com https://tiles.basemaps.cartocdn.com "
            "https://tiles-a.basemaps.cartocdn.com https://tiles-b.basemaps.cartocdn.com "
            "https://tiles-c.basemaps.cartocdn.com https://tiles-d.basemaps.cartocdn.com; "
            "frame-src https://www.youtube-nocookie.com; "
            "worker-src 'self' blob:; frame-ancestors 'none'; "
            "object-src 'none'; base-uri 'self'; form-action 'self'")

NUCLEAR_NOTE = ("STATIC DATASET — 64 facilities, Wikipedia-sourced; "
                "locations approximate; NOT live status")


# ------------------------------------------------------------ version
def test_version_pins():
    assert '"version": "1.25.0"' in APP2
    assert 'server_version = "VANTHEX/1.25.0"' in APP2
    assert "VANTHEX 1.25.0" in HTML
    assert "VANTHEX/1.25.0" in FEEDS


def _extract_csps(src):
    out = []
    for m in re.finditer(
            r'self\.send_header\("Content-Security-Policy",\s*(.*?)\)',
            src, re.S):
        parts = re.findall(r'"([^"]*)"', m.group(1))
        out.append("".join(parts))
    return out


def test_csp_byte_identical_to_v1230():
    csps = _extract_csps(APP2)
    assert csps, "no CSP send_header found"
    assert len(csps) >= 2, "streaming CSP copy missing"
    assert all(c == CSP_1240 for c in csps)
    assert "s3.amazonaws.com" in csps[0]
    assert "terrarium" not in csps[0]
    assert "gibs.earthdata.nasa.gov" not in csps[0]


def test_osint_byte_identical():
    h = hashlib.md5(open(os.path.join(ROOT, "osint.py"), "rb").read())
    assert h.hexdigest() == "65ec21c31b4aad76aa304fcb411388ae"


# ------------------------------------------------------------ breadth
def _row(rid, chg, kind="daily"):
    return {"id": rid, "name": rid, "change_pct": chg, "as_of_kind": kind}


def test_breadth_counts_only_computed_changes():
    rows = [_row("A", 1.5), _row("B", -0.5), _row("C", 0.0),
            _row("D", None), _row("BTC-USD", None, "spot")]
    b = gf._mk_breadth(rows)
    assert (b["up"], b["down"], b["flat"]) == (1, 1, 1)
    assert b["total"] == 3
    assert b["excluded"] == 2 and b["excluded_spot"] == 1
    assert b["hidden"] is False
    assert [x["id"] for x in b["best"]] == ["A", "C", "B"]
    assert [x["id"] for x in b["worst"]] == ["B", "C", "A"]


def test_breadth_hidden_when_fewer_than_two_counted():
    assert gf._mk_breadth([_row("A", 1.0), _row("B", None)])["hidden"] is True
    assert gf._mk_breadth([])["hidden"] is True
    assert gf._mk_breadth([_row("A", 1.0), _row("B", 2.0)])["hidden"] is False


def test_breadth_best_worst_capped_at_five():
    rows = [_row("S%d" % i, float(i)) for i in range(8)]
    b = gf._mk_breadth(rows)
    assert len(b["best"]) == 5 and len(b["worst"]) == 5
    assert b["best"][0]["id"] == "S7" and b["worst"][0]["id"] == "S0"
    assert b["flat"] == 1  # the 0.0 row counts flat; None never does


def test_breadth_spot_rows_never_counted_flat():
    rows = [_row("BTC-USD", None, "spot"), _row("ETH-USD", None, "spot"),
            _row("SP500", 0.34)]
    b = gf._mk_breadth(rows)
    assert b["flat"] == 0 and b["total"] == 1 and b["hidden"] is True
    assert b["excluded"] == 2 and b["excluded_spot"] == 2


def test_breadth_in_get_markets(monkeypatch):
    gf._mk_fred.clear()
    gf._mk_cb.clear()
    gf._mk_stq.clear()
    gf._mk_stq_blocked_at = None
    fix = {
        "SP500": b"observation_date,SP500\n2026-10-22,6590.12\n2026-10-23,6612.50\n",
        "DJIA": b"observation_date,DJIA\n2026-10-22,53500.00\n2026-10-23,53400.00\n",
    }

    def fake(url, timeout=30.0, cap=1024 * 1024, headers=None,
             method="GET", data=None):
        if "fred.stlouisfed.org" in url:
            sid = url.split("id=")[1].split("&")[0]
            body = fix.get(sid)
            if body is None:
                return (404, {}, b"<html>not found</html>", False)
            return (200, {}, body, False)
        if "api.coinbase.com" in url:
            return (200, {},
                    b'{"data":{"amount":"79412.14","currency":"USD"}}', False)
        if "stooq.com" in url:
            return (200, {},
                    b'<!DOCTYPE html><html><head><meta charset="utf-8">'
                    b'<meta name="robots" content="noindex,nofollow"></head>'
                    b'<body><noscript>This site requires JavaScript to '
                    b'verify you</noscript></body></html>', False)
        raise AssertionError("unexpected host: " + url)

    monkeypatch.setattr(gf, "_fetch_binary", fake)
    m = gf.get_markets()
    b = m["breadth"]
    assert b["up"] == 1 and b["down"] == 1 and b["flat"] == 0
    assert b["total"] == 2 and b["hidden"] is False
    assert b["excluded_spot"] >= 1  # BTC/ETH spot rows excluded
    assert "exchange" not in json.dumps(b).lower()


def test_breadth_bar_in_client():
    assert 'id="mk-breadth"' in HTML
    assert "glMkBreadthHtml" in HTML
    assert "TRACKED BASKET, NOT MARKET-WIDE" in HTML
    assert "Breadth unavailable without a licensed source." not in HTML
    assert "NOT INVESTMENT ADVICE" in HTML


# ------------------------------------------------------------ cables
def test_no_cables_dataset_in_tree():
    for dirpath, _dirs, files in os.walk(ROOT):
        if ".venv" in dirpath or "__pycache__" in dirpath:
            continue
        for f in files:
            assert "submarine-cables" not in f, os.path.join(dirpath, f)
            assert f not in ("cables.json", "cables.geojson")


def test_cables_fallback_link_only():
    assert HTML.count("submarinecablemap.com") == 1  # href only, no fetch
    assert "https://www.submarinecablemap.com" in HTML
    assert "View the live map" in HTML
    assert ("Cable routes not vendored — Telegeography restricts its "
            "underlying database to subscribers") in HTML
    m = re.search(r"const GL_SUBS = \{(.*?)\n\};", HTML, re.S)
    assert m and "cables" not in m.group(1)
    gate = HTML[HTML.index("v1.24.0 §16.6 cables gate"):
                HTML.index("if (gid === 'weather')")]
    assert "fetch(" not in gate


# ------------------------------------------------------------ nuclear
def test_nuclear_64_rich():
    nuc = gf.get_layer("nuclear")
    assert nuc["state"] == "static" and nuc["count_total"] == 64
    assert nuc["note"] == NUCLEAR_NOTE
    assert STATIC["nuclear_meta"]["count"] == 64
    pts = nuc["points"]
    assert len(pts) == 64
    assert len({p["nuc"]["id"] for p in pts}) == 64
    req = {"id", "name", "city", "country", "status", "reactors",
           "capacityMW", "owner"}
    for p in pts:
        assert set(("la", "lo", "lb", "ex", "nuc")) <= set(p)
        assert req <= set(p["nuc"])
        assert -90 <= p["la"] <= 90 and -180 <= p["lo"] <= 180
        assert isinstance(p["nuc"]["reactors"], int)
        assert isinstance(p["nuc"]["capacityMW"], (int, float))
    urls = [p["nuc"]["sourceUrl"] for p in pts if p["nuc"].get("sourceUrl")]
    assert len(urls) == 7
    assert all(u.startswith("https://en.wikipedia.org/") for u in urls)
    first = pts[0]["nuc"]
    assert first["id"] == "nuc-ua-zaporizhzhia"
    assert first["name"] == "Zaporizhzhia NPP"
    assert first["reactors"] == 6 and first["capacityMW"] == 5700


def test_nuclear_card_in_client():
    assert "if (p.nuc)" in HTML
    assert "Wikipedia ↗" in HTML
    assert "nuc_capacity" in HTML and "nuc_url" in HTML
    assert "p.nuc.capacityMW ? " in HTML


# ------------------------------------------------------------ pins
def test_alert_pins_structure():
    assert "glMapSyncPins" in HTML
    assert "ml-alert-pins" in HTML
    assert "ids.push('ml-alert-pins')" in HTML
    assert "Show alert pins on the map" in HTML
    assert 'id="gl-apins"' in HTML
    assert "st.pins ? 'checked' : ''" in HTML  # undefined -> unchecked (OFF)
    assert "layerId === 'alert-pins'" in HTML
    assert "glAlertsCard({ cat: props.cat" in HTML


# ------------------------------------------------------------ ticker
def test_ticker_strip():
    assert "gl-tk-track" in HTML
    assert "gl-tk-scroll" in HTML
    assert "animation-play-state:paused" in HTML
    assert "el._tkItems" in HTML
    assert "glMarketsToggle(true)" in HTML
    assert "glAlertsFlyTo({ la: it.la, lo: it.lo })" in HTML
    body = re.search(r"function glTicker\(\) \{(.*?)\n\}", HTML, re.S).group(1)
    assert "FEED OFFLINE" not in body  # warnings moved out of the strip
    assert "quakes" in body and "markets" in body
    assert "el.style.display = 'none'" in body  # hidden when all offline


# ------------------------------------------------------------ shortcuts
def test_shortcuts_and_help():
    for fn in ["glLayerPanelToggle", "glHelpToggle", "glEscClose",
               "glPadHold", "glPan"]:
        assert fn in HTML
    assert "e.key === 's'" in HTML and "e.key === 'l'" in HTML
    assert "e.key === 'm'" in HTML and "e.key === '?'" in HTML
    assert "e.key === 'Escape'" in HTML
    assert "row('O', 'Not assigned'" in HTML
    assert "row('I', 'Not assigned'" in HTML
    assert 'id="gl-help"' in HTML
    assert "? — SHORTCUTS" in HTML
    # pre-existing branches intact
    assert "glSearchToggle(true)" in HTML
    assert "glResetView()" in HTML
    # O/I have no action branch (only the help rows document them)
    assert "e.key === 'o'" not in HTML and "e.key === 'i'" not in HTML


# ------------------------------------------------------------ pad
def test_pad():
    for bid in ["gl-pup", "gl-pleft", "gl-pright", "gl-pdown"]:
        assert 'id="%s"' % bid in HTML
    assert "glPadHold(document.getElementById('gl-pup'), 0, -60)" in HTML
    assert "map.panBy([dx, dy])" in HTML
    assert "glClampPan(g); glDraw();" in HTML


# ------------------------------------------------------------ studio
def test_studio():
    assert "vanthex:style-studio" in HTML
    assert "GL_STUDIO_PRESETS" in HTML
    for p in ["VANTHEX GLASS", "HORUS", "PHANTOM", "TERMINAL", "CRIMSON",
              "ARCTIC", "BLACKOUT"]:
        assert "'%s'" % p in HTML
    assert 'data-gt="studio"' in HTML and 'id="gl-studio"' in HTML
    assert "glStudioToggle" in HTML and "glStudioValid" in HTML
    assert "Saved to this browser." in HTML
    assert "glStudioApply(glStudioRead())" in HTML
    studio = HTML[HTML.index("v1.24.0 Style Studio"):
                  HTML.index("function glStudioToggle")]
    assert "fetch(" not in studio and "glApi" not in studio
    assert "--gl-panel-alpha,.96" in HTML
    assert "--gl-border-alpha,1" in HTML
    assert "--gl-blur,0px" in HTML
    assert ("[['--radius-sm', 6], ['--radius-md', 10], ['--radius-lg', 14], "
            "['--radius-xl', 18]]") in HTML
    assert "--vx-font-ui" in HTML and "--vx-font-mono" in HTML


def test_scope_guard_no_new_tool_buttons_no_terrain_change():
    gts = sorted(set(v for v in
                     re.findall(r'data-gt="([^"]+)"', HTML)
                     if "+" not in v and "'" not in v))
    assert gts == ["arcgis", "copylink", "labels", "markets", "places",
                   "reset", "route", "space", "studio", "tools"]
    # v1.25.0: the DISPLAY placeholders are real toggles now.
    assert 'data-ctl="buildings"' in HTML
    assert 'data-ctl="terrain"' in HTML
    assert "Not built." not in HTML


# ------------------------------------------------------------ I18N
def test_extra17():
    m = re.search(r"const I18N_EXTRA17 = (\{.*?\});\nfor", HTML, re.S)
    assert m, "EXTRA17 block missing"
    obj = json.loads(m.group(1))
    assert set(obj.keys()) == {"id", "es", "fr", "de", "pt", "ru", "ja",
                               "ko", "zh", "ar", "hi"}
    keysets = [set(d.keys()) for d in obj.values()]
    assert all(ks == keysets[0] for ks in keysets)
    assert len(keysets[0]) == 38
    for k in ["BREADTH", "TRACKED BASKET, NOT MARKET-WIDE",
              "rows without daily change excluded", "spot-only",
              "SUBMARINE CABLES", "View the live map",
              "Show alert pins on the map", "ALERT PINS",
              "KEYBOARD SHORTCUTS", "Fullscreen", "Share / copy link",
              "Layer panel", "Markets panel", "Help",
              "Close panel / popup", "Not assigned", "Style Studio",
              "Saved to this browser.", "Copy theme", "Paste theme",
              "Invalid theme JSON", "Preset", "Accent", "Signals",
              "Panel opacity", "Border", "Blur", "Corner radius", "Font",
              "Theme copied", "Theme applied", "Critical", "Warning",
              "Nominal", "Info"]:
        assert k in keysets[0], k
    assert ("Object.assign(I18N[_lang] || {}, I18N_EXTRA17[_lang])"
            in HTML)


# ------------------------------------------------------------ live
class TestLiveServer:
    PORT = None
    PROC = None
    COOKIE = None

    @classmethod
    def _free_port(cls):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    @classmethod
    def setup_class(cls):
        import store as _store
        _store.init_db()
        try:
            _store.create_user("v1240test", "v1240testpw", "admin")
        except Exception:
            pass
        cls.PORT = cls._free_port()
        env = dict(os.environ)
        env["PTK_ADMIN_PW"] = "unused-in-this-test"
        cls.PROC = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "app2.py"),
             str(cls.PORT)],
            cwd=ROOT, env=env, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(
                        "http://127.0.0.1:%d/login" % cls.PORT,
                        timeout=5) as r:
                    assert r.status == 200
                    break
            except Exception:
                if cls.PROC.poll() is not None:
                    raise AssertionError("test server exited early")
                time.sleep(1)
        else:
            raise AssertionError("test server did not come up")
        req = urllib.request.Request(
            "http://127.0.0.1:%d/api/login" % cls.PORT,
            data=json.dumps({"username": "v1240test",
                             "password": "v1240testpw"}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.status == 200
            cls.COOKIE = r.headers.get("Set-Cookie", "").split(";")[0]

    @classmethod
    def teardown_class(cls):
        if cls.PROC is not None:
            cls.PROC.terminate()
            try:
                cls.PROC.wait(timeout=10)
            except Exception:
                cls.PROC.kill()

    def _get(self, path, authed=True):
        req = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (self.PORT, path))
        if authed and self.COOKIE:
            req.add_header("Cookie", self.COOKIE)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def test_live_header_csp_and_markers(self):
        st, headers, _body = self._get("/login", authed=False)
        assert st == 200
        assert headers.get("Server", "").startswith("VANTHEX/1.25.0")
        assert headers.get("Content-Security-Policy") == CSP_1240
        st, _h, body = self._get("/classic")
        assert st == 200
        html = body.decode("utf-8", "replace")
        for marker in ['id="mk-breadth"', 'data-gt="studio"',
                       'id="gl-studio"', 'id="gl-help"', 'id="gl-pup"',
                       "submarinecablemap.com", "glMapSyncPins",
                       "glStudioApply", "TRACKED BASKET, NOT MARKET-WIDE"]:
            assert marker in html, marker

    def test_live_nuclear_layer(self):
        st, _h, body = self._get("/api/osint/globe/layer/nuclear")
        assert st == 200
        d = json.loads(body)
        assert d["count_total"] == 64
        assert d["note"] == NUCLEAR_NOTE
        assert len(d["points"]) == 64
        assert all("nuc" in p for p in d["points"])
