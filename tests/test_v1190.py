"""v1.19.0 — Fase 3 program OSIRIS (service dashboard, globe view).

Design §5 + §14.5, host batch B only (api.github.com,
ll.thespacedevs.com, feeds.bbci.co.uk, www.aljazeera.com,
rss.dw.com, feeds.npr.org, www.france24.com), no CSP change, no AI,
no other phase item:
  1. GitHub Recon via the public GitHub API through the fetch
     daemon, text only (no profile photos, K9), max 2 requests per
     lookup, 24 h cache, local username validation, no search
     endpoint, no scraping; rate-limit guard + STALE cache fallback.
  2. ROCKET counter via Launch Library 2 through the fetch daemon
     (LAUNCHES sub-layer, SPACE group, TTL 3600 s): upcoming within
     30 days, cap 20, net order, TBD flagged, pad-less launches
     records-only.
  3. NEWS via RSS through the fetch daemon (BBC, Al Jazeera EN, DW,
     NPR, France 24 — NHK World DROPPED at build: both candidate
     paths 404'd and no documented feed URL found): verbatim
     headlines as the NEWS category in Live Alerts + LIVE NEWS
     FEEDS count, static factual outlet descriptors, no AI
     (overview/assistant/All sides/topic chips permanently excluded
     per ADE's 19:58 WIB decision; places filter OPEN, view count
     dropped).

Python fetch tests are hermetic: globe_feeds._fetch_binary is
monkeypatched, so no external network is used, and _save_snapshot
is stubbed so no test ever writes the production cache file. Live
GitHub/LL2/RSS proof is a deployment-time check, not part of this
suite. The alerts pure-JS block is exercised with the node harness
in the v1.16.0 pattern; the no-news call path must stay
byte-identical in behavior to v1.16.0 (exact counts object, exact
sources object).
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time

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


def _run_node(js):
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(js)
        path = f.name
    try:
        r = subprocess.run(["node", path], capture_output=True, text=True, timeout=120)
    finally:
        os.unlink(path)
    assert r.returncode == 0, f"node harness failed:\n{r.stdout}\n{r.stderr}"
    return r.stdout


def _pure_js():
    a = HTML.index("/* v1.16.0 alerts-pure-start */")
    b = HTML.index("/* v1.16.0 alerts-pure-end */") + len(
        "/* v1.16.0 alerts-pure-end */")
    return HTML[a:b]


# ---------------------------------------------------------------- fixtures
def _iso(ms):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms / 1000))


_NOW_MS = int(time.time() * 1000)

GH_PROFILE = {
    "login": "octocat", "name": "The Octocat",
    "bio": "A mysterious octocat", "location": "San Francisco",
    "company": "@github", "blog": "https://github.blog",
    "public_repos": 8, "followers": 100,
    "created_at": "2011-01-25T18:44:36Z",
    "avatar_url": "https://avatars.githubusercontent.com/u/583231?v=4",
}
GH_REPOS = [
    {"name": "hello-world", "description": None, "language": "Ruby",
     "stargazers_count": 42, "forks_count": 7,
     "updated_at": "2026-10-20T00:00:00Z",
     "html_url": "https://github.com/octocat/hello-world"},
    {"name": "spoon-knife", "description": "Test repo", "language": None,
     "stargazers_count": 3, "forks_count": 1,
     "updated_at": "2026-10-19T00:00:00Z",
     "html_url": "https://github.com/octocat/spoon-knife"},
]

LL2_PAGE = {
    "count": 4,
    "results": [
        # deliberately NOT net-ordered: the parser must sort, then cap
        {"name": "Far launch", "net": _iso(_NOW_MS + 40 * 86400 * 1000),
         "tbddate": False, "tbdtime": False,
         "status": {"name": "Go for Launch"},
         "launch_service_provider": {"name": "SpaceX"},
         "pad": {"name": "LC-39A", "latitude": 28.3922, "longitude": -80.6077}},
        {"name": "Padless launch", "net": _iso(_NOW_MS + 5 * 86400 * 1000),
         "tbddate": False, "tbdtime": False,
         "status": {"name": "To Be Determined"},
         "launch_service_provider": {"name": "ULA"},
         "pad": {"name": "No pad", "latitude": None, "longitude": None}},
        {"name": "Soon launch", "net": _iso(_NOW_MS + 2 * 86400 * 1000),
         "tbddate": False, "tbdtime": False,
         "status": {"name": "Go for Launch"},
         "launch_service_provider": {"name": "SpaceX"},
         "pad": {"name": "SLC-40", "latitude": 28.5618, "longitude": -80.5770}},
        {"name": "TBD launch", "net": _iso(_NOW_MS + 1 * 86400 * 1000),
         "tbddate": True, "tbdtime": True,
         "status": {"name": "TBD"},
         "launch_service_provider": {"name": "Rocket Lab"},
         "pad": {"name": "LC-1", "latitude": -39.2628, "longitude": 177.8641}},
    ],
}

RSS_BBC = (b'<?xml version="1.0" encoding="UTF-8"?>'
           b'<rss version="2.0"><channel><title>BBC News - World</title>'
           b'<item><title>First headline</title>'
           b'<link>https://www.bbc.com/news/articles/1</link>'
           b'<pubDate>Sat, 24 Oct 2026 10:00:00 GMT</pubDate></item>'
           b'<item><title><b>Bold</b> headline</title>'
           b'<link>https://www.bbc.com/news/articles/2</link>'
           b'<pubDate>Sat, 24 Oct 2026 09:00:00 GMT</pubDate></item>'
           b'<item><title>Dateless headline</title>'
           b'<link>https://www.bbc.com/news/articles/3</link></item>'
           b'</channel></rss>')
RSS_AJE = (b'<?xml version="1.0" encoding="UTF-8"?>'
           b'<rss version="2.0"><channel><title>Al Jazeera</title>'
           b'<item><title>AJ headline</title>'
           b'<link>https://www.aljazeera.com/news/1</link>'
           b'<pubDate>Sat, 24 Oct 2026 11:00:00 GMT</pubDate></item>'
           b'</channel></rss>')
RSS_BAD = b'<rss version="2.0"><channel><item><title>Broken'


# ---------------------------------------------------------------- helpers
def _reset_gh():
    with gf._gh_lock:
        gf._gh_cache.clear()
        gf._gh_state.update({"throttle": 0.0, "remaining": None,
                             "reset": None})


def _reset_news():
    with gf._news_lock:
        gf._news_state.clear()


def _reset_launches():
    gf._cache.pop("launches", None)


class _FakeBinary:
    """Routes _fetch_binary calls by URL substring. Each entry is
    (needle, status, headers, body). Calls are counted per needle."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = {}

    def __call__(self, url, timeout=30.0, cap=1024 * 1024, headers=None,
                 method="GET", data=None):
        for needle, status, hdrs, body in self.routes:
            if needle in url:
                self.calls[needle] = self.calls.get(needle, 0) + 1
                return status, hdrs, body, False
        raise IOError("unexpected URL in test: " + url)


def _gh_routes(profile_status=200, repos_status=200, remaining="59",
                reset=None):
    hdrs = {"x-ratelimit-remaining": remaining,
            "x-ratelimit-reset": str(reset or int(time.time()) + 3600)}
    return _FakeBinary([
        ("/users/octocat/repos", repos_status, hdrs,
         json.dumps(GH_REPOS).encode("utf-8")),
        ("/users/octocat", profile_status, hdrs,
         json.dumps(GH_PROFILE).encode("utf-8")),
    ])


# ---------------------------------------------------------------- version
def test_version_markers():
    assert '"version": "1.25.0"' in APP2
    assert 'server_version = "VANTHEX/1.25.0"' in APP2
    assert "VANTHEX 1.25.0" in HTML
    assert "VANTHEX/1.25.0" in GF_SRC
    assert "/api/osint/globe/github" in APP2
    assert "/api/osint/globe/launches" in APP2
    assert "/api/osint/globe/news" in APP2
    assert "/api/osint/globe/markets" in APP2


def test_csp_and_osint_untouched():
    m = re.search(r'send_header\("Content-Security-Policy",\s*(.*?)\)',
                  APP2, re.S)
    assert m, "CSP header block not found"
    served = "".join(re.findall(r'"([^"]*)"', m.group(1)))
    assert served == CSP_1150, served
    md5 = hashlib.md5(open(os.path.join(ROOT, "osint.py"),
                           "rb").read()).hexdigest()
    assert md5 == OSINT_MD5_1160, "osint.py must be byte-identical"


def test_no_ai_no_rejected_features_no_avatar_host():
    # v1.23.0 §16.2: "All sides" is the default chip label of the STATIC
    # perspective filter (not the AI feature) — no longer banned.
    # v1.23.0 §16.5: the v1.11.0 SHODAN rejection was repealed, so the
    # SHODAN IOT tool legitimately appears in the panel.
    for needle in ("AI OVERVIEW", "OpenAI"):
        assert needle not in HTML, needle
        assert needle not in GF_SRC, needle
    assert "avatars.githubusercontent.com" not in HTML
    assert "avatars.githubusercontent.com" not in GF_SRC
    recon = HTML[HTML.index("/* v1.19.0 recon-start */"):
                 HTML.index("/* v1.19.0 recon-end */")]
    assert "<img" not in recon, "recon panel must never render images"
    assert "fingerprin" not in GF_SRC.lower()


# ---------------------------------------------------------------- GitHub
def test_github_validation_never_touches_network():
    _reset_gh()
    fake = _FakeBinary([])
    orig = gf._fetch_binary
    gf._fetch_binary = fake
    try:
        for bad in ("", "-bad-", "bad-", "bad user", "a" * 40,
                    "bad/user", "bad_user"):
            res = gf.github_recon(bad)
            assert res["ok"] is False
            assert res["reason"] == "invalid username"
        assert fake.calls == {}, "invalid input must burn no quota"
    finally:
        gf._fetch_binary = orig


def test_github_lookup_two_requests_text_only_cached():
    _reset_gh()
    fake = _gh_routes()
    orig = gf._fetch_binary
    gf._fetch_binary = fake
    try:
        res = gf.github_recon("octocat")
        assert res["ok"] is True
        assert res["profile"]["login"] == "octocat"
        assert res["profile"]["name"] == "The Octocat"
        assert res["profile"]["bio"] == "A mysterious octocat"
        assert res["profile"]["location"] == "San Francisco"
        assert res["profile"]["company"] == "@github"
        assert res["profile"]["blog"] == "https://github.blog"
        assert res["profile"]["public_repos"] == 8
        assert res["profile"]["followers"] == 100
        assert res["profile"]["created_at"] == "2011-01-25T18:44:36Z"
        assert "avatar" not in json.dumps(res), "no profile photo ever"
        assert len(res["repos"]) == 2
        assert res["repos"][0]["name"] == "hello-world"
        assert res["repos"][0]["description"] == ""
        assert res["repos"][0]["language"] == "Ruby"
        assert res["repos"][0]["stars"] == 42
        assert res["repos"][1]["description"] == "Test repo"
        assert res["repos"][1]["language"] == ""
        assert sum(fake.calls.values()) == 2, "max 2 requests per lookup"
        res2 = gf.github_recon("octocat")
        assert res2["cached"] is True and res2["stale"] is False
        assert sum(fake.calls.values()) == 2, "cache hit burns nothing"
        res3 = gf.github_recon("OctoCat")
        assert res3["cached"] is True, "cache key is case-insensitive"
    finally:
        gf._fetch_binary = orig


def test_github_not_found_and_rate_limit():
    _reset_gh()
    fake = _gh_routes(profile_status=404)
    orig = gf._fetch_binary
    gf._fetch_binary = fake
    try:
        res = gf.github_recon("octocat")
        assert res["ok"] is False and res["reason"] == "user not found"
    finally:
        gf._fetch_binary = orig
    _reset_gh()
    reset = int(time.time()) + 1800
    fake = _gh_routes(profile_status=403, remaining="0", reset=reset)
    gf._fetch_binary = fake
    try:
        res = gf.github_recon("octocat")
        assert res["ok"] is False and res["reason"] == "rate limit"
        assert res["rate"]["reset"] == reset
        # with a warm cache, the same exhausted limit serves STALE
        with gf._gh_lock:
            gf._gh_cache["octocat"] = {
                "at": time.time() - 100000,
                "result": {"ok": True, "profile": {"login": "octocat"},
                           "repos": [], "rate": {}, "cached": False,
                           "stale": False}}
        res2 = gf.github_recon("octocat")
        assert res2["ok"] is True and res2["stale"] is True
        assert res2["cached"] is True
    finally:
        gf._fetch_binary = orig


# ---------------------------------------------------------------- launches
def test_ll2_parse_window_sort_cap_tbd_padless():
    raw = json.dumps(LL2_PAGE).encode("utf-8")
    records, points, note = gf.parse_ll2_upcoming(raw, now_ms=_NOW_MS)
    assert note == ""
    # 40-day launch excluded; the rest sorted by net, TBD flagged
    assert [r["name"] for r in records] == [
        "TBD launch", "Soon launch", "Padless launch"]
    assert records[0]["tbd"] is True
    assert records[1]["tbd"] is False
    # pad-less launch is records-only (detail-only, no invented coords)
    assert records[2]["lat"] is None and records[2]["lon"] is None
    assert len(points) == 2
    assert points[0]["lb"] == "TBD launch"
    assert "TBD" in points[0]["ex"]
    assert points[0]["t"] == records[0]["net_ms"]
    # cap: 25 in-window launches -> 20
    many = {"results": [
        {"name": "L%02d" % i,
         "net": _iso(_NOW_MS + (i + 1) * 3600 * 1000),
         "status": {"name": "Go"},
         "launch_service_provider": {"name": "P"},
         "pad": {"name": "Pad", "latitude": 10.0, "longitude": 20.0}}
        for i in range(25)]}
    recs, _pts, _n = gf.parse_ll2_upcoming(
        json.dumps(many).encode("utf-8"), now_ms=_NOW_MS)
    assert len(recs) == 20


def test_launches_layer_and_route():
    _reset_launches()
    fake = _FakeBinary([("ll.thespacedevs.com", 200, {},
                         json.dumps(LL2_PAGE).encode("utf-8"))])
    orig_bin, orig_save = gf._fetch_binary, gf._save_snapshot
    gf._fetch_binary = fake
    gf._save_snapshot = lambda: None
    try:
        payload = gf.get_layer("launches")
        assert payload["layer"] == "launches"
        assert payload["state"] == "live"
        assert payload["count_total"] == 3
        assert len(payload["points"]) == 2
        route = gf.get_launches()
        assert route["ok"] is True and route["count"] == 3
        assert route["attribution"].startswith("Launch data:")
        assert route["launches"][0]["name"] == "TBD launch"
        # offline path: transport failure with no snapshot
        _reset_launches()
        gf._fetch_binary = _FakeBinary([])
        gf._cache.pop("launches", None)
        try:
            gf.get_layer("launches")
        except Exception:
            pass
        route2 = gf.get_launches()
        assert route2["count"] == 0
        assert route2["state"] in ("offline", "stale")
    finally:
        gf._fetch_binary = orig_bin
        gf._save_snapshot = orig_save
        _reset_launches()


def test_launches_registered():
    spec = gf.SUBLAYERS["launches"]
    assert spec["group"] == "space"
    assert spec["family"] == "launches"
    assert spec["ttl"] == 3600
    assert "launches" in gf._FAMILY_FETCH


# ------------------------------------------------------------------- NEWS
def test_rss_parse_verbatim_stripped_null_time():
    items = gf.parse_rss_items(RSS_BBC)
    assert [i["title"] for i in items] == [
        "First headline", "Bold headline", "Dateless headline"]
    assert items[0]["link"] == "https://www.bbc.com/news/articles/1"
    assert items[0]["tms"] is not None
    assert items[2]["tms"] is None, "no pubDate -> null, never invented"
    try:
        gf.parse_rss_items(RSS_BAD)
        raise AssertionError("truncated XML must raise")
    except Exception:
        pass


def test_news_live_only_dead_hidden_all_offline():
    _reset_news()
    routes = _FakeBinary([
        ("feeds.bbci.co.uk", 200, {}, RSS_BBC),
        ("aljazeera.com", 200, {}, RSS_AJE),
        ("rss.dw.com", 200, {}, RSS_BAD),
        ("feeds.npr.org", 500, {}, b""),
        ("france24.com", 200, {}, RSS_AJE),
    ])
    orig = gf._fetch_binary
    gf._fetch_binary = routes
    try:
        res = gf.get_news()
        # DW unparseable + NPR HTTP 500 are hidden; BBC/AJE/F24 live
        assert res["live_count"] == 3
        assert res["total_count"] == 5
        assert res["all_offline"] is False
        by_outlet = {}
        for it in res["items"]:
            by_outlet.setdefault(it["outlet_id"], []).append(it)
        assert set(by_outlet) == {"bbc", "aljazeera", "france24"}
        assert by_outlet["bbc"][0]["descriptor"] == \
            "British public broadcaster"
        assert by_outlet["aljazeera"][0]["descriptor"] == \
            "Qatari state-funded broadcaster"
        # newest first, null-time last (BBC dateless is last overall)
        tms = [it["tms"] for it in res["items"]]
        assert tms[:-1] == sorted(
            [t for t in tms[:-1] if t is not None], reverse=True)
        assert res["items"][-1]["tms"] is None
        assert res["items"][-1]["title"] == "Dateless headline"
        # updated_at is the newest SUCCESSFUL fetch, never a failure
        assert res["updated_at"] is not None
        # all dead -> honest empty, never 'no news'
        _reset_news()
        gf._fetch_binary = _FakeBinary([])
        res2 = gf.get_news()
        assert res2["items"] == []
        assert res2["live_count"] == 0
        assert res2["all_offline"] is True
    finally:
        gf._fetch_binary = orig
        _reset_news()


def test_news_outlets_declared_hosts_only():
    declared = {"feeds.bbci.co.uk", "www.aljazeera.com", "rss.dw.com",
                "feeds.npr.org", "www.france24.com"}
    assert {o["host"] for o in gf._NEWS_OUTLETS} == declared
    assert gf._GH_HOST == "api.github.com"
    assert gf._LL2_HOST == "ll.thespacedevs.com"
    assert len(gf._NEWS_OUTLETS) == 5, "NHK dropped at build (404 paths)"


# ------------------------------------------------------------------ panel
def test_recon_panel_markers():
    assert 'data-gt="tools"' in HTML
    assert 'id="gl-recon"' in HTML
    assert ".gl-recon{" in HTML
    assert "function glReconToggle" in HTML
    assert "function glReconSubmit" in HTML
    assert "function glReconRender" in HTML
    assert "glApi('/api/osint/globe/github?u=' + encodeURIComponent(q))" in HTML
    assert "function glFetchNews" in HTML
    assert "function glFetchLaunches" in HTML
    assert "function glRocketGo" in HTML
    assert "data-arocket" in HTML
    assert "['ALL', 'QUAKE', 'WARN', 'FEEDS', 'NEWS', 'BREAKING']" in HTML
    assert "glAlertsBuild(_gl.data, _gl.meta, _gl.news)" in HTML


def test_i18n_extra13_complete():
    m = re.search(r"const I18N_EXTRA13 = (\{.*?\});\n", HTML, re.S)
    assert m, "I18N_EXTRA13 missing"
    table = json.loads(m.group(1))
    langs = ["id", "es", "fr", "de", "pt", "ru", "ja", "ko", "zh", "ar", "hi"]
    keys = ["Tools", "GitHub Recon", "GitHub username", "Look up",
            "Public repos", "Followers", "Created", "Repositories",
            "No description", "User not found", "Invalid username",
            "GitHub offline", "GitHub rate limit exhausted", "ROCKET",
            "Launch data offline", "NEWS", "LIVE NEWS FEEDS",
            "Open source", "All news sources offline", "Time unknown"]
    assert sorted(table) == sorted(langs)
    for lang in langs:
        assert sorted(table[lang]) == sorted(keys), lang
        assert all(table[lang][k] for k in keys), lang
    # Hindi values are fresh Devanagari, never the mojibake form
    assert "\ufffd" not in json.dumps(table["hi"])
    assert re.search(r"[\u0900-\u097F]", table["hi"]["Time unknown"])


def test_alerts_news_node_harness():
    js = _pure_js() + """
const assert = require('assert');
const NOW = 1790000000000, H = 3600000;
const data = {
  quakes: { points: [{ la: 0, lo: 0, lb: 'M6.5', ex: 'q', mag: 6.5, t: NOW - H }] },
  severe: { points: [] },
  incidents: { points: [] },
  gdelt_events: { items: [] },
};
const meta = {
  quakes: { state: 'live', updated_at: Math.floor(NOW / 1000) - 90, ttl_s: 120 },
  severe: { state: 'offline', updated_at: null, ttl_s: 1800 },
  incidents: { state: 'offline', updated_at: null, ttl_s: 1800 },
  gdelt_events: { state: 'offline', updated_at: null, ttl_s: 1800 },
};
// no-news call keeps the exact v1.16.0 contract
const old = glAlertsBuild(data, meta);
assert.deepStrictEqual(old.counts, { ALL: 1, QUAKE: 1, WARN: 0, FEEDS: 0, BREAKING: 1 });
assert.strictEqual(old.sourcesLive, 1);
assert.strictEqual(old.sourcesTotal, 3);
assert.deepStrictEqual(old.offline, ['NASA EONET', 'GDELT']);
// NEWS merge: verbatim titles, descriptors, link, noTime flag
const news = {
  items: [
    { title: 'Quake news headline', outlet: 'BBC World', outlet_id: 'bbc',
      descriptor: 'British public broadcaster', link: 'https://example.com/1', tms: NOW - 1000 },
    { title: 'Dateless headline', outlet: 'DW', outlet_id: 'dw',
      descriptor: 'German public broadcaster', link: 'https://example.com/2', tms: null },
  ],
  live_count: 3, total_count: 5,
  outlets: [
    { name: 'BBC World', live: true }, { name: 'DW', live: true },
    { name: 'NPR', live: true }, { name: 'Al Jazeera English', live: false },
    { name: 'France 24', live: false },
  ],
  updated_at: Math.floor(NOW / 1000) - 30,
};
const built = glAlertsBuild(data, meta, news);
assert.strictEqual(built.items.length, 3);
assert.deepStrictEqual(built.counts, { ALL: 3, QUAKE: 1, WARN: 0, FEEDS: 0, NEWS: 2, BREAKING: 1 });
const n0 = built.items[1];
assert.strictEqual(n0.cat, 'NEWS');
assert.strictEqual(n0.title, 'Quake news headline');
assert.strictEqual(n0.detail, 'BBC World \\u2014 British public broadcaster');
assert.strictEqual(n0.link, 'https://example.com/1');
assert.strictEqual(n0.la, null);
assert.strictEqual(n0.noTime, false);
assert.strictEqual(built.items[2].noTime, true);
// K8 combined sources: 1 family live + 3 outlets live = 4/8
assert.strictEqual(built.sourcesLive, 4);
assert.strictEqual(built.sourcesTotal, 8);
assert.deepStrictEqual(built.offline, ['NASA EONET', 'GDELT', 'Al Jazeera English', 'France 24']);
assert.strictEqual(built.famLive, 1);
assert.strictEqual(built.newsLive, 3);
assert.strictEqual(built.newsTotal, 5);
assert.strictEqual(built.updatedAt, Math.floor(NOW / 1000) - 30);
// NEWS never breaks, BREAKING unchanged with NEWS present
assert.strictEqual(glAlertIsBreaking({ cat: 'NEWS', mag: 9.9 }, NOW), false);
assert.strictEqual(glAlertsApplyFilter(built, 'BREAKING', '', NOW).total, 1);
assert.strictEqual(glAlertsApplyFilter(built, 'NEWS', '', NOW).total, 2);
assert.strictEqual(glAlertsApplyFilter(built, 'ALL', 'dateless', NOW).total, 1);
console.log('news-harness-ok');
"""
    out = _run_node(js)
    assert "news-harness-ok" in out


def test_recon_block_parses():
    a = HTML.index("/* v1.19.0 recon-start */")
    b = HTML.index("/* v1.19.0 recon-end */") + len("/* v1.19.0 recon-end */")
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(HTML[a:b])
        path = f.name
    try:
        r = subprocess.run(["node", "--check", path],
                           capture_output=True, text=True, timeout=60)
    finally:
        os.unlink(path)
    assert r.returncode == 0, r.stderr
