"""v1.2.1 artifact-UI port (docker wiring) — 2026-10-26.

ADE binding decisions 2026-10-26 09:50 WIB (do not re-litigate):
K1 / serves the artifact UI; K2 /classic REMOVED (404s); K3 client
4 h idle only, no server idle added; K4 committed prebuilt bundle;
K5 minimal docker shell (root div + SafeArea CSS + own QueryClient);
K6 ticker derived from the /api/osint/globe/markets payload, flagged
derived/assumed; K7 savenvdschedule -> POST /api/settings NVD fields;
K8 fingerprint = direct NDJSON route, no /actions handler; K9 envelope
stays {"data": ...}; K10 chunked-upload staging stays container-local
uploads_apk/.staging; K11 hashed immutable assets + no-store index;
K12 admin-only UI with 403 behavior as-is; K13 classic-only cells
(Findings Distribution, Unique Targets card) accepted as absent;
K14 /webui legacy stays untouched at /webui; K15 feed keys stay
required in .env, NEVER bundled; K16 bundle keeps the 1.2.1 label;
K17 bundle checks belong to the sibling export agent; K18 one-release
cutover of / (no preview route).

Scope of THIS file: the service tree only. The bundle directory
artifact-ui/ holds the REAL artifact bundle since the 2026-10-26
integration swap (see the bundle test below) — asset refs rewritten
from ./assets/ to /artifact-assets/assets/ per design §4 and the
artifact_file() shape (rel "assets/name.ext"; mechanical prefix
rewrite only; PNG bytes identical to the export). These tests assert
ROUTE MECHANICS (status, headers, CSP, auth gates, handler->route
mapping) plus real-bundle markers, never placeholder content.

Hermetic: reads files from this tree only, except handler tests which
monkeypatch actions.call_service (no live service, no DB, no creds).
"""

import hashlib
import os
import re
import subprocess
import sys

import pytest

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TREE)

import actions  # noqa: E402
import app2  # noqa: E402

MD5_OSINT = "65ec21c31b4aad76aa304fcb411388ae"

CSP_CURRENT = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
               "style-src 'self' 'unsafe-inline'; img-src 'self' data: "
               "https://server.arcgisonline.com https://tilecache.rainviewer.com "
               "https://nowcoast.noaa.gov https://tiles.basemaps.cartocdn.com "
               "https://s3.amazonaws.com; "
               "connect-src 'self' https://api.rainviewer.com "
               "https://basemaps.cartocdn.com https://tiles.basemaps.cartocdn.com "
               "https://tiles-a.basemaps.cartocdn.com https://tiles-b.basemaps.cartocdn.com "
               "https://tiles-c.basemaps.cartocdn.com https://tiles-d.basemaps.cartocdn.com; "
               "frame-src https://www.youtube-nocookie.com; "
               "worker-src 'self' blob:; frame-ancestors 'none'; "
               "object-src 'none'; base-uri 'self'; form-action 'self'")

# The 66 published actions (design §2, authoritative count 66/16).
# Keys are actions.py camelCase; the platform normalizes to lowercase
# and handle_action accepts either casing (see the fallback test).
ACTIONS_47_EXISTING = [
    "getStats", "getEngine", "getScans", "getScanDetail", "getScanDiff",
    "exportScan", "analyzeMobile", "startMobileUpload", "uploadMobileChunk",
    "finishMobileUpload", "cancelMobileUpload", "getSchedules",
    "createSchedule", "deleteSchedule", "toggleSchedule", "getAudit",
    "getUsers", "createUser", "getFindings", "getAssets", "startScan",
    "getJob", "cancelJob", "deleteScan", "setFindingStatus",
    "getReportDocx", "getReportHtml", "getInsights", "updateFinding",
    "setAssetMeta", "deleteAsset", "getMe", "logout", "getSettings",
    "saveSettings", "getTokens", "createToken", "deleteToken",
    "getSuppressions", "addSuppression", "deleteSuppression",
    "getNvdStatus", "syncNvd", "getMetrics", "getSecrets", "createSecret",
    "deleteSecret",
]
ACTIONS_14_GLOBE_NEW = [
    "getGlobeCam", "getGlobeCloudmeta", "getGlobeEntities",
    "getGlobeGithub", "getGlobeIssTelemetry", "getGlobeLaunches",
    "getGlobeLayer", "getGlobeMarkets", "getGlobeNews", "getGlobeRecon",
    "getGlobeRoute", "getGlobeSearch", "getGlobeStatus",
    "getGlobeWindgrid",
]
# 47 + 14 + fingerprint (direct) + ticker (derived) + 2 baseline + 1 NVD
# schedule = 66. No action may be silently missing.
ALL_66 = (ACTIONS_47_EXISTING + ACTIONS_14_GLOBE_NEW
          + ["getGlobeFingerprint", "getGlobeTicker",
             "addSecretBaseline", "removeSecretBaseline",
             "saveNvdSchedule"])


def _read(rel):
    with open(os.path.join(TREE, rel), encoding="utf-8") as fh:
        return fh.read()


def _md5(rel):
    h = hashlib.md5()
    with open(os.path.join(TREE, rel), "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------ 66 mapping

def test_66_action_mapping_none_silently_missing():
    assert len(ALL_66) == 66, len(ALL_66)
    assert len(set(a.lower() for a in ALL_66)) == 66, "duplicate actions"
    app2_src = _read("app2.py")
    lowered = {k.lower(): k for k in actions._ACTIONS}
    for name in ALL_66:
        if name == "getGlobeFingerprint":
            # K8: direct NDJSON route, deliberately NO /actions handler.
            assert name.lower() not in lowered
            assert '/api/osint/globe/fingerprint' in app2_src
            assert '_stream_ndjson' in app2_src
        elif name == "getGlobeTicker":
            # K6: DERIVED from the markets payload, flagged in every
            # response — explicitly listed here with its reason, never
            # silently missing and never a new service route.
            assert name.lower() in lowered
            assert '/api/osint/globe/ticker' not in app2_src
            handler = actions._ACTIONS[lowered[name.lower()]]
            import inspect
            assert "DERIVED" in inspect.getsource(handler)
            assert "derivedAssumed" in inspect.getsource(handler)
        else:
            assert name.lower() in lowered, "unmapped action: %s" % name


def test_handler_count_is_65_plus_direct_fingerprint():
    # 47 existing + 14 globe + ticker + 2 baseline + 1 NVD = 65 handlers;
    # fingerprint is the 66th action via its direct route.
    assert len(actions._ACTIONS) == 65, len(actions._ACTIONS)
    assert "getGlobeFingerprint" not in actions._ACTIONS


def test_lowercase_action_spelling_resolves():
    # The platform normalizes names to lowercase; the bundle's exact
    # casing is verified at integration, so either spelling resolves.
    code, env = actions.handle_action("getglobestatus", {}, 5000)
    # handle_action resolves the handler before calling it; with the
    # service down the handler returns a serviceDown shape, NOT 404.
    assert code == 200
    assert "data" in env


# ------------------------------------------------- handler -> route (double)

class _CallLog:
    def __init__(self):
        self.calls = []

    def __call__(self, port, method, path, body=actions._NO_BODY,
                 binary=False, timeout_ms=None):
        self.calls.append({"port": port, "method": method, "path": path,
                           "body": None if body is actions._NO_BODY else body,
                           "binary": binary})
        return {"down": False, "status": 200,
                "json": {"rows": [{"id": "BTC-USD", "symbol": "BTC-USD",
                                   "name": "Bitcoin", "value": 42,
                                   "change_pct": 1.5, "spark": [1, 2],
                                   "as_of": "2026-10-26", "source": "Coinbase"}],
                         "ok": True},
                "text": "", "base64": "aGVsbG8=",
                "contentType": "image/png", "error": ""}


@pytest.fixture
def logged(monkeypatch):
    log = _CallLog()
    monkeypatch.setattr(actions, "call_service", log)
    return log


HANDLER_ROUTES = [
    ("getGlobeStatus", {}, "GET", "/api/osint/globe/status"),
    ("getGlobeCam", {"cid": "c1", "kind": "img"}, "GET",
     "/api/osint/globe/cam"),
    ("getGlobeLayer", {"layerId": "firms"}, "GET",
     "/api/osint/globe/layer/"),
    ("getGlobeEntities", {"scanId": "s1"}, "GET",
     "/api/osint/globe/entities"),
    ("getGlobeSearch", {"q": "jakarta"}, "GET",
     "/api/osint/globe/search"),
    ("getGlobeRoute", {"profile": "driving", "wp": "1,2;3,4"}, "GET",
     "/api/osint/globe/route"),
    ("getGlobeGithub", {"username": "octocat"}, "GET",
     "/api/osint/globe/github"),
    ("getGlobeLaunches", {}, "GET", "/api/osint/globe/launches"),
    ("getGlobeNews", {}, "GET", "/api/osint/globe/news"),
    ("getGlobeMarkets", {}, "GET", "/api/osint/globe/markets"),
    ("getGlobeCloudmeta", {}, "GET", "/api/osint/globe/cloudmeta"),
    ("getGlobeWindgrid", {"cycle": "2026102600", "fhour": 6}, "GET",
     "/api/osint/globe/windgrid"),
    ("getGlobeIssTelemetry", {}, "GET", "/api/osint/globe/iss_telemetry"),
    ("getGlobeRecon", {"tool": "github", "target": "octocat"}, "GET",
     "/api/osint/globe/recon"),
    ("getGlobeTicker", {"symbol": "BTC-USD"}, "GET",
     "/api/osint/globe/markets"),
    ("addSecretBaseline", {"value": "x" * 16, "kind": "k"}, "POST",
     "/api/settings/baseline"),
    ("removeSecretBaseline", {"hash": "ab" * 32}, "POST",
     "/api/settings/baseline/remove"),
    ("saveNvdSchedule", {"enabled": True, "intervalH": 12}, "POST",
     "/api/settings"),
]


def test_new_handlers_call_their_design_routes(logged):
    for name, args, method, route in HANDLER_ROUTES:
        logged.calls.clear()
        code, env = actions.handle_action(name, args, 5000)
        assert code == 200, (name, code, env)
        assert logged.calls, name
        call = logged.calls[-1]
        assert call["method"] == method, (name, call)
        assert call["path"].startswith(route), (name, call["path"])
        if name == "getGlobeCam":
            assert call["binary"] is True
            assert env["data"]["base64"] == "aGVsbG8="
        if name == "getGlobeTicker":
            # K6 flag: every ticker response says it is derived.
            assert env["data"]["derived"] is True
            assert env["data"]["derivedAssumed"] is True
            assert env["data"]["found"] is True
            assert env["data"]["symbol"] == "BTC-USD"
        if name == "saveNvdSchedule":
            # K7: payload shape confirmed from the app2.py settings
            # handler — NVD fields only, no new endpoint.
            assert call["body"]["nvd_sync_enabled"] is True
            assert call["body"]["nvd_sync_interval_h"] == 12


def test_new_handler_sources_name_their_routes():
    import inspect
    for name, _args, _method, route in HANDLER_ROUTES:
        handler = actions._ACTIONS[name]
        assert route in inspect.getsource(handler), (name, route)


# ------------------------------------------------------------ envelope

def test_envelope_shape_success_unknown_error(monkeypatch):
    logged = _CallLog()
    monkeypatch.setattr(actions, "call_service", logged)
    code, env = actions.handle_action("getGlobeStatus", {}, 5000)
    assert code == 200
    assert set(env) == {"data"}

    code, env = actions.handle_action("noSuchAction", {}, 5000)
    assert code == 404
    assert env == {"error": "unknown action"}

    def _boom(args, port):
        raise RuntimeError("x" * 500)

    monkeypatch.setitem(actions._ACTIONS, "boomTest", _boom)
    code, env = actions.handle_action("boomTest", {}, 5000)
    assert code == 500
    assert len(env["error"]) <= 300


# ------------------------------------------------------------ CSP / routes

def test_csp_byte_identical_on_new_routes():
    src = _read("app2.py")
    out = []
    for m in re.finditer(
            r'self\.send_header\("Content-Security-Policy",\s*(.*?)\)',
            src, re.S):
        parts = re.findall(r'"([^"]*)"', m.group(1))
        out.append("".join(parts))
    # Exactly the two pre-existing occurrences (_send + NDJSON stream);
    # the new / and /artifact-assets/ routes go through _send, so they
    # emit the same value with no new literal and no new host.
    assert len(out) == 2, out
    assert out[0] == CSP_CURRENT
    assert out[1] == CSP_CURRENT


def test_routing_root_artifact_classic_removed_webui_stays():
    src = _read("app2.py")
    # / serves the bundle index, no-store (K11).
    root = src[src.index('if path == "/":'):]
    root = root[:root.index('elif path == "/webui":')]
    assert 'artifact_file("index.html")' in root
    assert '("Cache-Control", "no-store")' in root
    assert 'load_template("app.html")' not in root
    # /classic has NO branch at all: it falls through to the 404 tail.
    assert 'path == "/classic"' not in src
    assert not os.path.exists(os.path.join(TREE, "templates", "app.html"))
    # /webui keeps its admin + ACTIONS_OK gate and index (K14).
    webui = src[src.index('elif path == "/webui":'):]
    webui = webui[:webui.index('elif path.startswith("/artifact-assets/"):')]
    assert 'sess.get("role") == "admin" and ACTIONS_OK' in webui
    assert 'webui_file("index.html")' in webui
    # /artifact-assets/ branch: session-gated (it sits after the
    # _session gate in _do_GET), no '..', hashed-aware cache header.
    assert 'elif path.startswith("/artifact-assets/"):' in src
    assert "_artifact_cache_header" in src


def test_auth_gates_source():
    src = _read("app2.py")
    get = src[src.index("def _do_GET"):]
    # Unauthenticated requests hit the 302-to-/login gate BEFORE any
    # route branch, so / and /artifact-assets/ are gated like /assets/.
    gate = get.index('self._send(302, "", extra=[("Location", "/login")])')
    assert gate < get.index('if path == "/":')
    assert gate < get.index('elif path.startswith("/artifact-assets/"):')
    post = src[src.index('if path == "/actions":'):]
    assert 'sess.get("role") != "admin"' in post[:400]


def test_cache_headers_index_no_store_hashed_immutable():
    assert app2._artifact_cache_header("assets/index-a1b2c3d4.js") == \
        "public, max-age=31536000, immutable"
    assert app2._artifact_cache_header("assets/main.9f2c1a7b.css") == \
        "public, max-age=31536000, immutable"
    assert app2._artifact_cache_header("assets/style.css") == \
        "public, max-age=86400"
    src = _read("app2.py")
    root = src[src.index('if path == "/":'):]
    root = root[:root.index('elif path == "/webui":')]
    assert '("Cache-Control", "no-store")' in root


def test_artifact_file_shape_guards():
    assert app2.artifact_file("../secret") is None
    assert app2.artifact_file("assets/x/y.js") is None
    assert app2.artifact_file("assets/../../etc/passwd") is None
    data, ctype = app2.artifact_file("index.html")
    assert ctype.startswith("text/html")
    assert data


# ------------------------------------------------- real bundle (2026-10-26 swap; JS re-pinned to count-fix bundle 2026-10-26)

def test_real_bundle_present_not_placeholder():
    idx = _read(os.path.join("artifact-ui", "index.html"))
    assert "PLACEHOLDER — replaced by the real artifact bundle at integration" not in idx
    assert "PLACEHOLDER" not in idx
    # Bundle markers: platform root div + rewritten asset refs.
    assert "data-generated-space-root" in idx
    assert "/artifact-assets/assets/index-tzw0cgqg.css" in idx
    assert "/artifact-assets/assets/index-kmc432vj.js" in idx
    assert "./assets/" not in idx
    # All 10 asset files present.
    for name in ("index-tzw0cgqg.css", "index-kmc432vj.js",
                 "vhantex-logo-blue-471smhmh.png",
                 "vhantex-logo-orange-erzkbnsm.png",
                 "vhantex-logo-purple-c5f2jxas.png",
                 "vhantex-logo-red-7dvhn10s.png",
                 "vhantex-shield-blue-ekmz2g8v.png",
                 "vhantex-shield-orange-kb574c4n.png",
                 "vhantex-shield-purple-dzsj55tn.png",
                 "vhantex-shield-red-5a4wgnyq.png"):
        assert os.path.exists(os.path.join("artifact-ui", "assets", name)), name
    # Currency markers in the bundle JS (current artifact, not stale):
    # the 22:21 session-text fix ("4 hours") is in, "30 minutes" is out.
    js = _read(os.path.join("artifact-ui", "assets", "index-kmc432vj.js"))
    assert "4 hours" in js
    assert "Severe risk" in js
    assert "30 minutes" not in js
    assert "/artifact-assets/" in js
    assert "./assets/" not in js


def test_no_secret_or_key_in_bundle():
    idx = _read(os.path.join("artifact-ui", "index.html"))
    for banned in ("PTK_ADMIN_PW", "VANTHEX_FIRMS_MAP_KEY",
                   "VANTHEX_ABUSECH_AUTH_KEY"):
        assert banned not in idx


# ------------------------------------------------------------ untouched pins

def test_untouched_pins_osint_version():
    assert _md5("osint.py") == MD5_OSINT
    src = _read("app2.py")
    assert '"version": "1.2.1"' in src
    assert 'server_version = "VANTHEX/1.2.1"' in src
    assert "VANTHEX Offensive Security Platform v1.2.1" in src


def test_dockerignore_does_not_exclude_artifact_ui():
    txt = _read(".dockerignore")
    assert "artifact-ui" not in txt
    # Dockerfile already ships the new dir via COPY . .
    assert "COPY . ." in _read("Dockerfile")


def test_docs_describe_new_routing():
    for name in ("README.md", "DOCKER.md", "INSTALL.md"):
        txt = _read(name)
        assert "/classic" in txt  # mentioned only as removed/404
        assert "/webui" in txt
        assert "1.2.1" in txt
    # Archive docs are deliberately NOT touched.
    for name in ("ENTERPRISE_NOTES.md", "AUDIT.md", "UPGRADE_NOTES.md"):
        assert os.path.exists(os.path.join(TREE, name))


def test_touched_scripts_parse_under_node():
    # app.html is deleted, so its scripts are gone — do not node-check
    # a deleted file. Touched templates: login.html (unchanged) and
    # the real bundle index (inline theme script). Check whatever inline
    # scripts exist in those two files.
    for rel in ("templates/login.html", "artifact-ui/index.html"):
        src = _read(rel)
        blocks = re.findall(
            r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", src, re.S)
        for i, b in enumerate(blocks):
            p = "/tmp/v121artifact-script-%d.js" % i
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(b)
            r = subprocess.run(["node", "--check", p],
                               capture_output=True, text=True)
            assert r.returncode == 0, (rel, i, r.stderr[:400])


def test_python_parses():
    import py_compile
    for rel in ("app2.py", "actions.py"):
        py_compile.compile(os.path.join(TREE, rel), doraise=True)
