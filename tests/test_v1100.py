# -*- coding: utf-8 -*-
"""v1.10.0 — Framework Version Intelligence (WS1–WS6).

Prinsip yang dijaga test ini (aturan bukti keras):
- Versi HANYA dari bukti tercetak: grup regex versi pada header/footer
  error resmi, isi manifest tervalidasi struktur, endpoint versi resmi.
- Nama framework saja TIDAK PERNAH menghasilkan versi; build ID bukan
  versi; halaman yang sekadar MENYEBUT framework (artikel/dokumentasi)
  tidak menghasilkan deteksi versi; respons catch-all/SPA BUKAN
  manifest.
- Semua keluaran CVE tetap candidate.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import techdb
import vulnscan2 as V


def _get(techs, name):
    return next((t for t in techs if t["name"] == name), None)


# ------------------------------------------------------------ WS1 unit

def test_tomcat_version_from_error_page_footer():
    err = ("<html><head><title>HTTP Status 404 – Not Found</title></head>"
           "<body><h1>HTTP Status 404 – Not Found</h1><hr>"
           "<h3>Apache Tomcat/9.0.85</h3></body></html>")
    techs = techdb.profile([], "", [], err)
    t = _get(techs, "Tomcat")
    assert t and t["version"] == "9.0.85", techs


def test_jetty_version_from_error_page_footer():
    err = ("<html><body><h2>HTTP ERROR 404</h2>"
           "<p>Powered by Jetty:// 9.4.44.v20210927</p></body></html>")
    techs = techdb.profile([], "", [], err)
    t = _get(techs, "Jetty")
    assert t and t["version"] == "9.4.44", techs


def test_java_appserver_headers():
    t = _get(techdb.profile([("Server", "WildFly/27.0.1")], ""), "WildFly")
    assert t and t["version"] == "27.0.1"
    t = _get(techdb.profile([("Server", "GlassFish Server Open Source "
                                         "Edition 5.1.0")], ""), "GlassFish")
    assert t and t["version"] == "5.1.0"
    t = _get(techdb.profile([("Server", "WebSphere Application Server/"
                                         "9.0.5")], ""), "WebSphere")
    assert t and t["version"] == "9.0.5"
    t = _get(techdb.profile([("Server", "JBoss-EAP/7.4.0")], ""), "JBoss EAP")
    assert t and t["version"] == "7.4.0"
    t = _get(techdb.profile([("Server", "undertow/2.2.24")], ""), "Undertow")
    assert t and t["version"] == "2.2.24"


def test_spring_error_json_shape_corroborates_without_version():
    err = ('{"timestamp":"2026-10-22T10:15:30.123+00:00","status":404,'
           '"error":"Not Found","path":"/missing"}')
    techs = techdb.profile([], "", [], err)
    t = _get(techs, "Spring Boot")
    assert t, techs
    assert not t["version"]  # bentuk JSON bukan bukti versi


def test_struts_and_jsf_ecosystem_signals():
    t = _get(techdb.profile([], "", [], "Struts Problem Report: tag "
                                        "'select' — template error"),
             "Apache Struts")
    assert t and not t["version"]
    t = _get(techdb.profile([], '<input name="javax.faces.ViewState" '
                                'value="x">'), "JSF (Jakarta Faces)")
    assert t and not t["version"]


def test_php_framework_error_and_welcome_signals():
    t = _get(techdb.profile([], "", [], "CakePHP 4.4.11 error page"),
             "CakePHP")
    assert t and t["version"] == "4.4.11"
    t = _get(techdb.profile([], "", [], "Yii Framework/2.0.47 exception"),
             "Yii")
    assert t and t["version"] == "2.0.47"
    t = _get(techdb.profile([], "<h1>Welcome to CodeIgniter</h1>"),
             "CodeIgniter")
    assert t and not t["version"]
    t = _get(techdb.profile([], "", [], "Whoops, looks like something "
                                        "went wrong."), "Laravel")
    assert t and not t["version"]


def test_django_debug_version():
    err = ("<title>ImportError at /x</title> Django Version: 4.2.7 "
           "Python Version: 3.11")
    t = _get(techdb.profile([], "", [], err), "Django")
    assert t and t["version"] == "4.2.7"


def test_dotnet_ecosystem_signals():
    t = _get(techdb.profile([("X-AspNetMvc-Version", "5.2.9")], ""),
             "ASP.NET MVC")
    assert t and t["version"] == "5.2.9"
    t = _get(techdb.profile([], '<div id="dnn_ctl00">DotNetNuke</div>'),
             "DNN (DotNetNuke)")
    assert t and not t["version"]
    t = _get(techdb.profile([], '<meta name="generator" '
                                'content="Umbraco">'), "Umbraco")
    assert t and not t["version"]


def test_drupal_version_from_generator():
    t = _get(techdb.profile([("X-Generator", "Drupal 10.2.3 "
                                             "(https://www.drupal.org)")],
                            ""), "Drupal")
    assert t and t["version"] == "10.2.3"


def test_frontend_asset_versions():
    techs = techdb.profile([], "", ["/cdn/angular-1.8.2.min.js",
                                    "/cdn/react@18.2.0/umd/react.min.js",
                                    "/cdn/vue@3.4.21/dist/vue.js"])
    assert _get(techs, "Angular")["version"] == "1.8.2"
    assert _get(techs, "React")["version"] == "18.2.0"
    assert _get(techs, "Vue.js")["version"] == "3.4.21"


def test_genexus_runtime_scripts_corroborate():
    techs = techdb.profile([], "", ["/static/gxgral.js",
                                    "/static/gxcommon.js"])
    assert _get(techs, "GeneXus") is not None
    assert not _get(techs, "GeneXus")["version"]  # tidak ada versi tercetak


# ------------------------------------------------------------ WS3 unit

def test_connect_sid_means_node_ecosystem_not_express():
    # cookie sesi diuji lewat struktur rule terkompilasi techdb:
    # connect.sid -> ekosistem Node.js (bukan klaim Express).
    hits = [e["rules"] for e in techdb._COMPILED
            if e["name"] == "Node.js"]
    assert hits and any(src == "cookie" and pat.search("connect.sid")
                        for rules in hits for src, pat in rules)


def test_nestjs_error_shape_and_express_finalhandler():
    err = '{"statusCode":404,"message":"Cannot GET /missing","error":"Not Found"}'
    t = _get(techdb.profile([], "", [], err), "NestJS")
    assert t and not t["version"]
    err2 = "<pre>Cannot GET /missing</pre>"
    t = _get(techdb.profile([], "", [], err2), "Express (Node.js)")
    assert t and not t["version"]


# ------------------------------------------------------- jebakan (trap)

_ARTICLE = """<!DOCTYPE html><html><head><title>Comparing servers</title>
</head><body><article>
<h1>Apache Tomcat 9.0.85 vs Jetty 9.4.44</h1>
<p>Our benchmarks ran Spring Boot 2.6.5 on Tomcat and also mention
Laravel 11, Django 4.2, Express 4.19.2 and Next.js 14.2.24 in passing.
GlassFish 5.1.0 and WildFly 27 are discussed too.</p>
</article></body></html>"""


def test_article_mentions_yield_no_versions():
    """Halaman yang sekadar MENYEBUT nama+versi framework di prosa
    tidak boleh menghasilkan deteksi versi apa pun (jebakan battery)."""
    techs = techdb.profile([], _ARTICLE, [], _ARTICLE)
    versioned = {t["name"]: t["version"] for t in techs if t["version"]}
    assert versioned == {}, versioned
    for name in ("Tomcat", "Jetty", "Spring Boot", "WildFly",
                 "GlassFish"):
        assert _get(techs, name) is None, name


# ------------------------------------------------------------ WS2 unit

_LOCK = {
    "name": "demo", "lockfileVersion": 3,
    "packages": {
        "": {"name": "demo", "version": "1.0.0"},
        "node_modules/express": {"version": "4.19.2"},
        "node_modules/next": {"version": "14.2.24"},
        "node_modules/@nestjs/core": {"version": "10.3.0"},
        "node_modules/left-pad": {"version": "1.3.0"},
    },
}

_COMPOSER_LOCK = {
    "packages": [
        {"name": "laravel/framework", "version": "v11.9.0"},
        {"name": "symfony/console", "version": "v7.0.0"},
        {"name": "acme/unknown", "version": "1.0.0"},
    ],
    "content-hash": "abc",
}


def test_mine_package_lock_exact_versions_known_only():
    mined = dict((n, v) for n, v, _ in
                 V._mine_manifest("/package-lock.json", json.dumps(_LOCK)))
    assert mined == {"Express (Node.js)": "4.19.2", "Next.js": "14.2.24",
                     "NestJS": "10.3.0"}, mined


def test_mine_package_json_ranges_never_claimed():
    body = json.dumps({"name": "x", "dependencies": {
        "express": "^4.18.2", "next": "14.2.24", "vue": "~3.4.0"}})
    mined = dict((n, v) for n, v, _ in
                 V._mine_manifest("/package.json", body))
    assert mined == {"Next.js": "14.2.24"}, mined


def test_mine_composer_lock_strips_v_prefix():
    mined = dict((n, v) for n, v, _ in
                 V._mine_manifest("/composer.lock",
                                  json.dumps(_COMPOSER_LOCK)))
    assert mined == {"Laravel": "11.9.0"}, mined


def test_mine_other_ecosystems():
    gem = ("GEM\n  remote: https://rubygems.org/\n  specs:\n"
           "    rails (7.1.3)\n    rake (13.2.1)\n")
    mined = dict((n, v) for n, v, _ in
                 V._mine_manifest("/Gemfile.lock", gem))
    assert mined == {"Ruby on Rails": "7.1.3"}, mined
    req = "Django==4.2.7\nflask>=3.0\nrequests==2.32.0\n"
    mined = dict((n, v) for n, v, _ in
                 V._mine_manifest("/requirements.txt", req))
    assert mined == {"Django": "4.2.7"}, mined
    pom = ('<project><parent><groupId>org.springframework.boot</groupId>'
           '<artifactId>spring-boot-starter-parent</artifactId>'
           '<version>3.2.4</version></parent></project>')
    mined = dict((n, v) for n, v, _ in V._mine_manifest("/pom.xml", pom))
    assert mined == {"Spring Boot": "3.2.4"}, mined
    gradle = "plugins { id 'org.springframework.boot' version '2.7.18' }"
    mined = dict((n, v) for n, v, _ in
                 V._mine_manifest("/build.gradle", gradle))
    assert mined == {"Spring Boot": "2.7.18"}, mined
    pc = ('<?xml version="1.0"?><packages>'
          '<package id="Microsoft.AspNet.Mvc" version="5.2.9" />'
          '</packages>')
    mined = dict((n, v) for n, v, _ in
                 V._mine_manifest("/packages.config", pc))
    assert mined == {"ASP.NET MVC": "5.2.9"}, mined


def test_mine_rejects_invalid_and_html_bodies():
    assert V._mine_manifest("/package-lock.json", "{not json") == []
    assert V._mine_manifest("/package-lock.json",
                             json.dumps({"packages": {}})) == []
    spa = ("<!DOCTYPE html><html><body>SPA shell</body></html>")
    for p in V.DEP_FEED_PATHS:
        assert V._mine_manifest(p, spa) == [], p
    assert V._mine_manifest("/requirements.txt", spa) == []


# ------------------------------------------------------------ WS4 unit

def _cve_ids(name, ver):
    techs = [{"name": name, "version": ver}]
    hits = V._attach_cves(None, techs)
    return {c["id"] for _, c, _ in hits}


@pytest.mark.parametrize("name,ver,hit,miss", [
    ("Tomcat", "9.0.85", "CVE-2025-24813", None),
    ("Tomcat", "9.0.99", None, "CVE-2025-24813"),
    ("Tomcat", "9.0.30", "CVE-2020-1938", None),
    ("Spring Boot", "2.6.5", "CVE-2022-22965", None),
    ("Spring Boot", "2.6.6", None, "CVE-2022-22965"),
    ("Next.js", "14.2.24", "CVE-2025-29927", None),
    ("Next.js", "14.2.25", None, "CVE-2025-29927"),
    ("Express (Node.js)", "4.19.2", "CVE-2024-43796", None),
    ("Express (Node.js)", "4.20.0", None, "CVE-2024-43796"),
    ("Django", "3.2.3", "CVE-2021-35042", None),
    ("Django", "3.2.4", None, "CVE-2021-35042"),
    ("Jetty", "9.4.40", "CVE-2021-28169", None),
    ("Laravel", "8.4.1", "CVE-2021-3129", None),
    ("Laravel", "8.4.2", None, "CVE-2021-3129"),
    ("Drupal", "7.57", "CVE-2018-7600", None),
    ("Drupal", "7.58", None, "CVE-2018-7600"),
])
def test_ws4_curated_ranges(name, ver, hit, miss):
    ids = _cve_ids(name, ver)
    if hit:
        assert hit in ids, (name, ver, ids)
    if miss:
        assert miss not in ids, (name, ver, ids)


def test_profile_check_counts_after_ws2():
    assert len(V.PROFILES["enterprise-full"]) == 59
    assert len(V.PROFILES["active-deep"]) == 56
    assert "c_dependency_versions" in V.PROFILES["active-standard"]


# ------------------------------------------------------- integrasi (WS1–WS6)

_TOMCAT_404 = ("<html><head><title>HTTP Status 404</title></head><body>"
               "<h1>Whitelabel Error Page</h1>"
               "<p>There was an unexpected error (type=Not Found, "
               "status=404).</p><hr>"
               "<h3>Apache Tomcat/9.0.85</h3></body></html>")

_HOME = """<!DOCTYPE html><html><head><title>Demo</title>
<script src="/_next/static/chunks/main.js"></script>
<script src="/static/gxgral.js"></script></head>
<body><div id="__next"></div>
<script id="__NEXT_DATA__" type="application/json">
{"props":{},"buildId":"bld-xyz-123","nextExport":false}</script>
<p>{"gx ajax_key":"demo"}</p>
<a href="/legacy.jsp">legacy</a>
</body></html>"""


class _App(BaseHTTPRequestHandler):
    mode = "app"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html", extra=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.mode == "spa":
            if self.path == "/actuator/info":
                return self._send(200, json.dumps(
                    {"build": {"version": "9.9.9"}}),
                    "application/json")
            return self._send(200, _HOME)
        p = self.path.split("?")[0]
        if p == "/":
            return self._send(200, _HOME,
                              extra={"X-Powered-By": "Express"})
        if p == "/actuator":
            return self._send(200, json.dumps(
                {"_links": {"self": {"href": "/actuator"},
                            "health": {"href": "/actuator/health"}}}),
                "application/json")
        if p == "/actuator/info":
            return self._send(200, json.dumps(
                {"build": {"version": "1.4.2", "name": "demo"},
                 "git": {"commit": {"id": "abc1234"}}}),
                "application/json")
        if p == "/package-lock.json":
            return self._send(200, json.dumps(_LOCK), "application/json")
        if p == "/composer.lock":
            return self._send(200, json.dumps(_COMPOSER_LOCK),
                              "application/json")
        return self._send(404, _TOMCAT_404)

    do_POST = do_GET


def _serve(mode):
    _App.mode = mode
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


_MINI = ["c_tech_fingerprint", "c_sensitive_files",
         "c_dependency_versions", "c_cve_candidates"]


@pytest.mark.serial
def test_integration_app_fixture():
    srv, port = _serve("app")
    V.PROFILES["v1100-mini"] = list(_MINI)
    try:
        res = V.run_vulnscan(f"http://127.0.0.1:{port}", "v1100-mini",
                             log=[], opts={"timeout": 5,
                                           "max_pages": 5})
    finally:
        V.PROFILES.pop("v1100-mini", None)
        srv.shutdown()
    techs = {t["name"]: t for t in res["tech_profile"]}
    # WS1: versi Tomcat dari footer error page
    assert techs["Tomcat"]["version"] == "9.0.85", techs.keys()
    # WS2: versi dari lockfile tervalidasi (merge + entri baru)
    assert techs["Express (Node.js)"]["version"] == "4.19.2"
    assert techs["Next.js"]["version"] == "14.2.24"
    assert techs["Laravel"]["version"] == "11.9.0"
    assert "depfile" in techs["Next.js"]["sources"]
    assert not any("left-pad" in t["name"] for t in techs.values())
    # WS3/K4: buildId tercatat sebagai identifier, bukan versi
    assert techs["Next.js"].get("build_id") == "bld-xyz-123"
    # GeneXus terdeteksi dari marker aplikasi tergenerate (tanpa versi)
    assert "GeneXus" in techs and not techs["GeneXus"]["version"]
    # WS6: ekstensi .jsp -> ekosistem Java saja
    assert "Java (Servlet)" in techs
    assert not techs["Java (Servlet)"]["version"]
    titles = [f["title"] for f in res["findings"]]
    assert any("Framework version(s) from exposed dependency manifest"
               in t for t in titles), titles
    # WS4: kandidat CVE dari versi hasil tambang + footer
    cands = [f for f in res["findings"]
             if f["confidence"] == "candidate"]
    blob = " | ".join(f["title"] + f.get("description", "")
                       for f in cands)
    assert "CVE-2025-24813" in blob, blob
    assert "CVE-2024-43796" in blob, blob
    assert "CVE-2025-29927" in blob, blob
    # WS5: build aplikasi terlabeli BUKAN versi framework
    info = [f for f in res["findings"]
            if "application build version" in f["title"]]
    assert info and "1.4.2" in info[0]["title"], titles
    assert "NOT a Spring Boot" in info[0]["description"]
    assert techs["Spring Boot"].get("app_build_version") == "1.4.2"


@pytest.mark.serial
def test_integration_spa_catchall_no_manifest_claims():
    """Jebakan catch-all: SPA mengembalikan 200 HTML untuk SEMUA path
    (termasuk /package-lock.json) — tidak boleh ada klaim manifest,
    versi depfile, atau kandidat CVE dari 'manifest' itu. /actuator/
    info ada tetapi /actuator TIDAK terbuka -> WS5 diam (K1)."""
    srv, port = _serve("spa")
    V.PROFILES["v1100-mini"] = list(_MINI)
    try:
        res = V.run_vulnscan(f"http://127.0.0.1:{port}", "v1100-mini",
                             log=[], opts={"timeout": 5,
                                           "max_pages": 5})
    finally:
        V.PROFILES.pop("v1100-mini", None)
        srv.shutdown()
    for t in res["tech_profile"]:
        assert "depfile" not in (t.get("sources") or []), t
        assert t["name"] not in ("Laravel",) or not t["version"], t
    titles = [f["title"] for f in res["findings"]]
    assert not any("dependency manifest" in t for t in titles), titles
    assert not any("application build version" in t for t in titles), \
        titles
    assert not any("CVE-2025-24813" in t for t in titles), titles
