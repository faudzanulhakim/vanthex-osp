#!/usr/bin/env python3
"""
Server target UJI yang sengaja rentan (fixture) — hanya untuk test lokal engine.
BUKAN bagian dari toolkit produksi. Jalankan: python3 fixture_vuln_server.py [port]
Mode SPA (soft-404 di semua path): FIXTURE_MODE=spa python3 fixture_vuln_server.py [port]
"""
import base64
import hashlib
import html
import hmac
import json
import os
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

MODE = os.environ.get("FIXTURE_MODE", "vuln")


def weak_jwt():
    def b64(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    h, p = b64({"alg": "HS256", "typ": "JWT"}), b64({"user": "ade", "admin": True})
    sig = base64.urlsafe_b64encode(
        hmac.new(b"secret", f"{h}.{p}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{h}.{p}.{sig}"


HOME = """<!DOCTYPE html><html><head><title>FixtureMart Home</title>
<meta name="generator" content="WordPress 5.8">
<script src="/static/app.js"></script>
<script src="/static/jquery-1.11.1.min.js"></script>
<script src="/static/js/bundle.js"></script>
<script src="https://cdn.example.com/lib-2.0.js"></script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-FIXTURE123"></script>
<script src="https://www.google.com/recaptcha/api.js"></script>
<script src="https://js.stripe.com/v3"></script>
<script src="https://app.midtrans.com/snap/snap.js"></script></head><body>
<h1>FixtureMart</h1>
<a href="/search?q=sepatu">Search</a>
<a href="/item?id=1">Item</a>
<a href="/view?file=home">View</a>
<a href="/ping?host=127.0.0.1">Ping</a>
<a href="/redirect?url=/item">Go</a>
<a href="/home?PHPSESSID=abcdef1234567890">My Account</a>
<a href="/cached">Cached Page</a>
<a href="/forgot">Forgot Password</a>
<a href="/fixation">Alt Login</a>
<a href="/union?id=1">Union Demo</a>
<a href="/report.php">Report</a>
<a href="/fetch?url=https://example.org/">Fetch URL</a>
<a href="/echohdr?to=home">Echo Header</a>
<a href="/admin/login">Admin</a>
<a href="/safe/search?q=aman">Safe Search</a>
<a href="/safe/item?id=2">Safe Item</a>
<a href="/safe/redirect?next=/item">Safe Redirect</a>
<a href="/safe/fetch?url=https://example.com/">Safe Fetch</a>
<a href="/safe/slow?x=1">Safe Slow</a>
<a href="/vuln/search_bool?q=sepatu">Boolean Search</a>
<a href="/api/acct/profile/1001">My Profile (API)</a>
<a href="/safe/acct/profile/1001">My Profile (Safe API)</a>
<a href="/trap/vendors">Vendor Article</a>
<a href="/trap/databases">Database Article</a>
<a href="/trap/echo_raw_json?msg=halo">JSON Echo</a>
<a href="/guestbook">Guestbook</a>
<a href="/safe/guestbook">Safe Guestbook</a>
<form action="/login" method="POST">
  <input name="username"><input name="password" type="password">
  <button>Login</button></form>
<form action="/upload" method="POST" enctype="multipart/form-data">
  <input type="file" name="file"><button>Upload</button></form>
<form action="/xml" method="POST">
  <input name="data"><button>Send XML</button></form>
<div id="gx" data-key="38ff6460ffff59ffff06ff6bffff3644" data-iv="8722e2ea52fd44f599d35d1534485d8e"></div>
<footer>Powered by nginx — blog kami membahas akamai, barracuda, dan f5 secara umum.</footer>
<input type="hidden" name="__VIEWSTATE" value="/wEPDwUJNDYxNjExMDAxZGQyb3JkZXItdGVzdA==">
<input type="hidden" name="state" value='O:8:"stdClass":0:{}'>
<script>var demoToken = "__JWT__";</script>
<script>var W = new WebSocket("__WSURL__");</script>
</body></html>""".replace("__JWT__", weak_jwt())

STATE = {"cache_host": None}
UPLOADS = {}
GUESTBOOK = []
GUESTBOOK_SAFE = []
PP_STORE = {"theme": "dark", "lang": "en"}
PP_SAFE_STORE = {"theme": "dark", "lang": "en"}
USERS = [
    {"id": 1, "name": "Ade Pratama", "email": "ade.pratama@example.com",
     "password_hash": "$2b$12$fixturehashade0000000000000000000000000000000000001"},
    {"id": 2, "name": "Sari Wulandari", "email": "sari.wulandari@example.com",
     "password_hash": "$2b$12$fixturehashsari000000000000000000000000000000000002"},
]


class H(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.49"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _waf_block(self):
        """Mode waf: blokir payload khas serangan ala Cloudflare (kontrol positif
        untuk c_waf_detection) — di mode lain tidak aktif."""
        if MODE != "waf":
            return False
        raw = self.path.lower()
        # Pola serangan SPESIFIK saja (WAF sungguhan tidak memblokir tanda baca
        # tunggal) — kontrol jinak scanner, termasuk %27 tunggal, harus LOLOS
        # agar uji perilaku WAF v3.5 dapat membedakan blocking diferensial.
        if any(t in raw for t in ("%3cscript", "union", "../", "..%2f", "%0d%0a",
                                  "or%20%271%27%3d%271", "alert%28", "sleep%28")):
            self._send(403, "<html><title>Attention Required! | Cloudflare</title>"
                            "Sorry, you have been blocked</html>")
            return True
        return False

    def _send(self, code, body, ctype="text/html", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if MODE == "waf":
            self.send_header("Server", "cloudflare")
            self.send_header("CF-RAY", "8f00abcd-SIN")
        origin = self.headers.get("Origin")
        if origin:  # CORS buruk yang disengaja: echo origin + credentials
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _all_params(self):
        p = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(p.query).items()}
        return p.path, q

    def _maybe_sleep(self, values):
        blob = " ".join(values).lower()
        if "sleep(3)" in blob or "sleep 3" in blob or "pg_sleep" in blob or "waitfor delay" in blob:
            time.sleep(3)

    def do_GET(self):
        if self._waf_block():
            return
        path, q = self._all_params()
        self._maybe_sleep(list(q.values()))
        if MODE == "spa" and path not in ("/",):
            self._send(200, HOME)  # catch-all 200: jebakan soft-404 untuk scanner
            return
        if path == "/ws" and (self.headers.get("Upgrade", "").lower() == "websocket"):
            # Kontrol positif WebSocket: handshake valid, Origin apa pun diterima.
            import base64 as _b, hashlib as _hl
            key = self.headers.get("Sec-WebSocket-Key", "")
            acc = _b.b64encode(_hl.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", acc)
            self.end_headers()
            return
        if path == "/":
            body = HOME.replace("__WSURL__",
                                f"ws://{self.headers.get('Host', '')}/ws")
            xfh = self.headers.get("X-Forwarded-Host")
            if xfh:  # host-header reflection (kontrol positif c_host_header)
                body = body + f"<div>Reset password: http://{xfh}/reset</div>"
            self._send(200, body, extra=[("Set-Cookie", "session=abc123; Path=/")])
        elif path == "/wp-json/":
            self._send(200, json.dumps({"name": "FixtureMart",
                                        "generator": "WordPress 5.8",
                                        "namespaces": ["wp/v2", "oembed/1.0"]}),
                       "application/json")
        elif path in ("/api/me", "/api/profile"):
            # /api/me RENTAN (alg=none diterima + secret lemah) — kontrol positif
            # JWT forgery. /api/profile KETAT (secret kuat) — kontrol negatif.
            import base64 as _b, hmac as _hm, hashlib as _hl
            auth = self.headers.get("Authorization", "")
            tok = auth[7:] if auth.startswith("Bearer ") else ""

            def _dec(seg):
                return json.loads(_b.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))

            try:
                seg = tok.split(".")
                hdr, pay = _dec(seg[0]), _dec(seg[1])
            except Exception:
                seg, hdr, pay = [], {}, {}
            ok = False
            secret = b"secret" if path == "/api/me" else b"fixture-strong-secret-9f2c71"
            if path == "/api/me" and hdr.get("kid"):
                # Simulasi kid injection (kontrol positif v1.10): kid dipakai
                # sebagai path file kunci / fragmen SQL tanpa sanitasi.
                _kid = str(hdr["kid"])
                if "dev/null" in _kid:
                    secret = b""
                elif "UNION SELECT" in _kid.upper():
                    _m = re.search(r"SELECT\s+'([^']*)'", _kid, re.I)
                    if _m:
                        secret = _m.group(1).encode()
            if hdr.get("alg") == "none" and path == "/api/me":
                ok = True
            elif hdr.get("alg") == "HS256" and len(seg) == 3:
                exp = _b.urlsafe_b64encode(_hm.new(
                    secret, f"{seg[0]}.{seg[1]}".encode(), _hl.sha256
                ).digest()).rstrip(b"=").decode()
                ok = _hm.compare_digest(exp, seg[2])
            if ok:
                self._send(200, json.dumps({"user": pay.get("user"),
                                            "admin": pay.get("admin", False)}),
                           "application/json")
            else:
                self._send(401, json.dumps({"error": "unauthorized"}),
                           "application/json")
        elif path in ("/guestbook", "/safe/guestbook"):
            _safe = path.startswith("/safe")
            _lst = GUESTBOOK_SAFE if _safe else GUESTBOOK
            def _e(t):
                return html.escape(str(t)) if _safe else str(t)
            _entries = "".join(
                f"<div class='entry'><b>{_e(e['name'])}</b>: {_e(e['comment'])}</div>"
                for e in _lst)
            self._send(200, ("<html><title>Guestbook</title>"
                             f"<form method='POST' action='{path}'>"
                             "<input name='name'><input name='comment'>"
                             "<button>Sign</button></form>"
                             f"{_entries}</html>"))
        elif path in ("/api/json/config", "/safe/json/config"):
            _d = PP_SAFE_STORE if path.startswith("/safe") else PP_STORE
            self._send(200, json.dumps(_d), "application/json")
        elif path == "/fetch":
            import urllib.request as _u
            target = q.get("url", "")
            if target.startswith("http://169.254.169.254"):
                # Simulasi endpoint metadata cloud (kontrol positif SSRF metadata).
                self._send(200, "<html><title>Fetch Result</title>"
                                "ami-id: ami-0fixture123\ninstance-id: i-0fixture456\n"
                                "instance-type: t3.micro</html>")
                return
            try:
                with _u.urlopen(target, timeout=3) as resp:
                    data = resp.read(4096).decode("utf-8", "replace")
                self._send(200, f"<html><title>Fetch Result</title>{data}</html>")
            except Exception as e:
                self._send(200, f"<html>fetch gagal: {type(e).__name__}</html>")
        elif path == "/echohdr":
            # Kontrol positif CRLF: nilai param masuk header respons mentah.
            self._send(200, "<html>echo</html>", extra=[("X-Echo-Loc", q.get("to", ""))])
        elif path == "/admin/login":
            self._send(200, """<html><title>Admin Login</title><form method="POST" action="/admin/login">
                <input name="user"><input name="pass" type="password"><button>Sign in</button></form></html>""")
        elif path == "/safe/search":
            import html as _h
            self._send(200, f"<html><title>Safe Search</title>Results for {_h.escape(q.get('q', ''))} — aman dan ter-escape.</html>")
        elif path == "/safe/item":
            self._send(200, "<html>Safe Item #2 Fixture Shoes - data statis dari query berparameter (prepared statement).</html>")
        elif path == "/safe/redirect":
            nxt = q.get("next", "/")
            if nxt.startswith("/") and not nxt.startswith("//"):
                self._send(302, "", extra=[("Location", nxt)])
            else:
                self._send(400, "redirect eksternal ditolak")
        elif path == "/safe/slow":
            # Jebakan timing: endpoint jinak yang UNIFORM lambat. Baseline
            # sama lambatnya, jadi klaim SQLi time-based di sini = FP.
            time.sleep(1.6)
            self._send(200, "<html>Safe Slow — halaman berat yang sah (render 1.6 detik untuk semua request).</html>")
        elif path == "/vuln/search_bool":
            # Positif SQLi boolean-blind MURNI: tanpa error SQL sama sekali.
            term = q.get("q", "")
            low = term.lower()
            is_false = re.search(r"(and|or)\s+('?1'?='?2|1=2|2<1)", low)
            if is_false:
                self._send(200, "<html>no results</html>")
            else:
                self._send(200, "<html><title>BoolSearch</title>Daftar produk lengkap: sepatu lari, sepatu bola, sepatu gunung, sandal, topi — teks hasil yang panjang dan stabil untuk perbandingan boolean.</html>")
        elif path == "/login":
            # Simulasi konsol Jenkins (v1.1): header produk + judul sign-in
            # + footer versi — tiga artefak khas Jenkins asli.
            self._send(200, "<html><head><title>Sign in [Jenkins]</title></head>"
                            "<body><h1>Sign in to Jenkins</h1>"
                            "<footer>Jenkins ver. 2.319.1</footer></body></html>",
                       extra=[("X-Jenkins", "2.319.1")])
        elif path == "/gitlab":
            self._send(200, "<html><head><title>Sign in \u00b7 GitLab</title></head>"
                            "<body><div class=\"gitlab-logo\"></div>"
                            "<p>GitLab Community Edition</p></body></html>")
        elif path == "/-/health":
            self._send(200, "GitLab OK", ctype="text/plain")
        elif path == "/v2/":
            self._send(401, "{}", ctype="application/json",
                       extra=[("Docker-Distribution-API-Version",
                               "registry/2.8.3")])
        elif path == "/version":
            self._send(200, "{\"major\":\"1\",\"minor\":\"28\","
                            "\"gitVersion\":\"v1.28.2\"}",
                       ctype="application/json")
        elif path == "/api/system/status":
            self._send(200, "{\"Version\":\"2.19.4\",\"InstanceID\":\"fx1\"}",
                       ctype="application/json")
        elif path == "/openapi.json":
            self._send(200, "{\"openapi\":\"3.1.0\",\"info\":{\"title\":"
                            "\"Fixture API\",\"version\":\"1.4.0\"},\"paths\":{}}",
                       ctype="application/json")
        elif path == "/trap/vendors":
            # Jebakan vendor (regresi v3.4.1): token hex mengandung 'f5' +
            # nama-nama vendor WAF sebagai TEKS artikel biasa.
            self._send(200, "<html><title>Artikel</title>Perbandingan WAF populer: "
                            "cloudflare, akamai, imperva, sucuri, barracuda, dan f5 big-ip dibahas sebagai produk. "
                            "Artikel ini juga menyebut Jenkins, GitLab, Docker, Kubernetes, "
                            "Portainer, dan phpMyAdmin sebagai nama produk dalam teks biasa. "
                            "Token sesi: 38ff6460ffff59ffff06ff6bffff3644f5f5f5aabbcc. "
                            "Checksum f5f5f5f5ffff.</html>",
                       extra=[("Set-Cookie", "tracker=9f5abcffff0000f5; Path=/")])
        elif path == "/trap/databases":
            # Jebakan database (regresi v3.8): nama DB sebagai topik artikel,
            # BUKAN frasa error — tidak boleh jadi deteksi Database.
            self._send(200, "<html><title>Artikel DB</title>Banyak tim memakai MySQL, "
                            "PostgreSQL, MongoDB, Oracle, atau SQLite untuk proyek mereka. "
                            "Artikel ini membahas cara memilih database yang tepat.</html>")
        elif path == "/trap/echo_raw_json":
            # Jebakan konteks: refleksi ke JSON ter-escape dengan content-type
            # JSON — bukan konteks HTML, tidak boleh jadi XSS.
            self._send(200, json.dumps({"echo": q.get("msg", "")}),
                       "application/json")
        elif path == "/safe/fetch":
            host = urlparse(q.get("url", "")).hostname
            if host == "example.com":
                self._send(200, "<html>Safe fetch OK (allowlist)</html>")
            else:
                self._send(403, "host tidak di allowlist")
        elif path == "/cached":
            host_used = STATE["cache_host"] or self.headers.get("Host", "")
            if self.headers.get("X-Forwarded-Host"):
                STATE["cache_host"] = self.headers["X-Forwarded-Host"]
                host_used = STATE["cache_host"]
            self._send(200, f"<html>Cached page — host used: {host_used}</html>")
        elif path == "/forgot":
            self._send(200, """<html><title>Forgot</title><form action="/forgot" method="POST">
                <input name="email"><button>Kirim tautan reset</button></form></html>""")
        elif path == "/fixation":
            self._send(200, """<html><title>Alt Login</title><form action="/fixation-login" method="POST">
                <input name="username"><input name="password" type="password"><button>Login</button></form></html>""",
                       extra=[("Set-Cookie", "session=FIXED123; Path=/")])
        elif path == "/union":
            i = q.get("id", "1")
            if "UNION SELECT" in i.upper():
                ncols = i.upper().count("NULL")
                if ncols == 3:
                    self._send(200, "<html>Union Item #1 Fixture Shoes - full detail page with long stable description text for boolean comparison purposes only.</html>")
                else:
                    self._send(500, "You have an error in your SQL syntax near 'UNION' at line 1 (MySQL)")
            else:
                self._send(200, "<html>Union Item #1 Fixture Shoes - full detail page with long stable description text for boolean comparison purposes only.</html>")
        elif path == "/report.php":
            self._send(200, "<html>Quarterly report page</html>")
        elif path == "/report.php.bak":
            self._send(200, "<?php $db_pass = 'fixture-secret'; function report(){ $q = \"SELECT * FROM sales\"; } ?>", "text/plain")
        elif path == "/wp-content/plugins/wp-file-manager/readme.txt":
            self._send(200, "=== WP File Manager ===\nStable tag: 6.8\n", "text/plain")
        elif path == "/static/app.js":
            self._send(200, 'fetch("/api/users"); fetch("/api/orders"); fetch("/api/search"); fetch("/api/json/echo"); fetch("/safe/json/echo"); fetch("/api/json/search"); fetch("/api/json/config"); fetch("/safe/json/config");'
                            'var q=new URLSearchParams(location.search);'
                            'document.getElementById("x").innerHTML=q.get("q");'
                            'document.write(location.hash);', "application/javascript")
        elif path == "/static/app.js.map":
            self._send(200, json.dumps({"version": 3, "sources": ["app.ts"],
                                        "sourcesContent": ["const SECRET_SOURCE = 1;"],
                                        "mappings": "AAAA"}), "application/json")
        elif path == "/static/jquery-1.11.1.min.js":
            self._send(200, "/*! jQuery v1.11.1 fixture stub */", "application/javascript")
        elif path == "/manager/html":
            auth = self.headers.get("Authorization", "")
            import base64 as _b
            expect = "Basic " + _b.b64encode(b"tomcat:tomcat").decode()
            if auth == expect:
                self._send(200, "<html>Tomcat Manager Console</html>")
            else:
                self._send(401, "401 Unauthorized", extra=[("WWW-Authenticate", 'Basic realm="Tomcat Manager"')])
        elif path.startswith("/uploads/") and len(path) > len("/uploads/"):
            name = path.rsplit("/", 1)[-1]
            if name in UPLOADS:
                self._send(200, UPLOADS[name], "text/plain")
            else:
                self._send(404, "no such upload")
        elif path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin-secret\n", "text/plain")
        elif path == "/search":
            term = q.get("q", "")
            self._send(200, f"<html><title>Search</title>Results for {term} — 3 items found sepatu lari, sepatu bola, sepatu gunung dengan deskripsi panjang yang stabil.</html>")
        elif path == "/item":
            i = q.get("id", "1")
            if "\x00" in i:
                self._send(500, "Traceback (most recent call last):\n  File \"/srv/app/item.py\", line 42, in <module>\nValueError: embedded null byte")
            elif re.search(r"\{\{(\d+)\*(\d+)\}\}", i) or re.search(r"\$\{(\d+)\*(\d+)\}", i):
                m = re.search(r"(\d+)\*(\d+)", i)
                self._send(200, f"<html>computed value: {int(m.group(1))*int(m.group(2))}</html>")
            elif "'" in i and "''" not in i:
                self._send(500, "You have an error in your SQL syntax near '' at line 1 (MySQL)")
            elif "AND 1=2" in i.upper():
                self._send(200, "<html>no results</html>")
            else:
                dm = re.match(r"\s*(\d+)", i)
                n = int(dm.group(1)) if dm else 1
                u = USERS[(n - 1) % len(USERS)]
                self._send(200, f"<html>Item #{n} milik {u['name']} — kontak {u['email']} — "
                                f"alamat pengiriman pelanggan nomor {n} jalan fixture raya blok {n} — "
                                f"telepon 0800-000-{n:04d} — status pesanan pelanggan {n} selesai.</html>")
        elif path == "/view":
            f = q.get("file", "")
            if "etc/passwd" in f or "passwd" in f:
                self._send(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
            elif "win.ini" in f:
                self._send(200, "[extensions]\nfor16=1")
            else:
                self._send(200, f"<html>viewing file {f}</html>")
        elif path == "/ping":
            host = q.get("host", "")
            mc = re.search(r"\$\(\((\d+)\*(\d+)\)\)", host)
            m = re.search(r"echo\s+(\S+)", host)
            if mc:
                self._send(200, f"<html>ping result: {int(mc.group(1)) * int(mc.group(2))}</html>")
            elif m:
                self._send(200, f"<html>ping result: {m.group(1)}</html>")
            else:
                self._send(200, f"<html>ping {host}: 1 packets transmitted, 1 received</html>")
        elif path == "/static/js/bundle.js":
            self._send(200, 'a.src=t.head.appendChild(r),o=!n&&[],i=N.exec(e);var u="/static/media/logo.svg";', "application/javascript")
        elif path.startswith("/static/"):
            # SPA catch-all trap: semua path /static/* menjawab shell yang sama
            # dan MEMANTULKAN request URI mentah (URL-encoded) — jebakan FP v3.2.0.
            self._send(200, f"<html><title>SPA</title><!-- uri: {self.path} -->app shell</html>")
        elif path == "/redirect":
            self._send(302, "", extra=[("Location", q.get("url", "/"))])
        elif path == "/.env":
            self._send(200, "APP_KEY=base64:xyz\nDB_PASSWORD=fixture-secret\nDB_HOST=127.0.0.1\n", "text/plain")
        elif path == "/backup.sql":
            self._send(200, "-- dump\nCREATE TABLE users (id INT, name TEXT);\nINSERT INTO users VALUES (1,'ade');", "text/plain")
        elif path == "/.git/config":
            self._send(200, "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@example.com:x.git", "text/plain")
        elif path == "/uploads/":
            self._send(200, "<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1><a href='/'>Parent Directory</a> file1.txt</body></html>")
        elif path == "/api/users":
            self._send(200, json.dumps(USERS), "application/json")
        elif path == "/api/orders":
            self._send(200, json.dumps([{"order": 1001, "total": 50000}]), "application/json")
        elif path == "/api/search":
            self._send(200, "[]", "application/json")
        elif path == "/trap/ratelimit":
            self._send(429, "rate limited", extra=[("Retry-After", "1")])
        elif path.startswith("/api/acct/profile/") or path.startswith("/safe/acct/profile/"):
            profiles = {1001: {"id": 1001, "name": "Alice Fixture", "email": "alice@fixture.test"},
                        1002: {"id": 1002, "name": "Bob Fixture", "email": "bob@fixture.test"}}
            tokens = {"Bearer fixture-alice-token": 1001, "Bearer fixture-bob-token": 1002}
            me = tokens.get(self.headers.get("Authorization", ""))
            try:
                want = int(path.rsplit("/", 1)[1])
            except Exception:
                want = -1
            if me is None:
                self._send(401, json.dumps({"error": "unauthorized"}), "application/json")
            elif path.startswith("/safe/") and me != want:
                self._send(403, json.dumps({"error": "forbidden"}), "application/json")
            elif want in profiles:
                # versi /api/ RENTAN BOLA: token valid mana pun membaca profil siapa pun
                self._send(200, json.dumps(profiles[want]), "application/json")
            else:
                self._send(404, json.dumps({"error": "no such user"}), "application/json")
        elif path == "/openapi.json":
            self._send(200, json.dumps({"openapi": "3.0.0", "paths": {"/users": {}}}), "application/json")
        elif path == "/graphql":
            self._send(200, "<html>GraphQL endpoint</html>")
        elif path == "/login":
            self._send(200, '<html><form method="POST"><input name="username"><input type="password" name="password"></form>sign in</html>')
        else:
            self._send(404, "<html><title>404</title>Not Found - FixtureMart custom error page qwerty"
                            "<pre>Warning: mysqli_query(): You have an error in your SQL syntax; "
                            "check the manual that corresponds to your MySQL server version for the "
                            "right syntax to use near '' at line 1 in /var/www/html/index.php on line 42</pre></html>")

    def do_POST(self):
        if self._waf_block():
            return
        if MODE == "spa":
            self._send(200, HOME)  # SPA statis: POST pun dilayani shell
            return
        path, _ = self._all_params()
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw_bytes = self.rfile.read(length) if length else b""
        raw = raw_bytes.decode("utf-8", "replace")
        self._maybe_sleep([raw])
        if path == "/forgot":
            host_used = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "")
            self._send(200, f"<html>Tautan reset dikirim: http://{host_used}/reset?token=abc123</html>")
        elif path == "/fixation-login":
            self._send(200, "<html>welcome alt user (session tidak dirotasi)</html>")
        elif path == "/graphql" and raw.lstrip().startswith("["):
            # Simulasi batching GraphQL (kontrol positif v1.10).
            self._send(200, json.dumps([{"data": {"__typename": "Query"}},
                                        {"data": {"__typename": "Query"}}]),
                       "application/json")
        elif path == "/graphql" and "vxbadfield" in raw:
            # Simulasi field suggestion GraphQL (kontrol positif v1.10).
            self._send(200, json.dumps({"errors": [{"message":
                "Cannot query field 'vxbadfield' on type 'Query'. "
                "Did you mean 'user'?"}]}), "application/json")
        elif path == "/graphql" and "__typename" in raw:
            # Simulasi endpoint GraphQL (v1.1): menjawab introspeksi minimal.
            self._send(200, "{\"data\":{\"__typename\":\"Query\"}}",
                       ctype="application/json")
        elif path == "/xml" and "<!ENTITY" in raw and "&ptk;" in raw and "file:///etc/passwd" in raw:
            # Simulasi XXE HANYA di endpoint /xml (parser XML naif). Dulu branch
            # ini catch-all semua path — begitu fixture punya endpoint patched
            # (/safe/*), mereka ikut tampak rentan XXE (artefak fixture, bukan
            # bug engine). Battery v3.4 yang menangkapnya.
            self._send(200, "root:x:0:0:root:/root:/bin/bash\n")
        elif path == "/api/search":
            if "$gt" in raw or "$ne" in raw:
                self._send(200, json.dumps(USERS), "application/json")
            else:
                self._send(200, "[]", "application/json")
        elif path == "/upload":
            m = re.search(r'filename="([^"]+)"', raw)
            parts = raw.split("\r\n\r\n", 1)
            content = parts[1].split("\r\n--")[0] if len(parts) > 1 else ""
            if m:
                UPLOADS[m.group(1)] = content
                self._send(200, f"<html>uploaded {m.group(1)} ok</html>")
            else:
                self._send(400, "no file")
        elif path == "/graphql":
            if "__schema" in raw:
                self._send(200, json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}}),
                           "application/json")
            else:
                self._send(200, json.dumps({"data": {}}), "application/json")
        elif path == "/xml" and "<!ENTITY" in raw and "SYSTEM" in raw:
            # XXE OOB: parser naif mengambil entitas eksternal HTTP (canary)
            m = re.search(r'SYSTEM\s+"(http://[^"]+)"', raw)
            if m:
                try:
                    import urllib.request as _u
                    _u.urlopen(m.group(1), timeout=3).read()
                except Exception:
                    pass
            self._send(200, "<html>xml parsed</html>")
        elif path in ("/guestbook", "/safe/guestbook"):
            _form = {k: v[0] for k, v in parse_qs(raw).items()}
            _lst = GUESTBOOK_SAFE if path.startswith("/safe") else GUESTBOOK
            _lst.append({"name": _form.get("name", ""),
                         "comment": _form.get("comment", "")})
            self._send(200, "<html>signed</html>")
        elif path in ("/api/json/config", "/safe/json/config"):
            _safe = path.startswith("/safe")
            _store = PP_SAFE_STORE if _safe else PP_STORE
            try:
                _posted = json.loads(raw or "{}")
            except Exception:
                _posted = {}
            def _merge(dst, src):
                for k, v in src.items():
                    if _safe and k in ("__proto__", "constructor", "prototype"):
                        continue
                    if k == "__proto__" and isinstance(v, dict):
                        _merge(dst, v)  # polusi: isi __proto__ bocor ke atas
                    elif isinstance(v, dict) and isinstance(dst.get(k), dict):
                        _merge(dst[k], v)
                    else:
                        dst[k] = v
            if isinstance(_posted, dict):
                _merge(_store, _posted)
            self._send(200, json.dumps(_store), "application/json")
        elif path == "/api/json/echo":
            try:
                posted = json.loads(raw or "{}")
            except Exception:
                posted = {}
            prof = {"id": 7, "name": "Fixture User", "email": "user@fixture.test"}
            if isinstance(posted, dict):
                prof.update(posted)   # RENTAN mass assignment: semua field diterima & dipantulkan
            self._send(200, json.dumps(prof), "application/json")
        elif path == "/safe/json/echo":
            try:
                posted = json.loads(raw or "{}")
            except Exception:
                posted = {}
            prof = {"id": 7, "name": "Fixture User", "email": "user@fixture.test"}
            if isinstance(posted, dict):
                for k in ("id", "q", "name"):
                    if k in posted:
                        prof[k] = posted[k]
            self._send(200, json.dumps(prof), "application/json")
        elif path == "/api/json/search":
            try:
                posted = json.loads(raw or "{}")
            except Exception:
                posted = {}
            def _walk(v, depth):
                if isinstance(v, dict):
                    return any(_walk(x, depth + 1) for x in v.values())
                if isinstance(v, list):
                    return any(_walk(x, depth + 1) for x in v)
                return isinstance(v, str) and "' OR " in v and depth >= 2
            if _walk(posted, 0):
                # nilai BERSARANG dikonkatenasi ke query (rentan); nilai datar di-parameterize (aman)
                self._send(500, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")
            else:
                self._send(200, json.dumps({"results": []}), "application/json")
        elif path == "/login":
            self._send(200, "<html>welcome</html>", extra=[("Set-Cookie", "session=xyz; Path=/")])
        else:
            self._send(404, "not found")

    do_OPTIONS = lambda self: self._send(200, "", extra=[("Allow", "GET, POST, PUT, DELETE, TRACE, OPTIONS")])
    def do_TRACE(self):
        body = "TRACE / HTTP/1.1\r\n" + "\r\n".join(f"{k}: {v}" for k, v in self.headers.items())
        self._send(200, body, "message/http")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
