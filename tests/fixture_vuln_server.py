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

# --- v1.4.0 lab assets (WS1/WS2) -------------------------------------
# lab14 mode serves a MINIMAL home (only the lab + a few standard
# endpoints) so the lab parameters are never starved by the crawl /
# param-target budgets of the full fixture surface. The default
# battery surface is unchanged.
LAB14_HOME = """<!DOCTYPE html><html><head><title>Lab14</title></head><body>
<h1>VANTHEX v1.4.0 Lab</h1>
<a href="/search?q=sepatu">Search</a>
<a href="/fetch?url=https://example.org/">Fetch</a>
<a href="/ping?host=127.0.0.1">Ping</a>
<a href="/blind/fetch?url=https://example.org/">Blind Fetch</a>
<a href="/blind/ping?host=127.0.0.1">Blind Ping</a>
<a href="/blind/xss">Blind XSS Board</a>
<a href="/guestbook">Guestbook</a>
<a href="/xsslab/text?q=test">XSS Lab Text</a>
<a href="/xsslab/attr?q=test">XSS Lab Attr</a>
<a href="/xsslab/script?q=test">XSS Lab Script</a>
<a href="/xsslab/encoded?q=test">XSS Lab Encoded</a>
<a href="/xsslab/hidden?q=test">XSS Lab Hidden</a>
<form action="/xml" method="POST"><input name="data"><button>Send XML</button></form>
</body></html>"""
BLIND_XSS_STORE = []


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
<script src="/static/secrets.js"></script>
<script src="/static/clean.js"></script>
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
<a href="/ldap/search?user=admin">Directory Search</a>
<a href="/ldap/search_safe?user=admin">Directory Search (Safe)</a>
<a href="/oauth/authorize?client_id=fixture-client&redirect_uri=http://fixture.local/callback&response_type=code">SSO Sign-In</a>
<a href="/safe/search?q=aman">Safe Search</a>
<a href="/safe/item?id=2">Safe Item</a>
<a href="/safe/redirect?next=/item">Safe Redirect</a>
<a href="/safe/fetch?url=https://example.com/">Safe Fetch</a>
<a href="/safe/slow?x=1">Safe Slow</a>
<a href="/xpath/search?name=Ade">XPath Search</a>
<a href="/xpath/blind?name=Ade">XPath Blind Search</a>
<a href="/safe/xpath/search?name=Ade">Safe XPath Search</a>
<a href="/hidden?ref=home">Hidden Lab</a>
<a href="/vuln/search_bool?q=sepatu">Boolean Search</a>
<a href="/api/acct/profile/1001">My Profile (API)</a>
<a href="/safe/acct/profile/1001">My Profile (Safe API)</a>
<a href="/trap/vendors">Vendor Article</a>
<a href="/trap/databases">Database Article</a>
<a href="/trap/echo_raw_json?msg=halo">JSON Echo</a>
<a href="/guestbook">Guestbook</a>
<a href="/safe/guestbook">Safe Guestbook</a>
<a href="https://partner-example.org/promo" target="_blank">Partner Promo</a>
<a href="https://docs-example.org/help" target="_blank" rel="noopener">Partner Docs</a>
<a href="https://blog-example.org/post" target="_blank" rel="noreferrer">Partner Blog</a>
<a href="/item?id=1" target="_blank">Item In New Tab</a>
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
<script src="/static/app.v2.js"></script>
<script src="/static/config.js"></script>
<script>var demoToken = "__JWT__";</script>
<script>var W = new WebSocket("__WSURL__");</script>
</body></html>""".replace("__JWT__", weak_jwt())

# --- v1.8.0: LDAP directory simulation with a REAL filter evaluator --
# The /ldap/search endpoint embeds the user value into an (uid=...)
# filter WITHOUT escaping and evaluates the resulting filter with the
# recursive-descent parser below — genuine LDAP semantics (presence,
# substring, &, |, !), not literal pattern matching. /ldap/search_safe
# applies RFC 4515 escaping first, like a patched application.
LDAP_DIRECTORY = [
    {"uid": "admin", "cn": "Site Administrator", "mail": "admin@fixture.test"},
    {"uid": "alice", "cn": "Alice Anggraini", "mail": "alice@fixture.test"},
    {"uid": "bob", "cn": "Bob Budiman", "mail": "bob@fixture.test"},
]


class _LdapBadFilter(Exception):
    pass


def _ldap_parse(s, i):
    """Recursive-descent LDAP filter parser (RFC 4515 subset).
    Returns (node, next_i); raises _LdapBadFilter on malformed input."""
    if i >= len(s) or s[i] != "(":
        raise _LdapBadFilter()
    i += 1
    if i < len(s) and s[i] in "&|":
        op = s[i]
        i += 1
        subs = []
        while i < len(s) and s[i] == "(":
            node, i = _ldap_parse(s, i)
            subs.append(node)
        if not subs or i >= len(s) or s[i] != ")":
            raise _LdapBadFilter()
        return (op, subs), i + 1
    if i < len(s) and s[i] == "!":
        node, j = _ldap_parse(s, i + 1)
        if j >= len(s) or s[j] != ")":
            raise _LdapBadFilter()
        return ("!", [node]), j + 1
    m = re.match(r"([A-Za-z][A-Za-z0-9-]*)\s*(=|~=|>=|<=)", s[i:])
    if not m:
        raise _LdapBadFilter()
    attr, oper = m.group(1).lower(), m.group(2)
    i += m.end()
    j = s.find(")", i)
    if j < 0:
        raise _LdapBadFilter()
    return ("item", attr, oper, s[i:j]), j + 1


def _ldap_match(node, entry):
    kind = node[0]
    if kind == "&":
        return all(_ldap_match(n, entry) for n in node[1])
    if kind == "|":
        return any(_ldap_match(n, entry) for n in node[1])
    if kind == "!":
        return not _ldap_match(node[1][0], entry)
    _k, attr, oper, val = node
    actual = entry.get(attr)
    if actual is None:
        return False
    if oper == "=":
        if val == "*":
            return True                      # presence filter
        if "*" in val:                       # substring filter
            pat = "^" + re.escape(val).replace(r"\*", ".*") + "$"
            return re.match(pat, actual, re.I) is not None
        return actual.lower() == val.lower()
    if oper == "~=":
        return actual.lower() == val.lower()
    if oper == ">=":
        return actual.lower() >= val.lower()
    return actual.lower() <= val.lower()


def _ldap_run(raw_filter):
    node, used = _ldap_parse(raw_filter, 0)
    if used != len(raw_filter):
        raise _LdapBadFilter()
    return [e for e in LDAP_DIRECTORY if _ldap_match(node, e)]


def _ldap_escape(value):
    out = []
    for ch in value:
        if ch in "*()\\\x00":
            out.append("\\%02x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def _ldap_page(entries):
    rows = "".join(f"<li>{e['uid']} - {e['cn']} - {e['mail']}</li>"
                   for e in entries)
    return (f"<html><title>Directory Search</title>"
            f"<h1>Directory Search</h1>"
            f"<p>{len(entries)} entries found</p><ul>{rows}</ul></html>")


STATE = {"cache_host": None,
         # v1.6.0 — key live untuk kontrol API-key reuse (harus cocok dgn
         # pattern vk_live_[0-9a-f]{16,} di takeover.py)
         "bundled_key": "vk_live_" + "a3f9c2d17b40e5f8" * 2}

# v1.9.0 — cache CDN simulasi (path -> (status, body))
CDN_CACHE = {}

WEAK_JWT_SECRET = b"supersecret"   # sengaja lemah — ada di wordlist takeover.py


def _make_weak_jwt():
    """Token HS256 role=user dengan secret lemah (fixture v1.6.0)."""
    import base64 as _b
    def _e(b):
        return _b.urlsafe_b64encode(b).rstrip(b"=").decode()
    h = _e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    p = _e(json.dumps({"sub": "admin@fixture.local", "role": "user", "iat": 1730000000},
                      separators=(",", ":")).encode())
    s = _e(hmac.new(WEAK_JWT_SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{s}"


def _verify_weak_jwt(tok):
    """Verifikasi token bearer dgn secret lemah. Returns claims atau None."""
    import base64 as _b
    try:
        h, p, s = tok.split(".")
        expect = _b.urlsafe_b64encode(
            hmac.new(WEAK_JWT_SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        if not hmac.compare_digest(expect, s):
            return None
        pad = "=" * (-len(p) % 4)
        return json.loads(_b.urlsafe_b64decode(p + pad))
    except Exception:
        return None
UPLOADS = {}
GUESTBOOK = []
GUESTBOOK_SAFE = []
PP_STORE = {"theme": "dark", "lang": "en"}
PP_SAFE_STORE = {"theme": "dark", "lang": "en"}
# --- v1.3.4 lab controls ---
import threading as _thr
RACE_VULN_USED = {"used": False}
RACE_SAFE_USED = {"used": False}
RACE_LOCK = _thr.Lock()
SMUGGLE_MARKER = ""
# Publik key PEM untuk uji JWT key-confusion (RS256 -> HS256 pakai publik key).
# Fixture /api/jwt_rs salah memakai publik key sebagai HMAC secret.
JWT_PUB_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/qPXIZBICJ1MaJ7j8u5mW0g1Z\n"
    "zcM0C4Qj3B1+7n4Qk9YhrPjFqYKTaRkYq1VQpR2ObxQ0r9T4m5e8hZCVQKbJYw==\n"
    "-----END PUBLIC KEY-----"
)
USERS = [
    {"id": 1, "name": "Ade Pratama", "email": "ade.pratama@example.com",
     "password_hash": "$2b$12$fixturehashade0000000000000000000000000000000000001"},
    {"id": 2, "name": "Sari Wulandari", "email": "sari.wulandari@example.com",
     "password_hash": "$2b$12$fixturehashsari000000000000000000000000000000000002"},
]

# Priority 1 fixture assets: secrets.js holds fake-but-well-formed keys
# (Tier A) + one high-entropy generic assignment (Tier B). clean.js holds
# ONLY traps — every value in it must produce zero secret findings.
SECRETS_JS = (
    "// FixtureMart frontend configuration (fixture values)\n"
    'var awsAccessKeyId = "AKIA7F3K9Q2W8XZPLM4N";\n'
    'var stripeKey = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";\n'
    'var githubToken = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";\n'
    'const client_secret = "kX9vR2mQ8zLp4wN7sT3yB6cF1hJ5dG0a";\n'
)
CLEAN_JS = (
    "// Clean fixture file: traps only, zero findings expected.\n"
    'var exampleAws = "AKIAIOSFODNN7EXAMPLE";\n'
    'var api_key = "your-api-key-here";\n'
    'var fromEnv = "${process.env.API_KEY}";\n'
    'var testStripe = "sk_test_4eC39HqLyjWDarjtT1zdp7dc";\n'
    'var checksum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";\n'
    'var shortJwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln";\n'
    'const app_secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa";\n'
)
# --- v1.3.0: base64-embedded secret (decoder-layer target) -------------
import base64 as _b64mod
_B64_STRIPE = _b64mod.b64encode(
    b"backup payment key: sk_live_9f8e7d6c5b4a3210fedcba98").decode()
SECRETS_JS += 'var encodedCfg = "' + _B64_STRIPE + '";\n'

# --- v1.3.0: exposed .git with history (loose objects, built in-process)
import hashlib as _hashlib
import zlib as _zlib


def _git_obj(otype, payload):
    store = otype.encode() + b" " + str(len(payload)).encode() + b"\x00" + payload
    return _hashlib.sha1(store).hexdigest(), _zlib.compress(store)


import re as _remod
_AWS_ID_FIXTURE = _remod.search(r"AKIA[0-9A-Z]{16}", SECRETS_JS).group(0)
_GIT_OLD_CFG = (
    "# FixtureMart legacy config (committed with credentials, later rotated)\n"
    "aws_access_key_id = \"" + _AWS_ID_FIXTURE + "\"\n"
    "aws_secret_access_key = \"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0\"\n"
)
_GIT_NEW_CFG = "# FixtureMart config\naws_access_key_id = None  # loaded from env\n"
_b_old_sha, _b_old = _git_obj("blob", _GIT_OLD_CFG.encode())
_b_new_sha, _b_new = _git_obj("blob", _GIT_NEW_CFG.encode())
_t_old_sha, _t_old = _git_obj(
    "tree", b"100644 config.py\x00" + bytes.fromhex(_b_old_sha))
_t_new_sha, _t_new = _git_obj(
    "tree", b"100644 config.py\x00" + bytes.fromhex(_b_new_sha))
_c_old_sha, _c_old = _git_obj(
    "commit",
    ("tree " + _t_old_sha + "\n"
     "author Fixture Dev <dev@fixture.test> 1700000000 +0000\n"
     "committer Fixture Dev <dev@fixture.test> 1700000000 +0000\n\n"
     "initial import (with credentials)\n").encode())
_c_new_sha, _c_new = _git_obj(
    "commit",
    ("tree " + _t_new_sha + "\nparent " + _c_old_sha + "\n"
     "author Fixture Dev <dev@fixture.test> 1700003600 +0000\n"
     "committer Fixture Dev <dev@fixture.test> 1700003600 +0000\n\n"
     "rotate credentials\n").encode())
GIT_OBJECTS = {_b_old_sha: _b_old, _b_new_sha: _b_new,
               _t_old_sha: _t_old, _t_new_sha: _t_new,
               _c_old_sha: _c_old, _c_new_sha: _c_new}
GIT_HEAD_SHA = _c_new_sha
GIT_LOGS_HEAD = (
    "0" * 40 + " " + _c_old_sha + " Fixture Dev <dev@fixture.test> 1700000000 +0000\tcommit (initial): initial import\n"
    + _c_old_sha + " " + _c_new_sha + " Fixture Dev <dev@fixture.test> 1700003600 +0000\tcommit: rotate credentials\n"
)
XPATH_USERS_XML = (
    "<users>"
    "<user><name>Ade Pratama</name><account>ade.pratama</account></user>"
    "<user><name>Sari Wulandari</name><account>sari.wulandari</account></user>"
    "<user><name>Budi Santoso</name><account>budi.santoso</account></user>"
    "</users>"
)


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
            if MODE == "lab14":
                self._send(200, LAB14_HOME,
                           extra=[("Set-Cookie", "session=abc123; Path=/")])
                return
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
        elif path == "/blind/fetch":
            # WS1 lab: QUEUED server-side fetch — returns immediately,
            # fetches the URL after a delay (default 9s) so the callback
            # lands AFTER the check's initial wait: only the runner's
            # grace-window re-poll can catch it.
            import threading as _th
            import urllib.request as _u
            _target = q.get("url", "")
            try:
                _delay = min(20.0, float(q.get("delay", "9")))
            except Exception:
                _delay = 9.0

            def _later(u=_target, d=_delay):
                time.sleep(d)
                try:
                    _u.urlopen(u, timeout=4).read(64)
                except Exception:
                    pass
            if _target.startswith("http"):
                _th.Thread(target=_later, daemon=True).start()
            self._send(200, "<html>queued fetch</html>")
        elif path == "/blind/ping":
            # WS1 lab: simulates a host command that EXECUTES the
            # injected fetcher — a curl/wget URL inside the parameter
            # is actually fetched (command output itself stays blind).
            import urllib.request as _u
            _host = q.get("host", "")
            _m = re.search(r"(?:curl|wget)(?:\s+-\S+)*\s+(https?://\S+)", _host)
            if _m:
                try:
                    _u.urlopen(_m.group(1).rstrip("\"'"), timeout=4).read(64)
                except Exception:
                    pass
            self._send(200, "<html>ping executed</html>")
        elif path == "/blind/xss":
            # WS1 lab: stored board rendered RAW; rendering simulates a
            # victim browser by fetching any http(s) src= beacon found
            # in stored entries (server-side stand-in for the browser
            # loading the planted script/img).
            import urllib.request as _u
            _entries = ""
            for _e in BLIND_XSS_STORE:
                _entries += f"<div class='entry'>{_e}</div>"
                for _u2 in re.findall(r'src="(https?://[^"]+)"', _e):
                    try:
                        _u.urlopen(_u2, timeout=3).read(64)
                    except Exception:
                        pass
            self._send(200, "<html><title>Blind Board</title>"
                            "<form method='POST' action='/blind/xss'>"
                            "<input name='name'><input name='comment'>"
                            "<button>Post</button></form>"
                            f"{_entries}</html>")
        elif path == "/xsslab/text":
            self._send(200, f"<html><title>Lab</title><div>Results: {q.get('q', '')}</div></html>")
        elif path == "/xsslab/attr":
            self._send(200, f"<html><title>Lab</title><div title=\"{q.get('q', '')}\">hover</div></html>")
        elif path == "/xsslab/script":
            self._send(200, f"<html><title>Lab</title><script>var q = \"{q.get('q', '')}\";</script><p>lab</p></html>")
        elif path == "/xsslab/encoded":
            import html as _h
            self._send(200, f"<html><title>Lab</title><div>Results: {_h.escape(q.get('q', ''))}</div></html>")
        elif path == "/xsslab/comment":
            self._send(200, f"<html><title>Lab</title><!-- {q.get('q', '')} --><p>lab</p></html>")
        elif path == "/xsslab/textarea":
            self._send(200, f"<html><title>Lab</title><textarea>{q.get('q', '')}</textarea></html>")
        elif path == "/xsslab/hidden":
            # Attribute-encoded reflection: quotes are encoded, so the
            # value cannot break out of the hidden input — the classic
            # hidden-input inert trap (payload stays data).
            _v = q.get("q", "").replace('"', "&quot;").replace("'", "&#x27;")
            self._send(200, f"<html><title>Lab</title><form><input type='hidden' name='h' value=\"{_v}\"></form></html>")
        elif path == "/xsslab/urlattr":
            self._send(200, f"<html><title>Lab</title><a href=\"https://example.com/search?q={q.get('q', '')}\">go</a></html>")
        elif path == "/xsslab/strip":
            # Sanitizer simulation: script elements and on* handlers are
            # stripped, other markup (incl. the marker element) survives
            # — the K5 inert-guard trap.
            _v = q.get("q", "")
            _v = re.sub(r"<script.*?</script>", "", _v, flags=re.I | re.S)
            _v = re.sub(r"\son\w+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", "", _v, flags=re.I)
            self._send(200, f"<html><title>Lab</title><div>{_v}</div></html>")
        elif path.startswith("/sim/apiprofile/"):
            # WS4 lab: API-style profile JSON (GitHub-shaped) for one
            # known handle, 404 for everything else.
            _h = path[len("/sim/apiprofile/"):]
            if _h == "fixtureuser":
                self._send(200, json.dumps({
                    "login": "fixtureuser", "name": "Fixture User",
                    "twitter_username": "fixturetw",
                    "blog": "https://fixture.dev", "followers": 7,
                    "html_url": "https://api.fixture.test/users/fixtureuser"}),
                    "application/json")
            else:
                self._send(404, json.dumps({"message": "Not Found"}),
                           "application/json")
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
        elif path in ("/xpath/search", "/xpath/blind", "/safe/xpath/search"):
            # Kontrol Priority 1: /xpath/search membangun ekspresi XPath
            # dengan konkatenasi string (RENTAN, error verbose);
            # /xpath/blind sama rentannya tapi error digenerikkan (hanya
            # boolean yang bisa membuktikan); versi /safe melakukan
            # lookup terparameter tanpa membangun query dari input.
            _name = q.get("name", "")
            if path.startswith("/safe"):
                import xml.etree.ElementTree as _ET
                _root = _ET.fromstring(XPATH_USERS_XML)
                _hits = [u.findtext("name") for u in _root.iter("user")
                         if u.findtext("name") == _name]
            else:
                try:
                    from lxml import etree as _LET
                    _doc = _LET.fromstring(XPATH_USERS_XML.encode())
                    _nodes = _doc.xpath(f"//user[name/text()='{_name}']")
                    _hits = [n.findtext("name") for n in _nodes]
                except Exception as _e:
                    if path == "/xpath/blind":
                        self._send(500, "<html><title>Error</title>"
                                        "directory service unavailable</html>")
                    else:
                        self._send(500, "<html><title>Error</title>"
                                        "javax.xml.xpath.XPathExpressionException: "
                                        f"failed to compile XPath expression ({type(_e).__name__})"
                                        " — unterminated quote in expression</html>")
                    return
            if _hits:
                _items = "".join(f"<li>{h}</li>" for h in _hits)
                self._send(200, "<html><title>XPath Directory</title>"
                                f"<h1>Directory results</h1><ul>{_items}</ul>"
                                "<p>Directory listing provided by the legacy XML user "
                                "directory service for internal lookup purposes.</p></html>")
            else:
                self._send(200, "<html><title>XPath Directory</title>no results</html>")
        elif path in ("/hidden", "/safe/hidden"):
            # Kontrol Priority 1: hanya parameter debug & preview yang
            # mengubah respons di /hidden; /safe/hidden mengabaikan semua.
            _extra = ""
            if not path.startswith("/safe"):
                if "debug" in q:
                    _extra += ("<pre>DEBUG MODE enabled\nFixtureMart diagnostics: "
                               "build=fixture-18099, db=fixture.db, threads=4, "
                               "cache=off, verbose logging on, internal admin "
                               "tools linked from the debug console panel.</pre>")
                if "preview" in q:
                    _extra += ("<div class='draft'>DRAFT PREVIEW — unpublished "
                               "campaign banner 'Fixture Sale Draft' with internal "
                               "pricing notes and margin comments visible to "
                               "staff only.</div>")
            self._send(200, "<html><title>Hidden Lab</title>"
                            "<h1>Product listing</h1><p>Fixture shoes, fixture "
                            "bags, fixture hats — stable catalogue text for the "
                            "hidden parameter laboratory page used in engine "
                            f"tests.</p>{_extra}</html>")
        elif path == "/trap/dynamic":
            # Jebakan stabilitas: konten berubah SETIAP request — gerbang
            # stabilitas hidden-params & XPath boolean wajib melewatinya.
            import random as _rnd
            self._send(200, f"<html><title>Dynamic</title>rotating banner "
                            f"#{_rnd.randint(0, 10**9)} served at {time.time()} "
                            "— content rotates every request.</html>")
        elif path == "/vuln/search_bool":
            # Positif SQLi boolean-blind MURNI: tanpa error SQL sama sekali.
            # v1.7.0: evaluator boolean sungguhan (bukan hanya literal
            # 1=2) — kondisi aritmetika angka dinilai seperti backend SQL
            # asli, supaya Arithmetic Proof Battery diuji terhadap
            # semantik yang benar; operator boolean dengan kondisi yang
            # tidak bisa diparse = halaman error generik (500).
            term = q.get("q", "")
            low = term.lower()
            verdict = None
            if re.search(r"\b(and|or)\b", low):
                _cmps = re.findall(
                    r"'?(\d+)'?\s*(=|<|>)\s*'?(\d+)'?", low)
                if _cmps:
                    _a, _op, _b = _cmps[-1]
                    _a, _b = int(_a), int(_b)
                    verdict = ((_a == _b) if _op == "="
                               else (_a < _b) if _op == "<" else (_a > _b))
                else:
                    self._send(500, "<html>error</html>")
                    verdict = "error"
            if verdict == "error":
                pass
            elif verdict is False:
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
        elif path == "/static/app.v2.js":
            # v1.5.0 — bundle SPA v2: endpoint legacy TIDAK ter-link di HTML
            # mana pun, hanya hidup di dalam JS bundle (target bundle-miner).
            self._send(200,
                       'const routes={admin:"/admin/users",export:"/api/legacy/admin-export",'
                       'dead:"/api/legacy/dead-export",ship:"/api/shipments/3"};\n'
                       'fetch("/api/legacy/admin-export").then(r=>r.json());\n'
                       'fetch("/api/legacy/dead-export");\n'
                       'fetch("/api/shipments/3");\n', "application/javascript")
        elif path == "/api/legacy/admin-export":
            # v1.5.0 — kontrol bundle-miner: endpoint legacy hidup & bocor
            # data (tidak ter-link, hanya ada di bundle).
            self._send(200, json.dumps({"rows": [{"user": "ade", "role": "admin",
                                                  "ssn_masked": "***-**-1001"},
                                                 {"user": "sari", "role": "user"}]}),
                       "application/json")
        elif path in ("/api/session/new", "/safe/api/session/new"):
            # v1.5.0 — kontrol entropy analyzer: token sesi PREDIKTABEL
            # (counter berurutan) vs token acak kripto (safe).
            if path.startswith("/safe"):
                import secrets as _sec
                tok = "S-" + _sec.token_hex(16)
            else:
                STATE["sess_n"] = STATE.get("sess_n", 100000) + 1
                tok = f"SESS-{STATE['sess_n']}-FIXEDCHARSET"
            self._send(200, json.dumps({"session": tok}), "application/json",
                       extra=[("Set-Cookie", f"session={tok}; Path=/")])
        elif path == "/admin/users":
            # v1.5.0 — ACL role ber-cookie (aplikasi naif): hanya role=admin.
            role = ""
            for part in (self.headers.get("Cookie") or "").split(";"):
                if part.strip().startswith("role="):
                    role = part.strip()[5:]
            if role == "admin":
                self._send(200, "<html>Admin Users — ade(admin), sari(user)</html>")
            else:
                self._send(403, "<html>Forbidden — admin only</html>")
        elif path == "/admin/export":
            # v1.5.0 — kontrol authz matrix RENTAN: seharusnya admin-only,
            # tapi role=user diterima (verifikasi role di COOKIE, bukan
            # server-side session).
            role = ""
            for part in (self.headers.get("Cookie") or "").split(";"):
                if part.strip().startswith("role="):
                    role = part.strip()[5:]
            if role in ("admin", "user"):
                self._send(200, json.dumps({"export": True,
                                            "rows": 2,
                                            "secret": "customer-PII-rows"}),
                           "application/json")
            else:
                self._send(403, "<html>Forbidden</html>")
        elif path == "/safe/admin/export":
            self._send(403, "<html>Forbidden</html>")
        elif path == "/openapi.json":
            # v1.5.0 — spec diperkaya: path stateful utk fuzzer (harvest ID
            # dari /api/users lalu probe /api/shipments/{sid}).
            self._send(200, json.dumps({
                "openapi": "3.1.0",
                "info": {"title": "Fixture API", "version": "1.4.0"},
                "paths": {
                    "/api/users": {"get": {"responses": {"200": {}}}},
                    "/api/shipments/{sid}": {"get": {
                        "parameters": [{"name": "sid", "in": "path",
                                        "required": True, "schema":
                                        {"type": "integer"}}],
                        "responses": {"200": {}}}},
                }}), "application/json")
        elif path.startswith("/api/shipments/"):
            # v1.5.0 — kontrol openapi stateful: endpoint dari spec TIDAK
            # punya ACL; ID valid 1-9 mengembalikan data (IDOR by spec).
            try:
                sid = int(path.rsplit("/", 1)[-1])
            except Exception:
                sid = -1
            if 1 <= sid <= 9:
                self._send(200, json.dumps({"sid": sid, "dest": "Jakarta",
                                            "value": 150000}), "application/json")
            else:
                self._send(404, "no such shipment")
        elif path.startswith("/safe/api/shipments/"):
            self._send(403, "<html>Forbidden</html>")
        elif path == "/api/session/jwt":
            # v1.6.0 — kontrol JWT takeover: token HS256 dengan SECRET LEMAH
            # ('supersecret' ada di wordlist brute), claim role=user.
            tok = _make_weak_jwt()
            self._send(200, json.dumps({"token": tok}), "application/json")
        elif path == "/admin/me":
            # v1.6.0 — endpoint admin ber-bearer JWT: verifikasi dgn secret
            # lemah yang sama (token tempaan role=admin diterima).
            auth = self.headers.get("Authorization", "")
            tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            claims = _verify_weak_jwt(tok)
            if claims and claims.get("role") == "admin":
                self._send(200, json.dumps({"ok": True, "role": "admin",
                                            "user": claims.get("sub", "admin")}), "application/json")
            else:
                self._send(401, json.dumps({"ok": False, "error": "admin only"}), "application/json")
        elif path == "/safe/admin/me":
            # negatif: verifikasi dengan secret KUAT (token tempaan ditolak)
            auth = self.headers.get("Authorization", "")
            tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            self._send(401, json.dumps({"ok": False, "error": "signature invalid"}), "application/json")
        elif path == "/safe/oauth/authorize":
            # v1.6.0 — negatif token theft: hanya allowlist fixture.local
            redir = str(q.get("redirect_uri", ""))
            if redir.startswith(("http://fixture.local/", "https://fixture.local/")):
                self._send(302, "", "text/html",
                           extra=[("Location", redir + "?code=vhx-ok")])
            else:
                self._send(400, json.dumps({"ok": False,
                                            "error": "redirect_uri tidak di allowlist"}), "application/json")
        elif path == "/profile":
            # v1.6.0 — profil akun (untuk bukti email berubah)
            email = STATE.get("account_email", "admin@fixture.local")
            self._send(200, f"<html>Profil: admin@fixture.local | email: {email}</html>")
        elif path == "/static/config.js":
            # v1.6.0 — API key live tertanam di bundle (divalidasi /api/key/check)
            # v1.9.0 — + kredensial LLM (sk-...) + email admin + IdP hint
            #   (sasaran aisupply & identgraph)
            self._send(200, 'const CONFIG={key:"' + STATE["bundled_key"]
                        + '",env:"production"};\n'
                        'const AI={openai_key:"sk-fixture2026deadbeefcafebabe",'
                        'llm_provider:"openai"};\n'
                        'const IDP={sso:"https://fixture.local/sso/login",'
                        'provider:"auth0",admin:"root.admin@fixture.local"};\n'
                        '// contact dev-ops@fixture.local\n',
                        "application/javascript")
        elif path == "/admin/vault":
            # v1.7.0 — kontrol session replay: token SESS-* dari
            # /api/session/new (diterbitkan TANPA auth) diterima sebagai
            # kredensial halaman terproteksi.
            sess = ""
            for part in (self.headers.get("Cookie") or "").split(";"):
                if part.strip().startswith("session="):
                    sess = part.strip()[8:]
            if sess.startswith("SESS-"):
                self._send(200, "<html>Vault: kunci API produksi, "
                                "backup DB, catatan gaji</html>")
            else:
                self._send(401, "<html>Forbidden — butuh sesi</html>")
        elif path == "/safe/admin/vault":
            self._send(401, "<html>Forbidden</html>")
        elif path == "/admin/panel":
            # v1.7.0 — kontrol shadow admin: 403 langsung, tapi X-Original-URL
            # dipercaya (reverse-proxy misconfiguration klasik).
            xo = self.headers.get("X-Original-URL", "")
            if xo == "/admin/panel":
                self._send(200, "<html>Admin Panel — dashboard internal, "
                                "user management, audit log</html>")
            else:
                self._send(403, "<html>Forbidden — admin only</html>")
        elif path == "/safe/admin/panel":
            self._send(403, "<html>Forbidden</html>")
        elif path == "/blind/sleep":
            # v1.7.0 — kontrol blind timing: nilai dengan 'sleep N' membuat
            # respons lambat (simulasi eksekusi server-side). /safe abaikan.
            import time as _t
            v = str(q.get("host", ""))
            if not path.startswith("/safe") and "sleep" in v.lower():
                _t.sleep(0.32)
            self._send(200, json.dumps({"ok": True, "echo_len": len(v)}),
                       "application/json")
        elif path == "/safe/ws":
            # v1.7.0 — negatif CSWSH: Origin asing ditolak.
            self._send(403, "origin not allowed", "text/plain")
        elif path in ("/internal/netmap", "/safe/internal/netmap"):
            # v1.8.0 — pivot: endpoint netmap internal bocor TANPA auth
            # (topologi + kredensial internal) ; /safe menolak.
            if path.startswith("/safe"):
                self._send(403, json.dumps({"error": "forbidden"}),
                           "application/json")
            else:
                self._send(200, json.dumps({
                    "hosts": [
                        {"ip": "10.0.5.10", "role": "db-postgres"},
                        {"ip": "10.0.5.20", "role": "backup-nas"},
                        {"ip": "10.0.5.30", "role": "domain-controller"}],
                    "credentials": [
                        "postgres://appuser:FixN3t_2024@10.0.5.10:5432/appdb"],
                }), "application/json")
        elif path in ("/cloud/metadata", "/safe/cloud/metadata"):
            # v1.8.0 — IMDSv1: kredensial instance tanpa token IMDSv2;
            # /safe mensimulasikan IMDSv2 (token wajib → 401).
            if path.startswith("/safe"):
                self._send(401, json.dumps(
                    {"error": "IMDSv2 token required"}), "application/json")
            else:
                self._send(200, json.dumps({
                    "AccessKeyId": "AKIAFIXTUREV18X",
                    "SecretAccessKey": "FixCloudS3cret2024",
                    "Token": "FixToken==", "Expiration": "2026-12-31"}))
        elif path == "/cloud/validate":
            # (GET tidak valid) — ditangani do_POST
            self._send(405, "use POST", "text/plain")
        elif path in ("/docker/api", "/safe/docker/api"):
            # v1.8.0 — Docker daemon API exposed tanpa TLS/auth.
            if path.startswith("/safe"):
                self._send(403, "client certificates required", "text/plain")
            else:
                self._send(200, json.dumps({
                    "Version": "24.0.2",
                    "Containers": [
                        {"Image": "app:1.4", "Ports":
                         ["0.0.0.0:5432->5432", "0.0.0.0:6379->6379"]},
                        {"Image": "worker:2.1", "Ports": []}]}))
        elif path in ("/k8s/api", "/safe/k8s/api"):
            # v1.8.0 — Kubernetes API unauthenticated: listing pods +
            # referensi secret terbaca.
            if path.startswith("/safe"):
                self._send(403, json.dumps(
                    {"error": "authentication required"}), "application/json")
            else:
                self._send(200, json.dumps({
                    "kind": "PodList",
                    "items": [
                        {"metadata": {"name": "app-7d", "namespace":
                                      "prod",
                                      "annotations": {"secret-ref":
                                                      "prod/app-db-creds"}}},
                        {"metadata": {"name": "worker-1", "namespace":
                                      "prod"}}]}))
        elif path in ("/mcp/tools", "/safe/mcp/tools"):
            # v1.9.0 — MCP server: listing tool TANPA auth, termasuk
            # tool destruktif; /safe 403.
            if path.startswith("/safe"):
                self._send(403, json.dumps({"error": "unauthorized"}),
                           "application/json")
            else:
                self._send(200, json.dumps({"tools": [
                    {"name": "search_docs",
                     "description": "search internal documents"},
                    {"name": "exec_command",
                     "description": "run arbitrary shell command on host"},
                    {"name": "file_write",
                     "description": "write arbitrary file to disk"},
                    {"name": "db_query",
                     "description": "run SQL on prod database",
                     "token": "mcp-fix-token-2024"}]}))
        elif path in ("/ai/models", "/safe/ai/models"):
            # v1.9.0 — model endpoint (Ollama-style) tanpa auth; /safe 403.
            if path.startswith("/safe"):
                self._send(403, "authentication required", "text/plain")
            else:
                self._send(200, json.dumps({"models": [
                    "llama3:8b", "mistral:7b", "internal-embed-v2"]}))
        elif path == "/cdn/cache":
            # v1.9.0 — CDN cache: mengambil X-Forwarded-Host TERAKHIR
            # (normalisasi salah) lalu MENG-CACHE-nya untuk request
            # berikutnya (cache per-path, TTL simulasi).
            hdrs = self.headers.get_all("X-Forwarded-Host") or []
            host = hdrs[-1].split(",")[-1].strip() if hdrs else \
                "cdn.fixture.local"
            key = "cdn:" + urlparse(self.path).path.split("?")[0]
            if "evil.example" in host:
                CDN_CACHE[key] = (200, "Host: " + host +
                                   "<html>cached page</html>")
            if key in CDN_CACHE:
                self._send(*CDN_CACHE[key], "text/html")
            else:
                self._send(200, "Host: " + host +
                           "<html>origin page</html>", "text/html")
        elif path == "/safe/cdn/cache":
            # v1.9.0 — kontrol cache: host KANONIK selalu, header diabaikan.
            self._send(200, "Host: cdn.fixture.local<html>safe page</html>",
                       "text/html")
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
            _sg = "SG." + "A" * 22 + "." + "B" * 43
            self._send(200, json.dumps({"version": 3, "sources": ["app.ts"],
                                        "sourcesContent": [
                                            "const SECRET_SOURCE = 1;\n"
                                            "const sgKey = \"" + _sg + "\";"],
                                        "mappings": "AAAA"}), "application/json")
        elif path == "/static/jquery-1.11.1.min.js":
            self._send(200, "/*! jQuery v1.11.1 fixture stub */", "application/javascript")
        elif path == "/static/secrets.js":
            self._send(200, SECRETS_JS, "application/javascript")
        elif path == "/static/clean.js":
            self._send(200, CLEAN_JS, "application/javascript")
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
                # v1.8.0: lax static serving — content type follows the
                # file extension, like a naive upload directory config.
                low = name.lower()
                ct = ("text/html" if low.endswith((".html", ".htm")) else
                      "image/jpeg" if low.endswith((".jpg", ".jpeg")) else
                      "image/gif" if low.endswith(".gif") else "text/plain")
                self._send(200, UPLOADS[name], ct)
            else:
                self._send(404, "no such upload")
        elif path in ("/template/render", "/safe/template/render"):
            # v1.4.0 — kontrol SSTI: /template/render RENTAN (jinja2-style:
            # aritmetika ter-evaluasi + objek config bisa diakses).
            # /safe/template/render — template dirender literal (negatif).
            name = q.get("name", "")
            if path.startswith("/safe"):
                self._send(200, f"<html>Hello {name}</html>")
            elif "{{7*'7'}}" in name:
                self._send(200, "<html>Hello 7777777</html>")
            elif "{{7*7}}" in name:
                self._send(200, "<html>Hello 49</html>")
            elif "{{config}}" in name:
                self._send(200, "<html>Hello {'SECRET_KEY': 'fixture-sk-9911',"
                                "'DEBUG': False, 'DATABASE_URI': 'sqlite:///app.db'}</html>")
            else:
                self._send(200, f"<html>Hello {name}</html>")
        elif path == "/profile/view":
            # v1.4.0 — second-order: bio mentah dari /profile/save 'dieksekusi'
            # sebagai query; quote tunggal -> error SQL (kelas second-order).
            u = q.get("user", "ptk")
            bio = STATE.get("profiles", {}).get(u, "")
            if "'" in bio:
                self._send(500, "You have an error in your SQL syntax near bio at line 1 (MySQL)")
            else:
                self._send(200, f"<html>Profil {u}: {bio or '(kosong)'}</html>")
        elif path == "/safe/profile/view":
            self._send(200, "<html>Profil: (kosong)</html>")
        elif path == "/extract":
            # v1.4.0 — kontrol SQLi auto-extract (UNION): jumlah kolom =
            # token NULL + token table_name; information_schema -> nama tabel.
            i = q.get("id", "1")
            up = i.upper()
            n_fields = up.count("NULL") + up.count("TABLE_NAME")
            if "UNION SELECT" in up and "INFORMATION_SCHEMA" in up and n_fields >= 4:
                self._send(200, "<html>Extract: users, orders, secrets, logs</html>")
            elif "UNION SELECT" in up and n_fields >= 4:
                self._send(200, "<html>Extract: vhx-empty-set</html>")
            elif "UNION SELECT" in up:
                self._send(500, "You have an error in your SQL syntax near 'UNION' (MySQL)")
            else:
                self._send(200, "<html>Item #1 Fixture detail halaman stabil untuk baseline.</html>")
        elif path == "/cgi-bin/status":
            # v1.4.0 — kontrol Shellshock: UA berpola bash func dieksekusi.
            ua = self.headers.get("User-Agent", "")
            if ua.startswith("() {") and ":;}" in ua:
                m = re.search(r"echo\s+([A-Za-z0-9\-_]+)", ua)
                self._send(200, f"status: ok\nexec-out: {m.group(1) if m else 'empty'}")
            else:
                self._send(200, "status: ok")
        elif path == "/safe/cgi-bin/status":
            self._send(200, "status: ok")
        elif path == "/cgi-bin/php-cgi":
            # v1.4.0 — kontrol PHP-CGI arg injection (CVE-2012-1823 style).
            qs = self.path.split("?", 1)[1] if "?" in self.path else ""
            if "-d" in qs:
                self._send(200, "<html>PHP Version 5.3.3 — allow_url_include=On (exposed config)</html>")
            else:
                self._send(200, "<html>php-cgi normal</html>")
        elif path == "/safe/cgi-bin/php-cgi":
            self._send(403, "Forbidden")
        elif path == "/spel/eval":
            # v1.4.0 — kontrol Spring SpEL injection.
            expr = q.get("expr", "")
            if path.startswith("/safe"):
                self._send(200, f"<html>echo: {expr}</html>")
            elif "#{7*7}" in expr:
                self._send(200, "<html>eval: 49</html>")
            elif "T(java.lang.Runtime)" in expr:
                self._send(200, "<html>eval: class java.lang.Runtime</html>")
            else:
                self._send(200, f"<html>eval: {expr}</html>")
        elif path == "/safe/spel/eval":
            self._send(200, f"<html>echo: {q.get('expr', '')}</html>")
        elif path in ("/pollute", "/safe/pollute"):
            # v1.4.0 — kontrol prototype pollution -> gadget: query
            # __proto__[...] / JSON __proto__ memodifikasi runtime (rentan);
            # server naif men-echo X-Polluted + gadget gadgetX='exec' aktif.
            _safe = path.startswith("/safe")
            proto_keys = [k for k in q if "__proto__" in k.lower()] if q else []
            polluted = (not _safe) and (bool(proto_keys)
                                        or "__proto__" in self.path.lower())
            if polluted:
                # nilai gadget: dari nilai param __proto__[...] atau fallback
                val = "1"
                for k, v in q.items():
                    if "__proto__" in k.lower():
                        val = str(v) if v else ("gadgetx" if "[" in k else "1")
                        break
                self._send(200, json.dumps({"ok": True, "gadget": "child_process"
                                            if val == "exec" else "set"}),
                           "application/json",
                           extra=[("X-Polluted", val)])
            else:
                self._send(200, json.dumps({"ok": True, "gadget": "none"}), "application/json")
        elif path in ("/h2c", "/safe/h2c"):
            # v1.4.0 — kontrol h2c smuggling: upgrade diterima & body yang
            # berisi request kedua 'dieksekusi' backend (rentan). Safe: tolak.
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw2 = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            upgrade = self.headers.get("Upgrade", "").lower()
            if path == "/h2c" and upgrade == "h2c" and "/admin/internal" in raw2:
                self._send(200, "<html>HTTP/2 stream ok — internal: VHX-INTERNAL-OK</html>")
            elif path == "/h2c" and upgrade == "h2c":
                self._send(200, "<html>HTTP/2 stream ok</html>")
            else:
                self._send(200, "<html>normal response (no upgrade)</html>")
        elif path in ("/admin/profile", "/admin/profile.css"):
            # v1.4.0 — kontrol Web Cache Deception: /admin/profile 403 tanpa
            # sesi; /admin/profile.css dilayani isi privat + cacheable (naif
            # memutus ACL berdasarkan ekstensi statis).
            if path.endswith(".css"):
                self._send(200, "<html>Private: email admin@fixture.local, api_key sk_live_fixture</html>",
                           extra=[("Cache-Control", "public, max-age=3600")])
            else:
                self._send(403, "<html>Forbidden</html>")
        elif path in ("/safe/admin/profile", "/safe/admin/profile.css"):
            self._send(403, "<html>Forbidden</html>")
        elif path == "/vault/":
            self._send(200, "<html><title>Index of /vault/</title>"
                            "<a href=\"/vault/keys.txt\">keys.txt</a></html>")
        elif path == "/vault/keys.txt":
            self._send(200, "backup db password: fixture-vault-pw-777\napi_key = vhx-fixture-key\n",
                       "text/plain")
        elif path == "/wafgate/echo":
            # v1.4.0 — gerbang WAF in-process (independen dari MODE): blokir
            # pola serangan baku; loloskan bentuk termutasi. Untuk c_waf_bypass.
            qlow = (q.get("q", "") or "").lower()
            blocked = ("<script>alert(" in qlow or "union select" in qlow
                       or "../" in qlow)
            if blocked:
                self._send(403, "<html><title>Attention Required! | Cloudflare</title>"
                                "Sorry, you have been blocked</html>")
            else:
                self._send(200, f"<html>echo: {q.get('q', '')}</html>")
        elif path == "/admin/internal":
            self._send(200, "<html>VHX-INTERNAL-OK</html>")
        elif path in ("/api/log", "/safe/api/log"):
            # v1.4.0 — Log4Shell via GET: UA JNDI dieksekusi (versi do_POST
            # menerima body; versi ini menerima header).
            ua = self.headers.get("User-Agent", "")
            if path == "/api/log" and "${jndi:" in ua.lower():
                tok = re.search(r"\$\{jndi:([^}]+)\}", ua)
                self._send(200, json.dumps({"logged": True,
                                            "resolved": f"vhx-dns-hit:{tok.group(1) if tok else '?'}"}),
                           "application/json")
            else:
                self._send(200, "<html>log tersimpan</html>")
        elif path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin-secret\n", "text/plain")
        elif path in ("/admin/status", "/safe/admin/status"):
            # Kontrol positif auth-bypass via header proxy (X-Original-URL).
            # /admin/status — RENTAN: proxy naif, header X-Original-URL
            #   mengelabui ACL (server terlihat manggil /admin/status padahal
            #   path asli dieksekusi). Tanpa header = 403.
            # /safe/admin/status — ketat: selalu 403.
            _safe = path.startswith("/safe")
            if _safe or ("X-Original-URL" not in self.headers
                         and "X-Rewrite-URL" not in self.headers):
                self._send(403, "<html>Forbidden — admin only</html>")
            else:
                self._send(200, "<html>Admin Status — uptime 99.98% — internal build 2026</html>")
        elif path == "/api/jwks":
            self._send(200, json.dumps({"keys": [{"kty": "RSA", "alg": "RS256",
                                                  "n": "qPXIZBICJ1Ma...", "e": "AQAB",
                                                  "pem": JWT_PUB_PEM}]}), "application/json")
        elif path in ("/api/jwt_rs", "/safe/jwt_rs"):
            # /api/jwt_rs — RENTAN key-confusion: verifikasi HS256 dengan
            # publik key PEM sebagai HMAC secret (bukan RS256 verify). Attacker
            # yang tahu publik key (dari /api/jwks) bisa forge token.
            # /safe/jwt_rs — benar: verifikasi RS256 dengan publik key (butuh
            #   private key untuk tanda tangan, tak bisa diforge HS256).
            _safe = path.startswith("/safe")
            import base64 as _bb, hmac as _hh, hashlib as _h2, json as _jj
            auth = self.headers.get("Authorization", "")
            tok = auth[7:] if auth.startswith("Bearer ") else ""
            try:
                seg = tok.split(".")
                hh = _jj.loads(_bb.urlsafe_b64decode(seg[0] + "=" * (-len(seg[0]) % 4)))
                pp = _jj.loads(_bb.urlsafe_b64decode(seg[1] + "=" * (-len(seg[1]) % 4)))
            except Exception:
                hh, pp = {}, {}
            ok = False
            if hh.get("alg") == "HS256" and len(seg) == 3:
                if _safe:
                    # benar: HS256 seharusnya ditolak untuk token RS256
                    ok = False
                else:
                    # salah (rentan): sign dengan publik key sebagai secret
                    exp = _bb.urlsafe_b64encode(_hh.new(
                        JWT_PUB_PEM.encode(), f"{seg[0]}.{seg[1]}".encode(),
                        _h2.sha256).digest()).rstrip(b"=").decode()
                    ok = _hh.compare_digest(exp, seg[2])
            if ok:
                self._send(200, json.dumps({"user": pp.get("user"), "admin": True}),
                           "application/json")
            else:
                self._send(401, "401 Unauthorized")
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
        elif path == "/.git/HEAD":
            self._send(200, "ref: refs/heads/main\n", "text/plain")
        elif path == "/.git/refs/heads/main":
            self._send(200, GIT_HEAD_SHA + "\n", "text/plain")
        elif path == "/.git/logs/HEAD":
            self._send(200, GIT_LOGS_HEAD, "text/plain")
        elif path.startswith("/.git/objects/"):
            _sha = path[len("/.git/objects/"):].replace("/", "")
            if _sha in GIT_OBJECTS:
                self._send(200, GIT_OBJECTS[_sha], "application/octet-stream")
            else:
                self._send(404, "no such object")
        elif path.startswith("/sim/users/"):
            _h = path[len("/sim/users/"):]
            if _h == "fixtureuser":
                self._send(200, "profile:fixtureuser member of FixtureMart dev team")
            else:
                self._send(404, "no such user")
        elif path.startswith("/sim/catchall/"):
            _h = path[len("/sim/catchall/"):]
            self._send(200, f"welcome profile:{_h} — join our community today")
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
        # (openapi.json lama dihapus — di-shadow spec v1.5.0 yang lebih kaya)
        elif path == "/ldap/search":
            # v1.8.0: value embedded UNESCAPED into (uid=...) and the
            # filter genuinely evaluated (see _ldap_run).
            try:
                entries = _ldap_run(f"(uid={q.get('user', '')})")
                self._send(200, _ldap_page(entries))
            except _LdapBadFilter:
                self._send(500, "javax.naming.NamingException: "
                                "[LDAP: error code 87 - Bad search filter]")
        elif path == "/ldap/search_safe":
            # v1.8.0: same directory, RFC 4515 escaping applied (patched).
            try:
                entries = _ldap_run(
                    f"(uid={_ldap_escape(q.get('user', ''))})")
                self._send(200, _ldap_page(entries))
            except _LdapBadFilter:
                self._send(500, "directory error")
        elif path == "/.well-known/openid-configuration":
            # v1.8.0: deliberately risky OIDC configuration (password +
            # implicit grants, token response types, 'none' token auth).
            self._send(200, json.dumps({
                "issuer": "http://fixture.local/",
                "authorization_endpoint":
                    "http://fixture.local/oauth/authorize",
                "token_endpoint": "http://fixture.local/oauth/token",
                "jwks_uri": "http://fixture.local/.well-known/jwks.json",
                "response_types_supported": ["code", "id_token", "token"],
                "grant_types_supported": ["authorization_code", "password",
                                          "implicit", "refresh_token"],
                "token_endpoint_auth_methods_supported":
                    ["none", "client_secret_basic"],
            }), "application/json")
        elif path == "/oauth/authorize":
            # v1.8.0: lax authorization server — redirects to ANY
            # redirect_uri, state echoed but never required.
            ru = q.get("redirect_uri", "")
            if not ru:
                self._send(400, "missing redirect_uri")
            else:
                loc = ru + ("&" if "?" in ru else "?") \
                    + "code=fixture-auth-code"
                if q.get("state"):
                    loc += "&state=" + q["state"]
                self._send(302, "", extra=[("Location", loc)])
        elif path == "/graphql":
            self._send(200, "<html>GraphQL endpoint</html>")
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
        path, q = self._all_params()
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw_bytes = self.rfile.read(length) if length else b""
        raw = raw_bytes.decode("utf-8", "replace")
        self._maybe_sleep([raw])
        if path == "/forgot":
            host_used = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "")
            self._send(200, f"<html>Tautan reset dikirim: http://{host_used}/reset?token=abc123</html>")
        elif path in ("/spray/login", "/safe/spray/login"):
            # v1.4.0 — kontrol password-spray & enum username.
            # /spray/login RENTAN: (1) admin/test menerima "Password1!" tanpa
            # rate-limit (spray); (2) pesan beda utk user sah vs tidak (enum).
            # /safe/spray/login — selalu 401 seragam (negatif).
            _safe = path.startswith("/safe")
            from urllib.parse import parse_qs as _pqs
            _form = _pqs(raw or "")
            _qv = lambda k: (_form.get(k) or [q.get(k, "")])[0]
            u, p = _qv("username"), _qv("password")
            if _safe:
                self._send(401, json.dumps({"error": "kredensial tidak valid"}), "application/json")
            elif p == "Password1!" and u in ("admin", "test"):
                self._send(200, json.dumps({"ok": True, "user": u,
                                            "session": "SESS-vhx-spray"}), "application/json")
            elif u in ("admin", "test"):
                self._send(401, json.dumps({"error": "password salah untuk user '" + u
                                            + "', silakan coba lagi dengan password yang benar"}),
                           "application/json")
            else:
                self._send(401, json.dumps({"error": "user tidak ditemukan"}), "application/json")
        elif path in ("/otp/verify", "/safe/otp/verify"):
            # v1.4.0 — kontrol OTP bypass: /otp/verify RENTAN (null + kode lemah
            # diterima, tanpa rate-limit). /safe/otp/verify selalu menolak.
            _safe = path.startswith("/safe")
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            code = str(j.get("code", j.get("otp", "")))
            ok = (not _safe) and (code == "" or code in ("000000", "123456", "1234"))
            if ok:
                self._send(200, json.dumps({"ok": True, "status": "verified",
                                            "user": j.get("user", "admin")}), "application/json")
            else:
                self._send(401, json.dumps({"ok": False, "error": "kode salah"}), "application/json")
        elif path in ("/reset/request", "/safe/reset/request"):
            # v1.6.0 — kontrol reset-token takeover: /reset/request RENTAN
            # (token dikembalikan DI RESPONS + token prediktabel md5(email)).
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            email = str(j.get("email", ""))
            if path.startswith("/safe") or not email:
                # safe: tidak pernah membocorkan token
                self._send(200, json.dumps({"ok": True,
                                            "message": "tautan dikirim ke email"}), "application/json")
            else:
                tok = hashlib.md5(email.encode()).hexdigest()
                self._send(200, json.dumps({"ok": True, "email": email,
                                            "reset_token": tok}), "application/json")
        elif path in ("/reset/confirm", "/safe/reset/confirm"):
            # v1.6.0 — konfirmasi reset: RENTAN menerima token prediktabel
            # md5(email) dan 'mengganti password'; safe menolak.
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            tok = str(j.get("token", ""))
            if not path.startswith("/safe") and tok and \
                    re.fullmatch(r"[0-9a-f]{32}", tok):
                self._send(200, json.dumps({"ok": True,
                                            "status": "password updated"}), "application/json")
            else:
                self._send(403, json.dumps({"ok": False,
                                            "error": "token tidak valid / kedaluwarsa"}), "application/json")
        elif path in ("/login/limited", "/safe/login/limited"):
            # v1.6.0 — kontrol rate-limit bypass: /login/limited menghitung
            # kegagalan per X-Forwarded-For (client-controlled). /safe
            # menghitung GLOBAL (XFF diabaikan) -> lockout nyata.
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            u, p = str(j.get("user", "")), str(j.get("password", ""))
            xff = self.headers.get("X-Forwarded-For", "conn")
            bucket = "GLOBAL" if path.startswith("/safe") else xff
            STATE.setdefault("login_fails", {})
            STATE["login_fails"][bucket] = STATE["login_fails"].get(bucket, 0)
            if STATE["login_fails"].get(bucket, 0) >= 5:
                self._send(429, json.dumps({"ok": False, "error": "terlalu banyak percobaan",
                                            "retry_after": 60}), "application/json")
            elif u == "admin@fixture.local" and p == "Summer2025!":
                self._send(200, json.dumps({"ok": True, "user": u}), "application/json")
            else:
                STATE["login_fails"][bucket] += 1
                self._send(401, json.dumps({"ok": False, "error": "kredensial salah"}), "application/json")
        elif path in ("/profile/email", "/safe/profile/email"):
            # v1.6.0 — kontrol pre-hijack: /profile/email menerima ganti email
            # TANPA re-auth; /safe menuntut reauth=yes di body.
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            email = str(j.get("email", ""))
            if path.startswith("/safe") and str(j.get("reauth", "")) != "yes":
                self._send(403, json.dumps({"ok": False,
                                            "error": "re-auth dibutuhkan"}), "application/json")
            elif not email or "@" not in email:
                self._send(400, json.dumps({"ok": False, "error": "email tidak valid"}), "application/json")
            else:
                STATE["account_email"] = email
                self._send(200, json.dumps({"ok": True, "email": email}), "application/json")
        elif path == "/api/key/check":
            # v1.6.0 — validasi status API key (read-only): hanya key yang
            # memang tertanam di fixture yang 'aktif'.
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            k = str(j.get("key", ""))
            if k == STATE.get("bundled_key", ""):
                self._send(200, json.dumps({"active": True,
                                            "scope": "payments:write"}), "application/json")
            else:
                self._send(401, json.dumps({"active": False, "error": "key tidak dikenal"}), "application/json")
        elif path == "/safe/api/key/check":
            self._send(401, json.dumps({"active": False, "error": "tidak diizinkan"}), "application/json")
        elif path in ("/ai/validate", "/safe/ai/validate"):
            # v1.9.0 — validasi API key LLM (read-only simulasi models.list)
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            if not path.startswith("/safe") and \
                    j.get("key") == "sk-fixture2026deadbeefcafebabe":
                self._send(200, json.dumps({"active": True,
                                            "models": 3}),
                           "application/json")
            else:
                self._send(403, json.dumps({"active": False}),
                           "application/json")
        elif path in ("/api/llm/chat", "/safe/api/llm/chat"):
            # v1.9.0 — chatbot LLM: VULNERABLE loyal pada prompt injection
            # (mengulang system prompt + marker) ; /safe sanitasi.
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            msg = str(j.get("message", ""))
            low = msg.lower()
            if path.startswith("/safe"):
                # kontrol: model bersih menolak & tidak membocorkan
                self._send(200, json.dumps(
                    {"reply": "Sorry, I can only answer normal questions."}),
                    "application/json")
            elif ("ignore" in low or "system prompt" in low or
                  "sys>" in low or "internal_tool" in low or
                  "you are" in low):
                self._send(200, json.dumps({
                    "reply": "You are FIXTURE-ASSISTANT v1. My system "
                             "prompt: answer only fixture questions, "
                             "never touch internal_tool_exec unless "
                             "instructed. DEBUG-MARKER-7734 injected."}),
                    "application/json")
            else:
                self._send(200, json.dumps({"reply": "4"}), "application/json")
        elif path in ("/cloud/validate", "/safe/cloud/validate"):
            # v1.8.0 — validasi kredensial IMDS (read-only simulasi STS):
            # hanya key fixture yang dianggap aktif.
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            if not path.startswith("/safe") and \
                    j.get("key") == "AKIAFIXTUREV18X":
                self._send(200, json.dumps({"active": True,
                                            "role": "ec2-app-role"}),
                           "application/json")
            else:
                self._send(403, json.dumps({"active": False}),
                           "application/json")
        elif path in ("/api/fuzz", "/safe/api/fuzz"):
            # v1.8.0 — sasaran grammar fuzz: parser RAPUH terhadap
            # mutasi struktur (tipe salah → 500 traceback); /safe
            # mem-validasi dan selalu 200.
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = None
            if path.startswith("/safe"):
                self._send(200, json.dumps({"ok": True, "normalized": True}),
                           "application/json")
            else:
                bad = (not isinstance(j, dict)) or \
                    not isinstance(j.get("id"), int) or \
                    not isinstance(j.get("name"), str) or \
                    not isinstance(j.get("active"), bool) or \
                    not isinstance(j.get("tags"), list)
                if bad:
                    self._send(500, "Traceback (most recent call last):\n"
                               "TypeError: unsupported operand in handler\n"
                               "Internal Server Error", "text/plain")
                else:
                    self._send(200, json.dumps({"ok": True, "echo": j}),
                               "application/json")
        elif path in ("/svc/smtp-login", "/svc/dbadmin", "/svc/panel",
                      "/safe/svc/smtp-login", "/safe/svc/dbadmin",
                      "/safe/svc/panel"):
            # v1.7.0 — kontrol credential reuse: 3 service menerima
            # kredensial web (admin/Password1!); /safe menolak.
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            u, p = str(j.get("user", "")), str(j.get("password", ""))
            if not path.startswith("/safe") and \
                    u == "admin" and p == "Password1!":
                self._send(200, json.dumps({"ok": True,
                                            "service": path.split("/")[2]}),
                           "application/json")
            else:
                self._send(401, json.dumps({"ok": False,
                                            "error": "kredensial ditolak"}), "application/json")
        elif path in ("/deser/java", "/safe/deser/java"):
            # v1.4.0 — kontrol gadget chain Java (CommonsCollections-style):
            # RENTAN menerima gadget ber-marker dan memicu "DNS pingback".
            _safe = path.startswith("/safe")
            if not _safe and ("CommonsCollections" in raw or "ysoserial" in raw):
                self._send(200, json.dumps({"ok": True,
                                            "pingback": "vhx-dns-hit"}), "application/json")
            else:
                self._send(500, "java.lang.ClassNotFoundException: deserialization rejected",
                           "text/plain")
        elif path in ("/deser/php", "/safe/deser/php"):
            # v1.4.0 — kontrol gadget chain PHP (phpggc-style).
            _safe = path.startswith("/safe")
            if not _safe and "O:8:" in raw and ("Gadget" in raw or "RCE" in raw.upper()):
                self._send(200, json.dumps({"ok": True,
                                            "pingback": "vhx-dns-hit-php"}), "application/json")
            else:
                self._send(500, "unserialize(): rejected", "text/plain")
        elif path in ("/profile/save", "/safe/profile/save"):
            # v1.4.0 — kontrol second-order SQLi: bio disimpan mentah (rentan)
            # atau dibersihkan (safe); /profile/view yang 'menjalankan' query.
            u = q.get("user", "ptk")
            bio = raw if "/safe/" in path else raw
            if "/safe/" in path:
                bio = bio.replace("'", "''")
            STATE.setdefault("profiles", {})[u] = bio
            self._send(200, "<html>profil tersimpan</html>")
        elif path == "/api/log":
            # v1.4.0 — kontrol Log4Shell: lookup JNDI dieksekusi dan token OOB
            # 'sampai' (respons memuat resolusi vhx-dns).
            ua = self.headers.get("User-Agent", "")
            if "${jndi:" in ua.lower() or "${jndi:" in raw.lower():
                tok = re.search(r"\$\{jndi:([^}]+)\}", ua + raw)
                self._send(200, json.dumps({"logged": True,
                                            "resolved": f"vhx-dns-hit:{tok.group(1) if tok else '?'}"}),
                           "application/json")
            else:
                self._send(200, "<html>log tersimpan</html>")
        elif path == "/safe/api/log":
            self._send(200, "<html>log tersimpan</html>")
        elif path in ("/h2c", "/safe/h2c"):
            # v1.4.0 — kontrol h2c smuggling via POST: upgrade diterima &
            # body yang berisi request kedua 'dieksekusi' backend (rentan).
            upgrade = self.headers.get("Upgrade", "").lower()
            if path == "/h2c" and upgrade == "h2c" and "/admin/internal" in raw:
                self._send(200, "<html>HTTP/2 stream ok — internal: VHX-INTERNAL-OK</html>")
            elif path == "/h2c" and upgrade == "h2c":
                self._send(200, "<html>HTTP/2 stream ok</html>")
            else:
                self._send(200, "<html>normal response (no upgrade)</html>")
        elif path == "/fixation-login":
            self._send(200, "<html>welcome alt user (session tidak dirotasi)</html>")
        elif path == "/graphql" and raw.lstrip().startswith("["):
            # Simulasi batching GraphQL (kontrol positif v1.10).
            self._send(200, json.dumps([{"data": {"__typename": "Query"}},
                                        {"data": {"__typename": "Query"}}]),
                       "application/json")
        elif path == "/graphql" and len(re.findall(
                r"[A-Za-z_]\w*\s*:\s*__typename", raw)) >= 10:
            # v1.8.0: alias amplification control — every alias of
            # __typename is resolved, no alias/complexity limit at all.
            data = {m: "Query" for m in re.findall(
                r"([A-Za-z_]\w*)\s*:\s*__typename", raw)}
            self._send(200, json.dumps({"data": data}),
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
        elif path == "/blind/xss":
            _form = {k: v[0] for k, v in parse_qs(raw).items()}
            BLIND_XSS_STORE.append(
                f"<b>{_form.get('name', '')}</b>: {_form.get('comment', '')}")
            self._send(200, "<html>posted</html>")
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
        elif path in ("/deser", "/safe/deser"):
            # Kontrol positif deserialization: Python pickle.
            # /deser — vulnerable: pickle.loads() -> __reduce__ -> eval("7*6") -> 42.
            # /safe/deser — patched: hanya terima JSON, reject pickle bytes.
            if path.startswith("/safe") or raw_bytes[:2] not in (b"\x80\x03", b"\x80\x04"):
                try:
                    posted = json.loads(raw or "{}")
                    self._send(200, json.dumps({"deser": "json", "received": posted}),
                               "application/json")
                except Exception:
                    self._send(200, json.dumps({"deser": "unknown"}), "application/json")
            else:
                try:
                    import pickle as _pk
                    result = _pk.loads(raw_bytes)
                    self._send(200, json.dumps({"deser": "pickle", "result": result}),
                               "application/json")
                except Exception as _e:
                    self._send(200, json.dumps({"deser": "pickle-error", "msg": str(_e)}),
                               "application/json")
        elif path in ("/contact", "/safe/contact"):
            # Kontrol positif SMTP header injection:
            # /contact — vulnerable: email reflect ke raw RFC header (CRLF tidak distrip).
            # /safe/contact — patched: strip CRLF sebelum dipakai.
            _safe = path.startswith("/safe")
            try:
                _form = {k: v[0] for k, v in parse_qs(raw).items()}
            except Exception:
                _form = {}
            _email_raw = _form.get("email", "")
            _email = re.sub(r"[\r\n]", "", _email_raw) if _safe else _email_raw
            try:
                import email.utils as _eu
                parsed = _eu.formataddr(("Recipient", _email))
            except Exception:
                parsed = _email
            raw_hdr = (f"MAIL FROM:<noreply@fixture.test>\r\n"
                       f"RCPT TO:<{_email}>\r\n"
                       f"From: noreply@fixture.test\r\n"
                       f"To: {parsed}\r\n")
            self._send(200, json.dumps({"smtp_trace": raw_hdr,
                                       "email_received": _email}),
                      "application/json")
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
        elif path in ("/race/redeem", "/safe/race/redeem"):
            # Kontrol positif race condition (TOCTOU) — single-use voucher.
            # /race/redeem — RENTAN: check-then-act TANPA lock, ada sleep window
            #   -> N request konkurren semua lolos check sebelum flag di-set.
            # /safe/race/redeem — atomic pakai lock -> tepat 1 sukses.
            _safe = path.startswith("/safe")
            if _safe:
                with RACE_LOCK:
                    if RACE_SAFE_USED["used"]:
                        self._send(429, "already redeemed")
                    else:
                        RACE_SAFE_USED["used"] = True
                        self._send(200, "redeemed ok")
            else:
                if RACE_VULN_USED["used"]:
                    self._send(429, "already redeemed")
                else:
                    time.sleep(0.3)  # perlebar window kompetitif (non-atomic)
                    RACE_VULN_USED["used"] = True
                    self._send(200, "redeemed ok")
        elif path in ("/smuggle", "/safe/smuggle"):
            # Kontrol positif HTTP request smuggling (CL.TE) — simulator naif.
            # /smuggle — RENTAN: bila request membawa BOTH Content-Length dan
            #   Transfer-Encoding: chunked, backend naif mem-prioritas TE dan
            #   mengeksekusi "smuggled" sub-request; header X-Smuggle: <marker>
            #   di-reflect ke respons.
            # /safe/smuggle — ketat: tolak request dengan dua framing (400).
            _safe = path.startswith("/safe")
            ichunked = (self.headers.get("Transfer-Encoding", "") or "").lower()
            icl = self.headers.get("Content-Length", "")
            _m = re.search(r"X-Smuggle:\s*([A-Za-z0-9_-]+)", raw)
            if _safe or (("chunked" in ichunked) and icl):
                # safe: tolak dobel-framing; smgl: terima tapi jangan reflect
                if _m and not _safe:
                    self._send(200, json.dumps({"smuggled_marker": _m.group(1)}),
                               "application/json")
                else:
                    self._send(400, "bad request")
                    # terima CL.TE (rentan); jangan echol'd jika safe
            else:
                self._send(400, "bad request")
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
