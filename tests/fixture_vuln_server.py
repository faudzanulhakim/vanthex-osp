#!/usr/bin/env python3
"""
INTENTIONALLY VULNERABLE target server (fixture) — for local engine tests only.
NOT part of the production toolkit. Run: python3 fixture_vuln_server.py [port]
SPA mode (soft-404 on every path): FIXTURE_MODE=spa python3 fixture_vuln_server.py [port]
"""
import base64
import hashlib
import html
import hmac
import json
import os
import random
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

MODE = os.environ.get("FIXTURE_MODE", "vuln")

# accuracy-v3 (round 2): seeded jitter so /fp/blind-noisy is deterministic
# for the hermetic tests (uniform 0.2-0.4 s, elevated-but-not-scaling).
random.seed(57)

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
# blindxssapi lab (v1.9.x): stored comments (vuln renders RAW + victim-sim
# fetches src= beacons; safe variant HTML-escapes) and beacon hits recorded
# at /blx/beacon (canary.py-compatible token path) and listed at /blx/beacons.
BLX_STORE = []
BLX_SAFE_STORE = []
BLX_BEACONS = []


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
<footer>Powered by nginx — our blog discusses akamai, barracuda, and f5 in general terms.</footer>
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
         # v1.6.0 — live key for the API-key reuse control (must match the
         # pattern vk_live_[0-9a-f]{16,} in takeover.py)
         "bundled_key": "vk_live_" + "a3f9c2d17b40e5f8" * 2,
         # protocolattacks fixture counters (race-condition emulator)
         "proto_race": 0, "proto_race_safe": 0}

# v1.9.0 — simulated CDN cache (path -> (status, body))
CDN_CACHE = {}

# protocolattacks (v1.11+) — cache-poisoning emulator: path -> body.
# Only attacker-marked hosts (containing the scanner's 'ptk-<marker>' host)
# populate it, mirroring the /cdn/cache pattern, so the pre-poison baseline
# stays clean and the poison request alone populates the cache.
PROTO_CACHE = {}

WEAK_JWT_SECRET = b"supersecret"   # deliberately weak — in the takeover.py wordlist


def _make_weak_jwt():
    """HS256 role=user token with a weak secret (fixture v1.6.0)."""
    import base64 as _b
    def _e(b):
        return _b.urlsafe_b64encode(b).rstrip(b"=").decode()
    h = _e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    p = _e(json.dumps({"sub": "admin@fixture.local", "role": "user", "iat": 1730000000},
                      separators=(",", ":")).encode())
    s = _e(hmac.new(WEAK_JWT_SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{s}"


def _verify_weak_jwt(tok):
    """Verify a bearer token with the weak secret. Returns claims or None."""
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
# Public PEM key for the JWT key-confusion test (RS256 -> HS256 using the public key).
# The fixture /api/jwt_rs wrongly uses the public key as the HMAC secret.
JWT_PUB_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/qPXIZBICJ1MaJ7j8u5mW0g1Z\n"
    "zcM0C4Qj3B1+7n4Qk9YhrPjFqYKTaRkYq1VQpR2ObxQ0r9T4m5e8hZCVQKbJYw==\n"
    "-----END PUBLIC KEY-----"
)
# --- jwtred.py fixture assets (v1.2.2) --------------------------------
# HS256 weak secret for /jwt/* controls; SAFE one is strong (negative).
JWTRED_SECRET = b"vanthex-secret"
SAFE_JWT_SECRET = b"rbQ7x!safe-key-9f2c-unguessable-Zq8w"
OAUTH_ISSUED = set()   # codes ever issued (vuln exchange never invalidates)
OAUTH_USED = set()     # codes consumed (safe exchange)


def _jwtred_claims(tok, secret):
    """Verify a 3-part HS256 token with the given secret -> claims | None."""
    try:
        h, p, s = tok.split(".")
        expect = base64.urlsafe_b64encode(
            hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        if not hmac.compare_digest(expect, s):
            return None
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return None


def _jwtred_header(tok):
    try:
        h = tok.split(".")[0]
        return json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    except Exception:
        return {}

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
        """WAF mode: block Cloudflare-style attack payloads (positive control
        for c_waf_detection) — inactive in other modes."""
        if MODE != "waf":
            return False
        raw = self.path.lower()
        # SPECIFIC attack patterns only (a real WAF does not block lone
        # punctuation) — benign scanner controls, including a lone %27, must PASS
        # so the v3.5 WAF behavior test can tell differential blocking apart.
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
        if origin:  # deliberate bad CORS: echo origin + credentials
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

    # ---- graphqlsuite (GraphQL emulator) kontrol routes ----------------
    GQL_FIELDS = {
        "Query": {"hello": "String", "user": "User", "posts": "[Post]"},
        "User": {"id": "String", "name": "String", "posts": "[Post]"},
        "Post": {"id": "String", "title": "String", "author": "User"},
        "Mutation": {"createUser": "User", "login": "String"},
    }
    GQL_OPEN = ("/gql/open",)  # endpoints where mutations run unauthenticated

    def _gql_introspection(self):
        def _t(n):
            return {"kind": "OBJECT" if n in self.GQL_FIELDS else "SCALAR",
                    "name": n,
                    "ofType": {"kind": "LIST", "name": None,
                               "ofType": {"kind": "OBJECT", "name": n,
                                          "ofType": None}} if n in self.GQL_FIELDS else None}
        types = []
        for tname, fields in self.GQL_FIELDS.items():
            types.append({
                "name": tname, "kind": "OBJECT",
                "fields": [{"name": f,
                            "args": [{"name": "id", "defaultValue": None}],
                            "type": _t(ftype.strip("[]!"))}
                           for f, ftype in fields.items()]})
        return {"queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"}, "types": types}

    def _gql_did_you_mean(self, bad, typename):
        import difflib
        names = list(self.GQL_FIELDS.get(typename, {}).keys())
        close = difflib.get_close_matches(bad, names, n=3, cutoff=0.1)
        hint = ", ".join(f"'{c}'" for c in close) if close else "'user'"
        return [{"message": f"Cannot query field '{bad}' on type '{typename}'. "
                            f"Did you mean {hint}?"}]

    def _gql(self, path, raw=""):
        """Tiny GraphQL emulator: introspection ON, field suggestions ON,
        alias/depth uncapped. Mutations require 'Authorization: Bearer
        admin-token' except on /gql/open (positive control for the
        unauthenticated-mutation probe). Accepts GET ?query= (leakage)."""
        ctype = (self.headers.get("Content-Type") or "").lower()
        urlq = {k: v[0] for k, v in parse_qs(
            urlparse(self.path).query).items()}
        if ctype.startswith("application/graphql"):
            query = raw
        elif "query" in urlq:  # GET ?query= — query-in-URL
            query = urlq["query"]
        else:
            try:
                query = str(json.loads(raw or "{}").get("query") or "")
            except Exception:
                query = ""
        qtext = query or ""
        stripped = qtext.lstrip()

        # --- mutations ---------------------------------------------------
        if stripped.startswith("mutation"):
            m = re.search(r"mutation\s*\{?\s*(\w+)\s*(?:\(([^)]*)\))?", stripped)
            if not m:
                self._send(200, json.dumps({"errors": [{"message": "syntax"}]}),
                           "application/json")
                return
            mname, margs = m.group(1), m.group(2) or ""
            nm = re.search(r'name:\s*"([^"]*)"', margs)
            name = nm.group(1) if nm else "ptk"
            authorized = (self.headers.get("Authorization") or "") == "Bearer admin-token"
            if path in self.GQL_OPEN or authorized:
                if mname == "createUser":
                    data = {"createUser": {"__typename": "User", "id": "42",
                                           "name": name}}
                elif mname == "login":
                    data = {"login": "TOK-open"}
                else:
                    self._send(200, json.dumps({"errors": [{"message":
                        f"Cannot query field '{mname}' on type 'Mutation'. "
                        "Did you mean 'createUser' or 'login'?"}]}),
                        "application/json")
                    return
                self._send(200, json.dumps({"data": data}), "application/json")
            else:
                self._send(200, json.dumps({"errors": [{"message":
                    "Unauthorized: must be authenticated to run mutations"}]}),
                    "application/json")
            return

        # --- alias batch: name:__typename ----------------------------------
        aliases = re.findall(r"(\w+)\s*:\s*__typename", qtext)
        if aliases:
            self._send(200, json.dumps({"data": {a: "Query" for a in aliases}}),
                       "application/json")
            return

        # --- introspection -------------------------------------------------
        if "__schema" in qtext or "__type" in qtext.replace("__typename", ""):
            self._send(200, json.dumps({"data": {"__schema":
                                                 self._gql_introspection()}}),
                       "application/json")
            return

        # --- plain query: nested user{posts{author{...}}} resolution -------
        m = re.search(r"Cannot|invalid|(\w+)\s*\{", qtext)
        bad = re.search(r"\{\s*([a-zA-Z_]\w*)\s*\}?$|\{\s*([a-zA-Z_]\w*)\s*\}",
                        qtext)
        if "user" in qtext or "posts" in qtext or "author" in qtext:
            data = {"user": {"id": "u1", "name": "alice"}}
            node = data["user"]
            for _ in range(60):  # depth cycle, uncapped for scanners
                if "posts" not in qtext:
                    break
                node["posts"] = [{"id": "p1", "title": "t1"}]
                if "author" in qtext:
                    node["posts"][0]["author"] = {"id": "u1", "name": "alice"}
                    node = node["posts"][0]["author"]
                else:
                    break
            if "__typename" in qtext:
                data["__typename"] = "Query"
            self._send(200, json.dumps({"data": data}), "application/json")
            return
        # unknown top-level field -> Did-you-mean suggestion
        fb = re.search(r"\{\s*([a-zA-Z_]\w*)", qtext)
        if fb and not fb.group(1).startswith("__") \
                and fb.group(1) not in self.GQL_FIELDS["Query"]:
            self._send(200, json.dumps(
                {"errors": self._gql_did_you_mean(fb.group(1), "Query")}),
                "application/json")
            return
        self._send(200, json.dumps({"data": {"__typename": "Query",
                                             "hello": "world"}}),
                   "application/json")

    def do_GET(self):
        if self._waf_block():
            return
        path, q = self._all_params()
        self._maybe_sleep(list(q.values()))
        if MODE == "spa" and path not in ("/",):
            self._send(200, HOME)  # catch-all 200: soft-404 trap for scanners
            return
        if path in ("/gql", "/gql/open", "/api/graphql"):
            # graphqlsuite control: tiny GraphQL emulator. /gql and /api/graphql:
            # introspection ON, field suggestions ON, mutations REQUIRE auth.
            # /gql/open: mutation createUser executes WITHOUT auth (positive
            # control for the unauthenticated-mutation probe), mutations and
            # queries are also accepted over GET (query-in-URL leakage).
            self._gql(path)
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
            # /api/me VULNERABLE (alg=none accepted + weak secret) — positive control
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
                # kid injection simulation (v1.10 positive control): the kid is used
                # as a key file path / SQL fragment without sanitization.
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
        elif path == "/blx/":
            # blindxssapi lab: comment form (vuln store) + link to the
            # render page and a SAFE (escaped) variant.
            self._send(200, "<html><title>Comment Board</title>"
                            "<a href='/blx/comments'>comments</a>"
                            "<form method='POST' action='/blx/comment'>"
                            "<input name='name'><input name='comment'>"
                            "<button>Post</button></form>"
                            "<form method='POST' action='/blx/safe/comment'>"
                            "<input name='name'><input name='comment'>"
                            "<button>Post safe</button></form></html>")
        elif path == "/blx/comments":
            # blindxssapi: vuln board — stored entries rendered RAW; the
            # render simulates a privileged victim viewer by fetching
            # any http(s) src= beacon found in stored entries.
            import urllib.request as _u
            _entries = ""
            for _e in BLX_STORE:
                _entries += f"<div class='entry'>{_e}</div>"
                for _src in re.findall(r'src="(https?://[^"]+)"', _e):
                    try:
                        _u.urlopen(_src, timeout=3).read(64)
                    except Exception:
                        pass
            self._send(200, "<html><title>Comments</title>"
                            f"{_entries}</html>")
        elif path == "/blx/safe/comments":
            _entries = "".join(
                f"<div class='entry'>{html.escape(str(_e))}</div>"
                for _e in BLX_SAFE_STORE)
            self._send(200, "<html><title>Comments (safe)</title>"
                            f"{_entries}</html>")
        elif path == "/blx/beacons":
            self._send(200, json.dumps(BLX_BEACONS), "application/json")
        elif path.startswith("/blx/beacon"):
            # canary.py-compatible beacon recorder: token = last path
            # segment (any method), like canary._handle expects.
            _parts = [p for p in path.split("?")[0].split("/") if p]
            _tok = _parts[-1] if len(_parts) > 1 else ""
            if _tok and _tok != "beacon":
                BLX_BEACONS.append({"token": _tok, "ts": time.time(),
                                    "method": self.command,
                                    "ua": self.headers.get("User-Agent", "")[:120]})
            self._send(200, "ok", "text/plain")
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
                # Cloud metadata endpoint simulation (SSRF metadata positive control).
                self._send(200, "<html><title>Fetch Result</title>"
                                "ami-id: ami-0fixture123\ninstance-id: i-0fixture456\n"
                                "instance-type: t3.micro</html>")
                return
            try:
                with _u.urlopen(target, timeout=3) as resp:
                    data = resp.read(4096).decode("utf-8", "replace")
                self._send(200, f"<html><title>Fetch Result</title>{data}</html>")
            except Exception as e:
                self._send(200, f"<html>fetch failed: {type(e).__name__}</html>")
        elif path == "/echohdr":
            # Kontrol positif CRLF: nilai param masuk header respons mentah.
            self._send(200, "<html>echo</html>", extra=[("X-Echo-Loc", q.get("to", ""))])
        elif path == "/admin/login":
            self._send(200, """<html><title>Admin Login</title><form method="POST" action="/admin/login">
                <input name="user"><input name="pass" type="password"><button>Sign in</button></form></html>""")
        elif path == "/safe/search":
            import html as _h
            self._send(200, f"<html><title>Safe Search</title>Results for {_h.escape(q.get('q', ''))} — safe and escaped.</html>")
        elif path == "/safe/item":
            self._send(200, "<html>Safe Item #2 Fixture Shoes - data statis dari query berparameter (prepared statement).</html>")
        elif path == "/safe/redirect":
            nxt = q.get("next", "/")
            if nxt.startswith("/") and not nxt.startswith("//"):
                self._send(302, "", extra=[("Location", nxt)])
            else:
                self._send(400, "external redirect rejected")
        elif path == "/safe/slow":
            # Jebakan timing: endpoint jinak yang UNIFORM lambat. Baseline
            # sama lambatnya, jadi klaim SQLi time-based di sini = FP.
            time.sleep(1.6)
            self._send(200, "<html>Safe Slow — a heavy but legitimate page (renders in 1.6 seconds for every request).</html>")
        elif path in ("/xpath/search", "/xpath/blind", "/safe/xpath/search"):
            # Kontrol Priority 1: /xpath/search membangun ekspresi XPath
            # with string concatenation (VULNERABLE, verbose error);
            # /xpath/blind is equally vulnerable but the error is genericized (only
            # boolean yang bisa membuktikan); versi /safe melakukan
            # parameterized lookup without building the query from input.
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
            # Priority 1 control: only the debug & preview parameters change
            # the /hidden response; /safe/hidden ignores them all.
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
            # Stability trap: content changes on EVERY request — the hidden-params
            # & XPath boolean stability gate must skip it.
            import random as _rnd
            self._send(200, f"<html><title>Dynamic</title>rotating banner "
                            f"#{_rnd.randint(0, 10**9)} served at {time.time()} "
                            "— content rotates every request.</html>")
        elif path == "/vuln/search_bool":
            # PURE boolean-blind SQLi positive: no SQL error at all.
            # v1.7.0: a real boolean evaluator (not just literal
            # 1=2) — numeric arithmetic conditions are evaluated like a real
            # SQL backend, so the Arithmetic Proof Battery tests against
            # correct semantics; boolean operators with unparseable conditions
            # yield a generic error page (500).
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
                self._send(200, "<html><title>BoolSearch</title>Full product list: running shoes, football boots, hiking boots, sandals, hats — long stable result text for boolean comparison.</html>")
        elif path == "/login":
            # Jenkins console simulation (v1.1): product header + sign-in title
            # + version footer — the three artifacts typical of a real Jenkins.
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
            # anywhere; it only lives inside the JS bundle (bundle-miner target).
            self._send(200,
                       'const routes={admin:"/admin/users",export:"/api/legacy/admin-export",'
                       'dead:"/api/legacy/dead-export",ship:"/api/shipments/3"};\n'
                       'fetch("/api/legacy/admin-export").then(r=>r.json());\n'
                       'fetch("/api/legacy/dead-export");\n'
                       'fetch("/api/shipments/3");\n', "application/javascript")
        elif path == "/api/legacy/admin-export":
            # v1.5.0 — bundle-miner control: the legacy endpoint is live & leaks
            # data (not linked, only present in the bundle).
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
            # v1.5.0 — cookie-based role ACL (naive app): role=admin only.
            role = ""
            for part in (self.headers.get("Cookie") or "").split(";"):
                if part.strip().startswith("role="):
                    role = part.strip()[5:]
            if role == "admin":
                self._send(200, "<html>Admin Users — ade(admin), sari(user)</html>")
            else:
                self._send(403, "<html>Forbidden — admin only</html>")
        elif path == "/admin/export":
            # v1.5.0 — vulnerable authz matrix control: should be admin-only,
            # but role=user is accepted (role verified from the COOKIE, not
            # the server-side session).
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
            # v1.5.0 — enriched spec: stateful paths for the fuzzer (harvest IDs
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
            # v1.5.0 — openapi stateful control: the spec endpoint has NO
            # ACL; valid IDs 1-9 return data (IDOR by spec).
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
            # v1.6.0 — JWT takeover control: HS256 token with a WEAK SECRET
            # ('supersecret' is in the brute wordlist), role=user claim.
            tok = _make_weak_jwt()
            self._send(200, json.dumps({"token": tok}), "application/json")
        elif path == "/admin/me":
            # v1.6.0 — admin endpoint with bearer JWT: verified with the same
            # weak secret (a forged role=admin token is accepted).
            auth = self.headers.get("Authorization", "")
            tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            claims = _verify_weak_jwt(tok)
            if claims and claims.get("role") == "admin":
                self._send(200, json.dumps({"ok": True, "role": "admin",
                                            "user": claims.get("sub", "admin")}), "application/json")
            else:
                self._send(401, json.dumps({"ok": False, "error": "admin only"}), "application/json")
        elif path == "/safe/admin/me":
            # negative: verification with a STRONG secret (forged token rejected)
            auth = self.headers.get("Authorization", "")
            tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            self._send(401, json.dumps({"ok": False, "error": "signature invalid"}), "application/json")
        elif path == "/safe/oauth/authorize":
            # v1.6.0 — token theft negative: fixture.local allowlist only
            redir = str(q.get("redirect_uri", ""))
            if redir.startswith(("http://fixture.local/", "https://fixture.local/")):
                self._send(302, "", "text/html",
                           extra=[("Location", redir + "?code=vhx-ok")])
            else:
                self._send(400, json.dumps({"ok": False,
                                            "error": "redirect_uri not in allowlist"}), "application/json")
        elif path == "/profile":
            # v1.6.0 — account profile (evidence for the email change)
            email = STATE.get("account_email", "admin@fixture.local")
            self._send(200, f"<html>Profile: admin@fixture.local | email: {email}</html>")
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
                self._send(401, "<html>Forbidden — session required</html>")
        elif path == "/safe/admin/vault":
            self._send(401, "<html>Forbidden</html>")
        elif path == "/admin/panel":
            # v1.7.0 — shadow admin control: direct 403, but X-Original-URL
            # is trusted (classic reverse-proxy misconfiguration).
            xo = self.headers.get("X-Original-URL", "")
            if xo == "/admin/panel":
                self._send(200, "<html>Admin Panel — dashboard internal, "
                                "user management, audit log</html>")
            else:
                self._send(403, "<html>Forbidden — admin only</html>")
        elif path == "/safe/admin/panel":
            self._send(403, "<html>Forbidden</html>")
        elif path == "/blind/sleep":
            # v1.7.0 — blind timing control: a value with 'sleep N' makes the
            # response slow (simulated server-side execution). /safe ignores it.
            import time as _t
            v = str(q.get("host", ""))
            if not path.startswith("/safe") and "sleep" in v.lower():
                _t.sleep(0.32)
            self._send(200, json.dumps({"ok": True, "echo_len": len(v)}),
                       "application/json")
        elif path == "/safe/ws":
            # v1.7.0 — CSWSH negative: foreign Origin rejected.
            self._send(403, "origin not allowed", "text/plain")
        elif path in ("/internal/netmap", "/safe/internal/netmap"):
            # v1.8.0 — pivot: the internal netmap endpoint leaks WITHOUT auth
            # (topology + internal credentials); /safe refuses.
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
            # v1.8.0 — IMDSv1: instance credentials without an IMDSv2 token;
            # /safe simulates IMDSv2 (token required → 401).
            if path.startswith("/safe"):
                self._send(401, json.dumps(
                    {"error": "IMDSv2 token required"}), "application/json")
            else:
                self._send(200, json.dumps({
                    "AccessKeyId": "AKIAFIXTUREV18X",
                    "SecretAccessKey": "FixCloudS3cret2024",
                    "Token": "FixToken==", "Expiration": "2026-12-31"}))
        elif path == "/cloud/validate":
            # (GET is invalid) — handled by do_POST
            self._send(405, "use POST", "text/plain")
        elif path in ("/docker/api", "/safe/docker/api"):
            # v1.8.0 — Docker daemon API exposed without TLS/auth.
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
            # v1.9.0 — MCP server: tool listing WITHOUT auth, including
            # destructive tools; /safe 403.
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
            # v1.9.0 — model endpoint (Ollama-style) without auth; /safe 403.
            if path.startswith("/safe"):
                self._send(403, "authentication required", "text/plain")
            else:
                self._send(200, json.dumps({"models": [
                    "llama3:8b", "mistral:7b", "internal-embed-v2"]}))
        elif path == "/cdn/cache":
            # v1.9.0 — CDN cache: takes the LAST X-Forwarded-Host
            # (wrong normalization) then CACHES it for subsequent
            # requests (per-path cache, simulated TTL).
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
        elif path == "/proto/xfh":
            # protocolattacks: echoes X-Forwarded-Host into a canonical link
            # (host-header reflection positive control), honours
            # X-Original-URL as a comment marker.
            xfh = self.headers.get("X-Forwarded-Host", "")
            xou = self.headers.get("X-Original-URL", "")
            host = xfh or self.headers.get("Host", "proto.fixture.local")
            body = f"<html>canonical: http://{host}/account</html>"
            if xou:
                body += f"<!-- original-url: {xou} -->"
            self._send(200, body,
                       extra=[("Cache-Control", "public, max-age=60")])
        elif path == "/proto/cache":
            # protocolattacks: cache emulator. Poison requests carrying an
            # attacker-marked X-Forwarded-Host populate the cache; every
            # subsequent request is served from it (X-Cache: hit).
            hdrs = self.headers.get_all("X-Forwarded-Host") or []
            fwd = hdrs[-1].split(",")[-1].strip() if hdrs else ""
            key = "proto:" + urlparse(self.path).path
            if key in PROTO_CACHE:
                self._send(200, PROTO_CACHE[key],
                           extra=[("X-Cache", "hit")])
            elif "ptk" in fwd:
                page = f"<html>canonical: http://{fwd}/account</html>"
                PROTO_CACHE[key] = page
                self._send(200, page, extra=[("X-Cache", "miss")])
            else:
                host = fwd or "proto.fixture.local"
                self._send(200, f"<html>canonical: http://{host}/account</html>",
                           extra=[("X-Cache", "miss")])
        elif path == "/proto/cache/safe":
            # negative control: forwarded host ignored, nothing cached
            self._send(200, "<html>canonical: http://proto.fixture.local/account</html>",
                       extra=[("X-Cache", "bypass")])
        elif path == "/proto/h2":
            # protocolattacks: h2 Content-Length inconsistency emulator —
            # a duplicate, differing Content-Length header pair is reported.
            cls = self.headers.get_all("Content-Length") or []
            if len({c.strip() for c in cls}) > 1:
                self._send(200, "PROTO-H2-CL-CONFLICT", "text/plain")
            else:
                self._send(200, "ok", "text/plain")
        elif path == "/proto/race":
            # protocolattacks: readable race-condition state counter
            # (?which=safe reads the idempotent counter for negative tests)
            which = q.get("which", "main")
            val = STATE["proto_race_safe"] if which == "safe" \
                else STATE["proto_race"]
            self._send(200, json.dumps({"redeemed": val}),
                       "application/json")
        elif path == "/proto/smuggle":
            self._send(200, "smuggle origin ok", "text/plain")
        elif path == "/proto/smuggle-clean":
            self._send(200, "clean origin ok", "text/plain")
        elif path == "/safe/cdn/cache":
            # v1.9.0 — cache control: canonical host always, header ignored.
            self._send(200, "Host: cdn.fixture.local<html>safe page</html>",
                       "text/html")
        elif path == "/trap/vendors":
            # Vendor trap (v3.4.1 regression): the hex token contains 'f5' +
            # WAF vendor names as plain article TEXT.
            self._send(200, "<html><title>Artikel</title>Perbandingan WAF populer: "
                            "cloudflare, akamai, imperva, sucuri, barracuda, and f5 big-ip are discussed as products. "
                            "This article also mentions Jenkins, GitLab, Docker, Kubernetes, "
                            "Portainer, and phpMyAdmin as product names in plain text. "
                            "Token sesi: 38ff6460ffff59ffff06ff6bffff3644f5f5f5aabbcc. "
                            "Checksum f5f5f5f5ffff.</html>",
                       extra=[("Set-Cookie", "tracker=9f5abcffff0000f5; Path=/")])
        elif path == "/trap/databases":
            # Database trap (v3.8 regression): DB names as the article topic,
            # NOT error phrases — must not trigger Database detection.
            self._send(200, "<html><title>DB Article</title>Many teams use MySQL, "
                            "PostgreSQL, MongoDB, Oracle, or SQLite for their projects. "
                            "This article covers how to choose the right database.</html>")
        elif path == "/trap/echo_raw_json":
            # Context trap: reflection into escaped JSON with a JSON
            # content-type — not an HTML context, must not become XSS.
            self._send(200, json.dumps({"echo": q.get("msg", "")}),
                       "application/json")
        elif path == "/safe/fetch":
            host = urlparse(q.get("url", "")).hostname
            if host == "example.com":
                self._send(200, "<html>Safe fetch OK (allowlist)</html>")
            else:
                self._send(403, "host not in allowlist")
        elif path == "/cached":
            host_used = STATE["cache_host"] or self.headers.get("Host", "")
            if self.headers.get("X-Forwarded-Host"):
                STATE["cache_host"] = self.headers["X-Forwarded-Host"]
                host_used = STATE["cache_host"]
            self._send(200, f"<html>Cached page — host used: {host_used}</html>")
        elif path == "/forgot":
            self._send(200, """<html><title>Forgot</title><form action="/forgot" method="POST">
                <input name="email"><button>Send reset link</button></form></html>""")
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
            # as the query; a single quote -> SQL error (second-order class).
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
                self._send(200, "<html>Item #1 Fixture stable detail page for the baseline.</html>")
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
            # __proto__[...] / JSON __proto__ modifies the runtime (vulnerable);
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
            # containing a second request is 'executed' by the backend (vulnerable). Safe: reject.
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
            # v1.4.0 — Web Cache Deception control: /admin/profile 403 without
            # a session; /admin/profile.css serves private content + cacheable (naively
            # making the ACL decision based on a static extension).
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
            # v1.4.0 — in-process WAF gate (independent of MODE): blocks
            # canonical attack patterns; mutated forms pass. For c_waf_bypass.
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
            # accepts a body; this version accepts a header).
            ua = self.headers.get("User-Agent", "")
            if path == "/api/log" and "${jndi:" in ua.lower():
                tok = re.search(r"\$\{jndi:([^}]+)\}", ua)
                self._send(200, json.dumps({"logged": True,
                                            "resolved": f"vhx-dns-hit:{tok.group(1) if tok else '?'}"}),
                           "application/json")
            else:
                self._send(200, "<html>log saved</html>")
        elif path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin-secret\n", "text/plain")
        elif path in ("/admin/status", "/safe/admin/status"):
            # Auth-bypass-via-proxy-header positive control (X-Original-URL).
            # /admin/status — VULNERABLE: naive proxy; the X-Original-URL header
            #   fools the ACL (the server appears to call /admin/status when actually
            #   the original path is executed). No header = 403.
            # /safe/admin/status — strict: always 403.
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
            # /api/jwt_rs — VULNERABLE key-confusion: HS256 verification with
            # the PEM public key as the HMAC secret (not RS256 verify). An attacker
            # who knows the public key (from /api/jwks) can forge tokens.
            # /safe/jwt_rs — correct: RS256 verification with the public key (requires
            #   the private key to sign; cannot be forged to HS256).
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
                    # correct: HS256 should be rejected for an RS256 token
                    ok = False
                else:
                    # wrong (vulnerable): sign with the public key as the secret
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
            self._send(200, f"<html><title>Search</title>Results for {term} — 3 items found: running shoes, football boots, hiking boots with a long stable description.</html>")
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
                                f"phone 0800-000-{n:04d} — customer order {n} status completed.</html>")
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
            # SPA catch-all trap: every /static/* path answers the same shell
            # and REFLECTS the raw request URI (URL-encoded) — the v3.2.0 FP trap.
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
                # the /api/ version is WIDE-OPEN VULNERABLE: any valid token reads any profile
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
        elif path == "/jwt/jwks.json":
            # jwtred: JWKS hosting an attacker 'oct' key for jku injection.
            k = base64.urlsafe_b64encode(b"vhx-jwk-attacker-key").rstrip(b"=").decode()
            self._send(200, json.dumps({"keys": [{"kty": "oct",
                                                  "alg": "HS256", "k": k}]}),
                       "application/json")
        elif path == "/jwt/pub.pem":
            self._send(200, JWT_PUB_PEM, "text/plain")
        elif path in ("/jwt/profile", "/safe/jwt/profile"):
            # jwtred: profile endpoint — vuln verifies with the WEAK secret,
            # safe variant with a strong one (tampered tokens always 401).
            auth = self.headers.get("Authorization", "")
            tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            sec = SAFE_JWT_SECRET if path.startswith("/safe") else JWTRED_SECRET
            claims = _jwtred_claims(tok, sec)
            if claims:
                self._send(200, json.dumps({"ok": True, "sub": claims.get("sub", ""),
                                            "role": claims.get("role", "user"),
                                            "isAdmin": bool(claims.get("isAdmin"))}),
                           "application/json")
            else:
                self._send(401, json.dumps({"ok": False, "error": "invalid token"}),
                           "application/json")
        elif path in ("/jwt/none", "/safe/jwt/none"):
            # jwtred: alg:none control — vuln accepts unsigned tokens.
            auth = self.headers.get("Authorization", "")
            tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            hdr = _jwtred_header(tok)
            claims = None
            if str(hdr.get("alg", "")).lower() == "none":
                if not path.startswith("/safe"):
                    try:
                        p = tok.split(".")[1]
                        claims = json.loads(base64.urlsafe_b64decode(
                            p + "=" * (-len(p) % 4)))
                    except Exception:
                        claims = None
            else:
                sec = SAFE_JWT_SECRET if path.startswith("/safe") else JWTRED_SECRET
                claims = _jwtred_claims(tok, sec)
            if claims:
                self._send(200, json.dumps({"ok": True, "sub": claims.get("sub", ""),
                                            "role": claims.get("role", "user"),
                                            "isAdmin": bool(claims.get("isAdmin"))}),
                           "application/json")
            else:
                self._send(401, json.dumps({"ok": False, "error": "invalid token"}),
                           "application/json")
        elif path == "/jwt/kid":
            # jwtred: kid injection control — traversal uses empty secret,
            # SQLi pattern is "found" in the fake key store.
            auth = self.headers.get("Authorization", "")
            tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            kid = str(_jwtred_header(tok).get("kid", ""))
            claims = None
            if kid == "../../dev/null" or "' OR 1=1--" in kid:
                claims = _jwtred_claims(tok, b"")
            else:
                claims = _jwtred_claims(tok, JWTRED_SECRET)
            if claims:
                self._send(200, json.dumps({"ok": True, "kid": kid,
                                            "role": claims.get("role", "user")}),
                           "application/json")
            else:
                self._send(401, json.dumps({"ok": False, "error": "invalid token"}),
                           "application/json")
        elif path == "/jwt/jku":
            # jwtred: jku header injection — fetches attacker JWKS (oct key)
            # and verifies with it. Local-host only (hermetic).
            import urllib.request as _ur
            auth = self.headers.get("Authorization", "")
            tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            hdr = _jwtred_header(tok)
            jku = str(hdr.get("jku", ""))
            jwk = hdr.get("jwk") if isinstance(hdr.get("jwk"), dict) else None
            claims = None
            if jwk and jwk.get("k"):
                # jwtred: embedded jwk (oct key) trusted straight from the
                # token header.
                try:
                    k = str(jwk["k"])
                    sec = base64.urlsafe_b64decode(k + "=" * (-len(k) % 4))
                    claims = _jwtred_claims(tok, sec)
                except Exception:
                    claims = None
            elif jku.startswith(("http://127.0.0.1", "http://localhost")):
                try:
                    jw = json.loads(_ur.urlopen(jku, timeout=3).read())
                    k = jw["keys"][0]["k"]
                    sec = base64.urlsafe_b64decode(k + "=" * (-len(k) % 4))
                    claims = _jwtred_claims(tok, sec)
                except Exception:
                    claims = None
            else:
                # no key material in header: normal weak-secret verification
                # (so the GENUINE token is a valid baseline on this endpoint)
                claims = _jwtred_claims(tok, JWTRED_SECRET)
            if claims:
                self._send(200, json.dumps({"ok": True, "jku": jku,
                                            "role": claims.get("role", "user")}),
                           "application/json")
            else:
                self._send(401, json.dumps({"ok": False, "error": "invalid token"}),
                           "application/json")
        elif path in ("/jwt/rs", "/safe/jwt/rs"):
            # jwtred: RS256->HS256 key confusion. /jwt/rs wrongly verifies
            # HS256 with the PUBLIC key PEM; safe rejects HS256 outright.
            auth = self.headers.get("Authorization", "")
            tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            alg = str(_jwtred_header(tok).get("alg", ""))
            claims = None
            if path == "/jwt/rs" and alg == "HS256":
                claims = _jwtred_claims(tok, JWT_PUB_PEM.encode())
            if claims:
                self._send(200, json.dumps({"ok": True,
                                            "role": claims.get("role", "user")}),
                           "application/json")
            else:
                self._send(401, json.dumps({"ok": False, "error": "invalid token"}),
                           "application/json")
        elif path in ("/jwt/claims", "/safe/jwt/claims"):
            # jwtred: claim tampering — vuln decodes payload WITHOUT
            # verifying the signature.
            auth = self.headers.get("Authorization", "")
            tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            claims = None
            if path.startswith("/safe"):
                claims = _jwtred_claims(tok, JWTRED_SECRET)
            else:
                try:
                    p = tok.split(".")[1]
                    claims = json.loads(base64.urlsafe_b64decode(
                        p + "=" * (-len(p) % 4)))
                except Exception:
                    claims = None
            if claims:
                self._send(200, json.dumps({"ok": True, "claims": claims}),
                           "application/json")
            else:
                self._send(401, json.dumps({"ok": False, "error": "invalid token"}),
                           "application/json")
        elif path == "/jwt/referer":
            # jwtred: simulates an attacker page that logs the Referer.
            self._send(200, "logged Referer: "
                       + (self.headers.get("Referer") or "(none)"))
        elif path == "/reset/token":
            # jwtred: predictable reset token = md5(email + ':' + minute).
            email = q.get("email", "alice@fixture.local")
            host_used = self.headers.get("Host", "fixture.local")
            tok = hashlib.md5(f"{email}:{int(time.time()) // 60}".encode()).hexdigest()
            self._send(200, f"<html>Reset link: http://{host_used}"
                            f"/reset/token/confirm?email={email}&token={tok}"
                            "</html>")
        elif path == "/jwt/oauth/authorize":
            # jwtred: lax authorization server — ANY redirect_uri, no state,
            # code replay accepted at /jwt/oauth/exchange.
            ru = q.get("redirect_uri", "")
            if not ru:
                self._send(400, "missing redirect_uri")
            elif q.get("response_type") == "token":
                self._send(302, "", extra=[("Location",
                                            ru + "#access_token=vhx-implicit-token"
                                                 "&token_type=bearer")])
            else:
                code = "vxo-" + os.urandom(8).hex()
                OAUTH_ISSUED.add(code)
                sep = "&" if "?" in ru else "?"
                self._send(302, "", extra=[("Location",
                                            ru + sep + "code=" + code)])
        elif path == "/jwt/oauth/exchange":
            # jwtred: VULN — never invalidates the code (replay accepted).
            code = q.get("code", "")
            if code in OAUTH_ISSUED:
                self._send(200, json.dumps({"ok": True,
                                            "access_token": "at-" + code}),
                           "application/json")
            else:
                self._send(400, json.dumps({"ok": False,
                                            "error": "unknown code"}),
                           "application/json")
        elif path == "/safe/jwt/oauth/exchange":
            # jwtred: SAFE — single-use code (replay rejected).
            code = q.get("code", "")
            if code in OAUTH_ISSUED and code not in OAUTH_USED:
                OAUTH_USED.add(code)
                self._send(200, json.dumps({"ok": True,
                                            "access_token": "at-" + code}),
                           "application/json")
            else:
                self._send(400, json.dumps({"ok": False,
                                            "error": "code invalid or used"}),
                           "application/json")
        elif path == "/graphql":
            self._send(200, "<html>GraphQL endpoint</html>")
        elif path == "/api/admin/users":
            # v1.2.2 — authz matrix: admin-only JSON list (role check via
            # X-Test-User session header; admin bertahan, lainnya 403).
            if self.headers.get("X-Test-User") == "admin":
                self._send(200, json.dumps({"users": [
                    {"id": 999, "name": "Admin Fixture", "role": "admin"},
                    {"id": 1, "name": "Ade Pratama", "role": "user"}]}),
                    "application/json")
            else:
                self._send(403, json.dumps({"error": "admin only"}),
                           "application/json")
        elif path == "/api/user/me":
            # v1.2.2 — authz matrix: the session's own profile (the id serves as
            # the 'own id' baseline for the IDOR check).
            who = self.headers.get("X-Test-User", "user1")
            self._send(200, json.dumps({
                "id": 999 if who == "admin" else 1,
                "role": "admin" if who == "admin" else "user",
                "name": who}), "application/json")
        elif path.startswith("/api/user/") and path.endswith("/profile"):
            # v1.2.2 — IDOR VULNERABLE: ANY profile is returned WITHOUT an auth check
            # (change the id -> read another user's profile; even anonymous works).
            uid = path[len("/api/user/"):-len("/profile")]
            self._send(200, json.dumps({
                "id": uid, "name": f"User {uid}",
                "email": f"user{uid}@fixture.test",
                "ssn_masked": f"***-**-{uid[-4:] if uid else '0000'}"}),
                "application/json")
        elif path == "/app.js":
            # v1.2.2 — SPA bundle mining: fetches hidden endpoints that
            # are not linked anywhere in the HTML.
            self._send(200,
                       'fetch("/api/hidden/config").then(r=>r.json());\n'
                       'var me="/api/user/me";\n'
                       'axios.get("/api/orders/7");\n'
                       'query ViewerProfile { viewer { id } }\n',
                       "application/javascript")
        elif path == "/api/hidden/config":
            self._send(200, json.dumps({"feature_flags": ["bola_lab"],
                                        "env": "test"}), "application/json")
        elif path == "/fp/echo":
            # v1.2.4 FP pattern (field: Next.js SPA behind auth): 302 to the
            # login page with next= carrying the URL-encoded incoming query.
            from urllib.parse import quote as _q
            qs = urlparse(self.path).query
            self.send_response(302)
            self.send_header("Location", f"/fp/login?next={_q('/fp/echo?' + qs, safe='')}")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/fp/login":
            # Renders the next= param back in HTML (the FP echo surface).
            nxt = str(q.get("next", ""))
            self._send(200, "<html><head><title>Sign in required</title></head>"
                       "<body><form method='post' action='/fp/login'>"
                       "<input name='user'><input type='password' name='password'>"
                       "</form>"
                       f"<p>Continue: <a href=\"/fp/login?next={nxt}\">next</a>"
                       f"<input type='hidden' name='next' value='{nxt}'></p>"
                       "</body></html>")
        elif path == "/fp/true-cmdi":
            # v1.2.4 real-execution simulation: parse q for an 'echo X'
            # expression and return ONLY the decoded X / evaluated result
            # (never the payload string).
            import re as _re
            v = str(q.get("q", ""))
            out = "done"
            for mm in _re.finditer(r"echo\s+(\S+)", v):
                tok = mm.group(1).strip("`$()")
                mprod = _re.fullmatch(r"(\d+)\*(\d+)", tok)
                if mprod:
                    out = str(int(mprod.group(1)) * int(mprod.group(2)))
                else:
                    out = tok
                break
            self._send(200, out + "\n", "text/plain")
        elif path == "/fp/blind-cmdi":
            # accuracy-v3 (round 2): true BLIND command execution — parse q
            # for a 'sleep N' expression (float allowed) and sleep N before
            # answering, so a real scaling differential (sleep 1 vs sleep 2)
            # passes the round-2 blind_time_confirm rules.
            import re as _re
            v = str(q.get("q", ""))
            mm = _re.search(r"(?<![a-z(])sleep\s+([0-9]+(?:\.[0-9]+)?)", v)
            if mm:
                time.sleep(min(float(mm.group(1)), 8.0))
            self._send(200, "done\n", "text/plain")
        elif path == "/fp/blind-noisy":
            # accuracy-v3 (round 2): network-noise control — jitter 0.2-0.4 s
            # regardless of q, so the sleep variants can never scale.
            time.sleep(random.uniform(0.2, 0.4))
            self._send(200, "done\n", "text/plain")
        elif path == "/fp/safe/cmdi":
            # Negative control: input never reaches a shell.
            self._send(200, "done\n", "text/plain")
        elif path == "/fp/auth-redirect":
            # Auth redirect WITHOUT any query echo: the fp-guard 'skip' case.
            self.send_response(302)
            self.send_header("Location", "/fp/login?next=/fp/secure")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/fp/waf-block":
            # accuracy-v2: WAF/challenge block page (Cloudflare-style) — the
            # preflight classifier must emit the INCONCLUSIVE blocked finding.
            self._send(403,
                       "<html><head><title>Just a moment...</title></head>"
                       "<body>Attention Required! | Checking your browser "
                       "before accessing. cf-chl: 8f00abcd</body></html>")
        elif path in ("/fp/domxss", "/fp/domxss-static"):
            # accuracy-v2: DOM XSS pages — inline script with a plausible
            # source (location.search) and a reachable innerHTML sink.
            # /fp/domxss reflects the q value into the page body (differential
            # path); /fp/domxss-static does not (static-analysis downgrade).
            refl = str(q.get("q", ""))
            body = ("<html><head><title>DOM XSS lab</title></head><body>"
                    + (f"<p id='reflected'>{refl}</p>" if path == "/fp/domxss" else "<p id='reflected'></p>")
                    + "<div id='o'></div>"
                    "<script>var p=new URLSearchParams(location.search);"
                    "document.getElementById('o').innerHTML=p.get('q');</script>"
                    "</body></html>")
            self._send(200, body)
        elif path == "/fp/header-good":
            # accuracy-v2: hardened headers — CSP frame-ancestors present (so
            # the x-frame-options finding must be suppressed), nosniff,
            # referrer-policy set; x-frame-options intentionally absent.
            self._send(200, "<html><title>hardened</title></head><body>ok</body></html>",
                       extra=[("Content-Security-Policy",
                               "default-src 'self'; frame-ancestors 'self'"),
                              ("X-Content-Type-Options", "nosniff"),
                              ("Referrer-Policy", "strict-origin-when-cross-origin"),
                              ("Permissions-Policy", "geolocation=()")])
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
        if path in ("/gql", "/gql/open", "/api/graphql"):
            self._gql(path, raw)
            return
        if path == "/proto/h2":
            # protocolattacks: h2 CL-inconsistency probe (POST variant)
            cls = self.headers.get_all("Content-Length") or []
            if len({c.strip() for c in cls}) > 1:
                self._send(200, "PROTO-H2-CL-CONFLICT", "text/plain")
            else:
                self._send(200, "ok", "text/plain")
        elif path == "/proto/smuggle-clean":
            # negative control: single framing honored, keep-alive preserved
            self._send(200, "clean origin ok", "text/plain")
        if path == "/proto/smuggle":
            # protocolattacks: simple smuggling emulator — when BOTH framing
            # headers arrive, the server reports the desync explicitly
            # (single-response emulator; the detector's pipelined probes
            # treat this as the strong differential).
            cls = self.headers.get_all("Content-Length") or []
            te = self.headers.get("Transfer-Encoding", "")
            if cls and te:
                parsed = "TE" if "chunked" in te.lower() else "CL"
                self._send(200, f"PROTO-DESYNC-DETECTED parsed={parsed}",
                           "text/plain")
            else:
                self._send(200, "smuggle origin ok", "text/plain")
        elif path == "/proto/race/redeem":
            # protocolattacks: VULNERABLE — every duplicate POST increments
            # the counter (no single-use enforcement).
            STATE["proto_race"] += 1
            self._send(200, json.dumps({"ok": True,
                                        "redeemed": STATE["proto_race"]}),
                       "application/json")
        elif path == "/proto/race/safe/redeem":
            # negative control: idempotent — only the first redeem counts.
            STATE["proto_race_safe"] += 1 if not \
                STATE.get("proto_race_safe_done") else 0
            STATE["proto_race_safe_done"] = True
            self._send(200, json.dumps({"ok": True,
                                        "redeemed": STATE["proto_race_safe"]}),
                       "application/json")
        if path == "/jwt/login":
            # jwtred: issues an HS256 token signed with the WEAK secret
            # 'vanthex-secret', role=user.
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            user = str(j.get("user") or j.get("username") or "alice")
            def _e(b):
                return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
            h = _e(json.dumps({"alg": "HS256", "typ": "JWT"},
                              separators=(",", ":")).encode())
            p = _e(json.dumps({"sub": user, "role": "user",
                               "iat": int(time.time())},
                              separators=(",", ":")).encode())
            s = _e(hmac.new(JWTRED_SECRET, f"{h}.{p}".encode(),
                            hashlib.sha256).digest())
            self._send(200, json.dumps({"ok": True, "user": user,
                                        "token": f"{h}.{p}.{s}"}),
                       "application/json")
        elif path == "/reset/token":
            # jwtred: predictable reset token = md5(email + ':' + minute).
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            email = str(j.get("email") or "alice@fixture.local")
            host_used = self.headers.get("Host", "fixture.local")
            tok = hashlib.md5(f"{email}:{int(time.time()) // 60}".encode()).hexdigest()
            self._send(200, json.dumps({
                "ok": True, "email": email, "reset_token": tok,
                "link": f"http://{host_used}/reset/token/confirm"
                        f"?email={email}&token={tok}"}), "application/json")
        elif path == "/reset/token/confirm":
            # jwtred: accepts the predictable (timestamp-derivable) token.
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            email = str(j.get("email") or "")
            tok = str(j.get("token") or "")
            minute = int(time.time()) // 60
            ok = tok in {hashlib.md5(f"{email}:{m}".encode()).hexdigest()
                         for m in (minute - 1, minute, minute + 1)}
            if ok:
                self._send(200, json.dumps({"ok": True,
                                            "status": "password updated"}),
                           "application/json")
            else:
                self._send(403, json.dumps({"ok": False,
                                            "error": "token invalid"}),
                           "application/json")
        elif path == "/forgot":
            host_used = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "")
            self._send(200, f"<html>Reset link sent: http://{host_used}/reset?token=abc123</html>")
        elif path in ("/spray/login", "/safe/spray/login"):
            # v1.4.0 — kontrol password-spray & enum username.
            # /spray/login VULNERABLE: (1) admin/test accepts "Password1!" without
            # rate-limiting (spray); (2) different messages for valid vs invalid users (enum).
            # /safe/spray/login — always a uniform 401 (negative).
            _safe = path.startswith("/safe")
            from urllib.parse import parse_qs as _pqs
            _form = _pqs(raw or "")
            _qv = lambda k: (_form.get(k) or [q.get(k, "")])[0]
            u, p = _qv("username"), _qv("password")
            if _safe:
                self._send(401, json.dumps({"error": "invalid credentials"}), "application/json")
            elif p == "Password1!" and u in ("admin", "test"):
                self._send(200, json.dumps({"ok": True, "user": u,
                                            "session": "SESS-vhx-spray"}), "application/json")
            elif u in ("admin", "test"):
                self._send(401, json.dumps({"error": "wrong password for user '" + u
                                            + "', please try again with the correct password"}),
                           "application/json")
            else:
                self._send(401, json.dumps({"error": "user not found"}), "application/json")
        elif path in ("/otp/verify", "/safe/otp/verify"):
            # v1.4.0 — OTP bypass control: /otp/verify VULNERABLE (null + weak codes
            # accepted, no rate-limit). /safe/otp/verify always rejects.
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
                self._send(401, json.dumps({"ok": False, "error": "wrong code"}), "application/json")
        elif path in ("/reset/request", "/safe/reset/request"):
            # v1.6.0 — reset-token takeover control: /reset/request VULNERABLE
            # (token returned IN THE RESPONSE + predictable md5(email) token).
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            email = str(j.get("email", ""))
            if path.startswith("/safe") or not email:
                # safe: never leaks the token
                self._send(200, json.dumps({"ok": True,
                                            "message": "link sent to email"}), "application/json")
            else:
                tok = hashlib.md5(email.encode()).hexdigest()
                self._send(200, json.dumps({"ok": True, "email": email,
                                            "reset_token": tok}), "application/json")
        elif path in ("/reset/confirm", "/safe/reset/confirm"):
            # v1.6.0 — reset confirm: VULNERABLE, accepts the predictable md5(email)
            # token and 'changes the password'; safe rejects.
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
                                            "error": "invalid / expired token"}), "application/json")
        elif path in ("/login/limited", "/safe/login/limited"):
            # v1.6.0 — rate-limit bypass control: /login/limited counts failures
            # per X-Forwarded-For (client-controlled). /safe counts GLOBAL
            # (XFF ignored) -> a real lockout.
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
                self._send(429, json.dumps({"ok": False, "error": "too many attempts",
                                            "retry_after": 60}), "application/json")
            elif u == "admin@fixture.local" and p == "Summer2025!":
                self._send(200, json.dumps({"ok": True, "user": u}), "application/json")
            else:
                STATE["login_fails"][bucket] += 1
                self._send(401, json.dumps({"ok": False, "error": "invalid credentials"}), "application/json")
        elif path in ("/profile/email", "/safe/profile/email"):
            # v1.6.0 — pre-hijack control: /profile/email accepts an email change
            # WITHOUT re-auth; /safe requires reauth=yes in the body.
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            email = str(j.get("email", ""))
            if path.startswith("/safe") and str(j.get("reauth", "")) != "yes":
                self._send(403, json.dumps({"ok": False,
                                            "error": "re-auth required"}), "application/json")
            elif not email or "@" not in email:
                self._send(400, json.dumps({"ok": False, "error": "invalid email"}), "application/json")
            else:
                STATE["account_email"] = email
                self._send(200, json.dumps({"ok": True, "email": email}), "application/json")
        elif path == "/api/key/check":
            # v1.6.0 — API key status validation (read-only): only keys actually
            # embedded in the fixture are 'active'.
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            k = str(j.get("key", ""))
            if k == STATE.get("bundled_key", ""):
                self._send(200, json.dumps({"active": True,
                                            "scope": "payments:write"}), "application/json")
            else:
                self._send(401, json.dumps({"active": False, "error": "unknown key"}), "application/json")
        elif path == "/safe/api/key/check":
            self._send(401, json.dumps({"active": False, "error": "not allowed"}), "application/json")
        elif path in ("/ai/validate", "/safe/ai/validate"):
            # v1.9.0 — LLM API key validation (read-only models.list simulation)
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
                # control: the clean model refuses & does not leak
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
            # v1.8.0 — IMDS credential validation (read-only STS simulation):
            # only the fixture key counts as active.
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
            # v1.8.0 — grammar fuzz target: the parser is FRAGILE against
            # structural mutations (wrong type → 500 traceback); /safe
            # validates and always returns 200.
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
            # v1.7.0 — credential reuse control: 3 services accept the
            # web credentials (admin/Password1!); /safe rejects.
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
                                            "error": "credentials rejected"}), "application/json")
        elif path in ("/deser/java", "/safe/deser/java"):
            # v1.4.0 — kontrol gadget chain Java (CommonsCollections-style):
            # VULNERABLE: accepts a marker-carrying gadget and triggers a "DNS pingback".
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
            # v1.4.0 — second-order SQLi control: the bio is stored raw (vulnerable)
            # or sanitized (safe); /profile/view is what 'executes' the query.
            u = q.get("user", "ptk")
            bio = raw if "/safe/" in path else raw
            if "/safe/" in path:
                bio = bio.replace("'", "''")
            STATE.setdefault("profiles", {})[u] = bio
            self._send(200, "<html>profile saved</html>")
        elif path == "/api/log":
            # v1.4.0 — Log4Shell control: the JNDI lookup is executed and the OOB
            # token 'arrives' (the response contains the vhx-dns resolution).
            ua = self.headers.get("User-Agent", "")
            if "${jndi:" in ua.lower() or "${jndi:" in raw.lower():
                tok = re.search(r"\$\{jndi:([^}]+)\}", ua + raw)
                self._send(200, json.dumps({"logged": True,
                                            "resolved": f"vhx-dns-hit:{tok.group(1) if tok else '?'}"}),
                           "application/json")
            else:
                self._send(200, "<html>log saved</html>")
        elif path == "/safe/api/log":
            self._send(200, "<html>log saved</html>")
        elif path in ("/h2c", "/safe/h2c"):
            # v1.4.0 — h2c smuggling via POST control: the upgrade is accepted &
            # body containing a second request is 'executed' by the backend (vulnerable).
            upgrade = self.headers.get("Upgrade", "").lower()
            if path == "/h2c" and upgrade == "h2c" and "/admin/internal" in raw:
                self._send(200, "<html>HTTP/2 stream ok — internal: VHX-INTERNAL-OK</html>")
            elif path == "/h2c" and upgrade == "h2c":
                self._send(200, "<html>HTTP/2 stream ok</html>")
            else:
                self._send(200, "<html>normal response (no upgrade)</html>")
        elif path == "/fixation-login":
            self._send(200, "<html>welcome alt user (session not rotated)</html>")
        elif path == "/graphql" and raw.lstrip().startswith("["):
            # GraphQL batching simulation (v1.10 positive control).
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
            # GraphQL field suggestion simulation (v1.10 positive control).
            self._send(200, json.dumps({"errors": [{"message":
                "Cannot query field 'vxbadfield' on type 'Query'. "
                "Did you mean 'user'?"}]}), "application/json")
        elif path == "/graphql" and "__typename" in raw:
            # GraphQL endpoint simulation (v1.1): answers minimal introspection.
            self._send(200, "{\"data\":{\"__typename\":\"Query\"}}",
                       ctype="application/json")
        elif path == "/xml" and "<!ENTITY" in raw and "&ptk;" in raw and "file:///etc/passwd" in raw:
            # XXE simulation ONLY on the /xml endpoint (naive XML parser). This branch
            # used to be a catch-all for every path — once the fixture gained patched
            # (/safe/*) endpoints, they too appeared XXE-vulnerable (a fixture artifact,
            # not an engine bug). The v3.4 battery caught it.
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
        elif path == "/blx/comment":
            # blindxssapi vuln store: raw comment kept verbatim.
            _form = {k: v[0] for k, v in parse_qs(raw).items()}
            BLX_STORE.append(
                f"<b>{_form.get('name', '')}</b>: {_form.get('comment', '')}")
            self._send(200, "<html>posted</html>")
        elif path == "/blx/safe/comment":
            _form = {k: v[0] for k, v in parse_qs(raw).items()}
            BLX_SAFE_STORE.append(
                f"<b>{_form.get('name', '')}</b>: {_form.get('comment', '')}")
            self._send(200, "<html>posted</html>")
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
                        _merge(dst, v)  # pollution: __proto__ contents leak upward
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
                prof.update(posted)   # VULNERABLE mass assignment: all fields accepted & reflected
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
            # /safe/deser — patched: accepts JSON only, rejects pickle bytes.
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
            # /contact — vulnerable: email reflected into the raw RFC header (CRLF not stripped).
            # /safe/contact — patched: strips CRLF before use.
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
                # NESTED values are concatenated into the query (vulnerable); flat values are parameterized (safe)
                self._send(500, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")
            else:
                self._send(200, json.dumps({"results": []}), "application/json")
        elif path in ("/race/redeem", "/safe/race/redeem"):
            # Kontrol positif race condition (TOCTOU) — single-use voucher.
            # /race/redeem — VULNERABLE: check-then-act WITHOUT a lock, with a sleep window
            #   -> N concurrent requests all pass the check before the flag is set.
            # /safe/race/redeem — atomic with a lock -> exactly 1 success.
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
                    time.sleep(0.3)  # widen the competitive window (non-atomic)
                    RACE_VULN_USED["used"] = True
                    self._send(200, "redeemed ok")
        elif path in ("/smuggle", "/safe/smuggle"):
            # Kontrol positif HTTP request smuggling (CL.TE) — simulator naif.
            # /smuggle — VULNERABLE: when a request carries BOTH Content-Length and
            #   Transfer-Encoding: chunked, the naive backend prioritizes TE and
            #   executes the "smuggled" sub-request; the X-Smuggle: <marker> header
            #   is reflected into the response.
            # /safe/smuggle — strict: rejects doubly framed requests (400).
            _safe = path.startswith("/safe")
            ichunked = (self.headers.get("Transfer-Encoding", "") or "").lower()
            icl = self.headers.get("Content-Length", "")
            _m = re.search(r"X-Smuggle:\s*([A-Za-z0-9_-]+)", raw)
            if _safe or (("chunked" in ichunked) and icl):
                # safe: reject double framing; smgl: accept but do not reflect
                if _m and not _safe:
                    self._send(200, json.dumps({"smuggled_marker": _m.group(1)}),
                               "application/json")
                else:
                    self._send(400, "bad request")
                    # accept CL.TE (vulnerable); do not echo if safe
            else:
                self._send(400, "bad request")
        elif path == "/api/user/profile/update":
            # v1.2.2 — REFLECT-ONLY mass assignment: accepts role/is_admin/permissions
            # fields and echoes them in the response, but does NOT
            # store them (the next profile fetch is still role=user -> probable).
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            resp = {"ok": True, "user": "user1", "role": "user"}
            if isinstance(j, dict):
                resp.update(j)
            self._send(200, json.dumps(resp), "application/json")
        elif path == "/login":
            self._send(200, "<html>welcome</html>", extra=[("Set-Cookie", "session=xyz; Path=/")])
        # ---- authattack (auth engine) kontrol routes --------------------
        elif path in ("/auth/login", "/safe/auth/login"):
            # /auth/login VULNERABLE: 3 weak pairs (admin:admin123,
            # test:test1234, dev:devpass1); lockout after 5 failures per XFF bucket
            # (client-controlled -> evadable with a fresh XFF).
            # /safe/auth/login: no weak credentials, GLOBAL lockout
            # (XFF ignored) -> negative for brute force & evasion.
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            if not j:
                j = {}
                for part in (raw or "").split("&"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        j[k] = v
            u = str(j.get("username", j.get("user", "")))
            p = str(j.get("password", ""))
            xff = self.headers.get("X-Forwarded-For", "conn")
            bucket = "GLOBAL" if path.startswith("/safe") else xff
            STATE.setdefault("login_fails", {})
            STATE["login_fails"].setdefault(bucket, 0)
            creds = {} if path.startswith("/safe") else {
                "admin": "admin123", "test": "test1234", "dev": "devpass1"}
            if STATE["login_fails"][bucket] >= 5:
                self._send(429, json.dumps({"ok": False,
                                            "error": "too many attempts, locked"}),
                           "application/json")
            elif u in creds and creds[u] == p:
                self._send(200, json.dumps({"ok": True, "user": u,
                                            "session": "SESS-authattack"}),
                           "application/json")
            else:
                STATE["login_fails"][bucket] += 1
                self._send(401, json.dumps({"ok": False,
                                            "error": "invalid credentials"}),
                           "application/json")
        elif path == "/auth/open-login":
            # login with no lockout/rate-limit at all (always 401).
            self._send(401, json.dumps({"ok": False,
                                        "error": "invalid credentials"}),
                       "application/json")
        elif path == "/auth/register":
            # VULNERABLE mass-assignment: reflects role/isAdmin/email_verified
            # from the registration body.
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            u = str(j.get("username", j.get("user", "user")))
            role = "user"
            if j.get("role") == "admin" or j.get("isAdmin") is True:
                role = "admin"
            resp = {"ok": True, "user": u, "role": role}
            if "email_verified" in j:
                resp["email_verified"] = bool(j.get("email_verified"))
            self._send(200, json.dumps(resp), "application/json")
        elif path == "/auth/otp":
            # VULNERABLE to window brute force: accepts 123456..123463 (an 8-code window),
            # WITHOUT lockout / rate-limit.
            try:
                j = json.loads(raw or "{}")
            except Exception:
                j = {}
            try:
                code = int(str(j.get("code", "")))
            except Exception:
                code = -1
            if 123456 <= code <= 123463:
                self._send(200, json.dumps({"ok": True, "user":
                                            str(j.get("user", "admin"))}),
                           "application/json")
            else:
                self._send(401, json.dumps({"ok": False,
                                            "error": "invalid code"}),
                           "application/json")
        else:
            self._send(404, "not found")

    do_OPTIONS = lambda self: self._send(200, "", extra=[("Allow", "GET, POST, PUT, DELETE, TRACE, OPTIONS")])
    def do_TRACE(self):
        body = "TRACE / HTTP/1.1\r\n" + "\r\n".join(f"{k}: {v}" for k, v in self.headers.items())
        self._send(200, body, "message/http")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
