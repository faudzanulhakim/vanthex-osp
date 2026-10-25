"""Hermetic acceptance tests for VANTHEX v1.8.0 — Coverage Expansion.

Everything runs against in-process fixture servers on 127.0.0.1
ephemeral ports (plus the shared battery fixture for one integration
pass); bucket verdicts and AXFR name lookups are exercised through
injected transports. No external network is touched.

Run: .venv/bin/python -m pytest tests/test_v180.py -q
"""
import io
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import pytest

import vulnscan2 as V
import passive as P


# ------------------------------------------------------------ helpers

def _serve(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _ctx(base, opts=None):
    o = {"timeout": 4}
    o.update(opts or {})
    return V.Ctx(base, o, [])


def _collector():
    finds = []
    return finds, finds.append


def _titles(finds):
    return [f["title"] for f in finds]


# ------------------------------------------------------------ WS1 LDAP

class _FakeResp:
    def __init__(self, body, status=200):
        self.body, self.status = body, status


def _dir_page(entries):
    lis = "".join(f"<li>{u} - {n} - {e}</li>" for u, n, e in entries)
    return (f"<html><title>Directory</title><p>{len(entries)} entries "
            f"found</p><ul>{lis}</ul></html>")


_ENTRIES = [("admin", "Site Administrator", "admin@x.test"),
            ("alice", "Alice Anggraini", "alice@x.test"),
            ("bob", "Bob Hartono", "bob@x.test")]


def _genuine_backend(v):
    """A directory that interprets the value as filter syntax."""
    if v == "*":
        return _dir_page(_ENTRIES)
    return _dir_page([e for e in _ENTRIES if e[0] == v])


def _literal_backend(v):
    """An escaped backend: '*' is just an unknown literal username."""
    return _dir_page([e for e in _ENTRIES if e[0] == v])


def test_ws1_differential_genuine_wildcard_backend():
    ctx = _ctx("http://127.0.0.1:1")
    verdict, detail = V._ldap_differential(
        ctx, lambda v: _FakeResp(_genuine_backend(v)),
        _dir_page(_ENTRIES[:1]), lambda b, v: b)
    assert verdict == "full", (verdict, detail)


def test_ws1_differential_literal_backend_no_verdict():
    ctx = _ctx("http://127.0.0.1:1")
    verdict, detail = V._ldap_differential(
        ctx, lambda v: _FakeResp(_literal_backend(v)),
        _dir_page(_ENTRIES[:1]), lambda b, v: b)
    assert verdict == "none", (verdict, detail)


def test_ws1_differential_static_listing_trap_no_verdict():
    # A page that lists everyone for EVERY query (public directory):
    # wildcard == impossible == baseline, so no differential exists.
    ctx = _ctx("http://127.0.0.1:1")
    verdict, detail = V._ldap_differential(
        ctx, lambda v: _FakeResp(_dir_page(_ENTRIES)),
        _dir_page(_ENTRIES), lambda b, v: b)
    assert verdict == "none", (verdict, detail)


def test_ws1_differential_error_on_wildcard_indeterminate():
    ctx = _ctx("http://127.0.0.1:1")

    def backend(v):
        if v == "*":
            return ("javax.naming.NamingException: "
                    "[LDAP: error code 87 - Bad search filter]")
        return _dir_page([])

    verdict, _d = V._ldap_differential(
        ctx, lambda v: _FakeResp(backend(v)), _dir_page([]),
        lambda b, v: b)
    assert verdict == "indeterminate", verdict


# ------------------------------------------------------------ WS2 GraphQL

_SCHEMA = {
    "queryType": {"name": "Query"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "users", "args": [], "type": {
                "kind": "LIST", "name": None, "ofType": {
                    "kind": "OBJECT", "name": "User", "ofType": None}}},
            {"name": "adminStats", "args": [], "type": {
                "kind": "OBJECT", "name": "AdminStats", "ofType": None}},
            {"name": "node", "args": [
                {"name": "id", "defaultValue": None,
                 "type": {"kind": "NON_NULL", "name": None,
                          "ofType": {"kind": "SCALAR", "name": "ID",
                                     "ofType": None}}}],
             "type": {"kind": "OBJECT", "name": "User",
                      "ofType": None}},
        ]},
        {"name": "User", "kind": "OBJECT", "fields": [
            {"name": "id", "args": [], "type": {
                "kind": "SCALAR", "name": "ID", "ofType": None}},
            {"name": "name", "args": [], "type": {
                "kind": "SCALAR", "name": "String", "ofType": None}},
            {"name": "email", "args": [], "type": {
                "kind": "SCALAR", "name": "String", "ofType": None}},
            {"name": "friends", "args": [], "type": {
                "kind": "LIST", "name": None, "ofType": {
                    "kind": "OBJECT", "name": "User", "ofType": None}}},
        ]},
        {"name": "AdminStats", "kind": "OBJECT", "fields": [
            {"name": "totalUsers", "args": [], "type": {
                "kind": "SCALAR", "name": "Int", "ofType": None}},
        ]},
        {"name": "String", "kind": "SCALAR", "fields": None},
        {"name": "Int", "kind": "SCALAR", "fields": None},
        {"name": "ID", "kind": "SCALAR", "fields": None},
    ],
}
_USERS = [{"id": "1", "name": "Alice", "email": "alice@corp.test"},
          {"id": "2", "name": "Bob", "email": "bob@corp.test"}]


def _gql_handler(leaky):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, obj, code=200):
            raw = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            body = b'<html><a href="/graphql">GraphQL</a></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            try:
                q = json.loads(self.rfile.read(n) or b"{}") \
                    .get("query", "")
            except Exception:
                q = ""
            cookie = self.headers.get("Cookie") or ""
            authed = "sess=admin" in cookie
            aliases = re.findall(r"ptka\d+\s*:\s*__typename", q)
            if len(aliases) >= 10:
                if leaky:
                    return self._json({"data": {
                        a.split(":")[0]: "Query" for a in aliases}})
                return self._json({"errors": [{
                    "message": "Too many aliases: query complexity "
                               "limit exceeded"}]})
            if "__schema" in q:
                return self._json({"data": {"__schema": _SCHEMA}})
            if q.count("friends") >= 3:
                if leaky:
                    node = {"__typename": "User"}
                    for _i in range(q.count("friends")):
                        node = {"friends": node}
                    return self._json({"data": {"users": [node]}})
                return self._json({"errors": [{
                    "message": "Query depth exceeds maximum depth 5"}]})
            if re.search(r"\busers\s*\{", q):
                if leaky or authed:
                    return self._json({"data": {"users": _USERS}})
                return self._json({"data": {"users": None},
                                   "errors": [{"message": "forbidden"}]})
            if re.search(r"\badminStats\s*\{", q):
                if leaky or authed:
                    return self._json(
                        {"data": {"adminStats": {"totalUsers": 42}}})
                return self._json({"data": {"adminStats": None},
                                   "errors": [{"message": "forbidden"}]})
            if "__typename" in q:
                return self._json({"data": {"__typename": "Query"}})
            return self._json({"errors": [{
                "message": "Cannot query field"}]})
    return H


def test_ws2_schema_parse_and_depth_chain():
    schema = V._gql_parse_schema(_SCHEMA)
    assert schema and schema["queryType"] == "Query"
    chain = V._gql_depth_chain(schema, 8)
    assert len(chain) == 8, chain
    assert chain[0][1] == "users" and chain[1][1] == "friends"
    q = V._gql_nested_query(chain)
    data = {"users": [{"friends": {"friends": {"__typename": "User"}}}]}
    assert V._gql_resolve_path(data, chain[:3]) is True
    assert V._gql_resolve_path(data, chain) is False


def test_ws2_graphql_leaky_fixture():
    srv, base = _serve(_gql_handler(leaky=True))
    try:
        ctx = _ctx(base)
        finds, add = _collector()
        V.c_graphql_deep(ctx, add)
        titles = _titles(finds)
        assert any("returns data without authentication" in t
                   and "'users'" in t for t in titles), titles
        conf = [f for f in finds
                if "returns data without authentication" in f["title"]]
        assert conf[0]["confidence"] == "confirmed"
        assert any("alias amplification accepted" in t
                   for t in titles), titles
        assert any("query depth not limited" in t for t in titles), \
            titles
        # Honesty: with no credential set the cross-account axis is
        # recorded as not evaluated even though findings fired.
        assert "not evaluated" in json.dumps(ctx.check_meta) or \
            "anonymous-only" in json.dumps(ctx.check_meta), ctx.check_meta
    finally:
        srv.shutdown()


def test_ws2_graphql_strict_fixture_no_findings():
    srv, base = _serve(_gql_handler(leaky=False))
    try:
        ctx = _ctx(base)
        finds, add = _collector()
        V.c_graphql_deep(ctx, add)
        gql = [t for t in _titles(finds)
               if "without authentication" in t
               or "alias amplification" in t
               or "depth not limited" in t
               or "readable by a second account" in t]
        assert gql == [], gql
    finally:
        srv.shutdown()


# ------------------------------------------------------------ WS3 BFLA

def _bfla_handler(leaky):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="text/html"):
            raw = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            path = self.path.split("?")[0]
            cookie = self.headers.get("Cookie") or ""
            if path == "/":
                return self._send(
                    200, '<html><a href="/admin/panel">Admin</a></html>')
            if path == "/admin/panel":
                if "sess=admin" in cookie:
                    return self._send(
                        200, "<html><h1>Admin Panel</h1><p>user "
                             "management, role editor, delete users, "
                             "system settings</p></html>")
                if "sess=low" in cookie:
                    if leaky:
                        return self._send(
                            200, "<html><h1>Admin Panel</h1><p>user "
                                 "management, role editor, delete "
                                 "users, system settings</p></html>")
                    return self._send(403, "forbidden")
                return self._send(401, "login required")
            return self._send(404, "not found")
    return H


def test_ws3_bfla_confirmed_and_matrix_recorded():
    srv, base = _serve(_bfla_handler(leaky=True))
    try:
        ctx = _ctx(base, {"cookie": "sess=admin",
                          "auth_b": {"cookie": "sess=low"}})
        finds, add = _collector()
        V.c_bfla_matrix(ctx, add)
        hit = [f for f in finds if f["title"].startswith("BFLA:")]
        assert len(hit) == 1 and hit[0]["confidence"] == "confirmed", \
            _titles(finds)
        rows = ctx.check_meta.get("bfla_matrix") or []
        row = [r for r in rows if r["function"] == "/admin/panel"]
        assert row and row[0]["second"] == "granted" \
            and row[0]["anonymous"] == "denied", rows
        assert "BFLA" in row[0]["verdict"]
    finally:
        srv.shutdown()


def test_ws3_bfla_strict_no_finding():
    srv, base = _serve(_bfla_handler(leaky=False))
    try:
        ctx = _ctx(base, {"cookie": "sess=admin",
                          "auth_b": {"cookie": "sess=low"}})
        finds, add = _collector()
        V.c_bfla_matrix(ctx, add)
        assert [f for f in finds if "BFLA" in f["title"]
                or "Privileged function" in f["title"]] == [], \
            _titles(finds)
        rows = ctx.check_meta.get("bfla_matrix") or []
        row = [r for r in rows if r["function"] == "/admin/panel"]
        assert row and "healthy" in row[0]["verdict"], rows
    finally:
        srv.shutdown()


# ------------------------------------------------------------ WS4 OAuth

_OIDC_RISKY = {
    "issuer": "http://fixture.local/",
    "authorization_endpoint": "http://fixture.local/oauth/authorize",
    "token_endpoint": "http://fixture.local/oauth/token",
    "jwks_uri": "http://fixture.local/.well-known/jwks.json",
    "grant_types_supported": ["authorization_code", "password",
                              "implicit"],
    "response_types_supported": ["code", "id_token", "token"],
    "token_endpoint_auth_methods_supported": ["none",
                                              "client_secret_basic"],
}


def _oauth_handler(advance):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="text/html", extra=None):
            raw = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            from urllib.parse import parse_qs, urlparse
            u = urlparse(self.path)
            if u.path == "/":
                return self._send(
                    200, '<html><a href="/oauth/authorize?'
                         'client_id=fixture-client&amp;'
                         'redirect_uri=http://fixture.local/callback'
                         '&amp;response_type=code">Sign in</a></html>')
            if u.path == "/.well-known/openid-configuration":
                return self._send(200, json.dumps(_OIDC_RISKY),
                                  "application/json")
            if u.path == "/oauth/authorize":
                if not advance:
                    return self._send(
                        400, "login required before authorization")
                qs = parse_qs(u.query)
                ru = (qs.get("redirect_uri") or [""])[0]
                if not ru:
                    return self._send(400, "redirect_uri required")
                loc = ru + "?code=fixture-code"
                if qs.get("state"):
                    loc += "&state=" + qs["state"][0]
                return self._send(302, "", extra={"Location": loc})
            return self._send(404, "not found")
    return H


def test_ws4_oauth_risky_config_and_lax_flow():
    srv, base = _serve(_oauth_handler(advance=True))
    try:
        ctx = _ctx(base)
        finds, add = _collector()
        V.c_oauth_sso(ctx, add)
        titles = _titles(finds)
        assert any("password grant (ROPC)" in t for t in titles), titles
        assert any("implicit flow" in t for t in titles), titles
        redir = [f for f in finds if "redirect_uri not validated"
                 in f["title"]]
        assert redir and redir[0]["confidence"] == "confirmed", titles
        assert any("without a state parameter" in t for t in titles), \
            titles
        assert any("without PKCE" in t for t in titles), titles
        assert ctx.check_meta["oauth"]["flows_tested"] == 1
    finally:
        srv.shutdown()


def test_ws4_oauth_strict_flow_not_evaluated():
    srv, base = _serve(_oauth_handler(advance=False))
    try:
        ctx = _ctx(base)
        finds, add = _collector()
        V.c_oauth_sso(ctx, add)
        titles = _titles(finds)
        # Config findings are legitimate; NO flow finding may appear
        # when the flow never advances (K2 honesty).
        assert not [t for t in titles if "redirect_uri" in t
                    or "state" in t or "PKCE" in t], titles
        assert "not evaluated" in ctx.check_meta["oauth"]["note"], \
            ctx.check_meta
    finally:
        srv.shutdown()


# ------------------------------------------------------------ WS5 upload

def _upload_handler(lax):
    store = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="text/html", extra=None):
            raw = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/":
                return self._send(
                    200, '<html><form action="/upload" method="post" '
                         'enctype="multipart/form-data">'
                         '<input type="file" name="file">'
                         '<input type="submit"></form></html>')
            if path.startswith("/uploads/"):
                name = path.rsplit("/", 1)[-1]
                if name in store:
                    if lax:
                        ct = ("text/html" if name.endswith(".html")
                              else "image/gif" if name.endswith(".gif")
                              else "text/plain")
                        return self._send(200, store[name], ct)
                    return self._send(
                        200, store[name], "text/plain",
                        {"Content-Disposition": "attachment",
                         "X-Content-Type-Options": "nosniff"})
                return self._send(404, "not found")
            return self._send(404, "not found")

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n)
            m = re.search(rb'filename="([^"]+)"', raw)
            if self.path == "/upload" and m:
                name = m.group(1).decode()
                part = raw.split(b"\r\n\r\n", 1)[-1]
                store[name] = part.split(b"\r\n--")[0] \
                    .decode("utf-8", "replace")
                return self._send(200, f"uploaded {name} ok")
            return self._send(404, "not found")
    return H


def test_ws5_upload_lax_serving_context_confirmed():
    srv, base = _serve(_upload_handler(lax=True))
    try:
        ctx = _ctx(base)
        finds, add = _collector()
        V.c_upload_surface(ctx, add)
        hit = [f for f in finds if "Upload validation bypass"
               in f["title"]]
        assert hit and hit[0]["confidence"] == "confirmed", \
            _titles(finds)
        # The benign artifacts could not be deleted on this fixture
        # (no DELETE handler) and must be recorded, not hidden.
        assert ctx.check_meta.get("upload_artifacts"), ctx.check_meta
    finally:
        srv.shutdown()


def test_ws5_upload_strict_serving_no_confirmed_bypass():
    srv, base = _serve(_upload_handler(lax=False))
    try:
        ctx = _ctx(base)
        finds, add = _collector()
        V.c_upload_surface(ctx, add)
        assert not [f for f in finds
                    if "Upload validation bypass" in f["title"]], \
            _titles(finds)
    finally:
        srv.shutdown()


# ------------------------------------------------------------ WS6a AXFR

def _axfr_fixture(mode):
    """A minimal TCP DNS server speaking just enough AXFR: either a
    two-message transfer ending in a second SOA, or REFUSED."""
    import socket
    import dns.message
    import dns.rcode
    import dns.rdatatype
    import dns.rrset

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(4)
    port = sock.getsockname()[1]
    zone = "example.test."

    def _soa():
        return dns.rrset.from_text(
            zone, 300, "IN", "SOA",
            "ns1.example.test. hostmaster.example.test. "
            "1 7200 3600 1209600 300")

    def _serve_conn(conn):
        try:
            hdr = conn.recv(2)
            if len(hdr) < 2:
                return
            ln = int.from_bytes(hdr, "big")
            data = b""
            while len(data) < ln:
                chunk = conn.recv(ln - len(data))
                if not chunk:
                    break
                data += chunk
            q = dns.message.from_wire(data)
            if mode == "refuse":
                r = dns.message.make_response(q)
                r.set_rcode(dns.rcode.REFUSED)
                msgs = [r]
            else:
                r1 = dns.message.make_response(q)
                r1.answer.append(_soa())
                r1.answer.append(dns.rrset.from_text(
                    zone, 300, "IN", "NS", "ns1.example.test."))
                r1.answer.append(dns.rrset.from_text(
                    "www.example.test.", 300, "IN", "A", "192.0.2.10"))
                r2 = dns.message.make_response(q)
                r2.answer.append(_soa())
                msgs = [r1, r2]
            for m in msgs:
                wire = m.to_wire()
                conn.sendall(len(wire).to_bytes(2, "big") + wire)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _loop():
        while True:
            try:
                conn, _a = sock.accept()
            except Exception:
                return
            threading.Thread(target=_serve_conn, args=(conn,),
                             daemon=True).start()

    threading.Thread(target=_loop, daemon=True).start()
    return sock, port


def test_ws6a_axfr_open_and_refused():
    sock, port = _axfr_fixture("allow")
    try:
        status, info = V._axfr_attempt("127.0.0.1", "example.test",
                                       port=port)
        assert status == "transferred", (status, info)
        assert info["records"] >= 3 and info["types"].get("SOA") == 2, \
            info
    finally:
        sock.close()
    sock, port = _axfr_fixture("refuse")
    try:
        status, info = V._axfr_attempt("127.0.0.1", "example.test",
                                       port=port)
        assert status == "refused", (status, info)
    finally:
        sock.close()


def test_ws6a_axfr_check_end_to_end():
    sock, port = _axfr_fixture("allow")
    orig_ns, orig_a = V._dns_ns_records, V._dns_a_records
    V._dns_ns_records = lambda zone: ["ns1.example.test"]
    V._dns_a_records = lambda name: ["127.0.0.1"]
    try:
        ctx = _ctx("http://example.test:8080",
                   {"axfr_port": port})
        finds, add = _collector()
        V.c_dns_axfr(ctx, add)
        hit = [f for f in finds if "zone transfer (AXFR) open"
               in f["title"]]
        assert hit and hit[0]["confidence"] == "confirmed", \
            _titles(finds)
        assert "contents intentionally not stored" in hit[0]["evidence"]
    finally:
        V._dns_ns_records, V._dns_a_records = orig_ns, orig_a
        sock.close()


def test_ws6a_axfr_ip_literal_skipped():
    ctx = _ctx("http://127.0.0.1:8080")
    finds, add = _collector()
    V.c_dns_axfr(ctx, add)
    assert finds == []


# ------------------------------------------------------------ WS6b buckets

_S3_LIST = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/'
            '2006-03-01/"><Name>acme-example</Name>'
            '<Contents><Key>backups/db.sql</Key></Contents>'
            '<Contents><Key>index.html</Key></Contents>'
            '</ListBucketResult>')
_S3_DENIED = ('<?xml version="1.0" encoding="UTF-8"?>'
              '<Error><Code>AccessDenied</Code>'
              '<Message>Access Denied</Message></Error>')
_S3_ABSENT = ('<?xml version="1.0" encoding="UTF-8"?>'
              '<Error><Code>NoSuchBucket</Code>'
              '<Message>The specified bucket does not exist</Message>'
              '</Error>')


def _bucket_run(feed):
    orig = V._bucket_fetch
    V._bucket_fetch = feed
    try:
        ctx = _ctx("http://acme-example.com:8080")
        finds, add = _collector()
        V.c_cloud_buckets(ctx, add)
        return finds, ctx
    finally:
        V._bucket_fetch = orig


def test_ws6b_bucket_public_listing_confirmed():
    def feed(url):
        if "s3.amazonaws.com" in url:
            return 200, _S3_LIST
        return 0, ""
    finds, ctx = _bucket_run(feed)
    hit = [f for f in finds if "publicly listable" in f["title"]]
    assert hit and all(f["confidence"] == "confirmed" for f in hit), \
        _titles(finds)
    assert "db.sql" in hit[0]["evidence"]
    assert ctx.check_meta["cloud_buckets"]["probed"] <= 48


def test_ws6b_bucket_private_is_candidate_only():
    def feed(url):
        if "s3.amazonaws.com" in url:
            return 403, _S3_DENIED
        return 0, ""
    finds, _c = _bucket_run(feed)
    assert finds and all(f["confidence"] == "candidate"
                         and f["severity"] == "INFO" for f in finds), \
        _titles(finds)


def test_ws6b_bucket_absent_and_unmarked_bodies_no_findings():
    def feed_absent(url):
        if "s3.amazonaws.com" in url:
            return 404, _S3_ABSENT
        return 0, ""
    finds, _c = _bucket_run(feed_absent)
    assert finds == [], _titles(finds)

    def feed_garbage(url):
        # A bare 200 from some gateway/WAF must prove NOTHING.
        return 200, "<html><title>gateway</title>ok</html>"
    finds, _c = _bucket_run(feed_garbage)
    assert finds == [], _titles(finds)


def test_ws6b_bucket_names_from_domain_tokens():
    names = V._bucket_names("acme-example.com")
    assert "acme-example" in names
    assert "acme-example-backup" in names
    assert len(names) <= 18
    assert V._bucket_names("127.0.0.1") == []


# ------------------------------------------------------------ WS6c NVD schedule

def test_ws6c_nvd_schedule_due_logic():
    import app2
    import store
    fake = {}
    orig_get, orig_set = store.get_setting, store.set_setting
    store.get_setting = lambda k, d="": fake.get(k, d)
    store.set_setting = lambda k, v: fake.__setitem__(k, v)
    try:
        now = 2_000_000.0
        assert app2._nvd_schedule_due(now) is False      # default OFF
        fake["nvd_sync_enabled"] = "1"
        fake["nvd_sync_interval_h"] = "24"
        assert app2._nvd_schedule_due(now) is True       # never ran
        fake["nvd_last_sync_ts"] = str(int(now - 3600))
        assert app2._nvd_schedule_due(now) is False      # 1h < 24h
        fake["nvd_last_sync_ts"] = str(int(now - 25 * 3600))
        assert app2._nvd_schedule_due(now) is True       # overdue
        fake["nvd_sync_enabled"] = "0"
        assert app2._nvd_schedule_due(now) is False      # off wins
    finally:
        store.get_setting, store.set_setting = orig_get, orig_set


# ------------------------------------------------------------ WS6d doc metadata

def test_ws6d_pdf_metadata_crafted():
    raw = (b"%PDF-1.4\n1 0 obj<</Title(Annual Report)"
           b"/Author(Jane Doe)/Creator(Microsoft Word)"
           b"/Producer(Acrobat PDFMaker 24)"
           b"/CreationDate(D:20240101120000Z)>>endobj\n%%EOF")
    md = P._pdf_metadata(raw)
    assert md["author"] == "Jane Doe"
    assert md["creator"] == "Microsoft Word"
    assert md["producer"] == "Acrobat PDFMaker 24"
    assert md["created"].startswith("D:2024")
    assert P._pdf_metadata(b"not a pdf") == {}


def test_ws6d_docx_metadata_generated():
    import docx
    d = docx.Document()
    cp = d.core_properties
    cp.author = "John Smith"
    cp.title = "Internal Spec"
    cp.last_modified_by = "jsmith"
    buf = io.BytesIO()
    d.save(buf)
    md = P._docx_metadata(buf.getvalue())
    assert md["author"] == "John Smith"
    assert md["last_modified_by"] == "jsmith"
    assert "Word" in md.get("software", ""), md


# ------------------------------------------------------------ OSINT dorking

def test_osint_a6_dork_formulations():
    import osint
    forms, dorks = osint._a6_formulations("example.com", (), "domain")
    assert forms[0] == '"example.com"'
    assert "site:example.com" in dorks
    assert any("filetype:pdf" in d for d in dorks)
    assert any("inurl:login" in d for d in dorks)
    forms2, dorks2 = osint._a6_formulations("Jane Doe", ("jakarta",),
                                            "name")
    assert "Jane Doe jakarta" in forms2
    assert any("inurl:profile" in d for d in dorks2)
    assert any('intitle:"Jane Doe"' in d for d in dorks2)
    assert len(forms2) <= 9


# ------------------------------------------------------------ WS7 chaining

def _f(title, conf, sev="HIGH", cvss=7.5, loc="/x"):
    return {"title": title, "confidence": conf, "severity": sev,
            "cvss": cvss, "location": loc}


def test_ws7_chain_requires_two_strong_components():
    finds = [_f("SSRF in URL fetcher", "confirmed"),
             _f("SSRF to cloud metadata endpoint", "probable")]
    chains = V._chain_candidates(finds)
    hit = [c for c in chains if c["rule"] == "ssrf-cloud-metadata"]
    assert hit, chains
    assert len(hit[0]["components"]) == 2
    assert len(hit[0]["steps"]) >= 3
    # A candidate-tier component can never complete a chain.
    weak = [_f("SSRF in URL fetcher", "candidate"),
            _f("SSRF to cloud metadata endpoint", "probable")]
    assert V._chain_candidates(weak) == []
    # One finding alone is not a chain.
    assert V._chain_candidates(finds[:1]) == []
    # CRITICAL components are capped at HIGH on the chain itself.
    crit = [_f("SSRF in URL fetcher", "confirmed", "CRITICAL", 9.8),
            _f("SSRF to cloud metadata endpoint", "confirmed",
               "CRITICAL", 9.8)]
    c2 = V._chain_candidates(crit)
    assert c2 and c2[0]["severity"] == "HIGH", c2


def test_ws7_chain_bola_bfla_rule():
    finds = [_f("IDOR/BOLA indication: /api/acct/1002", "probable"),
             _f("BFLA: privileged function accessible to a "
                "low-privilege account: /admin/panel", "confirmed")]
    chains = V._chain_candidates(finds)
    assert any(c["rule"] == "bola-bfla" for c in chains), chains


# ------------------------------------------------------------ integration

_FIXTURE_PORT = 18096


def _wait_port(port, tries=40):
    for _ in range(tries):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/",
                                   timeout=2)
            return True
        except Exception:
            time.sleep(0.25)
    return False


# Serial + timeout longgar (v1.9.1): test integrasi ini menembak
# fixture lokal dengan urutan probe diffconfirm yang sensitif waktu.
# Di bawah beban suite paralel, timeout 4 dtk pernah membuat fixture
# LDAP turun ke probable — perilaku engine BENAR (degradasi
# konservatif saat bukti tak terkumpul), test-nya yang rapuh. Marker
# serial menandainya untuk dijalankan tanpa tumpang tindih suite lain.
@pytest.mark.serial
def test_integration_new_checks_on_battery_fixture():
    """One pass of the five new/extended checks over the shared
    battery fixture (which plants a real LDAP simulator, a lax
    upload, an OIDC config and a GraphQL endpoint)."""
    proc = subprocess.Popen(
        [sys.executable, "tests/fixture_vuln_server.py",
         str(_FIXTURE_PORT)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    V.PROFILES["v180-mini"] = ["c_web_injection", "c_upload_surface",
                               "c_bfla_matrix", "c_oauth_sso",
                               "c_graphql_deep"]
    try:
        assert _wait_port(_FIXTURE_PORT), "fixture did not start"
        res = V.run_vulnscan(f"http://127.0.0.1:{_FIXTURE_PORT}",
                             "v180-mini", log=[],
                             opts={"timeout": 10, "max_pages": 25})
        titles = _titles(res["findings"])
        ldap = [f for f in res["findings"]
                if "LDAP Injection (boolean-based)" in f["title"]]
        assert ldap and ldap[0]["confidence"] == "confirmed", titles
        # The escaped twin endpoint must stay clean.
        assert not [f for f in res["findings"] if "LDAP" in f["title"]
                    and "search_safe" in f.get("location", "")], titles
        assert any("OAuth password grant (ROPC) enabled" in t
                   for t in titles), titles
        assert any("Upload validation bypass" in t for t in titles), \
            titles
        assert any("alias amplification accepted" in t
                   for t in titles), titles
        # Structured metadata rides along in the scan result.
        assert isinstance(res.get("bfla_matrix"), list) \
            and len(res["bfla_matrix"]) >= 1, res.get("bfla_matrix")
        assert "oauth" in (res.get("meta") or {})
        assert isinstance(res.get("chains"), list)
        assert res["checks_total"] == 5
    finally:
        V.PROFILES.pop("v180-mini", None)
        proc.terminate()
