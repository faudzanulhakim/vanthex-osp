"""tests/test_jwtred.py — hermetic tests for jwtred.py (JWT forgery +
auth-flow attacks, operator-gated). Fixture routes live under /jwt/* and
/reset/token* in tests/fixture_vuln_server.py (v1.2.2 jwtred block).
"""
import json
import os
import sys
import threading
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixture_vuln_server import H, JWTRED_SECRET  # noqa: E402
import jwtred  # noqa: E402
import vulnscan2 as v  # noqa: E402

_PORT = 18444
BASE = f"http://127.0.0.1:{_PORT}"


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", _PORT), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()


def make_ctx(opts):
    return v.Ctx(BASE, dict(opts), [])


def run(opts):
    ctx, found = make_ctx(opts), []
    jwtred.c_jwt_attack(ctx, found.append)
    return found


def by_title(found, needle):
    return [f for f in found if needle.lower() in f["title"].lower()]


# ----------------------------------------------------------------- toolkit

def test_parse_sign_verify_roundtrip():
    tok = jwtred.sign_hs256("s3cret", {"alg": "HS256", "typ": "JWT"},
                            {"sub": "u1", "role": "user"})
    parsed = jwtred.parse_token(tok)
    assert parsed["header"]["alg"] == "HS256"
    assert parsed["payload"]["sub"] == "u1"
    assert jwtred.verify_hs256(tok, "s3cret")
    assert not jwtred.verify_hs256(tok, "wrong")
    assert jwtred.parse_token("garbage") == {}
    # b64url helpers are padding-tolerant and safe
    assert jwtred.b64url_decode(jwtred.b64url_encode(b"\x00\xff")) == b"\x00\xff"


def test_cracker_finds_weak_secret(server):
    ctx = make_ctx({"timeout": 6})
    r = ctx.client.post("/jwt/login",
                        data=json.dumps({"user": "alice"}),
                        headers={"Content-Type": "application/json"})
    tok = json.loads(r.body)["token"]
    secret = jwtred.crack_hs256(tok, time_budget=20)
    assert secret == "vanthex-secret"
    assert jwtred.verify_hs256(tok, secret)


# ---------------------------------------------------------------- gating

def test_gate_off_noop(server):
    found = run({})
    assert found == [], "check must be a no-op when ungated"
    found = run({"jwtred": False})
    assert found == []


# ------------------------------------------------------- gated token attacks

def test_jwt_token_attacks_confirmed(server):
    found = run({"jwtred": True,
                 "jwt_endpoint": "/jwt/profile,/jwt/none,/jwt/kid,/jwt/jku",
                 "jwt_jku_url": BASE + "/jwt/jwks.json"})
    titles = {f["title"] for f in found}
    assert "JWT alg:none Authentication Bypass" in titles
    alg_none = by_title(found, "alg:none")[0]
    assert alg_none["confidence"] == "confirmed"
    assert alg_none["severity"] == "CRITICAL" and alg_none["cvss"] == 9.8
    assert alg_none["cwe"] == "CWE-347"
    assert "JWT Weak HMAC Secret + Privilege Escalation" in titles
    weak = by_title(found, "Weak HMAC Secret")[0]
    assert weak["confidence"] == "confirmed" and weak["severity"] == "CRITICAL"
    assert "vanthex-secret" in weak["evidence"]
    assert "JWT kid Injection" in titles
    kid = by_title(found, "kid Injection")[0]
    assert kid["confidence"] == "confirmed" and kid["severity"] == "HIGH"
    assert "JWT Key-Confusion/JWK Header Injection" in titles
    jwk = by_title(found, "JWK Header Injection")[0]
    assert jwk["confidence"] == "confirmed" and jwk["cvss"] == 9.1


def test_jwt_safe_route_negative(server):
    found = run({"jwtred": True,
                 "jwt_endpoint": "/safe/jwt/profile,/safe/jwt/none"})
    # the strong-secret route rejects every forged token
    assert not by_title(found, "alg:none")
    assert not by_title(found, "Weak HMAC Secret")
    assert not by_title(found, "kid Injection")


def test_rs256_key_confusion(server):
    found = run({"jwtred": True, "jwt_rs_endpoint": "/jwt/rs"})
    rs = by_title(found, "RS256")
    assert rs and rs[0]["confidence"] == "confirmed"
    assert rs[0]["severity"] == "CRITICAL" and rs[0]["cvss"] == 9.1
    found_safe = run({"jwtred": True, "jwt_rs_endpoint": "/safe/jwt/rs"})
    assert not by_title(found_safe, "RS256")


def test_claim_tampering_probable(server):
    found = run({"jwtred": True, "jwt_claim_endpoint": "/jwt/claims"})
    ct = by_title(found, "Claim Tampering")
    assert ct and ct[0]["confidence"] == "probable"
    assert ct[0]["severity"] == "HIGH" and ct[0]["cvss"] == 7.4


# ------------------------------------------------------ password reset flow

def test_password_reset_flow(server):
    found = run({"jwtred": True})
    pred = by_title(found, "Predictable Password Reset Token")
    assert pred and pred[0]["confidence"] == "confirmed"
    assert pred[0]["severity"] == "HIGH"
    poison = by_title(found, "Password Reset Poisoning")
    assert poison and poison[0]["confidence"] == "confirmed"
    assert poison[0]["cvss"] == 6.8
    assert "attacker.jwtred.example" in poison[0]["evidence"]
    ref = by_title(found, "Referer")
    assert ref and ref[0]["severity"] == "MEDIUM"


# ---------------------------------------------------------------- OAuth

def test_oauth_abuse(server):
    found = run({"jwtred": True,
                 "oauth_authorize_endpoint": "/jwt/oauth/authorize"})
    leak = by_title(found, "Code Leak")
    assert leak and leak[0]["confidence"] == "confirmed"
    assert "attacker.jwtred.example" in leak[0]["evidence"]
    replay = by_title(found, "Code Replay")
    assert replay and replay[0]["confidence"] == "confirmed"
    assert replay[0]["severity"] == "HIGH" and replay[0]["cvss"] == 8.0
    implicit = by_title(found, "Implicit Flow")
    assert implicit and implicit[0]["confidence"] == "probable"


def test_oauth_code_replay_negative_on_safe_exchange(server):
    ctx = make_ctx({"jwtred": True})
    r = ctx.client.get("/jwt/oauth/authorize", params=(
        "client_id=c&response_type=code"
        "&redirect_uri=http://127.0.0.1:%d/cb" % _PORT))
    loc = r.hdr("location")
    code = loc.split("code=")[1].split("&")[0]
    ex = ctx.client.get("/safe/jwt/oauth/exchange", params=f"code={code}",
                        headers={"X-Jwtred": "1"})
    assert ex.status == 200
    ex2 = ctx.client.get("/safe/jwt/oauth/exchange", params=f"code={code}",
                         headers={"X-Jwtred": "2"})
    assert ex2.status == 400, "safe exchange must reject replayed codes"


# ------------------------------------------------------------- CHECKS wiring

def test_checks_registry():
    assert jwtred.CHECKS == [jwtred.c_jwt_attack]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
