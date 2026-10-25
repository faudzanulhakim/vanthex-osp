#!/usr/bin/env python3
"""
Pentest Toolkit Enterprise v3 — stdlib only. AUTHORIZED TESTING ONLY.
Run: python3 app2.py [port]   (default 5000, login: admin / $PTK_ADMIN_PW)

Upgrade v3 (lihat UPGRADE_NOTES.md):
- Tool lama v1 hidup lagi di dashboard: port scan, subdomain enum, dir discovery,
  SSL audit, header audit — sebagai scan_type tersendiri, tersimpan di history.
- Job dapat DIBATALKAN (POST /api/job/<id>/cancel), dibersihkan berkala, ada elapsed.
- Authorization gate: scan AKTIF wajib authorized=true dari UI (checkbox otorisasi).
  Allowlist opsional via env PTK_ALLOWED_TARGETS="example.com,10.0.0.0/8-host..." (host persis / suffix domain).
- Login anti-brute-force per IP: penundaan progresif (kegagalan beruntun
  membuat respons makin lambat, maks 30 detik — TANPA lockout, percobaan
  yang sah selalu diproses), session cookie bisa Secure via PTK_COOKIE_SECURE=1.
- Scan terautentikasi: custom headers + cookie diteruskan ke engine (tidak disimpan di DB).
- Export temuan JSON/CSV per scan + endpoint diff antar-scan.
"""
import csv
import io
import ipaddress
import json
import os
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import urllib.request

import base64

import mobile
import osint as osint_mod
import globe_feeds
import globe_recon
import passive as passive_mod
import scanners
import store
import jobgate
import nvd as nvd_mod
import sandbox as sandbox_mod
import secretsmgr
import netclient
import vulnscan2
try:
    import actions as actions_mod
    ACTIONS_OK = True
except Exception:
    actions_mod = None
    ACTIONS_OK = False
from report import render_report

HERE = os.path.dirname(os.path.abspath(__file__))
SESSIONS = {}   # token -> {user, role, exp}
JOBS = {}
GATE = jobgate.JobGate(global_limit=3, user_limit=2)
NVD_SYNC = {"state": "idle", "message": ""}       # job_id -> {status, log, result, started, cancel}

# Canary OOB (Fase 4): satu listener per proses service. Base URL adalah
# alamat yang dipakai TARGET untuk memanggil balik; tanpa PTK_CANARY_BASE
# ia loopback (hanya target lokal/satu mesin yang bisa menjangkau) dan
# mode dinyatakan apa adanya di metrics/scan.
CANARY = {"server": None, "registry": None, "base": "", "mode": "off"}


def _start_canary():
    try:
        import canary as canary_mod
        port = int(os.environ.get("PTK_CANARY_PORT", "8977"))
        srv, reg = canary_mod.serve(port=port, host="0.0.0.0")
        base = os.environ.get("PTK_CANARY_BASE", f"http://127.0.0.1:{port}")
        CANARY.update(server=srv, registry=reg, base=base,
                      mode="configured" if os.environ.get("PTK_CANARY_BASE")
                      else "loopback-only")
        print(f"[i] canary OOB listener on :{port} (mode {CANARY['mode']}, base {base})")
    except Exception as e:
        CANARY["mode"] = f"unavailable: {str(e)[:80]}"
        print(f"[!] canary listener failed: {e}")


def _canary_opts():
    if CANARY.get("registry"):
        # base_kind (WS1): "external" when the operator configured a
        # reachable base (PTK_CANARY_BASE), "builtin" for the loopback
        # listener this process runs itself.
        return {"registry": CANARY["registry"], "base": CANARY["base"],
                "base_kind": "external" if CANARY.get("mode") == "configured"
                             else "builtin"}
    return None
LOGIN_FAILS = {}  # ip -> [timestamps]
SESSION_TTL = 8 * 3600
SCAN_TYPES = ("vulnscan", "ports", "subdomains", "dirs", "ssl", "headers", "passive", "udp", "vhost", "hybrid", "syn", "osint")


def load_template(name):
    with open(os.path.join(HERE, "templates", name), encoding="utf-8", errors="replace") as f:
        return f.read()


WEBUI_DIR = os.path.join(HERE, "webui")
_WEBUI_CACHE = {}
_WEBUI_CTYPES = {
    ".js": "text/javascript", ".css": "text/css", ".png": "image/png",
    ".svg": "image/svg+xml", ".webp": "image/webp", ".json": "application/json",
    ".woff2": "font/woff2", ".woff": "font/woff", ".html": "text/html; charset=utf-8",
}


def webui_file(rel):
    """(bytes, ctype) for a file inside webui/, or None.

    Only "name.ext" and "assets/name.ext" shapes are served — no
    deeper paths, no traversal."""
    parts = rel.split("/")
    if (not rel or ".." in rel or len(parts) > 2
            or (len(parts) == 2 and parts[0] != "assets")):
        return None
    path = os.path.join(WEBUI_DIR, rel)
    try:
        mt = os.path.getmtime(path)
    except OSError:
        return None
    hit = _WEBUI_CACHE.get(rel)
    if hit and hit[0] == mt:
        return hit[1], hit[2]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    ctype = _WEBUI_CTYPES.get(os.path.splitext(rel)[1].lower(),
                              "application/octet-stream")
    _WEBUI_CACHE[rel] = (mt, data, ctype)
    return data, ctype


_VENDOR_FILES = {"maplibre-gl.js", "maplibre-gl.css", "LICENSE.txt"}


def vendor_file(rel):
    """(bytes, ctype) for a vendored MapLibre file, or None.

    Only the exact v1.22.0 vendor shape is served:
    vendor/maplibre/<version>/<allowlisted file> — no deeper paths,
    no traversal, no other filenames, no directory escapes."""
    parts = rel.split("/")
    if len(parts) != 4 or parts[0] != "vendor" or parts[1] != "maplibre":
        return None
    if parts[2] in ("", ".", "..") or parts[3] not in _VENDOR_FILES:
        return None
    if ".." in rel or "\\" in rel:
        return None
    path = os.path.join(WEBUI_DIR, rel)
    if os.path.realpath(path) != os.path.join(os.path.realpath(WEBUI_DIR), rel):
        return None
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if parts[3] == "LICENSE.txt":
        return data, "text/plain"
    ext = os.path.splitext(parts[3])[1]
    return data, _WEBUI_CTYPES.get(ext, "application/octet-stream")


def allowed_target(host):
    """Allowlist opsional. Kosong = semua host boleh (tetap wajib authorization gate utk aktif)."""
    raw = os.environ.get("PTK_ALLOWED_TARGETS", "").strip()
    if not raw or not host:
        return True
    host = host.lower()
    for entry in raw.split(","):
        e = entry.strip().lower()
        if not e:
            continue
        if e.startswith("*."):
            if host.endswith(e[1:]):
                return True
        elif host == e or host.endswith("." + e):
            return True
    return False


def engine_info():
    """Transparansi engine (v3.3): versi, profil + jumlah check, status library
    pihak ketiga yang benar-benar terpasang di venv, dan lapisan verifikasi
    yang dipakai engine untuk menekan false positive. Semua nilai dibaca
    live dari modul yang sedang berjalan — bukan teks statis."""
    import importlib.util
    libs = {}
    for name, mod in (("androguard", "androguard"), ("beautifulsoup4", "bs4"),
                      ("requests", "requests"), ("cryptography", "cryptography"),
                      ("dnspython", "dns"), ("lxml", "lxml")):
        try:
            libs[name] = importlib.util.find_spec(mod) is not None
        except Exception:
            libs[name] = False
    profiles = {}
    try:
        for pname, checks in vulnscan2.PROFILES.items():
            profiles[pname] = {"checks": len(checks), "check_names": list(checks)}
    except Exception:
        profiles = {}
    return {
        "version": "1.2.1",
        "engine": 'self-built (no ready-made scanner tools: nmap/nuclei/etc. are never invoked)',
        "libraries": libs,
        "html_parser": "beautifulsoup4" if libs.get("beautifulsoup4") else "regex-fallback",
        "profiles": profiles,
        "scan_types": list(SCAN_TYPES) + ["mobile"],
        "verification_layers": [
            {"name": "Baseline soft-404 + content signature",
             "detail": 'Responses are compared against a random-path baseline; sensitive files must match a content signature, not just a 200 status.'},
            {"name": "Payload pairs (boolean/time)",
             "detail": 'Injection is claimed only when a true vs false payload (or a statistical delay against the baseline median) produces a measurable difference.'},
            {"name": "Verification pass",
             "detail": 'Exposure findings with confirmed confidence are re-requested; ones that do not reproduce are downgraded to probable, never silently deleted.'},
            {"name": "Port protocol signatures",
             "detail": 'A port service claim must pass the real protocol signature (SSH/RFB/Redis PING/PostgreSQL SSLRequest/etc.); a bare connect = candidate, never confirmed.'},
            {"name": "Interceptor/tarpit detection",
             "detail": 'A known gateway banner or mass identical banners -> the entire port scan is declared INCONCLUSIVE (1 INFO finding, 0 port findings).'},
            {"name": "SPA catch-all gate + parameter validation",
             "detail": 'Parameters whose responses are identical to the soft-404 shell are skipped; JS/CSS files are not crawled as pages (anti-FP for minified code fragments).'},
            {"name": "Scan health (WAF/rate-limit)",
             "detail": 'A 403/429 response ratio > 20% triggers a warning that results may be suppressed by a WAF — shown as-is in the scan result.'},
        ],
        "mobile": {"analyzer": "mobile.py (static, OWASP MASVS)",
                   "parser": "androguard" if libs.get("androguard") else 'not available',
                   "available": bool(libs.get("androguard")),
                   "max_apk_mb": 60,
                   "scope_note": 'Static analysis only — runtime/dynamic testing (Frida, device interception) is not included and is not claimed.'},
    }


APP_STARTED = time.time()


def _system_info():
    """Info kesehatan proses & host via psutil (v3.3) — untuk dashboard.
    Gagal-aman: bila psutil tidak ada, kembalikan dict kosong."""
    try:
        import psutil
        p = psutil.Process()
        vm = psutil.virtual_memory()
        return {"app_uptime_s": int(time.time() - APP_STARTED),
                "app_mem_mb": round(p.memory_info().rss / 1048576, 1),
                "host_cpu_percent": psutil.cpu_percent(interval=None),
                "host_mem_percent": vm.percent,
                "jobs_active": sum(1 for j in JOBS.values()
                                   if j.get("status") == "running")}
    except Exception:
        return {}


def _fire_webhook(scan_id, target, result):
    """Notifikasi webhook (v3.4): POST JSON ke URL yang diatur admin bila scan
    menemukan temuan CRITICAL/HIGH yang BARU dibanding scan target sebelumnya.
    Gagal diam-diam (tidak boleh mengganggu scan)."""
    try:
        url = store.get_setting("webhook_url", "")
        if not url.startswith(("http://", "https://")):
            return
        prev = store.previous_scan(target, time.time(), scan_id)
        prev_keys = store.scan_finding_keys(prev) if prev else set()
        new_ch = [f for f in result.get("findings", [])
                  if f.get("severity") in ("CRITICAL", "HIGH")
                  and f"{f.get('title')}|{f.get('location', '')}|{f.get('param', '')}"
                  not in prev_keys]
        if not new_ch:
            return
        payload = {"event": "pentest_scan_completed", "target": target,
                   "scan_id": scan_id, "risk_score": result.get("risk_score"),
                   "overall_risk": result.get("overall_risk"),
                   "new_critical_high_count": len(new_ch),
                   "new_critical_high": [{"severity": f["severity"],
                                          "title": f["title"]} for f in new_ch[:20]]}
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "PTK-Webhook/3.4"})
        urllib.request.urlopen(req, timeout=6).close()
    except Exception:
        pass


def host_of(target):
    p = urlparse(target if "//" in target else "http://" + target)
    return p.hostname or ""


LOGIN_WINDOW = 300          # jendela hitung kegagalan login (detik)
LOGIN_DELAY_CAP = 30.0      # penundaan maksimum per percobaan (detik)


def login_delay(ip, now=None):
    """Penundaan progresif anti-brute-force untuk /api/login.

    Bukan lockout: percobaan login SELALU diproses (password yang benar
    tidak pernah ditolak), tetapi kegagalan beruntun dalam jendela
    LOGIN_WINDOW membuat respons berikutnya makin lambat — 0 detik
    untuk 2 kegagalan pertama, lalu 1, 2, 4, 8, 16 detik dan seterusnya
    sampai batas LOGIN_DELAY_CAP. Bucket per IP dibersihkan oleh
    handler saat ada login yang berhasil; entri kedaluwarsa dipangkas
    di sini agar dict tidak tumbuh tanpa batas.
    """
    now = time.time() if now is None else now
    fails = [t for t in LOGIN_FAILS.get(ip, []) if now - t < LOGIN_WINDOW]
    if fails:
        LOGIN_FAILS[ip] = fails
    else:
        LOGIN_FAILS.pop(ip, None)
    if len(fails) < 3:
        return 0.0
    return float(min(2 ** (len(fails) - 3), LOGIN_DELAY_CAP))


class Handler(BaseHTTPRequestHandler):
    server_version = "VANTHEX/1.2.1"

    def log_message(self, fmt, *args):
        pass

    def setup(self):
        # Batas waktu diam per koneksi: koneksi menggantung (slow-loris,
        # body yang tidak pernah selesai dikirim) tidak boleh menahan
        # thread handler selamanya. Semua endpoint menjawab jauh di
        # bawah batas ini; upload mobile adalah satu request JSON yang
        # dikirim berkesinambungan, bukan koneksi diam.
        self.request.settimeout(120)
        super().setup()

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline'; img-src 'self' data: "
                         "https://server.arcgisonline.com https://tilecache.rainviewer.com https://nowcoast.noaa.gov https://tiles.basemaps.cartocdn.com https://s3.amazonaws.com; "
                         "connect-src 'self' https://api.rainviewer.com https://basemaps.cartocdn.com https://tiles.basemaps.cartocdn.com https://tiles-a.basemaps.cartocdn.com https://tiles-b.basemaps.cartocdn.com https://tiles-c.basemaps.cartocdn.com https://tiles-d.basemaps.cartocdn.com; "
                         "frame-src https://www.youtube-nocookie.com; "
                         "worker-src 'self' blob:; "
                         "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; "
                         "form-action 'self'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj, extra=None):
        # Respons API memuat data assessment sensitif — jangan pernah di-cache.
        extra = [("Cache-Control", "no-store")] + list(extra or [])
        self._send(code, json.dumps(obj, default=str), "application/json", extra)

    def _stream_ndjson(self, gen):
        # v1.23.0 FINGERPRINT streaming: headers without
        # Content-Length, one JSON line per chunk, flush per line.
        # The CSP literal below is byte-identical to _send's (the
        # v1.25.0 CSP gate asserts every occurrence); _send itself
        # is untouched. Client disconnect ends the generator via
        # GeneratorExit inside globe_recon (single-flight released).
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline'; img-src 'self' data: "
                         "https://server.arcgisonline.com https://tilecache.rainviewer.com https://nowcoast.noaa.gov https://tiles.basemaps.cartocdn.com https://s3.amazonaws.com; "
                         "connect-src 'self' https://api.rainviewer.com https://basemaps.cartocdn.com https://tiles.basemaps.cartocdn.com https://tiles-a.basemaps.cartocdn.com https://tiles-b.basemaps.cartocdn.com https://tiles-c.basemaps.cartocdn.com https://tiles-d.basemaps.cartocdn.com; "
                         "frame-src https://www.youtube-nocookie.com; "
                         "worker-src 'self' blob:; "
                         "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; "
                         "form-action 'self'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.end_headers()
        try:
            for chunk in gen:
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _session(self):
        tok = (self.headers.get("Cookie") or "").split("ptk_session=")[-1].split(";")[0]
        s = SESSIONS.get(tok)
        if s and s["exp"] > time.time():
            return tok, s
        SESSIONS.pop(tok, None)
        # Token API (v3.4): Authorization: Bearer ptk_... untuk akses programatik.
        auth = self.headers.get("Authorization") or ""
        if auth.startswith("Bearer "):
            name = store.verify_token(auth[7:].strip())
            if name:
                return "", {"user": f"api:{name}", "role": "admin",
                            "exp": time.time() + 300}
        return None, None

    # ---------------- GET ----------------
    def do_GET(self):
        try:
            self._do_GET()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            # Jangan jatuhkan koneksi tanpa jawaban: klien menerima
            # 500 generik; traceback lengkap hanya ke log server.
            import traceback
            traceback.print_exc()
            try:
                self._json(500, {"error": "internal error"})
            except Exception:
                pass

    def _do_GET(self):
        path = urlparse(self.path).path
        if path == "/login":
            self._send(200, load_template("login.html"))
            return
        tok, sess = self._session()
        if not sess:
            self._send(302, "", extra=[("Location", "/login")])
            return
        if path == "/":
            if sess.get("role") == "admin" and ACTIONS_OK:
                ui = webui_file("index.html")
                if ui:
                    self._send(200, ui[0], ui[1], [("Cache-Control", "no-store")])
                    return
            self._send(200, load_template("app.html"))
        elif path == "/classic":
            self._send(200, load_template("app.html"))
        elif path.startswith("/assets/"):
            asset = webui_file("assets/" + path[len("/assets/"):])
            if not asset:
                self._send(404, "not found", "text/plain")
                return
            self._send(200, asset[0], asset[1],
                       [("Cache-Control", "public, max-age=86400")])
        elif path.startswith("/vendor/"):
            vend = vendor_file(path[len("/"):])
            if not vend:
                self._send(404, "not found", "text/plain")
                return
            self._send(200, vend[0], vend[1],
                       [("Cache-Control", "public, max-age=86400")])
        elif path == "/api/me":
            self._json(200, sess)
        elif path == "/api/osint/globe/status":
            self._json(200, globe_feeds.status())
        elif path == "/api/osint/globe/cam":
            # v1.13.0 CCTV preview proxy (design section 1): cid is
            # resolved against the server's own CCTV index only; the
            # media itself is served from 'self', CSP unchanged.
            _qs = parse_qs(urlparse(self.path).query)
            _cid = (_qs.get("cid") or [""])[0]
            _kind = (_qs.get("kind") or ["img"])[0]
            _res = globe_feeds.get_cam_preview(
                _cid, _kind, self.headers.get("Range"))
            if not _res.get("ok"):
                self._json(_res.get("status", 502),
                           {"ok": False,
                            "reason": _res.get("reason", "")})
            else:
                _extra = [("Cache-Control", "private, max-age=60")]
                for _k, _v in (_res.get("headers") or {}).items():
                    _extra.append((_k, _v))
                if _res.get("auth"):
                    _extra.append(("X-VANTHEX-Cam-Authority",
                                   str(_res["auth"])))
                if _res.get("fetched_at"):
                    _extra.append(("X-VANTHEX-Cam-Fetched",
                                   str(int(_res["fetched_at"]))))
                self._send(_res["status"], _res["body"],
                           _res["content_type"], _extra)
        elif path.startswith("/api/osint/globe/layer/"):
            _lname = path.rsplit("/", 1)[-1]
            if _lname in globe_feeds.LAYERS:
                self._json(200, globe_feeds.get_layer(_lname))
            else:
                self._json(404, {"error": "unknown globe layer"})
        elif path == "/api/osint/globe/entities":
            _qs = parse_qs(urlparse(self.path).query)
            _sid = (_qs.get("scan") or [""])[0]
            _scan = store.get_scan(_sid) if _sid else None
            if not _scan:
                for _s in store.list_scans(100):
                    if _s.get("scan_type") == "osint":
                        _scan = store.get_scan(_s["id"])
                        break
            if not _scan:
                self._json(200, {"layer": "entities", "points": [],
                                 "located": 0, "total": 0,
                                 "note": "NO INVESTIGATION LOADED"})
            else:
                _res = json.loads(_scan["result"] or "{}")
                self._json(200, globe_feeds.get_entities(
                    _res, scan_id=_scan["id"]))
        elif path == "/api/osint/globe/search":
            # v1.18.0 Search places (design §4 item 3): thin read over
            # the daemon-side Nominatim cache; the query is a fixed
            # template parameter, never a free-form URL.
            _qs = parse_qs(urlparse(self.path).query)
            _q = (_qs.get("q") or [""])[0]
            self._json(200, globe_feeds.search_places(_q))
        elif path == "/api/osint/globe/route":
            # v1.18.0 Directions (design §4 item 5): thin read over the
            # daemon-side OSRM cache; profile is allowlisted inside
            # get_route, waypoints are validated numbers only.
            _qs = parse_qs(urlparse(self.path).query)
            _prof = (_qs.get("profile") or ["driving"])[0]
            _wp = (_qs.get("wp") or [""])[0]
            _wps = []
            _bad = False
            for _pair in _wp.split(";"):
                _pair = _pair.strip()
                if not _pair:
                    continue
                try:
                    _la, _lo = _pair.split(",", 1)
                    _wps.append((float(_la), float(_lo)))
                except (ValueError, TypeError):
                    _bad = True
                    break
            if _bad or len(_wps) < 2:
                self._json(200, {"ok": False,
                                 "reason": "waypoints must be lat,lon pairs (min 2)"})
            else:
                self._json(200, globe_feeds.get_route(_prof, _wps))
        elif path == "/api/osint/globe/github":
            # v1.19.0 GitHub Recon (design §5 item 9): thin read over
            # the daemon-side GitHub cache; the username is validated
            # inside github_recon, never a free-form URL.
            _qs = parse_qs(urlparse(self.path).query)
            _u = (_qs.get("u") or [""])[0]
            self._json(200, globe_feeds.github_recon(_u))
        elif path == "/api/osint/globe/launches":
            # v1.19.0 ROCKET counter (design §5 item 8): thin read
            # over the launches family cache (demand-driven refresh).
            self._json(200, globe_feeds.get_launches())
        elif path == "/api/osint/globe/news":
            # v1.19.0 NEWS via RSS (design §5 item 11): thin read over
            # the daemon-side RSS cache; items only from live outlets.
            self._json(200, globe_feeds.get_news())
        elif path == "/api/osint/globe/markets":
            # v1.20.0 MARKETS (design §6 + §14.4): thin read over the
            # daemon-side FRED/Coinbase/Stooq caches; optional
            # ?ticker=SYM is a direct-symbol Stooq lookup (no
            # autocomplete). No breadth row ever (K25); dollar is the
            # Fed Broad Index, never DXY.
            _qs = parse_qs(urlparse(self.path).query)
            _t = (_qs.get("ticker") or [""])[0]
            if _t:
                self._json(200, globe_feeds.get_ticker(_t))
            else:
                self._json(200, globe_feeds.get_markets())
        elif path == "/api/osint/globe/cloudmeta":
            # v1.21.0 NowCOAST clouds (OSIRIS-aligned): computed
            # server-side meta (hourly TIME steps); tiles themselves
            # are browser-direct from nowcoast.noaa.gov.
            self._json(200, globe_feeds.get_cloudmeta())
        elif path == "/api/osint/globe/windgrid":
            # v1.21.0 GFS wind grid (design §7 item 2b): cycle is
            # YYYYMMDDHH (00/06/12/18), fhour validated inside
            # get_windgrid (0-120 hourly, then 3-hourly to 384).
            # A failed step returns ok:false — the client keeps the
            # previous grid and the Open-Meteo point layer runs on.
            _qs = parse_qs(urlparse(self.path).query)
            _cy = (_qs.get("cycle") or [""])[0]
            try:
                _fh = int((_qs.get("fhour") or ["0"])[0])
            except (TypeError, ValueError):
                _fh = -1
            self._json(200, globe_feeds.get_windgrid(_cy, _fh))
        elif path == "/api/osint/globe/iss_telemetry":
            # v1.21.0 LIVE FROM SPACE telemetry (design §14.2):
            # ISS ALT/ORBIT from its own TLE via SGP4, no new host.
            self._json(200, globe_feeds.get_iss_telemetry())
        elif path == "/api/osint/globe/recon":
            # v1.23.0 TOOLS panel (design §14.1 + §16.4 + §16.5):
            # thin read over globe_recon.run_tool. Tool name is
            # allowlisted and the target locally validated inside
            # run_tool — user input never becomes a host or URL.
            # ?tool= &target= ; dataleaks needs &optin=1 ;
            # arcgis needs &keyword= &bbox=xmin,ymin,xmax,ymax.
            _qs = parse_qs(urlparse(self.path).query)
            _tool = (_qs.get("tool") or [""])[0]
            _target = (_qs.get("target") or [""])[0]
            _bbox = (_qs.get("bbox") or [""])[0]
            _extra = {
                "optin": (_qs.get("optin") or [""])[0] == "1",
                "keyword": (_qs.get("keyword") or [""])[0],
                "bbox": [v for v in _bbox.split(",")] if _bbox else [],
            }
            self._json(200, globe_recon.run_tool(_tool, _target,
                                                 _extra))
        elif path == "/api/osint/globe/fingerprint":
            # v1.23.0 FINGERPRINT (design §16.3): streaming NDJSON,
            # one line per site as it answers, then calibration
            # lines, then a summary line. Single-flight inside
            # globe_recon; a second concurrent run gets one busy
            # line. NOT a _json call: the response streams.
            _qs = parse_qs(urlparse(self.path).query)
            _u = (_qs.get("u") or [""])[0]
            if not globe_recon._RE_USER.match(_u or ""):
                self._json(200, {"ok": False, "tool": "fingerprint",
                                 "reason": "invalid username"})
            else:
                self._stream_ndjson(
                    globe_recon.fingerprint_stream(_u))
        elif path == "/api/scans":
            self._json(200, store.list_scans())
        elif path == "/api/stats":
            st = store.dashboard_stats()
            st.update(store.stats_extended())
            st["system"] = _system_info()
            self._json(200, st)
        elif path == "/api/findings":
            qs = parse_qs(urlparse(self.path).query)
            try:
                _lim = int((qs.get("limit") or [200])[0])
            except (TypeError, ValueError):
                _lim = 200
            self._json(200, store.list_findings_global(
                limit=max(1, min(1000, _lim)),
                severity=(qs.get("severity") or [""])[0],
                status=(qs.get("status") or [""])[0],
                q=(qs.get("q") or [""])[0]))
        elif path == "/api/engine":
            self._json(200, engine_info())
        elif path == "/api/assets":
            assets = store.assets_summary()
            meta = store.get_asset_meta()
            for a in assets:
                m = meta.get(a["target"]) or {}
                a["criticality"] = m.get("criticality", "medium")
                a["owner"] = m.get("owner", "")
            self._json(200, assets)
        elif path == "/api/insights":
            self._json(200, store.insights())
        elif path == "/api/metrics":
            self._json(200, {"jobs": GATE.snapshot(),
                             "canary": {"mode": CANARY["mode"], "base": CANARY["base"],
                                        "hits": len(CANARY["registry"].hits()) if CANARY.get("registry") else 0},
                             "nvd": store.cve_stats(), "nvd_sync": NVD_SYNC,
                             "audit_chain_ok": store.verify_audit_chain(),
                             "dashboard": store.dashboard_stats()})
        elif path == "/api/nvd/status":
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0][:80]
            self._json(200, {"cache": store.cve_stats(), "sync": NVD_SYNC,
                             "results": store.cve_search(q) if q else []})
        elif path == "/api/suppressions":
            self._json(200, {"suppressions": store.list_suppressions()})
        elif path == "/api/secrets":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
            else:
                self._json(200, {"secrets": store.secret_list()})
        elif path == "/api/tokens":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
            else:
                self._json(200, store.list_tokens())
        elif path == "/api/settings":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
            else:
                self._json(200, {"webhook_url": store.get_setting("webhook_url", ""),
                                 "secret_baseline": store.list_secret_baseline(),
                                 "nvd_sync": {
                                     "enabled": str(store.get_setting("nvd_sync_enabled", "0")) == "1",
                                     "interval_h": store.get_setting("nvd_sync_interval_h", "24"),
                                     "last_sync_ts": store.get_setting("nvd_last_sync_ts", ""),
                                     "last_sync_msg": store.get_setting("nvd_last_sync_msg", ""),
                                     "state": NVD_SYNC.get("state", "idle"),
                                     "message": NVD_SYNC.get("message", "")}})
        elif path == "/api/schedules":
            self._json(200, store.list_schedules())
        elif path == "/api/audit":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
            else:
                self._json(200, store.list_audit())
        elif path == "/api/users":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
            else:
                self._json(200, store.list_users())
        elif path.startswith("/api/job/"):
            job = JOBS.get(path.split("/")[-1])
            if not job:
                self._json(404, {"error": "job not found"})
            elif not _job_visible(job, sess):
                self._json(403, {"error": "not your job"})
            else:
                self._json(200, {"status": job["status"], "log": job["log"],
                                 "result": job["result"],
                                 "elapsed": round(time.time() - job["started"], 1)})
        elif path.startswith("/api/scan/") and path.endswith("/diff"):
            sid = path.split("/")[-2]
            d = store.diff_scans(sid)
            self._json(200 if d else 404, d or {"error": "not found"})
        elif path.startswith("/api/scan/") and path.endswith("/export"):
            sid = path.split("/")[-2]
            scan = store.get_scan(sid)
            if not scan:
                self._json(404, {"error": "not found"})
                return
            fmt = (parse_qs(urlparse(self.path).query).get("fmt") or ["json"])[0]
            findings = store.get_findings(sid)
            if fmt == "csv":
                buf = io.StringIO()
                w = csv.writer(buf)
                w.writerow(["severity", "confidence", "origin", "title", "location", "param",
                            "cwe", "owasp", "cvss", "evidence", "remediation"])
                for f in findings:
                    w.writerow([f.get(k, "") for k in
                                ("severity", "confidence", "origin", "title", "location", "param",
                                 "cwe", "owasp", "cvss", "evidence", "remediation")])
                self._send(200, buf.getvalue(), "text/csv",
                           [("Content-Disposition", f'attachment; filename="findings_{sid}.csv"')])
            else:
                self._send(200, json.dumps({"scan": {k: scan[k] for k in
                                ("id", "target", "scan_type", "profile", "overall_risk")},
                                "findings": findings}, indent=2, default=str),
                           "application/json",
                           [("Content-Disposition", f'attachment; filename="findings_{sid}.json"')])
        elif path.startswith("/api/scan/"):
            sid = path.split("/")[-1]
            scan = store.get_scan(sid)
            if not scan:
                self._json(404, {"error": "not found"})
            else:
                scan["summary"] = json.loads(scan["summary"] or "{}")
                full = json.loads(scan["result"] or "{}")
                scan["result"] = None
                self._json(200, {"scan": scan, "findings": store.get_findings(sid),
                                 "tool_result": full if scan["scan_type"] != "vulnscan" else None,
                                 "technologies": full.get("technologies", []),
                                 "tech_profile": full.get("tech_profile", full.get("technologies", [])),
                                 "risk_score": full.get("risk_score"),
                                 "duration_s": full.get("duration_s"),
                                 "summary_by_confidence": full.get("summary_by_confidence", {}),
                                 "engine": {"checks_run": full.get("checks_run"),
                                            "checks_total": full.get("checks_total"),
                                            "checks_detail": full.get("checks_detail", []),
                                            "method": full.get("method", ""),
                                            "http_stats": full.get("http_stats", {}),
                                            "warnings": full.get("warnings", []),
                                            "errors": full.get("errors", []),
                                            "cancelled": bool(full.get("cancelled", False)),
                                            "intercepted": bool(full.get("intercepted", False)),
                                            "intercept_reason": full.get("intercept_reason", "")},
                                 "meta": full.get("meta"),
                                 "endpoints": full.get("endpoints", [])})
        elif path.startswith("/report/"):
            sid = path.split("/")[-1]
            scan = store.get_scan(sid)
            if not scan:
                self._send(404, "<h1>404</h1>")
            else:
                scan["summary"] = json.loads(scan["summary"] or "{}")
                fmt = (parse_qs(urlparse(self.path).query).get("fmt") or ["html"])[0]
                # Bahasa laporan mengikuti bahasa UI peminta (?lang=xx);
                # absen/tidak valid -> en (perilaku lama).
                import report_i18n as _RI
                rlang = _RI.norm_lang(
                    (parse_qs(urlparse(self.path).query).get("lang") or ["en"])[0])
                if fmt == "docx":
                    import docx_report
                    fname = f"vanthex_report_{sid}.docx"
                    # Nama temp unik per request: dua unduhan DOCX untuk
                    # scan yang sama secara bersamaan tidak boleh saling
                    # menimpa/menghapus file satu sama lain.
                    _safe_sid = "".join(
                        ch for ch in sid
                        if ch.isalnum() or ch in "-_")[:40] or "scan"
                    fpath = os.path.join(
                        "/tmp", f"vanthex_report_{_safe_sid}_"
                                f"{secrets.token_hex(4)}.docx")
                    docx_report.generate_docx(scan, store.get_findings(sid), fpath, lang=rlang)
                    with open(fpath, "rb") as fh:
                        data = fh.read()
                    os.unlink(fpath)
                    self._send(200, data,
                               "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                               [("Content-Disposition", f'attachment; filename="{fname}"')])
                else:
                    self._send(200, render_report(scan, store.get_findings(sid), lang=rlang))
        else:
            self._send(404, "<h1>404</h1>")

    # ---------------- POST ----------------
    def do_POST(self):
        try:
            self._do_POST()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            import traceback
            traceback.print_exc()
            try:
                self._json(500, {"error": "internal error"})
            except Exception:
                pass

    def _do_POST(self):
        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            length = -1
        if length < 0:
            # Content-Length negatif akan membuat rfile.read() menunggu
            # sampai EOF — tolak sebelum membaca apa pun.
            self._json(400, {"error": "invalid Content-Length"})
            return
        # Batas ukuran body per route (anti memory-exhaustion): endpoint JSON
        # biasa kecil; hanya analisis APK yang sah menerima puluhan MB.
        cap = 100 * 1024 * 1024 if path in ("/api/mobile/analyze", "/actions") else 2 * 1024 * 1024
        if length > cap:
            self.close_connection = True
            self._json(413, {"error": f"request body too large (max {cap // (1024 * 1024)} MB)"})
            return
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._json(400, {"error": "bad json"})
            return

        if path == "/api/login":
            ip = self.client_address[0]
            # Penundaan progresif (bukan lockout): kegagalan beruntun
            # memperlambat respons, tetapi password yang benar selalu
            # diproses — operator tidak bisa terkunci dari deploy-nya
            # sendiri oleh kegagalan login dari IP yang sama.
            _delay = login_delay(ip)
            if _delay:
                time.sleep(_delay)
            u = store.verify_user(str(payload.get("username", ""))[:60],
                                  str(payload.get("password", ""))[:128])
            if not u:
                LOGIN_FAILS.setdefault(ip, []).append(time.time())
                store.audit(str(payload.get("username", ""))[:60], "login_failed", f"ip={ip}")
                self._json(401, {"error": "invalid credentials"})
                return
            LOGIN_FAILS.pop(ip, None)
            store.audit(u["username"], "login", f"ip={ip}")
            # Pangkas sesi kedaluwarsa secara oportunistik agar dict
            # sesi tidak tumbuh tanpa batas di proses berumur panjang.
            _now = time.time()
            for _t in [t for t, s in SESSIONS.items() if s["exp"] <= _now]:
                SESSIONS.pop(_t, None)
            tok = secrets.token_hex(24)
            SESSIONS[tok] = {"user": u["username"], "role": u["role"],
                             "exp": time.time() + SESSION_TTL}
            secure = "; Secure" if os.environ.get("PTK_COOKIE_SECURE") == "1" else ""
            self._json(200, {"ok": True}, [("Set-Cookie",
                        f"ptk_session={tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}{secure}")])
            return

        tok, sess = self._session()
        if not sess:
            self._json(401, {"error": "unauthorized"})
            return

        if path == "/actions":
            if sess.get("role") != "admin" or not ACTIONS_OK:
                self._json(403, {"error": "forbidden"})
                return
            name = str(payload.get("action", ""))
            aargs = payload.get("args")
            if not isinstance(aargs, dict):
                aargs = {}
            try:
                code, envelope = actions_mod.handle_action(
                    name, aargs, self.server.server_address[1])
            except Exception:
                # Detail pengecualian (path internal, dsb.) hanya ke
                # log server; klien menerima pesan generik.
                import traceback
                traceback.print_exc()
                self._json(500, {"error": "internal error"})
                return
            extra = []
            if name == "logout":
                # A real sign-out: invalidate the caller's own browser
                # session as well, not only the actions layer's internal
                # one, and clear its cookie.
                SESSIONS.pop(tok, None)
                extra = [("Set-Cookie",
                          "ptk_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict")]
            self._json(code, envelope, extra)
            return

        if path == "/api/logout":
            SESSIONS.pop(tok, None)
            self._json(200, {"ok": True},
                       [("Set-Cookie", "ptk_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict")])
        elif path.startswith("/api/job/") and path.endswith("/cancel"):
            job = JOBS.get(path.split("/")[-2])
            if not job:
                self._json(404, {"error": "job not found"})
            elif not _job_visible(job, sess):
                self._json(403, {"error": "not your job"})
            else:
                job["cancel"] = True
                self._json(200, {"ok": True, "cancelling": True})
        elif path == "/api/scan":
            target = str(payload.get("target", "")).strip()[:300]
            stype = payload.get("type", "vulnscan")
            profile = payload.get("profile", "active-deep")
            if stype == "osint" and not target and payload.get("query"):
                # Universal OSINT: the free-text query IS the subject
                # (person name, institution, domain, email, handle, IP).
                # It is stored as the scan target so history, reports
                # and suppression keep working unchanged.
                target = str(payload["query"]).strip()[:300]
            if stype not in SCAN_TYPES or not target:
                self._json(400, {"error": f"type must be one of {SCAN_TYPES} + target is required"})
                return
            host = host_of(target)
            if stype == "osint":
                # The domain allowlist only applies when the query
                # itself carries a host (domain / IP / email domain).
                # Name and handle queries are not domain targets and
                # must never be blocked by it.
                host = osint_mod.query_subject_host(target)
            if not allowed_target(host):
                self._json(403, {"error": f"host {host} outside PTK_ALLOWED_TARGETS"})
                return
            is_active = ((stype != "vulnscan") or not profile.startswith("passive")) and stype not in ("passive", "osint")
            if is_active and payload.get("authorized") is not True:
                self._json(400, {"error": 'active scans require authorization confirmation (authorized=true) — tick the authorization statement in the UI'})
                return
            # bersihkan job lama yang selesai (>30 mnt) agar memori tidak bocor
            now = time.time()
            for jid in [j for j, jb in JOBS.items()
                        if jb["status"] in ("done", "error", "cancelled") and now - jb["started"] > 1800]:
                JOBS.pop(jid, None)
            job_id = secrets.token_hex(6)
            job = {"status": "queued", "log": [], "result": None,
                   "started": time.time(), "cancel": False,
                   "user": sess["user"],
                   "priority": 0 if payload.get("priority") == "high" else 1}
            JOBS[job_id] = job
            store.audit(sess["user"], "scan_start", f"{stype} {profile} {target}")

            def worker():
                try:
                    if not GATE.acquire(priority=job["priority"],
                                        user=job["user"],
                                        cancelled=lambda: job["cancel"]):
                        job["status"] = "cancelled"
                        return
                    job["status"] = "running"
                    try:
                        sensitive = []
                        if payload.get("secret_id2"):
                            patch_b, sensitive_b = _secret_injection(
                                payload["secret_id2"])
                            if patch_b:
                                payload["auth_b"] = patch_b
                                sensitive = sensitive + list(sensitive_b)
                                store.audit(job["user"], "secret_use",
                                            f"secret#{payload['secret_id2']} (account B) -> {target}")
                                job["log"].append(
                                    "[auth] second-account credential applied "
                                    f"(secret #{payload['secret_id2']}) — BOLA matrix enabled")
                        if payload.get("secret_id"):
                            patch, sensitive = _secret_injection(
                                payload["secret_id"])
                            for k, v in patch.items():
                                if k == "headers":
                                    cur = dict(payload.get("headers") or {})
                                    cur.update(v)
                                    payload["headers"] = cur
                                else:
                                    payload[k] = v
                            if patch:
                                store.audit(job["user"], "secret_use",
                                            f"secret#{payload['secret_id']} -> {target}")
                                job["log"].append(
                                    "[auth] target credential applied from vault "
                                    f"(secret #{payload['secret_id']})")
                        result = run_tool_scan(payload, target, stype, profile, job)
                        if result is not None and sensitive:
                            result, nred = _redact_result(result, sensitive)
                            if nred:
                                job["log"].append(
                                    f"[auth] redacted {nred} credential occurrence(s) from result")
                        if result is not None:
                            result = _apply_suppressions(result, target)
                            if result.get("suppressed_count"):
                                job["log"].append(
                                    f"[suppression] {result['suppressed_count']} finding(s) suppressed by target rules")
                            _eff = result.get("effective_target") or target
                            if _eff != target:
                                job["log"].append(
                                    f"[init] effective target being scanned: {_eff}")
                            result["scan_id"] = store.save_scan(
                                _eff, stype, result.get("profile", profile), result)
                            _bsupp = [f for f in result.get("findings", [])
                                      if f.get("baseline_suppressed")]
                            if _bsupp:
                                job["log"].append(
                                    f"[baseline] {len(_bsupp)} secret finding(s) matched the operator baseline — kept, status suppressed (baseline)")
                                store.audit(job["user"],
                                            "secret_baseline_suppress",
                                            f"{len(_bsupp)} finding(s) in scan "
                                            f"{result['scan_id']}: "
                                            + ", ".join(
                                                (f["baseline_suppressed"].get("label") or "?")[:40]
                                                for f in _bsupp[:5]))
                            job["result"] = result
                            _fire_webhook(result["scan_id"], target, result)
                        job["status"] = "cancelled" if job["cancel"] else "done"
                    finally:
                        GATE.release(job["user"])
                except Exception as e:
                    job["log"].append(f"[fatal] {str(e)[:200]}")
                    job["result"] = {"error": str(e)[:300]}
                    job["status"] = "error"

            threading.Thread(target=worker, daemon=True).start()
            self._json(200, {"job_id": job_id})
        elif path == "/api/mobile/analyze":
            # Analisis statis APK (v3.3): file diunggah sebagai base64 JSON,
            # dianalisis engine mobile.py (build sendiri + androguard), lalu
            # hasilnya disimpan sebagai scan tipe "mobile" — temuan masuk
            # pipeline Findings/triage/laporan yang sama dengan scan web.
            fname = os.path.basename(str(payload.get("filename", "app.apk"))[:120]) or "app.apk"
            if not fname.lower().endswith((".apk", ".ipa")):
                self._json(400, {"error": 'the file must have an .apk or .ipa extension'})
                return
            try:
                data = base64.b64decode(str(payload.get("data_base64", "")), validate=True)
            except Exception:
                self._json(400, {"error": 'invalid data_base64'})
                return
            if not data or len(data) > 60 * 1024 * 1024:
                self._json(400, {"error": 'invalid package size (max 60 MB)'})
                return
            os.makedirs("uploads_apk", exist_ok=True)
            fpath = os.path.join("uploads_apk",
                                 f"{int(time.time())}-{secrets.token_hex(3)}-{fname}")
            with open(fpath, "wb") as fh:
                fh.write(data)
            job_id = secrets.token_hex(6)
            job = {"status": "queued",
                   "log": [f"[mobile] received {fname} ({len(data)} byte)"],
                   "result": None, "started": time.time(), "cancel": False,
                   "user": sess["user"], "priority": 1}
            JOBS[job_id] = job
            store.audit(sess["user"], "mobile_analyze", fname)

            def mworker():
                _acquired = False
                try:
                    if not GATE.acquire(priority=1, user=job["user"],
                                        cancelled=lambda: job["cancel"]):
                        job["status"] = "cancelled"
                        return
                    _acquired = True
                    job["status"] = "running"
                    job["log"].append("[mobile] analyzing in sandbox "
                                      "(isolated subprocess, CPU/RAM limits)")
                    result = sandbox_mod.analyze_package_sandboxed(
                        fpath, fname, log=job["log"],
                        baseline=store.list_secret_baseline())
                    result["scan_id"] = store.save_scan(
                        result["target"], "mobile", result.get("profile", "apk-static"), result)
                    job["result"] = result
                    _fire_webhook(result["scan_id"], result["target"], result)
                    job["status"] = "done"
                except Exception as e:
                    job["log"].append(f"[fatal] {str(e)[:200]}")
                    job["result"] = {"error": str(e)[:300]}
                    job["status"] = "error"
                finally:
                    # Lepas slot HANYA bila benar-benar diperoleh: job
                    # yang batal saat mengantre tidak memegang slot —
                    # melepasnya menggelembungkan kapasitas gate
                    # melewati batas global/per-user yang ditetapkan.
                    if _acquired:
                        GATE.release(job["user"])
                    try:
                        os.unlink(fpath)
                    except Exception:
                        pass

            threading.Thread(target=mworker, daemon=True).start()
            self._json(200, {"job_id": job_id})
        elif path == "/api/scan/delete":
            sid = str(payload.get("scan_id", ""))[:24]
            if not sid or not store.get_scan(sid):
                self._json(404, {"error": "scan not found"})
            else:
                store.audit(sess["user"], "scan_delete", sid)
                store.delete_scan(sid)
                self._json(200, {"ok": True, "deleted": sid})
        elif path == "/api/finding/status":
            try:
                ok = store.set_finding_status(int(payload.get("finding_id", 0)),
                                              str(payload.get("status", "")))
                if not ok:
                    self._json(404, {"error": "finding not found"})
                else:
                    store.audit(sess["user"], "finding_status",
                                f"#{payload.get('finding_id')} -> {payload.get('status')}")
                    self._json(200, {"ok": True})
            except Exception as e:
                self._json(400, {"error": str(e)[:150]})
        elif path == "/api/finding/update":
            try:
                ok = store.update_finding(
                    int(payload.get("finding_id", 0)),
                    status=payload.get("status"),
                    assignee=payload.get("assignee"),
                    due_date=payload.get("due_date"))
                if not ok:
                    self._json(404, {"error": "finding not found"})
                else:
                    store.audit(sess["user"], "finding_update",
                                f"#{payload.get('finding_id')}")
                    self._json(200, {"ok": True})
            except Exception as e:
                self._json(400, {"error": str(e)[:150]})
        elif path == "/api/assets/meta":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
                return
            try:
                store.set_asset_meta(str(payload.get("host", "")),
                                     str(payload.get("criticality", "medium")),
                                     str(payload.get("owner", "")))
                store.audit(sess["user"], "asset_meta", str(payload.get("host", ""))[:80])
                self._json(200, {"ok": True})
            except Exception as e:
                self._json(400, {"error": str(e)[:150]})
        elif path == "/api/assets/delete":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
                return
            try:
                host = str(payload.get("host", ""))
                if not host:
                    self._json(400, {"error": "host required"})
                    return
                counts = store.delete_asset(host)
                store.audit(sess["user"], "asset_delete",
                            f"{host[:60]} scans={counts['scans']} "
                            f"findings={counts['findings']}")
                self._json(200, {"ok": True, **counts})
            except Exception as e:
                self._json(400, {"error": str(e)[:150]})
        elif path == "/api/settings":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
                return
            # Only keys actually present in the payload are updated —
            # a partial save (e.g. the NVD schedule panel) must never
            # wipe an unrelated setting.
            _changed = []
            if "webhook_url" in payload:
                store.set_setting("webhook_url", str(payload.get("webhook_url", ""))[:500])
                _changed.append("webhook_url")
            if "nvd_sync_enabled" in payload:
                store.set_setting("nvd_sync_enabled",
                                  "1" if payload.get("nvd_sync_enabled") else "0")
                _changed.append("nvd_sync_enabled")
            if "nvd_sync_interval_h" in payload:
                try:
                    _h = int(payload.get("nvd_sync_interval_h", 24))
                except Exception:
                    _h = 24
                store.set_setting("nvd_sync_interval_h",
                                  str(min(168, max(1, _h))))
                _changed.append("nvd_sync_interval_h")
            store.audit(sess["user"], "settings_update",
                        ",".join(_changed) or "none")
            self._json(200, {"ok": True})
        elif path == "/api/settings/baseline":
            # WS5 (v1.7.0): add an operator secret-baseline entry. The
            # raw value is hashed (SHA-256) on receipt and DISCARDED —
            # only the hash + label + reason are stored or audited.
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
                return
            _val = str(payload.get("value", ""))
            if len(_val) < 8:
                self._json(400, {"error": "value too short to baseline"})
                return
            import hashlib as _hl
            _h = _hl.sha256(_val.encode("utf-8", "replace")).hexdigest()
            store.add_secret_baseline(
                _h, str(payload.get("kind", "")),
                str(payload.get("label", ""))[:120] or "baseline entry",
                str(payload.get("reason", ""))[:300], sess["user"])
            store.audit(sess["user"], "secret_baseline_add",
                        f"sha256 {_h[:12]} label="
                        f"{str(payload.get('label', ''))[:60]}")
            self._json(200, {"ok": True, "hash": _h,
                             "baseline": store.list_secret_baseline()})
        elif path == "/api/settings/baseline/remove":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
                return
            _h = str(payload.get("hash", ""))
            _ok = store.remove_secret_baseline(_h)
            store.audit(sess["user"], "secret_baseline_remove",
                        f"sha256 {_h[:12]} removed={_ok}")
            self._json(200, {"ok": _ok,
                             "baseline": store.list_secret_baseline()})
        elif path == "/api/tokens":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
                return
            raw = store.create_token(str(payload.get("name", "token"))[:60], sess["user"])
            store.audit(sess["user"], "token_create", str(payload.get("name", ""))[:60])
            self._json(200, {"token": raw,
                             "note": "Save it now — the token is shown only once."})
        elif path == "/api/nvd/sync":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
            elif NVD_SYNC["state"] == "running":
                self._json(409, {"error": "NVD sync already running"})
            else:
                store.audit(sess["user"], "nvd_sync", "start")
                threading.Thread(target=_do_nvd_sync, args=("manual",),
                                 daemon=True).start()
                self._json(200, {"started": True})
        elif path == "/api/suppressions":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
                return
            host_v = str(payload.get("host", ""))[:120]
            title_v = str(payload.get("title", ""))[:200]
            if not title_v:
                self._json(400, {"error": "title is required"})
            else:
                sid = store.add_suppression(host_v, title_v, sess["user"])
                store.audit(sess["user"], "suppression_add",
                            f"{host_v} | {title_v}")
                self._json(200, {"ok": True, "id": sid})
        elif path == "/api/secrets":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
            else:
                kind = str(payload.get("kind", ""))[:12]
                val = str(payload.get("secret", ""))
                name = str(payload.get("name", "")).strip()
                if kind not in ("bearer", "cookie", "basic") or not val or not name:
                    self._json(400, {"error": "name, a valid kind (bearer/cookie/basic) and secret are required"})
                else:
                    sid = store.secret_create(
                        name, str(payload.get("host", "")),
                        kind, str(payload.get("username", "")),
                        secretsmgr.encrypt(val), sess["user"])
                    store.audit(sess["user"], "secret_create", f"#{sid} {name} ({kind})")
                    self._json(200, {"ok": True, "id": sid})
        elif path == "/api/secrets/delete":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
            else:
                try:
                    store.secret_delete(int(payload.get("id", 0)))
                    store.audit(sess["user"], "secret_delete", str(payload.get("id")))
                    self._json(200, {"ok": True})
                except Exception as e:
                    self._json(400, {"error": str(e)[:150]})
        elif path == "/api/suppressions/delete":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
                return
            try:
                store.delete_suppression(int(payload.get("id", 0)))
                store.audit(sess["user"], "suppression_delete",
                            str(payload.get("id")))
                self._json(200, {"ok": True})
            except Exception as e:
                self._json(400, {"error": str(e)[:150]})
        elif path == "/api/tokens/delete":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
                return
            ok = store.delete_token(int(payload.get("id", 0)))
            store.audit(sess["user"], "token_delete", str(payload.get("id")))
            self._json(200 if ok else 404, {"ok": ok})
        elif path == "/api/schedules":
            target = str(payload.get("target", "")).strip()[:300]
            profile = str(payload.get("profile", "passive-full"))
            if not target or payload.get("authorized") is not True:
                self._json(400, {"error": 'target + authorization confirmation are required for a scheduled scan'})
                return
            if profile not in vulnscan2.PROFILES:
                self._json(400, {"error": 'unknown profile'})
                return
            if not allowed_target(host_of(target)):
                self._json(403, {"error": 'target outside the allowlist'})
                return
            try:
                interval = max(1.0, min(24 * 30.0,
                                        float(payload.get("interval_h", 24))))
            except (TypeError, ValueError):
                self._json(400, {"error": "interval_h must be a number"})
                return
            sid = store.create_schedule(target, profile, interval, sess["user"])
            store.audit(sess["user"], "schedule_create", f"{target} {profile} every {interval} h")
            self._json(200, {"ok": True, "schedule_id": sid})
        elif path == "/api/schedules/delete":
            store.delete_schedule(str(payload.get("schedule_id", ""))[:20])
            store.audit(sess["user"], "schedule_delete", str(payload.get("schedule_id", ""))[:20])
            self._json(200, {"ok": True})
        elif path == "/api/schedules/toggle":
            store.set_schedule_enabled(str(payload.get("schedule_id", ""))[:20],
                                       bool(payload.get("enabled")))
            self._json(200, {"ok": True})
        elif path == "/api/users":
            if sess["role"] != "admin":
                self._json(403, {"error": "admin only"})
                return
            try:
                store.create_user(str(payload.get("username", ""))[:60],
                                  str(payload.get("password", ""))[:128])
                store.audit(sess["user"], "user_create", str(payload.get("username", ""))[:60])
                self._json(200, {"ok": True})
            except Exception as e:
                self._json(400, {"error": str(e)[:200]})
        else:
            self._json(404, {"error": "not found"})


def _secret_injection(secret_id):
    """Bangun injeksi kredensial dari vault untuk satu scan.
    Mengembalikan (patch_payload, [nilai_sensitif]) — nilai hanya hidup
    di memori worker dan dipakai untuk redaksi hasil; tidak pernah
    ditulis ke log/DB."""
    try:
        row = store.secret_get(int(secret_id))
    except Exception:
        return {}, []
    if not row:
        return {}, []
    val = secretsmgr.decrypt(row["secret_enc"])
    if row["kind"] == "bearer":
        return {"headers": {"Authorization": f"Bearer {val}"}}, [val]
    if row["kind"] == "cookie":
        return {"cookie": val}, [val]
    if row["kind"] == "basic":
        import base64 as _b64
        tok = _b64.b64encode(
            f"{row['username']}:{val}".encode()).decode()
        return {"headers": {"Authorization": f"Basic {tok}"}}, [val, tok]
    return {}, []


def _redact_result(result, sensitive):
    """Bila target memantulkan kredensial (mis. di evidence), samarkan
    sebelum hasil disimpan/ditampilkan."""
    vals = [v for v in sensitive if v and len(v) >= 4]
    if not vals or not result:
        return result, 0
    import json as _json
    blob = _json.dumps(result)
    n = 0
    for v in vals:
        n += blob.count(v)
        blob = blob.replace(v, "***")
    if n:
        return _json.loads(blob), n
    return result, 0


def _job_visible(job, sess):
    """Job hanya terlihat/dikendalikan pemiliknya atau admin (audit v3.18.1)."""
    return (sess["role"] == "admin" or not job.get("user")
            or job.get("user") == sess["user"])


def _apply_suppressions(result, target):
    """Terapkan aturan suppression per target (Fase 2): temuan yang cocok
    dikeluarkan dari daftar, dihitung transparan di result['suppressed']."""
    if not result or not result.get("findings"):
        return result
    host = host_of(target)
    kept, dropped = [], []
    for f in result["findings"]:
        if store.is_suppressed(host, f.get("title", "")):
            dropped.append(f.get("title", ""))
        else:
            kept.append(f)
    if dropped:
        result["findings"] = kept
        result["suppressed"] = dropped[:50]
        result["suppressed_count"] = len(dropped)
        summ = {}
        for f in kept:
            summ[f["severity"]] = summ.get(f["severity"], 0) + 1
        result["summary"] = summ
        result["risk_score"] = vulnscan2.risk_score(kept)
        result["overall_risk"] = (
            "CRITICAL" if summ.get("CRITICAL") else
            "HIGH" if summ.get("HIGH") else
            "MEDIUM" if summ.get("MEDIUM") else
            "LOW" if summ.get("LOW") else "NONE")
    return result


def run_tool_scan(payload, target, stype, profile, job):
    """Jalankan satu scan (vulnscan atau tool klasik) dan kembalikan result dict."""
    log = job["log"]
    cancelled = lambda: job["cancel"]
    if stype == "vulnscan":
        opts = {}
        hdrs = payload.get("headers") or {}
        if isinstance(hdrs, dict):
            opts["headers"] = {str(k)[:60]: str(v)[:300] for k, v in list(hdrs.items())[:10]}
        if payload.get("cookie"):
            opts["cookie"] = str(payload["cookie"])[:1000]
        if payload.get("proxy"):
            opts["proxy"] = str(payload["proxy"])[:300]
        if payload.get("timeout"):
            opts["timeout"] = max(2.0, min(20.0, float(payload["timeout"])))
        if payload.get("max_pages"):
            opts["max_pages"] = max(5, min(80, int(payload["max_pages"])))
        _can = _canary_opts()
        if _can:
            opts["canary"] = _can
        try:
            _bl = store.list_secret_baseline()
            if _bl:
                opts["secret_baseline"] = _bl
        except Exception:
            pass
        if payload.get("auth_b"):
            opts["auth_b"] = payload["auth_b"]
        if payload.get("headless"):
            opts["headless"] = True
        return vulnscan2.run_vulnscan(target, profile, log=log, opts=opts,
                                      cancelled=cancelled)
    host = host_of(target)
    if stype == "ports":
        raw = str(payload.get("ports", "")).strip()
        ports = None
        if raw:
            ports = []
            for part in raw.replace(" ", "").split(","):
                if "-" in part:
                    a, b = part.split("-", 1)
                    ports.extend(range(int(a), int(b) + 1))
                elif part:
                    ports.append(int(part))
            ports = ports[:2000]
        log.append(f"[ports] scan {host} ({len(ports) if ports else len(scanners.COMMON_PORTS)} port)")
        det = scanners.tcp_scan_detailed(host, ports)
        open_ports = det["open"]
        findings = []
        if det["intercepted"]:
            log.append(f"[ports] WARNING: TCP egress is intercepted ({det['intercept_reason']}) — the results do NOT reflect the target")
            log.append("[ports] intercepted: 0 ports reported — the raw connect results were discarded as inconclusive")
            findings = [{
                "severity": "INFO",
                "title": "Port scan inconclusive — direct TCP egress from this host is intercepted",
                "description": "Every connection was answered by an intercepting gateway instead of the target, so no port state could be measured. Run the port scan from a network with direct egress (for example the standalone package on your own machine) for a trustworthy result.",
                "evidence": det["intercept_reason"], "cwe": "", "owasp": "",
                "cvss": 0.0,
                "remediation": "Re-run the port scan from an unintercepted network position.",
                "confidence": "confirmed", "location": target, "param": "",
                "origin": "active"}]
            open_ports = []
        else:
            log.append(f"[ports] open: {[p['port'] for p in open_ports]} verified: {[p['port'] for p in open_ports if p.get('verified')]}")
        return {"type": "ports", "target": target, "profile": "ports",
                "open_ports": open_ports, "intercepted": det["intercepted"],
                "intercept_reason": det["intercept_reason"],
                "findings": findings,
                "summary": {}, "overall_risk": "-"}
    if stype == "passive":
        log.append(f"[passive] passive recon for {target}")
        return passive_mod.run_passive_recon(target, log)
    if stype == "osint":
        oopts = {}
        if payload.get("query"):
            oopts["query"] = str(payload["query"])[:300]
            log.append(f"[osint] universal OSINT query: {oopts['query']}")
        else:
            log.append(f"[osint] deep OSINT for {target}")
        if payload.get("handle"):
            oopts["handle"] = str(payload["handle"])[:80]
        if payload.get("breach") is True:
            oopts["breach"] = True
            if payload.get("breach_secret_id"):
                # API key comes from the vault only; the value lives in
                # the worker's memory and is never logged or stored.
                try:
                    row = store.secret_get(int(payload["breach_secret_id"]))
                    if row:
                        oopts["breach_api_key"] = secretsmgr.decrypt(
                            row["secret_enc"])
                except Exception:
                    log.append("[osint] breach API key could not be loaded from the vault")
        return osint_mod.run_osint_recon(target, log, oopts,
                                         cancelled=cancelled)
    if stype == "subdomains":
        subs = payload.get("subs") or scanners.DEFAULT_SUBS
        subs = [str(s)[:60] for s in subs][:300]
        log.append(f"[subs] enum {len(subs)} candidates on {host}")
        res = scanners.resolve_subdomain(host, subs)
        found = res["found"]
        findings = []
        if res["inconclusive"]:
            log.append(f"[subs] inconclusive: {res['reason']}")
            findings = [{
                "severity": "INFO",
                "title": "Subdomain enumeration inconclusive — DNS answers from this host cannot be trusted",
                "description": "The local resolver fabricates answers for nonexistent names and DNS-over-HTTPS was unreachable, so no subdomain verdict could be measured instead of guessed.",
                "evidence": res["reason"], "cwe": "", "owasp": "",
                "cvss": 0.0,
                "remediation": "Re-run when DNS-over-HTTPS is reachable or from a host with a real resolver.",
                "confidence": "confirmed", "location": target, "param": "",
                "origin": "active"}]
        else:
            if res["wildcard_ips"]:
                log.append(f"[subs] resolver: {res['resolver']} — wildcard DNS detected (IPs {res['wildcard_ips']}); wildcard answers filtered out")
            else:
                log.append(f"[subs] resolver: {res['resolver']}")
            log.append(f"[subs] found {len(found)}")
        return {"type": "subdomains", "target": target, "profile": "subdomains",
                "found": found, "findings": findings,
                "summary": {}, "overall_risk": "-"}
    if stype == "dirs":
        words = payload.get("words") or scanners.DEFAULT_WORDLIST
        words = [str(w)[:80] for w in words][:300]
        eff = target
        if "://" not in target:
            eff, _note = netclient.resolve_scheme_target(target)
            log.append(f"[dirs] effective target: {eff} ({_note})")
        log.append(f"[dirs] probe {len(words)} paths on {eff}")
        results = scanners.http_probe(eff, words)
        hits = [r for r in results if r["status"] and r["status"] != 404
                and not r.get("catch_all")]
        caught = [r for r in results if r.get("catch_all")]
        errors = [r for r in results if not r["status"]]
        findings = []
        if results and len(errors) == len(results):
            log.append("[dirs] target unreachable — 0 hits is NOT a clean result (inconclusive)")
            findings = [{
                "severity": "INFO",
                "title": "Directory discovery inconclusive — target unreachable",
                "description": "No probe received any response, so an empty result cannot be read as 'no directories exist'.",
                "evidence": "all probes failed to connect", "cwe": "",
                "owasp": "", "cvss": 0.0,
                "remediation": "Verify the target URL/scheme and re-run.",
                "confidence": "confirmed", "location": target, "param": "",
                "origin": "active"}]
        else:
            log.append(f"[dirs] {len(hits)} paths responded non-404"
                       + (f"; {len(caught)} catch-all responses filtered out"
                          if caught else ""))
        return {"type": "dirs", "target": target, "profile": "dirs",
                "results": hits, "findings": findings,
                "summary": {}, "overall_risk": "-"}
    if stype == "ssl":
        res = scanners.ssl_audit(host)
        log.append(f"[ssl] audit {host}:443 -> ok={res.get('ok')}")
        ciphers = {}
        try:
            ciphers = scanners.tls_cipher_audit(host)
        except Exception as e:
            log.append(f"[ssl] cipher enumeration failed: {str(e)[:120]}")
        finds = []
        for dep in ciphers.get("deprecated", []):
            finds.append(vulnscan2.F(
                "MEDIUM", f"Deprecated TLS protocol enabled: {dep.replace('_', '.').upper()}",
                "The server accepts a deprecated TLS version that no longer provides adequate security (POODLE/BEAST class weaknesses, no AEAD requirement).",
                f"Handshake succeeded for {dep}", "CWE-327",
                "A02:2021 Cryptographic Failures",
                remed="Disable TLS 1.0/1.1; serve TLS 1.2+ only.",
                location=f"https://{host}:443", confidence="confirmed"))
        if ciphers.get("weak"):
            names = ", ".join(sorted({w["cipher"] for w in ciphers["weak"]}))
            finds.append(vulnscan2.F(
                "MEDIUM", "Weak TLS cipher suites supported",
                "The server accepts cipher suites considered weak (RC4/3DES/DES/NULL/EXPORT/MD5 or anonymous DH).",
                f"Weak ciphers accepted: {names}", "CWE-327",
                "A02:2021 Cryptographic Failures",
                remed="Restrict the cipher list to AEAD suites (GCM/ChaCha20) with forward secrecy.",
                location=f"https://{host}:443", confidence="confirmed"))
        log.append(f"[ssl] protocols: {ciphers.get('protocols')} weak: {len(ciphers.get('weak', []))}")
        summ = {}
        for f in finds:
            summ[f["severity"]] = summ.get(f["severity"], 0) + 1
        return {"type": "ssl", "target": target, "profile": "ssl", **res,
                "ciphers": ciphers, "findings": finds, "summary": summ,
                "overall_risk": "MEDIUM" if finds else "-"}
    if stype == "headers":
        eff_h = target
        if "://" not in target:
            eff_h, _hnote = netclient.resolve_scheme_target(target)
            log.append(f"[headers] effective target: {eff_h} ({_hnote})")
        res = scanners.header_audit(eff_h)
        log.append(f"[headers] score {res.get('score')}")
        # Findings mirror vulnscan2.c_security_headers exactly (same titles,
        # severities, CWE, CVSS, remediation) so a typed headers scan and a
        # vulnscan never disagree about the same response. Before this fix
        # the branch discarded them all ("findings": []) and an unreachable
        # target silently looked clean.
        _HDR_RULES = {
            "strict-transport-security": ("MEDIUM", "CWE-319", 5.9,
                "Enable HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
            "content-security-policy": ("MEDIUM", "CWE-79", 5.4,
                "Add a CSP that restricts script/style sources."),
            "x-frame-options": ("LOW", "CWE-1021", 4.3,
                "Set X-Frame-Options: DENY/SAMEORIGIN or frame-ancestors in CSP."),
            "x-content-type-options": ("LOW", "CWE-430", 3.1,
                "Set X-Content-Type-Options: nosniff."),
            "referrer-policy": ("LOW", "CWE-200", 2.7,
                "Set Referrer-Policy: strict-origin-when-cross-origin."),
            "permissions-policy": ("LOW", "CWE-693", 2.7,
                "Restrict browser APIs via Permissions-Policy."),
        }
        hfinds = []
        if not res.get("ok"):
            hfinds.append(vulnscan2.F(
                "INFO", "Header audit inconclusive \u2014 target unreachable",
                "No response was received, so an empty header result cannot be read as 'all headers present'.",
                res.get("error", "no response"), "", "",
                remed="Verify the target URL/scheme and re-run.",
                location=eff_h, confidence="confirmed"))
        else:
            https_h = eff_h.lower().startswith("https://")
            present_h = ", ".join(sorted(res.get("headers", {}))) or "none"
            for miss in res.get("missing", []):
                name = miss.lower()
                if name == "strict-transport-security" and not https_h:
                    continue
                rule = _HDR_RULES.get(name)
                if not rule:
                    continue
                sev, cwe, cvss, remed = rule
                hfinds.append(vulnscan2.F(
                    sev, f"Security header not set: {name}",
                    f"Header {name} not found in the response. {remed}",
                    f"Response headers present: {present_h}", cwe,
                    "A05:2021 Security Misconfiguration",
                    cvss=cvss, remed=remed, location=eff_h,
                    confidence="confirmed"))
        hsumm = {}
        for f in hfinds:
            hsumm[f["severity"]] = hsumm.get(f["severity"], 0) + 1
        _rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        hoverall = max((f["severity"] for f in hfinds),
                       key=lambda s: _rank.get(s, 0), default="-")
        log.append(f"[headers] findings: {len(hfinds)}")
        return {"type": "headers", "target": target, "profile": "headers", **res,
                "findings": hfinds, "summary": hsumm,
                "overall_risk": hoverall}
    if stype == "udp":
        res = scanners.udp_scan(host)
        finds = []
        for o in res["open"]:
            if o["service"] == "snmp":
                finds.append(vulnscan2.F(
                    "HIGH", "SNMP service responds to the 'public' community string",
                    "The SNMP agent answered an SNMPv1 GetRequest using the default 'public' community, which grants unauthenticated read access to device information.",
                    f"UDP {o['port']}: {o['evidence']}", "CWE-798",
                    "A05:2021 Security Misconfiguration",
                    remed="Disable SNMPv1, use SNMPv3 with authentication, and change default community strings.",
                    location=f"udp://{host}:{o['port']}", confidence="confirmed"))
            else:
                finds.append(vulnscan2.F(
                    "INFO", f"UDP service responding: {o['service']} ({o['port']})",
                    "A UDP service answered the protocol probe.",
                    f"UDP {o['port']}: {o['evidence']}", "", "",
                    remed="Confirm the service is intended to be exposed.",
                    location=f"udp://{host}:{o['port']}", confidence="confirmed"))
        if res.get("inconclusive"):
            log.append(f"[udp] inconclusive: {res['note']}")
            finds.append(vulnscan2.F(
                "INFO", "UDP scan inconclusive — target could not be resolved trustworthily",
                "The hostname resolved only through the synthetic sandbox resolver and DNS-over-HTTPS was unreachable, so UDP probing would have measured the sandbox, not the target.",
                res["note"], "", "", remed="Re-run when DoH is reachable or from a host with a real resolver.",
                location=f"udp://{host}", confidence="confirmed"))
        log.append(f"[udp] open: {[o['port'] for o in res['open']]} ambiguous={res['ambiguous']}")
        summ = {}
        for f in finds:
            summ[f["severity"]] = summ.get(f["severity"], 0) + 1
        return {"type": "udp", "target": target, "profile": "udp",
                "udp_results": res["results"], "ambiguous": res["ambiguous"],
                "warnings": [res["note"]] if res["note"] else [],
                "findings": finds, "summary": summ,
                "overall_risk": "HIGH" if summ.get("HIGH") else "-"}
    if stype == "syn":
        raw = str(payload.get("ports", "")).strip()
        ports = None
        if raw:
            ports = []
            for part in raw.replace(" ", "").split(","):
                if "-" in part:
                    a, b = part.split("-", 1)
                    ports.extend(range(int(a), int(b) + 1))
                elif part:
                    ports.append(int(part))
            ports = ports[:500]
        res = scanners.syn_scan(host, ports or scanners.COMMON_PORTS[:200])
        if not res["available"]:
            log.append(f"[syn] unavailable: {res['reason']}")
            finds = [vulnscan2.F(
                "INFO", "SYN scan inconclusive in this environment",
                "The raw-socket SYN scan could not run here, so no port conclusion is drawn.",
                res["reason"], "", "", remed="Run SYN scans from a host with raw-socket capability.",
                location=target, confidence="confirmed")]
            return {"type": "syn", "target": target, "profile": "syn",
                    "available": False, "reason": res["reason"],
                    "findings": finds, "summary": {"INFO": 1},
                    "overall_risk": "-"}
        log.append(f"[syn] open: {res['open']}")
        return {"type": "syn", "target": target, "profile": "syn",
                "available": True, "open_ports": res["open"],
                "syn_results": res["results"],
                "warnings": ["Raw SYN results for remote hosts from this VM may still traverse the sandbox gateway; confirm exposure with an external scan."],
                "findings": [], "summary": {}, "overall_risk": "-"}
    if stype == "vhost":
        res = scanners.vhost_enum(target)
        finds = []
        for v in res["interesting"]:
            finds.append(vulnscan2.F(
                "LOW", f"Possible virtual host: {v['vhost']}",
                "A candidate Host header produced a materially different response than a random-host baseline, indicating a separate virtual host on the same server.",
                f"status {v['status']}, {v['length']} bytes (random baseline status {res['random_baseline_status']})",
                "CWE-200", "A05:2021 Security Misconfiguration",
                remed="Confirm the virtual host is intended to be reachable and apply the same hardening as the main site.",
                location=f"http://{v['vhost']}", confidence="probable"))
        log.append(f"[vhost] interesting: {[v['vhost'] for v in res['interesting']]}")
        return {"type": "vhost", "target": target, "profile": "vhost",
                "domain": res["domain"], "candidates": res["candidates"],
                "findings": finds,
                "summary": {"LOW": len(finds)} if finds else {},
                "overall_risk": "LOW" if finds else "-"}
    if stype == "hybrid":
        log.append("[hybrid] phase 1/2: passive recon")
        pres = passive_mod.run_passive_recon(target, log)
        if job["cancel"]:
            return None
        log.append("[hybrid] phase 2/2: active scan (active-deep)")
        opts = {}
        hdrs = payload.get("headers") or {}
        if isinstance(hdrs, dict):
            opts["headers"] = {str(k)[:60]: str(v)[:300] for k, v in list(hdrs.items())[:10]}
        if payload.get("cookie"):
            opts["cookie"] = str(payload["cookie"])[:1000]
        if payload.get("timeout"):
            opts["timeout"] = max(2.0, min(20.0, float(payload["timeout"])))
        _can = _canary_opts()
        if _can:
            opts["canary"] = _can
        try:
            _bl = store.list_secret_baseline()
            if _bl:
                opts["secret_baseline"] = _bl
        except Exception:
            pass
        if payload.get("auth_b"):
            opts["auth_b"] = payload["auth_b"]
        if payload.get("headless"):
            opts["headless"] = True
        vres = vulnscan2.run_vulnscan(target, "active-deep", log=log,
                                      opts=opts, cancelled=cancelled)
        seen, merged = set(), []
        for f in (pres.get("findings", []) + vres.get("findings", [])):
            key = (f.get("title"), f.get("location"), f.get("param"))
            if key in seen:
                continue
            seen.add(key)
            merged.append(f)
        summ = {}
        for f in merged:
            summ[f["severity"]] = summ.get(f["severity"], 0) + 1
        log.append(f"[hybrid] merged {len(merged)} findings "
                   f"({len(pres.get('findings', []))} passive + "
                   f"{len(vres.get('findings', []))} active, deduped)")
        return {"type": "hybrid", "target": target, "profile": "hybrid",
                "started_at": pres.get("started_at") or vres.get("started_at"),
                "findings": merged, "summary": summ,
                "risk_score": vulnscan2.risk_score(merged),
                "overall_risk": vres.get("overall_risk", "-"),
                "tech_profile": vres.get("tech_profile", []),
                "checks_detail": vres.get("checks_detail", []),
                "pages_crawled": vres.get("pages_crawled", 0),
                "scan_health": vres.get("scan_health", {}),
                "chains": vres.get("chains", []),
                "bfla_matrix": vres.get("bfla_matrix", []),
                "meta": {"passive": pres.get("meta", {}),
                         "vulnscan": vres.get("meta", {})},
                "warnings": (pres.get("warnings", []) +
                             vres.get("warnings", []))}
    return None


def _nvd_schedule_due(now=None):
    """WS6 (v1.8.0): is the operator-enabled scheduled NVD sync due?
    Default OFF — nothing syncs until the operator enables it in
    Settings. Pure function of the stored settings."""
    now = time.time() if now is None else now
    try:
        if str(store.get_setting("nvd_sync_enabled", "0")) != "1":
            return False
        hours = float(store.get_setting("nvd_sync_interval_h", "24"))
        hours = min(168.0, max(1.0, hours))
        last = float(store.get_setting("nvd_last_sync_ts", "0") or 0)
    except Exception:
        return False
    return (now - last) >= hours * 3600.0


_NVD_LOCK = threading.Lock()


def _do_nvd_sync(source):
    """Run one NVD sync (manual endpoint or scheduler) and record
    the outcome + timestamp in settings either way, so the Settings
    panel can show when the last sync ran and what it fetched."""
    if not _NVD_LOCK.acquire(blocking=False):
        return False
    try:
        return _do_nvd_sync_locked(source)
    finally:
        _NVD_LOCK.release()


def _do_nvd_sync_locked(source):
    if NVD_SYNC["state"] == "running":
        return False
    NVD_SYNC.update(state="running",
                    message=f"fetching NVD... ({source})")
    try:
        res = nvd_mod.sync(api_key=os.environ.get("PTK_NVD_KEY")
                           or None)
        store.cve_upsert(res["rows"])
        msg = (f"fetched {res['fetched']} CVEs"
               + (f"; errors: {'; '.join(res['errors'])}"
                  if res["errors"] else ""))
        NVD_SYNC.update(state="done", message=msg)
    except Exception as e:
        NVD_SYNC.update(state="error", message=str(e)[:200])
    store.set_setting("nvd_last_sync_ts", str(int(time.time())))
    store.set_setting("nvd_last_sync_msg",
                      f"{source}: {NVD_SYNC.get('message', '')}"[:200])
    store.audit("system", "nvd_sync_" + source,
                NVD_SYNC.get("message", "")[:150])
    return True


def scheduler_loop():
    """Jalankan scan terjadwal yang jatuh tempo (dibuat user dengan otorisasi tersimpan)."""
    while True:
        time.sleep(45)
        try:
            for sch in store.due_schedules():
                def run_one(sch=sch):
                    job = {"status": "running", "log": [], "result": None,
                           "started": time.time(), "cancel": False}
                    payload = {"type": "vulnscan", "profile": sch["profile"],
                               "authorized": True}
                    try:
                        result = run_tool_scan(payload, sch["target"], "vulnscan",
                                               sch["profile"], job)
                        if result is not None:
                            sid = store.save_scan(sch["target"], "vulnscan",
                                                  sch["profile"], result)
                            _fire_webhook(sid, sch["target"], result)
                        store.audit("scheduler", "scheduled_scan",
                                    f"{sch['target']} {sch['profile']}")
                    except Exception as e:
                        store.audit("scheduler", "scheduled_scan_error", str(e)[:150])
                    finally:
                        store.mark_schedule_ran(sch["id"], sch["interval_h"])
                threading.Thread(target=run_one, daemon=True).start()
        except Exception:
            pass
        # WS6 (v1.8.0): scheduled NVD sync — runs only when the
        # operator enabled it in Settings (default OFF).
        try:
            if _nvd_schedule_due() \
                    and NVD_SYNC["state"] != "running":
                threading.Thread(target=_do_nvd_sync,
                                 args=("scheduled",),
                                 daemon=True).start()
        except Exception:
            pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    store.init_db()
    store.init_v32()
    _start_canary()
    threading.Thread(target=scheduler_loop, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"[i] VANTHEX Offensive Security Platform v1.2.1 -> http://0.0.0.0:{port}")
    if getattr(store, "GENERATED_ADMIN_PW", None):
        print(f"[!] PTK_ADMIN_PW not set: generated one-time admin password: {store.GENERATED_ADMIN_PW}")
        print("[!] Record it now (shown only at this first startup); set PTK_ADMIN_PW to use your own.")
    else:
        print("[i] Admin login: admin (password from PTK_ADMIN_PW)")
    print("[!] AUTHORIZED TESTING ONLY")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
