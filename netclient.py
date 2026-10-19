"""
netclient.py — HTTP client bersama untuk Pentest Toolkit (stdlib only).

Perbaikan dari helper lama di vulnscan2.py:
- Header disimpan sebagai LIST (Set-Cookie ganda tidak hilang).
- Support GET/POST/HEAD/OPTIONS/TRACE, body form, custom header/cookie (scan terautentikasi).
- Dekode gzip, batas baca yang masuk akal, pengukuran waktu per request (untuk time-based checks).
- Tidak auto-follow redirect (caller yang menilai Location — penting untuk open-redirect/CRLF).
"""
import base64
import gzip
import http.client
import os
import ssl
import time
import urllib.request
from urllib.parse import urlparse

UA = "VANTHEX/1.8.0 (self-built; authorized testing only)"
MAX_BODY = 262144  # 256 KB


class Resp:
    __slots__ = ("status", "headers", "body", "elapsed", "error", "url")

    def __init__(self, status=0, headers=None, body="", elapsed=0.0, error="", url=""):
        self.status = status
        self.headers = headers or []          # list[(k, v)] sesuai urutan wire
        self.body = body
        self.elapsed = elapsed
        self.error = error
        self.url = url

    def hdr(self, name, default=""):
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return default

    def hdr_all(self, name):
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]

    @property
    def ok(self):
        return self.status != 0


def split_target(target):
    """Kembalikan (scheme, host, port, base_path) dari target bebas format."""
    p = urlparse(target if "//" in target else "http://" + target)
    scheme = p.scheme or "http"
    port = p.port or (443 if scheme == "https" else 80)
    return scheme, p.hostname, port, (p.path or "/")


def _proxy_for(scheme, host, explicit=""):
    """Tentukan proxy: eksplisit (opts/PTK_PROXY) > env HTTP(S)_PROXY, hormati NO_PROXY.
    Kredensial proxy TIDAK pernah dikembalikan utuh ke log — hanya dipakai di header."""
    raw = explicit or os.environ.get("PTK_PROXY", "")
    if not raw:
        raw = urllib.request.getproxies().get(scheme, "")
    if not raw:
        return None
    try:
        if urllib.request.proxy_bypass(host):
            return None
    except Exception:
        pass
    p = urlparse(raw if "//" in raw else "http://" + raw)
    if not p.hostname:
        return None
    auth = ""
    if p.username:
        cred = f"{p.username}:{p.password or ''}"
        auth = "Basic " + base64.b64encode(cred.encode()).decode()
    return {"host": p.hostname, "port": p.port or 8080, "auth": auth}


class RequestAborted(Exception):
    """Request dihentikan: scan dibatalkan user atau budget waktu check habis."""


class Client:
    """Client per-target: membawa konfigurasi auth header/cookie & timeout."""

    def __init__(self, target, timeout=6.0, extra_headers=None, cookie="", proxy=""):
        self.scheme, self.host, self.port, self.base_path = split_target(target)
        self.timeout = timeout
        self.extra_headers = dict(extra_headers or {})
        if cookie:
            self.extra_headers.setdefault("Cookie", cookie)
        self.origin = f"{self.scheme}://{self.host}" + (
            f":{self.port}" if self.port not in (80, 443) else "")
        # Egress banyak jaringan (termasuk VM ini) WAJIB lewat proxy; http.client
        # tidak membaca env proxy sendiri — v2 selalu gagal total di jaringan begitu.
        self.proxy = _proxy_for(self.scheme, self.host, proxy)
        # Statistik kesehatan scan: rasio respons blokir (403/429) dipakai engine
        # untuk memperingatkan hasil yang mungkin tertekan WAF/rate-limit.
        self.stats = {"total": 0, "blocked": 0, "status": {},
                      "attempts": 0, "cache_hits": 0,
                      "throttled_events": 0, "throttled_seconds": 0.0}
        self._cache = {}
        self._tainted = set()   # URL yang pernah diminta dengan header khusus: permukaan stateful, tidak boleh dilayani dari cache
        # Adaptive backoff (Fase 4): target yang memblokir (403/429) tidak
        # ditabrak terus — jeda adaptif menjaga cakupan scan tetap hidup.
        self._block_streak = 0
        self._pending_delay = 0.0
        self.should_continue = None      # callable opsional (cek cancel)

    def _sleep_interruptible(self, seconds):
        """Tidur dalam potongan kecil agar cancel tetap responsif.
        Mengembalikan detik yang benar-benar ditidurkan."""
        slept, step = 0.0, 0.2
        while slept < seconds:
            if self.should_continue is not None:
                try:
                    if not self.should_continue():
                        break
                except Exception:
                    pass
            chunk = min(step, seconds - slept)
            time.sleep(chunk)
            slept += chunk
        return slept

    @staticmethod
    def _retry_after(headers):
        for k, v in headers:
            if k.lower() == "retry-after":
                try:
                    return max(0.0, float(v))
                except Exception:
                    try:
                        from email.utils import parsedate_to_datetime
                        dt = parsedate_to_datetime(v)
                        if dt is not None:
                            import datetime as _dt
                            now = _dt.datetime.now(_dt.timezone.utc)
                            return max(0.0, (dt - now).total_seconds())
                    except Exception:
                        return None
        return None

    def request(self, method, path, params=None, data=None, headers=None,
                timeout=None):
        """path boleh mengandung query string sendiri; params ditambahkan apa adanya
        (caller bertanggung jawab meng-encode payload)."""
        if not path.startswith("/"):
            path = "/" + path
        url_path = path + (("?" + params) if params else "")
        self.stats["attempts"] = self.stats.get("attempts", 0) + 1
        if self.should_continue is not None:
            try:
                if not self.should_continue():
                    raise RequestAborted(
                        "request aborted (cancelled / check time budget exhausted)")
            except RequestAborted:
                raise
            except Exception:
                pass
        if headers:
            # Permintaan bervariasi header menandai URL ini stateful: buang
            # entri cache-nya dan jangan pernah cache lagi di scan ini.
            # Tanpa ini, verifikasi cache-poisoning membaca respons SEBELUM
            # diracuni dari cache klien sendiri (regresi battery v1.8.0).
            self._tainted.add(url_path)
            self._cache.pop(url_path, None)
        _cache_key = None
        # Cache HANYA untuk GET tanpa header khusus per-request: check yang
        # memvariasikan header di URL yang sama (CORS, Host-header, JWT,
        # cache poisoning) WAJIB selalu kena jaringan — meng-cache-nya
        # membunuh deteksi (regresi battery v1.8.0, diperbaiki di sini).
        if method == "GET" and data is None and not headers and url_path not in self._tainted:
            _cache_key = url_path
            if _cache_key in self._cache:
                self.stats["cache_hits"] = self.stats.get("cache_hits", 0) + 1
                return self._cache[_cache_key]
        hdrs = {"User-Agent": UA, "Accept": "*/*",
                "Accept-Encoding": "gzip"}
        hdrs.update(self.extra_headers)
        hdrs.update(headers or {})
        if data is not None and "Content-Type" not in hdrs:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        if self._pending_delay > 0:
            # Budget tidur kumulatif per scan (90s): backoff anti-WAF tidak
            # boleh memakan ratusan detik dan mengacak durasi antar-scan
            # (scan fixture terukur tidur 265s sebelum cap ini ada).
            _room = 90.0 - float(self.stats.get("throttled_seconds", 0.0))
            slept = self._sleep_interruptible(
                min(self._pending_delay, max(0.0, _room)))
            self._pending_delay = 0.0
            if slept > 0:
                self.stats["throttled_events"] += 1
                self.stats["throttled_seconds"] = round(
                    self.stats["throttled_seconds"] + slept, 2)
        t0 = time.time()
        try:
            send_path = url_path
            if self.proxy and self.scheme == "https":
                conn = http.client.HTTPSConnection(
                    self.proxy["host"], self.proxy["port"],
                    timeout=timeout or self.timeout,
                    context=ssl._create_unverified_context())
                th = {"Proxy-Authorization": self.proxy["auth"]} if self.proxy["auth"] else None
                conn.set_tunnel(self.host, self.port, headers=th)
            elif self.proxy:
                conn = http.client.HTTPConnection(
                    self.proxy["host"], self.proxy["port"],
                    timeout=timeout or self.timeout)
                send_path = f"{self.origin}{url_path}"  # absolute-form untuk proxy HTTP
                if self.proxy["auth"]:
                    hdrs.setdefault("Proxy-Authorization", self.proxy["auth"])
            elif self.scheme == "https":
                conn = http.client.HTTPSConnection(
                    self.host, self.port, timeout=timeout or self.timeout,
                    context=ssl._create_unverified_context())
            else:
                conn = http.client.HTTPConnection(
                    self.host, self.port, timeout=timeout or self.timeout)
            conn.request(method, send_path, body=data, headers=hdrs)
            r = conn.getresponse()
            raw = r.read(MAX_BODY)
            _enc = (r.getheader("Content-Encoding") or "").lower()
            if _enc == "gzip":
                try:
                    raw = gzip.decompress(raw)
                except Exception:
                    pass
            elif _enc == "deflate":
                try:
                    import zlib
                    raw = zlib.decompress(raw)
                except Exception:
                    try:
                        import zlib
                        raw = zlib.decompress(raw, -zlib.MAX_WBITS)
                    except Exception:
                        pass
            body = raw.decode("utf-8", "replace")
            out = Resp(r.status, r.getheaders(), body,
                       time.time() - t0, url=url_path)
            conn.close()
            self.stats["total"] += 1
            self.stats["status"][r.status] = self.stats["status"].get(r.status, 0) + 1
            if r.status in (403, 429):
                self.stats["blocked"] += 1
            # --- adaptive backoff: hitung jeda untuk request BERIKUTNYA ---
            if r.status == 429:
                ra = self._retry_after(r.getheaders())
                delay = ra if ra else 2.0
                self._block_streak += 2
                self._pending_delay = max(self._pending_delay,
                                          min(max(delay, 0.5), 30.0))
            elif r.status == 403:
                self._block_streak += 1
                if self._block_streak >= 3:
                    self._pending_delay = max(
                        self._pending_delay,
                        min(0.5 * (2 ** (self._block_streak - 3)), 8.0))
            elif 200 <= r.status < 400:
                self._block_streak = 0
            if _cache_key is not None and r.status in (
                    200, 301, 302, 307, 308, 404, 410):
                if len(self._cache) > 500:
                    self._cache.pop(next(iter(self._cache)))
                self._cache[_cache_key] = out
            return out
        except Exception as e:
            return Resp(0, [], "", time.time() - t0, str(e)[:200], url_path)

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)


def similarity(a, b):
    """Rasio kemiripan dua body (0..1) — dipakai untuk boolean-based & soft-404."""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    import difflib
    return difflib.SequenceMatcher(None, a[:20000], b[:20000]).ratio()


def resolve_scheme_target(target, probe_timeout=5.0):
    """Target tanpa skema ("host/path") ditebak http:// oleh parser lama —
    penyebab scan 30+ menit tanpa hasil ke aplikasi yang hanya hidup di
    https. Fungsi ini MEMBUKTIKAN skema dengan satu request ringan:
    https dulu, lalu http. Mengembalikan (target_efektif, catatan)."""
    if "://" in target:
        return target, None
    for scheme in ("https", "http"):
        cand = f"{scheme}://{target}"
        try:
            c = Client(cand, timeout=probe_timeout)
            r = c.get(c.base_path or "/")
            if r.status != 0:
                return cand, (f"scheme omitted — proven {scheme} "
                              f"(HTTP {r.status})")
        except Exception:
            pass
    return ("https://" + target,
            "scheme omitted — no scheme could be proven; "
            "https chosen; the preflight will decide")
