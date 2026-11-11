"""
netclient.py — shared HTTP client for the Pentest Toolkit (stdlib only).

Improvements over the old helper in vulnscan2.py:
- Headers are stored as a LIST (duplicate Set-Cookie is not lost).
- Supports GET/POST/HEAD/OPTIONS/TRACE, form bodies, custom headers/cookies (authenticated scans).
- gzip decoding, a sane read cap, per-request timing (for time-based checks).
- No auto-follow of redirects (the caller judges Location — important for open-redirect/CRLF).
"""
import base64
import gzip
import http.client
import os
import ssl
import time
import urllib.request
from urllib.parse import urlparse

UA = "VANTHEX/1.9.0 (self-built; authorized testing only)"
MAX_BODY = 262144  # 256 KB


class Resp:
    __slots__ = ("status", "headers", "body", "elapsed", "error", "url",
                 "raw")

    def __init__(self, status=0, headers=None, body="", elapsed=0.0, error="", url="", raw=b""):
        self.status = status
        self.headers = headers or []          # list[(k, v)] sesuai urutan wire
        self.body = body
        self.elapsed = elapsed
        self.error = error
        self.url = url
        self.raw = raw                        # decoded wire bytes (v1.7.0: favicon MD5)

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
    """Pick a proxy: explicit (opts/PTK_PROXY) > env HTTP(S)_PROXY, honoring NO_PROXY.
    Proxy credentials are NEVER returned intact to logs — only used in the header."""
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
    """Request aborted: the scan was cancelled by the user or the check's time budget ran out."""


class Client:
    """Per-target client: carries the auth header/cookie config & timeout."""

    def __init__(self, target, timeout=6.0, extra_headers=None, cookie="", proxy=""):
        self.scheme, self.host, self.port, self.base_path = split_target(target)
        self.timeout = timeout
        self.extra_headers = dict(extra_headers or {})
        if cookie:
            self.extra_headers.setdefault("Cookie", cookie)
        self.origin = f"{self.scheme}://{self.host}" + (
            f":{self.port}" if self.port not in (80, 443) else "")
        # Egress on many networks (including this VM) MUST go through a proxy; http.client
        # does not read proxy env itself — v2 always failed outright on such networks.
        self.proxy = _proxy_for(self.scheme, self.host, proxy)
        # Scan health statistics: the block-response ratio (403/429) is used by the
        # engine to warn that results may be suppressed by WAFs/rate limits.
        self.stats = {"total": 0, "blocked": 0, "status": {},
                      "attempts": 0, "cache_hits": 0,
                      "throttled_events": 0, "throttled_seconds": 0.0}
        self._cache = {}
        self._tainted = set()   # URLs requested with special headers: stateful surface, must never be served from cache
        # Adaptive backoff (Phase 4): targets that block (403/429) are not
        # hammered — adaptive delays keep the scan's coverage alive.
        self._block_streak = 0
        self._pending_delay = 0.0
        self.should_continue = None      # callable opsional (cek cancel)

    def _sleep_interruptible(self, seconds):
        """Sleep in small slices so cancel stays responsive.
        Returns the seconds actually slept."""
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
        """path may contain its own query string; params are appended as-is
        (the caller is responsible for encoding the payload)."""
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
            # A request that varies headers marks this URL as stateful: drop
            # its cache entry and never cache it again during this scan.
            # Without this, cache-poisoning verification reads the response
            # BEFORE poisoning from the client's own cache (battery v1.8.0 regression).
            self._tainted.add(url_path)
            self._cache.pop(url_path, None)
        _cache_key = None
        # Cache ONLY plain GETs without per-request special headers: checks
        # that vary headers on the same URL (CORS, Host-header, JWT,
        # cache poisoning) MUST always hit the network — caching them
        # kills detection (battery v1.8.0 regression, fixed here).
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
            # Cumulative per-scan sleep budget (90s): anti-WAF backoff must
            # not eat hundreds of seconds and randomize scan durations
            # (the fixture scan measured 265s asleep before this cap existed).
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
                send_path = f"{self.origin}{url_path}"  # absolute-form for the HTTP proxy
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
                       time.time() - t0, url=url_path, raw=raw)
            conn.close()
            self.stats["total"] += 1
            self.stats["status"][r.status] = self.stats["status"].get(r.status, 0) + 1
            if r.status in (403, 429):
                self.stats["blocked"] += 1
            # --- adaptive backoff: compute the delay for the NEXT request ---
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
    """Similarity ratio of two bodies (0..1) — used for boolean-based & soft-404."""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    import difflib
    return difflib.SequenceMatcher(None, a[:20000], b[:20000]).ratio()


def resolve_scheme_target(target, probe_timeout=5.0):
    """Targets without a scheme ("host/path") used to be guessed as http:// by
    the old parser — the cause of 30+ minute scans with zero results against
    apps that live only on https. This function PROVES the scheme with one
    lightweight request: https first, then http. Returns (effective_target, note)."""
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
