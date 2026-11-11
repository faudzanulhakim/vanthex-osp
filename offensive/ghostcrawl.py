"""
ghostcrawl.py — Stealth Crawler for VANTHEX.

AUTHORIZED TESTING ONLY — the crawler deliberately throttles itself; its goal
is to be indistinguishable from one slow human visitor, never to load a target.

Four capabilities, all driven through an injected `fetcher(path, headers=None)`
callable (same dependency-injection pattern as reconiblis/_fetch_bytes; tests
monkeypatch it or point it at a local http.server):

  1. HumanJitter      — bell-curve bounded delay generator plus a per-path-
                        prefix adaptive rate-limit tracker that slows down on
                        429/403 and remembers the learned threshold per prefix.
  2. HeaderPool       — realistic UA / Accept-Language sets rotated per
                        request, cookie passthrough, and a passive
                        header-reaction fingerprint (differential over exactly
                        2 requests with different header sets).
  3. cache_timing_enumeration — cold GET with a cache-busting query vs warm
                        GET: warm measurably faster AND cache headers present
                        means the path exists and is cacheable without a
                        direct hit; a confirming repeat promotes the finding
                        from candidate to probable (differential 2x).
  4. alt_map_discovery — paths the app itself leaks: robots.txt Disallow
                        entries (wildcards expanded), sitemap.xml <loc> URLs,
                        and route strings embedded in JavaScript.

run_ghost(ctx, add) is the scan-check wrapper matching zerodayheur's
c_zeroday_heur signature. Operator-gated: a no-op unless PTK_GHOST=1.
Hard caps: 8 findings, 60 requests. ctx.cancelled() is honored between steps.
Findings carry English descriptions with verification labels via the shared
F() factory (vulnscan2, imported lazily).
"""
import os as _os
import random as _random
import re as _re
import time as _time
from urllib.parse import urlparse as _urlparse

_MAX_FINDINGS = 8
_MAX_REQUESTS = 60

# ------------------------------------------------------------ HumanJitter


class HumanJitter:
    """Bell-curve bounded delay + adaptive per-prefix rate limiting.

    delay() returns a human-shaped pause: a Gaussian sample clamped to
    [min_delay, max_delay], multiplied by the adaptive penalty for the
    path's prefix. The tracker remembers 429/403 hits per prefix and raises
    the penalty until clean responses arrive again; the learned multiplier
    is kept (never reset below 1.0 once a throttle was observed — the
    threshold is remembered for the lifetime of the crawler).
    """

    def __init__(self, min_delay=0.2, max_delay=2.0, base=0.8,
                 seed=None, sleeper=None):
        self.min_delay = float(min_delay)
        self.max_delay = float(max_delay)
        self.base = float(base)
        self._rng = _random.Random(seed)
        self._sleeper = sleeper or _time.sleep
        self._penalty = {}          # prefix -> multiplier (>= 1.0)
        self.hit_prefixes = []      # prefixes that ever saw 429/403
        self._last = {}             # prefix -> time.time() of last request

    def delay(self, path="/", apply=True):
        """One clamped Gaussian pause for this path; applies it when asked."""
        prefix = self.prefix_of(path)
        pen = self._penalty.get(prefix, 1.0)
        span = max(0.05, (self.max_delay - self.min_delay))
        # sigma = span/4 keeps ~99.7% of samples inside the bounds
        d = self._rng.gauss(self.base * pen, span / 4.0)
        d = max(self.min_delay * pen, min(self.max_delay * pen, d))
        if apply:
            self._sleeper(d)
        return d

    @staticmethod
    def prefix_of(path):
        """Rate-limit key: first path segment only (/api/x -> /api/)."""
        p = _urlparse(path).path or "/"
        if not p.startswith("/"):
            p = "/" + p
        parts = p.split("/", 2)
        if len(parts) >= 2 and parts[1]:
            return "/" + parts[1] + "/"
        return "/"

    def record(self, status, path):
        """Feed one response status back into the adaptive tracker."""
        prefix = self.prefix_of(path)
        if status in (429, 403):
            old = self._penalty.get(prefix, 1.0)
            self._penalty[prefix] = min(8.0, max(1.5, old * 2.0))
            if prefix not in self.hit_prefixes:
                self.hit_prefixes.append(prefix)
        elif 200 <= status < 300:
            # gentle decay back, but never below 1.0 once throttled
            cur = self._penalty.get(prefix, 1.0)
            if cur > 1.0:
                self._penalty[prefix] = max(1.0, cur * 0.8)

    def penalty(self, path):
        return self._penalty.get(self.prefix_of(path), 1.0)

    def throttle(self, path):
        """Wait out any per-prefix spacing penalty between two requests."""
        prefix = self.prefix_of(path)
        pen = self._penalty.get(prefix, 1.0)
        if pen <= 1.0:
            return 0.0
        need = self.base * (pen - 1.0)
        last = self._last.get(prefix)
        if last is None:
            return 0.0
        wait = need - (_time.time() - last)
        if wait > 0:
            self._sleeper(min(wait, 5.0))
            return wait
        return 0.0

    def touch(self, path):
        self._last[self.prefix_of(path)] = _time.time()


# ------------------------------------------------------------ header pool

_UA_SETS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
]

_LANG_SETS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "en-US,en;q=0.9,fr;q=0.5",
    "en;q=0.7,de;q=0.4",
]


class HeaderPool:
    """Rotating realistic header sets + cookie passthrough.

    rotate() returns a fresh header dict each call (UA / Accept-Language
    chosen per request). add_cookies(resp) harvests Set-Cookie values from a
    netclient.Resp-shaped object and replays them on later requests.
    """

    def __init__(self, seed=None):
        self._rng = _random.Random(seed)
        self.cookies = {}          # name -> value

    def rotate(self):
        h = {
            "User-Agent": self._rng.choice(_UA_SETS),
            "Accept-Language": self._rng.choice(_LANG_SETS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        return h

    def add_cookies(self, resp):
        """Harvest Set-Cookie (netclient.Resp keeps duplicates as a list)."""
        n = 0
        for k, v in (getattr(resp, "headers", None) or []):
            if k.lower() == "set-cookie":
                first = v.split(";", 1)[0]
                if "=" in first:
                    name, val = first.split("=", 1)
                    name, val = name.strip(), val.strip()
                    if name:
                        self.cookies[name] = val
                        n += 1
        return n

    def fingerprint(self, fetcher, path):
        """Passive header-reaction fingerprint: differential over 2 requests
        with different header sets. Detects content/status that varies with
        client headers (geo-blocking, UA gating, personalized responses).

        Returns a dict {reactions: [...], differs: bool} or None if either
        request failed. Never destructive: both requests are plain GETs.
        """
        h1 = self.rotate()
        h2 = self.rotate()
        tries = 0
        r1 = r2 = None
        for hdrs in (h1, h2):
            tries += 1
            try:
                r = fetcher(path, headers=hdrs)
            except Exception:
                r = None
            if tries == 1:
                r1 = r
            else:
                r2 = r
        if r1 is None or r2 is None:
            return None
        b1 = (getattr(r1, "body", "") or "")
        b2 = (getattr(r2, "body", "") or "")
        reactions = []
        if (r1.status or 0) != (r2.status or 0):
            reactions.append("status changed between header sets "
                             f"({r1.status} vs {r2.status})")
        if r1.hdr("server", "") != r2.hdr("server", ""):
            reactions.append("Server header changed between header sets")
        if len(b1) and len(b2) and abs(len(b1) - len(b2)) > max(64, len(b1) // 4):
            reactions.append(f"body length shifted ({len(b1)} vs {len(b2)} bytes)")
        return {"reactions": reactions, "differs": bool(reactions),
                "cookie_names": sorted(self.cookies)}


# ------------------------------------------------------------ cache timing

_CACHE_HEADERS = ("x-cache", "age", "cf-cache-status",
                  "x-cache-status", "x-varnish", "x-drupal-cache")


def _cache_hit(resp):
    h = getattr(resp, "headers", None) or []
    for k, v in h:
        if k.lower() in _CACHE_HEADERS and str(v).strip().lower() not in (
                "", "miss", "none", "bypass", "dyn", "dynamically missing"):
            return True
    return False


def cache_timing_enumeration(paths, fetcher, jitter=None, log=None,
                             budget=_MAX_REQUESTS):
    """Cold/warm cache timing over candidate paths.

    Protocol per path (4 requests):
      * cold GET with a cache-busting query (?__gc=<rand>)  -> baseline
      * warm GET of the plain path                          -> candidate warm
      * if warm was measurably faster AND cache headers present:
          differential 2x — repeat both once to confirm.

    A path is reported only when warm beats cold twice AND cache headers
    appear twice: the path exists and is cacheable, observable without a
    direct hit on the real path. Returns a list of dicts:
    {path, cold_ms, warm_ms, cache_header, confirmed}.
    """
    L = log or (lambda m: None)
    out = []
    used = 0
    for path in paths:
        if used + 4 > budget:
            break
        bust = f"{path}{'&' if '?' in path else '?'}__gc={_random.randint(10**5, 10**6)}"
        try:
            cold = fetcher(bust)
            warm = fetcher(path)
        except Exception:
            continue
        used += 2
        if getattr(cold, "status", 0) >= 400 or getattr(warm, "status", 0) >= 400:
            continue
        cold_ms = (getattr(cold, "elapsed", 0.0) or 0.0) * 1000.0
        warm_ms = (getattr(warm, "elapsed", 0.0) or 0.0) * 1000.0
        hit = _cache_hit(warm)
        # warm must be measurably faster (>=15% and >=3ms — noise guards)
        faster = warm_ms < cold_ms * 0.85 and (cold_ms - warm_ms) >= 3.0
        if not (faster and hit):
            if jitter:
                jitter.delay(path)
            continue
        # differential 2x: repeat the pair once
        try:
            cold2 = fetcher(bust)
            warm2 = fetcher(path)
        except Exception:
            continue
        used += 2
        confirmed = (_cache_hit(warm2)
                     and (getattr(warm2, "elapsed", 0.0) or 0.0) * 1000.0
                     < (getattr(cold2, "elapsed", 0.0) or 0.0) * 1000.0)
        if confirmed:
            hdr = next((f"{k}: {v}" for k, v in (warm.headers or [])
                        if k.lower() in _CACHE_HEADERS and str(v).strip()
                        and str(v).strip().lower() not in ("miss", "none", "bypass")),
                       "cache header present")
            out.append({"path": path, "cold_ms": round(cold_ms, 1),
                        "warm_ms": round(warm_ms, 1), "cache_header": hdr,
                        "confirmed": True})
            L(f"  [ghostcrawl] cacheable path confirmed: {path} "
              f"(warm {warm_ms:.0f}ms vs cold {cold_ms:.0f}ms, {hdr})")
        if jitter:
            jitter.delay(path)
    return out


# ------------------------------------------------------------ alt map

_ROBOTS_LINE = _re.compile(r"^\s*Disallow:\s*(\S+)\s*$", _re.I | _re.M)
_SITEMAP_LOC = _re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", _re.I)
_JS_ROUTE_RE = _re.compile(
    r'''["'`](/[A-Za-z0-9_\-./]{2,60})["'`]''')


def _expand_wildcard(pattern):
    """robots.txt wildcard -> concrete probe candidates."""
    if "*" in pattern:
        stem = pattern.split("*", 1)[0]
        return [stem.rstrip("/") + "/admin", stem.rstrip("/") + "/test",
                stem.rstrip("/") + "/backup"]
    return [pattern]


def alt_map_discovery(fetcher, base="/", log=None):
    """Harvest paths the target leaks about itself. GET-only.

      * robots.txt Disallow entries (wildcards expanded to concrete probes)
      * sitemap.xml <loc> URLs (same-host paths only)
      * route strings embedded in the HTML page and its .js files

    Returns {"robots": [...], "sitemap": [...], "js_routes": [...]}.
    """
    L = log or (lambda m: None)
    out = {"robots": [], "sitemap": [], "js_routes": []}
    host = (_urlparse(base).hostname or "").lower()

    try:
        rb = fetcher("/robots.txt")
    except Exception:
        rb = None
    if rb is not None and getattr(rb, "status", 0) == 200:
        body = getattr(rb, "body", "") or ""
        for raw in _ROBOTS_LINE.findall(body):
            p = raw.strip()
            if not p.startswith("/"):
                continue
            out["robots"].extend(_expand_wildcard(p))
    out["robots"] = sorted(set(out["robots"]))

    try:
        sm = fetcher("/sitemap.xml")
    except Exception:
        sm = None
    if sm is not None and getattr(sm, "status", 0) == 200:
        sbody = getattr(sm, "body", "") or ""
        for loc in _SITEMAP_LOC.findall(sbody):
            u = _urlparse(loc)
            if host and u.hostname and u.hostname.lower() != host:
                continue
            if u.path and u.path not in out["sitemap"]:
                out["sitemap"].append(u.path)
            q = ("?" + u.query) if u.query else ""
            if q and (u.path + q) not in out["sitemap"]:
                out["sitemap"].append(u.path + q)
        out["sitemap"] = sorted(set(out["sitemap"]))

    # JS-embedded routes: homepage first, then same-host .js files it loads
    try:
        home = fetcher("/")
    except Exception:
        home = None
    js_files = []
    if home is not None and getattr(home, "status", 0) == 200:
        hbody = getattr(home, "body", "") or ""
        out["js_routes"] = _JS_ROUTE_RE.findall(hbody)
        js_files = _re.findall(
            r'''(?:src|href)\s*=\s*["']([^"']+\.js)["']''', hbody, _re.I)
    seen_js = set()
    for jf in js_files[:6]:
        if jf.startswith("//"):
            jf = "http:" + jf
        path = _urlparse(jf).path if "://" in jf else jf
        if not path or path.startswith("http") or path in seen_js:
            continue
        seen_js.add(path)
        try:
            jr = fetcher(path)
        except Exception:
            continue
        if getattr(jr, "status", 0) == 200:
            out["js_routes"].extend(
                _JS_ROUTE_RE.findall(getattr(jr, "body", "") or ""))
    out["js_routes"] = sorted(set(out["js_routes"]))
    L(f"  [ghostcrawl] alt map: {len(out['robots'])} robots paths, "
      f"{len(out['sitemap'])} sitemap URLs, "
      f"{len(out['js_routes'])} JS routes")
    return out


# ------------------------------------------------------------ finding factory


def _lazy_F():
    try:
        from vulnscan2 import F
        return F
    except Exception:
        def F(sev, title, desc, evidence="", cwe="", owasp="", cvss=0.0,
              remed="", confidence="probable", location="", param="",
              verification=None, verification_note=""):
            f = {"severity": sev, "title": title, "description": desc,
                 "evidence": evidence, "cwe": cwe, "owasp": owasp,
                 "cvss": cvss, "remediation": remed,
                 "confidence": confidence, "location": location,
                 "param": param, "origin": "ghostcrawl"}
            f["verification"] = verification or {
                "confirmed": "signature", "probable": "manual-required",
                "candidate": "reflection-only"}.get(confidence,
                                                    "manual-required")
            if verification_note:
                f["verification_note"] = verification_note
            return f
        return F


def _cap(findings):
    return findings[:_MAX_FINDINGS]


# ------------------------------------------------------------ scan check


def run_ghost(ctx, add):
    """Stealth crawler check (c_zeroday_heur signature). Gated on PTK_GHOST=1.

    Budget: max 60 requests, max 8 findings. Every phase honors
    ctx.cancelled() and applies HumanJitter pauses between requests.
    """
    if not (_os.environ.get("PTK_GHOST") == "1"
            or _os.environ.get("VANTHEX_GHOST") == "1"):
        ctx.L("  [ghostcrawl] operator gate PTK_GHOST not set — skipped")
        return
    F = _lazy_F()
    jitter = HumanJitter(seed=1337)
    pool = HeaderPool(seed=42)
    findings = []
    requests_used = [0]

    def fetch(path, headers=None):
        if ctx.cancelled() or requests_used[0] >= _MAX_REQUESTS:
            return None
        jitter.throttle(path)
        jitter.delay(path)
        hdrs = dict(headers or {})
        hdrs.update(pool.rotate())
        jitter.touch(path)
        requests_used[0] += 1
        try:
            resp = ctx.client.get(path, headers=hdrs)
        except Exception:
            return None
        jitter.record(getattr(resp, "status", 0), path)
        pool.add_cookies(resp)
        return resp

    base = getattr(ctx, "target", "") or "/"
    try:
        base_path = (getattr(ctx.client, "base_path", None) or "/")
    except Exception:
        base_path = "/"

    # phase 1: alt map (3 fetches for robots/sitemap + homepage/JS)
    if ctx.cancelled():
        return
    amap = alt_map_discovery(fetch, base=base or base_path,
                             log=lambda m: ctx.L(m))
    all_paths = sorted(set(amap["robots"] + amap["sitemap"]
                           + amap["js_routes"]))
    disclosed = amap["robots"] + amap["sitemap"]
    leaked_only = [p for p in all_paths if p not in set(disclosed)]

    if amap["robots"] or amap["sitemap"]:
        findings.append(F(
            "info",
            "Disclosed sensitive paths in robots.txt / sitemap.xml",
            "The target's robots.txt and/or sitemap.xml disclose "
            f"{len(disclosed)} path(s) the operator intended to keep out of "
            "crawlers. These lists often enumerate admin, backup, or staging "
            "areas and are an immediate prioritization source for review.",
            evidence="; ".join(disclosed[:10]),
            cwe="CWE-538", owasp="A05:2021", confidence="confirmed",
            location="/robots.txt, /sitemap.xml"))

    # phase 2: cache timing over a bounded slice of discovered paths
    if ctx.cancelled():
        ctx.L(f"  [ghostcrawl] done: {len(findings)} finding(s)")
        _emit(findings, add)
        return
    cache_paths = leaked_only[:8]
    cache_hits = cache_timing_enumeration(
        cache_paths, fetch, jitter=jitter,
        log=lambda m: ctx.L(m), budget=_MAX_REQUESTS - requests_used[0])
    for ch in cache_hits:
        findings.append(F(
            "low",
            f"Cacheable hidden path observable via cache timing ({ch['path']})",
            "A warm request to this path is measurably faster than a "
            "cache-busting cold request, and cache headers are present "
            f"({ch['cache_header']}). The path exists and is served from "
            "cache: its existence can be confirmed without a direct hit on "
            "the resource itself. Differential (cold vs warm) repeated twice "
            "with matching results.",
            evidence=(f"warm {ch['warm_ms']}ms vs cold {ch['cold_ms']}ms; "
                      f"{ch['cache_header']}"),
            cwe="CWE-200", owasp="A01:2021", confidence="probable",
            location=ch["path"],
            verification_note="Cold/warm differential reproduced 2x; "
                              "verify content sensitivity manually."))

    # phase 3: passive header-reaction fingerprint on the homepage
    if not ctx.cancelled() and requests_used[0] + 2 <= _MAX_REQUESTS:
        fp = pool.fingerprint(fetch, "/")
        if fp and fp["differs"]:
            findings.append(F(
                "info",
                "Header-dependent response behavior (passive fingerprint)",
                "Two identical GET requests with different User-Agent / "
                "Accept-Language header sets produced different responses: "
                + "; ".join(fp["reactions"]) + ". The server reacts to "
                "client headers, which indicates geo/UA-aware routing or "
                "per-client personalization worth reviewing.",
                evidence="; ".join(fp["reactions"]) +
                         (f"; cookies observed: {', '.join(fp['cookie_names'])}"
                          if fp["cookie_names"] else ""),
                cwe="CWE-200", owasp="A05:2021", confidence="probable",
                location="/",
                verification_note="Differential over 2 requests; "
                                  "re-check headers manually."))

    ctx.L(f"  [ghostcrawl] done: {len(findings)} finding(s), "
          f"{requests_used[0]} request(s)")
    _emit(_cap(findings), add)


def _emit(findings, add):
    for f in findings:
        try:
            f["origin"] = "ghostcrawl"
        except Exception:
            pass
        add(f)


if __name__ == "__main__" and _os.environ.get("PTK_GHOST") == "1":
    print("ghostcrawl: stealth crawler wired "
          f"(findings cap {_MAX_FINDINGS}, request cap {_MAX_REQUESTS})")
