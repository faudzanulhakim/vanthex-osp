"""
Sentinel v1 — Time-Based Persistence Detector untuk VANTHEX (v1.8.0).
AUTHORIZED TESTING ONLY.

Mendeteksi perubahan permukaan target ANTARA dua scan (re-scan terjadwal
oleh cron eksternal): endpoint BARU yang muncul, endpoint HILANG, halaman
yang isinya berubah drastis → sinyal deploy berisiko atau penanaman
backdoor. Murni diff — tidak mengubah apa pun.

- snapshot(): kumpulkan fingerprint permukaan ({path: hash}).
- diff_snapshots(): bandingkan baseline vs sekarang → {added, removed,
  changed, verdict}.
"""
import hashlib as _hashlib


def _h(b):
    return _hashlib.sha256(b.encode("utf-8", "replace")).hexdigest()[:16]


def snapshot(client, max_pages=25):
    """Fingerprint permukaan via surface crawler (paths saja — konten
    di-fetch sampel terbatas utk hash)."""
    surf = ctx_pages(client)
    snap = {}
    for p in surf[:max_pages]:
        try:
            r = client.get(p)
            if r.status == 200:
                snap[p] = _h(r.body or "")
        except Exception:
            continue
    return snap


def ctx_pages(client):
    """Daftar path dari crawler ringan (GET HOME + tautan umum)."""
    try:
        r = client.get("/")
        body = r.body or ""
    except Exception:
        return ["/"]
    import re
    paths = sorted(set(re.findall(r'href="(/[^"#?]{1,80})"', body)))[:25]
    return paths or ["/"]


def diff_snapshots(baseline, current):
    added = sorted(set(current) - set(baseline))
    removed = sorted(set(baseline) - set(current))
    changed = sorted(p for p in set(baseline) & set(current)
                     if baseline[p] != current[p])
    verdict = "stable"
    notes = []
    if added:
        verdict = "surface-changed"
        notes.append(f"{len(added)} endpoint BARU muncul — audit deploy "
                     "(atau indikasi penanaman backdoor)")
    if len(changed) > max(3, len(baseline) // 3):
        verdict = "surface-changed"
        notes.append(f"{len(changed)} halaman berubah drastis — deploy besar?")
    if removed:
        notes.append(f"{len(removed)} endpoint hilang")
    return {"added": added, "removed": removed, "changed": changed,
            "verdict": verdict, "notes": notes}
