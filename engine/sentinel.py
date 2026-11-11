"""
Sentinel v1 — Time-Based Persistence Detector for VANTHEX (v1.8.0).
AUTHORIZED TESTING ONLY.

Detects changes to the target surface BETWEEN two scans (re-scan
scheduled by an external cron): NEW endpoints that appear, MISSING
endpoints, pages whose content changed drastically → a signal of a
risky deploy or backdoor planting. Pure diff — changes nothing.

- snapshot(): collect surface fingerprints ({path: hash}).
- diff_snapshots(): compare baseline vs current → {added, removed,
  changed, verdict}.
"""
import hashlib as _hashlib


def _h(b):
    return _hashlib.sha256(b.encode("utf-8", "replace")).hexdigest()[:16]


def snapshot(client, max_pages=25):
    """Fingerprint the surface via the surface crawler (paths only —
    content fetched for a limited sample for hashing)."""
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
    """List of paths from a lightweight crawler (GET HOME + common links)."""
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
        notes.append(f"{len(added)} NEW endpoints appeared — audit the "
                     "deploy (or an indication of backdoor planting)")
    if len(changed) > max(3, len(baseline) // 3):
        verdict = "surface-changed"
        notes.append(f"{len(changed)} pages changed drastically — big deploy?")
    if removed:
        notes.append(f"{len(removed)} endpoints disappeared")
    return {"added": added, "removed": removed, "changed": changed,
            "verdict": verdict, "notes": notes}
