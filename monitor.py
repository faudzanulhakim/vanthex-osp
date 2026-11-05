"""
Monitor v1 — scan berulang + diff temuan untuk VANTHEX. OPERATOR-GATED.

Menjalankan scan (profil apa pun), membandingkan temuan dengan state
sebelumnya, dan melaporkan HANYA temuan BARU (regresi keamanan setelah
deploy). Dirancang untuk dijadwalkan (cron/Telegram) — tapi tidak
menjadwalkan dirinya sendiri; operator memilih target & jadwal.

    python3 monitor.py --target http://t --profile active-standard \
        --state ~/vanthex-state.json --json-out

Exit code: 0 = tidak ada temuan baru; 2 = ada temuan baru.
Modul diff_findings() murni & unit-testable.
"""
import argparse
import hashlib
import json as _json
import os
import sys


def _fkey(f):
    """Kunci stabil per temuan: hash (title + location + param)."""
    raw = f"{f.get('title', '')}|{f.get('location', '')}|{f.get('param', '')}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def diff_findings(old_findings, new_findings):
    """Temuan BARU = ada di run baru, tidak ada di run lama (per kunci).
    Returns list temuan baru (urutan dipertahankan)."""
    old = {_fkey(f) for f in (old_findings or [])}
    return [f for f in (new_findings or []) if _fkey(f) not in old]


def load_state(path):
    try:
        with open(path, encoding="utf-8") as fh:
            d = _json.load(fh)
        return d.get("findings", []), d.get("meta", {})
    except Exception:
        return [], {}


def save_state(path, findings, meta=None):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        _json.dump({"findings": findings, "meta": meta or {}}, fh, indent=1)
    os.replace(tmp, path)


def run_monitor(target, profile, state_path, opts=None, log=None):
    """Jalankan scan + diff. Returns dict {new_findings, total, state_path}."""
    import vulnscan2
    res = vulnscan2.run_vulnscan(target, profile, log=log or [],
                                 opts=opts or {"timeout": 6})
    new_all = res.get("findings", [])
    old, old_meta = load_state(state_path)
    new = diff_findings(old, new_all)
    save_state(state_path, new_all,
               meta={"target": target, "profile": profile,
                     "count": len(new_all)})
    return {"new_findings": new, "total": len(new_all),
            "prev_total": len(old), "state_path": state_path}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Monitor scan diff (operator-gated)")
    ap.add_argument("--target", required=True)
    ap.add_argument("--profile", default="active-standard")
    ap.add_argument("--state", default=os.path.expanduser("~/vanthex-state.json"))
    ap.add_argument("--json-out", action="store_true")
    ns = ap.parse_args(argv)
    rep = run_monitor(ns.target, ns.profile, ns.state)
    if ns.json_out:
        print(_json.dumps(rep, indent=1, ensure_ascii=False))
    else:
        print(f"[monitor] {ns.target} ({ns.profile}): {rep['total']} temuan, "
              f"{len(rep['new_findings'])} BARU")
        for f in rep["new_findings"]:
            print(f"  + [{f.get('severity')}] {f.get('title')} @ {f.get('location')}")
    return 2 if rep["new_findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
