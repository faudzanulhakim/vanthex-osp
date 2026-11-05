"""
Fleet v1 — Multi-Target Fleet Scan untuk VANTHEX (v1.8.0).
AUTHORIZED TESTING ONLY.

Scan N target paralel (thread pool) dengan global cap, lalu agregasi:
ranking risiko lintas-target, temuan unik & shared. CLI:
    .venv/bin/python fleet.py --targets http://a,http://b --profile quick
"""
import argparse as _argparse
import threading as _threading
import time as _time
from concurrent.futures import ThreadPoolExecutor

import vulnscan2 as _v

_lock = _threading.Lock()
_active = {"n": 0}


def _scan_one(base, profile, opts, timeout_s):
    with _lock:
        _active["n"] += 1
    try:
        log = []
        t0 = _time.time()
        try:
            res = _v.run_vulnscan(base, profile, log=log, opts=opts)
            res["elapsed_s"] = round(_time.time() - t0, 1)
            res["error"] = None
        except Exception as e:
            res = {"base": base, "findings": [], "error": str(e),
                   "elapsed_s": round(_time.time() - t0, 1)}
        return res
    finally:
        with _lock:
            _active["n"] -= 1


def scan_fleet(targets, profile="quick", opts=None, max_parallel=4):
    """targets: list URL. Return dict ter-agregasi:
    {results, ranking, shared_findings, totals}."""
    opts = dict(opts or {})
    results = []
    with ThreadPoolExecutor(max_workers=max_parallel) as ex:
        futs = [ex.submit(_scan_one, t.rstrip("/") + "/", profile, opts, None)
                for t in targets]
        for f in futs:
            results.append(f.result())
    # ranking: skor risiko = sum bobot severity * faktor confidence
    rank = []
    for r in results:
        score = sum(_v.SEV_WEIGHT.get(f.get("severity"), 0) *
                    _v.CONF_FACTOR.get(f.get("confidence"), 0.4)
                    for f in r.get("findings", []))
        rank.append({"target": r.get("base", "?"), "risk_score": round(score, 1),
                     "findings": len(r.get("findings", [])),
                     "critical": sum(1 for f in r.get("findings", [])
                                     if f.get("severity") == "CRITICAL"),
                     "error": r.get("error")})
    rank.sort(key=lambda x: -x["risk_score"])
    # temuan shared (judul sama di >=2 target)
    by_title = {}
    for r in results:
        for f in r.get("findings", []):
            by_title.setdefault(f["title"], set()).add(r.get("base", "?"))
    shared = [{"title": t, "targets": sorted(b)} for t, b in by_title.items()
              if len(b) > 1]
    shared.sort(key=lambda x: -len(x["targets"]))
    return {"results": results, "ranking": rank,
            "shared_findings": shared[:20],
            "totals": {"targets": len(targets),
                       "findings": sum(x["findings"] for x in rank),
                       "critical": sum(x["critical"] for x in rank)}}


if __name__ == "__main__":
    ap = _argparse.ArgumentParser(description="VANTHEX fleet scan")
    ap.add_argument("--targets", required=True,
                    help="URL dipisah koma")
    ap.add_argument("--profile", default="quick")
    ap.add_argument("--parallel", type=int, default=4)
    args = ap.parse_args()
    out = scan_fleet([t.strip() for t in args.targets.split(",") if t.strip()],
                     profile=args.profile, max_parallel=args.parallel)
    import json
    print(json.dumps(out["ranking"], indent=2, ensure_ascii=False))
    print("TOTALS:", json.dumps(out["totals"]))
    print("SHARED:", len(out["shared_findings"]), "temuan lintas-target")
