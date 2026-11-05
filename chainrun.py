"""
ChainRunner v1 — eksekusi rantai eksploit PER-APPROVAL untuk VANTHEX.
OPERATOR-GATED TOTAL: tidak pernah mengeksekusi apa pun tanpa fungsi
approver yang menyetujui tiap langkah (Telegram button / CLI y/n).

Mengambil output chainplanner.plan() → untuk tiap langkah:
  1. approver(step) → True/False (WAJIB)
  2. executor(step) → hasil (callable yang diberikan operator/engine)
  3. hasil dicatat; langkah gagal menghentikan rantai (fail-closed)

Modul murni: executor & approver disuntikkan — unit-testable.
"""
import json as _json
import time as _time


def run_chain(plan, approver, executor, max_steps=12, timeout_s=120):
    """Eksekusi rantai dengan gerbang approval per-langkah.

    plan   : output chainplanner.plan() (list of dict name/steps)
    approver  : callable(step_text) -> bool  (WAJIB, tidak boleh None)
    executor  : callable(step_text) -> dict hasil (WAJIB)
    Returns dict {chain, executed:[...], skipped:[...], failed, stopped}
    """
    if approver is None or executor is None:
        raise ValueError("approver dan executor WAJIB (operator-gated)")
    out = {"executed": [], "skipped": [], "failed": None, "stopped": False}
    t0 = _time.time()
    for chain in (plan or [])[:3]:
        name = chain.get("name", "?")
        out.setdefault("chains", []).append(name)
        for i, step in enumerate(chain.get("steps", [])[:max_steps]):
            if _time.time() - t0 > timeout_s:
                out["stopped"] = True
                return out
            if not approver(step):
                out["skipped"].append(step)
                continue
            try:
                res = executor(step)
            except Exception as e:
                out["failed"] = {"step": step, "error": str(e)}
                return out  # fail-closed
            out["executed"].append({"step": step, "result": res})
    return out


def summarize(result):
    """Ringkasan teks untuk operator."""
    if not result:
        return "Tidak ada eksekusi rantai."
    out = [f"Rantai: {', '.join(result.get('chains', []))}"]
    out.append(f"  dieksekusi: {len(result.get('executed', []))}, "
               f"diskip (tanpa approval): {len(result.get('skipped', []))}")
    for e in result.get("executed", []):
        out.append(f"  + {e['step'][:70]} -> {_json.dumps(e['result'], ensure_ascii=False)[:80]}")
    if result.get("failed"):
        out.append(f"  !! GAGAL (fail-closed): {result['failed']['step'][:70]}")
    if result.get("stopped"):
        out.append("  !! dihentikan: waktu habis")
    return "\n".join(out)
