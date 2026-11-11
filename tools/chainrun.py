"""
ChainRunner v1 — PER-APPROVAL exploit chain execution for VANTHEX.
FULLY OPERATOR-GATED: never executes anything without an approver
function approving every step (Telegram button / CLI y/n).

Takes chainplanner.plan() output → for each step:
  1. approver(step) → True/False (REQUIRED)
  2. executor(step) → result (callable supplied by operator/engine)
  3. result recorded; a failing step stops the chain (fail-closed)

Pure module: executor & approver injected — unit-testable.
"""
import json as _json
import time as _time


def run_chain(plan, approver, executor, max_steps=12, timeout_s=120):
    """Run a chain with per-step approval gating.

    plan   : output chainplanner.plan() (list of dict name/steps)
    approver  : callable(step_text) -> bool  (REQUIRED, must not be None)
    executor  : callable(step_text) -> dict result (REQUIRED)
    Returns dict {chain, executed:[...], skipped:[...], failed, stopped}
    """
    if approver is None or executor is None:
        raise ValueError("approver and executor are REQUIRED (operator-gated)")
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
    """Human-readable summary for the operator."""
    if not result:
        return "No chain execution."
    out = [f"Chains: {', '.join(result.get('chains', []))}"]
    out.append(f"  executed: {len(result.get('executed', []))}, "
               f"skipped (no approval): {len(result.get('skipped', []))}")
    for e in result.get("executed", []):
        out.append(f"  + {e['step'][:70]} -> {_json.dumps(e['result'], ensure_ascii=False)[:80]}")
    if result.get("failed"):
        out.append(f"  !! FAILED (fail-closed): {result['failed']['step'][:70]}")
    if result.get("stopped"):
        out.append("  !! stopped: timeout")
    return "\n".join(out)
