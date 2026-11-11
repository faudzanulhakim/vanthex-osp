"""
Campaign v1 — one-command campaign mode for VANTHEX. OPERATOR-GATED.

Runs sequential phases with a per-phase progress callback:
  recon (optional) -> scan -> chain -> report
Never executes exploitation without an injected executor
(chainrun). All phases can be cancelled via the cancel callable.

Pure module: scanner & reporter injected — unit-testable.
"""
import time as _time


def run_campaign(target, scanner, chain_planner, reporter,
                 on_phase=None, cancel=None, opts=None):
    """scanner       : callable(target, opts) -> dict scan result (findings)
    chain_planner : callable(findings) -> list of chains (chainplanner.plan)
    reporter      : callable(target, findings, chains) -> dict report
    on_phase      : callable(phase, info) -> None (progress, e.g. Telegram)
    cancel        : callable() -> True if the operator cancels
    Returns dict {phases, findings, chains, report, elapsed_s}."""
    opts = opts or {}
    phases = []
    t0 = _time.time()

    def _phase(name, info):
        phases.append({"phase": name, "info": info,
                       "ts": round(_time.time() - t0, 1)})
        if on_phase:
            try:
                on_phase(name, info)
            except Exception:
                pass

    _phase("scan", f"target={target} opts={list(opts)}")
    if cancel and cancel():
        return {"phases": phases, "cancelled": True}
    res = scanner(target, opts) or {}
    findings = res.get("findings", [])
    _phase("scan-done", f"{len(findings)} findings")

    _phase("chain", "building exploit chain")
    chains = chain_planner(findings) if findings else []
    _phase("chain-done", f"{len(chains)} chains built (operator-gated)")

    _phase("report", "building report")
    rep = reporter(target, findings, chains) or {}
    _phase("done", f"total {round(_time.time() - t0, 1)}s")
    return {"phases": phases, "findings": findings, "chains": chains,
            "report": rep, "elapsed_s": round(_time.time() - t0, 1),
            "cancelled": False}
