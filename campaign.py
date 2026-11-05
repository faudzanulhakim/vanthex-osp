"""
Campaign v1 — mode kampanye one-command untuk VANTHEX. OPERATOR-GATED.

Menjalankan fase berurutan dengan callback progress per fase:
  recon (opsional) -> scan -> chain -> report
Tidak pernah mengeksekusi eksploitasi tanpa executor yang disuntikkan
(chainrun). Semua fase bisa dibatalkan via cancel callable.

Modul murni: scanner & reporter disuntikkan — unit-testable.
"""
import time as _time


def run_campaign(target, scanner, chain_planner, reporter,
                 on_phase=None, cancel=None, opts=None):
    """scanner       : callable(target, opts) -> dict hasil scan (findings)
    chain_planner : callable(findings) -> list rantai (chainplanner.plan)
    reporter      : callable(target, findings, chains) -> dict laporan
    on_phase      : callable(phase, info) -> None (progress, mis. Telegram)
    cancel        : callable() -> True bila operator membatalkan
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
    _phase("scan-done", f"{len(findings)} temuan")

    _phase("chain", "menyusun rantai eksploit")
    chains = chain_planner(findings) if findings else []
    _phase("chain-done", f"{len(chains)} rantai tersusun (operator-gated)")

    _phase("report", "menyusun laporan")
    rep = reporter(target, findings, chains) or {}
    _phase("done", f"total {round(_time.time() - t0, 1)}s")
    return {"phases": phases, "findings": findings, "chains": chains,
            "report": rep, "elapsed_s": round(_time.time() - t0, 1),
            "cancelled": False}
