"""
ImpactSim v1 — ransomware-style impact simulator (READ-ONLY) for VANTHEX.
OPERATOR-GATED: only ASSESSES the impact that WOULD occur if already
proven access (session/RCE/SQLi) were exploited by a real attacker. It
does not encrypt, delete, or modify anything — all metrics are computed
with read/count operations only.

Impact metrics:
  - data_at_risk  : number of records/files readable through proven access
  - services      : services that could be stopped (listed only, untouched)
  - blast_radius  : skor 0-10 dari kombinasi metrik

Pure module: probe callables are injected — unit-testable.
"""


def assess(data_counts, services, access_level="user"):
    """Compute an impact score from metrics collected by probes.

    data_counts : dict {name: count} (records/files/emails ...)
    services    : list of service names reachable via that access
    access_level: "user" | "admin" | "system"
    Returns dict {blast_radius, data_at_risk, services, level, notes}
    """
    total = sum(int(v) for v in (data_counts or {}).values())
    weights = {"user": 1, "admin": 2, "system": 3}
    w = weights.get(access_level, 1)
    score = 0.0
    score += min(4.0, total / 1000.0)          # data volume
    score += min(3.0, len(services or []) * 1.0)  # service breadth
    score += {1: 1.0, 2: 2.0, 3: 3.0}[w]        # access level
    return {"blast_radius": round(min(10.0, score), 1),
            "data_at_risk": total,
            "data_breakdown": dict(data_counts or {}),
            "services": list(services or []),
            "level": access_level,
            "notes": "READ-ONLY assessment — no changes made to the target."}


def report(res):
    """Impact summary for reports (incident-report style)."""
    out = [f"Potential impact (read-only simulation): "
           f"blast radius {res['blast_radius']}/10 [{res['level']}]"]
    for k, v in (res.get("data_breakdown") or {}).items():
        out.append(f"  - {k}: {v}")
    if res.get("services"):
        out.append(f"  - reachable services: {', '.join(res['services'])}")
    out.append(f"  total records/files at risk: {res['data_at_risk']}")
    return "\n".join(out)
