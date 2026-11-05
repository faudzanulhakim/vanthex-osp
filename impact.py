"""
ImpactSim v1 — simulator dampak gaya-ransomware (READ-ONLY) untuk VANTHEX.
OPERATOR-GATED: hanya MENILAI dampak yang BISA terjadi bila akses yang
sudah terbukti (sesi/RCE/SQLi) dieksploitasi penyerang sungguhan. Tidak
mengenkripsi, tidak menghapus, tidak mengubah apa pun — semua metrik
dihitung dengan operasi baca/hitung saja.

Metrik dampak:
  - data_at_risk  : jumlah record/file yang terbaca lewat akses terbukti
  - services      : layanan yang bisa dihentikan (daftar saja, tidak disentuh)
  - blast_radius  : skor 0-10 dari kombinasi metrik

Modul murni: probe callable disuntikkan — unit-testable.
"""


def assess(data_counts, services, access_level="user"):
    """Hitung skor dampak dari metrik yang dikumpulkan probe.

    data_counts : dict {nama: jumlah} (records/files/emails ...)
    services    : list nama layanan yang terjangkau akses
    access_level: "user" | "admin" | "system"
    Returns dict {blast_radius, data_at_risk, services, level, notes}
    """
    total = sum(int(v) for v in (data_counts or {}).values())
    weights = {"user": 1, "admin": 2, "system": 3}
    w = weights.get(access_level, 1)
    score = 0.0
    score += min(4.0, total / 1000.0)          # volume data
    score += min(3.0, len(services or []) * 1.0)  # luas layanan
    score += {1: 1.0, 2: 2.0, 3: 3.0}[w]        # tingkat akses
    return {"blast_radius": round(min(10.0, score), 1),
            "data_at_risk": total,
            "data_breakdown": dict(data_counts or {}),
            "services": list(services or []),
            "level": access_level,
            "notes": "READ-ONLY assessment — tidak ada perubahan pada target."}


def report(res):
    """Ringkasan dampak untuk laporan (gaya laporan insiden)."""
    out = [f"Dampak potensial (simulasi read-only): "
           f"blast radius {res['blast_radius']}/10 [{res['level']}]"]
    for k, v in (res.get("data_breakdown") or {}).items():
        out.append(f"  - {k}: {v}")
    if res.get("services"):
        out.append(f"  - layanan terjangkau: {', '.join(res['services'])}")
    out.append(f"  total record/file berisiko: {res['data_at_risk']}")
    return "\n".join(out)
