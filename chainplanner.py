"""
ChainPlanner v1 — perencana rantai eksploit untuk VANTHEX. Read-only.

Mengambil daftar temuan hasil scan dan menyusun CHAIN penyerangan: urutan
langkah verifiable yang menggabungkan beberapa temuan menjadi jalur
take-over. Output murni RENCANA (teks langkah + perintah verifikasi untuk
operator) — tidak pernah mengeksekusi apa pun sendiri. Operator-gated.

Modul murni (tanpa network, tanpa import vulnscan2) — unit-testable.
Dipakai: python3 -c "import chainplanner; print(chainplanner.plan(findings))"
atau dari lapisan laporan.
"""

# ---- aturan rantai: (kondisi temuan, langkah yang menyusul)
_RULES = [
    # SSTI + akses config -> RCE -> sesi
    ({"ssti": ["ssti"], "cfg": ["config"]},
     "SSTI RCE", [
         "Render engine-specific fingerprint payload (jinja2/mako/freemarker)",
         "Escalate to reading config objects (secret key, DB credentials)",
         "Execute code via template engine gadget (safe verify: arithmetic)",
         "Open session: python3 sesskit.py --target T --upload U --name s.php --lang php",
     ]),
    # SSRF -> cloud metadata -> kredensial
    ({"ssrf": ["ssrf"]},
     "SSRF -> Cloud Metadata", [
         "Point SSRF at 169.254.169.254 (IMDS) — try IMDSv1 (no token)",
         "Grab instance temporary credentials (role access key)",
         "Validate credentials READ-ONLY (sts get-caller-identity / cloud whoami)",
         "Enumerate role permissions (no resource changes)",
     ]),
    # traversal ke file konfigurasi -> kredensial DB
    ({"trav": ["traversal", "lfi"], "cfg2": ["config", "env", ".bak", "secret"]},
     "Traversal -> Credentials", [
         "Extract app config files (.env / config.php / appsettings)",
         "Collect readable DB / SMTP / API key credentials",
         "Verify credentials against non-destructive services (read-only login)",
     ]),
    # deserialization -> sesi
    ({"deser": ["deserialization", "deser"]},
     "Deser -> RCE -> Session", [
         "Pick a confirmed gadget chain (ysoserial/phpggc/pickle)",
         "Use a safe gadget for verification (pingback, no real command)",
         "After RCE is proven: shellhandler.enum() for host inventory",
     ]),
    # spraying -> takeover
    ({"spray": ["password spray", "credential stuffing"]},
     "Spray -> Account Takeover", [
         "Lock accounts that accepted weak passwords (from spray findings)",
         "Verify post-login access: which endpoints open (authz matrix)",
         "Report takeover per-account with session evidence",
     ]),
    # SQLi extract -> dump terpandu
    ({"sqli": ["enumerasi skema", "union"]},
     "SQLi -> Guided Dump", [
         "From enumerated schema, pick credential tables (users/credentials)",
         "Extract limited columns (hash, email) — bounded, for the report",
         "Crack weak hashes offline (operator-gated, outside engine)",
     ]),
]


def plan(findings):
    """Susun rantai dari daftar temuan (list of dict dgn 'title'/'severity').

    Returns list of dict: {"name", "confidence", "entry_finding",
                           "steps": [...], "operator": True}.
    Rantai hanya diusulkan bila temuan pendukung ADA — tidak pernah
    mengeksekusi; semua langkah untuk operator (operator=True)."""
    blob = " | ".join(str(f.get("title", "")).lower() for f in findings)
    severities = {str(f.get("title", "")).lower(): f.get("confidence", "")
                  for f in findings}
    chains = []
    for need, name, steps in _RULES:
        ok = all(any(k in blob for k in kws) for kws in need.values())
        if ok:
            # confidence rantai = min(confidence temuan pemicu)
            confs = [severities.get(k, "") for k in blob.split(" | ")
                     if any(kw in k for kws in need.values() for kw in kws)]
            rank = {"confirmed": 2, "probable": 1, "candidate": 0}
            best = 2
            for c in confs:
                if c in rank:
                    best = min(best, rank[c])
            chains.append({
                "name": name,
                "confidence": {2: "confirmed", 1: "probable",
                               0: "candidate"}[best],
                "steps": steps,
                "operator": True,
            })
    return chains


def summarize(chains):
    """Ringkasan teks untuk laporan (read-only)."""
    if not chains:
        return "No exploit chain can be built from these findings."
    out = ["Recommended exploit chains (PLAN — operator-gated):"]
    for c in chains:
        out.append(f"- {c['name']} [{c['confidence']}]")
        for i, s in enumerate(c["steps"], 1):
            out.append(f"    {i}. {s}")
    return "\n".join(out)
