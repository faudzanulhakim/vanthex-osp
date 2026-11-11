"""
ChainPlanner v1 — exploit chain planner for VANTHEX. Read-only.

Takes a list of scan findings and builds an ATTACK CHAIN: an ordered
sequence of verifiable steps that combine several findings into a
take-over path. The output is purely a PLAN (step text + verification
commands for the operator) — it never executes anything itself.
Operator-gated.

Pure module (no network, no vulnscan2 import) — unit-testable.
Usage: python3 -c "import chainplanner; print(chainplanner.plan(findings))"
or from the reporting layer.
"""

# ---- chain rules: (finding conditions, resulting steps)
_RULES = [
    # SSTI + config access -> RCE -> session
    ({"ssti": ["ssti"], "cfg": ["config"]},
     "SSTI RCE", [
         "Render engine-specific fingerprint payload (jinja2/mako/freemarker)",
         "Escalate to reading config objects (secret key, DB credentials)",
         "Execute code via template engine gadget (safe verify: arithmetic)",
         "Open session: python3 sesskit.py --target T --upload U --name s.php --lang php",
     ]),
    # SSRF -> cloud metadata -> credentials
    ({"ssrf": ["ssrf"]},
     "SSRF -> Cloud Metadata", [
         "Point SSRF at 169.254.169.254 (IMDS) — try IMDSv1 (no token)",
         "Grab instance temporary credentials (role access key)",
         "Validate credentials READ-ONLY (sts get-caller-identity / cloud whoami)",
         "Enumerate role permissions (no resource changes)",
     ]),
    # traversal to config files -> DB credentials
    ({"trav": ["traversal", "lfi"], "cfg2": ["config", "env", ".bak", "secret"]},
     "Traversal -> Credentials", [
         "Extract app config files (.env / config.php / appsettings)",
         "Collect readable DB / SMTP / API key credentials",
         "Verify credentials against non-destructive services (read-only login)",
     ]),
    # deserialization -> session
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
    # SQLi extract -> guided dump
    ({"sqli": ["schema enumeration", "union"]},
     "SQLi -> Guided Dump", [
         "From enumerated schema, pick credential tables (users/credentials)",
         "Extract limited columns (hash, email) — bounded, for the report",
         "Crack weak hashes offline (operator-gated, outside engine)",
     ]),
]


def plan(findings):
    """Build chains from a list of findings (list of dicts with 'title'/'severity').

    Returns a list of dicts: {"name", "confidence", "entry_finding",
                              "steps": [...], "operator": True}.
    Chains are only proposed when the supporting findings EXIST — never
    executes; all steps are for the operator (operator=True)."""
    blob = " | ".join(str(f.get("title", "")).lower() for f in findings)
    severities = {str(f.get("title", "")).lower(): f.get("confidence", "")
                  for f in findings}
    chains = []
    for need, name, steps in _RULES:
        ok = all(any(k in blob for k in kws) for kws in need.values())
        if ok:
            # chain confidence = min(confidence of the triggering findings)
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
    """Text summary for reports (read-only)."""
    if not chains:
        return "No exploit chain can be built from these findings."
    out = ["Recommended exploit chains (PLAN — operator-gated):"]
    for c in chains:
        out.append(f"- {c['name']} [{c['confidence']}]")
        for i, s in enumerate(c["steps"], 1):
            out.append(f"    {i}. {s}")
    return "\n".join(out)
