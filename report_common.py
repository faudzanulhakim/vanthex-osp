"""Konten laporan bersama untuk generator HTML & DOCX (v3.4.1).

Standar industri / platform bug bounty (HackerOne): setiap temuan dilengkapi
vektor CVSS v3.1, langkah reproduksi, kerangka proof-of-concept, dampak
spesifik kelas kerentanan, dan referensi. Vektor CVSS di sini adalah base
metric REPRESENTATIF untuk kelas kelemahannya (pola yang sama dengan plugin
description scanner komersial) — wajib divalidasi terhadap lingkungan target
sebelum submisi eksternal; skor numerik temuan tetap yang utama.
"""
import re
from urllib.parse import urlsplit

# Vektor representatif per CWE (base metrics CVSS v3.1).
CVSS_BY_CWE = {
    "CWE-89": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-564": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-78": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-79": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "CWE-80": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "CWE-918": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    "CWE-611": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-22": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-352": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    "CWE-639": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "CWE-862": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "CWE-601": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "CWE-942": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    "CWE-113": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    "CWE-200": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "CWE-209": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "CWE-359": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-306": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-798": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-307": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-319": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-295": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CWE-384": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",
    "CWE-434": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CWE-770": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "CWE-90": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "CWE-943": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "CWE-1188": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
}
CVSS_BY_SEV = {
    "CRITICAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "HIGH": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "MEDIUM": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "LOW": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "INFO": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
}

IMPACT_BY_CWE = {
    "CWE-89": "An attacker can read, modify, or delete database data, bypass authentication, and on certain configurations execute system commands \u2014 a full compromise of application data.",
    "CWE-78": "An attacker executes operating system commands with the server process privileges \u2014 server takeover, pivoting into the internal network, and data theft.",
    "CWE-79": "Attacker script runs in the victim's browser within the application session context \u2014 session/token theft, actions on behalf of the victim, and trusted defacement/phishing.",
    "CWE-918": "The server can be forced to reach internal services/cloud metadata \u2014 leakage of instance credentials and access to systems not exposed to the internet.",
    "CWE-611": "The XML parser processes external entities \u2014 local file disclosure, SSRF, and denial of service (billion laughs).",
    "CWE-22": "An attacker reads arbitrary files on the server (configuration, credentials, source code) \u2014 a foundation for further compromise.",
    "CWE-352": "The victim's browser sends state-changing requests with their credentials \u2014 unauthorized actions on behalf of the victim.",
    "CWE-639": "A user can access or modify other users' data by guessing identifiers \u2014 a breach of confidentiality and integrity of data between users.",
    "CWE-862": "Functions/data can be accessed without authorization checks \u2014 exposure of data/functions beyond the user's privileges.",
    "CWE-601": "Users are redirected to an attacker site from a trusted domain \u2014 credential phishing riding on the victim domain's trust.",
    "CWE-942": "Any website can read API responses with the victim's credentials \u2014 cross-origin data theft.",
    "CWE-434": "Malicious files can be uploaded and potentially executed or publicly accessed \u2014 webshells and server compromise.",
    "CWE-306": "The service can be used without any authentication \u2014 exposure of critical functions/data to unauthorized parties.",
    "CWE-798": "Embedded/default credentials open direct access \u2014 account/service takeover.",
    "CWE-307": "Without rate limiting, credentials can be brute-forced until successful.",
    "CWE-770": "Without rate limiting, credentials can be brute-forced until successful.",
}
IMPACT_GENERIC = {
    "CRITICAL": "Exploitation could result in a full compromise of the system's confidentiality, integrity, and/or availability.",
    "HIGH": "Exploitation could result in significant unauthorized access or sensitive data leakage.",
    "MEDIUM": "Exploitation could result in limited information disclosure, weakened security controls, or a link in a longer attack chain.",
    "LOW": "Direct impact is limited, but the finding weakens defense in depth and can be combined with other findings.",
    "INFO": "Contextual information for hardening; no direct exploitation impact identified.",
}

OBSERVE_BY_KEY = [
    ("sql", "The response contains a database error message / boolean difference / time delay that does not appear in the baseline (see Evidence)."),
    ("xss", "The payload is reflected in the response without adequate encoding (see Evidence)."),
    ("command", "Computed output / a command marker appears in the response \u2014 proof of execution, not mere reflection (see Evidence)."),
    ("ssrf", "The response contains content from the internal/metadata target the server was made to fetch (see Evidence)."),
    ("xxe", "The response contains the contents of the file referenced by the external entity in the XML document (see Evidence)."),
    ("traversal", "The response contains contents of a file outside the directory that should be accessible (see Evidence)."),
    ("idor", "Object data belonging to another context is returned without effective authorization checks (see Evidence)."),
    ("redirect", "The Location header points to an external domain controlled by the tester."),
    ("cors", "The Access-Control-Allow-Origin header reflects the attacker origin, combined with Allow-Credentials: true."),
    ("cookie", "The Set-Cookie header in the response lacks the expected security attributes (see Evidence)."),
    ("header", "An expected security header is missing or misconfigured in the response (see Evidence)."),
]


def _cwe_id(f):
    m = re.search(r"(\d{2,4})", str(f.get("cwe") or ""))
    return f"CWE-{m.group(1)}" if m else ""


def cvss_vector(f):
    """Vektor CVSS v3.1 representatif per kelas kelemahan temuan."""
    return CVSS_BY_CWE.get(_cwe_id(f)) or CVSS_BY_SEV.get(f.get("severity"), CVSS_BY_SEV["INFO"])


def impact_for(f):
    return IMPACT_BY_CWE.get(_cwe_id(f)) or IMPACT_GENERIC.get(f.get("severity"), "")


def steps_for(f, target=""):
    """Langkah reproduksi gaya HackerOne, dibangun dari atribut temuan."""
    loc = f.get("location") or "/"
    prm = f.get("param") or ""
    ev = str(f.get("evidence") or "")
    steps = []
    steps.append(f"Open the target application ({target or loc}) with a standard HTTP client/browser, without any special privileges beyond those stated in the finding.")
    if prm:
        steps.append(f"Send a request to {loc} with the '{prm}' parameter set to the test value recorded in this finding's Evidence section.")
    else:
        steps.append(f"Send a standard request (GET) to {loc} and inspect the response headers and body.")
    m = re.search(r"payload=\s*('(?:[^']*)'|\"(?:[^\"]*)\"|\S+)", ev)
    if m:
        steps.append(f"Test value used: {m.group(1)[:120]}")
    title_l = (f.get("title") or "").lower()
    obs = next((txt for key, txt in OBSERVE_BY_KEY if key in title_l),
               "The vulnerable behavior recorded in the Evidence is observed in the response.")
    steps.append(f"Observe the result: {obs}")
    steps.append("As a control, repeat the request with a normal value (baseline) \u2014 the behavior above does not occur, confirming the finding is specific to the test value.")
    return steps


def poc_for(f, target=""):
    """Kerangka request PoC (nilai uji dirujuk ke Evidence — bukan difabrikasi)."""
    loc = f.get("location") or ""
    if not loc:
        return ""
    host = urlsplit(target).netloc if target else ""
    prm = f.get("param") or ""
    path = loc if loc.startswith("/") else "/" + loc
    qs = f"?{prm}=<test-value-from-evidence>" if prm else ""
    lines = [f"GET {path}{qs} HTTP/1.1"]
    if host:
        lines.append(f"Host: {host}")
    lines.append("User-Agent: Mozilla/5.0 (penetration test — authorized)")
    lines.append("Accept: */*")
    return "\n".join(lines)


def refs_for(f):
    refs = []
    cid = _cwe_id(f)
    if cid:
        refs.append(f"{cid}: https://cwe.mitre.org/data/definitions/{cid.split('-')[1]}.html")
    if f.get("owasp"):
        refs.append(f"Category: {f['owasp']} \u2014 OWASP Top 10 / API Security Top 10")
    refs.append("Testing guide: OWASP Web Security Testing Guide (WSTG) \u2014 https://owasp.org/www-project-web-security-testing-guide/")
    refs.append("CVSS v3.1 calculator & specification: https://www.first.org/cvss/calculator/3.1")
    return refs

def data_fingerprint(scan):
    """SHA-256 over the canonical source data (target + finding list).
    Printed in the report's Document Control so a recipient can verify
    the report's contents against the stored scan data."""
    import hashlib
    import json as _json
    findings = scan.get("findings")
    if findings is None:
        res = scan.get("result")
        if isinstance(res, str):
            try:
                res = _json.loads(res)
            except Exception:
                res = {}
        findings = (res or {}).get("findings", [])
    canon = {"target": scan.get("target"),
             "type": scan.get("scan_type") or scan.get("type"),
             "profile": scan.get("profile"),
             "started": scan.get("started_at"),
             "findings": [[f.get("title"), f.get("severity"),
                           f.get("location")] for f in findings]}
    return hashlib.sha256(_json.dumps(
        canon, sort_keys=True, default=str).encode()).hexdigest()
