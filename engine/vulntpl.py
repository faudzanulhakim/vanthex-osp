"""
VulnTPL v1 — custom detection templates for VANTHEX (JSON, no YAML).

Define your own detection checks in 5 lines of JSON — without touching
Python. Templates live in the `templates/*.json` directory; the check engine
`c_custom_templates` runs them all during a scan.

Template shape:
{
  "name": "Example: exposed key file",
  "severity": "MEDIUM",
  "cwe": "CWE-538",
  "requests": [
    {"path": "/vault/keys.txt", "method": "GET"},
    {"path": "/api/config", "method": "POST", "body": "{\"a\":1}",
     "headers": {"Content-Type": "application/json"}}
  ],
  "match": "status=200 && body~api_key"
}

Match expressions (&& / || / simple grouping, evaluated in order):
  status=<code>          exact HTTP status
  status~<code>          HTTP status prefix (e.g. status~4)
  body~<substring>       body contains substring (case-insensitive)
  body!~<substring>      body does NOT contain substring
  bodyre~<regex>         body matches regex (case-insensitive)
  header~<name>:<value>  header contains value (case-insensitive)

Safe: templates are read-only GET/POST only; expressions are evaluated in
sandboxed small functions (no free eval() — manual parser).
"""
import json as _json
import os as _os
import re as _re

TEMPLATE_DIR = "templates"      # relative to project root (cwd during scan)
MAX_TEMPLATES = 50
MAX_REQUESTS_PER_TEMPLATE = 12


def load_templates(directory=TEMPLATE_DIR):
    """Load all JSON templates in the directory. Returns (templates, errors)."""
    if not _os.path.isdir(directory):
        return [], []
    out, errs = [], []
    for fn in sorted(_os.listdir(directory))[:MAX_TEMPLATES]:
        if not fn.endswith(".json"):
            continue
        try:
            with open(_os.path.join(directory, fn), encoding="utf-8") as fh:
                t = _json.load(fh)
            t["_source"] = fn
            _validate(t)
            out.append(t)
        except Exception as e:
            errs.append(f"{fn}: {e}")
    return out, errs


def _validate(t):
    if not isinstance(t.get("requests"), list) or not t["requests"]:
        raise ValueError("template requires 'requests' containing a list")
    if len(t["requests"]) > MAX_REQUESTS_PER_TEMPLATE:
        raise ValueError("too many requests per template")
    for r in t["requests"]:
        if str(r.get("method", "GET")).upper() not in ("GET", "POST", "HEAD"):
            raise ValueError("method must be GET/POST/HEAD (read-only)")
        if not str(r.get("path", "")).startswith("/"):
            raise ValueError("path must be relative (start with '/')")
    if not str(t.get("match", "")).strip():
        raise ValueError("template requires 'match'")


def _one(clause, resp):
    """Evaluate ONE match clause against the response."""
    clause = clause.strip()
    if not clause:
        return False
    body = (getattr(resp, "body", "") or "")
    headers = dict((k.lower(), v) for k, v in (getattr(resp, "headers", None) or []))
    status = getattr(resp, "status", 0)
    neg = False
    if clause.startswith("body!~"):
        neg, clause = True, clause[6:]
    if clause.startswith("status="):
        return (status == int(clause[7:].strip())) != neg
    if clause.startswith("status~"):
        return str(status).startswith(clause[7:].strip()) != neg
    if clause.startswith("body~"):
        return (clause[5:].strip().lower() in body.lower()) != neg
    if clause.startswith("bodyre~"):
        try:
            return bool(_re.search(clause[7:].strip(), body, _re.I)) != neg
        except _re.error:
            return False
    if clause.startswith("header~"):
        nv = clause[7:].split(":", 1)
        if len(nv) != 2:
            return False
        return (nv[0].strip().lower() in headers
                and nv[1].strip().lower() in headers[nv[0].strip().lower()].lower()) != neg
    return False


def match(resp, expr):
    """Evaluate a match expression: clauses combined with && / || (left to
    right, && binds tighter). No free eval() — manual parser, safe."""
    expr = str(expr or "").strip()
    if not expr:
        return False
    # split top-level || first, then && within each segment
    ors = [s.strip() for s in expr.split("||")]
    for seg in ors:
        clauses = [c.strip() for c in seg.split("&&") if c.strip()]
        if clauses and all(_one(c, resp) for c in clauses):
            return True
    return False


def run_template(ctx, t):
    """Run one template: send requests in sequence, match is evaluated
    against the LAST response. Returns (bool, evidence_str)."""
    last = None
    trail = []
    for r in t["requests"][:MAX_REQUESTS_PER_TEMPLATE]:
        if ctx.cancelled():
            return False, ""
        method = str(r.get("method", "GET")).upper()
        path = r["path"]
        try:
            if method == "POST":
                last = ctx.client.post(path, data=r.get("body") or "",
                                       headers=r.get("headers") or {})
            else:
                last = ctx.client.get(path, headers=r.get("headers") or {})
        except Exception:
            from netclient import Resp  # noqa: F401  (consistent fallback)
            class _R:
                status = 0
                body = ""
                headers = []
            last = _R()
        trail.append(f"{method} {path} -> {getattr(last, 'status', 0)}")
    ok = match(last, t.get("match"))
    return ok, "; ".join(trail)


def run_all(ctx, add, directory=TEMPLATE_DIR):
    """Run all templates against the target. Returns the finding count."""
    templates, errs = load_templates(directory)
    for e in errs:
        ctx.L(f"  [vulntpl] invalid template: {e}")
    n = 0
    for t in templates:
        if ctx.cancelled():
            return n
        ok, ev = run_template(ctx, t)
        if ok:
            n += 1
            add(_mk_finding(t, ev))
    return n


def _mk_finding(t, evidence):
    sev = str(t.get("severity", "MEDIUM")).upper()
    if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        sev = "MEDIUM"
    return {"severity": sev,
            "title": f"Custom Template — {t.get('name', 'unnamed')}",
            "description": "Finding from an operator-written custom detection "
                           "template (vulntpl) — not a built-in check; "
                           "manual verification recommended.",
            "evidence": evidence,
            "cwe": str(t.get("cwe", "CWE-200")),
            "owasp": "A05:2021 Security Misconfiguration",
            "cvss": float(t.get("cvss", 5.0) or 5.0),
            "remediation": "Follow remediation according to the template context.",
            "confidence": "confirmed",
            "location": (t.get("requests") or [{}])[-1].get("path", ""),
            "param": "",
            "origin": "vulntpl"}
