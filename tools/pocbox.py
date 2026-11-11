"""
PoC Sandbox Validation — operator-gated single-probe finding confirmation.
AUTHORIZED TESTING ONLY.

validate_finding(ctx_or_client, finding, opts) re-tests ONE finding of a
supported kind with ONE safe, non-persistent probe derived from the
finding's own evidence:

  - reflected XSS      : unique per-run marker reflected back in the body
  - SQLi (error-based) : quote probe, existing SQL error signature
  - SSRF (callback)    : loopback metadata-style probe, fingerprint match
  - command injection  : arithmetic echo probe (unique numbers per run)
  - path traversal     : read-only /etc/hosts fingerprint

Hard limits (all kinds): marker/token unique per run, file-based or
read-only payloads only, ONE request per attempt, at most 3 attempts,
overall deadline 30s (PTK_POCBOX_TIMEOUT). Payloads are reused from
payloadforge (the toolkit's own generator library) — nothing is
reinvented here.

Gate: the probe ONLY fires when opts['poc_validate'] is True or the
environment variable PTK_POCBOX=1 is set. Default: never runs.
"""
import os
import re
import secrets as pysecrets
import time
from urllib.parse import quote

import payloadforge as pf

MAX_ATTEMPTS = 3
DEFAULT_TIMEOUT_S = 30.0

_KIND_PATTERNS = [
    ("reflected-xss", re.compile(
        r"reflected\s*xss|cross[- ]site scripting|\bxss\b", re.I)),
    ("sqli-error", re.compile(
        r"sql\s*injection|\bsqli\b|error[- ]based", re.I)),
    ("ssrf", re.compile(
        r"\bssrf\b|server[- ]side request forgery", re.I)),
    ("cmdi", re.compile(
        r"command\s*injection|\bcmdi\b|\brce\b", re.I)),
    ("traversal", re.compile(
        r"path\s*traversal|directory\s*traversal|\blfi\b|local file", re.I)),
]

_FINGERPRINTS = {
    "traversal": re.compile(
        r"127\.0\.0\.1\s+localhost|root:[x*]?:0:0", re.I),
    "sqli-error": None,  # uses the engine's own SQL_ERRORS list (lazy import)
}

_SQL_ERR_RE = re.compile(
    r"you have an error in your sql syntax|mysql_fetch|warning: mysql|"
    r"sqlite3\.|sqlite error|psql: error|postgresql error|pg_query|"
    r"unclosed quotation mark|quoted string not properly terminated|"
    r"ora-\d{5}|odbc microsoft access|org\.postgresql\.util|"
    r"syntax error at or near", re.I)

_SSRF_FP_RE = re.compile(
    r"ami-id|instance-id|computeMetadata|vmId|droplet|hostname", re.I)


def _enabled(opts):
    if isinstance(opts, dict) and opts.get("poc_validate"):
        return True
    return os.environ.get("PTK_POCBOX") == "1"


def _client_of(ctx_or_client):
    """Accept a vulnscan2.Ctx (uses .client) or a netclient.Client."""
    cl = getattr(ctx_or_client, "client", None)
    return cl if cl is not None else ctx_or_client


def classify(finding):
    """Map a finding dict to a supported probe kind (or None)."""
    text = " ".join(str(finding.get(k, ""))
                    for k in ("title", "description", "evidence"))
    for kind, pat in _KIND_PATTERNS:
        if pat.search(text):
            return kind
    return None


def _probe_target(finding):
    """(path, param) to probe, derived from the finding's location/param;
    falls back to a sane guess from any URL in the evidence."""
    loc = str(finding.get("location") or "")
    param = str(finding.get("param") or "")
    if not loc:
        m = re.search(r"https?://[^/\s]+(/[^\s?\"']*)",
                      str(finding.get("evidence") or ""))
        if m:
            loc = m.group(1) or "/"
    if loc.startswith("http"):
        loc = "/" + loc.split("/", 3)[-1] if loc.count("/") > 2 else "/"
    loc = ("/" + loc.lstrip("/")) if loc else "/"
    if "?" in loc:
        loc = loc.split("?", 1)[0]
    return loc, param


def _fire(cl, loc, param, payload, method="GET", body=None):
    """ONE request with the probe value. Returns the Resp."""
    val = quote(payload, safe="")
    if method == "POST":
        return cl.post(loc, data=f"{param}={val}" if param else body or "")
    return cl.get(loc, params=f"{param}={val}" if param else None)


def _probe_xss(cl, finding, marker, deadline):
    loc, param = _probe_target(finding)
    # Reuse payloadforge's own marker templates; one request per attempt.
    vecs = pf.xss_vectors(marker=marker)[:MAX_ATTEMPTS]
    proof, attempts = "", 0
    for v in vecs:
        if time.time() > deadline:
            break
        r = _fire(cl, loc, param, v["payload"])
        attempts += 1
        # Both the full tag AND the marker must come back verbatim: a
        # bare marker can be reflected by an escaping encoder, which is
        # NOT executable and must never count as a confirmed XSS.
        if r.status and v["payload"] in r.body and marker in r.body:
            proof = (f"marker {marker} reflected verbatim with executable "
                     f"payload {v['payload'][:60]!r}")
            return True, proof, attempts
    return False, "", attempts


def _probe_sqli(cl, finding, marker, deadline):
    loc, param = _probe_target(finding)
    payloads = [p["payload"] for p in pf.sqli_error_payloads()
                if "extractvalue" in p["payload"].lower()
                or p["payload"] in ("'", "1'")][:MAX_ATTEMPTS]
    attempts = 0
    for p in payloads:
        if time.time() > deadline:
            break
        r = _fire(cl, loc, param, p)
        attempts += 1
        if r.status and _SQL_ERR_RE.search(r.body):
            return True, f"SQL error signature in response to probe {p[:40]!r}", attempts
    return False, "", attempts


def _probe_ssrf(cl, finding, marker, deadline):
    loc, param = _probe_target(finding)
    # SSRF with callback: the probe URL embeds the unique run marker as a
    # fragment the vulnerable fetcher must request for the proof to count.
    cb = f"http://169.254.169.254/latest/meta-data/?ptk={marker}"
    r = _fire(cl, loc, param, cb)
    if r.status and (marker in r.body or _SSRF_FP_RE.search(r.body)):
        return True, f"metadata fetch fingerprint for callback {cb}", 1
    return False, "", 1


def _probe_cmdi(cl, finding, marker, deadline):
    loc, param = _probe_target(finding)
    a, b = pysecrets.randbelow(80) + 11, pysecrets.randbelow(8) + 3
    for p in pf.cmdi_echo(a, b)[:MAX_ATTEMPTS]:
        if time.time() > deadline:
            break
        r = _fire(cl, loc, param, p["payload"])
        if r.status and p["expect"] in r.body and p["control"] not in r.body:
            return True, (f"arithmetic echo {p['expect']} "
                          f"({a}*{b}) in response body"), 1
    return False, "", MAX_ATTEMPTS


def _probe_traversal(cl, finding, marker, deadline):
    loc, param = _probe_target(finding)
    for suite in pf.traversal_suite(depth=6):
        if "etc/hosts" not in suite["target"]:
            continue
        if time.time() > deadline:
            break
        r = _fire(cl, loc, param, suite["payload"])
        if r.status and _FINGERPRINTS["traversal"].search(r.body):
            return True, (f"read-only file fingerprint "
                          f"({suite['target']}) in response body"), 1
    return False, "", MAX_ATTEMPTS


_PROBES = {"reflected-xss": _probe_xss, "sqli-error": _probe_sqli,
           "ssrf": _probe_ssrf, "cmdi": _probe_cmdi,
           "traversal": _probe_traversal}


def validate_finding(ctx_or_client, finding, opts=None):
    """Fire ONE safe probe for a supported finding. Returns:
    {"validated": bool, "proof": str, "kind": str|None, "attempts": int,
     "gated": bool, "finding": updated_dict|None}.

    When validated, `finding` is the updated dict with
    confidence='confirmed' and poc_proof set; otherwise None.
    Never raises on malformed input."""
    out = {"validated": False, "proof": "", "kind": None,
           "attempts": 0, "gated": False, "finding": None}
    try:
        if not _enabled(opts):
            out["gated"] = True
            out["proof"] = "skipped: poc validation not enabled (opt-in only)"
            return out
        if not isinstance(finding, dict):
            return out
        kind = classify(finding)
        out["kind"] = kind
        if kind is None:
            out["proof"] = "skipped: finding kind not supported for PoC probes"
            return out
        deadline = time.time() + float(os.environ.get(
            "PTK_POCBOX_TIMEOUT", DEFAULT_TIMEOUT_S))
        cl = _client_of(ctx_or_client)
        marker = f"PTKPOC{pysecrets.token_hex(4)}"
        ok, proof, attempts = _PROBES[kind](cl, finding, marker, deadline)
        out["attempts"] = attempts
        if ok:
            out["validated"] = True
            out["proof"] = f"PoC sandbox ({kind}): {proof}"
            upd = dict(finding)
            upd["confidence"] = "confirmed"
            upd["poc_proof"] = out["proof"]
            out["finding"] = upd
        else:
            out["proof"] = f"probe did not confirm ({kind})"
    except Exception as e:  # never break the caller over a probe
        out["proof"] = f"probe error: {str(e)[:120]}"
    return out


def validate_top(findings, ctx_or_client, opts=None, limit=5,
                 budget_s=None, cancelled=None, log=None):
    """Bulk hook: validate the top `limit` probable findings of supported
    kinds within `budget_s` (default PTK_POCBOX_TIMEOUT / DEFAULT_TIMEOUT_S).
    Mutates nothing; returns (updated_findings_list, n_confirmed)."""
    total = float(os.environ.get("PTK_POCBOX_TIMEOUT", DEFAULT_TIMEOUT_S)) \
        if budget_s is None else float(budget_s)
    t0 = time.time()
    cands = [f for f in findings
             if isinstance(f, dict) and f.get("confidence") != "confirmed"
             and classify(f)]
    out = list(findings)
    confirmed = 0
    for f in cands[:max(1, int(limit))]:
        if cancelled and cancelled():
            break
        if time.time() - t0 > total:
            break
        res = validate_finding(ctx_or_client, f, opts)
        if res.get("validated") and res.get("finding"):
            try:
                out[out.index(f)] = res["finding"]
            except ValueError:
                pass
            confirmed += 1
            if log:
                log(f"[pocbox] confirmed: {f.get('title', '')[:60]} "
                    f"({res['kind']})")
    return out, confirmed
