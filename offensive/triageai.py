"""TriageAI — local heuristic false-positive killer (v3).

Pure-python rule+scoring engine that re-reasons each finding's evidence
the way an analyst would: executed proof and differential verification
push exploitability up, reflection-only evidence pushes false-positive
risk up, URL-encoded markers or login-redirect contexts push false-
positive risk up hard, database/stack-trace error strings push
exploitability up, version-fingerprint findings are capped, and findings
that ship a manual_check recipe gain confidence.

No network, no LLM calls. triage() and score_finding() are safe pure
data re-reasoning and are NOT gated. run_triage_on_scan() — the wrapper
that is meant to run over a completed scan's stored findings and persist
results — IS gated behind PTK_TRIAGE=1 (same operator-gate model as
llmv2.py / PTK_LLMV2=1, pocbox.py / PTK_POCBOX=1).

Future LLM hook: triage(..., llm_scorer=callable) accepts an optional
scorer callable of shape llm_scorer(finding, rule_score) -> dict with
keys {verdict, exploitability, fp_risk, reasons}. When provided and it
returns a well-formed dict, its verdict/scores override the rule engine
for that finding (documented for a future local-LLM integration; the
rule score is always passed as the second argument so the model can
reason about, or blend with, the heuristic result).
"""
import copy as _copy
import os as _os
import re as _re

__version__ = "1.0.0"

VERDICTS = ("likely-exploitable", "needs-human-look", "likely-false-positive")

# verdict thresholds
EXPLOITABLE_MIN = 7        # exploitability at/above this -> likely-exploitable
FP_RISK_HIGH = 7           # fp_risk at/above this -> likely-false-positive
FP_DOMINANCE_GAP = 2       # fp_risk exceeding exploitability by this -> FP

# cross-finding correlation: bounded bonus applied to each reinforced score
CORR_BONUS = 1.5
CORR_BONUS_MAX = 3.0

# --- evidence keyword banks -------------------------------------------------

# executed proof / differential confirmation markers (verification text
# or evidence showing the payload actually RAN, not merely echoed)
_EXECUTED_PROOF = (
    "uid=", "alert(1)", "alert(1) fired", "executed", "command output",
    "root:", "sleep took", "timing difference", "response time",
    "differential", "differed from baseline", "differing response",
    "boolean", "true/false", "different size", "out-of-band",
    "callback hit", "dns hit", "http hit", "metadata service",
    "ami-id", "instance-id", "confirmed by hand", "exec-proof",
    "sleep(5)", "sleep 5", "whoami", "document.write executed",
)

# reflection-only phrasing: the marker came back but nothing executed
_REFLECTION_ONLY = (
    "reflected", "echoed", "reflection", "appears in the response",
    "marker was returned", "value is echoed", "plain reflection",
    "reflected verbatim", "no execution", "not executed",
    "payload appears in response",
)

# URL-encoded payload markers: evidence quoting the ENCODED form usually
# means the scanner matched its own encoded input (weak signal)
_URL_ENCODED_MARKER = (
    "%3c", "%3e", "%27", "%22", "%28", "%29", "%3csvg", "%2f", "%3d",
    "%3csvg%2fonload", "svg%2fonload", "%24%28", "%7c", "%3a%2f%2f",
    "..%2f", "%2e%2e%2f",
)

# login/redirect context: reflection inside a login page or auth redirect
# chain is the classic false-positive story for reflected-input findings
_LOGIN_REDIRECT_CTX = (
    "login", "sign in", "signin", "log-in", "redirected to login",
    "authentication redirect", "auth redirect", "302 to login",
    "location: /login", "redirect_uri", "returnurl", "next=/",
    "session timeout", "unauthenticated",
)

# database / interpreter error strings — strong exploitation signal
_ERROR_SIGNATURES = (
    "sql syntax", "sqlstate", "ORA-", "psql:", "mysql", "postgresql",
    "sqlite", "unterminated", "syntax error", "quoted string not",
    "mysql_fetch", "warning: sqlite", "traceback (most recent",
    "stack trace", "exception in", "fatal error", "parse error",
    "java.sql", "hibernate", "odbc", "you have an error in your sql",
)

# version-fingerprint finding classes: informational by nature
_VERSION_FINGERPRINT_WORDS = (
    "version disclosure", "version-disclosure", "fingerprint",
    "server banner", "technology disclosure", "version detection",
    "server header", "x-powered-by",
)


def _text_of(f, *keys):
    return " ".join(str(f.get(k) or "") for k in keys).lower()


def _is_version_fingerprint(f):
    hay = _text_of(f, "title", "cwe", "owasp", "tags")
    return any(w in hay for w in _VERSION_FINGERPRINT_WORDS)


def _count_hits(text, bank):
    return sum(1 for w in bank if w in text)


def score_finding(f):
    """Re-reason one finding's evidence like an analyst.

    Returns {"exploitability": 0-10, "fp_risk": 0-10,
             "verdict": one of VERDICTS, "reasons": [str, ...]}.
    Never raises on malformed input; never touches the network.
    """
    try:
        if not isinstance(f, dict):
            f = {}
        ver = _text_of(f, "verification", "verification_note")
        ev = _text_of(f, "evidence", "description")
        title = _text_of(f, "title", "cwe", "owasp")
        conf = str(f.get("confidence") or "").lower()
        reasons = []

        exploit = 2.0   # baseline: unverified candidate
        fp_risk = 2.0

        # --- executed proof / differential verification ----------------
        n_exec = _count_hits(ver, _EXECUTED_PROOF) + _count_hits(ev, _EXECUTED_PROOF)
        if n_exec:
            exploit += min(5.0, 1.5 + 1.5 * n_exec)
            reasons.append(
                "Executed/differential proof markers in verification or "
                "evidence (%d hit%s) push exploitability up"
                % (n_exec, "" if n_exec == 1 else "s"))
        if conf == "confirmed":
            exploit += 2.0
            reasons.append("Finding carries 'confirmed' confidence (+2 exploitability)")

        # --- reflection-only evidence ---------------------------------
        n_refl = _count_hits(ev, _REFLECTION_ONLY)
        n_exec_in_ev = _count_hits(ev, _EXECUTED_PROOF)
        if n_refl and not n_exec_in_ev:
            fp_risk += min(5.0, 2.0 + 1.5 * n_refl)
            reasons.append(
                "Evidence is reflection-only (payload echoed, no execution "
                "marker) — weak signal, fp_risk up")

        # --- URL-encoded marker in evidence: fp_risk up HARD -----------
        n_enc = _count_hits(ev, _URL_ENCODED_MARKER)
        if n_enc:
            fp_risk += min(6.0, 4.0 + n_enc)
            reasons.append(
                "Evidence quotes URL-encoded payload (%d encoded token%s) — "
                "likely matched the scanner's own encoded input; fp_risk up "
                "hard" % (n_enc, "" if n_enc == 1 else "s"))

        # --- login-redirect context: fp_risk up HARD --------------------
        n_login = _count_hits(ev + " " + ver, _LOGIN_REDIRECT_CTX)
        if n_login:
            fp_risk += min(6.0, 4.0 + n_login)
            reasons.append(
                "Evidence/verification sits in a login-redirect context "
                "(%d hit%s) — classic reflected-input false-positive "
                "setting; fp_risk up hard"
                % (n_login, "" if n_login == 1 else "s"))

        # --- error signatures: exploitability up -----------------------
        n_err = _count_hits(ev, _ERROR_SIGNATURES)
        if n_err:
            exploit += min(4.0, 1.5 * n_err)
            reasons.append(
                "Database/interpreter error strings in evidence (%d hit%s) "
                "— injection surface responds; exploitability up"
                % (n_err, "" if n_err == 1 else "s"))

        # --- manual_check present: confidence up -----------------------
        mc = f.get("manual_check")
        if isinstance(mc, dict) and mc.get("commands"):
            exploit += 1.0
            reasons.append("Manual validation recipe available (+1 exploitability confidence)")

        # --- version-fingerprint cap -----------------------------------
        if _is_version_fingerprint(f):
            cap = 3.0
            if exploit > cap:
                reasons.append(
                    "Version-fingerprint finding: exploitability capped at %d"
                    % int(cap))
            exploit = min(exploit, cap)
            fp_risk = max(fp_risk, 4.0)
            reasons.append("Informational fingerprint class — fp_risk floored at 4")

        exploitability = max(0, min(10, round(exploit, 1)))
        fp = max(0, min(10, round(fp_risk, 1)))

        # --- verdict ----------------------------------------------------
        if fp >= FP_RISK_HIGH or (fp - exploitability) >= FP_DOMINANCE_GAP:
            verdict = "likely-false-positive"
        elif exploitability >= EXPLOITABLE_MIN and fp < 5:
            verdict = "likely-exploitable"
        else:
            verdict = "needs-human-look"

        if not reasons:
            reasons.append("No strong signals either way — scored from baseline")
        return {"exploitability": exploitability,
                "fp_risk": fp,
                "verdict": verdict,
                "reasons": reasons}
    except Exception as e:  # contain everything, like manualcheck.py
        return {"exploitability": 0, "fp_risk": 10,
                "verdict": "needs-human-look",
                "reasons": ["Scoring error contained: %s" % e]}


def _key(f):
    return (str(f.get("location") or ""), str(f.get("param") or ""))


def cross_finding_correlation(findings):
    """Reinforce findings that share a location+param.

    Returns (bonus_map, notes): bonus_map maps index-in-list -> bounded
    exploitability bonus; notes flags conflicting verdicts within a
    group (e.g. one says exploitable, another says false positive —
    usually a shared reflection, so treat the pair with suspicion).
    """
    bonus = {}
    notes = []
    groups = {}
    for i, f in enumerate(findings or []):
        groups.setdefault(_key(f), []).append(i)

    for (loc, param), idxs in groups.items():
        if len(idxs) < 2 or (not loc and not param):
            continue
        titles = [str(findings[i].get("title") or "?") for i in idxs]
        verdicts = {}
        for i in idxs:
            t = findings[i].get("triage") or {}
            verdicts.setdefault(t.get("verdict") or "needs-human-look", []).append(i)
        # reinforce each member by a bounded bonus
        per = min(CORR_BONUS_MAX, CORR_BONUS)
        for i in idxs:
            bonus[i] = bonus.get(i, 0.0) + per
        notes.append(
            "Correlated group at %s%s: %s reinforce each other (each +%s "
            "exploitability)" % (loc, (" param=" + param) if param else "",
                                 ", ".join(sorted(set(titles))),
                                 ("%.1f" % per)))
        if len(verdicts) > 1:
            desc = "; ".join("%d x %s" % (len(v), k) for k, v in sorted(verdicts.items()))
            notes.append(
                "Conflicting triage verdicts within correlated group at %s%s "
                "(%s) — usually a shared reflection; reconcile by hand"
                % (loc, (" param=" + param) if param else "", desc))
    return bonus, notes


def triage(findings, llm_scorer=None):
    """Orchestrator: annotate a COPY of the findings list with triage data.

    Each returned finding gains f["triage"] = {verdict, exploitability,
    fp_risk, reasons, note?}. Findings verdicted likely-false-positive
    have their severity demoted to 'info' IN THE RETURNED COPY ONLY
    (the input list and its dicts are never mutated) with a note.
    Returns {"findings": [...], "summary": {...}, "correlation_notes": [...]}.

    llm_scorer (optional callable): llm_scorer(finding, rule_score) -> dict
    with {verdict, exploitability, fp_risk, reasons}. If it returns a
    well-formed dict, its verdict/scores override the rule engine for
    that finding. Documented hook for future local-LLM integration;
    triage() itself makes NO LLM/network calls.
    """
    src = list(findings or [])
    out = _copy.deepcopy(src)

    # pass 1: rule scores on the copies
    rule_scores = []
    for f in out:
        rs = score_finding(f)
        rule_scores.append(rs)
        tri = {"verdict": rs["verdict"],
               "exploitability": rs["exploitability"],
               "fp_risk": rs["fp_risk"],
               "reasons": list(rs["reasons"]),
               "engine": "heuristic-v3"}
        f["triage"] = tri

    # pass 2: cross-finding correlation — apply bounded bonus, re-verdict
    bonus, corr_notes = cross_finding_correlation(out)
    for i, b in (bonus or {}).items():
        tri = out[i].get("triage") or {}
        exp = max(0, min(10, round((tri.get("exploitability") or 0) + b, 1)))
        tri["exploitability"] = exp
        tri["reasons"] = list(tri.get("reasons") or []) + [
            "Cross-finding correlation: %s findings share this "
            "location+param (bounded bonus +%.1f)" % (len(bonus), b)]
        fp = tri.get("fp_risk") or 0
        if fp >= FP_RISK_HIGH or (fp - exp) >= FP_DOMINANCE_GAP:
            tri["verdict"] = "likely-false-positive"
        elif exp >= EXPLOITABLE_MIN and fp < 5:
            tri["verdict"] = "likely-exploitable"
        else:
            tri["verdict"] = "needs-human-look"

    # pass 3: optional LLM hook overrides rule verdicts
    if llm_scorer is not None:
        for f, rs in zip(out, rule_scores):
            try:
                res = llm_scorer(f, rs)
            except Exception as e:
                f["triage"]["reasons"] = list(f["triage"].get("reasons") or []) + [
                    "llm_scorer raised (ignored): %s" % e]
                continue
            if not isinstance(res, dict):
                continue
            tri = f["triage"]
            v = res.get("verdict")
            if v in VERDICTS:
                tri["verdict"] = v
            for k in ("exploitability", "fp_risk"):
                val = res.get(k)
                if isinstance(val, (int, float)):
                    tri[k] = max(0, min(10, round(float(val), 1)))
            if isinstance(res.get("reasons"), (list, tuple)) and res["reasons"]:
                tri["reasons"] = list(res["reasons"])
            tri["engine"] = "llm-overrides-heuristic-v3"

    # pass 4: demote false positives to info in the returned copy only
    summary = {"total": len(out), "likely-exploitable": 0,
               "needs-human-look": 0, "likely-false-positive": 0,
               "demoted": 0}
    for f in out:
        tri = f.get("triage") or {}
        v = tri.get("verdict") or "needs-human-look"
        summary[v] = summary.get(v, 0) + 1
        if v == "likely-false-positive":
            old = str(f.get("severity") or "?")
            if old.lower() != "info":
                f["severity"] = "info"
                tri["note"] = ("Severity demoted %s -> info by triage "
                               "(likely false positive); original severity "
                               "preserved in source scan" % old)
                summary["demoted"] += 1

    return {"findings": out, "summary": summary,
            "correlation_notes": corr_notes}


def render_triage_summary(triage_result):
    """English markdown table of the triage result, for the report."""
    try:
        if not isinstance(triage_result, dict):
            return "Triage summary unavailable (malformed result)."
        fs = triage_result.get("findings") or []
        summary = triage_result.get("summary") or {}
        lines = ["## AI Triage Summary (heuristic v3)", ""]
        lines.append("| # | Severity | Title | Verdict | Exploitability | FP risk |")
        lines.append("|---|----------|-------|---------|----------------|---------|")
        if not fs:
            lines.append("| - | - | (no findings) | - | - | - |")
        for i, f in enumerate(fs, 1):
            tri = f.get("triage") or {}
            title = str(f.get("title") or "(untitled)").replace("|", "\\|")
            sev = str(f.get("severity") or "-")
            note = tri.get("note")
            if note:
                title += " *(demoted)*"
            lines.append(
                "| %d | %s | %s | %s | %s | %s |"
                % (i, sev, title, tri.get("verdict", "-"),
                   tri.get("exploitability", "-"), tri.get("fp_risk", "-")))
        lines.append("")
        lines.append(
            "**Totals:** %d finding(s) — %d likely-exploitable, "
            "%d needs-human-look, %d likely-false-positive (%d demoted "
            "to info in this triaged copy)."
            % (summary.get("total", len(fs)),
               summary.get("likely-exploitable", 0),
               summary.get("needs-human-look", 0),
               summary.get("likely-false-positive", 0),
               summary.get("demoted", 0)))
        notes = triage_result.get("correlation_notes") or []
        if notes:
            lines.append("")
            lines.append("**Correlation notes:**")
            for n in notes:
                lines.append("- " + str(n).replace("\n", " "))
        return "\n".join(lines)
    except Exception as e:
        return "Triage summary render error (contained): %s" % e


def triage_gate_open():
    """Operator gate for the scan wrapper: run only with PTK_TRIAGE=1."""
    return _os.environ.get("PTK_TRIAGE") == "1"


def run_triage_on_scan(findings, llm_scorer=None):
    """Gated wrapper: triage a completed scan's findings and attach the
    markdown summary. Requires PTK_TRIAGE=1 (operator-gated, same model
    as llmv2.py / PTK_LLMV2=1); returns None when the gate is closed.
    triage() itself is safe and ungated — this gate covers the step that
    would feed persisted scan output.
    """
    if not triage_gate_open():
        return None
    result = triage(findings, llm_scorer=llm_scorer)
    result["markdown"] = render_triage_summary(result)
    return result
