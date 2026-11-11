"""VANTHEX — second-order injection detector (v1.2.3).

AUTHORIZED TESTING ONLY. The probe plants a MARKER-ONLY value (no script,
no SQL, no template syntax — a benign random token and a benign
quote-variant token) through a form parameter, then re-reads OTHER pages
and compares their bodies for the token. The second-order signal is the
quote-variant appearing UNESCAPED on a later page: the application stored
raw user input at the injection point and renders it unencoded at a
different sink. A marker that comes back stored-but-escaped is logged,
never reported.

API: second_order_probe(ctx, inject_url, inject_param, echo_urls) ->
list of finding dicts (same shape as vulnscan2.F()). Callers (the
vulnscan2 c_second_order check) own the bounds: max 3 inject URLs x
5 echo URLs per scan, cancelled-aware.
"""

from urllib.parse import quote
import secrets

AUTHORIZED_HEADER = "AUTHORIZED TESTING ONLY"


def _F(sev, title, desc, evidence="", cwe="", owasp="", cvss=0.0, remed="",
       confidence="probable", location="", param="", origin="active"):
    return {"severity": sev, "title": title, "description": desc,
            "evidence": evidence, "cwe": cwe, "owasp": owasp,
            "cvss": cvss, "remediation": remed, "confidence": confidence,
            "location": location, "param": param, "origin": origin}


def _make_marker():
    # unique random per probe: collision-proof against pre-existing content
    return f"so2{secrets.token_hex(8)}"


def second_order_probe(ctx, inject_url, inject_param, echo_urls, log=None):
    """Plant marker-only values via POST, then hunt them on echo pages.

    Returns a list of finding dicts; empty when nothing stored-and-
    unescaped is found. Only the UNESCAPED quote variant is a finding —
    a plain stored marker (escaped on output) is not.
    """
    if not inject_url or not inject_param or not echo_urls:
        return []
    if hasattr(ctx, "cancelled") and ctx.cancelled():
        return []
    marker = _make_marker()
    variant = marker + "'"
    planted = 0
    for value in (marker, variant):
        try:
            resp = ctx.client.post(inject_url,
                                   data=f"{inject_param}={quote(value, safe='')}")
        except Exception:
            continue
        if getattr(resp, "status", 0) == 0:
            continue
        planted += 1
    if planted == 0 or (hasattr(ctx, "cancelled") and ctx.cancelled()):
        return []
    findings = []
    for url in list(echo_urls)[:5]:
        if hasattr(ctx, "cancelled") and ctx.cancelled():
            break
        if not url or url == inject_url:
            continue  # the POST's own response is reflection, not storage
        try:
            r = ctx.client.get(url)
        except Exception:
            continue
        if getattr(r, "status", 0) != 200:
            continue
        body = r.body or ""
        if variant in body:
            findings.append(_F(
                "HIGH", "Second-Order Injection Sink",
                "A marker-only value planted through the form parameter is "
                "stored by the application and rendered UNESCAPED on a "
                "different page: the quote character survives storage and "
                "output encoding end to end, so attacker-controlled input "
                "written at the injection point executes at this sink "
                "(second-order injection). The probe itself carried no "
                "executable payload — only a random token and a quote.",
                evidence=(f"stored via POST {inject_url} param '{inject_param}' "
                          f"(marker {marker}); quote variant rendered "
                          f"UNESCAPED on GET {url}"),
                cwe="CWE-79", owasp="A03:2021 Injection", cvss=7.1,
                remed=("Encode all user-supplied content on output at every "
                       "rendering sink (context-aware), not just on the page "
                       "that accepted the input; validate on storage too."),
                confidence="confirmed", location=url, param=inject_param))
        elif marker in body:
            if log is not None:
                try:
                    log(f"  [second-order] marker stored via {inject_url} "
                        f"but escaped on output at {url} — not a finding")
                except Exception:
                    pass
    return findings
