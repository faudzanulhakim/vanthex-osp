"""Per-finding manual validation commands (v1.2.2 appendix).

For each finding, build_manual_check() produces ready-to-run shell
commands (curl/dig, copy-paste safe: payloads percent-encoded, quoted)
plus the expected outcome for both the vulnerable and the not-vulnerable
case, so an operator can prove or disprove the finding by hand.

The class is detected from the finding's cwe / owasp / title keywords.
Any failure is contained: build_manual_check never raises.
"""
from urllib.parse import quote


def _q(url):
    """Split off the query string and percent-encode the values so the
    command is copy-paste safe in a shell."""
    if "?" not in (url or ""):
        return quote(url or "", safe="/:?&=%")
    base, _, qs = url.partition("?")
    pairs = []
    for pair in qs.split("&"):
        k, _, v = pair.partition("=")
        pairs.append(quote(k, safe="") + "=" + quote(v, safe=""))
    return base + "?" + "&".join(pairs)


def _url(finding):
    loc = str(finding.get("location") or "")
    # location may be a full URL or a path; return as-is (encoded later)
    return loc


def _with_param(url, param, value):
    """Append param=value to a URL (or replace existing value)."""
    enc = _q(url)
    if param and "=" + quote(str(param), safe="") + "=" not in enc and param:
        sep = "&" if "?" in enc else "?"
        enc = enc + sep + quote(str(param), safe="") + "=" + \
            quote(str(value), safe="%")
    return enc


def _match(finding, *words):
    hay = " ".join(str(finding.get(k) or "") for k in
                   ("cwe", "owasp", "title")).lower()
    return any(w in hay for w in words)


def build_manual_check(finding, target=None):
    """Return {"title", "commands", "vulnerable_if", "safe_if"} for the
    finding, tailored by class. Never raises; returns {} on unusable input."""
    try:
        if not isinstance(finding, dict):
            return {}
        loc = _url(finding)
        if not loc and target:
            loc = str(target)
        param = str(finding.get("param") or "")
        cmds = []
        title, vuln, safe = "", "", ""
        cls = _classify(finding)
        builder = _BUILDERS.get(cls, _generic)
        title, cmds, vuln, safe = builder(loc, param, finding)
        cmds = [c for c in cmds if c and not c.startswith("#")][:4]
        return {"title": title,
                "commands": cmds,
                "vulnerable_if": vuln,
                "safe_if": safe}
    except Exception:
        return {}


def _classify(finding):
    if _match(finding, "command injection", "cwe-78", "os command"):
        return "cmdi"
    if _match(finding, "sql injection", "cwe-89"):
        return "sqli"
    if _match(finding, "nosql injection", "cwe-943"):
        return "nosql"
    if _match(finding, "ldap injection", "cwe-90"):
        return "ldap"
    if _match(finding, "cross-site scripting", "xss", "cwe-79"):
        return "xss_dom" if _match(finding, "dom") else "xss"
    if _match(finding, "server-side request forgery", "ssrf", "cwe-918"):
        return "ssrf"
    if _match(finding, "path traversal", "directory traversal",
              "cwe-22", "cwe-23"):
        return "traversal"
    if _match(finding, "open redirect", "cwe-601"):
        return "redirect"
    if _match(finding, "subdomain takeover", "takeover", "cwe-350"):
        return "takeover"
    if _match(finding, "security header", "missing header", "header",
              "csp", "cwe-693", "cwe-1021"):
        return "header"
    if _match(finding, "version disclosure", "fingerprint", "server banner",
              "technology disclosure", "cwe-200"):
        return "version"
    return "generic"


# ---- per-class builders ------------------------------------------------

def _cmdi(loc, param, f):
    base = _with_param(loc, param, "1")
    canary = _with_param(loc, param, "%24%28id%29")  # $(id)
    sleep = _with_param(loc, param, "%7C%20sleep%205")  # | sleep 5
    return ("Manual command-injection check (" + (param or "parameter") + ")",
            ["# Baseline (normal value) — note the response time:",
             "curl -s -o /dev/null -w '%{http_code} %{time_total}s\\n' '" + base + "'",
             "# Canary: substitute $(id) (percent-encoded) and look for a uid:",
             "curl -s '" + canary + "' | grep -E 'uid=[0-9]+\\('",
             "# Timing: value '| sleep 5' (percent-encoded) should take ~5s:",
             "curl -s -o /dev/null -w 'time_total=%{time_total}s\\n' '" + sleep + "'"],
            "The canary request returns output like 'uid=0(root)' or the "
            "sleep request takes ~5 seconds longer than the baseline — "
            "command execution confirmed.",
            "No uid output and the sleep variant returns in roughly the "
            "same time as the baseline (within ~1s) — the injection is "
            "not executable; the finding is a false positive.")


def _sqli(loc, param, f):
    base = _with_param(loc, param, "1")
    err = _with_param(loc, param, "1%27")  # 1'
    true = _with_param(loc, param, "1%27%20OR%20%271%27%3D%271")  # ' OR '1'='1
    false = _with_param(loc, param, "1%27%20AND%20%271%27%3D%272")  # AND '1'='2
    return ("Manual SQL-injection check (" + (param or "parameter") + ")",
            ["# Baseline:",
             "curl -s -o baseline.html -w '%{http_code} %{size_download}\\n' '" + base + "'",
             "# Quote error probe (apostrophe, percent-encoded):",
             "curl -s '" + err + "' | grep -iE 'sql|syntax|oracle|mysql|postgresql|sqlite|unterminated'",
             "# Boolean pair — compare sizes of the TRUE vs FALSE responses:",
             "curl -s -o true.html -w 'true:  %{size_download}\\n' '" + true + "'",
             "curl -s -o false.html -w 'false: %{size_download}\\n' '" + false + "'"],
            "The quote probe returns a database error, or the TRUE variant "
            "returns different content (e.g. larger page / extra rows) "
            "than the FALSE variant — injectable SQL confirmed.",
            "No database error on the quote probe and the TRUE and FALSE "
            "responses are identical in size and content — not injectable; "
            "false positive.")


def _nosql(loc, param, f):
    taut = _with_param(loc, param, "%27%7C%7C%271%27%3D%3D%271")  # '||'1'=='1
    true = _with_param(loc, param, "%27%20%7C%7C%20%271%27%3D%3D%271%27")
    false = _with_param(loc, param, "%27%20%26%26%20%271%27%3D%3D%272%27")
    return ("Manual NoSQL-injection check (" + (param or "parameter") + ")",
            ["# Baseline:",
             "curl -s -o baseline.html -w '%{http_code} %{size_download}\\n' '" + _with_param(loc, param, "test") + "'",
             "# Tautology probe ($ne / || '1'=='1' style), percent-encoded:",
             "curl -s '" + taut + "'",
             "# Boolean pair — compare TRUE vs FALSE responses:",
             "curl -s -o true.html -w 'true:  %{size_download}\\n' '" + true + "'",
             "curl -s -o false.html -w 'false: %{size_download}\\n' '" + false + "'"],
            "The tautology probe returns authenticated/valid content or "
            "the TRUE and FALSE responses differ (different size or "
            "content) — NoSQL operator injection confirmed.",
            "The tautology probe is rejected (400/error) and the TRUE and "
            "FALSE responses are identical — not injectable; false "
            "positive.")


def _ldap(loc, param, f):
    base = _with_param(loc, param, "test")
    true = _with_param(loc, param, "test%29%28%7C%28uid%3D%2A%29%29")  # test)(|(uid=*))
    false = _with_param(loc, param, "test%29%28%26%28uid%3Dzzzzzz%29%29")  # & (uid=zzzzzz)
    return ("Manual LDAP-injection check (" + (param or "parameter") + ")",
            ["# Baseline:",
             "curl -s -o baseline.html -w '%{http_code} %{size_download}\\n' '" + base + "'",
             "# Tautology probe ')(|(uid=*))' vs unsatisfiable ')(&(uid=zzzzzz))':",
             "curl -s -o true.html -w 'true:  %{size_download}\\n' '" + true + "'",
             "curl -s -o false.html -w 'false: %{size_download}\\n' '" + false + "'"],
            "The tautology probe returns entries the baseline does not "
            "(or differs from the unsatisfiable probe) — LDAP filter "
            "injection confirmed.",
            "Both probes behave identically to the baseline (same size/"
            "content, no extra entries) — filter is escaped; false "
            "positive.")


def _xss(loc, param, f):
    canary = _with_param(loc, param, "%3Csvg%2Fonload%3Dalert%281%29%3E")  # <svg/onload=alert(1)>
    plain = _with_param(loc, param, "vthx123canary")
    return ("Manual reflected-XSS check (" + (param or "parameter") + ")",
            ["# Send a harmless marker and confirm the raw reflection point:",
             "curl -s '" + plain + "' | grep -F 'vthx123canary'",
             "# Send the percent-encoded canary payload <svg/onload=alert(1)>:",
             "curl -s '" + canary + "' | grep -Fi '<svg/onload=alert(1)>'"],
            "The payload appears in the response body DECODED and outside "
            "an attribute/context that would neutralize it (i.e. the "
            "browser would execute <svg/onload=alert(1)>) — reflected "
            "XSS confirmed. Open the URL in a browser to see alert(1).",
            "The payload is HTML-entity encoded (&lt;svg...), stripped, "
            "or only reflected inside a quoted attribute / script source "
            "it cannot escape — not exploitable; false positive.")


def _xss_dom(loc, param, f):
    return ("Manual DOM-based-XSS check (source-to-sink, browser "
            "devtools)",
            ["# 1. In the page JavaScript, find the source reading the "
             "parameter (DevTools > Search): location.hash, location.search, "
             "URLSearchParams — then trace it to a sink:",
             "grep -nE 'location\\.(search|hash)|URLSearchParams|innerHTML|document\\.write|eval' $(echo <js files from the page>)",
             "# 2. Open the URL with the payload in the fragment/search:",
             "curl -s '" + (_with_param(loc, param, "%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E") if loc else "<url>?<param>=<payload>") + "' | head -40"],
            "The sink (innerHTML/document.write/eval) receives the raw "
            "parameter value: in DevTools set a breakpoint on the sink, "
            "load the URL with <img src=x onerror=alert(1)>, and alert(1) "
            "fires — DOM XSS confirmed.",
            "The parameter is encoded/validated before reaching the sink, "
            "or the sink uses textContent / safe APIs — not exploitable; "
            "false positive.")


def _ssrf(loc, param, f):
    internal = _with_param(loc, param, "http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F")
    localhost = _with_param(loc, param, "http%3A%2F%2F127.0.0.1%3A80%2F")
    return ("Manual SSRF check (" + (param or "parameter") + ")",
            ["# Point the parameter at the cloud metadata endpoint (percent-encoded):",
             "curl -s '" + internal + "'",
             "# Point it at the host's own loopback web service:",
             "curl -s '" + localhost + "'"],
            "The response contains metadata service output (e.g. 'ami-id', "
            "'instance-id') or a page served from the target's own "
            "loopback — the server fetches attacker-controlled URLs; "
            "SSRF confirmed.",
            "The request is blocked, times out, or returns an error "
            "regardless of the URL scheme/host — URL validation is in "
            "place; false positive. For confirmation of an external "
            "callback, use a DNS/HTTP canary (e.g. a unique subdomain on "
            "an out-of-band interaction service) and check for a hit.")


def _traversal(loc, param, f):
    enc = _with_param(loc, param, "..%2F..%2F..%2F..%2Fetc%2Fpasswd")  # ../../../../etc/passwd
    return ("Manual path-traversal check (" + (param or "parameter") + ")",
            ["# Request the parameter with an encoded traversal to /etc/passwd:",
             "curl -s '" + enc + "' | grep -E 'root:[x*]:0:0:'"],
            "The response contains /etc/passwd content (a 'root:x:0:0:...' "
            "line) — file read outside the web root confirmed.",
            "The server returns 403/400/404 or the parameter value is "
            "normalized/rejected — no traversal; false positive. Note: "
            "an identical echo of the requested path in the body is a "
            "reflection, not proof.")


def _redirect(loc, param, f):
    canary = "vthx-open-redirect-canary.example.net"
    target = _with_param(loc, param, "https%3A%2F%2F" + canary)
    return ("Manual open-redirect check (" + (param or "parameter") + ")",
            ["# Do NOT follow automatically; inspect the redirect first:",
             "curl -sI '" + target + "' | grep -iE '^(HTTP|location)'",
             "# Then confirm the full redirect chain resolves to the canary host:",
             "curl -s -o /dev/null -w '%{url_effective}\\n' -L '" + target + "'"],
            "The Location header or the effective URL ends at "
            "'" + canary + "' — the application redirects to an "
            "attacker-controlled host; open redirect confirmed.",
            "The redirect is rejected, stripped, or limited to a whitelist "
            "of trusted hosts (Location unchanged / 400) — not "
            "exploitable; false positive.")


def _takeover(loc, param, f):
    host = str(f.get("evidence") or "").strip() or (loc or "<hostname>")
    # extract a bare hostname from the evidence/location if possible
    for token in host.replace('"', " ").split():
        if "." in token and "/" not in token:
            host = token
            break
    return ("Manual subdomain-takeover check (" + host + ")",
            ["# Resolve the CNAME chain for the dangling host:",
             "dig +short CNAME " + host,
             "dig +short " + host,
             "# Fetch the CNAME target to identify the provider fingerprint:",
             "curl -sI 'http://" + host + "'"],
            "The host has a CNAME to a cloud service whose canonical name "
            "no longer exists (NXDOMAIN on the target) and the HTTP "
            "response shows the provider's 'no such app / bucket not "
            "found' fingerprint — the subdomain can be claimed; takeover "
            "confirmed.",
            "The CNAME target resolves normally (or there is no CNAME) "
            "and the service responds normally — no dangling "
            "assignment; false positive.")


def _header(loc, param, f):
    rec = str(f.get("remediation") or "")
    import re as _re
    m = _re.search(r"([A-Za-z0-9-]+)\s*:", rec)
    hdr = m.group(1) if m else "X-Example-Header"
    return ("Manual missing-header check (" + hdr + ")",
            ["# Inspect response headers:",
             "curl -sI '" + (loc or "<url>") + "'",
             "# Grep specifically for the header:",
             "curl -sI '" + (loc or "<url>") + "' | grep -i '^" + hdr + ":'"],
            "The header is absent from the response (grep returns "
            "nothing) — the finding is confirmed; add the recommended "
            "value (see remediation).",
            "The header is present with an adequate value — already "
            "mitigated; false positive. Note: the check above also "
            "distinguishes 'present but weak value' cases.")


def _version(loc, param, f):
    return ("Manual version-disclosure check",
            ["# Inspect the Server / X-Powered-By banners:",
             "curl -sI '" + (loc or "<url>") + "' | grep -iE '^(server|x-powered-by|x-aspnet|x-generator):'"],
            "The banner discloses a concrete product and version (e.g. "
            "'Server: nginx/1.18.0') — version disclosure confirmed.",
            "No banner, a generic banner ('Server: cloudflare'), or one "
            "without a version number — not disclosed; false positive.")


def _generic(loc, param, f):
    base = _with_param(loc, param, "1") if param else (loc or "<url>")
    payload = _with_param(loc, param,
                          "%3Csvg%2Fonload%3Dalert%281%29%3E") if param else \
        (loc or "<url-with-payload>")
    ev = str(f.get("evidence") or "")[:120]
    return ("Manual verification (" +
            (param and ("parameter " + param) or "request") + ")",
            ["# 1. Baseline request (normal value):",
             "curl -s -o baseline.html -w '%{http_code} %{size_download}\\n' '" + base + "'",
             "# 2. Payload request (percent-encoded canary):",
             "curl -s -o payload.html -w '%{http_code} %{size_download}\\n' '" + payload + "'",
             "# 3. Compare the two responses:",
             "diff baseline.html payload.html | head -40"],
            "The payload request produces behavior consistent with the "
            "reported weakness (see finding evidence" +
            (": " + ev if ev else "") + ") and differs from the baseline "
            "in the way the finding describes — confirmed by hand.",
            "The payload request behaves identically to the baseline "
            "(same status, size and content) and shows none of the "
            "reported evidence — false positive; re-test with the "
            "payload variants listed in remediation.")


_BUILDERS = {
    "cmdi": _cmdi, "sqli": _sqli, "nosql": _nosql, "ldap": _ldap,
    "xss": _xss, "xss_dom": _xss_dom, "ssrf": _ssrf,
    "traversal": _traversal, "redirect": _redirect, "takeover": _takeover,
    "header": _header, "version": _version, "generic": _generic,
}
