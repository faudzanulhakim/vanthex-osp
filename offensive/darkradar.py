"""
darkradar.py — Dark-web / exposure radar for VANTHEX.
AUTHORIZED TESTING ONLY — PASSIVE, public sources only.

This module never scrapes paste sites or breach dumps and never sends the
target domain anywhere except as a query term in investigator links it
builds for a human. Everything is either:

  * a LINK the investigator can open manually (paste-site search, GitHub
    gist/dork search) — links only, no fetching of those sites, or
  * a probe of a breach-indicator API the OPERATOR configures explicitly
    (opts {url, headers}); when unconfigured the module emits a
    manual-required finding with instructions instead of calling anything,
  * a REGEX harvest over HTML that the VANTHEX crawler already fetched
    (crawl_output) — no new network traffic.

Honesty model: passive sources can never confirm a live vulnerability, so
every finding is candidate/probable with verification "manual-required"
(or worse). CONFIRMED is impossible by construction.

Resilience: network failures degrade to warnings in the exposure map,
never exceptions. Rate limit: hard cap of 8 outbound requests per run.

Operator-gated scan check: c_dark_radar is a no-op unless PTK_DARKRADAR=1
(same discipline as zerodayheur.c_zeroday_heur / PTK_ZERODAY).
"""
import json as _json
import os as _os
import re as _re
from urllib.parse import quote as _quote

from exploitkit import _F

MAX_REQUESTS = 8          # hard cap on outbound requests per run
FETCH_TIMEOUT = 15

# ------------------------------------------------- link builders (no fetch)

PASTE_SOURCES = (
    # (name, url template with {q} for the quoted domain query)
    ("pastebin-google", "https://www.google.com/search?q=site:pastebin.com+{q}"),
    ("psbdmp-ws",      "https://psbdmp.ws/api/search/{q}"),
    ("pastebin-search","https://pastebin.com/search?q={q}"),
    ("google-gists",   "https://www.google.com/search?q=site:gist.github.com+{q}"),
)

SECRET_KEYWORDS = ("email", "api_key", "apikey", "password", "secret",
                   "token", "credentials")

GIST_DORK_TEMPLATES = (
    # GitHub search links; {d} domain, {k} keyword
    "https://github.com/search?q=%22{d}%22+%22{k}%22&type=code",
    "https://gist.github.com/search?q=%22{d}%22+%22{k}%22",
)


def build_paste_links(domain):
    """Investigator links for the domain (quoted) across public paste /
    aggregator search endpoints. Links only — nothing is fetched."""
    d = (domain or "").strip().lstrip(".").lower()
    if not d:
        return []
    q = _quote(f'"{d}"')
    return [{"source": name, "url": tpl.format(q=q)}
            for name, tpl in PASTE_SOURCES]


def build_gist_dork_links(domain, keywords=SECRET_KEYWORDS):
    """GitHub gist/code-search dork links for domain x common secret
    keywords (email, api_key, password, ...). Links only."""
    d = (domain or "").strip().lstrip(".").lower()
    if not d:
        return []
    links = []
    for k in keywords:
        for tpl in GIST_DORK_TEMPLATES:
            links.append({"source": "github-dork", "keyword": k,
                          "url": tpl.format(d=d, k=_quote(k))})
    return links


# ------------------------------------------------- email / cred harvesting

EMAIL_RE = _re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# credential-shaped pair: email:password / user:pass in plain text
CRED_PAIR_RE = _re.compile(
    r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\s*[:|;]\s*"
    r"([^\s\"'<>|;]{4,64})")


def _mask(secret):
    """Mask a secret so the raw value never lands in findings/output."""
    if not secret:
        return ""
    if len(secret) <= 2:
        return "*" * 6
    return secret[0] + "*" * (len(secret) - 1)


def harvest_emails(crawl_output):
    """Extract emails + credential-shaped pairs from crawl output (the
    list of {url, html/body, ...} dicts or (url, html) tuples the VANTHEX
    crawler already produced). No network. Credential pairs are masked."""
    emails, pairs = [], []
    for item in crawl_output or []:
        if isinstance(item, dict):
            url = item.get("url", "")
            text = item.get("html") or item.get("body") or item.get("text") or ""
        elif isinstance(item, (tuple, list)) and len(item) >= 2:
            url, text = item[0], item[1]
        else:
            continue
        if not isinstance(text, str):
            try:
                text = text.decode("utf-8", "replace")
            except Exception:
                continue
        for m in EMAIL_RE.findall(text):
            if m.lower() not in emails:
                emails.append(m.lower())
        for m in CRED_PAIR_RE.finditer(text):
            email, pwd = m.group(1).lower(), m.group(2)
            masked = f"{email}:{_mask(pwd)}"
            if all(p.split(":", 1)[0] != email for p in pairs):
                pairs.append(masked)
    return emails, pairs


# ------------------------------------------------- breach-indicator probe

def probe_breach_api(domain, opts, fetch=None, budget=None):
    """Probe the operator-configured breach-indicator JSON endpoint
    (opts = {url, headers}). Returns (result, warnings):
      result is None when unconfigured (caller emits the manual-required
      finding) or on failure (warnings explain why)."""
    fetch = fetch or (lambda *a, **k: (0, {}, None))
    if budget is None:
        budget = {"n": 0}
    warnings = []
    url = (opts or {}).get("url")
    if not url:
        return None, ["breach API not configured — no probe performed"]
    if budget["n"] >= MAX_REQUESTS:
        warnings.append(f"request budget ({MAX_REQUESTS}) exhausted — "
                        "breach probe skipped")
        return None, warnings
    budget["n"] += 1
    try:
        q = url + (("&" if "?" in url else "?")
                   + "domain=" + _quote(domain) if domain else "")
        status, _h, raw = fetch(q, timeout=FETCH_TIMEOUT,
                                headers=(opts or {}).get("headers") or {})
        if status != 200 or raw is None:
            warnings.append(f"breach API HTTP {status}")
            return None, warnings
        return _json.loads(raw.decode("utf-8", "replace")), warnings
    except Exception as exc:
        return None, [f"breach API failed: {type(exc).__name__}"]


def _breach_counts(result):
    """Pull a plausible breach count out of arbitrary JSON shapes."""
    for key in ("breaches", "count", "total", "results", "leaks"):
        v = result.get(key) if isinstance(result, dict) else None
        if isinstance(v, int):
            return v
        if isinstance(v, (list, dict)):
            return len(v)
    return 0


# ------------------------------------------------- orchestrator

def run_darkradar(target, fetcher=None, crawl_output=None, breach_opts=None,
                  log=None):
    """Passive dark-web/exposure radar for a domain.

    Returns (findings, exposure_map) where exposure_map is:
      {links, emails_found, credential_pairs_masked, sources_checked,
       warnings}
    All findings are candidate/manual-required — no CONFIRMED is possible
    from passive sources. Network failures become warnings, not errors.
    """
    def L(msg):
        if log:
            log(msg)

    domain = (target or "").strip().replace("https://", "").replace(
        "http://", "").split("/")[0].strip()
    findings = []
    budget = {"n": 0}
    warnings = []
    sources_checked = []

    # 1) paste-site investigator links (links only, zero requests)
    paste_links = build_paste_links(domain)
    sources_checked.append("paste-sites")
    if paste_links:
        shown = "; ".join(l["url"] for l in paste_links[:4])
        findings.append(_F(
            "LOW",
            "Dark-Web Radar: Paste-Site Investigator Links for Domain",
            f"Public paste/aggregator search links were generated for the "
            f"domain {domain}. VANTHEX does not scrape these sites — a "
            "human should open the links and review hits for leaked "
            "credentials or internal data referencing the target.",
            evidence=f"links: {shown}",
            cwe="CWE-359", owasp="A01:2021 Broken Access Control", cvss=2.0,
            location=domain,
            remed="Manually review the listed paste-site searches; treat "
                  "any leaked credentials as incident-response input.",
            confidence="candidate", verification="manual-required"))

    # 2) GitHub gist/dork links (links only, zero requests)
    dork_links = build_gist_dork_links(domain)
    sources_checked.append("github-dorks")
    if dork_links:
        shown = "; ".join(l["url"] for l in dork_links[:4])
        findings.append(_F(
            "LOW",
            "Dark-Web Radar: GitHub Gist/Dork Investigator Links",
            f"GitHub code/gist search links were generated for {domain} "
            "crossed with common secret keywords (email, api_key, "
            "password, ...). Developers often commit credentials that "
            "reference internal domains; review these searches manually.",
            evidence=f"{len(dork_links)} links, e.g. {shown}",
            cwe="CWE-798", owasp="A07:2021 Identification and "
                                 "Authentication Failures", cvss=2.0,
            location=domain,
            remed="Review the dork links; if secrets surface, rotate the "
                  "credentials and add secret-scanning to CI.",
            confidence="candidate", verification="manual-required"))

    # 3) email harvest from already-crawled pages (no requests)
    emails, cred_pairs = harvest_emails(crawl_output)
    sources_checked.append("crawl-email-harvest")
    if emails:
        findings.append(_F(
            "LOW",
            "Dark-Web Radar: Email Addresses Harvested from Crawled Pages",
            f"{len(emails)} email address(es) were harvested from HTML "
            f"already fetched during the crawl of {domain}. Exposed "
            "addresses feed credential-stuffing and phishing.",
            evidence="sample: " + ", ".join(emails[:5]),
            cwe="CWE-359", owasp="A01:2021 Broken Access Control", cvss=2.0,
            location=domain,
            remed="Minimize plaintext email exposure; use role aliases "
                  "and obfuscation on public pages.",
            confidence="candidate", verification="manual-required"))
    if cred_pairs:
        findings.append(_F(
            "HIGH",
            "Dark-Web Radar: Credential-Shaped Pair Exposed in Crawled "
            "HTML (passwords masked)",
            "Plain text in one or more crawled pages contains "
            "email:password-shaped pairs. Even on the target's own pages "
            "this is an exposure problem; the raw passwords are NOT "
            "reproduced in this finding (masked).",
            evidence="masked pairs: " + "; ".join(cred_pairs[:5]),
            cwe="CWE-312", owasp="A02:2021 Cryptographic Failures",
            cvss=7.5, location=domain,
            remed="Remove stored/transmitted plaintext credentials from "
                  "public pages; rotate any pair found; investigate the "
                  "source page.",
            confidence="probable", verification="manual-required",
            verification_note="Passive evidence only: the pair shape was "
                              "seen in crawled HTML; validity of the "
                              "credentials requires manual follow-up."))

    # 4) breach-indicator probe (operator-configured endpoint only)
    result, w = probe_breach_api(domain, breach_opts, fetch=fetcher,
                                 budget=budget)
    warnings.extend(w)
    if breach_opts and breach_opts.get("url"):
        sources_checked.append("breach-api")
        if result is not None:
            n = _breach_counts(result)
            findings.append(_F(
                "MEDIUM" if n else "LOW",
                "Dark-Web Radar: Breach-Indicator API Report",
                f"The operator-configured breach-indicator endpoint "
                f"reported {n} breach indicator(s) for {domain}. The "
                "scanner cannot validate the feed's contents — treat as "
                "investigative input.",
                evidence=f"endpoint: {breach_opts['url']}; indicators: {n}",
                cwe="CWE-359", owasp="A01:2021 Broken Access Control",
                cvss=5.0 if n else 2.0, location=domain,
                remed="Cross-check reported breaches against haveibeenpwned "
                      "and force resets for affected accounts.",
                confidence="candidate", verification="manual-required"))
    else:
        findings.append(_F(
            "INFO",
            "Dark-Web Radar: Breach-Indicator API Not Configured "
            "(Manual Step Required)",
            "No breach-indicator API was configured for this run, so no "
            "breach probe was performed. To enable it, pass opts "
            "{'url': '<JSON breach-API endpoint with {domain} query>', "
            "'headers': {'Authorization': 'Bearer <key>'}} to "
            "run_darkradar / the scan opts under darkradar_breach. The "
            "scanner will then query that endpoint (max 8 outbound "
            "requests/run). Manual alternative: search the domain at "
            "https://haveibeenpwned.com/ and review paste-site links in "
            "the other findings.",
            evidence="opts['url'] not set — manual-required",
            cwe="CWE-1188", owasp="A05:2021 Security Misconfiguration",
            cvss=0.0, location=domain,
            remed="Configure a breach-indicator API or perform the manual "
                  "haveibeenpwned check documented above.",
            confidence="candidate", verification="manual-required"))

    exposure_map = {
        "links": paste_links + dork_links,
        "emails_found": emails,
        "credential_pairs_masked": cred_pairs,
        "sources_checked": sources_checked,
        "requests_made": budget["n"],
        "warnings": warnings,
    }
    L(f"  [darkradar] {len(findings)} finding(s), {len(exposure_map['links'])} "
      f"links, {len(emails)} email(s), {budget['n']} outbound request(s)")
    return findings, exposure_map


# ------------------------------------------------------------ check hook

def c_dark_radar(ctx, add):
    """Operator-gated scan check (PTK_DARKRADAR=1): passive exposure radar
    over the ctx surface / crawl output. No-op without the gate. Findings
    are links-only / manual-required; network failures warn, never raise."""
    if not (_os.environ.get("PTK_DARKRADAR") == "1"
            or _os.environ.get("VANTHEX_DARKRADAR") == "1"):
        ctx.L("  [darkradar] operator gate PTK_DARKRADAR not set — skipped")
        return
    target = getattr(ctx, "target", "") or ""
    try:
        target = target.split("//")[-1].split("/")[0]
    except Exception:
        pass
    crawl_output = getattr(ctx, "crawl_output", None) or getattr(
        ctx, "crawl_pages", None)
    breach_opts = None
    try:
        breach_opts = (getattr(ctx, "opts", None) or {}).get(
            "darkradar_breach")
    except Exception:
        breach_opts = None
    try:
        findings, emap = run_darkradar(target, crawl_output=crawl_output,
                                       breach_opts=breach_opts,
                                       log=ctx.L)
    except Exception as exc:
        ctx.L(f"  [darkradar] error (degraded to warning): "
              f"{type(exc).__name__}: {exc}")
        return
    for w in emap.get("warnings", []):
        ctx.L(f"  [darkradar] warning: {w}")
    for f in findings:
        f["origin"] = "darkradar"
        add(f)
    ctx.L(f"  [darkradar] done: {len(findings)} finding(s), "
          f"{len(emap['links'])} investigator link(s), "
          f"{emap['requests_made']} outbound request(s)")


if __name__ == "__main__":
    print("darkradar: passive exposure radar, "
          f"budget {MAX_REQUESTS} requests/run")
