"""
Pentest Toolkit — Aggressive Passive Attack-Surface Recon (reconiblis.py).

Composes the passive engines into one broad, key-free attack-surface map:

  1. Certificate Transparency (crt.sh JSON)  -> subdomain harvest
  2. Wayback Machine CDX API                 -> historical URLs + params
  3. GitHub code-search dork URLs            -> investigator links (no scraping)
  4. JS secret mining                        -> secretpatterns regexes over JS
  5. Package-confusion check                 -> typosquat candidates in manifests
  6. Subdomain takeover pre-checks           -> subtakeover CNAME fingerprints

Everything is passive (public lookups + GETs of the site's own public files).
Every network step is short-timeout and degrades to a warning when the
environment is offline; findings carry verification labels via the shared
F() factory (vulnscan2, imported lazily). No auth tokens required.
"""
import json
import re
from urllib.parse import quote_plus, urlparse

import netclient
def _passive():
    """Lazily import passive (it imports vulnscan2, so a module-level
    import would be circular when vulnscan2 loads this module)."""
    import passive
    return passive
from subtakeover import fingerprint as _takeover_fingerprint, scan as _takeover_scan

# Curated allow-list of well-known public-registry package names (inline,
# deliberately small: it exists to cut obvious false positives only).
_KNOWN_PACKAGES = {
    "react", "react-dom", "vue", "angular", "express", "lodash", "axios",
    "jquery", "moment", "chalk", "debug", "commander", "requests", "flask",
    "django", "numpy", "pandas", "boto3", "urllib3", "certifi", "setuptools",
    "pip", "wheel", "gunicorn", "celery", "sqlalchemy", "rails", "rake",
    "devise", "puma", "rspec", "webpack", "typescript", "eslint", "prettier",
    "jest", "mocha", "chai", "core-js", "babel", "@babel/core",
    "typescript compiler",
}
_MANIFEST_RE = re.compile(r"(?i)(?:package\.json|requirements[\w.-]*\.txt|"
                          r"Pipfile(?:\.lock)?|Gemfile(?:\.lock)?|poetry\.lock"
                          r"|package-lock\.json|yarn\.lock)$")
_GITHUB_DORKS = [
    '"{d}" "api_key"', '"{d}" "apikey"', '"{d}" "secret"', '"{d}" "password"',
    '"{d}" "Authorization: Bearer"', '"{d}" filename:.env',
    '"{d}" filename:config.json', '"{d}" "jdbc:"',
]


def _lazy_F():
    """F() factory imported lazily so the module loads without vulnscan2."""
    from vulnscan2 import F
    return F


def _fetch_bytes(url, timeout=8, verify=False, cap=2 * 1024 * 1024):
    """Proxy-aware byte fetch, delegating to passive._fetch_bytes (the shared
    netclient pattern). Unit tests monkeypatch this module-level wrapper."""
    return _passive()._fetch_bytes(url, timeout=timeout, verify=verify,
                                 cap=cap)


def _dns_cname(sub):
    """CNAME of one name via the system resolver (or '' offline)."""
    try:
        import dns.resolver
        res = dns.resolver.Resolver()
        res.timeout, res.lifetime = 3, 5
        ans = res.resolve(sub, "CNAME")
        return str(ans[0]).rstrip(".")
    except Exception:
        return ""


def _registrable(host):
    return _passive()._registrable(host)


def _host_of(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


# ---------------------------------------------------------------- 1. CT (crt.sh)
def ct_subdomains(domain, fetch=None):
    """crt.sh JSON -> {'certificates', 'subdomains', 'issuers'} (or {})."""
    fetch = fetch or _fetch_bytes
    st, _h, raw = fetch(f"https://crt.sh/?q=%25.{domain}&output=json",
                        timeout=15, verify=True)
    if st != 200 or not raw:
        return {}
    try:
        return _passive()._parse_crtsh(json.loads(raw.decode("utf-8", "replace")))
    except Exception:
        return {}


# ------------------------------------------------- 2. Wayback CDX (per host)
def wayback_urls(domain, fetch=None, limit=100):
    """CDX API -> {'urls': [...], 'params': {name: sample}, 'warnings': []}."""
    fetch = fetch or _fetch_bytes
    out = {"urls": [], "params": {}, "warnings": []}
    st, _h, raw = fetch(
        f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json"
        f"&collapse=urlkey&limit={limit}&fl=original,statuscode",
        timeout=15)
    if st != 200 or not raw:
        out["warnings"].append(f"wayback CDX unavailable (HTTP {st})")
        return out
    try:
        rows = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        out["warnings"].append("wayback CDX response not JSON")
        return out
    for row in rows[1:] if isinstance(rows, list) and rows else []:
        if not row:
            continue
        url = str(row[0])
        out["urls"].append(url)
        for k, v in re.findall(r"[?&]([^=&]+)=([^&]*)", url):
            out["params"].setdefault(k, url)
    out["urls"] = out["urls"][:limit]
    return out


# ---------------------------------------------- 3. GitHub dork links (no fetch)
def github_dork_urls(domain):
    """Investigator links (generated, not fetched — no token, no scraping)."""
    return [f"https://github.com/search?q={quote_plus(p.format(d=domain))}"
            f"&type=code" for p in _GITHUB_DORKS]


# ------------------------------------------------------- 4. JS secret mining
def _js_links_from_html(html, base_url):
    links = []
    for m in re.finditer(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""",
                         html or "", re.I):
        src = m.group(1)
        if src and re.search(r"\.js($|\?)", src, re.I):
            from urllib.parse import urljoin
            links.append(urljoin(base_url + "/", src))
    seen, out = set(), []
    for u in links:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:25]


def mine_secrets(text, source=""):
    """Run the secretpatterns detectors over raw text -> list of hits
    {kind, severity, masked, source} (masks values; never returns raw)."""
    import secretpatterns as sp
    hits = []
    for pat in getattr(sp, "SECRET_PATTERNS", []):
        kind, rx, sev = pat[0], pat[1], pat[2]
        for m in rx.finditer(text or ""):
            hits.append({"kind": kind, "severity": sev,
                         "masked": sp._mask(m.group(0)), "source": source})
    for m in sp._GENERIC_SECRET_RE.finditer(text or ""):
        hits.append({"kind": "generic_cred", "severity": "MEDIUM",
                     "masked": sp._mask(m.group(0)), "source": source})
    return hits


def collect_js_sources(root_url, js_crawl_output=None, fetch=None):
    """-> (js_urls, html_bodies). Reuses an existing JS-crawl result when the
    caller passes one (dict with 'js_urls'/'urls'/'scripts', or a plain list);
    otherwise fetches the root page and pulls <script src> links."""
    fetch = fetch or _fetch_bytes
    urls, bodies = [], {}
    if js_crawl_output:
        if isinstance(js_crawl_output, dict):
            for key in ("js_urls", "scripts", "urls"):
                v = js_crawl_output.get(key)
                if isinstance(v, (list, tuple)):
                    urls.extend(str(x) for x in v)
        elif isinstance(js_crawl_output, (list, tuple)):
            urls.extend(str(x) for x in js_crawl_output)
        return urls[:40], bodies
    st, _h, raw = fetch(root_url, timeout=8)
    html = raw.decode("utf-8", "replace") if st == 200 and raw else ""
    return _js_links_from_html(html, root_url), {"root": html}


def js_secret_findings(root_url, js_crawl_output=None, fetch=None):
    """-> (findings_meta_list, secrets_map). Never live-verifies secrets."""
    fetch = fetch or _fetch_bytes
    js_urls, bodies = collect_js_sources(root_url, js_crawl_output, fetch)
    secrets = []
    seen = set()
    for url in js_urls[:20]:
        if url in seen:
            continue
        seen.add(url)
        st, _h, raw = fetch(url, timeout=8)
        if st == 200 and raw:
            for hit in mine_secrets(raw.decode("utf-8", "replace"), url):
                key = (hit["kind"], hit["masked"])
                if key not in { (h["kind"], h["masked"]) for h in secrets }:
                    secrets.append(hit)
    for src, body in bodies.items():
        for hit in mine_secrets(body, src):
            if (hit["kind"], hit["masked"]) not in \
                    {(h["kind"], h["masked"]) for h in secrets}:
                secrets.append(hit)
    return secrets


# ------------------------------------------------- 5. package-confusion check
def extract_packages(text, source=""):
    """Pull dependency names out of manifest-style content (JSON deps,
    requirements lines, Gemfile lines) -> [{name, ecosystem, source}]."""
    out, seen = [], set()

    def add(name, eco):
        name = (name or "").strip()
        if not name or name.startswith("#") or name in seen:
            return
        seen.add(name)
        out.append({"name": name, "ecosystem": eco, "source": source})

    # JSON manifests (package.json / package-lock)
    if (text or "").lstrip().startswith("{"):
        try:
            data = json.loads(text)
            for key, eco in (("dependencies", "npm"), ("devDependencies", "npm"),
                             ("peerDependencies", "npm")):
                for name in (data.get(key) or {}):
                    add(name, eco)
        except Exception:
            pass
    # requirements.txt / Pipfile-style lines
    for m in re.finditer(r"(?m)^\s*([A-Za-z0-9._-]+)\s*(?:[=<>!~]==?|==)"
                         r"\s*[\w.]+", text or ""):
        add(m.group(1), "pypi")
    # Gemfile lines
    for m in re.finditer(r"(?m)^\s*gem\s+['\"]([\w.-]+)['\"]", text or ""):
        add(m.group(1), "gem")
    return out


def typosquat_candidates(packages):
    """Heuristic: a dependency name absent from the curated known-list is
    flagged as a public-registry confusion candidate (low confidence by
    design — an allow-list can never prove a name is legitimate)."""
    return [p for p in packages
            if p["name"].lower() not in _KNOWN_PACKAGES]


def package_findings_from_urls(urls, fetch=None, budget=3):
    """Fetch manifest-looking URLs from the historical URL set and analyse."""
    fetch = fetch or _fetch_bytes
    packages, warnings = [], []
    fetched = 0
    for url in urls:
        if len(packages) and fetched >= budget:
            break
        path = urlparse(url).path
        if not _MANIFEST_RE.search(path):
            continue
        st, _h, raw = fetch(url, timeout=8)
        fetched += 1
        if st != 200 or not raw:
            warnings.append(f"manifest not retrievable: {url[:120]}")
            continue
        packages += extract_packages(raw.decode("utf-8", "replace"), url)
    return packages, warnings


# --------------------------------------------- 6. subdomain takeover pre-checks
def takeover_precheck(subdomains, fetch=None, dns_lookup=None, bound=20):
    """Run subtakeover.scan over (subdomain, cname) pairs, bounded."""
    fetch = fetch or _fetch_bytes
    dns_lookup = dns_lookup or _dns_cname

    def _fetcher(sub):
        st, _h, raw = fetch(f"https://{sub}/", timeout=6)
        body = raw.decode("utf-8", "replace") if st and raw else ""
        return st, body

    try:
        results = _takeover_scan(
            [(s, "") for s in list(subdomains)[:bound]],
            _fetcher, dns_lookup)
    except Exception as e:
        return [], [f"takeover pre-check failed: {type(e).__name__}"]
    return results, []


# ------------------------------------------------------------------- orchestrator
def run_reconiblis(target, js_crawl_output=None, log=None):
    """Full aggressive-passive sweep -> engine dict in the passive.py shape,
    plus meta['attack_surface_map'] = {hosts, urls, params, secrets, packages,
    github_dorks, takeover_candidates, warnings}."""
    def L(msg):
        if log is None:
            return
        if callable(log):
            log(msg)
        else:
            log.append(msg)

    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("target has no hostname")
    domain = _registrable(host)
    root_url = f"{parsed.scheme}://{parsed.netloc}"
    F = _lazy_F()
    findings, warnings = [], []

    def add(f):
        key = (f["title"], f.get("location", ""), f.get("param", ""))
        if not any((x["title"], x.get("location", ""), x.get("param", "")) == key
                   for x in findings):
            findings.append(f)

    L(f"[reconiblis] aggressive-passive sweep of {host} (domain {domain})")

    # (1) certificate transparency
    ct = ct_subdomains(domain)
    subs = ct.get("subdomains", [])
    if not ct:
        warnings.append(f"crt.sh unavailable in this environment — CT "
                        f"subdomains not harvested (offline-safe skip)")
    else:
        add(F("INFO", f"CT harvest: {ct['certificates']} certificates, "
                      f"{len(subs)} subdomains for {domain}",
              "Certificate Transparency logs expose every hostname ever issued a cert for this domain — a free map of forgotten test/staging systems.",
              evidence=", ".join(subs[:10])[:300], cwe="CWE-200",
              owasp="ASVS V14", cvss=0.0,
              remed="Review listed hostnames; decommission or protect forgotten subdomains.",
              confidence="confirmed", location=domain, origin="passive",
              verification="verified",
              verification_note="Verified against the public crt.sh CT log index."))

    # (2) wayback CDX
    wb = wayback_urls(domain)
    warnings += wb["warnings"]
    if wb["urls"]:
        add(F("INFO", f"Wayback history: {len(wb['urls'])} archived URLs, "
                      f"{len(wb['params'])} parameter names for {domain}",
              "Archived URLs reveal endpoint structure and parameter names that are still likely valid attack surface.",
              evidence="; ".join(wb["urls"][:5])[:300], cwe="CWE-200",
              owasp="ASVS V14", cvss=0.0,
              remed="Inventory archived endpoints and confirm each is still intended and protected.",
              confidence="probable", location=domain, origin="passive",
              verification="verified",
              verification_note="Verified against the public Wayback CDX index."))

    # (3) GitHub dork links (investigator output — nothing fetched)
    dorks = github_dork_urls(domain)
    add(F("INFO", f"GitHub code-search dork links generated for {domain} ({len(dorks)})",
          "Ready-to-open code-search queries hunting leaked credentials/config referencing this domain. Links are provided for the investigator — no scraping, no token.",
          evidence=dorks[0], cwe="CWE-200", owasp="ASVS V14", cvss=0.0,
          remed="Open each link and triage any commits that reference real secrets or internal hosts.",
          confidence="candidate", location=domain, origin="passive",
          verification="manual_only",
          verification_note="Generated query URLs; results depend on GitHub at view time."))

    # (4) JS secret mining
    secrets = js_secret_findings(root_url, js_crawl_output)
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    if secrets:
        worst = min(secrets, key=lambda s: sev_rank.get(s["severity"], 4))
        add(F(worst["severity"], f"Secret-like material in served JavaScript "
                                 f"({len(secrets)} hit(s))",
              "Client-served JS contains credential-shaped strings. Values are masked here; treat every hit as leaked until proven otherwise.",
              evidence=json.dumps(secrets[:10])[:400], cwe="CWE-798",
              owasp="ASVS V14", cvss=7.4,
              remed="Revoke/rotate every real credential found; move secrets to a backend or secrets manager.",
              confidence="probable", location=worst.get("source", root_url),
              origin="passive", verification="pattern_match",
              verification_note="Regex match from the secretpatterns engine; validity requires manual confirmation."))

    # (5) package confusion
    pkgs, pkg_warn = package_findings_from_urls(wb["urls"])
    warnings += pkg_warn
    js_manifests = [u for u in (js_crawl_output or {}) .get("manifests", [])] \
        if isinstance(js_crawl_output, dict) else []
    for u in js_manifests[:3]:
        st, _h, raw = _fetch_bytes(u, timeout=8)
        if st == 200 and raw:
            pkgs += extract_packages(raw.decode("utf-8", "replace"), u)
    squat = typosquat_candidates(pkgs)
    if pkgs:
        add(F("LOW", f"Dependency manifest harvested: {len(pkgs)} package(s), "
                     f"{len(squat)} public-registry confusion candidate(s)",
              "Names not in the curated known-list are typosquat candidates: an attacker can register a look-alike package in the public registry and have builds pull attacker code.",
              evidence=json.dumps([p["name"] for p in squat[:15]] or
                                  [p["name"] for p in pkgs[:15]])[:300],
              cwe="CWE-1357", owasp="ASVS V14", cvss=3.1,
              remed="Pin exact versions, use a private registry/proxy, and verify unfamiliar package names before trusting them.",
              confidence="candidate", location=domain, origin="passive",
              verification="heuristic",
              verification_note="Allow-list heuristic — an allow-list cannot prove a name is legitimate."))

    # (6) subdomain takeover pre-checks (bounded 20)
    takeover, tk_warn = takeover_precheck(subs)
    warnings += tk_warn
    for r in takeover:
        sev = "HIGH" if r.get("confidence") == "confirmed" else "LOW"
        add(F(sev, f"Subdomain takeover pre-check: {r['subdomain']} "
                   f"points at unclaimed {r['service']}",
              "A subdomain's CNAME targets a third-party service that no longer holds the resource — whoever registers it can serve content on your hostname.",
              evidence=r.get("evidence", "")[:300], cwe="CWE-350",
              owasp="ASVS V14", cvss=7.4 if sev == "HIGH" else 3.7,
              remed="Remove the dangling DNS record or re-claim the resource at the provider.",
              confidence=r.get("confidence", "probable"),
              location=r["subdomain"], origin="passive",
              verification="fingerprint_match",
              verification_note="CNAME + response-body signature from subtakeover; confirm by claiming before full exploit."))

    # structured attack surface map (stored as finding evidence JSON)
    surface = {
        "domain": domain, "host": host,
        "hosts": sorted({h for h in subs} | {host}),
        "urls": wb["urls"], "params": sorted(wb["params"]),
        "secrets": secrets, "packages": pkgs,
        "typo_candidates": [p["name"] for p in squat],
        "github_dorks": dorks,
        "takeover_candidates": takeover,
        "warnings": warnings,
    }
    add(F("INFO", f"Attack surface map for {domain}",
          "Structured passive attack-surface inventory (hosts, archived URLs, parameters, secret hits, package manifests, dork links, takeover pre-checks) stored as JSON evidence.",
          evidence=json.dumps(surface)[:400], cwe="CWE-200",
          owasp="ASVS V14", cvss=0.0,
          remed="Use this inventory to prioritise active testing and clean up stale surface.",
          confidence="confirmed", location=domain, origin="passive",
          verification="verified",
          verification_note="Assembled from verified public sources and module checks."))

    summary = {}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    from vulnscan2 import risk_score
    score = risk_score(findings)
    risk = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                 if summary.get(s)), "CLEAN")
    L(f"[reconiblis] done: {len(findings)} findings | risk {risk} | "
      f"score {score}/100")
    return {"type": "reconiblis", "target": target,
            "profile": "aggressive-passive-recon", "method": "passive",
            "findings": findings, "summary": summary,
            "overall_risk": risk, "risk_score": score,
            "meta": {"attack_surface_map": surface},
            "endpoints": [], "warnings": warnings, "errors": []}
