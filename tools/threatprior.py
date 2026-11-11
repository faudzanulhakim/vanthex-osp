"""
Threat prioritization (v1.3) — EPSS + CISA KEV enrichment.
AUTHORIZED TESTING ONLY — priority validation, never touches the target.

Enriches CVE-bearing findings with real-world data:
- EPSS  (api.first.org, free, no API key): probability of exploitation
  within 30 days + percentile, batched up to 100 CVEs per request.
- KEV   (CISA Known Exploited Vulnerabilities feed, local cache with a 24h TTL):
  CVEs CONFIRMED exploited in the wild + a ransomware flag.

Result: extra keys per finding (epss, epss_percentile, kev, kev_date,
kev_ransomware) + 'priority' (P1..P3) on ALL findings, plus a sort key helper.
All network calls are wrapped in try/except — offline/blocked never raises and
never breaks a scan.
"""
import json
import os
import re
import time
import urllib.request
import urllib.parse
import urllib.error

__all__ = ["enrich", "fetch_epss", "load_kev", "cves_of", "priority_for",
           "sort_key", "priority_line"]

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")
_KEV_BASE = os.path.dirname(os.path.abspath(__file__))
if not os.path.exists(os.path.join(_KEV_BASE, "requirements.txt")):
    _KEV_BASE = os.path.dirname(_KEV_BASE)  # project root when module lives in tools/
KEV_DEFAULT_PATH = os.path.join(_KEV_BASE, "kev_cache.json")
KEV_TTL_S = 24 * 3600
EPSS_CHUNK = 100
EPSS_TIMEOUT_S = 10.0
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
SEV_PRIORITY = {"CRITICAL": "P2"}


def cves_of(finding):
    """Collect unique CVEs from the explicit 'cves' key or from
    title/description/evidence text (preserving order of appearance)."""
    out = []
    seen = set()
    for c in (finding.get("cves") or []):
        c = str(c).upper().strip()
        if CVE_RE.match(c) and c not in seen:
            seen.add(c)
            out.append(c)
    for field in ("title", "description", "evidence"):
        for m in CVE_RE.findall(str(finding.get(field) or "")):
            c = m.upper()
            if c not in seen:
                seen.add(c)
                out.append(c)
    return out


def _http_json(url, timeout_s):
    req = urllib.request.Request(
        url, headers={"User-Agent": "VANTHEX-threatprior/1.3",
                      "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def fetch_epss(cves, timeout_s=EPSS_TIMEOUT_S, fetcher=None):
    """Query EPSS in batches of <= 100 CVEs. Returns {CVE: {"epss": float,
    "percentile": float}}. Offline/blocked/error -> {} (never raises).
    'fetcher' is for test injection (fetcher(url) -> dict)."""
    out = {}
    cves = [c for c in dict.fromkeys(str(c).upper() for c in cves)
            if CVE_RE.match(c)]
    for i in range(0, len(cves), EPSS_CHUNK):
        chunk = cves[i:i + EPSS_CHUNK]
        url = EPSS_API + "?" + urllib.parse.urlencode(
            {"cve": ",".join(chunk)})
        data = None
        for attempt in (1, 2):  # one retry
            try:
                if fetcher is not None:
                    data = fetcher(url)
                else:
                    data = _http_json(url, timeout_s)
                break
            except Exception:
                data = None
                time.sleep(0.2 if attempt == 1 else 0)
        if not data:
            continue
        try:
            for row in (data.get("data") or []):
                cve = str(row.get("cve", "")).upper()
                if not CVE_RE.match(cve):
                    continue
                try:
                    out[cve] = {"epss": float(row.get("epss") or 0.0),
                                "percentile": float(row.get("percentile") or 0.0)}
                except (TypeError, ValueError):
                    continue
        except Exception:
            continue
    return out


def _kev_path():
    return os.environ.get("PTK_KEV_PATH") or KEV_DEFAULT_PATH


def load_kev(now=None, fetcher=None, path=None):
    """Load the KEV feed (local cache, 24h TTL). Returns {CVE: {date, ransomware,
    notes}}. Offline -> serve the stale cache; no cache -> {} (never raises)."""
    path = path or _kev_path()
    now = time.time() if now is None else now
    fresh = False
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                cache = json.load(fh)
            fresh = (now - float(cache.get("fetched_at", 0))) < KEV_TTL_S
            if fresh:
                return cache.get("entries", {})
        except Exception:
            cache = None
    else:
        cache = None
    try:
        if fetcher is not None:
            data = fetcher(KEV_FEED)
        else:
            data = _http_json(KEV_FEED, EPSS_TIMEOUT_S)
        entries = {}
        for item in (data or {}).get("vulnerabilities") or []:
            cve = str(item.get("cveID", "")).upper().strip()
            if not cve:
                continue
            rw = item.get("knownRansomwareCampaignUse",
                          item.get("ransomwareUse", "")) or ""
            entries[cve] = {
                "date": item.get("dateAdded") or "",
                "ransomware": str(rw).strip().lower() == "known",
                "notes": item.get("notes") or "",
            }
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"fetched_at": now, "entries": entries}, fh)
        except Exception:
            pass  # cache write failed -> keep using the in-memory data
        return entries
    except Exception:
        # offline: use the stale cache if present
        if cache and isinstance(cache, dict):
            return cache.get("entries", {})
        return {}


def priority_for(finding):
    """P1 if KEV or EPSS >= 0.5; P2 if EPSS >= 0.1; P3 otherwise.
    Without CVE data: CRITICAL -> P2, everything else P3."""
    if finding.get("kev"):
        return "P1"
    epss = finding.get("epss")
    if isinstance(epss, (int, float)):
        if epss >= 0.5:
            return "P1"
        if epss >= 0.1:
            return "P2"
        return "P3"
    if finding.get("cves") or cves_of(finding):
        return "P3"  # has CVEs but no threat-intel data
    return SEV_PRIORITY.get(str(finding.get("severity", "")).upper(), "P3")


def sort_key(f):
    """Sort key: KEV first (desc), then EPSS (desc), then CVSS (desc)."""
    return (1 if f.get("kev") else 0,
            float(f.get("epss") or 0.0),
            float(f.get("cvss") or 0.0))


def priority_line(f):
    """'EPSS 94% · KEV LISTED · P1' — only the available parts."""
    parts = []
    epss = f.get("epss")
    if isinstance(epss, (int, float)):
        parts.append(f"EPSS {round(float(epss) * 100)}%")
    if f.get("kev"):
        parts.append("KEV LISTED")
    parts.append(str(f.get("priority") or "P3"))
    return " · ".join(parts)


def enrich(findings, cancelled=None, log=None):
    """Return a NEW list of findings with threat-prior keys on every
    CVE-bearing finding, and 'priority' on ALL findings. Never raises."""
    out = [dict(f) for f in (findings or [])]
    try:
        if callable(cancelled) and cancelled():
            for f in out:
                f["priority"] = priority_for(f)
            return out
        all_cves = []
        for f in out:
            all_cves.extend(cves_of(f))
        epss_map = {}
        kev_map = {}
        if all_cves:
            epss_map = fetch_epss(all_cves)
            kev_map = load_kev()
        for f in out:
            cves = cves_of(f)
            if cves:
                ep = next((epss_map[c] for c in cves if c in epss_map), None)
                if ep:
                    f["epss"] = ep["epss"]
                    f["epss_percentile"] = ep["percentile"]
                kev = next((kev_map[c] for c in cves if c in kev_map), None)
                if kev:
                    f["kev"] = True
                    f["kev_date"] = kev.get("date") or ""
                    f["kev_ransomware"] = bool(kev.get("ransomware"))
                else:
                    f["kev"] = False
            f["priority"] = priority_for(f)
        counts = {"P1": 0, "P2": 0, "P3": 0}
        for f in out:
            counts[f["priority"]] = counts.get(f["priority"], 0) + 1
        if log:
            log(f"[threatprior] enriched {len(out)} findings: "
                f"P1 x{counts['P1']}, P2 x{counts['P2']}, P3 x{counts['P3']}")
    except Exception:
        for f in out:
            if "priority" not in f:
                try:
                    f["priority"] = priority_for(f)
                except Exception:
                    f["priority"] = "P3"
    return out
