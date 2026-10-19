"""Sinkronisasi NVD (Fase 2) — tarik CVE dari NVD API 2.0 ke cache SQLite.

Self-built di atas passive._fetch_bytes (TLS terverifikasi certifi lewat
proxy runtime). Tanpa API key berlaku rate limit publik NVD (5 req/30 dtk)
— jumlah keyword sengaja kecil dan diberi jeda. Kegagalan jaringan selalu
dilaporkan apa adanya (errors[]), tidak pernah difabrikasi jadi '0 CVE'.
"""
import json
import time
import urllib.parse as _up

import passive

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_KEYWORDS = ["wordpress", "apache http server", "jquery", "openssl",
                    "nginx", "php"]


def parse_nvd(data):
    """Parse respons NVD API 2.0 -> list dict ringkas untuk cve_cache."""
    rows = []
    for item in (data or {}).get("vulnerabilities", []):
        cve = item.get("cve", {}) or {}
        desc = ""
        for d in cve.get("descriptions", []) or []:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        score = severity = None
        metrics = cve.get("metrics", {}) or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            lst = metrics.get(key) or []
            if lst:
                cd = lst[0].get("cvssData", {}) or {}
                score = cd.get("baseScore")
                severity = cd.get("baseSeverity") or (
                    lst[0].get("baseSeverity"))
                break
        weak = []
        for w in cve.get("weaknesses", []) or []:
            for d in w.get("description", []) or []:
                if d.get("lang") == "en" and d.get("value"):
                    weak.append(d["value"])
        refs = [r.get("url", "") for r in (cve.get("references", []) or [])
                if r.get("url")][:5]
        cid = cve.get("id", "")
        if cid:
            rows.append({"cve_id": cid,
                         "published": cve.get("published", ""),
                         "modified": cve.get("lastModified", ""),
                         "description": desc[:1500],
                         "cvss": score, "severity": severity,
                         "weaknesses": weak, "refs": refs})
    return rows


def sync(keywords=None, api_key=None, per_keyword=20, fetcher=None):
    """Tarik CVE per keyword. Mengembalikan {fetched, rows, errors} —
    rows siap store.cve_upsert; errors memuat kegagalan per keyword."""
    fetch = fetcher or passive._fetch_bytes
    rows_all, errors = [], []
    for kw in (keywords or DEFAULT_KEYWORDS):
        q = _up.urlencode({"keywordSearch": kw, "resultsPerPage": per_keyword})
        hdr = {"apiKey": api_key} if api_key else {}
        status, _rh, data = fetch(f"{API}?{q}", timeout=25, verify=True,
                                  headers=hdr)
        if status != 200 or not data:
            errors.append(f"{kw}: HTTP {status}")
            continue
        try:
            rows_all += parse_nvd(json.loads(data.decode("utf-8", "replace")))
        except Exception as e:
            errors.append(f"{kw}: parse error {e}")
        time.sleep(1.2 if not api_key else 0.2)
    return {"fetched": len(rows_all), "rows": rows_all, "errors": errors}
