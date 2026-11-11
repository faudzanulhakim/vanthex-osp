"""
Tripwire v1 — Zero-Day Tripwire for VANTHEX (v1.9.0).
AUTHORIZED TESTING ONLY.

Monitors CVE feeds and matches them against the target's tech fingerprint:
new CVEs hitting the target's stack → alert + priority. Feeds come from:
- a local JSON file (feed_path option) — format: [{"cve_id", "products",
  "severity", "published", "summary"}]
- the compact builtin feed for offline/demo mode

CLI: .venv/bin/python tripwire.py --target http://host --feed feed.json
"""
import json as _json

import vulnscan2 as _v


def load_feed(path=None):
    """Load a CVE feed (local JSON) or the compact builtin feed."""
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return [
        {"cve_id": "CVE-2026-3001", "products": ["nginx"],
         "severity": "HIGH", "published": "2026-10-01",
         "summary": "HTTP/2 request smuggling in nginx < 1.27.4"},
        {"cve_id": "CVE-2026-3114", "products": ["flask"],
         "severity": "MEDIUM", "published": "2026-10-18",
         "summary": "Session cookie deserialization in Flask"},
        {"cve_id": "CVE-2026-3188", "products": ["express"],
         "severity": "HIGH", "published": "2026-10-25",
         "summary": "ReDoS in Express body parser"},
        {"cve_id": "CVE-2026-3250", "products": ["docker", "containerd"],
         "severity": "CRITICAL", "published": "2026-11-01",
         "summary": "Docker API auth bypass leading to host takeover"},
    ]


def match(target_profile, feed):
    """target_profile: result of techdb.profile (dict name->version?) or a list
    of technologies. Return a list of alerts {cve_id, product, severity, summary}."""
    techs = set()
    if isinstance(target_profile, dict):
        for k in target_profile:
            techs.add(str(k).lower())
    else:
        techs |= {str(t).lower() for t in target_profile}
    alerts = []
    for c in feed or []:
        for prod in (c.get("products") or []):
            if str(prod).lower() in techs:
                alerts.append({"cve_id": c.get("cve_id"),
                               "product": prod,
                               "severity": (c.get("severity") or "?").upper(),
                               "summary": (c.get("summary") or "")[:120]})
                break
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    alerts.sort(key=lambda a: order.get(a["severity"], 9))
    return alerts


def check_target(base, feed_path=None):
    """Quick passive scan → fingerprint → match feed. Return alerts."""
    res = _v.run_vulnscan(base, "passive-quick", log=[],
                          opts={"timeout": 8})
    profile = res.get("tech_profile") or {}
    if not profile:
        # fallback: use fingerprint finding titles
        profile = [f["title"] for f in res.get("findings", [])
                   if "fingerprint" in f["title"].lower() or
                   "version" in f["title"].lower()]
    return match(profile, load_feed(feed_path)), profile


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="VANTHEX zero-day tripwire")
    ap.add_argument("--target", required=True)
    ap.add_argument("--feed", default=None, help="local CVE JSON feed")
    a = ap.parse_args()
    alerts, prof = check_target(a.target, a.feed)
    print(f"tech: {prof}")
    print(f"{len(alerts)} CVEs hit the target's stack:")
    for al in alerts:
        print(f"  [{al['severity']}] {al['cve_id']} ({al['product']}): "
              f"{al['summary']}")
    if not alerts:
        print("  (clean)")
