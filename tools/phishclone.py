"""
PhishClone v1 — Phishing Page Cloner (Engagement-Only) for VANTHEX (v1.8.0).
AUTHORIZED TESTING ONLY — for phishing assessment simulation with written
permission from the owner of the domain being cloned.

- clone(): fetch page → inline CSS/img → insert engagement WATERMARK
  (banner + meta) on ALL output → write local file.
- Every cloned page MUST carry the markers:
  <meta name="x-vanthex-engagement"> + "AUTHORIZED SIMULATION" banner.
  No credential exfiltration — forms are pointed at a LOCAL /capture
  endpoint for flow demo, and the output file is clearly marked.
"""
import os as _os
import re as _re
import urllib.request as _urllib

WATERMARK_META = '<meta name="x-vanthex-engagement" content="AUTHORIZED-TESTING-ONLY">'
BANNER = ('<div style="position:fixed;bottom:0;left:0;right:0;z-index:99999;'
          'background:#b00020;color:#fff;font:12px sans-serif;padding:4px 8px;'
          'text-align:center">AUTHORIZED PHISHING SIMULATION — VANTHEX '
          'ENGAGEMENT — DO NOT ENTER REAL CREDENTIALS</div>')
CAPTURE = 'action="/capture" data-vanthex-demo="1"'


def _fetch(url):
    req = _urllib.Request(url, headers={"User-Agent": "VANTHEX-PhishClone/1.0"})
    with _urllib.urlopen(req, timeout=10) as r:
        return r.status, r.read().decode("utf-8", "replace")


def clone(url, out_dir, base=None):
    """Clone a single page → marked HTML file. Return {path, size, forms}."""
    status, html = _fetch(url)
    base = base or url
    # inline: rewrite relative src/href into simple absolute URLs
    html = _re.sub(r'(src|href)="/([^/"])',
                   rf'\1="{_rsplit(base)}\2', html)
    n_forms = html.lower().count("<form")
    # all forms pointed at the local capture endpoint + demo-marked
    html = _re.sub(r"<form([^>]*)>", rf"<form\1 {CAPTURE}>", html,
                   flags=_re.I)
    html = html.replace("<head>", "<head>" + WATERMARK_META, 1) \
        if "<head>" in html else WATERMARK_META + html
    html += BANNER
    _os.makedirs(out_dir, exist_ok=True)
    name = _re.sub(r"[^a-z0-9]+", "_", base.lower())[:40] or "page"
    path = _os.path.join(out_dir, f"clone_{name}.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return {"source": url, "path": path, "status": status,
            "size": len(html), "forms": n_forms,
            "watermarked": True}


def _rsplit(base):
    m = _re.match(r"(https?://[^/]+)", base)
    return m.group(1) if m else ""
