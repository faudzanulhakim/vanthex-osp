"""Headless browser rendering — OPSIONAL (Fase 4).

Mengaktifkan penemuan endpoint pada SPA (React/Vue/Angular) dengan
me-render halaman memakai Chromium via Playwright BILA operator sudah
memasangnya. Toolkit TIDAK membawa/memasang browser sendiri: bila
Playwright tidak ada, available() mengembalikan alasan yang jelas dan
engine terdegradasi ke crawler statis — dinyatakan di warnings scan,
tidak pernah pura-pura bisa me-render.

extract_endpoints_from_dom() adalah fungsi murni (tanpa browser):
mengekstrak kandidat endpoint dari HTML hasil render — tautan, action
form, src skrip, dan literal path "/api/…" di skrip inline (pola
fetch/XHR). Fungsi ini yang diuji unit; render() hanya pembawa datanya.
"""
import re
from urllib.parse import urljoin, urlparse

_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
               ".ico", ".map", ".woff", ".woff2", ".ttf", ".mp4", ".webp")
_API_LITERAL = re.compile(r"""["'](/api/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)["']""")
_PATH_LITERAL = re.compile(
    r"""["'](/[A-Za-z0-9][A-Za-z0-9._~!$&()*+,;=:@%/-]{2,120})["']""")


class HeadlessUnavailable(Exception):
    pass


def available():
    """(bool, reason) — cek Playwright TANPA memasang apa pun."""
    try:
        import playwright  # noqa: F401
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True, "playwright installed"
    except Exception as e:
        return False, f"playwright not installed ({type(e).__name__})"


def _clean(path, base_path="/"):
    if not path or path.startswith(("data:", "blob:", "mailto:", "tel:",
                                     "javascript:", "#")):
        return None
    if path.startswith(("http://", "https://", "//")):
        path = urlparse(path if not path.startswith("//")
                        else "http:" + path).path or "/"
    if not path.startswith("/"):
        path = urljoin(base_path, path)
    path = path.split("#")[0]
    low = path.lower()
    if any(low.endswith(e) for e in _STATIC_EXT):
        return None
    return path[:300]


def extract_endpoints_from_dom(html_text, base_path="/"):
    """Ekstrak kandidat endpoint dari HTML (hasil render atau statis).
    Mengembalikan list path unik terurut — termasuk endpoint API yang
    hanya muncul sebagai literal string di skrip inline."""
    found = set()
    if not html_text:
        return []
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_text, "html.parser")
        for tag, attr in (("a", "href"), ("form", "action"),
                          ("script", "src"), ("link", "href"),
                          ("iframe", "src")):
            for el in soup.find_all(tag):
                v = el.get(attr)
                c = _clean(v, base_path) if v else None
                if c:
                    found.add(c)
        inline = "\n".join(s.get_text() for s in soup.find_all("script")
                           if not s.get("src"))
    except Exception:
        inline = html_text
    for m in _API_LITERAL.finditer(inline):
        c = _clean(m.group(1), base_path)
        if c:
            found.add(c)
    for m in _PATH_LITERAL.finditer(inline):
        p = m.group(1)
        if any(k in p for k in ("/api", "/rest", "/graphql", "/v1/", "/v2/")):
            c = _clean(p, base_path)
            if c:
                found.add(c)
    return sorted(found)


def render(url, timeout_ms=15000):
    """Render satu URL dengan Chromium headless; kembalikan dict
    {html, endpoints, requests}. Melempar HeadlessUnavailable bila
    Playwright/browser tidak tersedia."""
    ok, reason = available()
    if not ok:
        raise HeadlessUnavailable(reason)
    from playwright.sync_api import sync_playwright
    reqs = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        page.on("request", lambda r: reqs.append(r.url))
        page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
        try:
            page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass
        html_text = page.content()
        browser.close()
    host = urlparse(url).netloc
    eps = extract_endpoints_from_dom(html_text, urlparse(url).path or "/")
    for u in reqs:
        pu = urlparse(u)
        if pu.netloc == host:
            c = _clean(pu.path + (("?" + pu.query) if pu.query else ""),
                       "/")
            if c and c not in eps:
                eps.append(c)
    return {"html": html_text, "endpoints": sorted(set(eps)),
            "requests": reqs}
