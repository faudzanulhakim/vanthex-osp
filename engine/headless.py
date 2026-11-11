"""Headless browser rendering — OPTIONAL (Phase 4).

Enables endpoint discovery on SPAs (React/Vue/Angular) by rendering pages
with Chromium via Playwright IF the operator has already installed it. The
toolkit does NOT bundle/install a browser of its own: if Playwright is
missing, available() returns a clear reason and the engine degrades to the
static crawler — stated in the scan warnings, it never pretends it can
render.

extract_endpoints_from_dom() is a pure function (no browser): it extracts
endpoint candidates from rendered HTML — links, form actions, script srcs,
and literal "/api/…" path strings in inline scripts (fetch/XHR patterns).
This is the unit-tested function; render() is just the data carrier.
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
    """(bool, reason) — check Playwright WITHOUT installing anything."""
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
    """Extract endpoint candidates from HTML (rendered output or static).
    Returns a sorted list of unique paths — including API endpoints that
    only appear as literal strings in inline scripts."""
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
    """Render one URL with headless Chromium; return a dict
    {html, endpoints, requests}. Raises HeadlessUnavailable if
    Playwright/the browser is unavailable."""
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
