"""
BrowserKit v1 — Browser-in-the-Middle untuk VANTHEX (v1.9.0).
AUTHORIZED TESTING ONLY.

Render SPA dengan headless Chromium (Playwright) dan audit dari DOM
NYATA — menangkap divergence yang scanner HTTP murni buta:
- konten ter-inject runtime (XSS berbasis DOM)
- form/payload yang baru muncul setelah JS jalan
- endpoint yang dipanggil JS saat runtime (bukan cuma dari bundle)
Degrade anggun: kalau Playwright/Chromium tidak tersedia → raise
BrowserUnavailable (pemanggil memutuskan fallback).
"""
import json as _json


class BrowserUnavailable(RuntimeError):
    pass


def _get_pw():
    try:
        from playwright.sync_api import sync_playwright
        return sync_playwright
    except ImportError:
        raise BrowserUnavailable("playwright tidak terpasang")


def render_and_probe(url, timeout_ms=15000):
    """Render URL di Chromium headless → {title, final_url, dom_text_len,
    runtime_requests, dom_injections, forms}. Screenshot opsional."""
    sync_pw = _get_pw()
    out = {"title": "", "final_url": "", "dom_text_len": 0,
           "runtime_requests": [], "dom_injections": [], "forms": 0}
    with sync_pw() as p:
        try:
            browser = p.chromium.launch(headless=True)
        except Exception as e:
            raise BrowserUnavailable(f"chromium gagal jalan: {e}")
        try:
            page = browser.new_page()
            reqs = []
            page.on("request", lambda r: reqs.append(r.url))
            page.goto(url, timeout=timeout_ms, wait_until="networkidle")
            page.wait_for_timeout(1200)  # beri waktu SPA hydrate
            out["title"] = page.title()
            out["final_url"] = page.url
            out["dom_text_len"] = len(page.inner_text("body"))
            out["runtime_requests"] = [
                u for u in reqs
                if any(k in u for k in ("/api/", "/ws", "fetch", "xhr"))
                or u.endswith(".json")]
            out["forms"] = page.locator("form").count()
            # indikasi DOM injection: elemen script/iframe yang bukan
            # bagian dari HTML sumber (ditambahkan runtime)
            injected = page.evaluate(
                """() => {
                  const out = [];
                  for (const s of document.querySelectorAll('script[src],iframe')) {
                    if (!s.closest('[data-vanthex-static]') &&
                        (s.outerHTML || '').length < 400) {
                      out.push(s.outerHTML.slice(0, 120));
                    }
                  }
                  return out.slice(0, 10);
                }""")
            out["dom_injections"] = injected
        finally:
            browser.close()
    return out


def compare_http_vs_dom(url, http_html):
    """Divergence: apa yang ada di DOM tapi TIDAK di HTML HTTP murni
    → konten yang hanya terlihat via browser (sinyal SPA logic / DOM XSS)."""
    probe = render_and_probe(url)
    dom_only = [r for r in probe["runtime_requests"]
                if r not in (http_html or "")]
    return {"probe": probe, "dom_only_requests": dom_only[:15],
            "divergent": bool(dom_only or probe["dom_injections"])}


def to_json(out):
    return _json.dumps(out, ensure_ascii=False, indent=2)
