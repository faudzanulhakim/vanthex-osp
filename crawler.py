"""
crawler.py — penemuan permukaan serangan.

Jauh lebih lengkap dari discover_paths() lama:
- BFS same-host dari homepage, mengikuti href/src/action (kutip tunggal/ganda/tanpa kutip).
- Ekstraksi FORM: action, method, nama input — sumber parameter POST/GET yang nyata.
- robots.txt & sitemap.xml di-parse (Disallow & <loc> adalah petunjuk path sensitif/valid).
- File .js same-host di-fetch; string endpoint (/api/..., /v1/...) diekstrak.
- Setiap URL tercatat beserta nama parameternya; endpoint tebakan lama hanya dipakai
  bila benar-benar merespons (bukan soft-404 / 404).

v3.3: ekstraksi link/form memakai BeautifulSoup (parser HTML asli) bila
tersedia — markup rusak/entity/komentar ditangani dengan benar dan teks di
dalam <script>/<style> tidak lagi berisiko terbaca sebagai atribut, menekan
kelas false positive ekstraksi. Regex lama dipertahankan sebagai fallback
persis perilaku v3.2.2 bila bs4 tidak terpasang.
"""
import re
from urllib.parse import urljoin, urlparse, parse_qsl

try:
    from bs4 import BeautifulSoup
    _HAVE_BS4 = True
except Exception:
    _HAVE_BS4 = False

_LINK_RE = re.compile(r'''(?:href|src|action)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))''', re.I)
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_FORMTAG_RE = re.compile(r"<form\b([^>]*)>", re.I)
_INPUT_RE = re.compile(r"<(?:input|textarea|select)\b[^>]*\bname\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s>]+))", re.I)
_ATTR_RE = lambda name: re.compile(name + r'''\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))''', re.I)
_JS_EP_RE = re.compile(r'''["'`](/[A-Za-z0-9_\-./]+(?:\?[A-Za-z0-9_\-=&%]*)?)["'`]''')
_SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff",
             ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip")


def _g(m):
    return next((x for x in m.groups() if x), "")


def _same_host(url, host):
    try:
        return urlparse(url).hostname in (None, host)
    except Exception:
        return False


def _extract_bs4(body, item, note_url, surf, host):
    """Ekstraksi link + form via BeautifulSoup (parser HTML asli).
    Mengembalikan True bila parse berhasil — pemanggil melewati jalur regex."""
    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception:
        return False
    for tag in soup.find_all(True):
        for attr in ("href", "src", "action"):
            v = tag.get(attr)
            if v:
                note_url(v, item)
    for form in soup.find_all("form"):
        action = form.get("action") or item.split("?")[0]
        method = (form.get("method") or "GET").upper()
        inputs = [i.get("name") for i in form.find_all(["input", "textarea", "select"])]
        inputs = [i for i in inputs if i]
        if action and _same_host(urljoin(item, action), host):
            ap = urlparse(urljoin(item, action)).path or "/"
            surf.forms.append({
                "action": ap, "method": method, "inputs": inputs, "page": item,
                "has_file": any((i.get("type") or "").lower() == "file"
                                for i in form.find_all("input")),
                "enctype": form.get("enctype") or ""})
            if method == "GET" and inputs:
                q = "&".join(f"{i}=1" for i in inputs[:4])
                cand = ap + "?" + q
                if cand not in surf.param_urls:
                    surf.param_urls.append(cand)
    return True


class Surface:
    def __init__(self):
        self.pages = []        # URL path+query yang berhasil di-fetch (status < 500 / != 404 keras)
        self.param_urls = []   # path?query yang punya parameter
        self.forms = []        # {action, method, inputs:[name]}
        self.js_endpoints = [] # path dari file JS
        self.ws_urls = []      # URL WebSocket (ws:// / wss://) dari HTML/JS
        self.robots_paths = [] # Disallow dari robots.txt
        self.homepage = None   # Resp homepage (untuk analisis pasif)


def crawl(client, log=None, max_pages=30, cancelled=None):
    L = log or (lambda m: None)
    surf = Surface()
    seen = set()
    queue = [client.base_path or "/"]
    home = client.get(queue[0])
    surf.homepage = home
    js_urls = []

    def note_url(raw, base="/"):
        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return
        full = urljoin(base, raw)
        if not _same_host(full, client.host):
            return
        p = urlparse(full)
        path = p.path or "/"
        low = path.lower()
        # File JS/CSS/map TIDAK PERNAH di-crawl sebagai halaman HTML: mengurai
        # JS minified dengan regex link menghasilkan URL/param sampah dari
        # fragmen kode (bug FP massal v3.2.0 — lihat ENTERPRISE_NOTES v3.2.1).
        if low.endswith(".js"):
            js_urls.append(path)
            return
        if low.endswith((".css", ".map")):
            return
        if low.endswith(_SKIP_EXT):
            return
        item = path + (("?" + p.query) if p.query else "")
        # Normalisasi Unicode (NFKC): URL yang setara secara kanonik
        # (mis. karakter full-width/kompatibilitas) tidak di-crawl ganda.
        import unicodedata as _ud
        item = _ud.normalize("NFKC", item)
        if item not in seen and len(seen) < max_pages * 3:
            seen.add(item)
            queue.append(item)
            if p.query and item not in surf.param_urls:
                surf.param_urls.append(item)

    # robots.txt + sitemap.xml
    rb = client.get("/robots.txt")
    if rb.status == 200 and "user-agent" in rb.body.lower():
        for line in rb.body.splitlines():
            if line.lower().startswith("disallow:"):
                v = line.split(":", 1)[1].strip()
                if v and v != "/":
                    surf.robots_paths.append(v)
                    note_url(v)
        L(f"[crawl] robots.txt: {len(surf.robots_paths)} disallow path")
    sm = client.get("/sitemap.xml")
    if sm.status == 200 and "<loc>" in sm.body:
        for loc in re.findall(r"<loc>([^<]+)</loc>", sm.body)[:40]:
            note_url(loc)
        L("[crawl] sitemap.xml ter-parse")

    # BFS
    fetched = 0
    while queue and fetched < max_pages:
        if cancelled and cancelled():
            break
        item = queue.pop(0)
        path = item.split("?")[0]
        if path in surf.pages:
            continue
        r = home if item == (client.base_path or "/") else client.get(item)
        if r.status == 0:
            continue
        fetched += 1
        if r.status != 404:
            surf.pages.append(item)
        ctype = (r.hdr("content-type") or "").lower()
        if "javascript" in ctype or "css" in ctype:
            continue  # aset statis: bukan halaman, jangan ekstrak link/param darinya
        body = r.body or ""
        if _HAVE_BS4 and _extract_bs4(body, item, note_url, surf, client.host):
            continue
        for m in _LINK_RE.finditer(body):
            note_url(_g(m), item)
        for fm in _FORM_RE.finditer(body):
            tagm = _FORMTAG_RE.search(fm.group(0))
            attrs = tagm.group(1) if tagm else ""
            am = _ATTR_RE("action").search(attrs)
            action = _g(am) if am else item.split("?")[0]
            mm = _ATTR_RE("method").search(attrs)
            method = (_g(mm) if mm else "GET").upper()
            inputs = [next((x for x in im.groups() if x), "")
                      for im in _INPUT_RE.finditer(fm.group(1))]
            inputs = [i for i in inputs if i]
            if action and _same_host(urljoin(item, action), client.host):
                ap = urlparse(urljoin(item, action)).path or "/"
                em = _ATTR_RE("enctype").search(attrs)
                surf.forms.append({"action": ap, "method": method,
                                   "inputs": inputs, "page": item,
                                   "has_file": bool(re.search(
                                       r'type\s*=\s*["\']?file\b', fm.group(1), re.I)),
                                   "enctype": _g(em) if em else ""})
                if method == "GET" and inputs:
                    q = "&".join(f"{i}=1" for i in inputs[:4])
                    cand = ap + "?" + q
                    if cand not in surf.param_urls:
                        surf.param_urls.append(cand)
        for m in re.finditer(r'''<script[^>]+src\s*=\s*["']([^"']+\.js[^"']*)["']''', body, re.I):
            js_urls.append(urlparse(urljoin(item, m.group(1))).path)

    # URL WebSocket dari homepage (pola ws:// / wss:// eksplisit)
    for m in re.finditer(r"wss?://[^\s\"'<>\)]+", (home.body or "") if home else ""):
        u = m.group(0).rstrip(".,;")
        if u not in surf.ws_urls:
            surf.ws_urls.append(u)
    # JS endpoints
    for jp in list(dict.fromkeys(js_urls))[:6]:
        r = client.get(jp)
        if r.status == 200 and r.body:
            for ep in _JS_EP_RE.findall(r.body):
                ep = ep.split("?")[0]
                if ep.startswith("/api") or "/api/" in ep:
                    if ep not in surf.js_endpoints:
                        surf.js_endpoints.append(ep)
            for m in re.finditer(r"wss?://[^\s\"'<>\)]+", r.body):
                u = m.group(0).rstrip(".,;")
                if u not in surf.ws_urls:
                    surf.ws_urls.append(u)
    L(f"[crawl] {len(surf.pages)} pages, {len(surf.param_urls)} parameterized URLs, {len(surf.forms)} forms, {len(surf.js_endpoints)} JS endpoints")
    return surf


def params_of(path_query):
    if "?" not in path_query:
        return path_query, []
    base, qs = path_query.split("?", 1)
    names = [k for k, _ in parse_qsl(qs, keep_blank_values=True)]
    return base, list(dict.fromkeys(names))


# Endpoint tebakan — HANYA dipakai setelah diverifikasi ada (bukan 404/soft-404).
GUESS_PARAM_URLS = ["/search?q=1", "/item?id=1", "/product?id=1", "/page?id=1",
                    "/index.php?id=1", "/post?id=1", "/comment?id=1",
                    "/user?id=1", "/api/users", "/view?file=home"]
REDIRECT_PATHS = ["/", "/login", "/logout", "/redirect", "/redir", "/go", "/out"]
URL_PARAM_NAMES = {"url", "uri", "link", "src", "dest", "destination", "target",
                   "feed", "callback", "image", "img", "file", "path", "page",
                   "redirect", "next", "return", "returnto", "load", "doc"}
