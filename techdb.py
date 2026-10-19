"""Database signature teknologi & integrasi (buatan sendiri, v3.5).

Memetakan artefak yang terlihat dari sebuah URL — header respons, nama cookie,
HTML, dan src script — ke teknologi yang terpasang/terintegrasi: web server,
runtime, framework, CMS, library JS, analytics, chat, payment, captcha, auth,
CDN. Pola Wappalyzer-style tetapi DB ditulis & dikurasi sendiri; setiap pola
wajib khas (bukan substring umum) dan hasil selalu membawa evidence penemunya
agar dapat diaudit — sejalan dengan aturan anti-tebakan toolkit ini.

Format entri: {"name", "cat", "rules": [(sumber, regex)]}
sumber: "header" (menguji string "Nama: nilai" per header), "cookie" (nama
cookie dari Set-Cookie), "html" (isi body), "script" (URL src script).
Grup bernama (?P<v>...) pada regex = versi yang diekstrak.
"""

SIGNATURE_DB_VERSION = "1.0.0"
import re

DB = [
    # ---------------- server & CDN ----------------
    {"name": "Apache", "cat": "Web Server", "rules": [("header", r"server:\s*apache/?(?P<v>[\d.]+)?")]},
    {"name": "nginx", "cat": "Web Server", "rules": [("header", r"server:\s*nginx/?(?P<v>[\d.]+)?")]},
    {"name": "Microsoft IIS", "cat": "Web Server", "rules": [("header", r"server:\s*microsoft-iis/(?P<v>[\d.]+)")]},
    {"name": "Tomcat", "cat": "Web Server", "rules": [("header", r"server:.*tomcat/?(?P<v>[\d.]+)?")]},
    {"name": "Jetty", "cat": "Web Server", "rules": [("header", r"server:\s*jetty\(?(?P<v>[\d.]+)?")]},
    {"name": "LiteSpeed", "cat": "Web Server", "rules": [("header", r"server:\s*litespeed")]},
    {"name": "OpenResty", "cat": "Web Server", "rules": [("header", r"server:\s*openresty/?(?P<v>[\d.]+)?")]},
    {"name": "Cloudflare", "cat": "CDN", "rules": [("header", r"cf-ray:"), ("header", r"server:\s*cloudflare")]},
    {"name": "Vercel", "cat": "Hosting/CDN", "rules": [("header", r"x-vercel-id:"), ("header", r"server:\s*vercel")]},
    {"name": "Netlify", "cat": "Hosting/CDN", "rules": [("header", r"x-nf-request-id:"), ("header", r"server:\s*netlify")]},
    # ---------------- runtime & bahasa ----------------
    {"name": "PHP", "cat": "Runtime", "rules": [("header", r"x-powered-by:\s*php/(?P<v>[\d.]+)"), ("cookie", r"^PHPSESSID$")]},
    {"name": "ASP.NET", "cat": "Runtime", "rules": [("header", r"x-aspnet-version:\s*(?P<v>[\d.]+)"), ("cookie", r"^ASP\.NET_SessionId$"), ("header", r"x-powered-by:\s*asp\.net")]},
    {"name": "Java (Servlet)", "cat": "Runtime", "rules": [("cookie", r"^JSESSIONID$")]},
    {"name": "Express (Node.js)", "cat": "Runtime", "rules": [("header", r"x-powered-by:\s*express")]},
    {"name": "Django", "cat": "Framework", "rules": [("cookie", r"^csrftoken$"), ("html", r"csrfmiddlewaretoken")]},
    {"name": "Laravel", "cat": "Framework", "rules": [("cookie", r"^laravel_session$"), ("cookie", r"^XSRF-TOKEN$")]},
    {"name": "Ruby on Rails", "cat": "Framework", "rules": [("header", r"x-powered-by:.*phusion passenger"), ("html", r"csrf-token.*authenticity")]},
    {"name": "GeneXus", "cat": "Framework", "rules": [("cookie", r"^GXSESSION"), ("html", r'"gx[_ ]ajax_key"'), ("html", r"[Gg]ene[Xx]us")]},
    # ---------------- CMS & e-commerce ----------------
    {"name": "WordPress", "cat": "CMS", "rules": [("html", r'<meta[^>]+generator[^>]+content="WordPress\s*(?P<v>[\d.]+)?'), ("html", r"/wp-(content|includes)/")]},
    {"name": "Joomla", "cat": "CMS", "rules": [("html", r'<meta[^>]+generator[^>]+content="Joomla'), ("html", r"/media/jui/")]},
    {"name": "Drupal", "cat": "CMS", "rules": [("html", r"drupal-settings-json|/sites/default/files"), ("header", r"x-generator:\s*drupal")]},
    {"name": "Ghost", "cat": "CMS", "rules": [("html", r'<meta[^>]+generator[^>]+content="Ghost\s*(?P<v>[\d.]+)?')]},
    {"name": "Magento", "cat": "E-commerce", "rules": [("html", r"Mage\.Cookies|/static/frontend/magento"), ("cookie", r"^PHPSESSID$|mage-")]},
    {"name": "Shopify", "cat": "E-commerce", "rules": [("html", r"cdn\.shopify\.com|Shopify\.theme"), ("header", r"x-shopid:")]},
    {"name": "PrestaShop", "cat": "E-commerce", "rules": [("html", r"prestashop|PrestaShop")]},
    {"name": "OpenCart", "cat": "E-commerce", "rules": [("html", r"catalog/view/theme.*opencart|OpenCart")]},
    {"name": "WooCommerce", "cat": "E-commerce", "rules": [("html", r"woocommerce|wc-cart-fragments")]},
    # ---------------- framework & library JS ----------------
    {"name": "Next.js", "cat": "Framework JS", "rules": [("html", r"__NEXT_DATA__|/_next/static/"), ("header", r"x-powered-by:\s*next\.js")]},
    {"name": "Nuxt", "cat": "Framework JS", "rules": [("html", r"__NUXT__|/_nuxt/")]},
    {"name": "React", "cat": "Library JS", "rules": [("html", r"data-reactroot|data-reactid"), ("script", r"react(-dom)?[.-](?P<v>[\d.]+)?(\.min)?\.js")]},
    {"name": "Angular", "cat": "Framework JS", "rules": [("html", r'ng-version="(?P<v>[\d.]+)"'), ("html", r"<app-root|ng-app")]},
    {"name": "Vue.js", "cat": "Library JS", "rules": [("script", r"vue[.-](?P<v>[\d.]+)?(\.min)?\.js|vue\.global"), ("html", r"data-v-app|v-cloak")]},
    {"name": "Svelte", "cat": "Framework JS", "rules": [("html", r"svelte-[a-z0-9]{6,}")]},
    {"name": "jQuery", "cat": "Library JS", "rules": [("script", r"jquery[-.](?P<v>[\d.]+)(\.min)?\.js"), ("script", r"jquery\.js\?ver=(?P<v>[\d.]+)")]},
    {"name": "jQuery UI", "cat": "Library JS", "rules": [("script", r"jquery-ui[-.](?P<v>[\d.]+)")]},
    {"name": "Bootstrap", "cat": "UI Framework", "rules": [("script", r"bootstrap[-.](?P<v>[\d.]+)(\.min)?\.js"), ("html", r"bootstrap[-.](?P<v>[\d.]+)(\.min)?\.css")]},
    {"name": "Tailwind CSS", "cat": "UI Framework", "rules": [("script", r"cdn\.tailwindcss\.com"), ("html", r"tailwindcss")]},
    {"name": "Lodash", "cat": "Library JS", "rules": [("script", r"lodash[-.](?P<v>[\d.]+)")]},
    {"name": "Moment.js", "cat": "Library JS", "rules": [("script", r"moment[-.](?P<v>[\d.]+)(\.min)?\.js")]},
    {"name": "GSAP", "cat": "Library JS", "rules": [("script", r"gsap[-.](?P<v>[\d.]+)")]},
    {"name": "Three.js", "cat": "Library JS", "rules": [("script", r"three[-.](?P<v>[\d.]+)(\.min)?\.js")]},
    {"name": "Chart.js", "cat": "Library JS", "rules": [("script", r"chart[-.](?P<v>[\d.]+)(\.min)?\.js|chart\.umd")]},
    {"name": "DataTables", "cat": "Library JS", "rules": [("script", r"(jquery\.)?datatables[-.](?P<v>[\d.]+)?")]},
    {"name": "SweetAlert2", "cat": "Library JS", "rules": [("script", r"sweetalert2")]},
    {"name": "Font Awesome", "cat": "UI/Font", "rules": [("html", r"font-awesome|fontawesome")]},
    {"name": "Google Fonts", "cat": "UI/Font", "rules": [("html", r"fonts\.googleapis\.com")]},
    # ---------------- analytics & marketing ----------------
    {"name": "Google Analytics", "cat": "Analytics", "rules": [("script", r"googletagmanager\.com/gtag/js\?id=(?P<v>G-[A-Z0-9]+|UA-[\d-]+)"), ("html", r"gtag\('config'")]},
    {"name": "Google Tag Manager", "cat": "Tag Manager", "rules": [("script", r"googletagmanager\.com/gtm\.js\?id=(?P<v>GTM-[A-Z0-9]+)"), ("html", r"GTM-[A-Z0-9]{5,}")]},
    {"name": "Meta (Facebook) Pixel", "cat": "Analytics", "rules": [("script", r"connect\.facebook\.net/[^/]+/fbevents\.js"), ("html", r"fbq\('init'")]},
    {"name": "Hotjar", "cat": "Analytics", "rules": [("script", r"static\.hotjar\.com"), ("html", r"_hjSettings")]},
    {"name": "Microsoft Clarity", "cat": "Analytics", "rules": [("script", r"clarity\.ms")]},
    {"name": "Mixpanel", "cat": "Analytics", "rules": [("script", r"cdn\.mxpnl\.com|mixpanel")]},
    {"name": "Segment", "cat": "Analytics", "rules": [("script", r"cdn\.segment\.com")]},
    {"name": "TikTok Pixel", "cat": "Analytics", "rules": [("script", r"analytics\.tiktok\.com")]},
    {"name": "Matomo", "cat": "Analytics", "rules": [("script", r"matomo\.js|piwik\.js")]},
    # ---------------- chat & support ----------------
    {"name": "Intercom", "cat": "Chat/Support", "rules": [("script", r"widget\.intercom\.io")]},
    {"name": "Crisp", "cat": "Chat/Support", "rules": [("script", r"client\.crisp\.chat")]},
    {"name": "Tawk.to", "cat": "Chat/Support", "rules": [("script", r"embed\.tawk\.to")]},
    {"name": "Zendesk", "cat": "Chat/Support", "rules": [("script", r"static\.zdassets\.com|zendesk")]},
    {"name": "HubSpot", "cat": "Marketing/CRM", "rules": [("script", r"js\.hs-scripts\.com|hs-analytics")]},
    {"name": "WhatsApp (klik chat)", "cat": "Chat/Support", "rules": [("html", r"wa\.me/\d|api\.whatsapp\.com/send")]},
    # ---------------- payment ----------------
    {"name": "Stripe", "cat": "Payment", "rules": [("script", r"js\.stripe\.com")]},
    {"name": "PayPal", "cat": "Payment", "rules": [("script", r"paypal\.com/sdk/js")]},
    {"name": "Midtrans", "cat": "Payment", "rules": [("script", r"app(\.sandbox)?\.midtrans\.com/snap")]},
    {"name": "Xendit", "cat": "Payment", "rules": [("script", r"js\.xendit\.co")]},
    {"name": "DOKU", "cat": "Payment", "rules": [("script", r"doku\.com")]},
    {"name": "Razorpay", "cat": "Payment", "rules": [("script", r"checkout\.razorpay\.com")]},
    # ---------------- captcha & auth ----------------
    {"name": "Google reCAPTCHA", "cat": "CAPTCHA", "rules": [("script", r"google\.com/recaptcha|gstatic\.com/recaptcha"), ("html", r"g-recaptcha")]},
    {"name": "hCaptcha", "cat": "CAPTCHA", "rules": [("script", r"hcaptcha\.com"), ("html", r"h-captcha")]},
    {"name": "Cloudflare Turnstile", "cat": "CAPTCHA", "rules": [("script", r"challenges\.cloudflare\.com/turnstile")]},
    {"name": "Keycloak", "cat": "Auth/SSO", "rules": [("cookie", r"^AUTH_SESSION_ID"), ("html", r"/auth/realms/|keycloak\.js"), ("html", r"realms/[A-Za-z0-9_.-]+/protocol/openid-connect"), ("script", r"/auth/js/keycloak")]},
    {"name": "Auth0", "cat": "Auth/SSO", "rules": [("script", r"cdn\.auth0\.com")]},
    {"name": "Firebase", "cat": "Backend/Auth", "rules": [("script", r"gstatic\.com/firebasejs/(?P<v>[\d.]+)"), ("html", r"firebaseapp\.com")]},
    {"name": "Supabase", "cat": "Backend/Auth", "rules": [("html", r"supabase\.co")]},
    # ---------------- peta & media ----------------
    {"name": "Google Maps", "cat": "Peta", "rules": [("script", r"maps\.googleapis\.com/maps/api")]},
    {"name": "Mapbox", "cat": "Peta", "rules": [("script", r"api\.mapbox\.com")]},
    {"name": "YouTube Embed", "cat": "Media", "rules": [("html", r"youtube\.com/embed/|youtube-nocookie\.com/embed/")]},
    {"name": "Vimeo Embed", "cat": "Media", "rules": [("html", r"player\.vimeo\.com/video/")]},
    # ---------------- framework tambahan ----------------
    {"name": "CodeIgniter", "cat": "Framework", "rules": [("cookie", r"^ci_session$")]},
    {"name": "Spring Boot", "cat": "Framework", "rules": [("html", r"Whitelabel Error Page"), ("error", r"Whitelabel Error Page")]},
    {"name": "Flask", "cat": "Framework", "rules": [("error", r"<title>werkzeug|The Werkzeug Debugger"), ("header", r"server:\s*werkzeug/?(?P<v>[\d.]+)?")]},
    {"name": "Werkzeug", "cat": "Web Server", "rules": [("header", r"server:\s*werkzeug/?(?P<v>[\d.]+)?")]},
    {"name": "FastAPI", "cat": "Framework", "rules": [("html", r"<title>FastAPI( - Swagger UI)?</title>")]},
    {"name": "Symfony", "cat": "Framework", "rules": [("header", r"x-debug-token:"), ("error", r"Symfony\\\\Component|Symfony\\\\\\\\Component")]},
    {"name": "ASP.NET (WebForms/MVC)", "cat": "Framework", "rules": [("html", r'name="__VIEWSTATE"'), ("html", r'name="__EVENTVALIDATION"')]},
    # ---------------- deployment / DevOps & admin tool ----------------
    # Pola wajib khas produk (judul halaman login / header produk / teks
    # edisi) — nama vendor telanjang di teks biasa TIDAK terdeteksi.
    {"name": "Jenkins", "cat": "Deployment/DevOps", "rules": [("header", r"x-jenkins:\s*(?P<v>[\d.]+)"), ("html", r"<title>Sign in \[Jenkins\]"), ("html", r"Jenkins ver\.?\s*(?P<v>[\d.]+)")]},
    {"name": "GitLab", "cat": "Deployment/DevOps", "rules": [("html", r"GitLab (Community|Enterprise) Edition"), ("html", r"<title>Sign in \u00b7 GitLab</title>"), ("html", r"gitlab-logo")]},
    {"name": "phpMyAdmin", "cat": "Admin Tool", "rules": [("html", r"<title>phpMyAdmin</title>"), ("cookie", r"^phpMyAdmin$")]},
    {"name": "Adminer", "cat": "Admin Tool", "rules": [("html", r"<title>Login - Adminer"), ("html", r"Adminer\s+(?P<v>\d+\.\d+\.\d+)")]},
    {"name": "Swagger UI", "cat": "API", "rules": [("html", r"swagger-ui|Swagger UI"), ("script", r"swagger-ui")]},
    # ---------------- database (dari artefak error — pola frasa error khas,
    # BUKAN nama telanjang; teks biasa yang menyebut nama DB tidak terdeteksi) --
    {"name": "MySQL", "cat": "Database", "rules": [("error", r"You have an error in your SQL syntax"), ("error", r"mysqli?_(query|fetch|connect)\(\)|Warning: mysqli"), ("error", r"MySQL server version for the right syntax")]},
    {"name": "MariaDB", "cat": "Database", "rules": [("error", r"MariaDB server version for the right syntax")]},
    {"name": "PostgreSQL", "cat": "Database", "rules": [("error", r"pg_(query|exec)\(\)"), ("error", r"PSQLException|org\.postgresql|Npgsql\."), ("error", r"PostgreSQL\s+\d+.*(ERROR|FATAL)")]},
    {"name": "Microsoft SQL Server", "cat": "Database", "rules": [("error", r"Microsoft OLE DB Provider for (ODBC Drivers|SQL Server)"), ("error", r"ODBC SQL Server Driver|System\.Data\.SqlClient|SqlException")]},
    {"name": "Oracle", "cat": "Database", "rules": [("error", r"ORA-\d{5}"), ("error", r"oci_(execute|parse)\(\)")]},
    {"name": "SQLite", "cat": "Database", "rules": [("error", r"SQLite3|SQLiteException|sqlite3\.OperationalError")]},
    {"name": "MongoDB", "cat": "Database", "rules": [("error", r"Mongo(Server|DB)?Error|com\.mongodb|MongoDB\.Driver")]},
    # ---------------- sistem operasi (indikasi jalur pada error) ----------------
    {"name": "Windows (from error path)", "cat": 'Operating System', "rules": [("error", r"[A-Za-z]:\\\\(xampp|inetpub|wwwroot|php|Windows)")]},
    {"name": "Linux (from error path)", "cat": 'Operating System', "rules": [("error", r"/(var/www|home/[A-Za-z0-9_]+/|usr/lib/php)")]},
]

# Penjelasan mendalam per komponen — ditampilkan di inventory integrasi
# (UI + laporan): apa komponennya, perannya, dan relevansi keamanannya.
DETAILS = {
    "Apache": "Apache HTTP Server — one of the most deployed web servers; serves the site's HTTP traffic and any CGI/module stack on this host. Version-specific CVEs are frequent, so exact patch level matters.",
    "nginx": "nginx — high-performance web server / reverse proxy fronting the application; also terminates TLS and often proxies to app runtimes behind it.",
    "Microsoft IIS": "Microsoft IIS — Windows web server; frequently paired with ASP.NET applications and Windows authentication.",
    "Tomcat": "Apache Tomcat — Java servlet container running Java web applications.",
    "PHP": "PHP runtime executing the server-side application code; its version determines which language-level and extension CVEs apply.",
    "ASP.NET": "Microsoft ASP.NET runtime for .NET web applications.",
    "Express (Node.js)": "Express on Node.js — the application is a Node.js web service; dependency (npm) supply chain is part of its attack surface.",
    "WordPress": "WordPress CMS — the site's content management core; core, theme and plugin versions each carry their own CVE surface and are a top exploitation target.",
    "Laravel": "Laravel — PHP application framework (routing, ORM, auth) behind the application.",
    "Django": "Django — Python web framework behind the application.",
    "Spring Boot": "Spring Boot — Java application framework; if Actuator endpoints are exposed they can leak env/heap data.",
    "FastAPI": "FastAPI — Python API framework; it auto-publishes OpenAPI documentation unless disabled.",
    "Next.js": "Next.js — React server-rendered framework; the app ships server components and API routes under this origin.",
    "React": "React — client-side UI library rendering the interface in the browser.",
    "jQuery": "jQuery — legacy DOM library loaded by the page; old versions carry well-known XSS / prototype-pollution CVEs.",
    "Bootstrap": "Bootstrap — CSS/JS UI framework used by the front end.",
    "MySQL": "MySQL database — identified from leaked database error artefacts; the application stores its data in MySQL. Error leakage itself indicates verbose error handling reaching the DB layer.",
    "MariaDB": "MariaDB database — identified from leaked database error artefacts (MySQL fork).",
    "PostgreSQL": "PostgreSQL database — identified from leaked database error artefacts.",
    "Microsoft SQL Server": "Microsoft SQL Server — identified from leaked OLE DB / SqlClient error artefacts.",
    "MongoDB": "MongoDB — identified from leaked MongoDB driver error artefacts.",
    "SQLite": "SQLite — embedded database, identified from leaked error artefacts.",
    "Oracle": "Oracle Database — identified from ORA- error artefacts.",
    "Jenkins": "Jenkins — CI/CD automation server (build & deployment pipeline). If this console is reachable it is a high-value target: job/script console access typically yields code execution and credential theft.",
    "GitLab": "GitLab — self-hosted Git + CI/CD platform hosting source code and pipelines; its version has a history of critical RCE CVEs.",
    "Docker Registry": "Docker Registry (v2 API) — container image registry; exposed registries can leak proprietary images or accept pushes that poison deployments.",
    "Kubernetes API": "Kubernetes API server — cluster control plane; an exposed API can mean full cluster compromise. Version endpoints should never be public.",
    "Portainer": "Portainer — Docker/Kubernetes management console; admin access equals control over the container host.",
    "Argo CD": "Argo CD — GitOps continuous-delivery controller for Kubernetes; access can alter what gets deployed to clusters.",
    "phpMyAdmin": "phpMyAdmin — web administration console for MySQL/MariaDB; an exposed console is a direct database attack surface (brute force, known CVEs).",
    "Adminer": "Adminer — single-file web database administration tool; exposed instances are a direct database attack surface.",
    "OpenAPI (REST API)": "A machine-readable OpenAPI description of the site's REST API is published — every endpoint, parameter and schema is an integration surface for clients and a map for attackers.",
    "GraphQL API": "GraphQL API endpoint — a single query endpoint for the application's data graph; introspection and query depth are its classic risks.",
    "Swagger UI": "Swagger UI — interactive API documentation console rendering the site's OpenAPI spec in the browser.",
    "Keycloak": "Keycloak — identity and access management (SSO/OIDC) integrated for authentication.",
    "Cloudflare": "Cloudflare — CDN / reverse proxy in front of the origin; edge caching and WAF sit between clients and the server.",
    "Qdrant": "Qdrant — vector database (similarity search engine) used for embeddings / semantic search and RAG features; its REST API returns its version at the service root. An exposed Qdrant lets anyone read or wipe the vector collections.",
    "OpenID Connect (OIDC)": "OpenID Connect identity layer — the application delegates login to an external identity provider (discovery document published at /.well-known/openid-configuration); the issuer identifies the actual IdP product.",
    "Firebase": "Firebase — Google backend platform (auth/database/hosting) integrated by the application.",
    "Stripe": "Stripe — payment processing integration (client-side SDK).",
    "Google Analytics": "Google Analytics — web analytics integration collecting visitor telemetry.",
    "Google reCAPTCHA": "Google reCAPTCHA — bot-protection integration on forms.",
}


_COMPILED = []
for _e in DB:
    _COMPILED.append({"name": _e["name"], "cat": _e["cat"],
                      "rules": [(src, re.compile(pat, re.I)) for src, pat in _e["rules"]]})


def profile(headers, body, script_srcs=None, error_body=""):
    """Profil teknologi dari artefak respons.
    headers: list[(nama, nilai)]; body: str; script_srcs: list[str];
    error_body: isi halaman error (soft-404) — ditambang khusus oleh rule
    bersumber "error" (sidik jari database/framework/OS dari pesan error).
    Return list {name, category, version, evidence, source} — dedup per nama,
    entri berversi didahulukan sebagai evidence utama."""
    hdr_lines = [f"{k}: {v}" for k, v in headers]
    cookies = []
    for k, v in headers:
        if k.lower() == "set-cookie":
            m = re.match(r"\s*([^=;\s]+)=", v)
            if m:
                cookies.append(m.group(1))
    scripts = script_srcs or []
    body = body or ""
    found = {}
    for e in _COMPILED:
        for src, pat in e["rules"]:
            hit, ev = None, ""
            if src == "header":
                for line in hdr_lines:
                    hit = pat.search(line)
                    if hit:
                        ev = line[:110]
                        break
            elif src == "cookie":
                for cname in cookies:
                    hit = pat.search(cname)
                    if hit:
                        ev = f"cookie {cname}"
                        break
            elif src == "script":
                for s in scripts:
                    hit = pat.search(s)
                    if hit:
                        ev = s[:110]
                        break
            elif src == "error":
                hit = pat.search(error_body or "")
                if hit:
                    ev = "error: " + hit.group(0)[:70]
            else:  # html
                hit = pat.search(body)
                if hit:
                    ev = hit.group(0)[:110]
            if hit:
                ver = ""
                try:
                    ver = hit.group("v") or ""
                except Exception:
                    ver = ""
                cur = found.get(e["name"])
                if cur is None:
                    cur = {"name": e["name"], "category": e["cat"],
                           "version": ver, "evidence": ev, "source": src,
                           "evidence_list": [ev], "sources": [src],
                           "detail": DETAILS.get(e["name"], "")}
                    found[e["name"]] = cur
                else:
                    if ev not in cur["evidence_list"]:
                        cur["evidence_list"].append(ev)
                    if src not in cur["sources"]:
                        cur["sources"].append(src)
                    if ver and not cur["version"]:
                        cur["version"] = ver
                        cur["evidence"] = ev
                        cur["source"] = src
    for t in found.values():
        t["evidence_list"] = t["evidence_list"][:4]
        # Keyakinan KEHADIRAN komponen dari artefak pasif: >=2 sumber
        # independen = confirmed; 1 sumber khas produk = probable.
        # (Probe aktif menaikkan ke "verified" di vulnscan2.)
        t["confidence"] = ("confirmed" if len(t["sources"]) >= 2
                           else "probable")
        t["version_confidence"] = (t["confidence"] if t["version"] else "")
    return sorted(found.values(), key=lambda t: (t["category"], t["name"]))


# ---------------------------------------------------------- verifikasi aktif
# Probe konfirmasi untuk stack yang terdeteksi: endpoint publik khas yang
# jawabannya membuktikan stack benar-benar berjalan (bukan sekadar banner).
# parse_verify(name, body) -> (terkonfirmasi: bool, versi: str|None)
VERIFY = {
    "WordPress": ("/wp-json/", r'"namespaces"|"generator"',
                  r'"generator"\s*:\s*"WordPress\s*([\d.]+)?'),
    "Drupal": ("/jsonapi", r'"jsonapi"\s*:',
               r'"version"\s*:\s*"([\d.]+)"'),
    "Joomla": ("/administrator/manifests/files/joomla.xml", r"<version>",
               r"<version>([\d.]+)</version>"),
    "Magento": ("/magento_version", r"Magento/",
                r"Magento/([\d.]+)"),
    "Spring Boot": ("/actuator/health", r'"status"\s*:\s*"UP"',
                    r'"status"\s*:\s*"UP"'),
    "FastAPI": ("/openapi.json", r'"openapi"\s*:',
                r'"openapi"\s*:'),
}


def verify_spec(name):
    return VERIFY.get(name)


def parse_verify(name, body):
    spec = VERIFY.get(name)
    if not spec or not body:
        return (False, None)
    _path, confirm_re, version_re = spec
    if not re.search(confirm_re, body):
        return (False, None)
    m = re.search(version_re, body)
    return (True, (m.group(1) if m and m.lastindex else None))


# ------------------------------------------------- probe komponen aktif
# Endpoint publik khas milik tool deployment/API itu sendiri. Parser murni:
# (headers_list, body) -> (ketemu, versi). Klaim hanya dari signature khas
# produk (header produk / JSON versi resmi), bukan status 200 telanjang.
import json as _json


def _hdr(headers, name):
    for k, v in (headers or []):
        if k.lower() == name.lower():
            return v
    return ""


def _p_docker_registry(headers, body):
    v = _hdr(headers, "Docker-Distribution-API-Version")
    m = re.search(r"registry/([\d.]+)", v or "")
    return (True, m.group(1)) if m else (False, "")


def _p_kubernetes(headers, body):
    try:
        d = _json.loads(body or "")
    except Exception:
        return (False, "")
    gv = str(d.get("gitVersion") or "")
    m = re.match(r"v?([\d.]+)", gv)
    return (True, m.group(1)) if m else (False, "")


def _p_portainer(headers, body):
    try:
        d = _json.loads(body or "")
    except Exception:
        return (False, "")
    v = str(d.get("Version") or "")
    return (True, v) if v and ("InstanceID" in d or "Version" in d) else (False, "")


def _p_argocd(headers, body):
    try:
        d = _json.loads(body or "")
    except Exception:
        return (False, "")
    v = str(d.get("Version") or "")
    m = re.match(r"v?([\d.]+)", v)
    return (True, m.group(1)) if (m and "Version" in d) else (False, "")


def _p_jenkins(headers, body):
    v = _hdr(headers, "X-Jenkins")
    if v:
        return (True, v.strip())
    m = re.search(r"Jenkins ver\.?\s*([\d.]+)", body or "")
    if "<title>Sign in [Jenkins]" in (body or "") or m:
        return (True, m.group(1) if m else "")
    return (False, "")


def _p_openapi(headers, body):
    try:
        d = _json.loads(body or "")
    except Exception:
        return (False, "")
    if "openapi" in d or "swagger" in d:
        ver = str((d.get("info") or {}).get("version") or "")
        return (True, ver)
    return (False, "")


def _p_graphql(headers, body):
    try:
        d = _json.loads(body or "")
    except Exception:
        return (False, "")
    return ((d.get("data") or {}).get("__typename") == "Query", "")


def _p_qdrant(headers, body):
    # Root API Qdrant menjawab JSON {"title":"qdrant - vector search
    # engine","version":"x.y.z",...} — signature produk yang khas.
    try:
        d = _json.loads(body or "")
    except Exception:
        return (False, "")
    if "qdrant" in str(d.get("title") or "").lower():
        return (True, str(d.get("version") or ""))
    return (False, "")


def _p_oidc(headers, body):
    # Dokumen discovery OIDC resmi: ada issuer + authorization_endpoint.
    try:
        d = _json.loads(body or "")
    except Exception:
        return (False, "")
    if d.get("issuer") and d.get("authorization_endpoint"):
        return (True, "")
    return (False, "")


def _p_gitlab_health(headers, body):
    # Endpoint health resmi GitLab menjawab teks khas "GitLab OK".
    return ("GitLab OK" in (body or ""), "")


# path, nama, kategori, parser, metode, body-probe (untuk GraphQL)
COMPONENT_PROBES = [
    ("/-/health", "GitLab", "Deployment/DevOps", _p_gitlab_health, "GET", None),
    ("/v2/", "Docker Registry", "Deployment/DevOps", _p_docker_registry, "GET", None),
    ("/version", "Kubernetes API", "Deployment/DevOps", _p_kubernetes, "GET", None),
    ("/api/system/status", "Portainer", "Deployment/DevOps", _p_portainer, "GET", None),
    ("/api/version", "Argo CD", "Deployment/DevOps", _p_argocd, "GET", None),
    ("/login", "Jenkins", "Deployment/DevOps", _p_jenkins, "GET", None),
    ("/openapi.json", "OpenAPI (REST API)", "API", _p_openapi, "GET", None),
    ("/graphql", "GraphQL API", "API", _p_graphql, "POST", {"query": "{__typename}"}),
    ("/", "Qdrant", "Database", _p_qdrant, "GET", None),
    ("/.well-known/openid-configuration", "OpenID Connect (OIDC)", "Auth/SSO", _p_oidc, "GET", None),
]
