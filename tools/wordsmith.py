"""
WordSmith v1 — context-aware wordlist engine for VANTHEX.
AUTHORIZED TESTING ONLY.

contextual_wordlist(target, techs, extra_seeds=None) builds an ordered,
deterministic candidate list of paths/subdomains from:
  - target domain parts (app-name, api.app-name, app-name-backup/...),
  - detected technologies (wordpress -> wp-content/wp-admin/..., php -> .php
    variants, asp -> .aspx, ...),
  - year-based backup naming (backup2024/2025/2026, .bak/.old/.sql),
  - a curated base set of ~200 high-signal paths.
Bounded (default max 1500 entries), duplicate-free, deterministic (no RNG,
no timestamps) so the same inputs always yield the same wordlist.
"""


def _host_of(target):
    """Extract a bare hostname from a target string (URL or bare host)."""
    t = str(target or "").strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0].split("?", 1)[0]
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    t = t.split(":", 1)[0]          # strip port
    return t.lower().strip(".")


def _tech_names(techs):
    """Normalize techs input (list of str or dicts with 'name') to names."""
    names = []
    for t in techs or []:
        if isinstance(t, dict):
            n = str(t.get("name") or t.get("tech") or "").lower()
        else:
            n = str(t or "").lower()
        n = n.strip().lower()
        if n and n not in names:
            names.append(n)
    return names


# Curated base set — high-signal paths (config, source, backups, panels,
# docs, cloud meta, VCS leaks). ~200 entries.
_BASE_PATHS = (
    # panels / auth
    "/admin", "/admin/", "/admin/login", "/administrator", "/admin/dashboard",
    "/admin/config", "/adminer.php", "/manager/html", "/wp-admin/",
    "/wp-login.php", "/cpanel", "/console", "/user/login", "/auth/login",
    "/signin", "/dashboard", "/panel", "/controlpanel",
    # config / env / secrets
    "/.env", "/.env.local", "/.env.production", "/.env.bak", "/config.php",
    "/config.json", "/config.yml", "/config.yaml", "/configuration.php",
    "/settings.py", "/app.config", "/web.config", "/web.config.bak",
    "/.aws/credentials", "/.npmrc", "/.netrc", "/.htaccess", "/.htpasswd",
    "/secrets.json", "/credentials.json", "/secrets.yml", "/local.settings.json",
    # git / vcs / metadata
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/.hg/hgrc",
    "/.DS_Store", "/.svn/wc.db", "/.git/logs/HEAD",
    # backups / archives
    "/backup", "/backup/", "/backup.sql", "/backup.zip", "/backup.tar.gz",
    "/db.sql", "/database.sql", "/dump.sql", "/site.bak", "/www.zip",
    "/backup.old", "/old/", "/archive/", "/bak/", "/dump/", "/db_backup.sql",
    # docs / api
    "/api", "/api/", "/api/v1", "/api/v2", "/api-docs", "/docs", "/doc",
    "/swagger", "/swagger-ui.html", "/swagger-ui/", "/swagger.json",
    "/openapi.json", "/v3/api-docs", "/v2/api-docs", "/graphql",
    "/api/graphql", "/graphiql", "/redoc", "/rpc", "/rest", "/wsdl",
    "/graphql/schema.json", "/api/health", "/health", "/healthz",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/heapdump",
    "/metrics", "/debug", "/status",
    # cms / frameworks
    "/wp-content/", "/wp-content/uploads/", "/wp-content/debug.log",
    "/wp-includes/", "/wp-json/", "/wp-config.php", "/wp-config.php.bak",
    "/xmlrpc.php", "/wp-cron.php", "/readme.html", "/license.txt",
    "/administrator/", "/components/", "/modules/", "/includes/",
    "/sites/default/settings.php", "/core/install.php", "/user/password",
    "/CHANGELOG.txt", "/misc/drupal.js", "/index.php", "/index.php.bak",
    "/info.php", "/phpinfo.php", "/test.php", "/install.php", "/setup.php",
    "/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
    "/yarn.lock", "/Gemfile.lock", "/requirements.txt", "/Pipfile",
    "/poem.lock", "/go.mod", "/OBJECTION", "/default.aspx", "/elmah.axd",
    "/trace.axd", "/server-status", "/server-info",
    # misc leaks
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/security.txt", "/.well-known/security.txt", "/humans.txt", "/favicon.ico",
    "/phpunit.xml", "/behat.yml", "/.gitlab-ci.yml", "/.github/workflows",
    "/Jenkinsfile", "/Dockerfile", "/docker-compose.yml", "/.dockerenv",
    "/k8s", "/kube", "/kubernetes", "/.kube/config", "/id_rsa", "/id_rsa.pub",
    "/private.key", "/server.key", "/key.pem", "/cert.pem", "/keystore.jks",
    "/uploads/", "/files/", "/static/", "/media/", "/assets/", "/data/",
    "/download/", "/documents/", "/tmp/", "/temp/", "/logs/", "/log/",
    "/error.log", "/access.log", "/debug.log", "/app.log", "/.DS_Store",
    "/cgi-bin/", "/cgi-bin/test.cgi", "/admin/config.php", "/api/config",
    "/actuator/logfile", "/druid/index.html", "/nacos/", "/solr/",
    "/elasticsearch/", "/_cat/indices", "/kibana/", "/jenkins/",
    "/sonar/", "/nexus/", "/gitlab/", "/jmx-console/", "/web-console/",
    "/axis2/", "/services/", "/ws/", "/soap", "/xmlrpc", "/JSON-RPC",
    "/api/swagger.json", "/api/openapi.json", "/api/v1/swagger.json",
    "/.DS_Store", "/Thumbs.db", "/desktop.ini", "/WEB-INF/web.xml",
    "/META-INF/MANIFEST.MF", "/.travis.yml", "/.circleci/config.yml",
    "/bitbucket-pipelines.yml", "/appsettings.json", "/appsettings.Production.json",
    "/.python_history", "/.bash_history", "/.mysql_history", "/dump.sql.gz",
    "/database.sqlite", "/db.sqlite3", "/database.db", "/app.db",
    "/prisma/dev.db", "/storage/logs/laravel.log", "/var/log/", "/logs/error.log",
    "/.idea/workspace.xml", "/.vscode/settings.json", "/nbproject/project.properties",
    "/listing", "/tree", "/files.json", "/manifest.json", "/.manifest",
)

# high-signal directory stems reused for domain/year variants
_CTX_STEMS = ("api", "admin", "backup", "dev", "staging", "test", "app",
              "config", "docs", "internal", "old", "new", "beta", "v1", "v2")

_YEAR_ENV_SUFFIXES = ("backup", "bak", "old", "dump", "archive", "site")
_YEARS = (2024, 2025, 2026)

# tech -> extra paths (deterministic tuples)
_TECH_PATHS = {
    "wordpress": ("/wp-json/wp/v2/users", "/wp-content/plugins/",
                  "/wp-content/themes/", "/wp-admin/setup-config.php",
                  "/wp-signup.php", "/wp-trackback.php", "/readme.html",
                  "/wp-content/debug.log", "/xmlrpc.php"),
    "php": ("/index.php", "/config.php", "/info.php", "/db.php",
            "/connect.php", "/inc/", "/includes/config.inc.php",
            "/phpinfo.php", "/upload.php", "/files.php"),
    "asp": ("/default.aspx", "/web.config", "/elmah.axd", "/trace.axd",
            "/aspnet_client/", "/App_Data/"),
    "aspx": ("/default.aspx", "/web.config", "/elmah.axd", "/trace.axd",
             "/aspnet_client/", "/App_Data/"),
    "aspnet": ("/default.aspx", "/web.config", "/elmah.axd", "/trace.axd",
               "/aspnet_client/", "/App_Data/"),
    "jsp": ("/index.jsp", "/META-INF/context.xml", "/WEB-INF/web.xml",
            "/status?full=true", "/examples/", "/manager/status"),
    "django": ("/admin/", "/admin/login/", "/static/", "/media/",
               "/__debug__/", "/accounts/login/"),
    "laravel": ("/storage/logs/laravel.log", "/.env", "/telescope",
                "/horizon", "/_ignition/health-check"),
    "rails": ("/rails/info/properties", "/rails/info/routes", "/assets/"),
    "spring": ("/actuator", "/actuator/env", "/actuator/heapdump",
               "/actuator/mappings", "/error", "/h2-console"),
    "node": ("/package.json", "/node_modules/", "/npm-debug.log",
             "/server.js", "/app.js"),
    "next": ("/_next/", "/_next/static/", "/api/health"),
    "nginx": ("/nginx_status", "/server-status"),
    "apache": ("/server-status", "/server-info"),
    "tomcat": ("/manager/html", "/manager/status", "/host-manager/",
               "/examples/jsp/", "/WEB-INF/web.xml"),
    "drupal": ("/user/login", "/core/install.php", "/update.php",
               "/sites/default/files/", "/CHANGELOG.txt"),
    "joomla": ("/administrator/", "/administrator/index.php",
               "/components/com_users/", "/configuration.php"),
    "magento": ("/admin", "/downloader/", "/var/log/", "/api/soap"),
    "gitlab": ("/users/sign_in", "/api/v4/version", "/help"),
    "jenkins": ("/login", "/script", "/asynchPeople/"),
    "elasticsearch": ("/_cat/indices", "/_cluster/health", "/_search"),
    "grafana": ("/login", "/api/health", "/metrics"),
    "kibana": ("/app/kibana", "/api/status"),
    "sharepoint": ("/_layouts/viewlsts.aspx", "/_vti_bin/"),
    "sap": ("/irj/servlet/jsp/irj/root/", "/sap/public/info"),
    "graphql": ("/graphql", "/graphiql", "/playground",
                "/graphql/schema.json", "/altair"),
}


def _domain_parts(target):
    """Yield path/subdomain candidates derived from the target's domain."""
    host = _host_of(target)
    parts = [p for p in host.split(".") if p]
    if not parts:
        return
    # app label: skip leading www / common providers
    label = parts[0]
    if label in ("www", "app", "web") and len(parts) > 1:
        label = parts[1]
    if not label or len(label) < 2:
        return
    # path-style variants
    for stem in _CTX_STEMS:
        yield f"/{label}-{stem}"
        yield f"/{label}{stem}"
        yield f"/{stem}.{label}"          # subdomain-shaped candidate
        yield f"{stem}.{label}"
        yield f"{label}.{stem}"
    for suf in _YEAR_ENV_SUFFIXES:
        yield f"/{label}-{suf}"
        yield f"{label}-{suf}"
        yield f"/{label}.{suf}"
    for y in _YEARS:
        yield f"/{label}{y}"
        yield f"/{label}-{y}"
        yield f"{label}{y}"
    for y in _YEARS:
        yield f"/backup{y}"
        yield f"/backup{y}.bak"
        yield f"/backup{y}.sql"
        yield f"/backup{y}.zip"
        yield f"/backup{y}/"
        yield f"/db{y}.sql"
        yield f"/{label}{y}.bak"
        yield f"/{label}{y}.old"
        yield f"/{label}{y}.sql"
    # extension-style backups of the app label
    for ext in (".bak", ".old", ".sql", ".zip", ".tar.gz"):
        yield f"/{label}{ext}"
    # classic subdomain-style names (bare, wordlist-of-hostnames form)
    for sub in ("api", "dev", "staging", "stage", "test", "admin", "backup",
                "old", "v2", "beta", "internal", "portal", "app", "www2"):
        yield f"{sub}.{host}"
        yield f"/{sub}-{label}"


def _tech_variants(techs):
    for name in _tech_names(techs):
        key = name
        for k, paths in _TECH_PATHS.items():
            if k in key or key in k:
                for p in paths:
                    yield p
        # php-style extension variants for generic stems
        if "php" in key:
            for stem in ("index", "config", "admin", "login", "upload",
                         "info", "db", "test", "debug", "shell", "cmd",
                         "backup", "old", "install", "setup"):
                yield f"/{stem}.php"
                yield f"/{stem}.php.bak"
                yield f"/{stem}.php~"
        if "asp" in key:
            for stem in ("index", "default", "admin", "login", "config",
                         "test", "backup", "old"):
                yield f"/{stem}.aspx"
                yield f"/{stem}.asp"
                yield f"/{stem}.aspx.bak"


def subdomain_candidates(target, max_entries=200):
    """Bare-hostname candidates for DNS/brute of subdomains, derived from
    the target's domain parts. Deterministic, bounded, duplicate-free."""
    host = _host_of(target)
    parts = [p for p in host.split(".") if p]
    if not parts:
        return []
    label = parts[0]
    if label in ("www", "app", "web") and len(parts) > 1:
        label = parts[1]
    out, seen = [], set()

    def add(s):
        if s and s not in seen and len(out) < max_entries:
            seen.add(s)
            out.append(s)

    for sub in ("api", "dev", "staging", "stage", "test", "admin", "backup",
                "old", "v1", "v2", "beta", "internal", "portal", "app", "www2"):
        add(f"{sub}.{host}")
        if label and label != sub:
            add(f"{sub}.{label}.{host}")
            add(f"{label}-{sub}.{host}")
    return out


def contextual_wordlist(target, techs, extra_seeds=None, max_entries=1500):
    """Build an ordered, deterministic, bounded contextual wordlist.

    Order: domain-derived variants -> tech-derived paths -> base paths ->
    year-based backups -> extra seeds. Entries are unique; the result is
    capped at `max_entries` (paths start with '/', subdomain candidates are
    bare hostnames).
    """
    out, seen = [], set()

    def add(entry):
        e = str(entry or "").strip()
        if not e or e in seen:
            return
        seen.add(e)
        out.append(e)

    for e in _domain_parts(target):
        if len(out) >= max_entries:
            return out
        add(e)
    for e in _tech_variants(techs):
        if len(out) >= max_entries:
            return out
        add(e)
    for e in _BASE_PATHS:
        if len(out) >= max_entries:
            return out
        add(e)
    for e in (extra_seeds or []):
        if len(out) >= max_entries:
            return out
        add(e)
    return out
