"""
SubTakeover v1 — verifikasi subdomain takeover untuk VANTHEX. Read-only.

Fingerprint CNAME mendangling: CNAME menunjuk layanan pihak ketiga yang
sudah tidak diklaim (NXDOMAIN di sisi layanan / halaman 'There isn't a
GitHub Pages site here' dst) → subdomain bisa diklaim penyerang.
Modul murni: fingerprint dari TULISAN respons — resolver DNS & fetch
disuntikkan. Tidak pernah melakukan klaim/pembelian.

Signature layanan umum (respons body / pesan NXDOMAIN):
"""
SIGNATURES = [
    ("github-pages", "There isn't a GitHub Pages site here"),
    ("azure-cdn", "404 Web Site not found"),
    ("aws-s3", "NoSuchBucket"),
    ("heroku", "No such app"),
    ("shopify", "Sorry, this shop is currently unavailable"),
    ("fastly", "Fastly error: unknown domain"),
    ("cloudfront", "Bad request: CloudFront"),
    ("bitbucket", "Repository not found"),
    ("surge-sh", "project not found"),
]


def fingerprint(cname, status_code, body):
    """Cocokkan CNAME + isi respons dgn signature layanan.
    Returns (service, confidence) atau (None, "")."""
    cname_l = str(cname or "").lower()
    body_l = str(body or "").lower()
    svc = None
    for name, marker in (("github", "github.io"), ("azure", "azurewebsites.net"),
                         ("cloudfront", "cloudfront.net"), ("heroku", "herokuapp.com"),
                         ("s3", "s3.amazonaws.com"), ("shopify", "myshopify.com"),
                         ("fastly", "fastly.net"), ("bitbucket", "bitbucket.io"),
                         ("surge", "surge.sh")):
        if marker in cname_l:
            svc = name
            break
    for name, marker in SIGNATURES:
        if marker.lower() in body_l:
            if svc is None or name.startswith(svc[:4]):
                return name, "confirmed" if status_code in (404, 409) else "probable"
    if svc and status_code in (404, "NXDOMAIN"):
        return svc, "probable"
    return None, ""


def verify(subdomain, cname, fetcher, dns_lookup):
    """Verifikasi end-to-end utk satu subdomain (read-only):
    dns_lookup(sub) -> cname (atau None bila NXDOMAIN di DNS target)
    fetcher(sub)    -> (status, body)
    Returns dict {subdomain, service, confidence, evidence} atau None."""
    try:
        resolved = dns_lookup(subdomain)
    except Exception:
        resolved = None
    try:
        status, body = fetcher(subdomain)
    except Exception:
        status, body = 0, ""
    svc, conf = fingerprint(cname or resolved, status, body)
    if not svc:
        return None
    return {"subdomain": subdomain, "cname": cname or resolved,
            "service": svc, "confidence": conf,
            "evidence": f"CNAME -> {cname or resolved}; HTTP {status}; "
                        f"signature '{svc}' cocok dgn respons layanan"}


def scan(pairs, fetcher, dns_lookup):
    """pairs: list (subdomain, cname). Returns list temuan terverifikasi."""
    out = []
    for sub, cname in (pairs or [])[:20]:
        r = verify(sub, cname, fetcher, dns_lookup)
        if r:
            out.append(r)
    return out
