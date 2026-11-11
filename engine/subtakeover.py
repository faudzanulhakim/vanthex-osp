"""
SubTakeover v1 — subdomain takeover verification for VANTHEX. Read-only.

Dangling CNAME fingerprinting: the CNAME points at a third-party service
that is no longer claimed (NXDOMAIN on the service side / a 'There isn't a
GitHub Pages site here' page etc.) → the subdomain can be claimed by an
attacker.
Pure module: fingerprinting from RESPONSE TEXT — DNS resolver & fetch
injected. Never performs claiming/purchasing.

Common service signatures (response body / NXDOMAIN message):
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
    """Match the CNAME + response body against service signatures.
    Returns (service, confidence) or (None, "")."""
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
    """End-to-end verification for one subdomain (read-only):
    dns_lookup(sub) -> cname (or None if NXDOMAIN on the target DNS)
    fetcher(sub)    -> (status, body)
    Returns dict {subdomain, service, confidence, evidence} or None."""
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
                        f"signature '{svc}' matched the service response"}


def scan(pairs, fetcher, dns_lookup):
    """pairs: list of (subdomain, cname). Returns list of verified findings."""
    out = []
    for sub, cname in (pairs or [])[:20]:
        r = verify(sub, cname, fetcher, dns_lookup)
        if r:
            out.append(r)
    return out
