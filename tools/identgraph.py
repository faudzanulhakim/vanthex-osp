"""
IdentGraph v1 — Identity Graph Builder for VANTHEX (v1.9.0).
AUTHORIZED TESTING ONLY — read-only, from the public surface.

Reconstructs the target's IDENTITY MAP from open sources:
- emails / usernames (HTML, JS bundles, meta)
- IdP/SSO in use (oauth/saml/sso endpoints in JS & links)
- corporate email patterns (first.last, flast, etc.)
Output: identity graph → vector candidates (precise phishing, token
replay, the right password-spray wordlist).
"""
import re as _re
from collections import Counter as _Counter

from exploitkit import _F

EMAIL_RE = _re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IDP_HINTS = ("auth0", "okta", "onelogin", "azure", "adfs", "keycloak",
             "saml", "/oauth/", "/sso/", "/sso/login", "login.microsoft",
             "accounts.google", "clerk", "workos")


def harvest(ctx):
    """Collect identity artifacts from the surface (HOME + JS assets)."""
    emails, idp, blob_all = set(), set(), ""
    for ep in ("/", "/static/config.js", "/static/app.v2.js"):
        try:
            r = ctx.client.get(ep)
        except Exception:
            continue
        if r is None or r.status != 200:
            continue
        blob = r.body or ""
        blob_all += blob.lower()
        emails |= set(EMAIL_RE.findall(blob))
        for h in IDP_HINTS:
            if h in blob.lower():
                idp.add(h)
    return sorted(emails), sorted(idp)


def email_pattern(emails, domain_hint=None):
    """Detect the dominant corporate email pattern → candidate generator."""
    if not emails:
        return None, []
    dom = domain_hint or _Counter(e.split("@")[1] for e in emails
                                  if "@" in e).most_common(1)
    dom = dom[0][0] if isinstance(dom, list) else dom
    locals_ = [e.split("@")[0].lower() for e in emails
               if "@" in e and dom in e]
    if not locals_:
        return None, []
    pat = None
    if all("." in l for l in locals_):
        pat = "first.last"
    elif all(l and locals_[0][0] == l[0] and l[1:] for l in locals_) \
            and len(locals_) > 1:
        pat = "flast"
    else:
        pat = "mixed"
    return pat, locals_[:10]


def build_graph(ctx, base_url):
    emails, idp = harvest(ctx)
    pat, locals_ = email_pattern(emails)
    return {"emails": emails, "idp": idp, "pattern": pat,
            "local_parts": locals_, "base": base_url}


def c_identity_graph(ctx, add):
    """Exposed identity map: email addresses + IdP + corporate email patterns
    leaked from the public surface = precise recon for phishing/spray."""
    emails, idp = harvest(ctx)
    admin_like = [e for e in emails if any(r in e.lower() for r in
                  ("admin", "root", "dev", "ops", "it@", "support"))]
    pat, _ = email_pattern(emails)
    if len(emails) >= 2 and (admin_like or idp):
        det = (f"email: {emails[:6]}" +
               (f" (admin: {admin_like[:2]})" if admin_like else "") +
               f"; IdP hint: {idp[:4]}" +
               (f"; email pattern: {pat}" if pat else ""))
        add(_F("MEDIUM",
               "Corporate Identity Map Exposed on the Public Surface",
               "Employee email addresses (including admin-privileged "
               "accounts) and the identity provider (IdP/SSO) can be "
               "mapped from public assets — precise recon for phishing "
               "and password spray without guesswork.",
               evidence=det,
               cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
               cvss=5.3, location="/", param="identity-surface",
               remed="Do not put personal emails in public assets; "
                     "use generic addresses (info@/no-reply@) on public "
                     "pages; hide the IdP vendor from JS bundles.",
               confidence="confirmed"))
