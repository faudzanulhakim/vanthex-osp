"""
IdentGraph v1 — Identity Graph Builder untuk VANTHEX (v1.9.0).
AUTHORIZED TESTING ONLY — read-only, dari permukaan publik.

Rekonstruksi PETA IDENTITAS target dari sumber terbuka:
- email / username (HTML, JS bundle, meta)
- IdP/SSO yang dipakai (endpoint oauth/saml/sso di JS & link)
- pola email korporat (first.last, flast, dll)
Output: graf identitas → kandidat vektor (phishing presisi, token
replay, password spray wordlist yang tepat).
"""
import re as _re
from collections import Counter as _Counter

from exploitkit import _F

EMAIL_RE = _re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IDP_HINTS = ("auth0", "okta", "onelogin", "azure", "adfs", "keycloak",
             "saml", "/oauth/", "/sso/", "/sso/login", "login.microsoft",
             "accounts.google", "clerk", "workos")


def harvest(ctx):
    """Kumpulkan artefak identitas dari permukaan (HOME + asset JS)."""
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
    """Deteksi pola email korporat dominan → generator kandidat."""
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
    """Peta identitas terbuka: alamat email + IdP + pola email korporat
    bocor dari permukaan publik = recon presisi buat phishing/spray."""
    emails, idp = harvest(ctx)
    admin_like = [e for e in emails if any(r in e.lower() for r in
                  ("admin", "root", "dev", "ops", "it@", "support"))]
    pat, _ = email_pattern(emails)
    if len(emails) >= 2 and (admin_like or idp):
        det = (f"email: {emails[:6]}" +
               (f" (admin: {admin_like[:2]})" if admin_like else "") +
               f"; IdP hint: {idp[:4]}" +
               (f"; pola email: {pat}" if pat else ""))
        add(_F("MEDIUM",
               "Peta Identitas Korporat Terekspose di Permukaan Publik",
               "Alamat email karyawan (termasuk akun ber-hak admin) dan "
               "penyedia identitas (IdP/SSO) dapat dipetakan dari asset "
               "publik — recon presisi untuk phishing dan password "
               "spray tak perlu menebak-nebak.",
               evidence=det,
               cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
               cvss=5.3, location="/", param="identity-surface",
               remed="Jangan taruh email personal di asset publik; "
                     "generik (info@/no-reply@) untuk halaman publik; "
                     "sembunyikan vendor IdP dari bundle JS.",
               confidence="confirmed"))
