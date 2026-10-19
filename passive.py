"""
Pentest Toolkit — Passive Reconnaissance module (passive.py, v3.13).

Self-built passive OSINT: the target is never probed with attack traffic.
Data sources are public lookups (DNS via the system resolver, Certificate
Transparency via crt.sh, RDAP) plus ordinary GETs of the site's own public
files (homepage, favicon, robots.txt, sitemap, security.txt, public images
for EXIF). Every finding is tagged origin="passive" so reports carry the
footprint of how each fact was obtained (passive vs active).

Honest limits: DNS runs over the system resolver of this host; if egress
DNS is intercepted the module reports the lookup as a warning instead of
inventing records. CT/RDAP need HTTPS egress (via the standard proxy env).
"""
import hashlib
import io
import json
import re
import time
from urllib.parse import urljoin, urlparse

import netclient
import techdb
from vulnscan2 import F, risk_score

_SECOND_LEVEL = {"co", "com", "ac", "go", "or", "net", "web", "sch", "mil"}
_CC_TLD = {"id", "uk", "au", "br", "jp", "kr", "nz", "za", "in", "my", "sg"}


def _registrable(host):
    import ipaddress as _ip
    try:
        _ip.ip_address(host)
        return host                      # IP literal: bukan domain
    except ValueError:
        pass
    parts = [p for p in host.lower().strip(".").split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if parts[-1] in _CC_TLD and parts[-2] in _SECOND_LEVEL and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _dns_error_kind(exc_name):
    """NoAnswer/NXDOMAIN = record terbukti tidak ada (nodata); sisanya
    (NoNameservers/Timeout/...) = lookup GAGAL — tidak boleh jadi klaim."""
    return "nodata" if exc_name in ("NoAnswer", "NXDOMAIN") else "failed"


def _dns_records(name, rtypes):
    """-> (records, failed, nodata). failed berisi label lookup yang gagal
    total; nodata berisi tipe yang terbukti kosong."""
    out, failed, nodata = {}, [], set()
    try:
        import dns.resolver
    except Exception as e:
        return out, [f"{name} *: dnspython unavailable"], nodata
    res = dns.resolver.Resolver()
    res.timeout = 4
    res.lifetime = 7
    for rt in rtypes:
        try:
            ans = res.resolve(name, rt)
            out[rt] = sorted(str(r).strip() for r in ans)
        except Exception as e:
            if _dns_error_kind(type(e).__name__) == "nodata":
                nodata.add(rt)
            else:
                failed.append(f"{name} {rt}: {type(e).__name__}")
    # Fallback A/AAAA via getaddrinfo (resolver sistem) bila dnspython gagal
    if any(f" {rt}:" in " ".join(failed) for rt in ()):
        pass
    for rt, fam in (("A", 2), ("AAAA", 10)):
        if rt in rtypes and rt not in out and any(
                x.startswith(f"{name} {rt}:") for x in failed):
            vals = []
            try:
                import scanners as _sc
                doh = _sc.doh_query(name, rt)
                if doh:
                    vals = sorted({v for v in doh
                                   if not _sc.is_synthetic_ip(v)})
                if not vals:
                    import socket as _sk
                    infos = _sk.getaddrinfo(name, None, fam)
                    vals = sorted({i[4][0] for i in infos
                                   if not _sc.is_synthetic_ip(i[4][0])})
            except Exception:
                vals = []
            if vals:
                out[rt] = vals
                failed = [x for x in failed
                          if not x.startswith(f"{name} {rt}:")]
    return out, failed, nodata


def _email_auth_findings(domain, apex_txt, dmarc_txt):
    """Evaluasi SPF/DMARC dari record TXT mentah -> findings (murni, teruji)."""
    out = []
    spf = next((t for t in apex_txt if t.replace('"', "").startswith("v=spf1")), "")
    if not spf:
        out.append(F("LOW", f"No SPF record for {domain}",
                     "Without an SPF record, anyone can send email that claims to come from this domain (spoofing surface for phishing).",
                     evidence=f"no v=spf1 TXT at {domain}", cwe="CWE-290",
                     owasp="ASVS V2", cvss=3.7,
                     remed="Publish an SPF record listing the legitimate mail senders and end it with -all.",
                     confidence="candidate", location=domain, origin="passive"))
    elif "+all" in spf:
        out.append(F("MEDIUM", f"SPF record for {domain} allows any sender (+all)",
                     "An SPF record ending in +all explicitly authorizes every host on the internet to send mail for this domain — SPF provides no protection.",
                     evidence=spf[:140], cwe="CWE-290", owasp="ASVS V2", cvss=5.3,
                     remed="Replace +all with -all (or ~all during transition) and list only real senders.",
                     confidence="confirmed", location=domain, origin="passive"))
    dmarc = next((t for t in dmarc_txt if "v=DMARC1" in t), "")
    if not dmarc:
        out.append(F("LOW", f"No DMARC record for {domain}",
                     "Without DMARC, receivers cannot verify alignment for this domain and spoofed mail is far more likely to be delivered.",
                     evidence=f"no v=DMARC1 TXT at _dmarc.{domain}", cwe="CWE-290",
                     owasp="ASVS V2", cvss=3.7,
                     remed="Publish _dmarc with at least p=quarantine and an aggregate reporting address.",
                     confidence="candidate", location=f"_dmarc.{domain}",
                     origin="passive"))
    elif "p=none" in dmarc.replace(" ", ""):
        out.append(F("LOW", f"DMARC policy for {domain} is monitor-only (p=none)",
                     "A p=none policy provides visibility but no enforcement: spoofed mail is still delivered.",
                     evidence=dmarc[:140], cwe="CWE-290", owasp="ASVS V2", cvss=3.7,
                     remed="Move to p=quarantine or p=reject after reviewing aggregate reports.",
                     confidence="confirmed", location=f"_dmarc.{domain}",
                     origin="passive"))
    return out


def _parse_crtsh(data):
    subs, issuers = set(), set()
    rows = data if isinstance(data, list) else []
    for row in rows:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower()
            if name:
                subs.add(name)
        if row.get("issuer_name"):
            issuers.add(str(row["issuer_name"])[:70])
    return {"certificates": len(rows), "subdomains": sorted(subs)[:300],
            "issuers": sorted(issuers)[:10]}


def _fetch_bytes(url, timeout=8, verify=False, cap=4 * 1024 * 1024, _hops=0, headers=None):
    if _hops > 3:
        return 0, [], b""
    """GET bytes mentah mengikuti pola proxy netclient. verify=True memakai
    bundel CA certifi (untuk API publik tepercaya: crt.sh, RDAP) — target
    scan sendiri memakai konteks tak-terverifikasi seperti engine lain."""
    import gzip
    import http.client
    import ssl
    scheme, host, port, _bp = netclient.split_target(url)
    proxy = netclient._proxy_for(scheme, host, "")
    if verify:
        try:
            import certifi
            ctx = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            ctx = ssl.create_default_context()
    else:
        ctx = ssl._create_unverified_context()
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    hdrs = {"User-Agent": netclient.UA, "Accept": "*/*", **(headers or {})}
    try:
        if proxy and scheme == "https":
            conn = http.client.HTTPSConnection(proxy["host"], proxy["port"],
                                               timeout=timeout, context=ctx)
            th = {"Proxy-Authorization": proxy["auth"]} if proxy["auth"] else None
            conn.set_tunnel(host, port, headers=th)
            send = path
        elif proxy:
            conn = http.client.HTTPConnection(proxy["host"], proxy["port"],
                                              timeout=timeout)
            send = url
            if proxy["auth"]:
                hdrs["Proxy-Authorization"] = proxy["auth"]
        elif scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                               context=ctx)
            send = path
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            send = path
        conn.request("GET", send, headers=hdrs)
        r = conn.getresponse()
        raw = r.read(cap)
        if (r.getheader("Content-Encoding") or "").lower() == "gzip":
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass
        status, headers = r.status, r.getheaders()
        conn.close()
        if status in (301, 302, 303, 307, 308):
            loc = next((v for k, v in headers if k.lower() == "location"), "")
            if loc:
                return _fetch_bytes(urljoin(url, loc), timeout=timeout,
                                    verify=verify, cap=cap, _hops=_hops + 1)
        return status, headers, raw
    except Exception:
        return 0, [], b""


def _exif_of(raw):
    """Ekstrak EXIF (Pillow) dari bytes gambar -> dict tag terbaca + GPS."""
    try:
        from PIL import Image
        from PIL.ExifTags import GPSTAGS, TAGS
        im = Image.open(io.BytesIO(raw))
        ex = im.getexif()
        if not ex:
            return {}
        out = {}
        for k, v in ex.items():
            out[TAGS.get(k, str(k))] = str(v)[:80]
        try:
            gps_ifd = ex.get_ifd(0x8825)
            if gps_ifd:
                out["GPS"] = {GPSTAGS.get(k, str(k)): str(v)[:50]
                              for k, v in gps_ifd.items()}
        except Exception:
            pass
        return out
    except Exception:
        return {}


class _PageSignals:
    """Ekstraksi sinyal halaman memakai html.parser (stdlib) — lebih kokoh
    daripada regex untuk komentar & tag img pada HTML dunia nyata."""

    def __init__(self, html_text):
        from html.parser import HTMLParser

        outer = self
        self.comments, self.images = [], []

        class _P(HTMLParser):
            def handle_comment(self, data):
                outer.comments.append(data)

            def handle_starttag(self, tag, attrs):
                if tag == "img":
                    for k, v in attrs:
                        if k == "src" and v:
                            outer.images.append(v)

        parser = _P(convert_charrefs=True)
        try:
            parser.feed(html_text or "")
        except Exception:
            pass


def _robots_rules(text):
    """Parse robots.txt terstruktur via urllib.robotparser -> ringkasan
    aturan (jumlah rule per agen + contoh jalur yang diblokir untuk '*')."""
    try:
        from urllib.robotparser import RobotFileParser
        rp = RobotFileParser()
        rp.parse((text or "").splitlines())
        entries = []
        all_entries = list(getattr(rp, "entries", []) or [])
        if getattr(rp, "default_entry", None) is not None:
            all_entries.insert(0, rp.default_entry)
        for e in all_entries:
            entries.append({"agents": list(getattr(e, "useragents", [])),
                            "disallow": [r.path for r in
                                         getattr(e, "rulelines", []) if not r.allowance],
                            "allow": [r.path for r in
                                      getattr(e, "rulelines", []) if r.allowance]})
        return {"entries": entries,
                "crawl_delay": rp.crawl_delay("*"),
                "sitemaps": rp.site_maps() or []}
    except Exception:
        return {"entries": [], "crawl_delay": None, "sitemaps": []}


def _sitemap_urls(xml_text):
    """Hitung + contoh URL sitemap via XML parser aman (defusedxml);
    fallback regex bila dokumen tidak ter-parse."""
    try:
        from defusedxml import ElementTree as DET
        root = DET.fromstring((xml_text or "").encode("utf-8", "replace"))
        locs = [el.text.strip() for el in root.iter()
                if el.tag.endswith("}loc") or el.tag == "loc"
                if el.text and el.text.strip()]
        return {"count": len(locs), "sample": locs[:10],
                "is_index": any("sitemapindex" in (el.tag or "")
                                for el in root.iter())}
    except Exception:
        locs = re.findall(r"<loc>\s*([^<\s]+)", xml_text or "")
        return {"count": len(locs), "sample": locs[:10], "is_index": False}


def _fingerprint(raw):
    return {"sha256": hashlib.sha256(raw).hexdigest(),
            "md5": hashlib.md5(raw).hexdigest(), "size": len(raw)}


def run_passive_recon(target, log=None):
    def L(msg):
        if log is None:
            return
        if callable(log):          # protokol CLI: fungsi log(msg)
            log(msg)
        else:                      # protokol service: list log
            log.append(msg)
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("target has no hostname")
    domain = _registrable(host)
    origin_url = f"{parsed.scheme}://{host}" + (f":{parsed.port}" if parsed.port else "")
    L(f"[passive] recon {host} (domain {domain}) — public lookups only")
    findings, warnings = [], []

    def add(f):
        key = (f["title"], f.get("location", ""), f.get("param", ""))
        if not any((x["title"], x.get("location", ""), x.get("param", "")) == key
                   for x in findings):
            findings.append(f)

    client = netclient.Client(target, timeout=8.0)
    home = client.get(parsed.path or "/")
    home_body = home.body or ""
    home_headers = {k: v for k, v in home.headers}
    L(f"[passive] homepage HTTP {home.status}")

    # ---- profil teknologi pasif dari respons yang sudah tertangkap
    tech = []
    if home.status:
        tech = techdb.profile(home.headers, home_body)
        if tech:
            add(F("INFO", "Technology & integration profile",
                  "Passive fingerprint of the technologies and integrations visible in the site's own responses.",
                  evidence="; ".join(f"{t['category']}: {t['name']}" for t in tech)[:400],
                  cwe="CWE-200", owasp="ASVS V14", cvss=0.0,
                  remed="No action required — informational profile of the public attack surface.",
                  confidence="confirmed", location=target, origin="passive"))
    cdn_hint = next((h for h in ("cf-ray", "x-amz-cf-id", "x-akamai-request-id",
                                 "x-cache", "via", "x-served-by")
                     if h in {k.lower() for k in home_headers}), "")

    # ---- DNS enumeration + email auth
    apex, fail1, _n1 = _dns_records(domain, ("A", "AAAA", "NS", "MX", "TXT", "CAA"))
    hostrec, fail2, _n2 = _dns_records(host, ("A", "AAAA", "CNAME"))
    dmarc_rec, fail3, _n3 = _dns_records(f"_dmarc.{domain}", ("TXT",))
    warnings += [f"DNS lookup failed — {e}" for e in (fail1 + fail2 + fail3)][:8]
    txt_failed = (any(x.startswith(f"{domain} TXT:") for x in fail1)
                  or any(x.startswith(f"_dmarc.{domain} TXT:") for x in fail3))
    if txt_failed:
        warnings.append("SPF/DMARC NOT evaluated: the DNS TXT lookups failed "
                        "in this environment, so record absence is unproven")
    else:
        for f in _email_auth_findings(domain, apex.get("TXT", []),
                                      dmarc_rec.get("TXT", [])):
            add(f)
    wild_name = f"ptkwild9x7.{domain}"
    wild, _wf, _wn = _dns_records(wild_name, ("A",))
    wildcard = bool(wild.get("A"))
    if wildcard:
        add(F("INFO", f"Wildcard DNS on {domain}",
              "A random subdomain resolves, so the zone answers for arbitrary names — subdomain-based findings need extra care and phishing subdomains are easier to blend in.",
              evidence=f"{wild_name} -> {', '.join(wild['A'][:3])}",
              cwe="CWE-200", owasp="ASVS V14", cvss=0.0,
              remed="No action required in most setups — informational.",
              confidence="probable", location=domain, origin="passive"))
    L(f"[passive] DNS: apex {sum(len(v) for v in apex.values())} record, "
      f"host {sum(len(v) for v in hostrec.values())}, wildcard={wildcard}")

    # ---- Certificate Transparency (crt.sh, TLS terverifikasi certifi)
    ct = {"certificates": 0, "subdomains": [], "issuers": []}
    st, _h, raw = _fetch_bytes(
        f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20, verify=True)
    if st == 200 and raw:
        try:
            ct = _parse_crtsh(json.loads(raw.decode("utf-8", "replace")))
        except Exception:
            warnings.append("crt.sh response could not be parsed")
    else:
        warnings.append(f"crt.sh lookup unavailable (HTTP {st})")
    if ct["certificates"]:
        add(F("INFO", f"Certificate Transparency: {ct['certificates']} certificates, "
                      f"{len(ct['subdomains'])} unique subdomains for {domain}",
              "Public CT logs expose every hostname that ever received a certificate for this domain — a free map of the external attack surface (including forgotten test/staging systems).",
              evidence=", ".join(ct["subdomains"][:10])[:300],
              cwe="CWE-200", owasp="ASVS V14", cvss=0.0,
              remed="Review the listed hostnames: decommission or protect forgotten subdomains.",
              confidence="confirmed", location=domain, origin="passive"))
    L(f"[passive] CT: {ct['certificates']} cert, {len(ct['subdomains'])} subdomain")

    # ---- RDAP (registrar, status, tanggal)
    rdap = {}
    st, _h, raw = _fetch_bytes(f"https://rdap.org/domain/{domain}",
                                timeout=12, verify=True)
    if st == 200 and raw:
        try:
            d = json.loads(raw.decode("utf-8", "replace"))
            registrar = ""
            for ent in d.get("entities", []):
                if "registrar" in (ent.get("roles") or []):
                    try:
                        registrar = ent["vcardArray"][1][1][3]
                    except Exception:
                        pass
            events = {e.get("eventAction"): e.get("eventDate")
                      for e in d.get("events", [])}
            rdap = {"handle": d.get("handle", ""), "registrar": registrar,
                    "status": d.get("status", []), "events": events,
                    "nameservers": [n.get("ldhName", "")
                                    for n in d.get("nameservers", [])][:8]}
            exp = str(events.get("expiration", ""))[:10]
            if exp:
                try:
                    import datetime as _dt
                    days = (_dt.date.fromisoformat(exp)
                            - _dt.date.today()).days
                    if 0 <= days <= 30:
                        add(F("LOW", f"Domain {domain} expires in {days} days",
                              "A domain close to expiry risks service loss and hostile re-registration.",
                              evidence=f"RDAP expiration {exp}", cwe="CWE-324",
                              owasp="ASVS V14", cvss=3.1,
                              remed="Renew the domain and enable auto-renew + registrar lock.",
                              confidence="confirmed", location=domain,
                              origin="passive"))
                except Exception:
                    pass
        except Exception:
            warnings.append("RDAP response could not be parsed")
    else:
        warnings.append(f"RDAP lookup unavailable (HTTP {st})")
    L(f"[passive] RDAP: registrar={rdap.get('registrar') or '-'}")

    # ---- favicon fingerprint
    fav = {}
    st, _h, raw = _fetch_bytes(origin_url + "/favicon.ico", timeout=8)
    if st == 200 and raw:
        fav = _fingerprint(raw)
        add(F("INFO", "Favicon fingerprint recorded",
              "The favicon hash fingerprints the product/build for correlation with internet-wide scan data (Shodan-style).",
              evidence=f"sha256={fav['sha256'][:24]}… md5={fav['md5']} size={fav['size']}",
              cwe="CWE-200", owasp="ASVS V14", cvss=0.0,
              remed="No action required — informational fingerprint.",
              confidence="confirmed", location="/favicon.ico", origin="passive"))

    # ---- robots.txt / sitemap.xml / security.txt
    files_meta = {}
    rb = client.get("/robots.txt")
    if rb.status == 200 and rb.body and "user-agent" in rb.body.lower():
        rrules = _robots_rules(rb.body)
        files_meta["robots_rules"] = rrules["entries"][:6]
        if rrules["sitemaps"]:
            files_meta["robots_sitemaps"] = rrules["sitemaps"][:5]
        dis = re.findall(r"(?im)^\s*disallow:\s*(\S+)", rb.body)
        files_meta["robots_disallow"] = dis[:40]
        sensitive = [d for d in dis if re.search(
            r"admin|api|private|backup|config|internal|debug|test", d, re.I)]
        if sensitive:
            add(F("LOW", "robots.txt discloses sensitive paths",
                  "Disallow entries are public and often map the very areas the operator wants hidden.",
                  evidence=", ".join(sensitive[:8])[:200], cwe="CWE-200",
                  owasp="ASVS V14", cvss=3.7,
                  remed="Do not rely on robots.txt for secrecy; protect the paths themselves.",
                  confidence="probable", location="/robots.txt", origin="passive"))
    sm = client.get("/sitemap.xml")
    if sm.status == 200 and sm.body:
        smap = _sitemap_urls(sm.body)
        files_meta["sitemap_urls"] = smap["count"]
        files_meta["sitemap_sample"] = smap["sample"]
        files_meta["sitemap_is_index"] = smap["is_index"]
    stxt = client.get("/.well-known/security.txt")
    if not (stxt.status == 200 and stxt.body and "contact" in stxt.body.lower()):
        add(F("INFO", "security.txt not found",
              "No RFC 9116 security.txt — researchers have no published channel to report vulnerabilities in this site.",
              evidence=f"HTTP {stxt.status} at /.well-known/security.txt",
              cwe="CWE-200", owasp="ASVS V14", cvss=0.0,
              remed="Publish a security.txt with a monitored security contact.",
              confidence="candidate", location="/.well-known/security.txt",
              origin="passive"))
    else:
        files_meta["security_txt"] = True

    # ---- komentar HTML & EXIF (kebocoran metadata)
    signals = _PageSignals(home_body)
    comments = [c.strip() for c in signals.comments
                if 12 <= len(c.strip()) <= 300 and re.search(
                    r"todo|fixme|password|secret|internal|debug|hack|temp", c, re.I)]
    if comments:
        add(F("LOW", "Suspicious HTML comments in the homepage",
              "HTML comments ship to every visitor; TODO/internal notes in them leak implementation details.",
              evidence="; ".join(comments[:3])[:240], cwe="CWE-200",
              owasp="ASVS V14", cvss=3.1,
              remed="Strip non-essential comments from production HTML.",
              confidence="candidate", location=target, origin="passive"))
    exif_hits, exif_meta = [], {}
    img_srcs = signals.images
    for src in img_srcs[:40]:
        if len(exif_hits) >= 3:
            break
        if not re.search(r"\.(jpe?g|png|tiff?)($|\?)", src, re.I):
            continue
        st, _h, raw = _fetch_bytes(urljoin(origin_url + "/", src),
                                   timeout=8, cap=3 * 1024 * 1024)
        if st != 200 or not raw:
            continue
        ex = _exif_of(raw)
        if not ex:
            continue
        exif_meta[src[:100]] = {k: v for k, v in ex.items()
                                if k in ("Make", "Model", "Software",
                                         "DateTime", "GPS")}
        if "GPS" in ex:
            exif_hits.append(src)
            add(F("MEDIUM", "Image EXIF contains GPS coordinates",
                  "A publicly served photo carries precise GPS location data in its EXIF block — a direct privacy/location leak.",
                  evidence=f"{src[:100]} GPS: {str(ex['GPS'])[:120]}",
                  cwe="CWE-200", owasp="ASVS V14", cvss=5.3,
                  remed="Strip EXIF metadata from images before publishing.",
                  confidence="probable", location=src[:140], origin="passive"))
    if exif_meta and not exif_hits:
        L(f"[passive] EXIF: metadata in {len(exif_meta)} image(s), no GPS")

    summary = {}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    risk = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                 if summary.get(s)), "CLEAN")
    score = risk_score(findings)
    meta = {"domain": domain, "host": host, "dns": {"apex": apex, "host": hostrec},
            "wildcard_dns": wildcard, "ct": ct, "rdap": rdap,
            "favicon": fav, "files": files_meta, "tech_profile": tech,
            "cdn_indication": cdn_hint, "exif": exif_meta,
            "homepage_status": home.status}
    L(f"[passive] done: {len(findings)} findings | risk {risk} | score {score}/100")
    return {"type": "passive", "target": target, "profile": "passive-recon",
            "method": "passive", "findings": findings, "summary": summary,
            "overall_risk": risk, "risk_score": score, "meta": meta,
            "endpoints": [], "warnings": warnings, "errors": []}
