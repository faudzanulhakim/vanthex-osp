#!/usr/bin/env python3
"""VANTHEX v1.23.0 — TOOLS-panel + ARCGIS backends for the OSINT globe.

Design: vanthex-osiris-features-design.md §14.1 (TOOLS panel), §14.3
(ARCGIS INTEL), §16.2 (NEWS perspective, server side = bloc table only;
the chips live in app.html), §16.3 (FINGERPRINT), §16.4 (DATA LEAKS /
CHAIN INTEL / DONBOT / THREATS), §16.5 (SHODAN IOT / MAC ADDR /
BGP ROUTE). Placement confirmed by ADE 2026-10-25 01:08 WIB.

Transport rules (hard, from the program's standing rules):
- ALL panel HTTP goes through the daemon tier: globe_feeds._fetch
  (GET) or globe_feeds._fetch_binary (POST / headers / HTTP-only
  hosts / redirect-following). No direct in-process HTTP, except the
  two documented cases: PORT SCAN (in-process TCP by design, results
  FORCED to INCONCLUSIVE — VM egress) and the SSL fallback to
  scanners.ssl_audit when no delegation exists (same-as-New-Scan
  path; from the service it fails honestly, never fabricates).
- User input is NEVER a host or URL: every tool validates its input
  locally first (domain / IP / MAC / email / username / wallet /
  ticker syntax) and only then calls a FIXED endpoint template with
  the validated value interpolated. Unknown tool names are rejected.
- RDAP follows redirects (max 3 hops, https only, urljoin) — the
  SAME policy as the engine's passive._fetch_bytes, which New Scan's
  RDAP relies on. The redirect target is registry-determined by the
  rdap.org bootstrap, never user-controlled.
- ip-api.com free tier is HTTP-only (HTTPS answers 403 "SSL
  unavailable"): geo lookups use _fetch_binary over http://.
- BreachDirectory is NOT contacted: its build gate FAILED (vendor
  distribution is keyed RapidAPI; keyless claims come from a
  third-party tutorial and an auth-bypass bug report, neither a
  verified public access term). XposedOrNot is the sole DATA LEAKS
  source. The OTX "recent public pulses" strip is NOT built: both
  /pulses/subscribed and /pulses/activity answer 403 "Authentication
  required". The SOL wallet portion is NOT built: both official
  public RPC hostnames timed out from the daemon at build
  verification (docs say keyless, live egress does not answer).
  DONBOT holder-cluster map is NOT built: holder-list APIs are
  keyed (Etherscan requires a key; Solscan Pro 401s without auth).
- FINGERPRINT follows the OSIRIS sherlock.ts semantics (two
  independent 16-char control handles; a site is unreliable if
  EITHER control lands; NSFW sites excluded; every hit CANDIDATE),
  but uses the VANTHEX UA (transparent identification) instead of a
  browser UA; sites that refuse it report 'blocked', never a miss.
- No AI, no DRAW, no terrain, no v1.24/v1.25 items, no REMOTE /
  GLOBAL SWEEP / SELF TRACK / SCM / AIS / bus / breadth / DXY /
  keyed Shodan Host API anywhere in this module (negative-grepped
  by tests/test_v1230.py).

Caches mirror the existing globe_feeds pattern: module dicts with a
lock and a TTL; stale cache is served with stale=True when a refresh
fails, never an invented value.
"""

import base64
import binascii
import ipaddress
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urljoin

import globe_feeds as _gf

# ---------------------------------------------------------------- validation

_RE_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$")
_RE_MAC = re.compile(r"^[0-9A-Fa-f]{12}$")
_RE_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}\.[A-Za-z]{2,63}$")
_RE_USER = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_RE_TICKER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .\-]{0,127}$")
_RE_KEYWORD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 \-_]{0,99}$")

TOOLS = ("dns", "whois", "certs", "ssl", "subdomains", "headers",
         "tech", "ports", "vulnsweep", "username", "phone",
         "shodan", "mac", "bgp", "threats", "dataleaks",
         "chain", "donbot", "fingerprint", "arcgis")

# Tools whose target is a domain, an IP, or either (for route validation).
_DOMAIN_TOOLS = {"dns", "certs", "subdomains", "headers", "tech",
                 "ports", "vulnsweep"}
_IP_TOOLS = {"shodan"}
_DOMAIN_OR_IP = {"whois", "bgp", "threats"}


def _is_domain(v):
    return bool(v) and bool(_RE_DOMAIN.match(v))


def _is_ip(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _is_ipv4(v):
    try:
        return isinstance(ipaddress.ip_address(v), ipaddress.IPv4Address)
    except ValueError:
        return False


def _norm_mac(v):
    h = re.sub(r"[^0-9A-Fa-f]", "", v or "")
    if _RE_MAC.match(h):
        return h.upper()
    return None


def _fail(tool, target, reason):
    return {"ok": False, "tool": tool, "target": target, "reason": reason}


def _validate(tool, target):
    """Local validation FIRST: invalid input is rejected without any
    fetch (never burns quota, never becomes a host). Returns a
    normalized target string, or None when invalid."""
    t = (target or "").strip()
    if tool in _DOMAIN_TOOLS:
        return t.lower() if _is_domain(t) else None
    if tool in _IP_TOOLS:
        return t if _is_ip(t) else None
    if tool in _DOMAIN_OR_IP:
        return t.lower() if (_is_domain(t) or _is_ip(t)) else None
    if tool == "username":
        return t if _RE_USER.match(t) else None
    if tool == "phone":
        return t if t else None
    if tool == "mac":
        return _norm_mac(t)
    if tool == "dataleaks":
        return t if _RE_EMAIL.match(t) else None
    if tool == "donbot":
        return t if _RE_TICKER.match(t) else None
    if tool == "chain":
        return t if t else None
    if tool == "fingerprint":
        return t if _RE_USER.match(t) else None
    return t or None


# ---------------------------------------------------------------- caches

class _Cache(object):
    """Tiny TTL cache: {key: (expires_at, value)}. Mirrors the
    in-memory caches in globe_feeds."""

    def __init__(self):
        self._d = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            row = self._d.get(key)
            if row and row[0] > time.time():
                return row[1]
            return None

    def get_stale(self, key):
        with self._lock:
            row = self._d.get(key)
            return row[1] if row else None

    def put(self, key, value, ttl):
        with self._lock:
            self._d[key] = (time.time() + ttl, value)


_CACHES = {name: _Cache() for name in (
    "dns", "whois", "certs", "headers", "tech", "subdomains",
    "shodan", "mac", "bgp", "threats", "tor", "dataleaks",
    "chain", "donbot", "arcgis", "geo", "sherlock", "coin_price")}


def _cached(cache, key, ttl, fn):
    """Serve fresh cache; on refresh failure serve stale with
    stale=True; else propagate the failure dict from fn."""
    hit = _CACHES[cache].get(key)
    if hit is not None:
        out = dict(hit)
        out["stale"] = False
        return out
    try:
        out = fn()
    except Exception as exc:  # noqa: BLE001 — surfaced as ok:false
        stale = _CACHES[cache].get_stale(key)
        if stale is not None:
            out = dict(stale)
            out["stale"] = True
            return out
        return {"ok": False, "reason": "fetch failed: %s"
                % str(exc)[:160]}
    if isinstance(out, dict) and out.get("ok"):
        _CACHES[cache].put(key, dict(out), ttl)
    return out


# ---------------------------------------------------------------- transport

def _get(host, path, timeout=30.0, headers=None):
    """Daemon-tier GET. headers=None keeps the stock VANTHEX UA."""
    if headers is None:
        return _gf._fetch(host, path, timeout=timeout)
    # _fetch has no headers parameter in older trees; the v1.23.0
    # globe_feeds adds an optional one — fall back to binary GET
    # (which preserves headers) when it is absent.
    try:
        return _gf._fetch(host, path, timeout=timeout, headers=headers)
    except TypeError:
        st, hdrs, body, _cut = _gf._fetch_binary(
            "https://" + host + path, timeout=timeout,
            cap=4 * 1024 * 1024, headers=headers)
        return st, body


def _bin(url, timeout=30.0, cap=1024 * 1024, headers=None,
         method="GET", data=None):
    """Daemon-tier binary fetch (POST / headers / HTTP-only hosts).
    Returns (status, headers-lowercased, body, cut)."""
    return _gf._fetch_binary(url, timeout=timeout, cap=cap,
                             headers=headers, method=method, data=data)


def _follow(url, timeout=30.0, cap=1024 * 1024, headers=None,
            method="GET", data=None, hops=3):
    """GET/POST following redirects like passive._fetch_bytes: max 3
    hops, https targets only after the first hop, urljoin for
    relative Location. Returns (status, headers, body, final_url)."""
    cur, cur_method, cur_data = url, method, data
    for _ in range(hops + 1):
        st, hdrs, body, _cut = _bin(cur, timeout=timeout, cap=cap,
                                    headers=headers, method=cur_method,
                                    data=cur_data)
        if st in (301, 302, 303, 307, 308):
            loc = (hdrs or {}).get("location")
            if not loc:
                return st, hdrs, body, cur
            nxt = urljoin(cur, loc)
            if not nxt.startswith("https://"):
                return st, hdrs, body, cur
            cur = nxt
            if st == 303:
                cur_method, cur_data = "GET", None
            continue
        return st, hdrs, body, cur
    return 0, {}, b"", cur


def _json_body(body, cap_items=None):
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return None


# ---------------------------------------------------------------- geo

# Country centroids: SMALL static table for the §14.1 fallback
# (IP without city -> country-level marker, labeled approximate).
# Coordinates are stable geographic facts, not guesses.
_COUNTRY_CENTROID = {
    "US": (39.8, -98.6), "GB": (54.0, -2.0), "DE": (51.2, 10.4),
    "FR": (46.6, 2.4), "NL": (52.2, 5.3), "JP": (36.2, 138.3),
    "AU": (-25.3, 133.8), "CA": (56.1, -106.4), "BR": (-10.8, -52.9),
    "IN": (20.6, 78.9), "CN": (35.9, 104.2), "RU": (61.5, 105.3),
    "KR": (36.3, 127.9), "SG": (1.35, 103.8), "ID": (-2.5, 118.0),
    "MY": (4.2, 102.0), "TH": (15.9, 101.0), "VN": (14.1, 108.3),
    "PH": (12.9, 121.8), "IT": (42.8, 12.8), "ES": (40.2, -3.7),
    "SE": (60.1, 18.6), "NO": (60.5, 8.5), "FI": (61.9, 25.7),
    "DK": (56.3, 10.4), "PL": (51.9, 19.4), "TR": (39.0, 35.2),
    "ZA": (-30.6, 22.9), "EG": (26.8, 30.8), "NG": (9.1, 8.7),
    "KE": (-0.0, 37.9), "MX": (23.6, -102.5), "AR": (-38.4, -63.6),
    "CL": (-35.7, -71.5), "CO": (4.6, -74.1), "PE": (-9.2, -75.0),
    "UA": (48.4, 31.2), "IL": (31.0, 34.8), "AE": (23.4, 53.8),
    "SA": (25.0, 45.0), "IR": (32.4, 53.7), "IQ": (33.0, 44.4),
    "PK": (30.4, 69.3), "BD": (23.8, 90.4), "TW": (23.7, 120.9),
    "HK": (22.3, 114.2), "NZ": (-41.2, 174.8), "IE": (53.4, -8.2),
    "PT": (39.4, -8.2), "GR": (39.1, 21.8), "CZ": (49.8, 15.5),
    "AT": (47.6, 14.1), "CH": (46.8, 8.2), "BE": (50.5, 4.5),
    "LU": (49.8, 6.1), "HU": (47.2, 19.5), "RO": (45.9, 25.0),
}


def geo_for_ip(ip):
    """City geo via ip-api.com (HTTP-only free tier) with the
    country-centroid fallback. Returns a marker dict or None
    (detail-only row, no invented coordinates)."""
    def _load():
        st, _h, body, _c = _bin(
            "http://ip-api.com/json/%s?fields=status,country,"
            "countryCode,regionName,city,lat,lon,isp,org,as" % quote(ip),
            timeout=15.0, cap=65536)
        if st != 200:
            return {"ok": False, "reason": "geo unavailable"}
        d = _json_body(body) or {}
        if d.get("status") != "success":
            return {"ok": False, "reason": "geo unavailable"}
        lat, lon = d.get("lat"), d.get("lon")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            return {"ok": True, "lat": lat, "lon": lon,
                    "city": d.get("city") or "", "country": d.get("country") or "",
                    "country_code": d.get("countryCode") or "",
                    "level": "city", "isp": d.get("isp") or "",
                    "org": d.get("org") or "", "asn": d.get("as") or ""}
        cc = d.get("countryCode") or ""
        cen = _COUNTRY_CENTROID.get(cc)
        if cen:
            return {"ok": True, "lat": cen[0], "lon": cen[1],
                    "city": "", "country": d.get("country") or "",
                    "country_code": cc, "level": "country-approx",
                    "isp": d.get("isp") or "", "org": d.get("org") or "",
                    "asn": d.get("as") or ""}
        return {"ok": False, "reason": "geo unavailable"}
    out = _cached("geo", ip, 30 * 24 * 3600, _load)
    if not out.get("ok"):
        return None
    return {"lat": out["lat"], "lon": out["lon"], "city": out.get("city", ""),
            "country": out.get("country", ""),
            "country_code": out.get("country_code", ""),
            "level": out.get("level", "city"),
            "isp": out.get("isp", ""), "org": out.get("org", ""),
            "asn": out.get("asn", "")}


# ---------------------------------------------------------------- DNS (DoH)

def _doh(name, rtype):
    """DNS-over-HTTPS: Cloudflare first (needs the Accept header),
    Google fallback. Returns a list of answer strings, or None."""
    for host, path in (
            ("cloudflare-dns.com",
             "/dns-query?name=%s&type=%s" % (quote(name), rtype)),
            ("dns.google",
             "/resolve?name=%s&type=%s" % (quote(name), rtype))):
        try:
            st, body = _get(host, path, timeout=15.0,
                            headers={"Accept": "application/dns-json"})
            if st != 200:
                continue
            d = _json_body(body) or {}
            if d.get("Status") != 0:
                continue
            ans = []
            for a in d.get("Answer") or []:
                if a.get("type") == {"A": 1, "AAAA": 28, "MX": 15,
                                     "NS": 2, "TXT": 16,
                                     "CNAME": 5}.get(rtype):
                    v = str(a.get("data", ""))
                    if rtype == "TXT":
                        v = v.strip('"')
                    ans.append(v)
            return ans
        except Exception:
            continue
    return None


def tool_dns(domain):
    out = {"ok": True, "tool": "dns", "target": domain, "records": {}}
    for rt in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        ans = _doh(domain, rt)
        out["records"][rt] = ans if ans is not None else []
    out["note"] = ("DNS-over-HTTPS (Cloudflare, fallback Google); "
                   "the VM system resolver is synthetic and is never used")
    return out


# ---------------------------------------------------------------- WHOIS (RDAP)

def _rdap_doc(url):
    st, _h, body, _final = _follow(url, timeout=20.0, cap=1024 * 1024)
    if st != 200 or not body:
        return None
    return _json_body(body)


def _vcard_fn(ent):
    try:
        for item in (ent.get("vcardArray") or [None, []])[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                return str(item[3])[:120]
    except Exception:
        pass
    return ""


def tool_whois(target):
    if _is_ip(target):
        d = _rdap_doc("https://rdap.org/ip/%s" % quote(target))
        if not d:
            return {"ok": False, "tool": "whois", "target": target,
                    "reason": "RDAP unavailable"}
        owner = ""
        for ent in d.get("entities") or []:
            roles = ent.get("roles") or []
            if any(r in roles for r in ("registrant", "administrative",
                                        "abuse")):
                owner = _vcard_fn(ent)
                if owner:
                    break
        cidrs = d.get("cidr0_cidrs") or []
        prefix = ""
        if cidrs and isinstance(cidrs[0], dict):
            c0 = cidrs[0]
            if c0.get("v4prefix"):
                prefix = "%s/%s" % (c0["v4prefix"], c0.get("length", ""))
            elif c0.get("v6prefix"):
                prefix = "%s/%s" % (c0["v6prefix"], c0.get("length", ""))
        if not prefix and d.get("startAddress"):
            prefix = "%s - %s" % (d.get("startAddress"),
                                  d.get("endAddress"))
        return {"ok": True, "tool": "whois", "target": target,
                "kind": "ip", "network": str(d.get("name", ""))[:80],
                "owner": owner, "country": str(d.get("country", ""))[:4],
                "prefix": prefix,
                "note": "RDAP (modern WHOIS successor); classic WHOIS "
                        "port 43 is unavailable from this VM"}
    d = _rdap_doc("https://rdap.org/domain/%s" % quote(target))
    if not d:
        return {"ok": False, "tool": "whois", "target": target,
                "reason": "RDAP unavailable"}
    registrar = ""
    for ent in d.get("entities") or []:
        if "registrar" in (ent.get("roles") or []):
            registrar = _vcard_fn(ent)
            if registrar:
                break
    events = {e.get("eventAction"): e.get("eventDate")
              for e in d.get("events") or []}
    return {"ok": True, "tool": "whois", "target": target, "kind": "domain",
            "handle": str(d.get("handle", ""))[:120],
            "registrar": registrar,
            "status": [str(s)[:60] for s in (d.get("status") or [])][:10],
            "events": {k: str(v)[:30] for k, v in events.items()},
            "nameservers": [str(n.get("ldhName", ""))[:120]
                            for n in (d.get("nameservers") or [])][:8],
            "note": "RDAP (modern WHOIS successor); classic WHOIS "
                    "port 43 is unavailable from this VM"}


# ---------------------------------------------------------------- CERTS (crt.sh)

def tool_certs(domain):
    import osint as _osint
    from datetime import datetime, timezone
    def _adapter(url, timeout=20, cap=4 * 1024 * 1024, verify=True):
        st, body = _get("crt.sh", url.split("crt.sh", 1)[1]
                        if "crt.sh" in url else url, timeout=timeout)
        return st, {}, body
    rows, status = _osint._ct_rows(_adapter, domain)
    if not isinstance(rows, list):
        reason = "crt.sh parse error" if rows == "parse_error" \
            else "crt.sh unavailable"
        return {"ok": False, "tool": "certs", "target": domain,
                "reason": reason}
    live_names, _expired_names = _osint._ct_parse_rows(rows)
    issuers = {}
    not_afters = []
    live_rows = 0
    for r in rows:
        na = str(r.get("not_after", ""))
        try:
            parsed = datetime.fromisoformat(na.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            if parsed < datetime.now(timezone.utc):
                continue
        except Exception:
            pass
        live_rows += 1
        iss = str(r.get("issuer_name", ""))[:120]
        if iss:
            issuers[iss] = issuers.get(iss, 0) + 1
        if na:
            not_afters.append(na[:10])
    return {"ok": True, "tool": "certs", "target": domain,
            "certificates": live_rows,
            "live_names": len(live_names),
            "issuers": sorted(issuers.items(), key=lambda kv: -kv[1])[:10],
            "earliest_expiry": min(not_afters) if not_afters else "",
            "latest_expiry": max(not_afters) if not_afters else "",
            "sample_names": sorted(live_names)[:20],
            "note": "Certificate Transparency log (crt.sh) — live "
                    "certificates only; expired-only names excluded"}


# ---------------------------------------------------------------- HEADERS / TECH

def _homepage(domain):
    """Homepage fetch returning (status, headers, body). Redirects
    are NOT followed: the reported headers are the first response's,
    labeled as such."""
    st, hdrs, body, _c = _bin("https://" + domain + "/", timeout=20.0,
                              cap=256 * 1024)
    return st, hdrs, body


def tool_headers(domain):
    import scanners as _sc
    st, hdrs, _body = _homepage(domain)
    if st == 0:
        return {"ok": False, "tool": "headers", "target": domain,
                "reason": "homepage unreachable"}
    present, missing = {}, []
    for name in _sc.SECURITY_HEADERS:
        v = None
        for k, val in (hdrs or {}).items():
            if k.lower() == name.lower():
                v = val
                break
        if v is None:
            missing.append(name)
        else:
            present[name] = str(v)[:120]
    total = len(_sc.SECURITY_HEADERS)
    return {"ok": True, "tool": "headers", "target": domain,
            "http_status": st, "present": present, "missing": missing,
            "score": "%d/%d" % (len(present), total),
            "note": "Headers of the first response (redirects are not "
                    "followed); checks reuse scanners.SECURITY_HEADERS"}


def tool_tech(domain):
    import techdb as _td
    st, hdrs, body = _homepage(domain)
    if st == 0 or not body:
        return {"ok": False, "tool": "tech", "target": domain,
                "reason": "homepage unreachable"}
    text = body.decode("utf-8", "replace")
    srcs = re.findall(r"""src=["']([^"']+\.js[^"']*)["']""", text)[:50]
    # techdb.profile takes headers as a LIST of (name, value)
    # tuples (per its docstring), not a dict.
    dets = _td.profile(list((hdrs or {}).items()), text, script_srcs=srcs)
    return {"ok": True, "tool": "tech", "target": domain,
            "http_status": st,
            "detections": [{"name": d.get("name", ""),
                            "category": d.get("category", ""),
                            "version": d.get("version", ""),
                            "evidence": str(d.get("evidence", ""))[:200],
                            "source": d.get("source", "")}
                           for d in dets][:50],
            "note": "Fingerprint via techdb.profile (same engine path "
                    "as passive recon); versioned entries first"}


# ---------------------------------------------------------------- SSL (daemon tls op)

def tool_ssl(domain):
    out = _gf.tls_audit(domain, 443, timeout=15.0)
    if not out.get("ok"):
        return {"ok": False, "tool": "ssl", "target": domain,
                "reason": out.get("reason", "TLS audit unavailable")}
    cert = out.get("cert") or {}
    return {"ok": True, "tool": "ssl", "target": domain,
            "tls_version": out.get("tls_version", ""),
            "cipher": out.get("cipher", ""),
            "verify_ok": bool(out.get("verify_ok")),
            "verify_error": out.get("verify_error", ""),
            "subject": cert.get("subject", ""),
            "issuer": cert.get("issuer", ""),
            "not_before": cert.get("not_before", ""),
            "not_after": cert.get("not_after", ""),
            "san": cert.get("san", [])[:20],
            "transport": out.get("transport", ""),
            "note": "Certificate via the fetch daemon (proxied TLS); "
                    "in-process TLS from the service is intercepted "
                    "and is never used as evidence"}

# ---------------------------------------------------------------- SUBDOMAINS

def tool_subdomains(domain):
    import osint as _osint
    def _adapter(url, timeout=20, cap=4 * 1024 * 1024, verify=True):
        part = url.split("crt.sh", 1)[1] if "crt.sh" in url else url
        st, body = _get("crt.sh", part, timeout=timeout)
        return st, {}, body
    rows, _status = _osint._ct_rows(_adapter, domain)
    if not isinstance(rows, list):
        return {"ok": False, "tool": "subdomains", "target": domain,
                "reason": "crt.sh unavailable"}
    live_names, _expired_names = _osint._ct_parse_rows(rows)
    subs = sorted(nm for nm in live_names
                  if nm.endswith("." + domain) and nm != domain)
    confirmed, ct_only = [], []
    deadline = time.time() + 55.0

    def _verify(name):
        if time.time() > deadline:
            return (name, None)
        return (name, _doh(name, "A"))

    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(_verify, s): s for s in subs[:200]}
        for fut in as_completed(futs):
            name, ans = fut.result()
            if ans:
                confirmed.append(name)
            elif ans is not None:
                ct_only.append(name)
    return {"ok": True, "tool": "subdomains", "target": domain,
            "confirmed": sorted(confirmed)[:100],
            "ct_only": sorted(ct_only)[:100],
            "total_ct": len(subs),
            "note": "Names from Certificate Transparency; 'confirmed' "
                    "means a DoH A record answered (never the VM "
                    "system resolver); the rest are CT-only"}


# ---------------------------------------------------------------- PORT SCAN

def tool_ports(domain_or_ip):
    import scanners as _sc
    host = domain_or_ip
    if _is_domain(host):
        a = _doh(host, "A")
        if not a:
            return {"ok": False, "tool": "ports", "target": host,
                    "reason": "host does not resolve via DoH"}
    try:
        rows = _sc.tcp_scan_detailed(host, _sc.COMMON_PORTS)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "tool": "ports", "target": host,
                "reason": "scan failed: %s" % str(exc)[:120]}
    opens = [r for r in rows if r.get("state") == "open"]
    intercepted, why, _ex = _sc.detect_interception(opens)
    if intercepted:
        return {"ok": True, "tool": "ports", "target": host,
                "label": "INCONCLUSIVE — VM egress",
                "ports": [],
                "note": "Port scan from this VM is intercepted (%s); "
                        "no port is reported. External ground truth "
                        "is nmap from an outside network." % why}
    return {"ok": True, "tool": "ports", "target": host,
            "label": "INCONCLUSIVE — VM egress",
            "ports": [{"port": r["port"], "service": r.get("service", ""),
                       "state": "open"} for r in opens],
            "note": "INCONCLUSIVE — VM egress: direct TCP from this VM "
                    "is intercepted by the sandbox gateway, so no "
                    "port below is a confirmed finding. External "
                    "ground truth is nmap from an outside network."}


# ---------------------------------------------------------------- VULN SWEEP (passive web layer only)

_VULN_PROBES = ("/.git/HEAD", "/.env", "/.svn/entries",
                "/.well-known/security.txt")
_VULN_LABELS = {"/.git/HEAD": "git metadata exposed",
                "/.env": "environment file exposed",
                "/.svn/entries": "svn metadata exposed",
                "/.well-known/security.txt": "security.txt present"}


def _probe_presence(domain, path):
    """Presence ONLY: HEAD first; on 405, one GET whose body is
    discarded immediately and never stored or returned. Returns
    (http_status, present_bool)."""
    url = "https://" + domain + path
    try:
        st, _h, _b, _c = _bin(url, timeout=15.0, cap=1024,
                              method="HEAD")
    except Exception:
        return 0, False
    if st == 405:
        try:
            st, _h, _b, _c = _bin(url, timeout=15.0, cap=1024,
                                  method="GET")
        except Exception:
            return 0, False
    return st, st == 200


def tool_vulnsweep(domain):
    st, hdrs, body = _homepage(domain)
    if st == 0:
        return {"ok": False, "tool": "vulnsweep", "target": domain,
                "reason": "homepage unreachable"}
    findings = []
    import scanners as _sc
    missing = [n for n in _sc.SECURITY_HEADERS
               if not any(k.lower() == n.lower()
                          for k in (hdrs or {}).keys())]
    if missing:
        findings.append({"tier": "candidate",
                         "title": "security headers missing: "
                                  + ", ".join(missing[:4]),
                         "evidence": "homepage first response"})
    for p in ("/robots.txt", "/sitemap.xml"):
        pst, _present = _probe_presence(domain, p)
        if pst == 200:
            findings.append({"tier": "info",
                             "title": "%s present" % p,
                             "evidence": "HTTP 200"})
    for p in _VULN_PROBES:
        pst, present = _probe_presence(domain, p)
        if pst == 0:
            continue
        if present:
            tier = "probable" if p != "/.well-known/security.txt" \
                else "info"
            findings.append({"tier": tier,
                             "title": _VULN_LABELS[p],
                             "evidence": "HTTP 200 on %s (presence "
                                         "only — body never read)" % p})
    import techdb as _td
    text = (body or b"").decode("utf-8", "replace")
    dets = _td.profile(list((hdrs or {}).items()), text) if body else []
    return {"ok": True, "tool": "vulnsweep", "target": domain,
            "http_status": st, "findings": findings[:50],
            "tech": [d.get("name", "") for d in dets][:20],
            "scope": "passive web-layer subset only — homepage, "
                     "robots/sitemap presence, exposure probes "
                     "(status only, bodies never stored), header "
                     "summary, tech fingerprint. Active payload "
                     "testing stays in New Scan.",
            "note": "Findings are candidate/probable by evidence; "
                    "nothing here is a confirmed exploitation"}


# ---------------------------------------------------------------- USERNAME / PHONE

def tool_username(handle, deadline_s=55.0):
    import osint as _osint
    started = time.time()
    state = {"cancelled": False}

    def _cancelled():
        return state["cancelled"] or (time.time() - started > deadline_s)

    def _adapter(url, timeout=15, cap=4 * 1024 * 1024, verify=True):
        from urllib.parse import urlparse
        p = urlparse(url)
        host, path = p.hostname, p.path
        if p.query:
            path += "?" + p.query
        if not host:
            return 0, {}, b""
        try:
            st, body = _get(host, path, timeout=timeout)
            return st, {}, body
        except Exception:
            return 0, {}, b""

    findings, meta = _osint._username_osint(
        _adapter, handle, lambda m: None, [],
        platforms=None, cancelled=_cancelled)
    rows = []
    for f in findings:
        title = getattr(f, "title", "") or ""
        m = re.match(r"^(?:Username '[^']*' found on "
                     r"|Possible username '[^']*' on )(.+?)"
                     r"(?: \(unverified\))?$", title)
        rows.append({"platform": m.group(1) if m else "",
                     "title": title,
                     "url": getattr(f, "location", "") or "",
                     "verdict": getattr(f, "confidence", "") or ""})
    probable = meta.get("probable", []) or []
    candidate = meta.get("candidate", []) or []
    skipped = meta.get("skipped", []) or []
    return {"ok": True, "tool": "username", "target": handle,
            "findings": rows[:200],
            "probable": probable,
            "candidate": candidate,
            "unevaluated": meta.get("unevaluated", []) or [],
            "skipped": skipped,
            "partial": bool(skipped),
            "note": "Curated USERNAME check (303 platforms, 150 "
                    "active) via the engine path; unevaluated = "
                    "fetch failed, not absence; partial = the 55 s "
                    "panel deadline skipped queued platforms"}


def tool_phone(raw):
    import osint as _osint
    info = _osint.parse_phone(raw)
    if not info:
        return {"ok": False, "tool": "phone", "target": raw,
                "reason": "unparsable phone number"}
    return {"ok": True, "tool": "phone", "target": raw,
            "parsed": info,
            "note": "Structural parse only, local, no network; "
                    "carrier/owner attribution is not claimed"}

# ---------------------------------------------------------------- SHODAN IOT

def tool_shodan(ip):
    def _load():
        st, body = _get("internetdb.shodan.io", "/%s" % quote(ip),
                        timeout=20.0)
        if st != 200:
            return {"ok": False, "reason": "InternetDB unavailable"}
        d = _json_body(body) or {}
        return {"ok": True, "tool": "shodan", "target": ip,
                "ip": d.get("ip", ip),
                "ports": [int(p) for p in (d.get("ports") or [])
                          if isinstance(p, int)][:50],
                "hostnames": [str(h)[:120]
                              for h in (d.get("hostnames") or [])][:20],
                "tags": [str(t)[:60] for t in (d.get("tags") or [])][:20],
                "cpes": [str(c)[:120] for c in (d.get("cpes") or [])][:20],
                "vulns": [str(v)[:60] for v in (d.get("vulns") or [])][:20],
                "note": "Data from Shodan's scans (InternetDB), NOT "
                        "a VANTHEX scan; freshness = Shodan's last "
                        "scan. The keyed Shodan Host API is never "
                        "called."}
    return _cached("shodan", ip, 24 * 3600, _load)


# ---------------------------------------------------------------- MAC ADDR

def tool_mac(mac):
    def _load():
        st, body = _get("api.maclookup.app",
                        "/v2/macs/%s" % quote(mac), timeout=20.0)
        if st != 200:
            return {"ok": False, "reason": "maclookup unavailable"}
        d = _json_body(body) or {}
        if not d.get("found"):
            return {"ok": True, "tool": "mac", "target": mac,
                    "found": False,
                    "note": "No OUI record for this prefix"}
        return {"ok": True, "tool": "mac", "target": mac, "found": True,
                "mac_prefix": d.get("macPrefix", ""),
                "company": d.get("company", ""),
                "address": d.get("address", ""),
                "country": d.get("country", ""),
                "block_start": d.get("blockStart", ""),
                "block_end": d.get("blockEnd", ""),
                "note": "Vendor from the OUI database; MACs can be "
                        "spoofed — vendor is not device identity"}
    return _cached("mac", mac, 30 * 24 * 3600, _load)


# ---------------------------------------------------------------- BGP ROUTE

def tool_bgp(target):
    def _load():
        out = {"ok": True, "tool": "bgp", "target": target}
        geo = geo_for_ip(target) if _is_ip(target) else None
        if geo:
            out["geo"] = geo
        asn = ""
        if geo and geo.get("asn"):
            m = re.search(r"\bAS(\d+)\b", geo["asn"])
            if m:
                asn = m.group(1)
        if not asn and _is_ip(target):
            # ip-api 'as' field is "AS15169 Google LLC" shaped.
            pass
        overview = None
        if asn:
            st, body = _get("stat.ripe.net",
                            "/data/as-overview/data.json?resource=AS%s"
                            % quote(asn), timeout=20.0)
            if st == 200:
                d = _json_body(body) or {}
                overview = d.get("data") or {}
        prefixes = []
        prefix_total = None
        if asn:
            st, body = _get("stat.ripe.net",
                            "/data/announced-prefixes/data.json"
                            "?resource=AS%s" % quote(asn), timeout=20.0)
            if st == 200:
                d = _json_body(body) or {}
                dd = d.get("data") or {}
                prefs = dd.get("prefixes") or []
                prefix_total = len(prefs)
                prefixes = [str(p.get("prefix", ""))[:60]
                            for p in prefs[:50]]
        out["asn"] = ("AS" + asn) if asn else ""
        out["holder"] = ""
        if isinstance(overview, dict):
            out["holder"] = str(overview.get("holder", ""))[:120]
            out["overview"] = {k: str(v)[:200] for k, v in
                               overview.items()
                               if k in ("holder", "type", "announced")}
        out["prefixes"] = prefixes
        out["prefix_total"] = prefix_total
        out["note"] = ("Routing DATA (ip-api + RIPEstat as-overview), "
                       "not a map route drawing: as-overview carries "
                       "no hop coordinates, so no route line is "
                       "drawn. Marker, when present, is the ip-api "
                       "city or a country-centroid fallback labeled "
                       "country-level, approximate.")
        return out
    return _cached("bgp", target, 24 * 3600, _load)


# ---------------------------------------------------------------- THREATS

def _tor_exit_set():
    def _load():
        st, _h, body, cut = _bin(
            "https://check.torproject.org/torbulkexitlist",
            timeout=30.0, cap=1024 * 1024)
        if st != 200 or not body:
            return {"ok": False, "reason": "Tor exit list unavailable"}
        ips = set()
        for line in body.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and _is_ipv4(line):
                ips.add(line)
        return {"ok": True, "ips": ips, "partial": bool(cut),
                "count": len(ips)}
    out = _cached("tor", "bulk", 24 * 3600, _load)
    if not out.get("ok"):
        return None, out.get("reason", "Tor exit list unavailable")
    return out.get("ips") or set(), ("partial" if out.get("partial")
                                     else "")


def tool_threats(target):
    def _load():
        out = {"ok": True, "tool": "threats", "target": target}
        kind = "IPv4" if _is_ipv4(target) else "domain"
        pulse_count, pulses, otx_ok = None, [], False
        try:
            st, body = _get("otx.alienvault.com",
                            "/api/v1/indicators/%s/%s/general"
                            % (kind, quote(target)), timeout=20.0)
            if st == 200:
                d = _json_body(body) or {}
                pi = d.get("pulse_info") or {}
                pulse_count = pi.get("count")
                pulses = [str(p.get("name", ""))[:120]
                          for p in (pi.get("pulses") or [])[:10]]
                out["reputation"] = d.get("reputation")
                out["asn"] = str(d.get("asn", ""))[:80]
                otx_ok = True
        except Exception:
            pass
        if pulse_count is None:
            out["otx"] = "UNKNOWN"
            out["pulse_count"] = None
            out["pulse_bucket"] = "UNKNOWN"
            out["note_otx"] = ("OTX did not answer — UNKNOWN is not "
                               "a clean verdict")
        else:
            out["otx"] = "answered"
            out["pulse_count"] = pulse_count
            out["pulse_bucket"] = ("HIGH" if pulse_count > 5 else
                                   "MEDIUM" if pulse_count > 0 else "LOW")
            out["note_otx"] = ("OTX pulse bucket — community "
                               "reports, NOT a verdict")
        out["pulses"] = pulses
        tor_ips, tor_note = _tor_exit_set()
        if tor_ips is None:
            out["tor_exit"] = None
            out["tor_note"] = "Tor exit list unavailable: %s" % tor_note
        else:
            out["tor_exit"] = target in tor_ips if _is_ip(target) else None
            out["tor_note"] = ("Present in the current Tor exit list "
                               "— NOT evidence of maliciousness")
            if tor_note:
                out["tor_note"] += " (list truncated; membership " \
                    "checked against the partial cache)"
        geo = geo_for_ip(target) if _is_ip(target) else None
        if geo:
            out["geo"] = geo
        out["note"] = ("No 'recent public pulses' strip: OTX "
                       "/pulses/subscribed and /pulses/activity both "
                       "demand authentication (403) at build "
                       "verification, so that strip was dropped; "
                       "indicator lookup + Tor list still run.")
        return out
    return _cached("threats", target, 24 * 3600, _load)


# ---------------------------------------------------------------- DATA LEAKS

def tool_dataleaks(email, optin=False):
    if not optin:
        return {"ok": False, "tool": "dataleaks", "target": email,
                "reason": "opt-in required: pass optin=1 to run a "
                          "breach lookup for this email"}
    def _load():
        st, body = _get("api.xposedornot.com",
                        "/v1/breach-analytics?email=%s" % quote(email),
                        timeout=20.0)
        if st != 200:
            return {"ok": False, "reason": "XposedOrNot unavailable"}
        d = _json_body(body) or {}
        breaches = []
        eb = d.get("ExposedBreaches")
        items = []
        if isinstance(eb, dict):
            items = eb.get("breaches") or eb.get("data") or []
        elif isinstance(eb, list):
            items = eb
        for b in items[:50]:
            if isinstance(b, dict):
                breaches.append({
                    "name": str(b.get("breach") or b.get("name")
                                or "")[:120],
                    "date": str(b.get("breachDate") or b.get("date")
                                or b.get("addedDate") or "")[:30],
                    "data_classes": [str(c)[:60] for c in
                                     (b.get("dataClasses")
                                      or b.get("exposedData")
                                      or b.get("data") or [])][:20]})
            elif isinstance(b, str):
                breaches.append({"name": b[:120], "date": "",
                                 "data_classes": []})
        bm = d.get("BreachMetrics") or {}
        return {"ok": True, "tool": "dataleaks", "target": email,
                "source": "XposedOrNot",
                "breaches": breaches,
                "breach_count": bm.get("breaches_count"),
                "paste_count": (d.get("PasteMetrics") or {}).get(
                    "pastes_count"),
                "note": "Breach presence only — no passwords or "
                        "content shown. BreachDirectory is not a "
                        "source in this build (its build gate "
                        "failed: keyed RapidAPI distribution, no "
                        "verified public access term)."}
    return _cached("dataleaks", email, 24 * 3600, _load)


# ---------------------------------------------------------------- CHAIN INTEL

def _coin_prices():
    def _load():
        st, body = _get("api.coingecko.com",
                        "/api/v3/simple/price?ids=bitcoin,ethereum,"
                        "solana&vs_currencies=usd", timeout=15.0)
        if st != 200:
            return {"ok": False, "reason": "CoinGecko unavailable"}
        d = _json_body(body) or {}
        return {"ok": True, "prices": {
            k: (v or {}).get("usd") for k, v in d.items()}}
    return _cached("coin_price", "simple", 3600, _load)


def _sanctions_flag(address):
    """Address-vs-snapshot flag, candidate label only. Returns a
    dict or None when the snapshot is not evaluated."""
    try:
        import osint as _osint
        state, _date, _reason = _osint._sanctions_load()
        if state != "ok":
            return {"evaluated": False}
        crypto = (_osint._sanctions_cache.get("index") or {}).get(
            "crypto") or {}
        # Membership test, NOT truthiness: snapshot holders are
        # often "" (empty), which is still a match.
        if address in crypto:
            holder = crypto[address]
        elif address.lower() in crypto:
            holder = crypto[address.lower()]
        else:
            return {"evaluated": True, "match": False}
        return {"evaluated": True, "match": True,
                "holder": str(holder)[:120],
                "label": "Snapshot match — NOT an identification"}
    except Exception:
        return {"evaluated": False}


def tool_chain(address):
    import osint as _osint
    info = _osint.wallet_info(address)
    if not info:
        return {"ok": False, "tool": "chain", "target": address,
                "reason": "not a recognized BTC/ETH/SOL wallet address"}
    chain = info["chain"]
    if chain == "SOL":
        return {"ok": True, "tool": "chain", "target": address,
                "chain": "SOL",
                "available": False,
                "reason": "SOL wallet lookup is not available in "
                          "this build: the public Solana RPC "
                          "endpoints did not answer from the service "
                          "network at build verification (both "
                          "official hostnames timed out). BTC/ETH "
                          "lookups are unaffected.",
                "prices": _coin_prices().get("prices", {})}
    def _load():
        out = {"ok": True, "tool": "chain", "target": address,
               "chain": chain}
        if chain == "BTC":
            st, body = _get("mempool.space",
                            "/api/address/%s" % quote(address),
                            timeout=20.0)
            if st != 200:
                return {"ok": False, "reason": "mempool unavailable"}
            d = _json_body(body) or {}
            cs = d.get("chain_stats") or {}
            out["balance_sats"] = cs.get("funded_txo_sum", 0) \
                - cs.get("spent_txo_sum", 0)
            out["tx_count"] = cs.get("tx_count")
            st, body = _get("mempool.space",
                            "/api/address/%s/txs" % quote(address),
                            timeout=20.0)
            txs = []
            if st == 200:
                for t in (_json_body(body) or [])[:50]:
                    if isinstance(t, dict):
                        txs.append({"txid": str(t.get("txid", ""))[:80],
                                    "status": (t.get("status") or {})
                                    .get("confirmed"),
                                    "fee": (t.get("fee"))})
            out["transactions"] = txs
        else:
            st, body = _get("eth.blockscout.com",
                            "/api/v2/addresses/%s" % quote(address),
                            timeout=20.0)
            if st != 200:
                return {"ok": False, "reason": "Blockscout unavailable"}
            d = _json_body(body) or {}
            out["balance_wei"] = (d.get("coin_balance") or "")
            out["tx_count"] = None
            st, body = _get("eth.blockscout.com",
                            "/api/v2/addresses/%s/transactions"
                            % quote(address), timeout=20.0)
            txs = []
            if st == 200:
                dd = _json_body(body) or {}
                for t in (dd.get("items") or [])[:50]:
                    if isinstance(t, dict):
                        txs.append({"hash": str(t.get("hash", ""))[:80],
                                    "timestamp": t.get("timestamp", ""),
                                    "value": t.get("value", ""),
                                    "status": t.get("status", "")})
                out["tx_count"] = len(dd.get("items") or [])
            out["transactions"] = txs
        prices = _coin_prices()
        out["prices"] = prices.get("prices", {}) if prices.get("ok") \
            else {}
        out["sanctions"] = _sanctions_flag(address)
        out["note"] = ("Wallet data from public explorers, verbatim; "
                       "not an attribution verdict. Transaction "
                       "history is capped at 50 rows.")
        return out
    return _cached("chain", address, 3600, _load)


# ---------------------------------------------------------------- DONBOT

def tool_donbot(query):
    def _load():
        st, body = _get("api.coingecko.com",
                        "/api/v3/search?query=%s" % quote(query),
                        timeout=15.0)
        coin_id, symbol, name = None, "", ""
        if st == 200:
            d = _json_body(body) or {}
            coins = d.get("coins") or []
            if coins:
                coin_id = coins[0].get("id")
                symbol = coins[0].get("symbol", "")
                name = coins[0].get("name", "")
        if not coin_id and query.startswith("0x") and len(query) == 42:
            st, body = _get("api.coingecko.com",
                            "/api/v3/coins/ethereum/contract/%s"
                            % quote(query), timeout=15.0)
            if st == 200:
                d = _json_body(body) or {}
                coin_id = d.get("id")
                symbol = d.get("symbol", "")
                name = d.get("name", "")
        if not coin_id:
            return {"ok": False, "reason": "token not found on "
                                           "CoinGecko"}
        st, body = _get("api.coingecko.com",
                        "/api/v3/coins/markets?vs_currency=usd&ids=%s"
                        % quote(coin_id), timeout=15.0)
        if st != 200:
            return {"ok": False, "reason": "CoinGecko markets "
                                           "unavailable"}
        rows = _json_body(body) or []
        if not rows:
            return {"ok": False, "reason": "token not found on "
                                           "CoinGecko"}
        r = rows[0]
        return {"ok": True, "tool": "donbot", "target": query,
                "coin_id": coin_id, "symbol": symbol, "name": name,
                "price_usd": r.get("current_price"),
                "market_cap": r.get("market_cap"),
                "change_24h": r.get("price_change_percentage_24h"),
                "volume_24h": r.get("total_volume"),
                "label": "TOKEN SCAN — CoinGecko market data only; "
                         "no signal score",
                "note": "Digital Don signal scores and holder-cluster "
                        "maps are excluded: scores are black-box "
                        "third-party output and holder-list APIs are "
                        "keyed. This tool never contacts "
                        "digitaldon.net."}
    return _cached("donbot", query, 3600, _load)

# ---------------------------------------------------------------- ARCGIS

_ARCGIS_CHIPS = {
    "PIPELINES": "pipelines",
    "POWER GRID": "power plants substations transmission",
    "INFRASTRUCTURE": "hospitals fire stations",
    "MILITARY": "military installations",
    "EMERGENCY": "evacuation routes",
}
_ARCGIS_HOSTS = ("www.arcgis.com", "services.arcgis.com",
                 "services1.arcgis.com", "services2.arcgis.com",
                 "services3.arcgis.com")


def _arcgis_host_ok(url):
    from urllib.parse import urlparse
    return urlparse(url).hostname in _ARCGIS_HOSTS


def arcgis_scan(keyword, bbox):
    """Two-step daemon-side scan: portal search (public items only)
    -> per-service extent query. Caps: 10 candidates, 5 services,
    200 features total, 8 attribute keys per feature, service
    order. bbox = (xmin, ymin, xmax, ymax) floats, verbatim from
    the globe camera. NOTE on the design text: §14.3 writes
    '<service>/query', but ArcGIS REST requires a layer index —
    the service root /query answers 400 (verified at build), so
    each service is read via its ?f=pjson layer list and queried
    per layer (<service>/<id>/query). Same intent, working path."""
    if not _RE_KEYWORD.match(keyword or ""):
        return {"ok": False, "tool": "arcgis",
                "reason": "invalid keyword (letters, digits, space, "
                          "hyphen, max 100 chars)"}
    try:
        xmin, ymin, xmax, ymax = (float(v) for v in bbox)
        if not (-180.0 <= xmin < xmax <= 180.0
                and -90.0 <= ymin < ymax <= 90.0):
            raise ValueError("bbox out of range")
    except Exception:
        return {"ok": False, "tool": "arcgis",
                "reason": "invalid bbox (need xmin,ymin,xmax,ymax)"}
    geom = "%s,%s,%s,%s" % (xmin, ymin, xmax, ymax)
    st, body = _get("www.arcgis.com",
                    "/sharing/rest/search?q=%s&type=%s&f=pjson&num=10"
                    % (quote(keyword), quote('"Feature Service"')),
                    timeout=30.0)
    if st != 200:
        return {"ok": False, "tool": "arcgis",
                "reason": "catalog offline"}
    doc = _json_body(body) or {}
    candidates = []
    for r in (doc.get("results") or [])[:10]:
        url = r.get("url", "")
        if r.get("access") != "public":
            continue
        if r.get("type") != "Feature Service":
            continue
        if not url or not _arcgis_host_ok(url):
            continue
        candidates.append({"title": str(r.get("title", ""))[:120],
                           "url": url})
    services = []
    total_features = 0
    for cand in candidates[:5]:
        svc = {"title": cand["title"], "url": cand["url"],
               "health": "OFFLINE", "features": [], "layers": []}
        try:
            from urllib.parse import urlparse
            p = urlparse(cand["url"])
            st, sbody = _get(p.hostname, p.path + "?f=pjson",
                             timeout=20.0)
            layers = []
            if st == 200:
                sdoc = _json_body(sbody) or {}
                layers = sdoc.get("layers") or []
            ok_layers, fail_layers = 0, 0
            for layer in layers[:5]:
                if total_features >= 200:
                    break
                lid = layer.get("id")
                if lid is None:
                    continue
                q = ("/%s/query?where=1%%3D1&geometry=%s"
                     "&geometryType=esriGeometryEnvelope&inSR=4326"
                     "&spatialRel=esriSpatialRelIntersects"
                     "&outFields=*&f=geojson&resultRecordCount=%d"
                     "&returnGeometry=true"
                     % (lid, quote(geom, safe=""),
                        200 - total_features))
                st, fbody = _get(p.hostname, p.path + q, timeout=30.0)
                if st != 200:
                    fail_layers += 1
                    continue
                fdoc = _json_body(fbody) or {}
                feats = fdoc.get("features") or []
                ok_layers += 1
                for f in feats:
                    if total_features >= 200:
                        break
                    props = f.get("properties") or {}
                    keys = list(props.keys())[:8]
                    svc["features"].append({
                        "geometry": f.get("geometry"),
                        "properties": {k: props[k] for k in keys},
                        "layer": str(layer.get("name", ""))[:80]})
                    total_features += 1
            svc["layers"] = [str(l.get("name", ""))[:80]
                             for l in layers[:5]]
            if ok_layers and not fail_layers:
                svc["health"] = "ONLINE"
            elif ok_layers:
                svc["health"] = "DEGRADED"
            else:
                svc["health"] = "OFFLINE"
        except Exception:
            svc["health"] = "OFFLINE"
        services.append(svc)
    active = [s for s in services if s["health"] in ("ONLINE", "DEGRADED")]
    return {"ok": True, "tool": "arcgis", "keyword": keyword,
            "bbox": [xmin, ymin, xmax, ymax],
            "services": services,
            "layers_active": len(active),
            "features": total_features,
            "note": "Portal catalog + FeatureServer extent queries, "
                    "public items only; private/token items dropped; "
                    "services outside the declared ArcGIS host "
                    "family dropped; attributes verbatim, trimmed "
                    "to 8 keys per feature"}


# ---------------------------------------------------------------- FINGERPRINT

_FP_LOCK = threading.Lock()
_FP_RUNNING = {"busy": False}
_FP_CONCURRENCY = 18
_FP_SITE_TIMEOUT = 15.0
_FP_SESSION_CAP = 600.0
_FP_BLOCKED = {401, 403, 407, 429, 451, 503}


def _fp_fill(template, username):
    return template.replace("{}", username)


def _fp_control():
    import random
    import string
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(16))


def _fp_load_db():
    cached = _CACHES["sherlock"].get("db")
    if cached is not None:
        return cached
    st, _h, body, _c = _bin(
        "https://raw.githubusercontent.com/sherlock-project/sherlock"
        "/master/sherlock_project/resources/data.json",
        timeout=60.0, cap=8 * 1024 * 1024)
    if st != 200 or not body:
        return None
    doc = _json_body(body)
    if not isinstance(doc, dict):
        return None
    sites = {}
    for name, entry in doc.items():
        if name == "$schema":
            continue
        if not isinstance(entry, dict):
            continue
        if entry.get("isNSFW"):
            continue
        if not entry.get("url") or not entry.get("errorType"):
            continue
        sites[name] = entry
    _CACHES["sherlock"].put("db", sites, 7 * 24 * 3600)
    return sites


def _fp_check(name, entry, username, timeout=15.0):
    """One Sherlock-model site check. Returns a result dict with
    status in found/not_found/blocked/skipped/error."""
    profile_url = _fp_fill(entry["url"], username)
    regex = entry.get("regexCheck")
    if regex:
        try:
            if not re.search(regex, username):
                return {"site": name, "url": profile_url,
                        "status": "skipped",
                        "reason": "username invalid for this site"}
        except re.error:
            pass
    req_url = _fp_fill(entry["urlProbe"], username) \
        if entry.get("urlProbe") else profile_url
    method = str(entry.get("request_method") or "GET").upper()
    data = None
    hdrs = dict(entry.get("headers") or {})
    if method == "POST" and entry.get("request_payload") is not None:
        payload = json.dumps(entry["request_payload"]).replace(
            "{}", username, 1)
        data = payload.encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    try:
        st, rhdrs, body, landed = _follow(
            req_url, timeout=timeout, cap=1024 * 1024, headers=hdrs,
            method=method, data=data)
    except Exception as exc:  # noqa: BLE001
        return {"site": name, "url": profile_url, "status": "error",
                "reason": str(exc)[:120]}
    if st == 0:
        return {"site": name, "url": profile_url, "status": "error",
                "reason": "fetch failed"}
    declared = entry.get("errorCode")
    declared = [declared] if isinstance(declared, int) else (
        declared or [])
    if st in _FP_BLOCKED and st not in declared:
        return {"site": name, "url": profile_url, "status": "blocked",
                "http_status": st,
                "reason": ("rate limited by the site" if st == 429
                           else "refused with HTTP %d" % st)}
    etype = entry.get("errorType")
    if etype == "status_code":
        if st in declared:
            return {"site": name, "url": profile_url,
                    "status": "not_found", "http_status": st}
        found = 200 <= st < 300
        if not found and entry.get("urlProbe") \
                and req_url != profile_url:
            try:
                st2, _h2, _b2, _l2 = _follow(
                    profile_url, timeout=timeout, cap=1024 * 1024,
                    headers=hdrs, method="GET")
                if 200 <= st2 < 300:
                    return {"site": name, "url": profile_url,
                            "status": "found", "http_status": st2}
            except Exception:
                pass
        return {"site": name, "url": profile_url,
                "status": "found" if found else "not_found",
                "http_status": st}
    if etype == "message":
        text = (body or b"").decode("utf-8", "replace")
        markers = entry.get("errorMsg")
        markers = [markers] if isinstance(markers, str) else (
            markers or [])
        missing = any(m in text for m in markers)
        return {"site": name, "url": profile_url,
                "status": "not_found" if missing else "found",
                "http_status": st}
    if etype == "response_url":
        err_url = _fp_fill(entry["errorUrl"], username) \
            if entry.get("errorUrl") else ""
        is_err = bool(err_url) and landed.startswith(err_url)
        found = (not is_err) and 200 <= st < 300
        return {"site": name, "url": profile_url,
                "status": "found" if found else "not_found",
                "http_status": st}
    return {"site": name, "url": profile_url, "status": "error",
            "reason": "unknown errorType %r" % (etype,)}


def fingerprint_stream(username):
    """Yield NDJSON lines (bytes) for one FINGERPRINT run: one line
    per site as it answers (status found/not_found/blocked/skipped/
    error, tier CANDIDATE on found), then calibration lines for
    positives re-tested against TWO random controls (either control
    landing -> inconclusive), then a summary line. Single-flight:
    a second concurrent run yields one busy line and stops."""
    if not _FP_LOCK.acquire(blocking=False):
        yield (json.dumps({"type": "busy",
                           "reason": "a fingerprint run is already "
                                     "in progress"}).encode()
               + b"\n")
        return
    try:
        db = _fp_load_db()
        if db is None:
            yield (json.dumps({"type": "unavailable",
                               "reason": "Sherlock database unreachable "
                                         "and no cache; the tool does "
                                         "not fall back to the curated "
                                         "303 set"}).encode() + b"\n")
            return
        names = sorted(db.keys())
        total = len(names)
        yield (json.dumps({"type": "start", "total": total,
                           "label": "FINGERPRINT — broad heuristic "
                                    "sweep over the Sherlock database "
                                    "(non-NSFW); results are "
                                    "CANDIDATE; higher false-positive "
                                    "rate than the curated USERNAME "
                                    "check"}).encode() + b"\n")
        started = time.time()
        found = []
        counts = {"found": 0, "not_found": 0, "blocked": 0,
                  "skipped": 0, "error": 0}
        stop = {"flag": False}

        def _check_one(site):
            if stop["flag"] or time.time() - started > _FP_SESSION_CAP:
                return {"site": site, "url": _fp_fill(db[site]["url"],
                                                      username),
                        "status": "skipped", "reason": "session cap"}
            return _fp_check(site, db[site], username,
                             timeout=_FP_SITE_TIMEOUT)

        with ThreadPoolExecutor(max_workers=_FP_CONCURRENCY) as ex:
            futs = {ex.submit(_check_one, n): n for n in names}
            try:
                for fut in as_completed(futs):
                    try:
                        r = fut.result()
                    except Exception as exc:  # noqa: BLE001
                        r = {"site": futs[fut], "url": "",
                             "status": "error", "reason": str(exc)[:120]}
                    counts[r["status"]] = counts.get(r["status"], 0) + 1
                    if r["status"] == "found":
                        r = dict(r)
                        r["tier"] = "candidate"
                        found.append(r)
                    yield (json.dumps({"type": "site", **r}).encode()
                           + b"\n")
                    if time.time() - started > _FP_SESSION_CAP:
                        stop["flag"] = True
                        break
            except GeneratorExit:
                stop["flag"] = True
                raise
        # Calibration: positives re-tested against TWO controls.
        inconclusive = set()
        if found and not stop["flag"]:
            controls = [_fp_control(), _fp_control()]
            probes = [(r["site"], c) for r in found for c in controls]
            with ThreadPoolExecutor(
                    max_workers=min(_FP_CONCURRENCY,
                                    len(probes))) as ex:
                futs = {ex.submit(_fp_check, site, db[site], ctrl,
                                  _FP_SITE_TIMEOUT): site
                        for site, ctrl in probes}
                for fut in as_completed(futs):
                    try:
                        r = fut.result()
                    except Exception:
                        continue
                    if r.get("status") == "found":
                        inconclusive.add(futs[fut])
            for site in sorted(inconclusive):
                yield (json.dumps({"type": "calibration", "site": site,
                                   "status": "inconclusive",
                                   "reason": "site also reports a "
                                             "random control username "
                                             "as present (soft 404)"}
                                  ).encode() + b"\n")
        final_found = [r for r in found if r["site"] not in inconclusive]
        yield (json.dumps({"type": "summary", "total": total,
                           "found": len(final_found),
                           "inconclusive": len(inconclusive),
                           "counts": counts,
                           "note": "All FINGERPRINT hits are "
                                   "CANDIDATE, never confirmed"}).encode()
               + b"\n")
    finally:
        _FP_LOCK.release()


# ---------------------------------------------------------------- dispatcher

def run_tool(tool, target, extra=None):
    """Route-level entry: allowlist + local validation, then the
    tool. extra carries optin (dataleaks), bbox/keyword (arcgis).
    Returns a plain dict (fingerprint handled by its own route)."""
    extra = extra or {}
    if tool not in TOOLS:
        return {"ok": False, "tool": tool, "reason": "unknown tool"}
    if tool == "arcgis":
        return arcgis_scan(extra.get("keyword", ""),
                           extra.get("bbox", []))
    if tool == "fingerprint":
        return {"ok": False, "tool": "fingerprint",
                "reason": "use the streaming route"}
    norm = _validate(tool, target)
    if norm is None:
        return {"ok": False, "tool": tool, "target": target,
                "reason": "invalid target for %s" % tool}
    fn = None
    if tool == "dataleaks":
        out = tool_dataleaks(norm, optin=bool(extra.get("optin")))
    else:
        fn = {"dns": tool_dns, "whois": tool_whois, "certs": tool_certs,
              "ssl": tool_ssl, "subdomains": tool_subdomains,
              "headers": tool_headers, "tech": tool_tech,
              "ports": tool_ports, "vulnsweep": tool_vulnsweep,
              "username": tool_username, "phone": tool_phone,
              "shodan": tool_shodan, "mac": tool_mac, "bgp": tool_bgp,
              "threats": tool_threats, "chain": tool_chain,
              "donbot": tool_donbot}[tool]
        out = fn(norm)
    out.setdefault("tool", tool)
    out.setdefault("target", norm)
    # Geo marker for IP-typed tools (same click-card pattern as
    # globe layers; detail-only when no coordinates exist).
    if tool in ("shodan", "bgp", "threats") and _is_ip(norm):
        marker = out.get("geo") or geo_for_ip(norm)
        if marker:
            out["marker"] = marker
    return out
