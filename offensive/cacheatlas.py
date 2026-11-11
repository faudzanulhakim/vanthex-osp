"""
CacheAtlas v1 — web-cache deception & poisoning atlas for VANTHEX.
AUTHORIZED TESTING ONLY.

The deeper cache atlas (protocolattacks.c_proto_cache_poisoning covers the
basic XFH reflection; this module maps the cache itself):

- CDN_QUIRKS_DB          : inline knowledge table (varnish, akamai, cloudfront,
                           fastly, cloudflare, nginx proxy_cache, squid) —
                           cached header names, path-normalization bugs,
                           cache-key elements, purge mechanisms.
- deception_probe        : web cache deception — cacheable-extension tricks
                           (.css suffix, ;.js, %2e%2e.css) applied to a
                           cookie-carrying URL, then replayed session-less.
                           CONFIRMED only when the SESSION-LESS request is
                           served from cache with the SAME authenticated body
                           shape (fp-guard: the plain unauthenticated path must
                           look different); otherwise a candidate with cache
                           evidence only.
- normalization_probe    : semicolon / double-slash / dot-segment /
                           encoded-slash path variants vs the plain path.
                           Differential probable only when reproduced 2x.
- key_element_fingerprint: vary Accept-Encoding / User-Agent /
                           X-Forwarded-Proto / Cookie pairs over cache-busted
                           requests and report which elements change the
                           cached body (a cache-key map).
- c_cache_atlas(ctx, add): the registered check. Gated by PTK_CACHEATLAS=1
                           (or opts['cacheatlas']). Max 5 endpoints, max 40
                           requests TOTAL (shared budget, enforced in the
                           fetcher wrapper); every loop honours
                           ctx.cancelled().

Honesty rules (same discipline as protocolattacks/authattack):
- CONFIRMED requires the cache-served differential (session-less cache hit
  returning the authenticated body shape, with the unauthenticated baseline
  shape different — that differential IS the fp-guard).
- Weak signals are "probable"/"candidate" with verification /
  verification_note labels explaining exactly what was and was not proven.
- Bounded request counts everywhere.
"""
import os as _os
import urllib.parse as _up

# ---- hard limits (no flooding) --------------------------------------------
MAX_ATLAS_ENDPOINTS = 5          # endpoints probed per scan
ATLAS_REQUEST_BUDGET = 40        # total requests per c_cache_atlas scan
DECEPTION_TRICKS = (".css", ";.js", "%2e%2e.css")
NORMALIZATION_VARIANTS = ("semicolon", "semicolon-ext", "double-slash",
                          "dot-segment", "encoded-slash")
_KEY_ELEMENTS = ("Accept-Encoding", "User-Agent", "X-Forwarded-Proto",
                 "Cookie")
_RAW_TIMEOUT = 6.0


# ============================================================ CDN_QUIRKS_DB
# Inline knowledge table: per-CDN cache behaviour. Values are documentation
# (consumed as evidence context / remediation hints, not as fuzz input).

CDN_QUIRKS_DB = {
    "varnish": {
        "cached_header_names": ["X-Varnish", "Age", "X-Cache-Hits"],
        "path_normalization_bugs": [
            "double slashes collapsed before lookup",
            "matreshka path confusion: /a/../../b normalised to /b for the "
            "hash while the origin sees the raw path",
        ],
        "cache_key_elements": ["host", "url", "selected vcl-req variables"],
        "purge_mechanisms": ["ban expression (vcl)", "xkey/softpurge module",
                             "purge ACL request"],
    },
    "akamai": {
        "cached_header_names": ["X-Cache", "X-Cache-Key", "X-Check-Cacheable"],
        "path_normalization_bugs": [
            "cache key retains one variant of // sequences depending on "
            "the SureRoute/origin config",
            "query-parameter ordering is normalised but not dropped by "
            "default",
        ],
        "cache_key_elements": ["host (arbitrary cache-id header optional)",
                               "url incl. query", "edge key variables"],
        "purge_mechanisms": ["Fast Purge API (CCU v3)", "invalidate-by-URL",
                             "invalidate-by-cache-tag"],
    },
    "cloudfront": {
        "cached_header_names": ["X-Cache", "Via", "Age", "X-Amz-Cf-Pop"],
        "path_normalization_bugs": [
            "origin request policy can forward raw path while the key uses "
            "the normalised one",
            "semicolon path parameters preserved in the cache key",
        ],
        "cache_key_elements": ["host (alternate domain name)", "url",
                               "query keys/whitelist", "selected headers",
                               "cookies: none/all/whitelist"],
        "purge_mechanisms": ["invalidation API (path glob)",
                             "versioned deployments"],
    },
    "fastly": {
        "cached_header_names": ["X-Served-By", "X-Cache", "X-Cache-Hits",
                                "Age"],
        "path_normalization_bugs": [
            "VCL stores the raw req.url; normalisation only if configured",
            "double slashes and dot segments are NOT collapsed by default",
        ],
        "cache_key_elements": ["host", "req.url (raw)", "VCL hash keys"],
        "purge_mechanisms": ["purge by URL", "surrogate-key purge",
                             "instant purge API"],
    },
    "cloudflare": {
        "cached_header_names": ["CF-Cache-Status", "Age", "CF-Ray"],
        "path_normalization_bugs": [
            "// sequences collapsed; /../ and /./ resolved",
            "%2f decoded during normalisation in some zones",
        ],
        "cache_key_elements": ["host", "normalized url", "query (all/none/"
                               "whitelist)"],
        "purge_mechanisms": ["purge by URL", "purge by hostname",
                             "purge by tag/prefix (enterprise)",
                             "purge everything"],
    },
    "nginx proxy_cache": {
        "cached_header_names": ["X-Cache-Status", "X-Proxy-Cache"],
        "path_normalization_bugs": [
            "merge_slashes on by default (// collapsed) but the proxy_pass "
            "URI may keep the raw form",
            "location matching happens on the normalized path; the cache "
            "key can be built from $request_uri (raw)",
        ],
        "cache_key_elements": ["$scheme$proxy_host$request_uri (default "
                               "proxy_cache_key)", "custom key zones"],
        "purge_mechanisms": ["cache purge module (third-party)",
                             "restart / cache-manager deletion"],
    },
    "squid": {
        "cached_header_names": ["X-Cache", "X-Squid-Error", "Via", "Age"],
        "path_normalization_bugs": [
            "store key uses the raw URI; internal redirects (accel mode) "
            "may hash a different form than the origin received",
        ],
        "cache_key_elements": ["method", "host", "port", "uri path+query"],
        "purge_mechanisms": ["PURGE HTTP method (restricted ACL)",
                             "cache manager (cachemgr)"],
    },
}


# ============================================================ helpers

def _cache_hint(resp):
    """Human-readable cache evidence from a response dict (status, headers,
    body). Empty string when nothing cache-related is visible."""
    hdrs = {}
    for k, v in (resp.get("headers") or []):
        hdrs.setdefault(k.lower(), v)
    for h in ("x-cache", "age", "cf-cache-status", "x-varnish",
              "x-cache-hits", "x-served-by", "x-cache-status"):
        if h in hdrs:
            return f"{h}: {hdrs[h]}"
    cc = hdrs.get("cache-control", "")
    if cc and "no-store" not in cc.lower():
        return f"cache-control: {cc}"
    return ""


def _norm_shape(body):
    """Whitespace-collapsed body shape used for the same-shape comparison."""
    return " ".join((body or "").split())


def _same_shape(a, b):
    return _norm_shape(a) == _norm_shape(b) and _norm_shape(a) != ""


def _header_dict(headers):
    out = {}
    for k, v in (headers or []):
        out.setdefault(k.lower(), v)
    return out


# ============================================================ 1. deception

def deception_probe(fetcher, url):
    """Web cache deception probe against one authenticated URL.

    fetcher(path, headers=None) -> {"status", "headers": [(k, v)], "body"}.
    Cookie-carrying requests pass headers={"Cookie": "..."}; session-less
    requests pass no Cookie header at all.

    For each cacheable-extension trick (url + '.css', url + ';.js',
    url + '%2e%2e.css'):
      1. fp-guard baseline: plain url, NO cookie (the unauthenticated shape).
      2. cookie-carrying request to the tricked path (lets the cache store
         the authenticated body under a cacheable key).
      3. session-less replay of the tricked path.

    CONFIRMED only when the session-less replay is served with cache
    evidence AND has the SAME body shape as the cookie-carrying response
    AND that shape differs from the plain unauthenticated baseline (the
    differential is the false-positive guard). Otherwise: candidate when
    cache evidence was observed; else no finding.
    Returns a list of per-trick result dicts (max 3 tricks x 3 requests).
    """
    results = []
    if not url.startswith("/"):
        url = "/" + url
    for trick in DECEPTION_TRICKS:
        tricked = url + trick
        base = fetcher(url) or {}
        base_status = base.get("status") or 0
        if base_status in (0, 404, 410):
            continue  # endpoint unreachable — nothing to compare
        auth = fetcher(tricked, headers={"Cookie": "ptk=1; session=probe"}) \
            or {}
        auth_status = auth.get("status") or 0
        if auth_status in (0, 404, 410):
            continue
        sess = fetcher(tricked) or {}
        sess_status = sess.get("status") or 0
        sess_hint = _cache_hint(sess)
        auth_hint = _cache_hint(auth)
        same_as_auth = _same_shape(sess.get("body"), auth.get("body"))
        differs_from_base = not _same_shape(sess.get("body"), base.get("body"))
        r = {
            "trick": trick,
            "path": tricked,
            "baseline_status": base_status,
            "cookie_status": auth_status,
            "sessionless_status": sess_status,
            "cache_evidence": sess_hint or auth_hint,
            "same_shape_as_authenticated": same_as_auth,
            "differs_from_unauthenticated": differs_from_base,
            "confidence": "none",
            "verification": "",
            "verification_note": "",
        }
        if (sess_status == 200 and same_as_auth and differs_from_base
                and sess_hint):
            r["confidence"] = "confirmed"
            r["verification"] = "cache-served-authenticated-body"
            r["verification_note"] = (
                "Confirmed by differential: cookie-carrying request cached "
                "the authenticated body under the cacheable tricked path; a "
                "session-less replay was served from cache with the SAME "
                "authenticated body shape, while the plain unauthenticated "
                "path returns a different shape. Requests: 3 (baseline + "
                "cookie + session-less replay).")
        elif same_as_auth and differs_from_base:
            r["confidence"] = "candidate"
            r["verification"] = "body-shape-match-no-cache-proof"
            r["verification_note"] = (
                "Session-less response matches the authenticated body shape "
                "and differs from the unauthenticated baseline, but cache "
                "delivery was not proven (no cache headers on the replay) — "
                "may be origin-side misrouting.")
        elif sess_hint:
            r["confidence"] = "candidate"
            r["verification"] = "cache-evidence-only"
            r["verification_note"] = (
                "Cache infrastructure observed (" + (sess_hint or "") +
                ") on the tricked path, but the session-less response did "
                "NOT match the authenticated body shape — the trick did not "
                "store the authenticated payload in the shared cache.")
        results.append(r)
    return results


# ============================================================ 2. normalization

def _norm_variant_paths(url):
    """Variant path list (name, path) for the normalization differential."""
    base = url.rstrip("/") if url != "/" else "/"
    name = base.lstrip("/") or ""
    parent = "/" if "/" not in base[1:] else base[:base.rindex("/")] or "/"
    return [
        ("semicolon", url + ";"),
        ("semicolon-ext", url + ";.js"),
        ("double-slash", "//" + name),
        ("dot-segment", parent.rstrip("/") + "/x/../" + name),
        ("encoded-slash", "/x%2f..%2f" + _up.quote(name, safe="/")),
    ]


def normalization_probe(fetcher, url):
    """Path-normalization differential: semicolon / double-slash /
    dot-segment / encoded-slash variants vs the plain path.

    A variant is a DIFFERENTIAL when its body differs from the plain path
    body. fp-guard: the plain path is requested twice first and must be
    stable; an unstable baseline disqualifies all differentials.
    Probable only when the differential REPRODUCES on two requests of the
    same variant; a one-off difference is a candidate.
    Requests: 2 (baseline) + up to 10 (5 variants x 2)."""
    if not url.startswith("/"):
        url = "/" + url
    p1 = fetcher(url) or {}
    p2 = fetcher(url) or {}
    base_body = p1.get("body") or ""
    base_status = p1.get("status") or 0
    plain_stable = (base_status not in (0, 404, 410)
                    and _same_shape(base_body, p2.get("body")))
    results = []
    for name, path in _norm_variant_paths(url):
        r1 = fetcher(path) or {}
        r2 = fetcher(path) or {}
        d1 = (r1.get("body") or "") != base_body and (
            r1.get("status") or 0) == base_status
        d2 = (r2.get("body") or "") != base_body and (
            r2.get("status") or 0) == base_status
        if d1 and d2:
            conf, ver = "probable", "differential-reproduced-2x"
        elif d1 or d2:
            conf, ver = "candidate", "differential-once"
        else:
            conf, ver = "none", ""
        results.append({
            "variant": name,
            "path": path,
            "differs": bool(d1 or d2),
            "reproduced": bool(d1 and d2),
            "confidence": conf,
            "verification": ver,
        })
    conf_order = {"probable": 3, "candidate": 2, "none": 0}
    top = max((r["confidence"] for r in results),
              key=lambda c: conf_order[c]) if results else "none"
    return {
        "url": url,
        "plain_stable": plain_stable,
        "baseline_status": base_status,
        "results": results,
        "confidence": top if (plain_stable and top != "none") else "none",
        "verification": next((r["verification"] for r in results
                              if r["confidence"] == top and top != "none"),
                             ""),
    }


# ============================================================ 3. cache-key map

def key_element_fingerprint(fetcher, url):
    """Cache-key element map: vary each key-element candidate in PAIRS over
    cache-busted (unique query param) requests and report which values
    change the cached body.

    Requests: 2 per element (4 elements) = 8, each with a distinct cache-bust
    query so the pair comparison reflects element sensitivity, not reuse.
    """
    if not url.startswith("/"):
        url = "/" + url
    pairs = {
        "Accept-Encoding": ("gzip", "identity"),
        "User-Agent": ("ptk-probe-a/1.0", "ptk-probe-b/1.0"),
        "X-Forwarded-Proto": ("http", "https"),
        "Cookie": ("ptkfpa=1", ""),
    }
    elements = {}
    n = 0
    for element, (va, vb) in pairs.items():
        if element == "Cookie":
            ha = {"Cookie": va}
            hb = {}
        else:
            ha = {element: va}
            hb = {element: vb}
        nonce = _os.urandom(6).hex()
        ra = fetcher(f"{url}?ptkcb{nonce}={element.lower()}a", headers=ha) or {}
        rb = fetcher(f"{url}?ptkcb{nonce}={element.lower()}b", headers=hb) or {}
        n += 2
        elements[element] = (ra.get("body") or "") != (rb.get("body") or "")
    return {
        "url": url,
        "elements": elements,
        "requests": n,
        "cache_busted": True,
        "note": "True = changing this element changes the cached body "
                "(element is in the cache key or varies the response).",
    }


# ============================================================ 4. raw fetcher

def _raw_get(host, port, path, headers=None):
    """One bounded GET via protocolattacks' raw client (reused, not
    duplicated). Returns {"status", "headers", "body", "err"}."""
    try:
        from offensive.protocolattacks import _raw_request
    except Exception as e:  # pragma: no cover
        return {"status": 0, "headers": [], "body": "", "err": str(e)}
    lines = [f"GET {path} HTTP/1.1", f"Host: {host}", "Connection: close"]
    for k, v in (headers or {}).items():
        if v:
            lines.append(f"{k}: {v}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return _raw_request(host, port, raw, timeout=_RAW_TIMEOUT)


def _atlas_fetcher(host, port, budget):
    """Build the c_cache_atlas fetcher: raw GET with a SHARED request budget
    (max 40 per scan). When the budget is exhausted the fetcher returns an
    empty/err result that all probes treat as 'unusable' and stop."""
    def fetcher(path, headers=None):
        if budget["used"] >= ATLAS_REQUEST_BUDGET:
            return {"status": 0, "headers": [], "body": "",
                    "err": "atlas request budget exhausted"}
        budget["used"] += 1
        return _raw_get(host, port, path, headers)
    return fetcher


def _atlas_endpoints(ctx, limit=MAX_ATLAS_ENDPOINTS):
    eps = list(ctx.opts.get("cacheatlas_endpoints") or [])
    if eps:
        return [e if e.startswith("/") else "/" + e for e in eps[:limit]]
    try:
        surf = ctx.surface(full=True)
        urls = list(getattr(surf, "param_urls", None) or []) or ["/"]
    except Exception:
        urls = ["/"]
    out = []
    for u in urls:
        base = u.split("?")[0]
        if base not in out:
            out.append(base)
        if len(out) >= limit:
            break
    return out or ["/"]


def _F(ctx, sev, title, desc, **kw):
    """Finding factory on vulnscan2.F, origin=cacheatlas."""
    import vulnscan2 as _v
    kw.setdefault("origin", "cacheatlas")
    return _v.F(sev, title, desc, **kw)


def _atlas_gated(ctx):
    return bool(_os.environ.get("PTK_CACHEATLAS") == "1"
                or ctx.opts.get("cacheatlas"))


# ============================================================ 5. the check

def c_cache_atlas(ctx, add):
    """Web-cache deception & poisoning atlas (gated: PTK_CACHEATLAS=1 or
    opts['cacheatlas']).

    Per endpoint (max 5, shared budget max 40 requests):
    - deception_probe  : cacheable-extension tricks, cookie-carrying vs
                         session-less. CONFIRMED only on the cache-served
                         authenticated-body differential.
    - normalization_probe: semicolon/double-slash/dot-segment/encoded-slash
                         differential; probable only when reproduced 2x.
    - key_element_fingerprint: cache-key map (logged, used as evidence
                         context for the deception finding).
    Budget is honoured between phases so later phases degrade gracefully
    instead of overrunning; ctx.cancelled() is checked between everything.
    """
    if ctx.cancelled():
        return
    if not _atlas_gated(ctx):
        ctx.L("  [cacheatlas] check gated off (PTK_CACHEATLAS not set)")
        return
    host, port = ctx.client.host, ctx.client.port
    cookie = (ctx.opts.get("cacheatlas_cookie")
              or (getattr(ctx.client, "extra_headers", {}) or {})
              .get("Cookie") or "")
    budget = {"used": 0}
    fetcher = _atlas_fetcher(host, port, budget)
    eps = _atlas_endpoints(ctx)
    ctx.L(f"  [cacheatlas] probing {len(eps)} endpoint(s), budget "
          f"{ATLAS_REQUEST_BUDGET} requests")
    for ep in eps:
        if ctx.cancelled():
            return
        if budget["used"] >= ATLAS_REQUEST_BUDGET - 6:
            ctx.L("  [cacheatlas] request budget exhausted — stopping")
            return
        # ---- phase 1: cache deception -------------------------------
        dres = deception_probe(fetcher, ep)
        fingerprinted = False
        for r in dres:
            if r["confidence"] == "confirmed":
                if fingerprinted:
                    keymap = "n/a (see first confirmed trick)"
                else:
                    kp = key_element_fingerprint(fetcher, ep)
                    keymap = ", ".join(f"{k}={'key' if v else 'ignored'}"
                                       for k, v in kp["elements"].items())
                    fingerprinted = True
                add(_F(ctx, "HIGH",
                       "Web Cache Deception (authenticated body served "
                       "session-less from cache)",
                       "A cacheable-extension trick (" + r["path"] + ") made "
                       "the cache store the authenticated response under a "
                       "publicly cacheable key. A session-less replay of the "
                       "same path was served from cache with the SAME "
                       "authenticated body shape, while the plain "
                       "unauthenticated path returns a different shape. An "
                       "attacker can exfiltrate a victim's private page "
                       "simply by making their browser request this URL.",
                       evidence=f"endpoint {ep}: trick {r['trick']} "
                                f"({r['path']}); session-less replay cache "
                                f"evidence: {r['cache_evidence']}; body shape "
                                f"matches the cookie-carrying response and "
                                f"differs from the unauthenticated baseline; "
                                f"cache-key map: {keymap}",
                       cwe="CWE-525", owasp="A05:2021", cvss=7.5,
                       remed="Do not cache responses carrying Set-Cookie or "
                             "session credentials; key the cache on the "
                             "Cookie header for authenticated paths; reject "
                             "unknown path extensions instead of normalising "
                             "them away.",
                       confidence="confirmed", location=r["path"],
                       verification=r["verification"],
                       verification_note=r["verification_note"]))
            elif r["confidence"] == "candidate":
                add(_F(ctx, "LOW",
                       "Web Cache Deception candidate (cache evidence, no "
                       "cache-served authenticated body)",
                       "Cache infrastructure was observed on a "
                       "cacheable-extension trick path, but the session-less "
                       "response did not prove that the authenticated body "
                       "was stored in the shared cache. Needs manual "
                       "confirmation with a real session.",
                       evidence=f"endpoint {ep}: trick {r['trick']} "
                                f"({r['path']}); cache evidence: "
                                f"{r['cache_evidence']}",
                       cwe="CWE-525", owasp="A05:2021", cvss=3.9,
                       remed="Verify manually: replay the tricked path from "
                             "a clean browser session and compare bodies.",
                       confidence="candidate", location=r["path"],
                       verification=r["verification"],
                       verification_note=r["verification_note"]))
        # ---- phase 2: path normalization ----------------------------
        if ctx.cancelled():
            return
        if budget["used"] >= ATLAS_REQUEST_BUDGET - 10:
            ctx.L(f"  [cacheatlas] {ep}: skipping normalization probe "
                  f"(budget)")
        else:
            nres = normalization_probe(fetcher, ep)
            if nres["confidence"] in ("probable", "candidate"):
                strong = [r for r in nres["results"]
                          if r["confidence"] == nres["confidence"]]
                det = "; ".join(f"{r['variant']} ({r['path']})"
                                for r in strong)
                conf = nres["confidence"]
                add(_F(ctx, "MEDIUM" if conf == "probable" else "LOW",
                       "Path Normalization Differential (cache/origin "
                       "routing confusion)",
                       "Path variants (" + det + ") return a DIFFERENT body "
                       "than the plain path while resolving to the same "
                       "resource family. When a cache or proxy normalises "
                       "one of these forms differently than the origin, the "
                       "authority/routing decision can be bypassed (path "
                       "confusion, ACL bypass via crafted segments).",
                       evidence=f"endpoint {ep}: plain path stable="
                                f"{nres['plain_stable']}; variants: {det}",
                       cwe="CWE-436", owasp="A01:2021",
                       cvss=6.0 if conf == "probable" else 3.9,
                       remed="Normalise (decode, collapse //, resolve . and "
                             ".., strip path parameters) ONCE before both "
                             "the routing/ACL decision and the cache-key "
                             "computation; reject requests whose normalized "
                             "path differs from the raw path.",
                       confidence=conf, location=ep,
                       verification=nres["verification"],
                       verification_note=(
                           "Differential vs the plain path; probable only "
                           "because the different body reproduced on two "
                           "requests of the same variant. Manual review of "
                           "the variant body recommended."
                           if conf == "probable" else
                           "Weak signal: the differential appeared once and "
                           "did not reproduce — could be transient.")))
        # ---- phase 3: cache-key map (evidence context, logged) -------
        if ctx.cancelled():
            return
        if budget["used"] >= ATLAS_REQUEST_BUDGET - 8:
            ctx.L(f"  [cacheatlas] {ep}: skipping cache-key fingerprint "
                  f"(budget)")
        else:
            kp = key_element_fingerprint(fetcher, ep)
            varying = [k for k, v in kp["elements"].items() if v]
            ctx.L(f"  [cacheatlas] {ep}: cache-key map — varying elements: "
                  f"{varying or 'none observed'} ({kp['requests']} requests)")
    ctx.L(f"  [cacheatlas] done: {budget['used']} requests used")


CHECKS = [c_cache_atlas]
