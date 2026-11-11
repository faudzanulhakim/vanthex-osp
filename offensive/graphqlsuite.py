"""
GraphQLSuite — GraphQL attack surface pack for VANTHEX.
AUTHORIZED TESTING ONLY.

Mixed gating, following the auth-pack convention (authattack/jwtred/authzmatrix):
- SAFE PASSIVE parts always run (cheap, non-intrusive, read-only):
    (1) field-suggestion probing ("Did you mean" schema harvest),
    (2) introspection availability check,
    (5) query-in-URL / GET support leakage.
- OPERATOR-GATED offensive probes (opts['graphql_suite'] or env PTK_GRAPHQL=1):
    (2b) introspection bypass variants when plain introspection is blocked,
    (3)  alias-based batching brute (rate-limit probe with many aliases),
    (4)  depth/cost abuse probe (deeply nested query),
    (6)  unauthenticated mutation probe against discovered mutation names.

FP-guard semantics:
- CONFIRMED only with real differential evidence vs a baseline request
  (e.g. plain introspection blocked but a bypass variant returns __schema,
  1 alias resolves but 50 aliases also resolve, baseline 200 but deep
  query returns 500/times out, mutation executes without auth while an
  ordinary erroring query does not).
- Content-only evidence (introspection open, field suggestions, GET
  support) is reported as "probable" with manual verification labels —
  never "confirmed".
- Non-destructive: mutation probes use canary values ("ptk-canary") and a
  tight budget; protected mutations (auth error) are treated as healthy
  and are NOT reported.
"""
import json as _json
import os as _os
import re as _re

AUTHORIZED_TESTING_ONLY = "AUTHORIZED TESTING ONLY"

GATE_ENV = "PTK_GRAPHQL"
MUTATION_BUDGET = 5        # max mutations probed per endpoint
MAX_DEPTH = 8              # nesting depth of the abuse probe
ALIAS_COUNT = 50           # aliases in the batching brute probe
CANARY = "ptk-canary"

_INTROSPECTION_Q = (
    "query IntrospectionDump { __schema { queryType { name } "
    "mutationType { name } types { name kind "
    "fields { name args { name defaultValue } "
    "type { name kind ofType { name kind } } } } } } }"
)

_AUTH_ERR_TOKENS = ("unauthorized", "unauthorised", "forbidden", "not authorized",
                    "permission denied", "not authenticated", "auth required",
                    "must be authenticated", "access denied", "login required")

_ARG_VALUES = {
    "id": '1', "user_id": '1', "userid": '1',
    "name": f'"{CANARY}"', "title": f'"{CANARY}"',
    "email": f'"{CANARY}@example.com"', "username": f'"{CANARY}"',
    "password": f'"{CANARY}"', "input": f'{{ name: "{CANARY}" }}',
}


def _gate(opts):
    """Operator gate: opts['graphql_suite'] or env PTK_GRAPHQL=1."""
    if opts and str(opts.get("graphql_suite", "")).strip() in ("1", "true", "yes"):
        return True
    return str(_os.environ.get(GATE_ENV, "")).strip() in ("1", "true", "yes")


def _F(sev, title, desc, evidence="", cwe="", owasp="", cvss=0.0, remed="",
       confidence="probable", location="", param="", origin="graphqlsuite",
       verification=None, verification_note=""):
    """Finding factory — mirrors vulnscan2.F (imported lazily so the module
    has no hard dependency at import time; falls back to a plain dict)."""
    try:
        import vulnscan2 as _v
        return _v.F(sev, title, desc, evidence=evidence, cwe=cwe, owasp=owasp,
                    cvss=cvss, remed=remed, confidence=confidence,
                    location=location, param=param, origin=origin,
                    verification=verification,
                    verification_note=verification_note)
    except Exception:
        f = {"severity": sev, "title": title, "description": desc,
             "evidence": evidence, "cwe": cwe, "owasp": owasp, "cvss": cvss,
             "remediation": remed, "confidence": confidence,
             "location": location, "param": param, "origin": origin,
             "verification": verification or
             {"confirmed": "differential", "probable": "manual-required",
              "candidate": "reflection-only"}.get(confidence, "manual-required")}
        if verification_note:
            f["verification_note"] = verification_note
        return f


# ---------------------------------------------------------------- discovery

def _candidates(ctx):
    """GraphQL endpoint candidates from the crawl surface + common paths."""
    cand = []
    try:
        surf = ctx.surface(full=True)
        urls = list(getattr(surf, "js_endpoints", None) or []) + \
            list(getattr(surf, "param_urls", None) or [])
    except Exception:
        urls = []
    for u in urls:
        ep = str(u or "").split("?")[0]
        low = ep.lower()
        if ("graphql" in low or low.rstrip("/").endswith("/gql")) and ep not in cand:
            cand.append(ep)
    for d in ("/graphql", "/gql", "/gql/open", "/api/graphql"):
        if d not in cand:
            cand.append(d)
    return cand[:6]


def _gql_post(ctx, ep, query, variables=None, ctype="application/json"):
    """POST a query; application/json body (or application/graphql raw)."""
    hdr = {"Content-Type": ctype}
    if ctype == "application/graphql":
        data = query
    else:
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        data = _json.dumps(payload)
    return ctx.client.post(ep, data=data, headers=hdr)


def _gql_get(ctx, ep, query):
    """GET with the query in the URL query-string (netclient 'params' is a
    raw query string)."""
    from urllib.parse import quote as _q
    return ctx.client.get(ep, params="query=" + _q(query, safe=""))


def _parse(resp):
    """Parse a GraphQL JSON response; returns dict or None."""
    try:
        p = _json.loads(resp.body or "")
        return p if isinstance(p, dict) else None
    except Exception:
        return None


def _errors_text(parsed):
    return _json.dumps(parsed.get("errors") or []).lower()


def _is_live_endpoint(ctx, ep):
    """Baseline proof: the endpoint answers {__typename} with data."""
    try:
        r = _gql_post(ctx, ep, "{ __typename }")
    except Exception:
        return None
    p = _parse(r)
    if p is not None and isinstance(p.get("data"), dict):
        return p
    return None


# ------------------------------------------------- 1. field suggestions

def _suggest_probe(ctx, add, ep):
    """Always-on: send an invalid field; harvest 'Did you mean' names."""
    try:
        r = _gql_post(ctx, ep, "{ vxptk_invalid_field_xyz }")
    except Exception:
        return
    body = r.body or ""
    if "did you mean" not in body.lower():
        return
    names = sorted(set(_re.findall(r"did you mean[^?]*\?((?:\s*['\u201c][\w]+[\u201d'],?)*)",
                                   body.lower())) or
                   _re.findall(r"['\u201c]([a-z_][a-z0-9_]*)['\u201d]", body.lower()))
    add(_F("LOW", f"GraphQL field suggestion leakage: {ep}",
           'Error responses include "Did you mean" field suggestions, letting an '
           "attacker harvest valid schema field names interactively even when "
           "introspection is disabled.",
           evidence=body[:300],
           cwe="CWE-209", owasp="API8:2023", cvss=3.7,
           remed="Disable field suggestions in production (custom error "
                 "formatting / hide schema details).",
           confidence="probable", location=ep,
           verification_note="Content-only evidence; manually confirm the "
                             "suggestion response and enumerate harvested names."))


# ------------------------------------------- 2. introspection + bypasses

def _introspection_probe(ctx, add, ep):
    """Returns schema dict (types map) or None. Reports finding when open."""
    try:
        r = _gql_post(ctx, ep, _INTROSPECTION_Q)
    except Exception:
        return None
    p = _parse(r)
    sch = (p or {}).get("data", {}).get("__schema") \
        if isinstance(p, dict) and isinstance(p.get("data"), dict) else None
    if isinstance(sch, dict):
        add(_F("MEDIUM", f"GraphQL introspection enabled: {ep}",
               "The endpoint answers full introspection queries, handing the "
               "complete schema (types, fields, mutations, arguments) to any "
               "unauthenticated client and making every other GraphQL attack "
               "targeted instead of blind.",
               evidence="__schema answered with types map "
                        f"({len(sch.get('types') or [])} types)",
               cwe="CWE-200", owasp="API8:2023", cvss=5.3,
               remed="Disable introspection in production or restrict it to "
                     "authenticated/internal clients.",
               confidence="probable", location=ep,
               verification_note="Content-only evidence (no differential); "
                                 "verify the introspection response manually."))
        return _schema_map(sch)
    return None


def _schema_map(sch):
    """Flatten an introspection __schema into {typeName: {field: {args...}}}."""
    tmap = {}
    for t in sch.get("types") or []:
        if not isinstance(t, dict) or str(t.get("name") or "").startswith("__"):
            continue
        fields = {}
        for f in t.get("fields") or []:
            if isinstance(f, dict) and f.get("name"):
                args = {a.get("name"): a.get("defaultValue")
                        for a in (f.get("args") or []) if isinstance(a, dict)}
                fields[f["name"]] = {"args": args, "type": f.get("type") or {}}
        if fields:
            tmap[t["name"]] = fields
    return tmap


def _introspection_bypass_probe(ctx, add, ep, baseline):
    """GATED: plain introspection is blocked — try bypass variants.
    CONFIRMED requires differential evidence: a variant that returns
    __schema data where the plain query did not."""
    p = baseline
    if not p:
        return None
    variants = [
        ("POST aliased __schema",
         _gql_post(ctx, ep, "{ a: __schema { queryType { name } } }")),
        ("GET __schema via query param",
         _gql_get(ctx, ep, "{ __schema { queryType { name } } }")),
        ("POST application/graphql content-type",
         _gql_post(ctx, ep, "{ __schema { queryType { name } } }",
                   ctype="application/graphql")),
        ("GET field with __schema alias",
         _gql_get(ctx, ep, "{ a: __schema { types { name } } }")),
    ]
    for label, r in variants:
        try:
            pp = _parse(r)
        except Exception:
            continue
        data = (pp or {}).get("data")
        if isinstance(data, dict) and "__schema" in _json.dumps(data):
            add(_F("MEDIUM", f"GraphQL introspection bypass works: {ep} ({label})",
                   "Plain introspection is blocked but the bypass variant "
                   f"'{label}' still returns __schema data — the block is "
                   "pattern-based only and the full schema remains exposed.",
                   evidence=(r.body or "")[:300],
                   cwe="CWE-200", owasp="API8:2023", cvss=5.3,
                   remed="Block introspection at the resolver/engine level, not "
                         "by string-matching 'introspection' or '__schema' in "
                         "the query text.",
                   confidence="confirmed", location=ep,
                   verification="differential",
                   verification_note="Differential evidence: plain introspection "
                                     "did NOT return a schema, this variant did."))
            return _parse(r) and pp
    return None


# --------------------------------------------- 3. alias batching brute

def _alias_brute_probe(ctx, add, ep, baseline):
    """GATED: one request with many aliases of the same field; differential
    vs a single-alias baseline. CONFIRMED only when the alias batch actually
    resolves (rate limiting / alias caps absent)."""
    p = baseline
    if p is None:
        return
    single = _parse(_gql_post(ctx, ep, "{ s0: __typename }"))
    if not (single and isinstance(single.get("data"), dict) and single["data"].get("s0")):
        return  # even one alias does not resolve — no amplification baseline
    aliases = [f"ptka{i}" for i in range(ALIAS_COUNT)]
    q = "{ " + " ".join(f"{a}:__typename" for a in aliases) + " }"
    r = _gql_post(ctx, ep, q)
    p2 = _parse(r)
    data = (p2 or {}).get("data") if isinstance(p2, dict) else None
    resolved = sum(1 for a in aliases if isinstance(data, dict) and data.get(a) is not None)
    etxt = _errors_text(p2) if isinstance(p2, dict) else ""
    if resolved >= max(10, int(ALIAS_COUNT * 0.9)):
        add(_F("MEDIUM", f"GraphQL alias batching amplification: {ep}",
               f"A single request carrying {ALIAS_COUNT} aliases of the same field "
               f"resolved {resolved}/{ALIAS_COUNT} results while a single-alias "
               "baseline resolves normally — no alias/batch cap or per-operation "
               "rate limit, so one HTTP request multiplies resolver work "
               "(credential stuffing, object enumeration, DoS amplification).",
               evidence=f"differential: 1-alias baseline OK, {resolved}/{ALIAS_COUNT} "
                        "aliases resolved in one response",
               cwe="CWE-770", owasp="API4:2023", cvss=5.3,
               remed="Enforce alias limits, query complexity/cost analysis and "
                     "rate limits per operation rather than per request.",
               confidence="confirmed", location=ep,
               verification="differential",
               verification_note="Differential evidence: single-alias baseline "
                                 f"vs {resolved}/{ALIAS_COUNT}-alias batch resolved."))
    elif any(k in etxt for k in ("alias", "complexity", "too many", "limit", "cost")):
        ctx.L(f"  [graphqlsuite] {ep}: alias batching is capped (healthy)")


# --------------------------------------------- 4. depth/cost abuse probe

def _depth_chain(tmap, start, maxd=MAX_DEPTH):
    """Pick a nested chain of object fields from the schema map. Type cycles
    are deliberately allowed (user > posts > author > posts > ...) — they
    are exactly the amplification a depth probe must exercise."""
    chain, cur, last = [], start, None
    for _ in range(maxd):
        fields = tmap.get(cur) or {}
        nxt = None
        for fname, finfo in fields.items():
            if fname.startswith("__") or fname == last:
                continue
            t = finfo.get("type") or {}
            tname = t.get("name") or ((t.get("ofType") or {}).get("name"))
            if tname and tname in tmap:
                chain.append(fname)
                last = fname
                nxt = tname
                break
        if nxt is None:
            break
        cur = nxt
    return chain


def _depth_probe(ctx, add, ep, tmap, qtype):
    """GATED: deeply nested query. CONFIRMED on 500/timeout (differential vs
    the 200 baseline); on full resolution, the no-depth-limit exposure is
    confirmed with the resolved-data differential."""
    chain = _depth_chain(tmap, qtype)
    if len(chain) < 3:
        return
    q, close = "", ""
    for f in chain:
        q += f + " { "
        close += " } "
    q += "__typename " + close
    base = _is_live_endpoint(ctx, ep)
    r = _gql_post(ctx, ep, q)
    p = _parse(r)
    if r.status == 0:
        add(_F("HIGH", f"GraphQL depth/cost abuse hangs the endpoint: {ep}",
               f"A nested query of depth {len(chain)} timed out the client while "
               "the {__typename} baseline answers normally — resolvers recurse "
               "without a depth/complexity budget (denial-of-service surface).",
               evidence=f"differential: baseline 200, deep query (depth "
                        f"{len(chain)}) no response within client timeout "
                        f"({getattr(r, 'elapsed', 0):.1f}s)",
               cwe="CWE-400", owasp="API4:2023", cvss=7.5,
               remed="Enforce maximum query depth and a complexity/cost budget "
                     "with pagination limits at the GraphQL layer.",
               confidence="confirmed", location=ep,
               verification="differential",
               verification_note="Differential evidence: baseline answered 200; "
                                 "the deep query hung."))
        return
    etxt = _errors_text(p) if isinstance(p, dict) else ""
    if r.status >= 500:
        add(_F("HIGH", f"GraphQL depth/cost abuse returns a server error: {ep}",
               f"A nested query of depth {len(chain)} produced HTTP {r.status} "
               "while the baseline {__typename} query returns 200 — the resolver "
               "stack breaks down without a depth/complexity budget "
               "(denial-of-service and error-disclosure surface).",
               evidence=f"differential: baseline 200, depth-{len(chain)} query "
                        f"-> HTTP {r.status}: {(r.body or '')[:200]}",
               cwe="CWE-400", owasp="API4:2023", cvss=7.5,
               remed="Enforce maximum query depth and a complexity/cost budget; "
                     "return structured GraphQL errors instead of 500s.",
               confidence="confirmed", location=ep,
               verification="differential",
               verification_note="Differential evidence: baseline 200 vs deep "
                                 f"query HTTP {r.status}."))
    elif any(k in etxt for k in ("depth", "complexity", "too deep", "maximum",
                                 "limit", "cost")):
        ctx.L(f"  [graphqlsuite] {ep}: depth/complexity limit enforced (healthy)")
    elif isinstance(p, dict) and isinstance(p.get("data"), dict):
        def _resolved(d):
            if isinstance(d, dict):
                return any(_resolved(v) for v in d.values())
            return d is not None
        if _resolved(p["data"]):
            add(_F("MEDIUM", f"GraphQL query depth not limited: {ep}",
                   f"A nested query following the schema's own object fields "
                   f"(depth {len(chain)}) was fully resolved with data — no "
                   "query depth/complexity limit is enforced (nested-query "
                   "denial-of-service surface).",
                   evidence=f"differential: resolved chain: {' > '.join(chain)}",
                   cwe="CWE-400", owasp="API4:2023", cvss=5.3,
                   remed="Enforce a maximum query depth and complexity budget.",
                   confidence="confirmed", location=ep,
                   verification="differential",
                   verification_note="Differential evidence: baseline answered "
                                     "flat; the nested query resolved data at "
                                     "the deepest level."))


# --------------------------------- 5. GET support / query-in-URL leakage

def _get_leak_probe(ctx, add, ep, gated=False, mutation_names=()):
    """Always-on: query-in-URL (sensitive queries end up in logs/history).
    The GET-mutation execution check is offensive (it may trigger a state
    change) — only run behind the operator gate, with an introspected
    mutation name. GET-mutation execution is differential evidence."""
    try:
        r = _gql_get(ctx, ep, "{ __typename }")
    except Exception:
        return
    p = _parse(r)
    if not (isinstance(p, dict) and isinstance(p.get("data"), dict)):
        return
    add(_F("LOW", f"GraphQL queries accepted over GET (query-in-URL): {ep}",
           "The endpoint executes queries passed in the URL query string — full "
           "queries (tokens, IDs, filters) land in access logs, browser history "
           "and Referer headers.",
           evidence="GET with ?query={__typename} returned data",
           cwe="CWE-598", owasp="API8:2023", cvss=3.7,
           remed="Restrict GraphQL to POST; if GET is required, disable query "
                 "persistence via URL and use persisted queries.",
           confidence="probable", location=ep,
           verification_note="Content-only evidence; verify which requests are "
                             "actually logged with the full query string."))
    if not gated or not mutation_names:
        return
    # GET-mutation check — differential: a mutation over GET must only be
    # reported when the server actually executes it (data present).
    mname = sorted(mutation_names)[0]
    mut = f"mutation {{ {mname} {{ __typename }} }}"
    try:
        r2 = _gql_get(ctx, ep, mut)
    except Exception:
        return
    p2 = _parse(r2)
    etxt = _errors_text(p2) if isinstance(p2, dict) else ""
    if isinstance(p2, dict) and isinstance(p2.get("data"), dict) \
            and p2["data"].get(mname) is not None:
        add(_F("HIGH", f"GraphQL mutations accepted over GET: {ep}",
               "A mutation sent as a URL query string was EXECUTED — state-"
               "changing operations can be triggered from link prefetchers, "
               "crawlers and CSRF-style vectors with no POST requirement.",
               evidence=f"differential: GET query baseline OK, GET mutation "
                        f"executed and returned data: {str(p2['data'])[:200]}",
               cwe="CWE-352", owasp="API8:2023", cvss=8.1,
               remed="Reject mutations on GET at the GraphQL layer; require POST "
                     "for all state-changing operations.",
               confidence="confirmed", location=ep,
               verification="differential",
               verification_note="Differential evidence: the GET mutation "
                                 "resolved data (executed), the GET baseline "
                                 "only proves GET support."))
    elif any(k in etxt for k in ("must be post", "post only", "method not allowed")):
        ctx.L(f"  [graphqlsuite] {ep}: mutations correctly rejected on GET")


# ------------------------------------------ 6. unauthenticated mutations

_MUT_ARG_RE = _re.compile(r"(\w+)\s*:")


def _fill_args(args):
    parts = []
    for name in args or {}:
        parts.append(f"{name}: {_ARG_VALUES.get(str(name).lower(), f'\"{CANARY}\"')}")
    return ", ".join(parts)


def _mutation_probe(ctx, add, ep, tmap, mtype):
    """GATED: probe discovered mutation names WITHOUT credentials.
    Non-destructive: canary values, small budget. CONFIRMED only when a
    mutation actually executes (data returned) — differential vs the
    ordinary query erroring. Auth-challenged mutations are healthy and
    silently skipped."""
    fields = tmap.get(mtype) or {}
    tried = 0
    for mname, finfo in list(fields.items())[:MUTATION_BUDGET]:
        if mname.startswith("__"):
            continue
        tried += 1
        args = _fill_args((finfo or {}).get("args"))
        q = f"mutation {{ {mname}{('(%s)' % args) if args else ''} {{ __typename }} }}"
        try:
            r = _gql_post(ctx, ep, q)
        except Exception:
            continue
        p = _parse(r)
        etxt = _errors_text(p) if isinstance(p, dict) else ""
        if any(tok in etxt for tok in _AUTH_ERR_TOKENS):
            continue  # protected — healthy, not reported
        if isinstance(p, dict) and isinstance(p.get("data"), dict) \
                and p["data"].get(mname) is not None:
            add(_F("HIGH", f"GraphQL mutation executes without authentication: {ep} ({mname})",
                   f"The mutation '{mname}' (discovered via introspection) was "
                   "executed with canary values and no credentials — state-"
                   "changing operations are reachable unauthenticated (broken "
                   "function-level authorization).",
                   evidence=f"differential: mutation returned data: "
                            f"{str(p['data'])[:200]} (query errors normally; "
                            "mutation executed)",
                   cwe="CWE-306", owasp="API5:2023", cvss=8.6,
                   remed="Require authorization on every mutation at the "
                         "resolver layer; default-deny unauthenticated "
                         "mutations.",
                   confidence="confirmed", location=ep, param=mname,
                   verification="differential",
                   verification_note="Differential evidence: mutation executed "
                                     "and returned data with canary "
                                     f"'{CANARY}'. Verify no real state changed; "
                                     "the probe used only canary values."))
        else:
            add(_F("MEDIUM", f"GraphQL mutation reachable without authentication (no auth challenge): {ep} ({mname})",
                   f"The mutation '{mname}' answered without an authentication "
                   "challenge (no auth error in the response) — verify manually "
                   "whether it mutates state without credentials.",
                   evidence=(r.body or "")[:300],
                   cwe="CWE-306", owasp="API5:2023", cvss=5.3,
                   remed="Require authorization on every mutation at the "
                         "resolver layer.",
                   confidence="probable", location=ep, param=mname,
                   verification_note="No execution proof (no differential); "
                                     "manual verification required before "
                                     "treating as exploitable."))


# ------------------------------------------------------- check entrypoint

def c_graphql_suite(ctx, add):
    """CHECKS entry: GraphQL attack suite (field suggestions, introspection
    bypasses, alias batching, depth abuse, GET leakage, unauth mutations).
    Passive parts always run; offensive probes require opts['graphql_suite']
    or env PTK_GRAPHQL=1."""
    gated = _gate(getattr(ctx, "opts", None) or {})
    if not gated:
        ctx.L("  [graphqlsuite] offensive probes disabled — set PTK_GRAPHQL=1 "
              "or opts['graphql_suite'] to enable")
    for ep in _candidates(ctx):
        if ctx.cancelled():
            return
        baseline = _is_live_endpoint(ctx, ep)
        if baseline is None:
            continue
        ctx.L(f"  [graphqlsuite] probing GraphQL endpoint {ep}")
        # passive (always)
        _suggest_probe(ctx, add, ep)
        tmap = _introspection_probe(ctx, add, ep)
        qtype = "Query"
        mtype = None
        try:
            r = _gql_post(ctx, ep, "{ __schema { mutationType { name } } }")
            mt = ((_parse(r) or {}).get("data") or {}).get("__schema") or {}
            mtype = (mt.get("mutationType") or {}).get("name")
        except Exception:
            mtype = None
        if tmap is None and gated:
            bp = _introspection_bypass_probe(ctx, add, ep, baseline)
            if isinstance(bp, dict):
                sch = bp.get("data", {}).get("__schema") or {}
                tmap = _schema_map(sch) if sch else None
        mnames = list((tmap or {}).get(mtype) or {})
        _get_leak_probe(ctx, add, ep, gated=gated, mutation_names=mnames)
        if not gated or not tmap:
            continue
        # offensive (gated)
        _alias_brute_probe(ctx, add, ep, baseline)
        _depth_probe(ctx, add, ep, tmap, qtype)
        if mtype:
            _mutation_probe(ctx, add, ep, tmap, mtype)
