"""
FuzzKit v1 — Grammar-Based Fuzzing Engine for VANTHEX (v1.8.0).
AUTHORIZED TESTING ONLY — non-destructive (valid copies of target values,
structure mutations, bounded attempts).

Difference from a static payload list: STRUCTURE mutation (not just values) —
types flipped (number<->object<->null), nested depth added, keys duplicated,
arrays/objects swapped → finds parser bugs that plain payload strings miss.
"""
import json as _json
import random as _random

from exploitkit import _F

# mutation grammar: function (dict) -> mutation (dict)
DEPTH = 12          # max total requests per endpoint
STATE_RE = _random.Random(1701)


def _flip_types(v):
    if isinstance(v, str):
        return [123, None, True, 3.14, ["x"], {"k": "v"}]
    if isinstance(v, (int, float)):
        return ["str", None, {"k": 1}, [1], -1]
    if isinstance(v, dict):
        return ["str", 123, None, [1, 2]]
    if isinstance(v, list):
        return {"k": 1}, "str", 0, None
    return [None, "x", 0]


def _mutations(obj):
    """Yield structural mutations of obj (dict)."""
    for k in list(obj)[:6]:
        base = obj[k]
        for newv in _flip_types(base)[:4]:
            m = dict(obj)
            m[k] = newv
            yield m, f"type-flip:{k}"
        # nested depth injection
        if isinstance(base, dict) and base:
            m = dict(obj)
            m[k] = {"nested": base, "dup": base}
            yield m, f"depth-nest:{k}"
        # key duplication via JSON raw (parser-dependent behavior)
        m = dict(obj)
        m[k] = base
        yield m, f"same-value:{k}"
    # extra global depth
    m = dict(obj)
    for k in list(m)[:3]:
        m[k] = {"a": {"b": {"c": {"d": m[k]}}}}
    yield m, "deep-nest-all"
    m = dict(obj)
    m["__proto_extra__"] = {"__proto__": {"admin": True}}
    yield m, "proto-pollution"


def _looks_500(resp):
    body = (resp.body or "").lower()
    return resp.status >= 500 or ("traceback" in body or
                                  "internal server error" in body and
                                  resp.status >= 400)


def fuzz_endpoint(ctx, ep, base_body, content_type="application/json",
                  max_requests=DEPTH):
    """Send mutations → return parser findings: (endpoint, mutation, status)
    where the response != baseline and indicates a server error."""
    findings = []
    try:
        base = ctx.client.post(ep, data=_json.dumps(base_body),
                               headers={"Content-Type": content_type})
    except Exception:
        return findings
    bstatus = base.status
    count = 0
    for mut, tag in _mutations(base_body):
        if count >= max_requests:
            break
        count += 1
        try:
            r = ctx.client.post(ep, data=_json.dumps(mut),
                                headers={"Content-Type": content_type})
        except Exception:
            continue
        if _looks_500(r) and bstatus < 500:
            findings.append({"endpoint": ep, "mutation": tag,
                             "status": r.status, "body_hint":
                             (r.body or "")[:80]})
    return findings


def c_grammar_fuzz(ctx, add):
    """Grammar-based fuzz against valid JSON endpoints: structure/type/depth
    mutations → parsers that crash (5xx) are reported. /safe control: the
    same fuzz does NOT produce 5xx — if safe also crashes, it is not a target."""
    targets = [("/api/fuzz", {"id": 1, "name": "x", "active": True,
                              "tags": ["a"]})]
    allf = []
    for ep, body in targets:
        allf += fuzz_endpoint(ctx, ep, body)
        sf = fuzz_endpoint(ctx, "/safe" + ep, body)
        if sf:
            ctx.L(f"  [fuzz] /safe control also 5xx ({len(sf)}) — not a target")
            allf = [f for f in allf if f["endpoint"] != ep]
    if not allf:
        return
    seen, uniq = set(), []
    for f in allf:
        k = (f["endpoint"], f["mutation"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    det = "; ".join(f"{f['mutation']}→{f['status']}" for f in uniq[:5])
    add(_F("HIGH",
           "Endpoint Parser Crash on Structure Mutation (Grammar Fuzz)",
           f"The endpoint serves 5xx when JSON types/depth are mutated "
           f"({det}) — often an unhandled exception that could be "
           "developed into deserialization/logic bypass, and the traceback "
           "leaks internal stack details.",
           evidence=f"mutations: {[(f['endpoint'], f['mutation'], f['status']) for f in uniq[:4]]}",
           cwe="CWE-754", owasp="A03:2021 Injection", cvss=7.5,
           location=uniq[0]["endpoint"], param="body-structure",
           remed="Schema validation (pydantic/jsonschema), global error "
                 "handler without stack trace, fuzz regression tests in CI.",
           confidence="confirmed"))
