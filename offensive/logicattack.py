"""Business-Logic Attack Engine (logicattack.py) — built on session replay.

AUTHORIZED TESTING ONLY, NON-DESTRUCTIVE BY CONSTRUCTION (fail-closed):
the replay engine only ever sends requests when the caller explicitly
provides a context with an approval flag (`ctx["approve"] == True`) —
without it, every check short-circuits to a "skipped" result and ZERO
requests leave the process. The coupon-stacking probe is additionally
gated behind the PTK_LOGIC=1 environment variable (PTK_PROTO=1-style
env gate, per the toolkit convention). Targets scanned with this engine
must be operator-owned test fixtures; findings carry an evidence
differential (before/after comparison) whenever the outcome itself
proves the flaw, otherwise they stay candidates.

Layered on top of sessionreplay.parse_har: HAR requests (or an explicit
request-sequence list) become a replayable flow, and the engine probes
four classes of business-logic flaw by differential outcome:

  duplicate-apply     same state-changing request replayed twice ->
                      two distinct resources created from one intent.
  negative/zero qty   quantity/count/qty param mutated to -5 / 0 ->
                      response amount field goes negative.
  step-skip           final step called without intermediate steps ->
                      succeeds?
  cross-user apply    state-changing request replayed with a SWAPPED
                      session (two known sessions) -> still 2xx?
  coupon stacking     (PTK_LOGIC=1) coupon applied twice -> total
                      decreases twice.
  workflow bypass     final-state URL fetched directly without the
                      flow -> reachable?

Findings use the shared vulnscan2.F dict shape (same as vulnscan2 /
sessionreplay / mobile). Confidence ladder: a differential that proves
the flaw => "confirmed"/"probable" with the differential quoted in the
evidence; a suspicious outcome without a differential => "candidate",
never rounded up.
"""
import json
import os
import re
import time

from netclient import Client
from sessionreplay import parse_har, _origin_of
from vulnscan2 import F

# ---------------------------------------------------------------- gates ---

_ENV_LOGIC_GATE = "PTK_LOGIC"


def _approved(ctx):
    """Fail-closed approval gate: replay happens ONLY when the ctx object
    explicitly carries a truthy approve flag (and is a dict, so a None
    ctx can never approve by accident)."""
    return isinstance(ctx, dict) and bool(ctx.get("approve"))


def _client_for(ctx, origin):
    """Build (or reuse) a client for an origin. ctx may carry 'client'
    (a netclient.Client) like sibling modules do; otherwise fresh."""
    cli = ctx.get("client") if isinstance(ctx, dict) else None
    if cli is not None:
        return cli
    return Client(origin, timeout=6.0)


# ------------------------------------------------------- request helpers ---

_AMOUNT_KEY_RE = re.compile(
    r"(?i)^\(?([a-z0-9_./-]*(?:total|amount|price|subtotal|grand|sum|balance|due)[a-z0-9_./-]*)\)?$")
_QTY_KEY_RE = re.compile(r"(?i)^(qty|quantity|count|units|items_count)$")
_NEG_NUM_RE = re.compile(r"(?<![\w.])-(?:\d{1,12})(?:\.\d{1,4})?(?![\w])")


def _try_json(text):
    if not isinstance(text, str) or not text.strip():
        return None
    t = text.strip()
    if t[0] not in "{[":
        return None
    try:
        return json.loads(t)
    except Exception:
        return None


def _walk_amounts(node, out, prefix=""):
    """Collect (key, value) for amount-like fields in a parsed JSON blob."""
    if isinstance(node, dict):
        for k, v in node.items():
            key = str(k)
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                if _AMOUNT_KEY_RE.match(key) or _QTY_KEY_RE.match(key):
                    out.append((key, v))
            elif isinstance(v, (dict, list)):
                _walk_amounts(v, out, prefix + key + ".")
    elif isinstance(node, list):
        for item in node[:20]:
            _walk_amounts(item, out, prefix)


def amounts_in_response(body):
    """Heuristic amount extraction: JSON amount-like fields, then a loose
    negative-number scan over the raw text (HTML/order receipts)."""
    out = []
    parsed = _try_json(body)
    if parsed is not None:
        _walk_amounts(parsed, out)
    else:
        for m in _NEG_NUM_RE.finditer(body or ""):
            out.append(("text", float(m.group(0))))
    return out


def _success_marker(body):
    """Cheap 'the operation succeeded' indicator in a response body."""
    low = (body or "").lower()
    return any(t in low for t in (
        "created", "\"status\": \"success\"", "\"status\":\"success\"",
        "success", "confirmed", "\"status\": \"complete\"",
        "\"status\":\"complete\"", "order_id", "order-id"))


def _set_body_param(body, key, value):
    """Return (new_body, ok) with `key` set to `value`, preserving the
    original encoding (form-encoded or JSON). Unknown encodings fail
    closed (ok=False) rather than guessing."""
    if isinstance(body, str) and body.strip().startswith("{"):
        try:
            obj = json.loads(body)
        except Exception:
            return body, False
        if isinstance(obj, dict):
            obj[key] = value
            return json.dumps(obj), True
        return body, False
    # form-encoded
    pairs = []
    found = False
    for part in (body or "").split("&"):
        if not part:
            continue
        k, _, v = part.partition("=")
        from urllib.parse import quote
        if k.strip() == key:
            pairs.append("%s=%s" % (k, quote(str(value), safe="")))
            found = True
        else:
            pairs.append(part)
    if not found:
        from urllib.parse import quote
        pairs.append("%s=%s" % (key, quote(str(value), safe="")))
    return "&".join(pairs), True


def _resource_ids(body):
    """Extract resource identifiers from a response (id/order_id/uuid-ish)."""
    ids = set()
    parsed = _try_json(body)
    if isinstance(parsed, dict):
        for k, v in parsed.items():
            lk = str(k).lower()
            if lk.endswith("_id") or lk == "id" or lk.endswith("uuid"):
                ids.add(str(v))
    else:
        for m in re.finditer(
                r"(?i)\b(?:order_id|invoice_id|ticket_id|resource_id|id)"
                r"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_-]{1,40})", body or ""):
            ids.add(m.group(1))
    return ids


def _do(client, method, path, body=None, headers=None):
    """One HTTP request through netclient.Client; never raises (returns a
    {status, body, error} dict)."""
    try:
        resp = client.request(method, path,
                              data=body if method != "GET" else None,
                              headers=headers or {}, timeout=6.0)
        return {"status": int(getattr(resp, "status", 0) or 0),
                "body": getattr(resp, "body", "") or "",
                "error": str(getattr(resp, "error", "") or "")}
    except Exception as exc:  # noqa: BLE001 — never abort a check mid-way
        return {"status": 0, "body": "", "error": str(exc)[:200]}


# ----------------------------------------------------------- discovery ---

_STATE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
_FINAL_URL_RE = re.compile(
    r"(?i)(/|=&|\b)(final|complete|completed|confirm|confirmation|receipt|"
    r"success|checkout|submit|placeorder|finish|done)(/|\b|[?=&])")


def discover_flow(requests):
    """Split a parsed HAR request list into flow metadata: ordered
    state-changing steps, final-state GET candidates, coupon candidates,
    quantity-bearing candidates. Purely local — no requests are sent."""
    steps, final_gets, coupons, qty_reqs = [], [], [], []
    for i, req in enumerate(requests or []):
        if not isinstance(req, dict):
            continue
        method = str(req.get("method") or "GET").upper()
        url = str(req.get("url") or "")
        origin, path = _origin_of(url)
        low = (path + " " + str(req.get("body") or "")).lower()
        if method in _STATE_METHODS:
            step = dict(req)
            step["_origin"], step["_path"], step["_index"] = origin, path, i
            steps.append(step)
            if "coupon" in low or "promo" in low or "discount" in low \
                    or "voucher" in low:
                coupons.append(step)
            if any(_QTY_KEY_RE.search(p.split("=")[0])
                   for p in str(req.get("body") or "").split("&")):
                qty_reqs.append(step)
        elif method == "GET" and _FINAL_URL_RE.search(path):
            final_gets.append({"_origin": origin, "_path": path,
                               "_index": i, "req": req})
    return {"steps": steps, "final_gets": final_gets,
            "coupons": coupons, "qty_reqs": qty_reqs}


def _final_step(steps):
    """Best guess at the flow's final (completion) step: the last
    state-changing request whose path matches completion words, else the
    last state-changing request."""
    for step in reversed(steps):
        if _FINAL_URL_RE.search(step["_path"]):
            return step
    return steps[-1] if steps else None


def _capture_headers(req):
    hdrs = {k: v for k, v in (req.get("headers") or {}).items()
            if k not in ("host", "content-length", "connection",
                         "transfer-encoding", "accept-encoding", "cookie")}
    return hdrs


def _origin_of_step(step):
    return step.get("_origin") or _origin_of(str(step.get("url") or ""))[0]


# -------------------------------------------------------------- checks ----

def check_duplicate_apply(ctx, step, client=None):
    """Replay ONE state-changing request twice; if the two responses both
    succeed AND carry DIFFERENT resource identifiers, the differential
    (two ids from one user intent) proves duplicate creation."""
    if not _approved(ctx):
        return []
    cli = client or _client_for(ctx, _origin_of_step(step))
    hdrs = _capture_headers(step)
    r1 = _do(cli, step["method"], step["_path"], step.get("body"), hdrs)
    r2 = _do(cli, step["method"], step["_path"], step.get("body"), hdrs)
    ok1, ok2 = 200 <= r1["status"] < 300, 200 <= r2["status"] < 300
    id1, id2 = _resource_ids(r1["body"]), _resource_ids(r2["body"])
    new_id = id2 - id1 if (id1 or id2) else set()
    if ok1 and ok2 and id1 and id2 and new_id:
        return [F(
            "HIGH", "Duplicate-Apply: State-Changing Request Replayed Creates a Second Resource",
            "The same captured state-changing request was replayed verbatim and BOTH the "
            "original and the replay succeeded, with the replay returning a DIFFERENT "
            "resource identifier than the first call. The server created two resources "
            "from one user intent (no idempotency key / no replay protection) — the "
            "differential (distinct ids on identical requests) proves the flaw.",
            evidence="replay of %s %s -> id(s) %s, then replay #2 -> new id(s) %s "
                     "(statuses %d/%d)" % (step["method"], step["_path"],
                                           ",".join(sorted(id1))[:60],
                                           ",".join(sorted(new_id))[:60],
                                           r1["status"], r2["status"]),
            cwe="CWE-841", owasp="A04:2021", cvss=7.5,
            remed="Make state-changing handlers idempotent: accept a client-supplied "
                  "idempotency key (or derive one from the request), reject/merge "
                  "duplicate submissions, and never allocate a new resource for a "
                  "replayed identical request.",
            confidence="confirmed", location=step["_path"])]
    if ok1 and ok2:
        return [F(
            "MEDIUM", "Duplicate-Apply Suspect: Replayed State-Changing Request Accepted Twice",
            "The same captured state-changing request succeeded on replay (both calls "
            "returned 2xx), but the responses did not expose resource identifiers, so "
            "the duplicate-creation differential could not be verified from the "
            "responses alone.",
            evidence="%s %s replayed twice -> statuses %d/%d (no resource ids in "
                     "responses)" % (step["method"], step["_path"],
                                     r1["status"], r2["status"]),
            cwe="CWE-841", owasp="A04:2021", cvss=5.3,
            remed="Verify server-side whether both calls mutated state; add "
                  "idempotency protection to state-changing handlers.",
            confidence="candidate", location=step["_path"])]
    return []


def check_negative_quantity(ctx, step, client=None):
    """Mutate a quantity-like body parameter to -5 (and 0) and look for a
    NEGATIVE amount in the response — the differential (negative total on
    a purchasable item) proves the flaw."""
    if not _approved(ctx):
        return []
    cli = client or _client_for(ctx, _origin_of_step(step))
    hdrs = _capture_headers(step)
    findings = []
    for key in _qty_keys_of(step):
        for value, label in (("-5", "quantity=-5"), ("0", "quantity=0")):
            new_body, ok = _set_body_param(step.get("body") or "", key, value)
            if not ok:
                continue
            r = _do(cli, step["method"], step["_path"], new_body, hdrs)
            amounts = amounts_in_response(r["body"])
            negs = [(k, v) for k, v in amounts
                    if isinstance(v, (int, float)) and v < 0
                    and not _QTY_KEY_RE.match(k)]
            if 200 <= r["status"] < 300 and negs:
                k, v = negs[0]
                findings.append(F(
                    "HIGH", "Negative Amount Accepted: %s Not Validated" % key,
                    "Setting the quantity-style parameter '%s' to %s was ACCEPTED "
                    "(2xx) and the response's amount field '%s' computed to a "
                    "NEGATIVE value (%s). The differential (negative total for a "
                    "real item) proves the server lacks lower-bound validation on "
                    "quantities — a purchase with a negative total, or a refund "
                    "forced from an order, follows directly." % (key, value, k, v),
                    evidence="POST body '%s' with %s -> status %d, %s=%s"
                             % (step["_path"][:120], label, r["status"], k, v),
                    cwe="CWE-20", owasp="A03:2021", cvss=8.1,
                    remed="Validate quantity/count parameters server-side: integer "
                          "type, strict lower bound (> 0), and recompute every "
                          "amount from server-side reference prices — never trust "
                          "client-computed totals.",
                    confidence="confirmed",
                    location=step["_path"], param=key))
            elif 200 <= r["status"] < 300 and value == "-5" and \
                    _success_marker(r["body"]):
                findings.append(F(
                    "MEDIUM", "Non-Positive Quantity Accepted (Negative-Amount Suspect)",
                    "Setting the quantity-style parameter '%s' to %s was accepted "
                    "(2xx success response), but no negative amount could be read "
                    "from the response, so the pricing differential could not be "
                    "confirmed from the response alone." % (key, value),
                    evidence="%s %s with %s -> status %d, success marker in body"
                             % (step["method"], step["_path"], label, r["status"]),
                    cwe="CWE-20", owasp="A03:2021", cvss=5.3,
                    remed="Add strict lower-bound validation on quantity "
                          "parameters and recompute amounts server-side.",
                    confidence="candidate",
                    location=step["_path"], param=key))
        break  # probe the first quantity-looking parameter only
    return findings


def _qty_keys_of(step):
    keys = []
    for part in str(step.get("body") or "").split("&"):
        k = part.partition("=")[0].strip()
        if k and _QTY_KEY_RE.match(k):
            keys.append(k)
    return keys or ["quantity"]


def check_step_skip(ctx, steps, client=None):
    """Call the FINAL step alone (fresh client, no cookies, no prior
    steps). Succeeding where the flow requires predecessors is the
    differential proof of a missing step-order/state check."""
    if not _approved(ctx) or not steps:
        return []
    step = _final_step(steps)
    cli = client or _client_for(ctx, _origin_of_step(step))
    hdrs = _capture_headers(step)
    hdrs.pop("cookie", None)
    r = _do(cli, step["method"], step["_path"], step.get("body"), hdrs)
    if 200 <= r["status"] < 300 and _success_marker(r["body"]):
        return [F(
            "HIGH", "Workflow Step-Skip: Final Step Succeeds Without Intermediate Steps",
            "The flow's final step was replayed ALONE — no intermediate steps were "
            "performed and the request carried no captured session state — and it "
            "SUCCEEDED (2xx with a success indicator). The differential (final step "
            "completes without its predecessors) proves the server does not "
            "validate workflow order/state before performing the final action.",
            evidence="%s %s replayed standalone -> status %d, success marker in "
                     "body" % (step["method"], step["_path"], r["status"]),
            cwe="CWE-840", owasp="A04:2021", cvss=7.5,
            remed="Model the workflow as server-side state: each step must check "
                  "that its predecessors completed for THIS session/transaction "
                  "before performing the final action; reject out-of-order calls.",
            confidence="confirmed", location=step["_path"])]
    if 200 <= r["status"] < 300:
        return [F(
            "MEDIUM", "Workflow Step-Skip Suspect: Final Step Reachable Without Prior Steps",
            "The flow's final step was replayed alone (no intermediate steps, no "
            "session state) and returned 2xx, but the response carried no success "
            "indicator, so the differential could not be confirmed from the "
            "response body.",
            evidence="%s %s replayed standalone -> status %d (no success marker)"
                     % (step["method"], step["_path"], r["status"]),
            cwe="CWE-840", owasp="A04:2021", cvss=5.3,
            remed="Verify server-side whether the call mutated state; gate the "
                  "final step on completed predecessor state.",
            confidence="candidate", location=step["_path"])]
    return []


def check_cross_user_apply(ctx, steps, sessions, client=None):
    """Replay each state-changing request with each OTHER known session's
    cookie. A 2xx under a swapped identity on a state-changing call is a
    strong authorization-gap differential (cross-user apply)."""
    if not _approved(ctx) or not steps:
        return []
    if not isinstance(sessions, (list, tuple)) or len(sessions) < 2:
        return []
    findings, seen = [], set()
    for step in steps:
        cli = client or _client_for(ctx, _origin_of_step(step))
        base_hdrs = _capture_headers(step)
        captured_cookie = (step.get("headers") or {}).get("cookie", "")
        for cookie in sessions:
            if str(cookie) == captured_cookie:
                continue  # only SWAPPED identities are interesting
            hdrs = dict(base_hdrs)
            hdrs["cookie"] = str(cookie)
            r = _do(cli, step["method"], step["_path"], step.get("body"), hdrs)
            key = (step["_path"], step["method"])
            if 200 <= r["status"] < 300 and key not in seen:
                seen.add(key)
                findings.append(F(
                    "HIGH", "Cross-User Apply: State-Changing Request Accepted Under a Swapped Session",
                    "A captured state-changing request was replayed with a DIFFERENT "
                    "session's cookie and the server performed it (2xx). The "
                    "differential (same action, different identity, still accepted) "
                    "indicates the action is authorized on something other than the "
                    "presented session — cross-user state application / broken "
                    "object-level authorization. Verify manually that the target "
                    "object really belongs to the other session before treating "
                    "this as exploitable.",
                    evidence="%s %s replayed with a swapped session cookie -> "
                             "status %d" % (step["method"], step["_path"],
                                            r["status"]),
                    cwe="CWE-639", owasp="A01:2021", cvss=8.2,
                    remed="Derive the actor identity server-side from the "
                          "authenticated session and check object ownership "
                          "before applying state changes; return 403 on mismatch.",
                    confidence="probable", location=step["_path"]))
    return findings


def check_coupon_stacking(ctx, coupon_steps, client=None):
    """Apply the coupon TWICE. If the second application also succeeds and
    the response total DECREASES again, the differential (total1 > total2
    on an identical request) proves stacking. Gated behind PTK_LOGIC=1."""
    if os.environ.get(_ENV_LOGIC_GATE) != "1":
        return []
    if not _approved(ctx) or not coupon_steps:
        return []
    findings = []
    for step in coupon_steps:
        cli = client or _client_for(ctx, _origin_of_step(step))
        hdrs = _capture_headers(step)
        r1 = _do(cli, step["method"], step["_path"], step.get("body"), hdrs)
        r2 = _do(cli, step["method"], step["_path"], step.get("body"), hdrs)
        a1 = [v for _k, v in amounts_in_response(r1["body"])]
        a2 = [v for _k, v in amounts_in_response(r2["body"])]
        ok1, ok2 = 200 <= r1["status"] < 300, 200 <= r2["status"] < 300
        stacked = ok1 and ok2 and a1 and a2 and min(a2) < min(a1)
        if stacked:
            findings.append(F(
                "HIGH", "Discount/Coupon Stacking: Coupon Applied Twice Reduces the Total Twice",
                "The same coupon-apply request was replayed and the SECOND "
                "application also succeeded, with the response total DROPPING "
                "again (first apply total %s, replay total %s). The differential "
                "(monotonically decreasing total on identical requests) proves "
                "the coupon is not bound to one redemption — an attacker can "
                "stack the discount by replaying the apply request." % (
                    min(a1), min(a2)),
                evidence="%s %s applied twice -> totals %s then %s (statuses "
                         "%d/%d)" % (step["method"], step["_path"], a1[:3],
                                     a2[:3], r1["status"], r2["status"]),
                cwe="CWE-841", owasp="A04:2021", cvss=7.5,
                remed="Bind a coupon redemption to a unique claim per user/"
                      "transaction (redeemed flag or single-use ledger entry); "
                      "reject a second apply of the same code for the same "
                      "cart/user.",
                confidence="confirmed", location=step["_path"]))
        elif ok1 and ok2:
            findings.append(F(
                "MEDIUM", "Discount/Coupon Re-Apply Suspect (Stacking Candidate)",
                "The coupon-apply request succeeded on replay (both calls 2xx), "
                "but the response totals did not show a second decrease, so "
                "stacking could not be proven from the responses alone.",
                evidence="%s %s applied twice -> statuses %d/%d (totals %s / %s)"
                         % (step["method"], step["_path"], r1["status"],
                            r2["status"], a1[:3], a2[:3]),
                cwe="CWE-841", owasp="A04:2021", cvss=5.3,
                remed="Verify server-side redemption state; enforce single-use "
                      "coupons per cart/user.",
                confidence="candidate", location=step["_path"]))
    return findings


def check_workflow_bypass(ctx, final_gets, client=None):
    """Fetch final-state URLs DIRECTLY (no flow, fresh session). A 2xx on
    a URL that should only exist after the flow completes is the bypass
    differential (reachable when it should not be)."""
    if not _approved(ctx):
        return []
    findings, seen = [], set()
    for fg in final_gets:
        origin, path = fg["_origin"], fg["_path"]
        if origin in seen:
            continue
        seen.add(origin)
        cli = client or _client_for(ctx, origin)
        r = _do(cli, "GET", path, None, {})
        if 200 <= r["status"] < 300:
            findings.append(F(
                "MEDIUM", "Workflow Bypass: Final-State Resource Reachable Without the Flow",
                "A final-state URL was fetched DIRECTLY with a fresh session "
                "(no cookies, no preceding flow steps) and returned 2xx. The "
                "differential (final-state resource served without the flow that "
                "should produce it) indicates the endpoint serves completion "
                "state without validating that the workflow actually ran.",
                evidence="direct GET %s -> status %d, %d bytes (no session)"
                         % (path[:120], r["status"], len(r["body"])),
                cwe="CWE-840", owasp="A04:2021", cvss=5.3,
                remed="Gate final-state resources on server-side workflow "
                      "completion for the requesting session; return 4xx/404 "
                      "when the flow has not completed.",
                confidence="probable", location=path))
        else:
            findings.append(F(
                "LOW", "Final-State URL Not Directly Reachable (control present)",
                "The final-state URL did NOT serve completion state to a fresh "
                "session — the workflow gate appears effective for this URL "
                "(informational, recorded as a negative control).",
                evidence="direct GET %s -> status %d" % (path[:120], r["status"]),
                cwe="", owasp="", cvss=3.0,
                remed="No action needed for this URL; keep the state check "
                      "covered by regression tests.",
                confidence="candidate", location=path))
    return findings


# ----------------------------------------------------------- orchestrator -

def run_logic_checks(har=None, requests=None, ctx=None, sessions=None,
                     client=None, max_steps=20):
    """End-to-end business-logic attack pass.

    har:      HAR document (dict / bytes / str) OR None.
    requests: explicit parsed request list (used when no har given).
    ctx:      MUST be a dict with a truthy 'approve' flag for ANY request
              to leave the process (fail-closed); may carry 'client'.
    sessions: list of >= 2 session cookie strings for cross-user checks.
    client:   optional shared netclient.Client.

    Returns {"findings": [...], "checks": {...}, "skipped": reason|None}.
    """
    result = {"findings": [], "checks": {}, "skipped": None}
    if not _approved(ctx):
        result["skipped"] = ("fail-closed: replay requires ctx['approve']=true "
                             "against an operator-owned test fixture")
        return result
    reqs = requests
    if reqs is None and har is not None:
        reqs = parse_har(har)
    if not reqs:
        result["skipped"] = "no parsable requests (HAR empty or invalid)"
        return result
    flow = discover_flow(reqs)
    steps = flow["steps"][:max(0, max_steps)]
    findings = []
    counts = {}
    for name, fn in (
            ("duplicate_apply", lambda: check_duplicate_apply(ctx, steps[0], client) if steps else []),
            ("negative_quantity", lambda: [f for s in flow["qty_reqs"][:3]
                                           for f in check_negative_quantity(ctx, s, client)]),
            ("step_skip", lambda: check_step_skip(ctx, steps, client)),
            ("cross_user_apply", lambda: check_cross_user_apply(ctx, steps, sessions, client)),
            ("coupon_stacking", lambda: [f for s in flow["coupons"][:2]
                                         for f in check_coupon_stacking(ctx, [s], client)]),
            ("workflow_bypass", lambda: check_workflow_bypass(ctx, flow["final_gets"][:4], client)),
    ):
        try:
            got = fn() or []
        except Exception as exc:  # noqa: BLE001 — a broken check never kills the pass
            got = []
            counts[name] = "error: %s" % str(exc)[:120]
        counts[name] = len(got)
        findings.extend(got)
    result["findings"] = findings
    result["checks"] = {"flow_steps": len(steps),
                        "final_gets": len(flow["final_gets"]),
                        "coupon_candidates": len(flow["coupons"]),
                        "quantity_candidates": len(flow["qty_reqs"]),
                        **counts}
    return result
