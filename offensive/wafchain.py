"""VANTHEX — WAF fingerprint -> auto-bypass chain (wafchain).

AUTHORIZED TESTING ONLY. Read-only, form-only payload reshaping: every
transform preserves what the payload *says*, only changing how it looks
on the wire, so an authorized scanner can tell an application's own
behavior from a blocking inspection layer's. No destructive capability.

Pipeline:
  1. fingerprint_waf(resp_headers, body, status) -> named WAF + confidence,
     built on wafscore's scored rules (max-merge, display floor) and
     wafbank's vendor normalization. Unknown blocking layers are reported
     as "Unknown WAF" — never a guessed vendor name.
  2. select_bypasses(waf) -> ordered [(strategy_name, str->str transform)]
     from wafbank's per-vendor BANK (case tricks, comment splitting,
     encoding layers, whitespace alternates) extended with chain-level
     strategies (nested/overlap keyword insertion) that wafbank alone
     does not carry. Capped at MAX_STRATEGIES (6).
  3. test_bypasses(req_builder, marker) — sandboxed live probe, each
     strategy one request plus one raw-marker baseline (budget: 7
     requests total). A strategy WINS when the marker is reflected
     DECODED and intact in the body and vulnscan2's _echo_only_response
     guard says it is NOT just an echoed query string. CONFIRMED bypass
     is differential: winner passed AND the raw control was blocked.
     Otherwise the result is a candidate.
     The live probe is operator-gated: no-op unless PTK_WAFCHAIN=1 in
     the environment (or gate=True passed explicitly).
  4. chain_into_check(ctx, waf, check_fn, ...) — runs the gated probe
     once, then returns check_fn wrapped so every payload string it is
     given (first positional str argument) is transformed by the winning
     strategy before the check runs. Pure transformation: the wrapped
     check itself makes no extra requests; the only added traffic is the
     one bypass probe. No winner -> check_fn returned unchanged.

All findings text is English; a finding carries the evidence (strategy,
transformed payload, baseline behavior) so a human can audit the claim.
"""

import os

import wafbank
import wafscore

try:
    from vulnscan2 import _echo_only_response
except Exception:                                    # pragma: no cover
    def _echo_only_response(resp, marker):           # conservative fallback
        return False

GATE_ENV = "PTK_WAFCHAIN"
MAX_STRATEGIES = 6

# ------------------------------------------------------ chain strategies
# str -> str, form-only. `overlap-nest` inserts a keyword inside itself at
# its midpoint ("script" -> "scr<script>ipt"): a one-pass, non-recursive
# filter that deletes the keyword once reassembles the survivor into the
# original token — the classic overlap-replace bypass. It nests only the
# tokens listed; other text is untouched.

_NEST_TOKENS = ("<script>", "select", "union", "onload", "alert")


def _overlap_nest(s):
    out = s
    for kw in _NEST_TOKENS:
        if kw in out:
            mid = max(1, len(kw) // 2)
            out = out.replace(kw, kw[:mid] + kw + kw[mid:])
    return out


def _case_first(s):
    """Uppercase only alphabetic tokens (ScRiPt) — case-insensitive filter
    defeats; kept distinct from wafbank's alternating case-mix."""
    out, tok = [], []
    for c in s:
        if c.isalpha():
            tok.append(c)
        else:
            if tok:
                out.append("".join(tok).upper())
                tok = []
            out.append(c)
    if tok:
        out.append("".join(tok).upper())
    return "".join(out)


CHAIN_STRATEGIES = {
    "overlap-nest": _overlap_nest,
    "case-upper": _case_first,
}


def fingerprint_waf(resp_headers, body, status=None):
    """Name the WAF behind a response.

    resp_headers: list of (name, value) pairs, a dict, or raw header
    lines; body: response text; status: HTTP status (boosts blocking
    corroboration). Returns
      {"waf": vendor name or "Unknown WAF", "confidence": 0..1,
       "evidence": [signal strings], "bank_key": wafbank fingerprint}
    Reuses wafscore's scored rule tables; vendor names below the display
    floor are never returned as a guess.
    """
    if isinstance(resp_headers, dict):
        hdrs = list(resp_headers.items())
    else:
        hdrs = resp_headers
    scored = wafscore.score_waf(hdrs, body, status=status)
    v = wafscore.best_vendor(scored)
    if v:
        return {"waf": v["vendor"],
                "confidence": round(v["score"], 2),
                "evidence": list(v["signals"]),
                "bank_key": wafbank.normalize_vendor(v["vendor"])}
    gb = bool(scored.get("generic_block")) or \
        (status in wafscore.BLOCK_STATUSES)
    if gb:
        return {"waf": "Unknown WAF",
                "confidence": wafscore.UNKNOWN_WAF_SCORE,
                "evidence": ["blocking behavior with no vendor signal"],
                "bank_key": "generic"}
    return {"waf": None, "confidence": 0.0, "evidence": [],
            "bank_key": "generic"}


def select_bypasses(waf):
    """Ordered [(strategy_name, transform)] for a WAF fingerprint.

    Chain strategies first (overlap-nest, case-upper), then wafbank's
    vendor-tuned order for the fingerprint (comment splitting, encoding
    layers, whitespace alternates, JSON wrap). Deduped, capped at
    MAX_STRATEGIES. Unknown fingerprints degrade to wafbank "generic".
    """
    bank_key = wafbank.normalize_vendor(waf)
    names = list(CHAIN_STRATEGIES.keys())
    for n in wafbank.BANK.get(bank_key) or wafbank.BANK["generic"]:
        if n not in names:
            names.append(n)
    out = []
    for n in names[:MAX_STRATEGIES]:
        fn = CHAIN_STRATEGIES.get(n) or wafbank.TRANSFORMS.get(n)
        if fn:
            out.append((n, fn))
    return out


def _resp_status(resp):
    try:
        return int(getattr(resp, "status", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _passed(resp, marker):
    """True when `marker` is reflected decoded & intact and NOT merely an
    echoed query-string artifact (vulnscan2 fp-guard reused)."""
    if resp is None:
        return False
    body = getattr(resp, "body", "") or ""
    if not body or str(marker) not in body:
        return False
    return not _echo_only_response(resp, marker)


def gated(gate=None):
    """Operator gate: explicit argument wins, else env PTK_WAFCHAIN=1."""
    if gate is not None:
        return bool(gate)
    return os.environ.get(GATE_ENV, "").strip() == "1"


def test_bypasses(target_req_builder, marker, waf=None, log=None,
                  gate=None, max_strategies=MAX_STRATEGIES):
    """Sandboxed live probe: does any bypass let `marker` through?

    target_req_builder: callable(payload_str) -> response-like object
    (attributes .status, .body; called once per strategy plus one
    baseline). waf: fingerprint name from fingerprint_waf (None ->
    generic order). At most `max_strategies` strategies, 1 request each,
    +1 baseline; every request is wrapped so builder/network exceptions
    stay inside the loop.

    Returns (finding, detail). finding is an English finding dict
    (confidence "confirmed" | "candidate" | "none"); detail carries
    baseline/winner/evidence for audit. The probe only runs when gated();
    otherwise it returns ({...confidence "none", gated-out...}, {...})
    with ZERO requests made.
    """
    m = str(marker or "")
    if not m:
        return ({"severity": "info", "title": "WAF bypass probe skipped",
                 "description": "Empty marker; nothing to probe.",
                 "confidence": "none"}, {"requests": 0})
    if not gated(gate):
        f = {"severity": "info",
             "title": "WAF bypass probe not enabled",
             "description": (
                 "Live WAF-bypass probing is operator-gated. Set %s=1 to "
                 "allow the sandboxed probe (max %d strategies, 1 request "
                 "each + 1 baseline)." % (GATE_ENV, max_strategies)),
             "confidence": "none"}
        return (f, {"requests": 0, "gated": True})

    strategies = select_bypasses(waf)[:max_strategies]
    requests = 0
    baseline_blocked = False
    try:
        base = target_req_builder(m)
        requests += 1
        baseline_blocked = wafbank.is_blocked(_resp_status(base),
                                              getattr(base, "body", ""))
    except Exception as e:
        return ({"severity": "info",
                 "title": "WAF bypass probe failed",
                 "description": "Baseline request errored: %s" % e,
                 "confidence": "none"},
                {"requests": requests, "error": str(e)})

    winner = None
    evidence = []
    for name, fn in strategies:
        try:
            payload = fn(m)
        except Exception:
            continue
        if not payload or payload == m:
            continue
        try:
            resp = target_req_builder(payload)
        except Exception as e:
            evidence.append("%s: request error (%s)" % (name, e))
            continue
        requests += 1
        if _passed(resp, m):
            winner = {"strategy": name, "payload": payload,
                      "status": _resp_status(resp)}
            evidence.append("%s: marker reflected decoded & intact" % name)
            break
        evidence.append("%s: marker not reflected intact" % name)

    if winner and baseline_blocked:
        f = {"severity": "medium",
             "title": "WAF bypass confirmed (%s)" % winner["strategy"],
             "description": (
                 "Differential confirmed: the raw control payload was "
                 "blocked, but strategy '%s' carried the marker through "
                 "decoded and intact (outside any echoed query string). "
                 "The winning transformation can be chained onto checks "
                 "for this target." % winner["strategy"]),
             "confidence": "confirmed",
             "evidence": "; ".join(evidence)}
        d = {"requests": requests, "baseline_blocked": True,
             "winner": winner, "confirmed": True, "evidence": evidence}
    elif winner:
        f = {"severity": "low",
             "title": "WAF bypass candidate (%s)" % winner["strategy"],
             "description": (
                 "Strategy '%s' reflected the marker decoded and intact, "
                 "but the raw control was not blocked, so no differential "
                 "exists — treat as a candidate, not a confirmed bypass."
                 % winner["strategy"]),
             "confidence": "candidate",
             "evidence": "; ".join(evidence)}
        d = {"requests": requests, "baseline_blocked": False,
             "winner": winner, "confirmed": False, "evidence": evidence}
    else:
        f = {"severity": "info", "title": "No WAF bypass found",
             "description": (
                 "%d strategy/-ies tried against the fingerprinted WAF; "
                 "none carried the marker through intact." % len(strategies)),
             "confidence": "none",
             "evidence": "; ".join(evidence)}
        d = {"requests": requests, "baseline_blocked": baseline_blocked,
             "winner": None, "confirmed": False, "evidence": evidence}
    if log is not None:
        try:
            log("[wafchain] %s" % f["title"])
        except Exception:
            pass
    return f, d


def chain_into_check(ctx, waf, check_fn, target_req_builder=None,
                     marker=None, gate=None):
    """Wrap `check_fn` so its payloads ride the winning bypass transform.

    Runs the operator-gated bypass probe once (test_bypasses) when
    target_req_builder + marker are provided, then returns a wrapped
    check: every first positional str argument (the payload) is
    transformed by the winning strategy before check_fn runs. Pure
    transformation — the wrapped check adds no requests of its own; the
    only extra traffic is the single probe. No winner (probe gated out,
    errored, or failed) -> check_fn is returned as-is.

    ctx: scan context (only .L logging is used, optional). Results are
    cached on ctx as _waf_chain_<bank_key> so repeated chaining for the
    same WAF does not re-probe.
    """
    bank_key = wafbank.normalize_vendor(waf)
    cache_key = "_waf_chain_%s" % bank_key
    winner = getattr(ctx, cache_key, None) if ctx is not None else None
    log = getattr(ctx, "L", None) if ctx is not None else None

    if winner is None and target_req_builder is not None and marker:
        _f, d = test_bypasses(target_req_builder, marker, waf=waf,
                              log=log, gate=gate)
        winner = d.get("winner")
        if winner is not None:
            winner = dict(winner)
            winner["confirmed"] = bool(d.get("confirmed"))
        if ctx is not None:
            try:
                setattr(ctx, cache_key, winner)
            except Exception:
                pass

    if not winner:
        return check_fn

    transform = None
    for name, fn in select_bypasses(waf):
        if name == winner.get("strategy"):
            transform = fn
            break

    def wrapped(payload=None, *args, **kwargs):
        if isinstance(payload, str) and transform is not None:
            try:
                payload = transform(payload)
            except Exception:
                pass
        return check_fn(payload, *args, **kwargs)

    wrapped.__name__ = getattr(check_fn, "__name__", "check") + "_wafchained"
    wrapped._wafchain = {"strategy": winner.get("strategy"),
                         "confirmed": bool(winner.get("confirmed"))}
    return wrapped
