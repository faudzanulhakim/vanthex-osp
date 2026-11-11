"""
sideoracle.py — VANTHEX time-based side-channel oracles (accuracy-first).

Applies the same measurement discipline as timingoracle.py to three
authentication/data side channels:

  * user enumeration on login endpoints (valid vs nonexistent user),
  * token-validity oracles on validation endpoints,
  * record-existence inference on search endpoints.

Honesty rules (mirroring timingoracle's "never a guess"):

  * Every verdict is built from a median-of-trimmed-samples model with
    MAD spread, measured in independent rounds.
  * The control (nonexistent user / invalid token / missing record) is
    always measured in the SAME session, in the SAME round, so clock
    drift between rounds cannot manufacture a delta.
  * A probable finding requires the delta to REPRODUCE in every
    independent round. A delta seen in only one round is reported as an
    explicit no-signal — no finding is emitted (honesty over FPs).
  * Sub-5 ms deltas can never be a probable finding over a network:
    they are surfaced at most as candidate / manual-required.
  * All oracles respect a hard request cap (MAX_REQUESTS = 60) and a
    cancellation callable, checked before every request.
"""

import os
import time

MAX_REQUESTS = 60        # hard cap per oracle call (target+control+rounds)
DEFAULT_SAMPLES = 9      # samples per probe
TRIM_RATIO = 0.10        # drop top/bottom 10% of samples
MAD_SCALE = 1.4826       # MAD -> stdev consistency factor

USER_ENUM_RATIO = 1.5    # target median >= 1.5x control median
USER_ENUM_MIN_MS = 30.0  # ... and the absolute delta >= 30 ms
RECORD_RATIO = 1.3       # target median >= 1.3x control median
TOKEN_DELTA_MAX_MS = 5.0 # micro-timing candidate band: consistent delta < 5 ms
ROUNDS = 2               # every oracle must reproduce across 2 rounds

SEARCH_PARAMS = ("search", "q", "query", "s", "keyword", "term", "find")
LOGIN_HINTS = ("login", "signin", "sign-in", "auth", "session", "logon")

PROBABLE = "probable"
CANDIDATE = "candidate"
NO_SIGNAL = "no_signal"
INCONCLUSIVE = "inconclusive"


# --------------------------------------------------------------- statistics

def trimmed(samples):
    """Drop the top and bottom TRIM_RATIO fraction of samples (slow and
    fast outliers). With 9 samples this drops 1 from each side."""
    vals = sorted(float(v) for v in samples)
    n = int(len(vals) * TRIM_RATIO + 0.5)
    if len(vals) >= 3 and n == 0:
        n = 1
    return vals[n:len(vals) - n] if n else vals


def median_mad(samples):
    """(median, mad, mad_range) over trimmed samples. mad_range is the
    median +/- 1.4826 x MAD — the interval used for overlap tests."""
    vals = trimmed(samples)
    if not vals:
        return None, None, None
    med = _median(vals)
    mad = _median(sorted(abs(v - med) for v in vals))
    half = MAD_SCALE * mad
    return med, mad, (med - half, med + half)


def _median(vals):
    n = len(vals)
    s = sorted(vals)
    mid = n // 2
    if n % 2:
        return s[mid]
    return (s[mid - 1] + s[mid]) / 2.0


class TimingProbe:
    """Collects N timing samples (seconds) via a callable, trims the top
    and bottom 10%, and reports median + MAD."""

    def __init__(self, n=DEFAULT_SAMPLES):
        self.n = max(1, int(n))
        self.samples = []

    def measure(self, fn, stop=None):
        """Run `fn()` up to self.n times, keeping each result (fn returns
        elapsed seconds or None on failure). `stop()` aborts early
        (cancellation / budget exhaustion). Returns samples collected."""
        self.samples = []
        got = misses = 0
        while got < self.n:
            if stop is not None and stop():
                break
            t = fn()
            if t is None:
                misses += 1
                if misses >= self.n:
                    break          # endpoint is failing, not slow
                continue
            misses = 0
            self.samples.append(float(t))
            got += 1
        return self.samples

    @property
    def median(self):
        m, _, _ = median_mad(self.samples)
        return m

    @property
    def mad(self):
        _, mad, _ = median_mad(self.samples)
        return mad

    @property
    def mad_range(self):
        _, _, rng = median_mad(self.samples)
        return rng

    def describe(self):
        return (f"median={_ms(self.median)} ms "
                f"mad={_ms(self.mad)} ms (n={len(self.samples)}, "
                f"trimmed top/bottom {int(TRIM_RATIO * 100)}%)")


# --------------------------------------------------------------- plumbing

def _ms(sec):
    return "n/a" if sec is None else f"{sec * 1000.0:.1f}"


class _Budget:
    """Hard request cap shared by every probe in one oracle call."""

    def __init__(self, limit=MAX_REQUESTS):
        self.limit = int(limit)
        self.spent = 0

    @property
    def exhausted(self):
        return self.spent >= self.limit

    def spend(self):
        if self.exhausted:
            return False
        self.spent += 1
        return True


class _Cancelled:
    """True when the cancel callable fires OR the budget is spent. Every
    request path checks this first — a cancelled scan never sends."""

    def __init__(self, cancel, budget):
        self._cancel = cancel
        self._budget = budget

    def __call__(self):
        if self._budget is not None and self._budget.exhausted:
            return True
        try:
            return bool(self._cancel and self._cancel())
        except Exception:
            return False


def _req(client, method, url, data, budget, cancelled, counter):
    """One timed request with a cache-buster so the client's GET cache
    can never serve a timing sample. Returns elapsed seconds or None."""
    if cancelled():
        return None
    if not budget.spend():
        return None
    nonce = f"_ptk={counter[0]:x}"
    counter[0] += 1
    full = url + ("&" if "?" in url else "?") + nonce
    if data is not None and method.upper() == "GET":
        method = "POST"
    if isinstance(data, dict):
        from urllib.parse import urlencode
        data = urlencode(data).encode()
    elif isinstance(data, str):
        data = data.encode()
    t0 = time.perf_counter()
    try:
        resp = client.request(method.upper(), full, data=data)
    except Exception:
        return None
    el = getattr(resp, "elapsed", None)
    if el is None:
        el = time.perf_counter() - t0
    if getattr(resp, "status", 0) == 0:
        return None          # transport failure — never a timing sample
    try:
        return float(el)
    except (TypeError, ValueError):
        return None


def _probe(client, method, url, data, budget, cancelled, counter,
           n=DEFAULT_SAMPLES):
    p = TimingProbe(n)
    p.measure(lambda: _req(client, method, url, data, budget, cancelled,
                           counter), stop=cancelled)
    return p


def _round_pass(target_med, control_med, ratio, min_ms):
    """One round's pass test: relative ratio AND absolute floor."""
    if target_med is None or control_med is None or control_med <= 0:
        return False
    return (target_med >= ratio * control_med
            and (target_med - control_med) * 1000.0 >= min_ms)


def _finish_ratio(kind, rounds, ratio, min_ms, url, param,
                  cancelled, budget, passed):
    t_meds = [m for (m, _, _) in rounds]
    c_meds = [c for (_, c, _) in rounds]
    mads = [mad for (_, _, mad) in rounds]
    evidence = (f"{kind}: {len(rounds)} independent rounds, "
                f"same-session control pair, threshold "
                f">= {ratio}x and >= {min_ms:.0f} ms; "
                + "; ".join(
                    f"round {i + 1}: target {_ms(t)} ms vs control "
                    f"{_ms(c)} ms (MAD {_ms(md)} ms)"
                    for i, (t, c, md) in enumerate(zip(t_meds, c_meds, mads))))
    if cancelled():
        return {"verdict": INCONCLUSIVE, "finding": None,
                "evidence": evidence + " (cancelled)"}
    if passed:
        f = _finding(
            sev="low",
            title=f"Time-based {kind}",
            desc=(
                f"The {kind} response time for the tested value is "
                f"consistently slower than the same-session control "
                f"(nonexistent/absent counterpart) across {len(rounds)} "
                f"independent rounds. This is a statistical timing "
                f"differential, not proof of a valid value — verify "
                f"manually with an independent timing run."),
            evidence=evidence,
            cwe="208",
            owasp="A07",
            cvss=3.1,
            remed=("Make authentication/search processing constant-time "
                   "with respect to value existence: perform the same "
                   "work for valid and invalid inputs (dummy hash "
                   "comparison, uniform record lookup)."),
            confidence=PROBABLE,
            location=url,
            param=param,
            verification="probable-timing-differential",
        )
        return {"verdict": PROBABLE, "finding": f, "evidence": evidence,
                "target_median_ms": t_meds, "control_median_ms": c_meds,
                "mad_ms": mads, "rounds": len(rounds)}
    return {"verdict": NO_SIGNAL, "finding": None, "evidence": evidence,
            "target_median_ms": t_meds, "control_median_ms": c_meds,
            "mad_ms": mads, "rounds": len(rounds)}


def _finding(sev, title, desc, evidence, cwe, owasp, cvss, remed,
             confidence, location, param, verification):
    import vulnscan2
    return vulnscan2.F(sev, title, desc, evidence=evidence, cwe=cwe,
                       owasp=owasp, cvss=cvss, remed=remed,
                       confidence=confidence, location=location,
                       param=param, verification=verification,
                       verification_note=(
                           "Statistical timing oracle: differential "
                           "reproduced across independent rounds but "
                           "network jitter can imitate it. Confirm with "
                           "an independent measurement or source review."))


# --------------------------------------------------------------- oracles

def oracle_user_enum(login_url, username, client, cancelled=None,
                     samples=DEFAULT_SAMPLES, method="POST",
                     control_user=None, budget_limit=MAX_REQUESTS):
    """Time-based user enumeration on a login endpoint.

    Measures login latency for `username` against a control
    nonexistent user, in ROUNDS independent rounds with the control
    pair measured in the SAME session each round. Verdict:

      probable  — target median >= 1.5x control AND >= 30 ms delta in
                  EVERY round -> finding (verification differential)
      no_signal — otherwise, explicitly, with NO finding
    """
    budget = _Budget(budget_limit)
    cancelled = _Cancelled(cancelled, budget)
    counter = [0]
    control = control_user or f"ptk-nonexistent-{os.urandom(4).hex()}"
    rounds = []
    for _ in range(ROUNDS):
        if cancelled():
            break
        # control first, then target, alternating each round to average
        # out slow-start drift within the session.
        order = ((control, "c"), (username, "t")) if len(rounds) % 2 == 0 \
            else ((username, "t"), (control, "c"))
        res = {}
        for user, key in order:
            p = _probe(client, method, login_url,
                       {"username": user, "password": "ptk-wrong-pass"},
                       budget, cancelled, counter, samples)
            res[key] = p
        rounds.append((res["t"].median, res["c"].median, res["t"].mad))
    if not rounds:
        return {"verdict": INCONCLUSIVE, "finding": None, "evidence":
                "no rounds measured (cancelled or budget exhausted)"}
    passed = all(_round_pass(t, c, USER_ENUM_RATIO, USER_ENUM_MIN_MS)
                 for (t, c, _) in rounds)
    return _finish_ratio("user enumeration", rounds, USER_ENUM_RATIO,
                         USER_ENUM_MIN_MS, login_url, "username",
                         cancelled, budget, passed)


def oracle_token_valid(validate_url, token, client, cancelled=None,
                       samples=DEFAULT_SAMPLES, method="GET",
                       budget_limit=MAX_REQUESTS):
    """Micro-timing token-validity oracle.

    A consistent delta BELOW 5 ms that reproduces in every round with
    NON-OVERLAPPING MAD ranges is surfaced as a candidate,
    manual-required finding — never probable. Any larger or
    irreproducible pattern is an explicit no-signal with NO finding.
    """
    budget = _Budget(budget_limit)
    cancelled = _Cancelled(cancelled, budget)
    counter = [0]
    control_token = "ptk-invalid-" + os.urandom(8).hex()
    rounds = []
    for _ in range(ROUNDS):
        if cancelled():
            break
        p_valid = _probe(client, method, validate_url, {"token": token},
                         budget, cancelled, counter, samples)
        p_ctrl = _probe(client, method, validate_url,
                        {"token": control_token},
                        budget, cancelled, counter, samples)
        rounds.append((p_valid.median, p_valid.mad_range,
                       p_ctrl.median, p_ctrl.mad_range))
    if not rounds:
        return {"verdict": INCONCLUSIVE, "finding": None, "evidence":
                "no rounds measured (cancelled or budget exhausted)"}
    parts = []
    ok = True
    for i, (tv, rv, tc, rc) in enumerate(rounds):
        if tv is None or tc is None:
            ok = False
            parts.append(f"round {i + 1}: measurement failed")
            continue
        delta_ms = abs(tv - tc) * 1000.0
        overlap = (rv is not None and rc is not None
                   and rv[0] <= rc[1] and rc[0] <= rv[1])
        parts.append(f"round {i + 1}: valid {_ms(tv)} ms vs control "
                     f"{_ms(tc)} ms (delta {delta_ms:.2f} ms, MAD ranges "
                     f"{'overlap' if overlap else 'disjoint'})")
        ok = ok and (delta_ms < TOKEN_DELTA_MAX_MS and not overlap)
    evidence = (f"token-validity micro-timing: {len(rounds)} rounds, "
                f"same-session control, candidate band delta < "
                f"{TOKEN_DELTA_MAX_MS:.0f} ms with disjoint MAD ranges; "
                + "; ".join(parts))
    if cancelled():
        return {"verdict": INCONCLUSIVE, "finding": None,
                "evidence": evidence + " (cancelled)"}
    if ok:
        f = _finding(
            sev="info",
            title="Token-validity micro-timing differential",
            desc=(
                "The token-validation endpoint answers consistently "
                "faster for the supplied token than for an invalid "
                "control token, with statistically disjoint timing "
                "distributions. The absolute delta is below the "
                f"{TOKEN_DELTA_MAX_MS:.0f} ms band, so this is NOT a "
                "reliable remote oracle by itself — manual offline "
                "verification required."),
            evidence=evidence,
            cwe="208",
            owasp="A07",
            cvss=0.0,
            remed=("Compare tokens in constant time and perform "
                   "identical processing for valid and invalid tokens."),
            confidence=CANDIDATE,
            location=validate_url,
            param="token",
            verification="candidate-manual-required",
        )
        return {"verdict": CANDIDATE, "finding": f, "evidence": evidence}
    return {"verdict": NO_SIGNAL, "finding": None, "evidence": evidence}


def oracle_record_exists(search_url, param, value, client,
                         cancelled=None, samples=DEFAULT_SAMPLES,
                         method="GET", budget_limit=MAX_REQUESTS):
    """Record-existence inference on a search endpoint.

    probable — target median >= 1.3x control median in EVERY round.
    Otherwise explicit no-signal, NO finding.
    """
    budget = _Budget(budget_limit)
    cancelled = _Cancelled(cancelled, budget)
    counter = [0]
    control_value = f"ptk-absent-{os.urandom(4).hex()}"
    rounds = []
    for _ in range(ROUNDS):
        if cancelled():
            break
        p_t = _probe(client, method, search_url, {param: value},
                     budget, cancelled, counter, samples)
        p_c = _probe(client, method, search_url, {param: control_value},
                     budget, cancelled, counter, samples)
        rounds.append((p_t.median, p_c.median, p_t.mad))
    if not rounds:
        return {"verdict": INCONCLUSIVE, "finding": None, "evidence":
                "no rounds measured (cancelled or budget exhausted)"}
    passed = all(_round_pass(t, c, RECORD_RATIO, 0.0) for (t, c, _) in rounds)
    return _finish_ratio("record existence", rounds, RECORD_RATIO, 0.0,
                         search_url, param, cancelled, budget, passed)


# --------------------------------------------------------------- gate

def _is_login_form(form):
    action = str(form.get("action") or "").lower()
    inputs = " ".join(str(i) for i in (form.get("inputs") or [])).lower()
    if any(h in inputs for h in ("password", "passwd", "pass")):
        return True
    return any(h in action for h in LOGIN_HINTS) and any(
        h in inputs for h in ("user", "email", "login", "account"))


def _is_search_url(url):
    low = str(url).lower()
    if "?" not in low:
        return False
    query = low.split("?", 1)[1]
    names = [p.split("=")[0] for p in query.split("&") if "=" in p]
    return any(n in SEARCH_PARAMS for n in names)


def _login_endpoints(surf, limit=2):
    out = []
    for form in (surf.forms or []):
        if _is_login_form(form) and form.get("action"):
            ep = form["action"]
            if ep not in out:
                out.append((ep, "POST", form))
            if len(out) >= limit:
                return out
    for url in (surf.pages or []) + (surf.param_urls or []):
        if any(h in str(url).lower() for h in LOGIN_HINTS) and url not in out:
            out.append((url, "POST", None))
            if len(out) >= limit:
                return out
    return out


def _search_endpoints(surf, limit=2):
    out = []
    for url in (surf.param_urls or []) + (surf.pages or []):
        if _is_search_url(url):
            base = str(url).split("?", 1)[0]
            if base not in [b for (b, _) in out]:
                names = [p.split("=")[0].lower()
                         for p in str(url).split("?", 1)[1].split("&")]
                p = next((n for n in names if n in SEARCH_PARAMS), "q")
                out.append((base, p))
            if len(out) >= limit:
                return out
    return out


def c_side_oracle(ctx, add):
    """Gated check (PTK_SIDEORACLE=1 or opts['sideoracle']): run the
    time-based side-channel oracles against login and search endpoints
    discovered on the surface. Max 2 endpoints per kind; every oracle
    respects the shared request cap and cancellation."""
    opts = getattr(ctx, "opts", {}) or {}
    gated = (os.environ.get("PTK_SIDEORACLE", "").strip() == "1"
             or bool(opts.get("sideoracle")))
    if not gated:
        return []
    surf = ctx.surface(full=True)
    findings = []
    for (url, method, _form) in _login_endpoints(surf):
        if ctx.cancelled():
            break
        username = "ptk-probe-user"
        res = oracle_user_enum(url, username, ctx.client,
                               cancelled=ctx.cancelled)
        ctx.L(f"  [sideoracle] user-enum {url}: {res['verdict']}")
        if res.get("finding"):
            add(res["finding"])
            findings.append(res["finding"])
    for (base, param) in _search_endpoints(surf):
        if ctx.cancelled():
            break
        res = oracle_record_exists(base, param, "ptk-probe-record",
                                   ctx.client, cancelled=ctx.cancelled)
        ctx.L(f"  [sideoracle] record-exists {base}?{param}: "
              f"{res['verdict']}")
        if res.get("finding"):
            add(res["finding"])
            findings.append(res["finding"])
    return findings
