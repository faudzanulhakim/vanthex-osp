"""
diffconfirm.py — VANTHEX WS2 (v1.7.0, Accuracy 2): differential boolean
confirmation with dynamic-content markings, a learned match ratio, a
four-step verdict with a WAF guard, and a mandatory arithmetic proof
battery for the `confirmed` tier.

Original re-implementation of the confirmation discipline audited in
vanthex-sqlmap-source-audit.md (technique + constants studied from a
mature open-source scanner; no third-party code is copied):

  * Dynamic markings: the same page is fetched twice; regions that
    change between the two fetches are dynamic and are projected out
    before any comparison. Matching blocks of <= 40 chars are dropped
    too, and every kept block is trimmed by a 20-char anchor margin.
  * The oracle learns its `matchRatio` from a FALSE-prime shot.
  * Read bands: ratio > 0.98 -> True; ratio < 0.02 -> False; otherwise
    (ratio - matchRatio) > 0.05 decides. A candidate page carrying a
    database/framework error that the template does not carry is
    indeterminate (None) — never a boolean.
  * Verdict order: (1) sanity — the FALSE page must differ from both
    the original page and the heuristic-probe page; (2) the TRUE shot
    must read True; (3) a re-shot FALSE must read False; (4) WAF
    guard — a TRUE shot answered with a blocking status while the
    FALSE shot is a plain 2xx means the "difference" is the WAF,
    not the query: the point is rejected as a false positive.
  * Arithmetic Proof Battery: fresh random integers r1 < r2 < r3 are
    embedded as arithmetic conditions; five assertions must ALL hold
    (r1=r1 True, r1=r3 False, r3=r2 False, invalid syntax not-True,
    r2=r2 True). One failed assertion discards the point as a false
    positive — page-shape tricks (reflection, length games) cannot
    pass fresh arithmetic.

Nothing here performs I/O: the caller supplies a `probe(value)`
callable returning an object with `.status` and `.body`, which keeps
the module fully unit-testable offline.
"""

import difflib
import random
import string

UPPER_RATIO = 0.98        # above: page reads as the TRUE page
LOWER_RATIO = 0.02        # below: page reads as the FALSE page
DIFF_TOLERANCE = 0.05     # mid-band: (ratio - matchRatio) must exceed
ANCHOR = 20               # chars trimmed from each end of a kept block
MIN_BLOCK = 2 * ANCHOR    # matching blocks <= 40 chars are dropped
BLOCKING_STATUSES = (401, 403, 406, 419, 429, 501, 503)

# Framework type-casting exception fragments: when the heuristic probe
# makes the application complain it cannot CAST the value, the
# parameter is converted to a number before reaching any query and is
# not string-injectable (triage signal, per the audit).
CASTING_SIGNATURES = (
    "numberformatexception", "formatexception", "format exception",
    "invalid literal for int", "could not be resolved to an int",
    "cannot convert the value", "failed to convert the value",
    "invalid input syntax for type integer",
    "invalid input syntax for type bigint",
)


def heuristic_payload(rng=None):
    """Random 10-char string guaranteed to contain exactly one single
    quote and one double quote (heuristic pre-screen probe)."""
    rng = rng or random
    chars = [rng.choice(string.ascii_letters + string.digits)
             for _ in range(8)]
    chars.insert(rng.randrange(len(chars) + 1), "'")
    chars.insert(rng.randrange(len(chars) + 1), '"')
    return "".join(chars)


def heuristic_triage(status, body, template_body, error_signatures=()):
    """Classify a heuristic-probe response: "dbms_error" (the probe
    reached a database — worth differential testing), "casting" (the
    application casts the parameter — not string-injectable), or
    "clean"."""
    low = (body or "").lower()
    tlow = (template_body or "").lower()
    for sig in CASTING_SIGNATURES:
        if sig in low and sig not in tlow:
            return "casting"
    for sig in error_signatures:
        if sig in low and sig not in tlow:
            return "dbms_error"
    return "clean"


def _stable_segments(t1, t2):
    """Project two fetches of the same page onto their stable skeleton:
    the matching blocks longer than MIN_BLOCK, anchor-trimmed."""
    if not t1:
        return []
    sm = difflib.SequenceMatcher(None, t1, t2, autojunk=False)
    segs = []
    for i, _j, size in sm.get_matching_blocks():
        if size > MIN_BLOCK:
            segs.append(t1[i + ANCHOR:i + size - ANCHOR])
    return segs


class DifferentialOracle:
    """Reads candidate pages as True / False / None against a learned
    template + FALSE-prime pair."""

    def __init__(self, template_body, template_body2, false_body,
                 error_signatures=()):
        self.template = template_body or ""
        self.segments = _stable_segments(self.template,
                                         template_body2 or "")
        self._template_low = self.template.lower()
        self.error_signatures = tuple(s.lower()
                                      for s in error_signatures)
        self.template_projection = self.project(self.template)
        self.match_ratio = self.ratio(false_body or "")

    def project(self, body):
        """Reduce a page to its stable-segment projection (dynamic
        regions removed). Falls back to the raw body when the page had
        no stable skeleton (fully chaotic page)."""
        if not self.segments:
            return body or ""
        page = body or ""
        parts, pos = [], 0
        for seg in self.segments:
            idx = page.find(seg, pos)
            if idx >= 0:
                parts.append(seg)
                pos = idx + len(seg)
        return "".join(parts)

    def ratio(self, body):
        a = self.project(body)
        b = self.template_projection
        if a == b:
            return 1.0
        if not a or not b:
            return 0.0
        return difflib.SequenceMatcher(None, a[:20000], b[:20000],
                                       autojunk=False).ratio()

    def read(self, body, status=None):
        """True / False / None (indeterminate on error pages)."""
        low = (body or "").lower()
        for sig in self.error_signatures:
            if sig in low and sig not in self._template_low:
                return None
        r = self.ratio(body)
        if r > UPPER_RATIO:
            return True
        if r < LOWER_RATIO:
            return False
        return (r - self.match_ratio) > DIFF_TOLERANCE


class BooleanProver:
    """Runs the four-step differential verdict and the arithmetic
    proof battery over a caller-supplied probe.

    probe(value) -> object with .status and .body (or None on failure).
    make_condition(kind, r1, r2, r3) -> parameter value embedding the
    named arithmetic condition in the caller's injection syntax.
    """

    def __init__(self, probe, template_body, template_body2,
                 true_value, false_value, heur_value,
                 error_signatures=()):
        self.probe = probe
        self.true_value = true_value
        self.false_value = false_value
        self.heur_value = heur_value
        self.template_body = template_body or ""
        f0 = probe(false_value)
        self._f0 = f0
        self.oracle = DifferentialOracle(
            template_body, template_body2,
            f0.body if f0 else "", error_signatures)
        self.detail = []

    def _read(self, value):
        r = self.probe(value)
        if r is None:
            return None, None
        return r, self.oracle.read(r.body, r.status)

    def run_verdict(self):
        """Four-step verdict. Returns one of: "differential_ok",
        "no_difference", "fp_waf", "indeterminate"."""
        o = self.oracle
        # Step 1 — sanity: FALSE page differs from original AND from
        # the heuristic-probe page (raw pages compared, as audited).
        heur = self.probe(self.heur_value)
        if self._f0 is None or heur is None:
            return "indeterminate"

        def _same(a, b):
            a, b = a or "", b or ""
            if a == b:
                return True
            if not a or not b:
                return False
            return difflib.SequenceMatcher(
                None, a[:20000], b[:20000], autojunk=False).ratio() > 0.98

        if _same(self._f0.body, self.template_body):
            self.detail.append("FALSE page identical to original page")
            return "no_difference"
        if _same(self._f0.body, heur.body):
            self.detail.append("FALSE page identical to heuristic page")
            return "no_difference"
        # Step 2 — TRUE shot must read True.
        rt, read_t = self._read(self.true_value)
        if rt is None or read_t is None:
            return "indeterminate"
        if read_t is not True:
            self.detail.append("TRUE shot did not read True")
            return "no_difference"
        # Step 3 — re-shot FALSE must read False.
        rf, read_f = self._read(self.false_value)
        if rf is None or read_f is None:
            return "indeterminate"
        if read_f is not False:
            self.detail.append("re-shot FALSE did not read False")
            return "no_difference"
        # Step 4 — WAF guard: TRUE blocked while FALSE is a plain 2xx
        # means the difference is the WAF answering, not the query.
        if (rt.status in BLOCKING_STATUSES
                and rf.status and 200 <= rf.status < 300):
            self.detail.append(
                f"TRUE shot blocked (HTTP {rt.status}) while FALSE "
                f"shot is HTTP {rf.status} — difference attributed to "
                "a WAF, point rejected as false positive")
            return "fp_waf"
        self.detail.append(
            f"differential proven (matchRatio learned "
            f"{o.match_ratio:.3f}; TRUE reads True, FALSE reads False)")
        return "differential_ok"

    # ---------------------------------------------------- proof battery
    def run_battery(self, make_condition, rounds=1, rng=None):
        """Arithmetic Proof Battery. Returns (passed, report_lines).
        Every assertion of every round must hold; one failure discards
        the point as a false positive."""
        rng = rng or random.Random()
        rounds = max(1, min(3, rounds))
        report = []
        for rnd in range(rounds):
            r1 = rng.randrange(100, 900)
            r2 = rng.randrange(r1 + 1, r1 + 900)
            r3 = rng.randrange(r2 + 1, r2 + 900)
            cases = [
                ("eq_true", f"{r1}={r1}", True),
                ("eq_false_a", f"{r1}={r3}", False),
                ("eq_false_b", f"{r3}={r2}", False),
                ("invalid", f"{r3} {r2}", "not_true"),
                ("eq_true_b", f"{r2}={r2}", True),
            ]
            for kind, label, expect in cases:
                value = make_condition(kind, r1, r2, r3)
                r = self.probe(value)
                if r is None:
                    report.append(f"round {rnd + 1} {label}: "
                                  "request failed — battery aborted")
                    return False, report
                read = self.oracle.read(r.body, r.status)
                if expect is True:
                    ok = read is True
                elif expect is False:
                    ok = read is False
                else:  # invalid syntax: anything except a True read
                    ok = read is not True
                report.append(f"round {rnd + 1} {label}: read="
                              f"{read} expected={expect} -> "
                              f"{'ok' if ok else 'FAIL'}")
                if not ok:
                    return False, report
        return True, report
