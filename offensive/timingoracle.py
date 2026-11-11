"""
timingoracle.py — VANTHEX WS1 (v1.7.0, Accuracy 2): a statistical timing
oracle for blind time-based injection verdicts.

Original re-implementation of the measurement discipline audited in
vanthex-sqlmap-source-audit.md (technique and constants studied from a
mature open-source scanner; no third-party code is copied — the model
below is written from the audit's parameter sheet):

  * The null model is built from FALSE-condition response times (the
    parameter answering a condition that cannot trigger a delay).
  * Minimum 30 samples before any verdict (MIN_SAMPLES); samples are
    kept in a rolling window of 200, trimmed to the newest 100.
  * Slow outliers are trimmed before statistics: cutoff at
    median + 10 x 1.4826 x MAD, capped at the second-largest deviation
    when the largest exceeds the cutoff (outlier trim ONLY — the
    verdict itself never uses median/MAD).
  * Delayed verdict: elapsed > mean + 7 x stdev AND the excess over the
    mean is at least 0.5 s (MIN_DELAY_EXCESS).
  * A model whose stdev exceeds 0.5 s is too noisy to judge:
    every verdict is INCONCLUSIVE (never a guess).
  * A delay is CONFIRMED only by the triple step: delay payload fires,
    the zero-delay twin does NOT fire, the delay payload fires again.

Verdicts are strings: "delayed" (confirmed), "not_delayed",
"inconclusive". Nothing here performs I/O: callers pass timing samples
and callables, which keeps the module fully unit-testable offline.
"""

import statistics
import time

MIN_SAMPLES = 30          # false-condition samples required for a model
MAX_WINDOW = 200          # rolling window capacity
TRIM_WINDOW = 100         # window trimmed back to this many samples
STDEV_COEFF = 7           # verdict threshold = mean + 7 * stdev
MIN_DELAY_EXCESS = 0.5    # a real delay must exceed the mean by >= 0.5 s
MAX_MODEL_STDEV = 0.5     # model stdev above this = too noisy to judge
MAD_CUTOFF_COEFF = 10.0   # outlier cutoff = median + 10 * 1.4826 * MAD
MAD_SCALE = 1.4826        # MAD -> stdev consistency factor

DELAYED = "delayed"
NOT_DELAYED = "not_delayed"
INCONCLUSIVE = "inconclusive"


def strip_outliers(samples):
    """Trim slow outliers exactly per the audited rule: deviations from
    the median larger than 10 x 1.4826 x MAD are dropped; when the
    single largest deviation exceeds that cutoff, the cap falls back to
    the second-largest deviation. Only the slow side is trimmed."""
    vals = list(samples)
    if len(vals) < 10:
        return vals
    median = statistics.median(vals)
    devs = sorted(abs(v - median) for v in vals)
    mad = statistics.median(devs)
    cutoff = MAD_CUTOFF_COEFF * MAD_SCALE * mad
    if devs[-1] > cutoff and len(devs) > 1:
        cutoff = devs[-2]
    return [v for v in vals if (v - median) <= cutoff]


class TimingModel:
    """Null-distribution model for one (target, parameter) built from
    false-condition timings."""

    def __init__(self, samples=None):
        self.samples = []
        self.mean = 0.0
        self.stdev = 0.0
        for s in samples or ():
            self.add(s)

    # ------------------------------------------------------------ build
    def add(self, elapsed):
        if elapsed is None or elapsed < 0:
            return
        self.samples.append(float(elapsed))
        if len(self.samples) > MAX_WINDOW:
            self.samples = self.samples[-TRIM_WINDOW:]
        self._recompute()

    def collect(self, fetch, cancelled=None, min_samples=MIN_SAMPLES):
        """Pull timings from `fetch()` (returns elapsed seconds or None)
        until `min_samples` are held. Returns the number of samples in
        the model. Stops early on cancellation or repeated failures."""
        misses = 0
        while len(self.samples) < min_samples:
            if cancelled and cancelled():
                break
            t = fetch()
            if t is None:
                misses += 1
                if misses >= 5:
                    break
                continue
            misses = 0
            self.add(t)
        return len(self.samples)

    def _recompute(self):
        trimmed = strip_outliers(self.samples)
        if not trimmed:
            self.mean, self.stdev = 0.0, 0.0
            return
        self.mean = statistics.fmean(trimmed)
        self.stdev = statistics.stdev(trimmed) if len(trimmed) > 1 else 0.0

    # ---------------------------------------------------------- verdict
    @property
    def ready(self):
        return len(self.samples) >= MIN_SAMPLES

    @property
    def noisy(self):
        return self.stdev > MAX_MODEL_STDEV

    @property
    def threshold(self):
        return self.mean + STDEV_COEFF * self.stdev

    def is_delayed(self, elapsed):
        """Single-shot delayed test against the model."""
        if elapsed is None:
            return False
        return (elapsed - self.mean >= MIN_DELAY_EXCESS
                and elapsed > self.threshold)

    def judge(self, elapsed):
        """Verdict for one measured response time."""
        if not self.ready or self.noisy or elapsed is None:
            return INCONCLUSIVE
        return DELAYED if self.is_delayed(elapsed) else NOT_DELAYED

    def confirm(self, fire, cancelled=None):
        """Triple-step confirmation. `fire(delay: bool)` performs one
        request — with the delay payload when True, with its zero-delay
        twin when False — and returns the elapsed seconds (or None on
        request failure). CONFIRMED (DELAYED) requires: fire, no-fire,
        fire. A clean non-delayed first shot is NOT_DELAYED; anything
        ambiguous is INCONCLUSIVE."""
        if not self.ready or self.noisy:
            return INCONCLUSIVE
        seq = []
        for want_delay in (True, False, True):
            if cancelled and cancelled():
                return INCONCLUSIVE
            t = fire(want_delay)
            if t is None:
                return INCONCLUSIVE
            seq.append(self.is_delayed(t))
        if seq == [True, False, True]:
            return DELAYED
        if seq[0] is False:
            return NOT_DELAYED
        return INCONCLUSIVE

    def describe(self):
        return (f"timing model: n={len(self.samples)} "
                f"mean={self.mean:.3f}s stdev={self.stdev:.3f}s "
                f"threshold={self.threshold:.3f}s"
                + (" (TOO NOISY — inconclusive)" if self.noisy else ""))


# ============================================================ accuracy v3
# (round 2): blind time-based confirmation. A bare 0.3 s wobble over the
# baseline is network noise, never a verdict: the delay must reproduce
# consistently AND scale with the requested sleep before it can confirm.
SCALE_FACTOR = 2.5        # (a) each attempt >= 2.5x the baseline
MIN_ABS_EXCESS = 0.8      # (a) ... and >= baseline + 0.8 s
CONSISTENCY_REPS = 3      # (b) ALL delay attempts must pass
SCALING_RATIO = 1.4       # (c) 2 s variant >= 1.4x the 1 s variant
MIN_SLEEP_S = 1           # (a) payload must request >= 1 s of sleep
ELEV_RATIO = 1.8          # weak-signal gate that makes rule (d) apply
ELEV_ABS = 0.15

CANDIDATE_TIME_NOTE = ("Elevated response time detected but scaling test "
                       "failed - likely network noise. Manual verification "
                       "required.")


def _measure(R, payload):
    """One request; returns (elapsed, response). Uses the client's own
    elapsed when present, otherwise falls back to wall-clock timing."""
    t0 = time.time()
    try:
        resp = R(payload)
    except Exception:
        return None, None
    el = getattr(resp, "elapsed", None)
    if el is None:
        el = time.time() - t0
    try:
        return float(el), resp
    except (TypeError, ValueError):
        return None, resp


def _fmt(times):
    return "/".join(f"{t:.2f}s" for t in times)


def blind_time_confirm(R, baseline_payload, delay_fn, cancelled=None):
    """Confirm a blind time-based injection with the round-2 rules.

    `R(payload)` performs one request; `delay_fn(seconds)` returns the
    payload that requests that many seconds of sleep (must be >=
    MIN_SLEEP_S — a sub-second payload can never prove a delay). Returns
    a dict:
      verdict    'confirmed' | 'candidate' | 'not_delayed' | 'inconclusive'
      evidence   baseline, every delay attempt timing and the scaling pair
      note       candidate-downgrade verification note ('' otherwise)
      last_resp  the last response seen (for the caller's FP guard)
    """
    out = {"verdict": "inconclusive", "evidence": "", "note": "",
           "last_resp": None}
    base_times = []
    base_min = None
    for _ in range(2):
        if cancelled and cancelled():
            return out
        t, resp = _measure(R, baseline_payload)
        out["last_resp"] = resp
        if t is not None:
            base_times.append(t)
            base_min = t if base_min is None else min(base_min, t)
    if not base_times:
        return out
    base_mean = statistics.fmean(base_times)

    times2, times1 = [], []
    for seconds, acc in ((2, times2), (1, times1)):
        payload = delay_fn(max(seconds, MIN_SLEEP_S))
        for _ in range(CONSISTENCY_REPS):
            if cancelled and cancelled():
                return out
            t, resp = _measure(R, payload)
            out["last_resp"] = resp
            if t is not None:
                acc.append(t)

    def _strict(t):
        return (t >= SCALE_FACTOR * base_mean
                and t >= base_mean + MIN_ABS_EXCESS)

    consistent = (len(times2) == CONSISTENCY_REPS
                  and all(_strict(t) for t in times2))
    m2 = statistics.fmean(times2) if times2 else None
    m1 = statistics.fmean(times1) if times1 else None
    scaling = bool(m2 and m1 and m2 >= SCALING_RATIO * m1)

    evidence = (f"baseline {base_mean:.2f}s (min {base_min:.2f}s); "
                f"sleep-2 attempts: {_fmt(times2)}; "
                f"scaling pair: sleep-1 mean "
                f"{m1:.2f}s vs sleep-2 mean {m2:.2f}s "
                f"(ratio {(m2 / m1):.2f}, need {SCALING_RATIO:.2f})"
                if m1 and m2 else
                f"baseline {base_mean:.2f}s (min {base_min:.2f}s); "
                f"sleep-2 attempts: {_fmt(times2)}")

    if consistent and scaling:
        out.update(verdict="confirmed", evidence=evidence)
        return out

    # (d) timing looks elevated but failed the consistency and/or scaling
    # rule -> candidate with manual-required, never CONFIRMED.
    elevated = any(t >= ELEV_RATIO * base_min and t >= base_min + ELEV_ABS
                   for t in times2)
    if elevated:
        out.update(verdict="candidate", evidence=evidence,
                   note=CANDIDATE_TIME_NOTE)
    else:
        out["evidence"] = evidence
        out["verdict"] = "not_delayed"
    return out
