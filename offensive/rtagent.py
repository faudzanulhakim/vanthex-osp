"""
rtagent.py — autonomous red-team agent loop (pure planning/loop logic).

AUTHORIZED TESTING ONLY — heuristics only, no external LLM calls.

RedTeamAgent(plan_iter, executor, budget) implements a decide -> act ->
observe loop over a prioritized queue of attack plans (dicts with
id/class/steps/proof_pattern, as built from scan findings by
chainexec.build_chains or equivalent):

  1. Each iteration selects the highest-expected-impact UNEXECUTED plan
     (impact score = plan impact + severity weight; already-executed and
     exhausted plans are skipped).
  2. The plan runs via the INJECTED executor callable. The agent module
     itself never touches the network — all execution lives in the
     executor, and the executor MUST refuse to act without an explicit
     approve token (fail-closed, same model as chainexec.execute_chain).
     The agent additionally refuses to record a confirmed success unless
     the executor's result carries auth_ok=True: an executor that reports
     proof evidence without asserting authorization is treated as
     "unauthorized" and the outcome is downgraded to manual-required.
  3. Evidence is matched against the plan's proof_pattern:
       - full match + auth_ok  -> CONFIRMED (verification 'executed-proof')
       - no match              -> PARTIAL, generates 2-3 follow-up
                                  mutation plans by class heuristics
                                  (widen scope, vary payload family,
                                  chain with a discovered sibling)
  4. Budget: budget dict {max_iterations (default 12), max_requests}
     caps the loop and per-iteration request count. A cancel_check
     callable passed to run() is honored between steps.
  5. Full decision trace: every decision appends a dict to agent_trace
     (iteration, chosen plan, reason, outcome, next mutation) so the
     operator can audit exactly what the agent would do.

GATE: run() refuses with PermissionError unless the environment variable
PTK_RTAGENT=1 is set OR opts={'approve': True} is passed. Default: the
agent never executes anything. run() returns
  {'executed_plans', 'confirmed', 'partial', 'trace', 'followups_generated'}.
Verification labels on outcomes are English: 'executed-proof' for
confirmed plans, 'differential' for reproduced anomalies/partial
reproductions, 'manual-required' otherwise.
"""
import os as _os
import re as _re

MAX_ITERATIONS = 12
MAX_REQUESTS = 20

SEV_WEIGHTS = {"CRITICAL": 45, "HIGH": 35, "MEDIUM": 25, "LOW": 15, "INFO": 5}

GATE_ENV = "PTK_RTAGENT"

# follow-up mutation families per plan class; each entry is
# (mutation tag, one-line English rationale). At most 2-3 emitted per
# partial outcome.
_MUTATIONS = {
    "sqli": [
        ("widen-scope", "Widen the injection to additional parameters and "
                        "endpoints in the same component to map the extent "
                        "of the injectable surface."),
        ("vary-payload", "Vary the payload family (boolean oracle, UNION "
                         "probe, time delay) in case the first syntax was "
                         "filtered but the sink remains injectable."),
        ("chain-sibling", "Chain the injection with a sibling data-exposure "
                          "finding (e.g. dump an identifier usable for "
                          "access-control tests)."),
    ],
    "cmdi": [
        ("widen-scope", "Widen command execution attempts to every other "
                        "parameter of the affected endpoint."),
        ("vary-payload", "Vary the command separator family (;, |, &&, "
                         "newline, backtick) to bypass separator filtering."),
        ("chain-sibling", "Chain confirmed command execution with a sibling "
                          "internal-service finding for lateral movement "
                          "scoping."),
    ],
    "ssrf": [
        ("widen-scope", "Widen the SSRF probe to internal host ranges and "
                        "additional schemes (file, gopher) beyond the first "
                        "hit."),
        ("vary-payload", "Vary the URL encoding family (double-encoding, "
                         "decimal IP, DNS rebinding names) to bypass "
                         "allow-list checks."),
        ("chain-sibling", "Chain the SSRF with a discovered internal "
                          "service finding to fetch its unauthenticated "
                          "endpoint."),
    ],
    "idor": [
        ("widen-scope", "Widen object-ID enumeration around the observed id "
                        "to measure cross-user exposure breadth."),
        ("vary-payload", "Vary identifier shape (uuid, email, sequential "
                         "int, base64 id) in case only one representation "
                         "is unprotected."),
        ("chain-sibling", "Chain the object access with a sibling "
                          "privilege-escalation finding (e.g. modify the "
                          "read-access object)."),
    ],
    "xss": [
        ("widen-scope", "Widen reflection probing to other parameters and "
                        "pages that share the rendering path."),
        ("vary-payload", "Vary the payload family (event handlers, SVG, "
                         "template breakout, encoding tricks) against the "
                         "observed filter."),
        ("chain-sibling", "Chain the reflection with a sibling session or "
                          "CSRF finding to demonstrate impact."),
    ],
    "generic": [
        ("widen-scope", "Widen the probe to neighboring endpoints of the "
                        "same component."),
        ("vary-payload", "Vary the payload encoding to test filter-based "
                         "rather than structural protection."),
    ],
}


def _gate_open(opts):
    """Operator gate: PTK_RTAGENT=1 env or explicit approve=True opt."""
    if _os.environ.get(GATE_ENV) == "1":
        return True
    if isinstance(opts, dict) and opts.get("approve") is True:
        return True
    return False


def _normalize(plans):
    """Coerce findings/plan dicts into the internal plan shape (pure,
    never raises). Accepts raw scan findings (title/severity/location)
    or ready plans (id/class/steps/proof_pattern)."""
    out = []
    try:
        for i, p in enumerate(plans or []):
            if not isinstance(p, dict):
                continue
            pid = str(p.get("id") or p.get("name") or f"plan-{i + 1}")
            pclass = str(p.get("class") or p.get("type") or "generic").lower()
            steps = p.get("steps") or [p.get("location") or "/"]
            proof = str(p.get("proof_pattern") or p.get("expected_proof")
                        or "PROOF")
            sev = str(p.get("severity", "INFO")).upper()
            impact = p.get("impact")
            if not isinstance(impact, (int, float)):
                impact = min(100, SEV_WEIGHTS.get(sev, 10) + 30)
            out.append({
                "id": pid,
                "class": pclass,
                "steps": [str(s) for s in steps],
                "proof_pattern": proof,
                "severity": sev,
                "impact": int(impact),
            })
        out.sort(key=lambda q: -q["impact"])
    except Exception:
        pass
    return out


class RedTeamAgent:
    """Autonomous decide -> act -> observe red-team loop (heuristic only).

    The agent is pure loop/planning logic: every side effect goes through
    the injected ``executor(plan)`` callable, which MUST enforce its own
    authorization (refuse without an approve token, fail-closed). The
    agent additionally checks the executor's ``auth_ok`` flag and refuses
    to record a confirmed success without it.
    """

    def __init__(self, plan_iter, executor, budget=None):
        self.executor = executor
        self.plans = _normalize(plan_iter)
        budget = budget or {}
        self.max_iterations = int(budget.get("max_iterations", MAX_ITERATIONS))
        self.max_requests = int(budget.get("max_requests", MAX_REQUESTS))
        self.agent_trace = []
        self.executed = set()
        self.confirmed = []
        self.partial = []
        self.followups_generated = []
        self._sibling_seen = False

    # -------------------------------------------------------------- decisions
    def _select_plan(self):
        """Pick the highest-expected-impact unexecuted plan."""
        for p in self.plans:
            if p["id"] not in self.executed:
                return p
        return None

    def _mutations_for(self, plan, result):
        """2-3 follow-up mutation plans for a partial outcome, by class."""
        fam = _MUTATIONS.get(plan["class"], _MUTATIONS["generic"])
        outs = []
        for tag, why in fam[:3]:
            fid = f"{plan['id']}::{tag}"
            outs.append({
                "id": fid,
                "class": plan["class"],
                "steps": list(plan["steps"]),
                "proof_pattern": plan["proof_pattern"],
                "severity": plan["severity"],
                "impact": max(5, plan["impact"] - 10),
                "mutation": tag,
                "rationale": why,
                "parent": plan["id"],
            })
        return outs

    def _trace(self, **kw):
        self.agent_trace.append(kw)

    # ------------------------------------------------------------------- loop
    def run(self, cancel_check=None, opts=None):
        """Execute the loop. Operator-gated: raises PermissionError unless
        PTK_RTAGENT=1 is set in the environment or opts={'approve': True}."""
        if not _gate_open(opts):
            raise PermissionError(
                "rtagent is operator-gated: set PTK_RTAGENT=1 or pass "
                "opts={'approve': True} to authorize the loop "
                "(the executor must additionally enforce its own approve "
                "token — this module only plans)")
        executed_plans = []
        iterations = 0
        while iterations < self.max_iterations:
            plan = self._select_plan()
            if plan is None:
                self._trace(iteration=iterations, chosen=None,
                            reason="queue exhausted: every plan has been "
                                   "executed",
                            outcome="done", next_mutation=None)
                break
            if callable(cancel_check):
                try:
                    if cancel_check():
                        self._trace(iteration=iterations, chosen=plan["id"],
                                    reason="cancel_check returned True before "
                                           "selection was acted on",
                                    outcome="cancelled", next_mutation=None)
                        break
                except Exception:
                    pass
            iterations += 1
            reason = (f"highest expected impact among unexecuted plans "
                      f"(impact={plan['impact']}, class={plan['class']}, "
                      f"severity={plan['severity']})")
            # act — all side effects live inside the executor
            reqs = min(self.max_requests, max(1, len(plan["steps"])))
            try:
                result = self.executor(plan) or {}
            except Exception as e:
                result = {"status": "error", "auth_ok": False,
                          "evidence": "", "note": f"executor raised: {e}"}
            auth_ok = bool(result.get("auth_ok"))
            evidence = str(result.get("evidence", "") or "")
            matched = bool(_re.search(plan["proof_pattern"], evidence))
            status = str(result.get("status", ""))
            outcome_note = str(result.get("note", "") or "")

            if matched and auth_ok:
                verification = "executed-proof"
                outcome = "confirmed"
                self.confirmed.append(plan["id"])
                next_mut = None
            elif matched and not auth_ok:
                # proof-shaped evidence without the executor asserting
                # authorization: never recorded as success
                verification = "manual-required"
                outcome = "unauthorized"
                next_mut = None
            elif status == "refused":
                verification = "manual-required"
                outcome = "refused"
                next_mut = None
            else:
                verification = "differential"
                outcome = "partial"
                self.partial.append(plan["id"])
                # first-generation plans generate follow-ups; mutations of
                # mutations are capped (no exponential queue growth)
                next_mut = (self._mutations_for(plan, result)
                            if "mutation" not in plan else None)
                self.followups_generated.extend(next_mut or [])
                if reqs >= self.max_requests:
                    outcome_note = (outcome_note +
                                    " per-iteration request budget reached; "
                                    "mutations queued, not executed this "
                                    "iteration").strip()
            self.executed.add(plan["id"])
            executed_plans.append(plan["id"])
            self._trace(iteration=iterations - 1, chosen=plan["id"],
                        reason=reason,
                        outcome=f"{outcome} (verification={verification}; "
                                f"requests={reqs}; note={outcome_note or 'none'})",
                        next_mutation=(next_mut[0]["id"] if next_mut else None))
            # mutations enter the queue at the END (lower priority than
            # original high-impact plans) and are themselves executable
            self.plans.extend(next_mut or [])
            if callable(cancel_check):
                try:
                    if cancel_check():
                        self._trace(iteration=iterations, chosen=None,
                                    reason="cancel_check returned True after "
                                           "observation",
                                    outcome="cancelled", next_mutation=None)
                        break
                except Exception:
                    pass
        else:
            self._trace(iteration=iterations, chosen=None,
                        reason=f"max_iterations={self.max_iterations} "
                               "budget reached",
                        outcome="budget-exhausted", next_mutation=None)
        return {
            "executed_plans": executed_plans,
            "confirmed": list(self.confirmed),
            "partial": list(self.partial),
            "trace": list(self.agent_trace),
            "followups_generated": list(self.followups_generated),
        }


def summarize(run_out):
    """Human-readable English summary of a run() result."""
    if not run_out or not run_out.get("trace"):
        return "The red-team agent ran no iterations."
    lines = ["Red-team agent decision trace (operator-gated loop):"]
    for t in run_out["trace"]:
        lines.append(f"- iteration {t.get('iteration')}: "
                     f"chosen={t.get('chosen')} — {t.get('reason')}")
        lines.append(f"    outcome: {t.get('outcome')}")
        if t.get("next_mutation"):
            lines.append(f"    next mutation: {t['next_mutation']}")
    lines.append(f"totals: confirmed={len(run_out.get('confirmed', []))}, "
                 f"partial={len(run_out.get('partial', []))}, "
                 f"followups={len(run_out.get('followups_generated', []))}")
    return "\n".join(lines)
