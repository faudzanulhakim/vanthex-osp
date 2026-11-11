"""
test_rtagent.py — hermetic tests for the autonomous red-team agent loop.

No network: the executor is a fake callable returning canned evidence.
Covers: gate refusal, happy-path confirmation with auth_ok, unauthorized
downgrade, budget enforcement (max_iterations + max_requests), trace
auditability, and mutation generation on partial outcomes.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offensive import rtagent  # noqa: E402


def make_plans(n=3):
    return [
        {"id": f"p{i}", "class": ["sqli", "ssrf", "idor"][i % 3],
         "steps": [f"/target{i}?q=probe"], "proof_pattern": r"PTKPROOF\d+",
         "severity": ["CRITICAL", "HIGH", "MEDIUM"][i % 3], "impact": 90 - i * 10}
        for i in range(n)
    ]


def fake_executor(proof="PTKPROOF12345", auth=True, status="ran"):
    calls = []
    def ex(plan):
        calls.append(plan["id"])
        return {"status": status, "auth_ok": auth,
                "evidence": f"response contains {proof} in body",
                "note": "canned executor response"}
    ex.calls = calls
    return ex


class TestGate(unittest.TestCase):
    def test_gate_refusal(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PTK_RTAGENT", None)
            a = rtagent.RedTeamAgent(make_plans(), fake_executor())
            with self.assertRaises(PermissionError):
                a.run()
            self.assertEqual(a.agent_trace, [])

    def test_gate_env_open(self):
        with mock.patch.dict(os.environ, {"PTK_RTAGENT": "1"}):
            a = rtagent.RedTeamAgent(make_plans(), fake_executor())
            out = a.run()
            self.assertEqual(len(out["executed_plans"]), 3)

    def test_gate_approve_opt(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PTK_RTAGENT", None)
            a = rtagent.RedTeamAgent(make_plans(), fake_executor())
            out = a.run(opts={"approve": True})
            self.assertEqual(out["confirmed"], ["p0", "p1", "p2"])


class TestLoop(unittest.TestCase):
    def setUp(self):
        os.environ.pop("PTK_RTAGENT", None)

    def test_confirmed_with_auth(self):
        a = rtagent.RedTeamAgent(make_plans(), fake_executor())
        out = a.run(opts={"approve": True})
        self.assertEqual(out["confirmed"], ["p0", "p1", "p2"])
        self.assertEqual(out["partial"], [])
        self.assertEqual(out["followups_generated"], [])

    def test_unauthorized_not_recorded_success(self):
        # proof evidence present but executor did not assert auth_ok:
        # must NOT be confirmed, no execution success recorded
        a = rtagent.RedTeamAgent(make_plans(),
                                 fake_executor(auth=False))
        out = a.run(opts={"approve": True})
        self.assertEqual(out["confirmed"], [])
        self.assertIn("verification=manual-required", out["trace"][0]["outcome"])

    def test_partial_generates_mutations(self):
        # executor never produces the proof -> partial + follow-ups
        a = rtagent.RedTeamAgent(make_plans(),
                                 fake_executor(proof="nothing matched"))
        out = a.run(opts={"approve": True})
        self.assertEqual(out["confirmed"], [])
        # 3 original plans + 3 mutations each = 12 partial executions
        self.assertEqual(len(out["partial"]), 12)
        # exactly 3 direct follow-ups per partial original
        self.assertEqual(len(out["followups_generated"]), 9)
        self.assertTrue({f["parent"] for f in out["followups_generated"]}
                        == {"p0", "p1", "p2"})
        tags = {f["mutation"] for f in out["followups_generated"]}
        self.assertTrue(tags <= {"widen-scope", "vary-payload",
                                 "chain-sibling"})
        # each partial plan generated 2-3 mutations
        for f in out["followups_generated"]:
            self.assertTrue(f["id"].startswith(f["parent"] + "::"))

    def test_mutation_quality_labels(self):
        a = rtagent.RedTeamAgent(
            [{"id": "x1", "class": "cmdi", "steps": ["/x?c=echo"],
              "proof_pattern": "PTKCMD", "severity": "HIGH", "impact": 70}],
            fake_executor(proof="nope"))
        out = a.run(opts={"approve": True})
        self.assertEqual(len(out["followups_generated"]), 3)
        self.assertIn("verification=differential", out["trace"][0]["outcome"])
        self.assertEqual({f["mutation"] for f in out["followups_generated"]},
                         {"widen-scope", "vary-payload", "chain-sibling"})

    def test_max_iterations_budget(self):
        plans = make_plans(20)  # far more plans than iterations
        a = rtagent.RedTeamAgent(plans, fake_executor(),
                                 budget={"max_iterations": 4})
        out = a.run(opts={"approve": True})
        self.assertEqual(len(out["executed_plans"]), 4)
        self.assertEqual(out["executed_plans"], ["p0", "p1", "p2", "p3"])
        # trace records the budget stop
        self.assertIn("budget-exhausted", out["trace"][-1]["outcome"])

    def test_max_requests_per_iteration(self):
        plans = [{"id": "big", "class": "ssrf",
                  "steps": [f"/s{i}" for i in range(50)],
                  "proof_pattern": "NOPE", "severity": "HIGH", "impact": 80}]
        a = rtagent.RedTeamAgent(plans, fake_executor(proof="nope"),
                                 budget={"max_requests": 5})
        out = a.run(opts={"approve": True})
        self.assertIn("request budget reached",
                      out["trace"][0]["outcome"])

    def test_cancel_check_between_steps(self):
        a = rtagent.RedTeamAgent(make_plans(), fake_executor())
        state = {"n": 0}
        def cancel():
            state["n"] += 1
            return state["n"] > 1  # cancel after first observation
        out = a.run(cancel_check=cancel, opts={"approve": True})
        self.assertEqual(len(out["executed_plans"]), 1)
        self.assertIn("cancelled", out["trace"][-1]["outcome"])

    def test_executor_exception_is_observed(self):
        def boom(plan):
            raise RuntimeError("network down")
        a = rtagent.RedTeamAgent(make_plans(), boom)
        out = a.run(opts={"approve": True})
        self.assertEqual(out["confirmed"], [])
        self.assertIn("executor raised", out["trace"][0]["outcome"])

    def test_mutation_plans_become_executable(self):
        # a mutation whose payload variation hits gets confirmed later
        seq = {"n": 0}
        def ex(plan):
            seq["n"] += 1
            if "::" in plan["id"] and plan["mutation"] == "vary-payload":
                return {"status": "ran", "auth_ok": True,
                        "evidence": "matched PTKPROOF99 now",
                        "note": "mutation succeeded"}
            return {"status": "ran", "auth_ok": True, "evidence": "miss",
                    "note": "no proof"}
        a = rtagent.RedTeamAgent(
            [{"id": "m1", "class": "idor", "steps": ["/obj/1"],
              "proof_pattern": r"PTKPROOF\d+", "severity": "HIGH",
              "impact": 60}], ex,
            budget={"max_iterations": 5})
        out = a.run(opts={"approve": True})
        self.assertEqual(out["confirmed"], ["m1::vary-payload"])


class TestTrace(unittest.TestCase):
    def test_trace_auditability(self):
        a = rtagent.RedTeamAgent(make_plans(2), fake_executor())
        out = a.run(opts={"approve": True})
        self.assertEqual(len(out["trace"]), 3)  # 2 iterations + done entry
        for t in out["trace"]:
            self.assertIn("iteration", t)
            self.assertIn("chosen", t)
            self.assertIn("reason", t)
            self.assertIn("outcome", t)
            self.assertIn("next_mutation", t)
        self.assertIn("highest expected impact",
                      out["trace"][0]["reason"])
        self.assertIn("queue exhausted", out["trace"][-1]["reason"])
        # summarize produces English text
        s = rtagent.summarize(out)
        self.assertIn("decision trace", s)
        self.assertIn("totals", s)


if __name__ == "__main__":
    unittest.main()
