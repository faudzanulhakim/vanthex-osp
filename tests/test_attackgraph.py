"""Hermetic tests for the attack graph module (attackgraph.py) and its
integration into vulnscan2 / report.py / docx_report.py — no network."""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attackgraph as AG


def F(title, sev="HIGH", desc="", **kw):
    return dict({"severity": sev, "title": title, "description": desc,
                 "cvss": 0.0, "confidence": "confirmed"}, **kw)


def sample_findings():
    return [
        F("Hardcoded API key in JavaScript bundle", "HIGH",
          "api_key exposed", location="/app.js"),
        F("OTP brute force not rate limited", "MEDIUM",
          "otp verification allows brute force"),
        F("SQL injection in search parameter", "CRITICAL",
          "sql injection allows reading the database"),
        F("SSRF in report exporter", "HIGH",
          "server-side request forgery reaches internal service"),
        F("Exposed admin panel without authentication", "CRITICAL",
          "admin dashboard exposed"),
    ]


class TestChainConstruction(unittest.TestCase):
    def test_secret_to_otp_brute_to_atr(self):
        g = AG.build_attack_graph(sample_findings())
        found = [c for c in g["chains"]
                 if c["final_impact"] == "Account takeover"
                 and any("API key" in t for t in c["titles"])
                 and any("OTP" in t for t in c["titles"])]
        self.assertTrue(found, "secret -> OTP brute -> account takeover chain missing")
        c = found[0]
        self.assertLess(c["titles"].index(
            [t for t in c["titles"] if "API key" in t][0]),
            c["titles"].index([t for t in c["titles"] if "OTP" in t][0]))
        self.assertIn("nodes", c)
        self.assertTrue(all(isinstance(n, str) for n in c["nodes"]))

    def test_terminal_chains_present(self):
        g = AG.build_attack_graph(sample_findings())
        impacts = {c["final_impact"] for c in g["chains"]}
        self.assertIn("Internal service access", impacts)     # SSRF
        self.assertIn("Sensitive data access", impacts)       # SQLi
        self.assertIn("Account takeover", impacts)            # secret/admin
        self.assertIn("Foothold / persistence", impacts)      # injection
        # structure
        self.assertTrue(g["nodes"] and g["edges"])
        for e in g["edges"]:
            self.assertIn("from", e); self.assertIn("to", e)
            self.assertIn("relation", e)
        for n in g["nodes"]:
            self.assertIn("type", n); self.assertIn("severity", n)

    def test_no_findings_empty_graph(self):
        for empty in ([], None, [F("Totally unrelated bug")]):
            g = AG.build_attack_graph(empty)
            self.assertEqual(g["chains"], [])
            self.assertEqual(g["top_impact"], 0)


class TestImpactScoring(unittest.TestCase):
    def test_deeper_chain_scores_higher(self):
        f = [F("Leaked session token", "HIGH", "session token leaked"),
             F("Weak OTP rate limiting", "MEDIUM", "otp brute force"),
             F("Account takeover via OTP", "HIGH", "auth bypass takeover")]
        g = AG.build_attack_graph(f)
        scores = [c["impact_score"] for c in g["chains"]]
        self.assertTrue(scores)
        self.assertTrue(g["chains"][0]["impact_score"] >= scores[-1])
        # a 2-hop chain (secret->ATR) scores lower than the 3-hop one
        if any(len(c["nodes"]) >= 3 for c in g["chains"]):
            deep = max(c["impact_score"] for c in g["chains"]
                       if len(c["nodes"]) >= 3)
            shallow = max((c["impact_score"] for c in g["chains"]
                           if len(c["nodes"]) < 3), default=0)
            self.assertGreater(deep, shallow)
        self.assertTrue(all(0 <= s <= 100 for s in scores))

    def test_top_attack_paths_order_and_limit(self):
        paths = AG.top_attack_paths(sample_findings(), limit=2)
        self.assertEqual(len(paths), 2)
        self.assertGreaterEqual(paths[0]["impact_score"],
                                paths[1]["impact_score"])


class TestCaps(unittest.TestCase):
    def _bulk(self, n):
        return [F(f"Leaked token #{i}", "HIGH", "api_key token leaked")
                for i in range(n)]

    def test_node_cap(self):
        g = AG.build_attack_graph(self._bulk(60))
        self.assertLessEqual(len(g["nodes"]), AG.MAX_NODES)
        self.assertLessEqual(len(g["nodes"]), 40)

    def test_edge_cap(self):
        g = AG.build_attack_graph(self._bulk(60))
        self.assertLessEqual(len(g["edges"]), AG.MAX_EDGES)
        self.assertLessEqual(len(g["edges"]), 60)

    def test_malformed_input_never_raises(self):
        g = AG.build_attack_graph([None, "junk", 42, F("SQL injection", desc="sql")])
        self.assertIsInstance(g, dict)


class TestReportIntegration(unittest.TestCase):
    def _scan(self, graph=None):
        scan = {"id": "abc123", "target": "https://example.test",
                "profile": "active-deep", "scan_type": "vulnscan",
                "overall_risk": "HIGH",
                "result": json.dumps({"risk_score": 70,
                                      "attack_graph": graph})}
        return scan

    def test_html_report_contains_attack_paths(self):
        import report
        g = AG.build_attack_graph(sample_findings())
        html = report.render_report(self._scan(g),
                                    sample_findings(), lang="en")
        self.assertIn("Attack Paths", html)
        self.assertIn("(impact ", html)
        self.assertIn("-&gt;", html)

    def test_html_report_graceful_without_graph(self):
        import report
        html = report.render_report(self._scan(None),
                                    sample_findings(), lang="en")
        self.assertNotIn("Attack Paths", html)

    def test_docx_report_contains_attack_paths(self):
        import docx_report
        import tempfile
        g = AG.build_attack_graph(sample_findings())
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "r.docx")
            docx_report.generate_docx(self._scan(g), sample_findings(), p)
            with open(p, "rb") as fh:
                import zipfile
                z = zipfile.ZipFile(fh)
                doc = z.read("word/document.xml").decode("utf-8")
        self.assertIn("Attack Paths", doc)
        self.assertIn("(impact ", doc)


class TestEnvGate(unittest.TestCase):
    def test_env_off_disables_attackgraph(self):
        import vulnscan2
        with mock.patch.dict(os.environ, {"PTK_ATTACKGRAPH": "0"}):
            log = []
            g = vulnscan2._attack_graph_for(sample_findings(), log.append)
            self.assertIsNone(g)

    def test_env_default_on(self):
        import vulnscan2
        env = {k: v for k, v in os.environ.items() if k != "PTK_ATTACKGRAPH"}
        with mock.patch.dict(os.environ, env, clear=True):
            log = []
            g = vulnscan2._attack_graph_for(sample_findings(), log.append)
            self.assertIsNotNone(g)
            self.assertTrue(any("[attackgraph]" in m for m in log))


if __name__ == "__main__":
    unittest.main()
