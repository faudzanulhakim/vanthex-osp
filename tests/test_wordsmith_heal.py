#!/usr/bin/env python3
"""Hermetic tests for WordSmith contextual wordlist + self-healing probes.
AUTHORIZED TESTING ONLY. No live HTTP — fake client serves a path table.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import wordsmith
import vulnscan2


class _Resp:
    def __init__(self, status, body=""):
        self.status = status
        self.body = body
        self.headers = {}

    def hdr(self, name, default=""):
        return default


class _FakeClient:
    """Path-table HTTP stub."""

    def __init__(self, table):
        self.table = table          # path -> (status, body)
        self.calls = []

    def get(self, path, **kw):
        self.calls.append(path)
        st, body = self.table.get(path, (404, "not found"))
        return _Resp(st, body)

    def post(self, path, **kw):
        return self.get(path)


def _fake_ctx(table, opts=None):
    class _Ctx:
        pass

    c = _Ctx()
    c.target = "http://127.0.0.1:1"
    c.client = _FakeClient(table)
    c.opts = opts or {}
    c.log = []
    c.technologies = []
    c.L = c.log.append
    c.cancelled = lambda: False
    c.is_missing = lambda r: r.status in (404, 410)
    return c


# ----------------------------------------------------------------- wordsmith
class TestContextualWordlist(unittest.TestCase):
    def test_tech_keywords_present(self):
        wl = wordsmith.contextual_wordlist("https://acme.example.com",
                                           [{"name": "WordPress 6.0"}])
        joined = "\n".join(wl)
        for needle in ("/wp-admin", "/wp-login.php", "/wp-content/",
                       "/wp-json/", "/xmlrpc.php"):
            self.assertIn(needle, joined)
        wl_php = wordsmith.contextual_wordlist("https://acme.example.com",
                                               ["php"])
        self.assertIn("/index.php", wl_php)
        self.assertIn("/config.php", wl_php)
        wl_asp = wordsmith.contextual_wordlist("https://acme.example.com",
                                               ["ASP.NET"])
        self.assertIn("/default.aspx", wl_asp)
        self.assertIn("/web.config", wl_asp)

    def test_domain_parts_present(self):
        wl = wordsmith.contextual_wordlist("https://appname.example.com/", [])
        joined = "\n".join(wl)
        for needle in ("/appname", "/appname-api", "/appname-backup",
                       "api.appname", "appname-api", "appname-admin",
                       "dev.appname", "staging.appname", "appname-v2"):
            self.assertIn(needle, joined)

    def test_year_based_entries(self):
        wl = wordsmith.contextual_wordlist("https://acme.example.com", [])
        joined = "\n".join(wl)
        for y in (2024, 2025, 2026):
            self.assertIn(f"/backup{y}", joined)
        self.assertIn("/backup2026.bak", joined)
        self.assertIn("/backup2025.sql", joined)
        self.assertIn("/acme2026.old", joined)

    def test_base_paths_and_bounded(self):
        wl = wordsmith.contextual_wordlist("https://acme.example.com", [])
        self.assertIn("/.env", wl)
        self.assertIn("/.git/config", wl)
        self.assertLessEqual(len(wl), 1500)
        self.assertGreaterEqual(len(wl), 200)  # curated base set intact

    def test_deterministic_and_unique(self):
        a = wordsmith.contextual_wordlist("https://acme.example.com",
                                          ["wordpress", "php"],
                                          extra_seeds=["/custom-seed"])
        b = wordsmith.contextual_wordlist("https://acme.example.com",
                                          ["wordpress", "php"],
                                          extra_seeds=["/custom-seed"])
        self.assertEqual(a, b)
        self.assertEqual(len(a), len(set(a)))
        self.assertIn("/custom-seed", a)

    def test_subdomain_wordlist_form(self):
        subs = wordsmith.subdomain_candidates("https://appname.example.com")
        self.assertIn("api.appname.example.com", subs)
        self.assertIn("dev.appname.example.com", subs)
        self.assertIn("appname-api.appname.example.com", subs)


# --------------------------------------------------------------------- heal
class TestHealVariants(unittest.TestCase):
    def test_trailing_slash_and_case(self):
        vs = vulnscan2.heal_variants("/admin")
        self.assertIn("/admin/", vs)
        self.assertIn("/api/admin", vs)
        self.assertIn("/v1/admin", vs)
        self.assertNotIn("/admin", vs)  # original never included

    def test_kebab_camel(self):
        vs = vulnscan2.heal_variants("/api/user-profile")
        self.assertIn("/api/userProfile", vs)
        vs2 = vulnscan2.heal_variants("/api/userProfile")
        self.assertIn("/api/user-profile", vs2)

    def test_plural_singular(self):
        self.assertIn("/users", vulnscan2.heal_variants("/user"))
        self.assertIn("/user", vulnscan2.heal_variants("/users"))

    def test_suffix_variants(self):
        vs = vulnscan2.heal_variants("/admin/login")
        self.assertIn("/admin/login.php", vs)
        self.assertIn("/admin/login.html", vs)
        # already has an extension -> no suffix spam
        vs2 = vulnscan2.heal_variants("/index.php")
        self.assertNotIn("/index.php.php", vs2)

    def test_deterministic(self):
        self.assertEqual(vulnscan2.heal_variants("/a/b-C"),
                         vulnscan2.heal_variants("/a/b-C"))


class TestHealPath(unittest.TestCase):
    def test_moved_endpoint_heals(self):
        ctx = _fake_ctx({"/admin/": (200, "<form>type='password'</form>")})
        h = vulnscan2.heal_path(ctx, "/admin")
        self.assertIsNotNone(h)
        variant, r = h
        self.assertEqual(variant, "/admin/")
        self.assertEqual(r.status, 200)
        self.assertEqual(ctx.client.calls, ["/admin/"])
        self.assertTrue(any("[heal] /admin -> /admin/ (200)" in l
                            for l in ctx.log))

    def test_all_404_returns_none(self):
        ctx = _fake_ctx({})
        self.assertIsNone(vulnscan2.heal_path(ctx, "/nope"))

    def test_budget_respected(self):
        ctx = _fake_ctx({})
        vulnscan2.heal_path(ctx, "/x", variants_budget=3)
        self.assertEqual(len(ctx.client.calls), 3)

    def test_ptk_heal_zero_disables(self):
        ctx = _fake_ctx({"/admin/": (200, "hi")})
        with mock.patch.dict(os.environ, {"PTK_HEAL": "0"}):
            self.assertIsNone(vulnscan2.heal_path(ctx, "/admin"))
        self.assertEqual(ctx.client.calls, [])

    def test_log_cap(self):
        # many healed endpoints -> at most a few [heal] lines
        table = {f"/p{i}/": (200, "x") for i in range(10)}
        ctx = _fake_ctx(table)
        for i in range(10):
            vulnscan2.heal_path(ctx, f"/p{i}")
        heal_lines = [l for l in ctx.log if l.startswith("[heal]")]
        self.assertLessEqual(len(heal_lines), 5)


class TestWire(unittest.TestCase):
    def test_admin_panel_via_variant(self):
        # /admin 404s but the panel really lives at /admin/ (moved) —
        # c_admin_panels must still yield a finding via heal_path.
        ctx = _fake_ctx({
            "/admin": (404, "not found"),
            "/admin/": (200, "<html><input type='password'></html>"),
        })
        findings = []
        vulnscan2.c_admin_panels(ctx, findings.append)
        self.assertTrue(any(f["title"].startswith("Admin/login panel exposed")
                            for f in findings), ctx.log)
        hit = [f for f in findings
               if f["title"].startswith("Admin/login panel exposed")][0]
        self.assertEqual(hit["location"], "/admin/")

    def test_admin_panel_no_heal_env_off(self):
        ctx = _fake_ctx({
            "/admin": (404, "not found"),
            "/admin/": (200, "<html><input type='password'></html>"),
        })
        with mock.patch.dict(os.environ, {"PTK_HEAL": "0"}):
            findings = []
            vulnscan2.c_admin_panels(ctx, findings.append)
        self.assertEqual(findings, [])

    def test_no_false_positive_when_all_missing(self):
        ctx = _fake_ctx({})
        findings = []
        vulnscan2.c_admin_panels(ctx, findings.append)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
