"""
tests/test_darkradar.py — hermetic tests for darkradar.py (passive
dark-web/exposure radar). Fully offline: fetchers are monkeypatched /
injected stubs; no link source is ever fetched.

Run: .venv/bin/python -m pytest tests/test_darkradar.py -q
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offensive import darkradar as dr  # noqa: E402

DOMAIN = "example.com"


# ------------------------------------------------------------ link builders
def test_paste_links_build_and_quote_domain():
    links = dr.build_paste_links(DOMAIN)
    assert links, "expected paste-site links"
    sources = {l["source"] for l in links}
    assert {"pastebin-google", "psbdmp-ws"} <= sources
    for l in links:
        assert DOMAIN in l["url"]
        # domain appears inside quoted search term
        assert "%22example.com%22" in l["url"] or '"example.com"' in l["url"]


def test_gist_dork_links_cover_secret_keywords():
    links = dr.build_gist_dork_links(DOMAIN)
    kws = {l["keyword"] for l in links}
    assert {"email", "api_key", "password"} <= kws
    assert all(DOMAIN in l["url"] for l in links)
    assert all(l["url"].startswith("https://") for l in links)


# ------------------------------------------------------------ email harvest
CRAWL = [
    {"url": f"https://{DOMAIN}/team.html",
     "html": "<div>Contact alice@%s or bob@%s</div>" % (DOMAIN, DOMAIN)},
    {"url": f"https://{DOMAIN}/leak.html",
     "html": "dump: alice@%s:S3cr3t-Passw0rd! | carol@%s:hunter2" % (
         DOMAIN, DOMAIN)},
]


def test_crawl_email_harvest():
    emails, pairs = dr.harvest_emails(CRAWL)
    assert f"alice@{DOMAIN}" in emails and f"bob@{DOMAIN}" in emails
    assert f"carol@{DOMAIN}" in emails


def test_credential_pair_masked_raw_password_never_leaks():
    emails, pairs = dr.harvest_emails(CRAWL)
    joined = json.dumps(pairs)
    assert f"alice@{DOMAIN}" in joined
    assert "S3cr3t-Passw0rd!" not in joined, "raw password leaked!"
    assert "hunter2" not in joined, "raw password leaked!"
    assert all(":" in p and "*" in p for p in pairs)


# ------------------------------------------------------------ breach probe
def test_unconfigured_breach_api_is_manual_required_with_instructions():
    findings, emap = dr.run_darkradar(DOMAIN, fetcher=_boom_fetcher)
    titles = [f["title"] for f in findings]
    assert any("Not Configured" in t for t in titles)
    f = next(f for f in findings if "Not Configured" in f["title"])
    assert f["verification"] == "manual-required"
    assert "haveibeenpwned" in f["description"] or "url" in f["description"]
    assert "breach-api" not in emap["sources_checked"]
    assert emap["requests_made"] == 0


def _boom_fetcher(*a, **k):  # any network attempt is a test failure
    raise AssertionError("network call attempted: %r" % (a,))


def test_configured_breach_api_probed_once_and_reported():
    calls = []

    def fetch(url, timeout=0, headers=None):
        calls.append(url)
        return 200, {}, json.dumps({"breaches": [
            {"name": "MegaLeak2019"}, {"name": "Other"}]}).encode()

    findings, emap = dr.run_darkradar(DOMAIN, fetcher=fetch,
                                      breach_opts={
                                          "url": "https://breachx.internal/api",
                                          "headers": {"Authorization": "x"}})
    assert len(calls) == 1 and DOMAIN in calls[0]
    assert emap["requests_made"] == 1
    assert any("Breach-Indicator API Report" in f["title"] for f in findings)
    for f in findings:
        assert f["verification"] != "confirmed"


# ------------------------------------------------------------ resilience
def test_network_failure_degrades_to_warning_not_exception():
    def fetch(url, timeout=0, headers=None):
        raise OSError("connection refused")

    findings, emap = dr.run_darkradar(DOMAIN, fetcher=fetch,
                                      breach_opts={"url": "https://x/api"})
    assert findings, "links findings must still exist"
    assert any("failed" in w for w in emap["warnings"])
    assert any("Breach-Indicator API Report" not in f["title"]
               for f in findings)


def test_all_findings_never_confirmed():
    findings, _ = dr.run_darkradar(DOMAIN, crawl_output=CRAWL)
    assert findings
    for f in findings:
        assert f["verification"] != "confirmed"
        assert f["verification"] == "manual-required"


# ------------------------------------------------------------ rate limit
def test_request_cap_enforced():
    calls = []

    def fetch(url, timeout=0, headers=None):
        calls.append(url)
        return 500, {}, None

    # call the probe directly with a pre-exhausted budget
    res, warns = dr.probe_breach_api(DOMAIN, {"url": "https://x/api"},
                                     fetch=fetch, budget={"n": dr.MAX_REQUESTS})
    assert res is None and calls == []
    assert any("budget" in w for w in warns)
    # and a full run can never exceed the cap
    def fetch2(url, timeout=0, headers=None):
        calls.append(url)
        return 200, {}, b"{}"
    # simulate many breach probes sharing one budget
    budget = {"n": 0}
    for _ in range(20):
        dr.probe_breach_api(DOMAIN, {"url": "https://x/api"},
                            fetch=fetch2, budget=budget)
    assert len(calls) == dr.MAX_REQUESTS


# ------------------------------------------------------------ check gate
class _Ctx:
    def __init__(self, **kw):
        self.target = kw.get("target", f"https://{DOMAIN}/")
        self.opts = kw.get("opts", {})
        self.crawl_output = kw.get("crawl_output")
        self.log = []

    def L(self, msg):
        self.log.append(msg)


def test_gate_noop_without_env(monkeypatch):
    monkeypatch.delenv("PTK_DARKRADAR", raising=False)
    monkeypatch.delenv("VANTHEX_DARKRADAR", raising=False)
    ctx, out = _Ctx(), []
    dr.c_dark_radar(ctx, out.append)
    assert out == []
    assert any("gate" in l for l in ctx.log)


def test_gate_on_runs_links_only(monkeypatch):
    monkeypatch.setenv("PTK_DARKRADAR", "1")
    ctx = _Ctx(crawl_output=CRAWL)
    out = []
    dr.c_dark_radar(ctx, out.append)
    assert out, "expected findings with gate on"
    for f in out:
        assert f["origin"] == "darkradar"
        assert f["verification"] != "confirmed"
    assert any("done" in l for l in ctx.log)
