"""Hermetic tests for SARIF export and the notification dispatcher.

All network calls are monkeypatched — nothing leaves the process.
Run: .venv/bin/python -m pytest tests/test_sarif_notify.py -q
"""
import json
import os
import sys
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sarif_export  # noqa: E402
import notify as notify_mod  # noqa: E402


def F(sev, title="XSS in search", cwe="CWE-79", cvss=9.1, prio="P1",
      loc="https://t.example/search?q=1"):
    return {"severity": sev, "title": title, "description": "Reflected input",
            "evidence": "q=<script>", "cwe": cwe, "owasp": "A03:2021",
            "cvss": cvss, "confidence": "confirmed", "priority": prio,
            "location": loc}


# --------------------------------------------------------------- SARIF ----

def test_sarif_shape():
    s = sarif_export.findings_to_sarif(
        [F("CRITICAL")], {"target": "https://t.example", "profile": "deep",
                          "tool": "VANTHEX", "version": "1.2.2"})
    assert s["version"] == "2.1.0"
    assert s["$schema"].endswith("sarif-schema-2.1.0.json")
    assert isinstance(s["runs"], list) and len(s["runs"]) == 1
    run = s["runs"][0]
    assert run["tool"]["driver"]["name"] == "VANTHEX"
    assert run["tool"]["driver"]["version"] == "1.2.2"
    assert len(run["results"]) == 1
    r = run["results"][0]
    assert r["ruleId"] == "CWE-79"
    assert r["message"]["text"].startswith("XSS in search")
    assert "Reflected input" in r["message"]["text"]
    assert r["properties"]["severity"] == "CRITICAL"
    assert r["properties"]["cvss"] == 9.1
    assert r["properties"]["priority"] == "P1"
    loc = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert loc == "https://t.example/search?q=1"
    # rule registry populated
    assert run["tool"]["driver"]["rules"][0]["id"] == "CWE-79"
    # serializable
    json.dumps(s)


def test_sarif_level_mapping():
    findings = [F("CRITICAL"), F("HIGH"), F("MEDIUM"), F("LOW"), F("INFO")]
    s = sarif_export.findings_to_sarif(findings)
    levels = [r["level"] for r in s["runs"][0]["results"]]
    assert levels == ["error", "error", "warning", "note", "note"]


def test_sarif_ruleid_slug_and_uri_filtering():
    f = F("MEDIUM", title="Odd Header Thing!", cwe="", loc="/.git@abc:x")
    s = sarif_export.findings_to_sarif([f])
    r = s["runs"][0]["results"][0]
    assert r["ruleId"] == "odd-header-thing"
    assert "locations" not in r  # virtual location is not a URI
    # relative path without @/# is kept
    f2 = F("MEDIUM", loc="/admin/config")
    assert (sarif_export.findings_to_sarif([f2])["runs"][0]["results"][0]
            ["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            == "/admin/config")


def test_sarif_empty_and_junk():
    s = sarif_export.findings_to_sarif([])
    assert s["runs"][0]["results"] == []
    s2 = sarif_export.findings_to_sarif(None, "notadict")
    assert s2["version"] == "2.1.0"


# -------------------------------------------------------------- notify ----

class FakeResp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def capture(monkeypatch):
    calls = []

    def fake_post(url, payload, headers=None):
        calls.append((url, payload))
        return True

    monkeypatch.setattr(notify_mod, "_post", fake_post)
    return calls


CFG = {"PTK_NOTIFY_TELEGRAM_BOT_TOKEN": "TOK",
       "PTK_NOTIFY_TELEGRAM_CHAT_ID": "42",
       "PTK_NOTIFY_SLACK_WEBHOOK": "https://hooks.slack.test/x",
       "PTK_NOTIFY_WEBHOOK_URL": "https://hook.test/z"}


def test_notify_sends_all_channels(capture):
    sent = notify_mod.notify([F("CRITICAL")], CFG)
    assert sent == ["telegram", "slack", "webhook"]
    urls = [c[0] for c in capture]
    assert "api.telegram.org/botTOK/sendMessage" in urls[0]
    assert urls[1] == "https://hooks.slack.test/x"
    assert capture[1][1] == {"text": notify_mod.build_summary(
        [F("CRITICAL")])}


def test_notify_p1_gating(capture):
    assert notify_mod.notify([F("LOW", prio="P3")], CFG) == []
    assert capture == []
    assert notify_mod.notify([F("HIGH", prio="P2")], CFG) == []
    # P1 priority alone triggers
    assert notify_mod.notify([F("LOW", prio="P1")], CFG)
    assert notify_mod.notify([F("LOW", prio="P3")],
                             dict(CFG, PTK_NOTIFY_ALWAYS="1"))


def test_notify_disabled_and_unconfigured(capture):
    assert notify_mod.notify([F("CRITICAL")], dict(CFG, PTK_NOTIFY="0")) == []
    assert notify_mod.notify([F("CRITICAL")], {}) == []
    assert capture == []


def test_notify_never_raises(monkeypatch):
    def boom(*a, **k):
        raise OSError("network down")

    monkeypatch.setattr(notify_mod, "_post", boom)
    sent = notify_mod.notify([F("CRITICAL")], CFG)
    assert sent == []  # swallowed


def test_notify_timeout_and_retry(monkeypatch, capture):
    """Each channel gets at most 2 attempts on failure, then gives up."""
    results = {"n": 0}

    def flaky(url, payload, headers=None):
        results["n"] += 1
        return results["n"] % 2 == 0  # fails on 1st, succeeds on retry

    monkeypatch.setattr(notify_mod, "_post", flaky)
    sent = notify_mod.notify([F("CRITICAL")], {"PTK_NOTIFY_WEBHOOK_URL": "h"})
    assert sent == ["webhook"]
    assert results["n"] == 2


def test_build_summary_content():
    fs = [F("CRITICAL", title="RCE in admin"), F("HIGH", title="SQLi"),
          F("LOW", prio="P3")]
    text = notify_mod.build_summary(fs)
    assert "CRITICAL=1" in text and "LOW=1" in text
    assert "P1=2" in text and "P3=1" in text
    assert "- [CRITICAL] RCE in admin" in text
    assert "SQLi" in text
    # top 5 cap
    many = [F("CRITICAL", title=f"t{i}") for i in range(8)]
    lines = [ln for ln in notify_mod.build_summary(many).splitlines()
             if ln.startswith("- ")]
    assert len(lines) == 5
