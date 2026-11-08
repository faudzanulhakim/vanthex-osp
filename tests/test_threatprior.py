"""Test threatprior (v1.3) — 100% hermetic (urllib di-stub, tanpa jaringan)."""
import json
import os
import sys
import time
import urllib.parse

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import threatprior as tp


# ---------------------------------------------------------------- EPSS

def test_epss_chunking_and_parse(monkeypatch):
    calls = []

    def fake_fetch(url):
        calls.append(url)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        cves = q["cve"][0].split(",")
        # 150 CVE -> 2 chunk (100 + 50)
        half = len(cves)
        return {"data": [{"cve": c, "epss": "0.42", "percentile": "0.77"}
                         for c in cves]}

    cves = [f"CVE-2024-{1000 + i}" for i in range(150)]
    out = tp.fetch_epss(cves, fetcher=fake_fetch)
    assert len(calls) == 2
    assert len(out) == 150
    assert out["CVE-2024-1000"] == {"epss": 0.42, "percentile": 0.77}
    # each chunk <= 100 CVEs
    for url in calls:
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        assert len(q["cve"][0].split(",")) <= 100


def test_epss_offline_returns_empty(monkeypatch):
    def boom(url):
        raise OSError("network blocked")
    monkeypatch.setattr(tp.time, "sleep", lambda s: None)
    out = tp.fetch_epss(["CVE-2024-1234", "garbage"], fetcher=boom)
    assert out == {}


def test_epss_retries_once_then_succeeds(monkeypatch):
    attempts = []

    def flaky(url):
        attempts.append(url)
        if len(attempts) == 1:
            raise OSError("transient")
        return {"data": [{"cve": "CVE-2024-1234", "epss": "0.9",
                          "percentile": "0.99"}]}

    monkeypatch.setattr(tp.time, "sleep", lambda s: None)
    out = tp.fetch_epss(["CVE-2024-1234"], fetcher=flaky)
    assert len(attempts) == 2
    assert out["CVE-2024-1234"]["epss"] == 0.9


# ---------------------------------------------------------------- KEV

def test_kev_cache_write_and_ttl(tmp_path, monkeypatch):
    feed = {"vulnerabilities": [
        {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10",
         "knownRansomwareCampaignUse": "Known",
         "notes": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
        {"cveID": "CVE-2020-9999", "dateAdded": "2022-01-01",
         "knownRansomwareCampaignUse": "None", "notes": ""},
    ]}
    cache = tmp_path / "kev.json"
    monkeypatch.setenv("PTK_KEV_PATH", str(cache))
    def fake_fetch(url):
        assert url == tp.KEV_FEED
        return feed
    m = tp.load_kev(fetcher=fake_fetch)
    assert m["CVE-2021-44228"]["ransomware"] is True
    assert m["CVE-2020-9999"]["ransomware"] is False
    assert cache.exists()
    # fresh cache -> no network call at all
    m2 = tp.load_kev(fetcher=lambda url: pytest.fail("network used"),
                     now=time.time() + 3600)
    assert m2["CVE-2021-44228"]["date"] == "2021-12-10"


def test_kev_stale_cache_served_when_offline(tmp_path):
    cache = tmp_path / "kev.json"
    old = time.time() - 3 * 24 * 3600  # > TTL
    cache.write_text(json.dumps({
        "fetched_at": old,
        "entries": {"CVE-2019-0708": {"date": "2019-05-14",
                                      "ransomware": True, "notes": ""}},
    }))
    with pytest.raises(Exception):
        tp._http_json("http://127.0.0.1:1/x", 0.1)  # sanity: network stub
    m = tp.load_kev(path=str(cache), now=time.time(),
                    fetcher=lambda url: (_ for _ in ()).throw(OSError("down")))
    assert m["CVE-2019-0708"]["ransomware"] is True


def test_kev_no_cache_offline_empty(tmp_path):
    m = tp.load_kev(path=str(tmp_path / "missing.json"),
                    fetcher=lambda url: (_ for _ in ()).throw(OSError("down")))
    assert m == {}


# ------------------------------------------------------------- priority

def test_priority_mapping():
    base = {"severity": "HIGH"}
    assert tp.priority_for({"kev": True}) == "P1"
    assert tp.priority_for({"epss": 0.5}) == "P1"
    assert tp.priority_for({"epss": 0.94}) == "P1"
    assert tp.priority_for({"epss": 0.1}) == "P2"
    assert tp.priority_for({"epss": 0.09}) == "P3"
    assert tp.priority_for({"description": "affects CVE-2024-1"} ) == "P3"
    assert tp.priority_for({"severity": "CRITICAL"}) == "P2"
    assert tp.priority_for({"severity": "HIGH"}) == "P3"
    assert tp.priority_for({"severity": "INFO"}) == "P3"


def test_sort_key():
    fs = [
        {"kev": False, "epss": 0.9, "cvss": 9.8},
        {"kev": True, "epss": 0.0, "cvss": 5.0},
        {"kev": False, "epss": 0.9, "cvss": 7.5},
        {"kev": False, "epss": 0.1, "cvss": 10.0},
    ]
    fs.sort(key=tp.sort_key, reverse=True)
    assert [f["cvss"] for f in fs] == [5.0, 9.8, 7.5, 10.0]


# ----------------------------------------------------------- enrichment

def test_enrich_sample_findings(monkeypatch, tmp_path):
    monkeypatch.setenv("PTK_KEV_PATH", str(tmp_path / "kev.json"))
    findings = [
        {"severity": "CRITICAL", "title": "Log4Shell CVE-2021-44228",
         "description": "RCE", "evidence": "", "cvss": 10.0},
        {"severity": "HIGH", "title": "OpenSSL vuln",
         "description": "CVE-2023-5678 present", "evidence": "", "cvss": 7.5},
        {"severity": "MEDIUM", "title": "Missing header",
         "description": "no CVE here", "evidence": "", "cvss": 5.0},
    ]
    epss_map = {"CVE-2021-44228": {"epss": 0.94, "percentile": 0.99},
                "CVE-2023-5678": {"epss": 0.05, "percentile": 0.3}}
    kev_map = {"CVE-2021-44228": {"date": "2021-12-10", "ransomware": True,
                                  "notes": ""}}
    monkeypatch.setattr(tp, "fetch_epss", lambda cves: epss_map)
    monkeypatch.setattr(tp, "load_kev", lambda: kev_map)
    out = tp.enrich(findings)
    assert len(out) == 3
    f0, f1, f2 = out
    assert f0["kev"] is True and f0["kev_ransomware"] is True
    assert f0["kev_date"] == "2021-12-10"
    assert f0["epss"] == 0.94 and f0["epss_percentile"] == 0.99
    assert f0["priority"] == "P1"
    assert f1["kev"] is False and f1["epss"] == 0.05
    assert f1["priority"] == "P3"
    assert f2["priority"] == "P3"
    # original list not mutated
    assert "priority" not in findings[0]
    # every finding has priority
    assert all("priority" in f for f in out)


def test_enrich_explicit_cves_key(monkeypatch, tmp_path):
    monkeypatch.setenv("PTK_KEV_PATH", str(tmp_path / "kev.json"))
    monkeypatch.setattr(tp, "fetch_epss",
                        lambda cves: {"CVE-2022-22965": {"epss": 0.6,
                                                         "percentile": 0.9}})
    monkeypatch.setattr(tp, "load_kev", lambda: {})
    out = tp.enrich([{"severity": "HIGH", "title": "Spring4Shell",
                      "cves": ["cve-2022-22965"]}])
    assert out[0]["priority"] == "P1"
    assert out[0]["epss"] == 0.6


def test_enrich_offline_degrades_gracefully(monkeypatch, tmp_path):
    monkeypatch.setenv("PTK_KEV_PATH", str(tmp_path / "kev.json"))

    def boom(url):
        raise OSError("offline")
    monkeypatch.setattr(tp, "_http_json", boom)
    monkeypatch.setattr(tp.time, "sleep", lambda s: None)
    findings = [{"severity": "CRITICAL", "title": "Thing CVE-2024-1111",
                 "description": "", "evidence": "", "cvss": 9.0},
                {"severity": "LOW", "title": "No CVE", "description": "",
                 "evidence": "", "cvss": 3.0}]
    out = tp.enrich(findings)  # must NOT raise
    assert out[0]["priority"] == "P3"  # CVE present, no data
    assert out[1]["priority"] == "P3"
    assert "kev" not in out[0] or out[0]["kev"] is False


def test_enrich_respects_cancelled(monkeypatch, tmp_path):
    monkeypatch.setenv("PTK_KEV_PATH", str(tmp_path / "kev.json"))
    called = []

    def fail(url):
        called.append(url)
        raise AssertionError("network must not be used when cancelled")
    monkeypatch.setattr(tp, "_http_json", fail)
    out = tp.enrich([{"severity": "CRITICAL", "title": "CVE-2024-2222",
                      "description": "", "evidence": "", "cvss": 9.0}],
                    cancelled=lambda: True)
    assert called == []
    assert out[0]["priority"] == "P3"


# ---------------------------------------------------------- reports

def _scan(findings):
    import vulnscan2
    return {"target": "http://example.com", "profile": "active-deep",
            "findings": findings, "overall_risk": "CRITICAL",
            "risk_score": 90, "started_at": time.time(),
            "result": json.dumps({"findings": findings,
                                  "risk_score": 90, "overall_risk": "CRITICAL"})}


def test_report_html_renders_priority_line():
    import report as report_mod
    f = {"severity": "CRITICAL", "title": "RCE CVE-2021-44228",
         "description": "x", "evidence": "y", "cvss": 10.0,
         "confidence": "confirmed", "origin": "active",
         "epss": 0.94, "epss_percentile": 0.99, "kev": True,
         "kev_date": "2021-12-10", "kev_ransomware": True,
         "priority": "P1"}
    html = report_mod.render_report(_scan([f]), [f])
    assert "EPSS 94%" in html and "KEV LISTED" in html and "P1" in html
    # graceful when keys absent
    f2 = {"severity": "LOW", "title": "Plain", "description": "d",
          "evidence": "", "cvss": 3.0, "confidence": "probable",
          "origin": "active"}
    html2 = report_mod.render_report(_scan([f2]), [f2])
    assert "EPSS" not in html2 and "KEV LISTED" not in html2


def test_report_docx_renders_priority_line(tmp_path):
    docx = pytest.importorskip("docx_report")
    f = {"severity": "HIGH", "title": "CVE-2023-1 issue",
         "description": "d", "evidence": "e", "cvss": 7.5,
         "confidence": "probable", "origin": "active",
         "epss": 0.2, "kev": False, "priority": "P2"}
    out = tmp_path / "r.docx"
    docx.generate_docx(_scan([f]), [f], str(out))
    assert out.exists()
    import report_common as RC
    assert RC.priority_line(f) == "EPSS 20% · P2"


def test_vulnscan_run_integration_env_gate():
    src = open(os.path.join(os.path.dirname(__file__), "..",
                            "vulnscan2.py"), encoding="utf-8").read()
    assert "PTK_THREATPRIOR" in src
    assert "threatprior" in src
