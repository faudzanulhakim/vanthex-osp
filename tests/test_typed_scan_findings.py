"""Regression tests: typed-scan branch findings must map F() fields
correctly (v1.16.0 arg-order fix).

vulnscan2.F is F(sev, title, desc, evidence, cwe, owasp, cvss=0.0,
remed="", ...). The app2 typed branches (ssl/udp/syn/vhost) passed the
remediation string as the 7th positional, so it landed in `cvss` and
`remediation` stayed empty. These tests pin, per branch: remediation
text in "remediation", cvss a float, severity/title intact.
"""
import app2


def _job():
    return {"log": [], "cancel": False}


def _assert_clean(f, remed_prefix):
    assert isinstance(f["cvss"], float), f"cvss corrupted: {f['cvss']!r}"
    assert f["remediation"].startswith(remed_prefix), f["remediation"]


def test_ssl_branch_findings_fields(monkeypatch):
    monkeypatch.setattr(app2.scanners, "ssl_audit",
                        lambda host: {"ok": True, "host": host})
    monkeypatch.setattr(app2.scanners, "tls_cipher_audit", lambda host: {
        "deprecated": ["tls1_0"],
        "weak": [{"cipher": "TLS_RSA_WITH_RC4_128_SHA"}],
        "protocols": {"tls1_0": True}})
    res = app2.run_tool_scan({}, "example.com", "ssl", "ssl", _job())
    assert len(res["findings"]) == 2
    _assert_clean(res["findings"][0], "Disable TLS 1.0/1.1")
    _assert_clean(res["findings"][1], "Restrict the cipher list")
    assert res["overall_risk"] == "MEDIUM"


def test_udp_branch_snmp_finding_fields(monkeypatch):
    monkeypatch.setattr(app2.scanners, "udp_scan", lambda host: {
        "open": [{"service": "snmp", "port": 161, "evidence": "sysDescr x"}],
        "results": [], "ambiguous": False, "note": "", "inconclusive": False})
    res = app2.run_tool_scan({}, "example.com", "udp", "udp", _job())
    assert len(res["findings"]) == 1
    f0 = res["findings"][0]
    assert f0["severity"] == "HIGH"
    _assert_clean(f0, "Disable SNMPv1")
    assert res["overall_risk"] == "HIGH"


def test_udp_branch_inconclusive_finding_fields(monkeypatch):
    monkeypatch.setattr(app2.scanners, "udp_scan", lambda host: {
        "open": [], "results": [], "ambiguous": False,
        "note": "synthetic resolver only", "inconclusive": True})
    res = app2.run_tool_scan({}, "example.com", "udp", "udp", _job())
    infos = [f for f in res["findings"] if "inconclusive" in f["title"].lower()]
    assert len(infos) == 1
    _assert_clean(infos[0], "Re-run when DoH is reachable")


def test_syn_branch_unavailable_finding_fields(monkeypatch):
    monkeypatch.setattr(app2.scanners, "syn_scan", lambda host, ports: {
        "available": False, "reason": "raw sockets not permitted (EPERM)"})
    res = app2.run_tool_scan({}, "example.com", "syn", "syn", _job())
    assert res["available"] is False
    assert len(res["findings"]) == 1
    _assert_clean(res["findings"][0], "Run SYN scans from a host")


def test_vhost_branch_finding_fields(monkeypatch):
    monkeypatch.setattr(app2.scanners, "vhost_enum", lambda target: {
        "interesting": [{"vhost": "dev.example.com", "status": 200,
                         "length": 4321}],
        "domain": "example.com", "candidates": ["dev.example.com"],
        "random_baseline_status": 404})
    res = app2.run_tool_scan({}, "example.com", "vhost", "vhost", _job())
    assert len(res["findings"]) == 1
    f0 = res["findings"][0]
    assert f0["severity"] == "LOW" and f0["confidence"] == "probable"
    _assert_clean(f0, "Confirm the virtual host is intended")
