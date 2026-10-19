"""Kejujuran akurasi DNS & port (insiden ADE 2026-10-18): resolver sistem VM
ini sintetis (IP fake 198.18.x.x untuk nama apa pun) dan egress TCP
terintercept gateway — scan TIDAK boleh menyajikan jawaban gateway/resolver
sintetis sebagai fakta target."""
import scanners
import app2


def test_is_synthetic_ip():
    assert scanners.is_synthetic_ip("198.18.0.1")
    assert scanners.is_synthetic_ip("198.19.255.254")
    assert not scanners.is_synthetic_ip("198.17.255.255")
    assert not scanners.is_synthetic_ip("202.59.166.166")
    assert not scanners.is_synthetic_ip("10.0.0.1")
    assert not scanners.is_synthetic_ip("bukan-ip")


def _doh_map(mapping, probes_status=3):
    def fake(name, timeout=6.0):
        label = name.split(".")[0]
        if label.startswith("vx"):
            return {"status": probes_status, "ips": [], "cname": False}
        return mapping.get(label, {"status": 3, "ips": [], "cname": False})
    return fake


def test_resolve_subdomain_doh_normal(monkeypatch):
    monkeypatch.setattr(scanners, "doh_a", _doh_map({
        "www": {"status": 0, "ips": ["93.184.216.34"], "cname": False},
        "mail": {"status": 3, "ips": [], "cname": False},
    }))
    res = scanners.resolve_subdomain("example.com", ["www", "mail"])
    assert res["inconclusive"] is False and res["resolver"] == "doh"
    assert res["found"] == [{"sub": "www.example.com", "ips": ["93.184.216.34"]}]


def test_resolve_subdomain_wildcard_filtered(monkeypatch):
    def fake(name, timeout=6.0):
        label = name.split(".")[0]
        if label.startswith("vx"):
            return {"status": 0, "ips": ["10.9.9.9"], "cname": False}
        if label == "www":
            return {"status": 0, "ips": ["10.9.9.9"], "cname": False}
        if label == "api":
            return {"status": 0, "ips": ["10.9.9.10"], "cname": False}
        return {"status": 3, "ips": [], "cname": False}
    monkeypatch.setattr(scanners, "doh_a", fake)
    res = scanners.resolve_subdomain("example.com", ["www", "api"])
    assert [f["sub"] for f in res["found"]] == ["api.example.com"]
    assert res["wildcard_ips"] == ["10.9.9.9"]


def test_resolve_subdomain_inconclusive_when_doh_down_and_system_synthetic(monkeypatch):
    monkeypatch.setattr(scanners, "doh_a", lambda name, timeout=6.0: None)
    monkeypatch.setattr(scanners, "resolve_host", lambda h: ["198.18.51.104"])
    res = scanners.resolve_subdomain("example.com", ["www"])
    assert res["inconclusive"] is True and res["found"] == []


def test_resolve_subdomain_system_fallback_healthy(monkeypatch):
    monkeypatch.setattr(scanners, "doh_a", lambda name, timeout=6.0: None)
    def fake_host(h):
        return ["93.184.216.34"] if h.startswith("www.") else []
    monkeypatch.setattr(scanners, "resolve_host", fake_host)
    res = scanners.resolve_subdomain("example.com", ["www", "mail"])
    assert res["resolver"] == "system" and res["inconclusive"] is False
    assert [f["sub"] for f in res["found"]] == ["www.example.com"]


def test_ports_intercepted_reports_zero_and_info(monkeypatch):
    fake = {"open": [{"port": 22, "service": "ssh", "verified": False,
                      "banner": "muse: Outbound SSH is turned off"}],
            "intercepted": True,
            "intercept_reason": "interceptor gateway banner detected"}
    monkeypatch.setattr(app2.scanners, "tcp_scan_detailed",
                        lambda host, ports=None: fake)
    app2.LOGIN_FAILS.clear()
    job = {"log": [], "cancel": False}
    res = app2.run_tool_scan({}, "example.com", "ports", "ports", job)
    assert res["open_ports"] == []
    assert res["intercepted"] is True
    assert len(res["findings"]) == 1
    assert res["findings"][0]["severity"] == "INFO"
    assert "inconclusive" in res["findings"][0]["title"]


def test_subdomains_branch_inconclusive(monkeypatch):
    monkeypatch.setattr(app2.scanners, "resolve_subdomain", lambda h, s: {
        "found": [], "inconclusive": True, "reason": "synthetic resolver",
        "wildcard_ips": [], "resolver": "none"})
    job = {"log": [], "cancel": False}
    res = app2.run_tool_scan({}, "example.com", "subdomains", "subdomains", job)
    assert res["found"] == []
    assert len(res["findings"]) == 1 and "inconclusive" in res["findings"][0]["title"]
