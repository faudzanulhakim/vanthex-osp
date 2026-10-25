"""v1.23.0 — program gap OSIRIS (service dashboard, globe view).

Scope (design §14.1 TOOLS panel, §14.3 ARCGIS, §15 placement,
§16.2 perspective, §16.3 FINGERPRINT, §16.4 DATA LEAKS / CHAIN /
DONBOT / THREATS, §16.5 SHODAN / MAC / BGP, §16.9 host batch):
full TOOLS panel, NEWS perspective filter (static, no AI),
FINGERPRINT (Sherlock non-NSFW, streaming, two-control
calibration), DATA LEAKS (XposedOrNot only), CHAIN INTEL (BTC/ETH),
DONBOT (CoinGecko only), THREATS (OTX indicators + Tor list),
SHODAN IOT (InternetDB only), MAC ADDR, BGP ROUTE, ARCGIS INTEL.

GATES HONESTLY RECORDED (build verification, 2026-10-25):
- BreachDirectory DROPS: vendor distribution is keyed RapidAPI;
  keyless claims rest on a third-party tutorial and an auth-bypass
  bug report — neither is a verified public access term. The host
  is never contacted and never appears in the release.
- OTX "recent public pulses" strip DROPS: both /pulses/subscribed
  and /pulses/activity answer 403 "Authentication required".
  Indicator lookup (200, keyless) + Tor list still run.
- SOL wallet portion DROPS: both official public RPC hostnames
  timed out from the fetch daemon at build verification (docs say
  keyless; live egress does not answer). BTC/ETH + CoinGecko
  prices still run; a SOL address gets an honest unavailable
  answer, not a dead card.
- DONBOT holder-cluster map DROPS: holder-list APIs are keyed
  (Etherscan requires a key; Solscan Pro 401s without auth).
- RIPEstat announced-prefixes PASSES (200): the BGP prefix list
  is IN (no longer TBD).
- ArcGIS extent queries REQUIRE a layer index: the service-root
  /query answers 400 (verified at build); the implementation reads
  ?f=pjson layers first, then <service>/<id>/query. Same intent,
  working path.
- ip-api.com free tier is HTTP-only (HTTPS answers 403): geo
  lookups use _fetch_binary over http://.
- "All sides" as the DEFAULT CHIP of the static perspective filter
  is allowed by §16.2 (ADE-approved 01:08 WIB); what stays banned
  is the AI "All sides" perspective feature + AI OVERVIEW + topic
  clusters. The negative test checks for those, not the chip label.

All tool tests below are hermetic (monkeypatched fetch); no test
contacts a live host. The live-server class only checks auth
gating, headers, and invalid-input shapes (validation happens
before any fetch).
"""

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

HTML = open(os.path.join(ROOT, "templates", "app.html"),
             encoding="utf-8").read()
APP2 = open(os.path.join(ROOT, "app2.py"), encoding="utf-8").read()
FEEDS = open(os.path.join(ROOT, "globe_feeds.py"), encoding="utf-8").read()
RECON = open(os.path.join(ROOT, "globe_recon.py"), encoding="utf-8").read()
HELPER = open(os.path.join(ROOT, "globe_fetch_helper.py"),
              encoding="utf-8").read()

import globe_recon as gr  # noqa: E402
import globe_feeds as gf  # noqa: E402

CSP_1230 = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: "
            "https://server.arcgisonline.com https://tilecache.rainviewer.com "
            "https://nowcoast.noaa.gov https://tiles.basemaps.cartocdn.com https://s3.amazonaws.com; "
            "connect-src 'self' https://api.rainviewer.com "
            "https://basemaps.cartocdn.com https://tiles.basemaps.cartocdn.com "
            "https://tiles-a.basemaps.cartocdn.com https://tiles-b.basemaps.cartocdn.com "
            "https://tiles-c.basemaps.cartocdn.com https://tiles-d.basemaps.cartocdn.com; "
            "frame-src https://www.youtube-nocookie.com; "
            "worker-src 'self' blob:; "
            "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; "
            "form-action 'self'")

LANGS = ["id", "es", "fr", "de", "pt", "ru", "ja", "ko", "zh", "ar", "hi"]


def _extract_csps(src):
    out = []
    for m in re.finditer(
            r'self\.send_header\("Content-Security-Policy",\s*(.*?)\)',
            src, re.S):
        parts = re.findall(r'"([^"]*)"', m.group(1))
        out.append("".join(parts))
    return out


def _hosts(text):
    return set(re.findall(r"https://([A-Za-z0-9.\-]+)", text))


def _extra16():
    m = re.search(r"const I18N_EXTRA16 = (\{.*?\});\n", HTML)
    assert m, "I18N_EXTRA16 not found"
    return json.loads(m.group(1))


# ---------------------------------------------------------------- pins / CSP

def test_server_version():
    assert 'server_version = "VANTHEX/1.25.0"' in APP2
    assert 'server_version = "VANTHEX/1.22.0"' not in APP2


def test_api_version():
    assert '"version": "1.25.0"' in APP2
    assert '"version": "1.22.0"' not in APP2


def test_report_versions():
    for f in ("report.py", "docx_report.py"):
        txt = open(os.path.join(ROOT, f), encoding="utf-8").read()
        assert 'VERSION = "1.25.0"' in txt
    assert "VANTHEX/1.25.0 (OSINT globe" in FEEDS
    assert "VANTHEX 1.25.0" in HTML


def test_csp_verbatim():
    csps = _extract_csps(APP2)
    assert csps, "no CSP send_header found"
    assert csps[0] == CSP_1230


def test_csp_all_occurrences_identical():
    # The streaming method duplicates the literal; every occurrence
    # must equal the F6 value (v1.23.0 has no CSP diff).
    csps = _extract_csps(APP2)
    assert len(csps) >= 2, "streaming CSP copy missing"
    assert all(c == CSP_1230 for c in csps)


def test_csp_terrain_s3_no_gibs():
    csp = _extract_csps(APP2)[0]
    assert "s3.amazonaws.com" in csp
    assert "terrarium" not in csp
    assert "gibs.earthdata.nasa.gov" not in csp


def test_csp_hosts_within_batch():
    allowed = {
        "server.arcgisonline.com", "tilecache.rainviewer.com",
        "nowcoast.noaa.gov", "tiles.basemaps.cartocdn.com",
        "api.rainviewer.com", "basemaps.cartocdn.com",
        "tiles-a.basemaps.cartocdn.com", "tiles-b.basemaps.cartocdn.com",
        "tiles-c.basemaps.cartocdn.com", "tiles-d.basemaps.cartocdn.com",
        "www.youtube-nocookie.com",
        "s3.amazonaws.com",
    }
    assert _hosts(_extract_csps(APP2)[0]) <= allowed


def test_osint_byte_identical():
    p = os.path.join(ROOT, "osint.py")
    h = hashlib.md5(open(p, "rb").read()).hexdigest()
    assert h == "65ec21c31b4aad76aa304fcb411388ae"


def test_recon_routes_present():
    assert 'import globe_recon' in APP2
    assert '"/api/osint/globe/recon"' in APP2
    assert '"/api/osint/globe/fingerprint"' in APP2
    assert "_stream_ndjson" in APP2


# ---------------------------------------------------------------- allowlist / validation

def test_tool_allowlist():
    assert set(gr.TOOLS) == {
        "dns", "whois", "certs", "ssl", "subdomains", "headers",
        "tech", "ports", "vulnsweep", "username", "phone",
        "shodan", "mac", "bgp", "threats", "dataleaks",
        "chain", "donbot", "fingerprint", "arcgis"}
    assert gr.run_tool("nosuchtool", "example.com")["ok"] is False
    assert gr.run_tool("fingerprint", "x")["ok"] is False  # stream route
    # URL-shaped targets are rejected before any fetch.
    assert gr.run_tool("dns", "https://example.com/x")["ok"] is False
    assert gr.run_tool("shodan", "https://8.8.8.8")["ok"] is False
    assert gr.run_tool("mac", "not-a-mac")["ok"] is False
    assert gr.run_tool("dataleaks", "not-an-email")["ok"] is False


def test_validation_units():
    assert gr._validate("dns", "Example.COM") == "example.com"
    assert gr._validate("dns", "bad_host") is None
    assert gr._validate("shodan", "8.8.8.8") == "8.8.8.8"
    assert gr._validate("shodan", "999.1.1.1") is None
    assert gr._validate("mac", "00:1a:2b:3c:4d:5e") == "001A2B3C4D5E"
    assert gr._validate("mac", "00-1A-2B-3C-4D-5E") == "001A2B3C4D5E"
    assert gr._validate("username", "ok_user-1") == "ok_user-1"
    assert gr._validate("username", "bad user!") is None
    assert gr._validate("donbot", "bitcoin") == "bitcoin"
    assert gr._validate("donbot", "") is None


# ---------------------------------------------------------------- DNS / WHOIS / CERTS

def test_dns_parse(monkeypatch):
    def fake_get(host, path, timeout=30.0, headers=None):
        assert headers and headers.get("Accept") == "application/dns-json"
        if "type=A" in path:
            body = json.dumps({"Status": 0, "Answer": [
                {"name": "example.com", "type": 1, "data": "93.184.216.34"},
                {"name": "example.com", "type": 1, "data": "93.184.216.35"}]})
        elif "type=MX" in path:
            body = json.dumps({"Status": 0, "Answer": [
                {"name": "example.com", "type": 15, "data": "10 mail.example.com."}]})
        else:
            body = json.dumps({"Status": 0})
        return 200, body.encode()
    monkeypatch.setattr(gr, "_get", fake_get)
    out = gr.tool_dns("example.com")
    assert out["ok"] is True
    assert out["records"]["A"] == ["93.184.216.34", "93.184.216.35"]
    assert out["records"]["MX"] == ["10 mail.example.com."]
    assert out["records"]["AAAA"] == []


def test_whois_domain_parse(monkeypatch):
    doc = {"handle": "123-REG", "status": ["clientTransferProhibited"],
           "entities": [{"roles": ["registrar"], "vcardArray": [
               None, [["version", {}, "text", "4.0"],
                      ["fn", {}, "text", "Example Registrar, Inc."]]]}],
           "events": [{"eventAction": "registration",
                       "eventDate": "1995-08-14T04:00:00Z"},
                      {"eventAction": "expiration",
                       "eventDate": "2030-08-13T04:00:00Z"}],
           "nameservers": [{"ldhName": "a.iana-servers.net"},
                           {"ldhName": "b.iana-servers.net"}]}
    monkeypatch.setattr(gr, "_follow",
                        lambda url, **kw: (200, {}, json.dumps(doc).encode(), url))
    out = gr.tool_whois("example.com")
    assert out["ok"] is True and out["kind"] == "domain"
    assert out["registrar"] == "Example Registrar, Inc."
    assert out["events"]["expiration"].startswith("2030-08-13")
    assert out["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert "port 43" in out["note"]


def test_whois_ip_parse(monkeypatch):
    doc = {"name": "GOOGLE", "country": "US",
           "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
           "entities": [{"roles": ["registrant"], "vcardArray": [
               None, [["fn", {}, "text", "Google LLC"]]]}]}
    monkeypatch.setattr(gr, "_follow",
                        lambda url, **kw: (200, {}, json.dumps(doc).encode(), url))
    out = gr.tool_whois("8.8.8.8")
    assert out["ok"] is True and out["kind"] == "ip"
    assert out["prefix"] == "8.8.8.0/24"
    assert out["owner"] == "Google LLC"


def test_certs_parse(monkeypatch):
    import osint as _osint
    rows = [
        {"issuer_name": "C=US, O=Example CA", "name_value": "example.com\nwww.example.com",
         "not_after": "2030-01-01T00:00:00Z"},
        {"issuer_name": "C=US, O=Old CA", "name_value": "old.example.com",
         "not_after": "2020-01-01T00:00:00Z"},
    ]
    monkeypatch.setattr(_osint, "_ct_rows", lambda fetch, domain: (rows, 200))
    monkeypatch.setattr(gr, "_get", lambda h, p, **kw: (200, b""))
    out = gr.tool_certs("example.com")
    assert out["ok"] is True
    assert out["certificates"] == 1
    assert out["issuers"] == [("C=US, O=Example CA", 1)]
    assert "example.com" in out["sample_names"]
    assert "old.example.com" not in out["sample_names"]


def test_certs_parse_error(monkeypatch):
    import osint as _osint
    monkeypatch.setattr(_osint, "_ct_rows",
                        lambda fetch, domain: ("parse_error", 200))
    out = gr.tool_certs("example.com")
    assert out["ok"] is False and "parse error" in out["reason"]

# ---------------------------------------------------------------- HEADERS / TECH / PORTS / VULNSWEEP

def test_headers_check(monkeypatch):
    monkeypatch.setattr(gr, "_bin", lambda url, **kw: (
        200, {"Strict-Transport-Security": "max-age=31536000",
              "X-Content-Type-Options": "nosniff",
              "Server": "nginx"}, b"", False))
    out = gr.tool_headers("example.com")
    assert out["ok"] is True
    assert out["score"].startswith("2/")
    assert "Content-Security-Policy" in out["missing"]
    assert out["present"]["Strict-Transport-Security"] == "max-age=31536000"


def test_tech_profile(monkeypatch):
    body = (b'<html><head><script src="/wp-includes/js/jquery.js">'
            b'</script></head><body data-wp="1"></body></html>')
    monkeypatch.setattr(gr, "_bin", lambda url, **kw: (
        200, {"Server": "nginx"}, body, False))
    out = gr.tool_tech("example.com")
    assert out["ok"] is True
    assert isinstance(out["detections"], list)


def test_ports_inconclusive_always(monkeypatch):
    import scanners as _sc
    rows = [{"port": 443, "state": "open", "service": "https",
             "verified": True, "banner": "TLS handshake sukses"},
            {"port": 22, "state": "closed", "service": "",
             "verified": False, "banner": ""}]
    monkeypatch.setattr(_sc, "tcp_scan_detailed", lambda h, p: rows)
    monkeypatch.setattr(_sc, "detect_interception",
                        lambda opens: (False, "", ""))
    monkeypatch.setattr(gr, "_doh", lambda n, t: ["93.184.216.34"])
    out = gr.tool_ports("example.com")
    assert out["ok"] is True
    assert out["label"] == "INCONCLUSIVE — VM egress"
    assert "no port below is a confirmed finding" in out["note"]
    assert out["ports"] == [{"port": 443, "service": "https",
                             "state": "open"}]


def test_ports_intercepted_discards(monkeypatch):
    import scanners as _sc
    rows = [{"port": 443, "state": "open", "service": "https",
             "verified": False, "banner": "muse: connections is turned off"}]
    monkeypatch.setattr(_sc, "tcp_scan_detailed", lambda h, p: rows)
    monkeypatch.setattr(_sc, "detect_interception",
                        lambda opens: (True, "interceptor gateway banner detected", "muse:"))
    monkeypatch.setattr(gr, "_doh", lambda n, t: ["93.184.216.34"])
    out = gr.tool_ports("example.com")
    assert out["ports"] == []
    assert out["label"] == "INCONCLUSIVE — VM egress"


def test_vulnsweep_status_only(monkeypatch):
    calls = []

    def fake_bin(url, **kw):
        calls.append((url, kw.get("method", "GET")))
        if url == "https://example.com/":
            return 200, {}, b"<html>home</html>", False
        if url.endswith("/.git/HEAD"):
            # A body that MUST never surface in the output.
            return 200, {}, b"SECRET-LEAK-BODY-12345", False
        if url.endswith("/.env"):
            return 404, {}, b"", False
        return 404, {}, b"", False
    monkeypatch.setattr(gr, "_bin", fake_bin)
    out = gr.tool_vulnsweep("example.com")
    assert out["ok"] is True
    blob = json.dumps(out)
    assert "SECRET-LEAK-BODY-12345" not in blob
    assert "presence only" in blob
    assert any(f["title"] == "git metadata exposed"
               for f in out["findings"])
    assert "passive web-layer subset" in out["scope"]


# ---------------------------------------------------------------- USERNAME / PHONE

def test_username_rows(monkeypatch):
    from types import SimpleNamespace
    import osint as _osint
    f1 = SimpleNamespace(title="Username 'alice' found on GitHub",
                         location="https://github.com/alice",
                         confidence="probable")
    f2 = SimpleNamespace(title="Possible username 'alice' on Xyz (unverified)",
                         location="https://xyz.example/alice",
                         confidence="candidate")
    meta = {"probable": ["GitHub"], "candidate": ["Xyz"],
            "unevaluated": ["SlowSite"], "skipped": ["QueuedSite"]}
    monkeypatch.setattr(_osint, "_username_osint",
                        lambda *a, **k: ([f1, f2], meta))
    out = gr.tool_username("alice")
    assert out["ok"] is True
    assert out["findings"][0]["platform"] == "GitHub"
    assert out["findings"][0]["verdict"] == "probable"
    assert out["findings"][1]["platform"] == "Xyz"
    assert out["partial"] is True
    assert out["unevaluated"] == ["SlowSite"]


def test_phone_parse():
    out = gr.tool_phone("+6281234567890")
    assert out["ok"] is True
    assert out["parsed"]["e164"] == "+6281234567890"
    assert out["parsed"]["region"] == "Indonesia"
    assert gr.tool_phone("not-a-phone")["ok"] is False


# ---------------------------------------------------------------- SHODAN / MAC / BGP

def test_shodan_parse(monkeypatch):
    doc = {"ip": "8.8.8.8", "ports": [53, 443],
           "hostnames": ["dns.google"], "tags": ["dns"],
           "cpes": ["cpe:2.3:a:google:dns:*:*:*:*:*:*:*:*"],
           "vulns": ["CVE-2020-1234"]}
    monkeypatch.setattr(gr, "_get",
                        lambda h, p, **kw: (200, json.dumps(doc).encode()))
    out = gr.tool_shodan("8.8.8.8")
    assert out["ok"] is True
    assert out["ports"] == [53, 443]
    assert out["vulns"] == ["CVE-2020-1234"]
    assert "NOT a VANTHEX scan" in out["note"]
    assert "Host API" in out["note"]


def test_mac_parse_and_reject(monkeypatch):
    calls = []
    doc = {"found": True, "macPrefix": "001A2B",
           "company": "Ayecom Technology Co., Ltd.",
           "address": "Somewhere", "country": "TW",
           "blockStart": "001A2B000000", "blockEnd": "001A2BFFFFFF"}
    def fake_get(h, p, **kw):
        calls.append((h, p))
        return 200, json.dumps(doc).encode()
    monkeypatch.setattr(gr, "_get", fake_get)
    out = gr.tool_mac("00:1A:2B:3C:4D:5E")
    assert out["ok"] is True and out["company"].startswith("Ayecom")
    assert "vendor is not device identity" in out["note"].lower() or \
        "not device identity" in out["note"]
    n = len(calls)
    assert gr.run_tool("mac", "zz:zz:zz:zz:zz:zz")["ok"] is False
    assert len(calls) == n  # invalid input never fetched


def test_bgp_parse(monkeypatch):
    geo = {"lat": 39.03, "lon": -77.5, "city": "Ashburn",
           "country": "United States", "country_code": "US",
           "level": "city", "isp": "Google LLC", "org": "",
           "asn": "AS15169 Google LLC"}
    monkeypatch.setattr(gr, "geo_for_ip", lambda ip: geo)
    def fake_get(host, path, **kw):
        if "as-overview" in path:
            return 200, json.dumps({"data": {"holder": "Google LLC",
                                             "type": "ISP"}}).encode()
        if "announced-prefixes" in path:
            return 200, json.dumps({"data": {"prefixes": [
                {"prefix": "8.8.8.0/24"},
                {"prefix": "8.8.4.0/24"}]}}).encode()
        raise AssertionError("unexpected host " + host)
    monkeypatch.setattr(gr, "_get", fake_get)
    out = gr.tool_bgp("8.8.8.8")
    assert out["ok"] is True
    assert out["asn"] == "AS15169"
    assert out["holder"] == "Google LLC"
    assert out["prefixes"] == ["8.8.8.0/24", "8.8.4.0/24"]
    assert out["prefix_total"] == 2
    assert "no route line" in out["note"]


# ---------------------------------------------------------------- THREATS

def _otx_doc(count, names):
    return {"reputation": 0, "asn": "AS15169 google llc",
            "pulse_info": {"count": count,
                           "pulses": [{"name": n} for n in names]}}


def test_threats_buckets(monkeypatch):
    monkeypatch.setattr(gr, "_get", lambda h, p, **kw: (
        200, json.dumps(_otx_doc(7, ["EvilPulse"])).encode()))
    monkeypatch.setattr(gr, "_tor_exit_set", lambda: ({"1.2.3.4"}, ""))
    monkeypatch.setattr(gr, "geo_for_ip", lambda ip: None)
    out = gr.tool_threats("8.8.8.8")
    assert out["pulse_bucket"] == "HIGH"
    assert out["pulses"] == ["EvilPulse"]
    assert out["tor_exit"] is False
    assert "NOT a verdict" in out["note_otx"]
    monkeypatch.setattr(gr, "_get", lambda h, p, **kw: (
        200, json.dumps(_otx_doc(0, [])).encode()))
    # Different target: the threats cache is keyed by target, so a
    # second expectation needs a second key (never a cache leak).
    out = gr.tool_threats("8.8.4.4")
    assert out["pulse_bucket"] == "LOW"


def test_threats_unknown_not_clean(monkeypatch):
    monkeypatch.setattr(gr, "_get", lambda h, p, **kw: (403, b""))
    monkeypatch.setattr(gr, "_tor_exit_set", lambda: ({"1.1.1.1"}, ""))
    monkeypatch.setattr(gr, "geo_for_ip", lambda ip: None)
    out = gr.tool_threats("1.1.1.1")
    assert out["otx"] == "UNKNOWN"
    assert "not a clean verdict" in out["note_otx"].lower()
    assert out["tor_exit"] is True
    assert "NOT evidence of maliciousness" in out["tor_note"]


# ---------------------------------------------------------------- DATA LEAKS / CHAIN / DONBOT

def test_dataleaks_optin_and_trim(monkeypatch):
    assert gr.tool_dataleaks("a@b.com", optin=False)["ok"] is False
    doc = {"BreachMetrics": {"breaches_count": 1},
           "PasteMetrics": {"pastes_count": 0},
           "ExposedBreaches": {"breaches": [
               {"breach": "ExampleBreach", "breachDate": "2021-05-01",
                "dataClasses": ["Email addresses", "Passwords"],
                "password": "SHOULD-NEVER-SURFACE"}]}}
    monkeypatch.setattr(gr, "_get",
                        lambda h, p, **kw: (200, json.dumps(doc).encode()))
    out = gr.tool_dataleaks("a@b.com", optin=True)
    assert out["ok"] is True
    blob = json.dumps(out)
    # The password VALUE must never surface; the data-class NAME
    # ("Passwords") is metadata and is allowed by design.
    assert "SHOULD-NEVER-SURFACE" not in blob
    assert out["breaches"][0]["name"] == "ExampleBreach"
    assert "Email addresses" in out["breaches"][0]["data_classes"]
    assert "BreachDirectory is not a source" in out["note"]


def test_chain_btc(monkeypatch):
    import osint as _osint
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assert _osint.wallet_info(addr)["chain"] == "BTC"
    def fake_get(host, path, **kw):
        if "mempool.space" in host and path.endswith("/txs"):
            return 200, json.dumps([{"txid": "a" * 64,
                                     "status": {"confirmed": True},
                                     "fee": 100}]).encode()
        if "mempool.space" in host:
            return 200, json.dumps({"chain_stats": {
                "funded_txo_sum": 1000, "spent_txo_sum": 400,
                "tx_count": 5}}).encode()
        if "coingecko" in host:
            return 200, json.dumps({"bitcoin": {"usd": 80000}}).encode()
        raise AssertionError(host)
    monkeypatch.setattr(gr, "_get", fake_get)
    monkeypatch.setattr(gr, "_sanctions_flag",
                        lambda a: {"evaluated": True, "match": True,
                                   "holder": "Test Holder",
                                   "label": "Snapshot match — NOT an identification"})
    out = gr.tool_chain(addr)
    assert out["ok"] is True and out["chain"] == "BTC"
    assert out["balance_sats"] == 600
    assert out["tx_count"] == 5
    assert len(out["transactions"]) == 1
    assert out["sanctions"]["match"] is True
    assert "not an attribution verdict" in out["note"]


def test_chain_sol_unavailable(monkeypatch):
    calls = []
    monkeypatch.setattr(gr, "_get", lambda h, p, **kw: (
        calls.append(h), (200, b"{}"))[1])
    out = gr.tool_chain("11111111111111111111111111111111")
    assert out["ok"] is True and out["chain"] == "SOL"
    assert out["available"] is False
    assert "not available in this build" in out["reason"]
    assert not any("solana" in h for h in calls)


def test_chain_sanctions_flag_real():
    # Real snapshot in the copy (age-checked by the loader itself).
    import osint as _osint
    snap = json.load(open(os.path.join(ROOT, "sanctions_snapshot.json"),
                          encoding="utf-8"))
    crypto = snap.get("crypto") or []
    assert crypto, "snapshot has no crypto entries"
    addr = str(crypto[0][0])
    flag = gr._sanctions_flag(addr)
    if flag.get("evaluated"):
        assert flag["match"] is True
        assert "NOT an identification" in flag["label"]
    else:
        # Stale snapshot -> honestly not evaluated, never a claim.
        assert flag == {"evaluated": False}


def test_donbot_parse(monkeypatch):
    def fake_get(host, path, **kw):
        if "/search" in path:
            return 200, json.dumps({"coins": [
                {"id": "bitcoin", "symbol": "btc",
                 "name": "Bitcoin"}]}).encode()
        if "/markets" in path:
            return 200, json.dumps([{
                "current_price": 80000, "market_cap": 1500000000000,
                "price_change_percentage_24h": 1.5,
                "total_volume": 30000000000}]).encode()
        raise AssertionError(path)
    monkeypatch.setattr(gr, "_get", fake_get)
    out = gr.tool_donbot("bitcoin")
    assert out["ok"] is True
    assert out["price_usd"] == 80000
    assert "no signal score" in out["label"]
    assert "digitaldon" not in json.dumps(out).lower().replace(
        "never contacts digitaldon.net", "")

# ---------------------------------------------------------------- ARCGIS

def _arcgis_get_factory(paths):
    def fake_get(host, path, **kw):
        paths.append((host, path))
        if "/sharing/rest/search" in path:
            return 200, json.dumps({"results": [
                {"title": "Power Plants", "type": "Feature Service",
                 "access": "public",
                 "url": "https://services2.arcgis.com/ABC/arcgis/rest/services/Power/FeatureServer"},
                {"title": "Private Set", "type": "Feature Service",
                 "access": "private",
                 "url": "https://services2.arcgis.com/ABC/arcgis/rest/services/Priv/FeatureServer"},
                {"title": "Off Family", "type": "Feature Service",
                 "access": "public",
                 "url": "https://evil.example.com/arcgis/rest/services/X/FeatureServer"},
            ]}).encode()
        if path.endswith("?f=pjson"):
            return 200, json.dumps({"layers": [
                {"id": 0, "name": "Plants"},
                {"id": 1, "name": "Lines"}]}).encode()
        if "/query" in path:
            return 200, json.dumps({"type": "FeatureCollection",
                                    "features": [
                {"type": "Feature",
                 "geometry": {"type": "Point",
                              "coordinates": [-84.3, 45.3]},
                 "properties": {"NAME": "Plant A", "STATE": "MI",
                                "K1": "v1", "K2": "v2", "K3": "v3",
                                "K4": "v4", "K5": "v5", "K6": "v6",
                                "K7": "v7", "K8": "v8", "K9": "v9"}}]}).encode()
        raise AssertionError("unexpected " + host + path)
    return fake_get


def test_arcgis_allowlist_caps_trim(monkeypatch):
    paths = []
    monkeypatch.setattr(gr, "_get", _arcgis_get_factory(paths))
    out = gr.arcgis_scan("power plants", [-180, -90, 180, 90])
    assert out["ok"] is True
    # Only the public in-family service survives.
    assert len(out["services"]) == 1
    svc = out["services"][0]
    assert svc["title"] == "Power Plants"
    assert svc["health"] == "ONLINE"
    # 8 keys per feature, service order.
    assert len(svc["features"][0]["properties"]) == 8
    assert "K9" not in svc["features"][0]["properties"]
    # Layer index is in the query path (service-root /query is 400).
    qpaths = [p for _h, p in paths if "/query" in p]
    assert qpaths and all(re.search(r"/\d+/query", p) for p in qpaths)
    assert "public items only" in out["note"]


def test_arcgis_validation():
    assert gr.arcgis_scan("bad!keyword", [-180, -90, 180, 90])["ok"] is False
    assert gr.arcgis_scan("power", [180, -90, -180, 90])["ok"] is False
    assert gr.arcgis_scan("power", [0, 0, 0])["ok"] is False


# ---------------------------------------------------------------- PERSPECTIVE / GEO

def test_perspective_bloc_table():
    assert gf._NEWS_BLOC == {"bbc": "western", "aljazeera": "regional",
                            "dw": "western", "npr": "western",
                            "france24": "western"}
    assert gf._NEWS_BLOC.get("unknown-outlet", "unclassified") \
        == "unclassified"


def test_perspective_client_chips():
    assert "data-abloc" in HTML
    assert "All sides" in HTML
    # The bloc filter applies to NEWS rows only.
    assert "r.cat === 'NEWS' && r.bloc !== bloc" in HTML
    # No AI strings ride along with the filter.
    assert "AI OVERVIEW" not in HTML
    assert "topic cluster" not in HTML.lower()


def test_geo_centroid_fallback(monkeypatch):
    def fake_bin(url, **kw):
        assert url.startswith("http://ip-api.com/json/")
        return 200, {}, json.dumps({
            "status": "success", "country": "Atlantis Testland",
            "countryCode": "US", "city": "", "lat": None, "lon": None,
            "isp": "Test ISP", "org": "", "as": "AS123 Test"}).encode(), False
    monkeypatch.setattr(gr, "_bin", fake_bin)
    m = gr.geo_for_ip("203.0.113.7")
    assert m is not None
    assert m["level"] == "country-approx"
    assert (m["lat"], m["lon"]) == (39.8, -98.6)


# ---------------------------------------------------------------- FINGERPRINT

def test_fingerprint_calibration(monkeypatch):
    db = {
        "SiteA": {"url": "https://sitea.example/{}",
                  "errorType": "status_code"},
        "SiteB": {"url": "https://siteb.example/{}",
                  "errorType": "status_code"},
    }
    monkeypatch.setattr(gr, "_fp_load_db", lambda: db)
    monkeypatch.setattr(gr, "_fp_control",
                        lambda: "ctrl111111111111")
    # Controls are fixed by the stub above; _fp_control is called
    # twice, so both controls are identical here — that still
    # exercises the either-control-lands rule for SiteA.
    def fake_check(site, entry, username, timeout=15.0):
        if username == "alice":
            return {"site": site, "url": "https://x.example/alice",
                    "status": "found"}
        if site == "SiteA":
            return {"site": site, "url": "https://x.example/ctrl",
                    "status": "found"}
        return {"site": site, "url": "https://x.example/ctrl",
                "status": "not_found"}
    monkeypatch.setattr(gr, "_fp_check", fake_check)
    lines = [json.loads(x) for x in gr.fingerprint_stream("alice")]
    kinds = [l["type"] for l in lines]
    assert kinds[0] == "start" and lines[0]["total"] == 2
    found = [l for l in lines if l["type"] == "site"
             and l["status"] == "found"]
    assert len(found) == 2
    assert all(l.get("tier") == "candidate" for l in found)
    cal = [l for l in lines if l["type"] == "calibration"]
    assert len(cal) == 1 and cal[0]["site"] == "SiteA"
    assert cal[0]["status"] == "inconclusive"
    summary = [l for l in lines if l["type"] == "summary"][0]
    assert summary["found"] == 1 and summary["inconclusive"] == 1


def test_fingerprint_db_filter_and_unavailable(monkeypatch):
    doc = {"$schema": "x",
           "Good": {"url": "https://good.example/{}",
                    "errorType": "status_code"},
           "Nsfw": {"url": "https://nsfw.example/{}",
                    "errorType": "status_code", "isNSFW": True},
           "NoType": {"url": "https://notype.example/{}"}}
    monkeypatch.setattr(gr, "_bin", lambda url, **kw: (
        200, {}, json.dumps(doc).encode(), False))
    # Fresh cache bucket for this test (db cache is global).
    gr._CACHES["sherlock"]._d.clear()
    db = gr._fp_load_db()
    assert db is not None
    assert set(db.keys()) == {"Good"}
    monkeypatch.setattr(gr, "_bin", lambda url, **kw: (0, {}, b"", False))
    gr._CACHES["sherlock"]._d.clear()
    assert gr._fp_load_db() is None
    lines = [json.loads(x) for x in gr.fingerprint_stream("alice")]
    assert lines[0]["type"] == "unavailable"
    # No fallback: the stream is exactly one line, no site rows.
    assert len(lines) == 1


def test_fingerprint_single_flight(monkeypatch):
    assert gr._FP_LOCK.acquire(blocking=False) is True
    try:
        lines = [json.loads(x) for x in gr.fingerprint_stream("alice")]
        assert lines[0]["type"] == "busy"
    finally:
        gr._FP_LOCK.release()


# ---------------------------------------------------------------- TLS op

def test_tls_op_present():
    assert '"tls"' in HELPER
    assert "def tls_audit" in FEEDS
    assert "no proxy configured for TLS audit" in HELPER


def test_tls_op_refuses_without_proxy(monkeypatch):
    import globe_fetch_helper as helper
    import urllib.request
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {})
    meta, _body = helper.execute({"op": "tls", "host": "example.com",
                                  "port": 443, "timeout": 5})
    assert meta["error"] == "no proxy configured for TLS audit"


def test_tls_op_via_stub_proxy():
    """End-to-end: stub CONNECT proxy + self-signed cert. The op
    must return the target cert DER (parsed subject), version and
    cipher; verify_ok is False for self-signed (honest)."""
    import ssl
    import threading
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime as _dt
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                            "tls-test.invalid")])
    cert = (x509.CertificateBuilder().subject_name(subject)
            .issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.now(_dt.timezone.utc)
                              - _dt.timedelta(days=1))
            .not_valid_after(_dt.datetime.now(_dt.timezone.utc)
                             + _dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("tls-test.invalid")]), critical=False)
            .sign(key, hashes.SHA256()))
    from cryptography.hazmat.primitives import serialization
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())
    open("/tmp/v1230-tls-cert.pem", "wb").write(cert_pem)
    open("/tmp/v1230-tls-key.pem", "wb").write(key_pem)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(5)
    srv.settimeout(30)

    def _serve():
        # Two CONNECTs: unverified capture + verify handshake.
        for _ in range(2):
            try:
                conn, _addr = srv.accept()
            except socket.timeout:
                return
            buf = b""
            try:
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain("/tmp/v1230-tls-cert.pem",
                                    "/tmp/v1230-tls-key.pem")
                try:
                    with ctx.wrap_socket(conn, server_side=True) as ss:
                        ss.recv(1)
                except Exception:
                    pass
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        srv.close()
    th = threading.Thread(target=_serve, daemon=True)
    th.start()
    import globe_fetch_helper as helper
    import urllib.request
    real = urllib.request.getproxies
    urllib.request.getproxies = lambda: {
        "https": "http://127.0.0.1:%d" % port}
    try:
        meta, _body = helper.execute({"op": "tls",
                                      "host": "tls-test.invalid",
                                      "port": 443, "timeout": 10})
    finally:
        urllib.request.getproxies = real
    th.join(timeout=35)
    assert meta.get("status") == "ok", meta
    assert meta.get("version", "").startswith("TLS")
    assert meta.get("cipher")
    assert meta.get("verify_ok") is False
    parsed = gf._parse_cert_der(__import__("base64").b64decode(
        meta["der_b64"]))
    assert "tls-test.invalid" in parsed["subject"]
    assert parsed["san"] == ["tls-test.invalid"]
    assert len(parsed["sha256"]) == 64


# ---------------------------------------------------------------- EXTRA16 / negative gates / client hosts

def test_extra16_parity():
    d = _extra16()
    assert set(d.keys()) == set(LANGS)
    keys = None
    for lang in LANGS:
        assert isinstance(d[lang], dict)
        if keys is None:
            keys = set(d[lang].keys())
        else:
            assert set(d[lang].keys()) == keys
        assert all(isinstance(v, str) and v for v in d[lang].values())
    assert len(keys) == 54


def test_extra16_covers_new_tr_keys():
    d = _extra16()
    used = {"SCAN", "LAYERS ACTIVE", "Features", "Extent", "Keyword",
            "Invalid keyword", "Catalog offline", "Scanning…",
            "Checked", "Done", "Cancelled", "Tool offline",
            "Invalid target", "All sides", "Western", "Regional",
            "Unclassified", "ArcGIS Intel", "PIPELINES", "POWER GRID",
            "INFRASTRUCTURE", "EMERGENCY", "sites…", "found",
            "inconclusive", "Cancel",
            "I authorize a breach lookup for this email"}
    keys = set(d["id"].keys())
    assert used <= keys


def test_negative_gates():
    py_all = APP2 + FEEDS + RECON + HELPER
    # Endpoint hostnames that must never be contacted.
    assert "widget.digitaldon" not in py_all
    assert "analyzer.digitaldon" not in py_all
    assert "api.shodan.io" not in py_all
    # Struck tools must not be offered in the picker.
    opts = re.search(r"const GL_RC_TOOLS = \[(.*?)\];", HTML, re.S)
    assert opts, "tool list not found"
    low = opts.group(1).lower()
    assert "global sweep" not in low
    assert "self track" not in low
    assert "remote" not in low
    assert "scm" not in low
    # Dollar is the Fed Broad Index, never labeled DXY: the short
    # label mapping must say DOLLAR (the word DXY appears in code
    # comments explaining the rule, which is not a label).
    assert "DTWEXBGS: 'DOLLAR'" in HTML
    # No new external hosts in the client: all v1.23.0 hosts are
    # daemon-side; the client only talks same-origin.
    for host in ("otx.alienvault.com", "check.torproject.org",
                 "api.coingecko.com", "mempool.space",
                 "eth.blockscout.com", "raw.githubusercontent.com",
                 "internetdb.shodan.io", "api.maclookup.app",
                 "stat.ripe.net", "api.mainnet-beta.solana.com",
                 "breachdirectory"):
        assert host not in HTML


def test_no_ai_no_draw_strings_in_panels():
    assert "AI OVERVIEW" not in HTML
    assert "Drawing Tools" not in HTML
    assert "data-gt=\"draw\"" not in HTML


def test_tools_session_timeout_cancel_source():
    # §14.1 (recovery fix): regular tool fetches get a 60 s/tool hard
    # timeout + user cancel, and completed results accumulate in an
    # in-memory session list capped at 200 rows (never DB-written).
    assert "glApi(path, opts)" in HTML
    assert "new AbortController()" in HTML
    assert "60000" in HTML
    assert "signal: ctl.signal" in HTML
    assert "_gl.rcAbort" in HTML
    assert "glRcCancelTool();" in HTML
    assert "glFpCancel(); glRcCancelTool();" in HTML
    assert "rc-session" in HTML
    assert "function glReconSessionPush" in HTML
    assert "ses.prepend(row)" in HTML
    assert "ses.children.length > 200" in HTML
    assert "glReconSessionPush(d.tool" in HTML


# ---------------------------------------------------------------- live server

class TestLiveServer:
    PORT = None
    PROC = None
    COOKIE = None

    @classmethod
    def _free_port(cls):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    @classmethod
    def setup_class(cls):
        import store as _store
        _store.init_db()
        try:
            _store.create_user("v1230test", "v1230testpw", "admin")
        except Exception:
            pass  # user already exists from a previous run
        cls.PORT = cls._free_port()
        env = dict(os.environ)
        env["PTK_ADMIN_PW"] = "unused-in-this-test"
        cls.PROC = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "app2.py"),
             str(cls.PORT)],
            cwd=ROOT, env=env, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(
                        "http://127.0.0.1:%d/login" % cls.PORT,
                        timeout=5) as r:
                    assert r.status == 200
                    break
            except Exception:
                if cls.PROC.poll() is not None:
                    raise AssertionError("test server exited early")
                time.sleep(1)
        else:
            raise AssertionError("test server did not come up")
        # Log in with the seeded user.
        req = urllib.request.Request(
            "http://127.0.0.1:%d/api/login" % cls.PORT,
            data=json.dumps({"username": "v1230test",
                             "password": "v1230testpw"}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.status == 200
            cls.COOKIE = r.headers.get("Set-Cookie", "").split(";")[0]

    @classmethod
    def teardown_class(cls):
        if cls.PROC is not None:
            cls.PROC.terminate()
            try:
                cls.PROC.wait(timeout=10)
            except Exception:
                cls.PROC.kill()

    def _get(self, path, authed=True):
        req = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (self.PORT, path))
        if authed and self.COOKIE:
            req.add_header("Cookie", self.COOKIE)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def test_login_page_version_and_csp(self):
        st, headers, _body = self._get("/login", authed=False)
        assert st == 200
        assert headers.get("Server", "").startswith("VANTHEX/1.25.0")
        assert headers.get("Content-Security-Policy") == CSP_1230

    def test_recon_requires_session(self):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.PORT,
                                          timeout=15)
        conn.request("GET",
                     "/api/osint/globe/recon?tool=dns&target=example.com")
        r = conn.getresponse()
        assert r.status == 302
        assert r.getheader("Location") == "/login"
        r.read()
        conn.close()

    def test_recon_invalid_shapes_authed(self):
        st, _h, body = self._get(
            "/api/osint/globe/recon?tool=nosuchtool&target=x")
        assert st == 200
        assert json.loads(body)["ok"] is False
        st, _h, body = self._get(
            "/api/osint/globe/recon?tool=dns&target=https://x.example/")
        assert json.loads(body)["ok"] is False
        st, _h, body = self._get(
            "/api/osint/globe/recon?tool=dataleaks&target=a@b.com")
        d = json.loads(body)
        assert d["ok"] is False and "opt-in" in d["reason"]
        st, _h, body = self._get(
            "/api/osint/globe/fingerprint?u=bad%20user!")
        assert json.loads(body)["ok"] is False
