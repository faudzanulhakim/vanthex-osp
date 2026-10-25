"""v1.13.3 — Feodo Tracker download host correction (abuse.ch family).

Measured diagnosis behind the fix: with ADE's genuine abuse.ch
Auth-Key installed, the family still died on its FIRST fetch. The
Feodo ipblocklist was requested from feodotracker-api.abuse.ch,
whose server drops the connection on the downloads path
('Remote end closed connection without response') — even with a
valid key — and because the family fetcher is all-or-nothing,
URLhaus was never attempted and BOTH sub-layers sat offline.
The plain download host feodotracker.abuse.ch answers 200 with
the blocklist JSON (measured live 2026-10-23; URLhaus recent also
200, query_status ok, with the same key).

Second defect in the same fetcher, found once the Feodo leg
passed: the URLhaus recent call went out as a POST with a form
body — the endpoint is GET-only and answers 405 with the literal
body {"query_status": "http_get_expected"}. A plain GET with the
Auth-Key header returns 200 and up to 1,000 recent URLs by
default. Both endpoint shapes are locked by the tests below.

Hermetic tests: gf._fetch_binary and gf._feed_keys are stubbed at
the module seams the family fetcher resolves at call time. No
external network, no real key.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import globe_feeds as gf  # noqa: E402

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

FEODO_BODY = json.dumps([
    {"ip_address": "203.0.113.7", "port": 8080, "malware": "Emotet",
     "status": "online", "first_seen": "2026-10-01",
     "last_online": "2026-10-23"},
    {"ip_address": "198.51.100.9", "port": 443, "malware": "QakBot",
     "status": "offline", "first_seen": "2026-09-14",
     "last_online": "2026-10-20"},
]).encode()

URLHAUS_BODY = json.dumps({
    "query_status": "ok",
    "urls": [
        {"url": "http://198.51.100.23/payload.exe",
         "url_status": "online", "date_added": "2026-10-23 01:02:03"},
        {"url": "http://203.0.113.55/drop.bin",
         "url_status": "offline", "date_added": "2026-10-23 02:03:04"},
    ],
}).encode()


class _Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, url, timeout=0.0, cap=0, headers=None,
                 method="GET", data=None):
        self.calls.append({"url": url, "headers": headers or {},
                           "method": method, "data": data})
        if "feodotracker" in url:
            return 200, {}, FEODO_BODY, False
        return 200, {}, URLHAUS_BODY, False


def test_abusech_family_fetches_feodo_from_download_host(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(gf, "_fetch_binary", rec)
    monkeypatch.setattr(gf, "_feed_keys",
                        lambda: {"abusech": "test-key", "firms": ""})
    out = gf._fetch_abusech_family()
    urls = [c["url"] for c in rec.calls]
    # Feodo is fetched FIRST, from the plain download host, exactly.
    assert urls[0] == FEODO_URL
    # The connection-dropping -api host must never be used for Feodo.
    assert all("feodotracker-api.abuse.ch" not in u for u in urls)
    # URLhaus recent is the second fetch: a plain GET on its API
    # host — no form body, no form Content-Type (POST is answered
    # 405 'http_get_expected' by the endpoint itself).
    assert urls[1] == URLHAUS_URL
    assert rec.calls[1]["method"] == "GET"
    assert rec.calls[1]["data"] is None
    assert "Content-Type" not in rec.calls[1]["headers"]
    # The Auth-Key header rides on both calls.
    assert all(c["headers"].get("Auth-Key") == "test-key"
               for c in rec.calls)
    # Both sub-layers come back populated from the canned bodies.
    assert out["botnet_c2"]["total"] == 2
    assert out["malware_urls"]["total"] == 2


def test_abusech_family_without_key_never_fetches(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(gf, "_fetch_binary", rec)
    monkeypatch.setattr(gf, "_feed_keys",
                        lambda: {"abusech": "", "firms": ""})
    with pytest.raises(gf._KeyMissing):
        gf._fetch_abusech_family()
    assert rec.calls == []
