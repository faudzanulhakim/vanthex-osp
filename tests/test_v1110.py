"""VANTHEX v1.11.0 — OSINT alignment pack (F1–F6) hermetic tests.

Design traps covered:
  * a sanctions NAME match alone is candidate + labelled
    "NAME MATCH ONLY — NOT AN IDENTIFICATION"; probable needs a
    hard attribute on the SAME entry, or an exact crypto address;
  * fuzzy/partial names never match; a missing or stale (>30d)
    snapshot makes the module "not evaluated", never fabricated;
  * wallet promotion requires a real checksum (Base58Check /
    Bech32 / EIP-55) — mutated lookalikes fall through; Solana is
    base58-to-32-bytes only;
  * phone detection is structural only: unknown country codes and
    wrong national lengths are rejected; carrier stays
    "not evaluated" by design;
  * XposedOrNot is an independent second breach source: one source
    failing never fails the other, agreement never raises the tier;
  * Telegram metadata comes from the public preview only;
  * the dataset gate mechanics: a catch-all platform FAILS the
    self-check, a well-behaved one passes;
  * a plain handle query grows no unprovoked sanctions/wallet/
    phone nodes.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, __file__.rsplit("/tests/", 1)[0])
import osint  # noqa: E402
import scanners  # noqa: E402


class _DohNone:
    def __enter__(self):
        self._orig = scanners.doh_query
        scanners.doh_query = lambda *a, **k: None
        return self

    def __exit__(self, *exc):
        scanners.doh_query = self._orig


def _fetch_factory(routes):
    def fetch(url, timeout=8, verify=False, cap=0, headers=None,
              _hops=0):
        for key, resp in routes.items():
            if key in url:
                return resp
        return (404, {}, b"")
    return fetch


EMPTY_FETCH = _fetch_factory({})

SNAP = {
    "v": 1, "snapshot_date": "2026-10-23", "source": "test fixture",
    "entries": [
        ["Fiktif Sanctionedperson", "Person", ["1970-01-15"], ["ru"],
         ["P12345"], ["Fiktif S. Person"]],
        ["Contoh Nama Umum", "Person", ["1985-05-05"], ["id"], [], []],
    ],
    "crypto": [["0x8589427373D6D84E98730D7795D8f6f8731FDA16",
                "Tornado Cash (fixture)"]],
}
TORNADO = "0x8589427373D6D84E98730D7795D8f6f8731FDA16"
GENESIS_BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


@pytest.fixture()
def snap_env(tmp_path, monkeypatch):
    p = tmp_path / "snap.json"
    p.write_text(json.dumps(SNAP), encoding="utf-8")
    monkeypatch.setenv("PTK_OSINT_SANCTIONS_SNAPSHOT", str(p))
    osint._sanctions_cache.clear()
    osint._sanctions_cache["state"] = None
    yield p
    osint._sanctions_cache.clear()
    osint._sanctions_cache["state"] = None


def _ctx(fetch=EMPTY_FETCH):
    ctx = osint._Ctx(fetch, lambda m: None, {}, None)
    ctx.root_id = ctx.graph.node("query", "fixture", "info")
    return ctx


# ------------------------------------------------------------ Keccak

def test_keccak256_vectors():
    assert osint._keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    assert osint._keccak256(b"abc").hex() == (
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
    # hashlib.sha3_256 is a DIFFERENT function (FIPS padding) — the
    # engine must not silently be that:
    import hashlib
    assert osint._keccak256(b"").hex() != hashlib.sha3_256(b"").hexdigest()


def test_eip55_canonical_addresses():
    for addr in ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                 "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                 "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
                 "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"):
        assert osint._eip55_checksum_ok(addr) == "valid", addr
        assert osint._eip55_checksum_ok(addr.lower()) == "plain", addr


# ------------------------------------------------------------ wallet

def test_wallet_detection_gates():
    assert osint.wallet_info(GENESIS_BTC)["chain"] == "BTC"
    assert osint.wallet_info(GENESIS_BTC[:-1] + "b") is None
    assert osint.wallet_info(
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")["chain"] == "BTC"
    assert osint.wallet_info(
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5") is None
    taproot = ("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr"
               "9rusxg3297")
    assert osint.wallet_info(taproot)["chain"] == "BTC"
    assert osint.wallet_info(
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")["chain"] == "ETH"
    assert osint.wallet_info(
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD") is None
    assert osint.wallet_info(
        "11111111111111111111111111111111")["chain"] == "SOL"
    assert osint.wallet_info("z" * 44) is None  # decodes != 32 bytes
    assert osint.wallet_info("somehandle") is None
    assert osint.wallet_info("a" * 40) is None  # hex-ish, no 0x


def test_detect_query_type_new_types():
    assert osint.detect_query_type(GENESIS_BTC) == "wallet"
    assert osint.detect_query_type(TORNADO) == "wallet"
    assert osint.detect_query_type("+62 812-3456-7890") == "phone"
    assert osint.detect_query_type("example.com") == "domain"
    assert osint.detect_query_type("john doe") == "name"
    assert osint.detect_query_type("johndoe") == "handle"


def test_btc_wallet_summary_hermetic(snap_env):
    fetch = _fetch_factory({
        "/txs": (200, {}, json.dumps([
            {"txid": "a", "status": {"confirmed": True,
                                     "block_time": 1700000000}},
            {"txid": "b", "status": {"confirmed": True,
                                     "block_time": 1600000000}},
            {"txid": "c", "status": {"confirmed": True,
                                     "block_time": 1650000000}},
        ]).encode()),
        "blockstream.info/api/address/": (200, {}, json.dumps({
            "chain_stats": {"funded_txo_sum": 150000000,
                            "spent_txo_sum": 50000000,
                            "tx_count": 3}}).encode()),
    })
    with _DohNone():
        res = osint.run_osint_recon("x", log=[],
                                    opts={"query": GENESIS_BTC},
                                    _fetch=fetch)
    summ = res["meta"]["wallet"]["summary"]
    assert summ["balance_btc"] == 1.0 and summ["tx_count"] == 3
    assert summ["first_seen"].startswith("2020-")
    assert summ["last_seen"].startswith("2023-")
    assert res["meta"]["wallet"]["sanctioned"] is False


def test_btc_first_seen_not_evaluated_when_paged(snap_env):
    # tx_count (30) exceeds the fetched page (2) -> first seen must
    # stay "not evaluated", last seen is real.
    fetch = _fetch_factory({
        "/txs": (200, {}, json.dumps([
            {"txid": "a", "status": {"confirmed": True,
                                     "block_time": 1700000000}},
            {"txid": "b", "status": {"confirmed": True,
                                     "block_time": 1690000000}},
        ]).encode()),
        "blockstream.info/api/address/": (200, {}, json.dumps({
            "chain_stats": {"funded_txo_sum": 10, "spent_txo_sum": 0,
                            "tx_count": 30}}).encode()),
    })
    with _DohNone():
        res = osint.run_osint_recon("x", log=[],
                                    opts={"query": GENESIS_BTC},
                                    _fetch=fetch)
    summ = res["meta"]["wallet"]["summary"]
    assert summ["first_seen"] == "not evaluated"
    assert summ["last_seen"].startswith("2023-")


# ------------------------------------------------------------- phone

def test_phone_structural_gates():
    p = osint.parse_phone("+62 812-3456-7890")
    assert p["region"] == "Indonesia" and p["e164"] == "+6281234567890"
    assert osint.parse_phone("+1 (202) 555-0123")["country_code"] == "1"
    assert osint.parse_phone("+44 20 7946 0958")["region"] == \
        "United Kingdom"
    assert osint.parse_phone("+999123456789") is None   # unknown CC
    assert osint.parse_phone("+62 812") is None        # too short
    assert osint.parse_phone("0812-3456-7890") is None  # no '+' prefix
    assert osint.parse_phone("+49 30 90182012")["country_code"] == "49"


def test_phone_pivot_meta_no_enrichment(snap_env):
    with _DohNone():
        res = osint.run_osint_recon(
            "x", log=[], opts={"query": "+62 812-3456-7890"},
            _fetch=EMPTY_FETCH)
    ph = res["meta"]["phone"]
    assert ph["carrier"] == "not evaluated"
    assert ph["line_type"] == "not evaluated"
    assert ph["owner"] == "not evaluated"
    assert res["detected_type"] == "phone"
    assert any("phone carrier" in s for s in
               res["meta"]["coverage"]["modules_not_evaluated"])


# ---------------------------------------------------------- sanctions

def test_sanctions_name_only_is_candidate(snap_env):
    hits = osint.sanctions_match_name("Fiktif Sanctionedperson")
    assert hits and hits[0]["tier"] == "candidate"
    assert hits[0]["attribute"] is None
    ctx = _ctx()
    osint._sanctions_check_name(ctx, "Fiktif Sanctionedperson",
                                "test source")
    f = [x for x in ctx.findings if "NOT an identification"
         in x["title"]]
    assert f and f[0]["confidence"] == "candidate"
    node = [n for n in ctx.graph.build()[0]["nodes"]
            if n["type"] == "sanction"]
    assert node and node[0]["flag"] == "sanctions_name"


def test_sanctions_attribute_match_is_probable(snap_env):
    hits = osint.sanctions_match_name(
        "Fiktif Sanctionedperson", {"dob": ["1970-01-15"]})
    assert hits and hits[0]["tier"] == "probable"
    assert hits[0]["attribute"] == "date of birth"
    hits = osint.sanctions_match_name(
        "Fiktif Sanctionedperson", {"nationality": ["RU"]})
    assert hits and hits[0]["tier"] == "probable"
    hits = osint.sanctions_match_name(
        "Fiktif Sanctionedperson", {"dob": ["1999-12-31"]})
    assert hits and hits[0]["tier"] == "candidate"  # wrong DOB


def test_sanctions_alias_and_no_fuzzy(snap_env):
    assert osint.sanctions_match_name("Fiktif S. Person")
    assert osint.sanctions_match_name("Fiktif Sanctionedperson Jr") == []
    assert osint.sanctions_match_name("Sanctionedperson") == []
    assert osint.sanctions_match_name("Nama Tidak Terdaftar") == []


def test_sanctions_address_exact(snap_env):
    hit = osint.sanctions_match_address(TORNADO)
    assert hit and "Tornado" in hit["holder"]
    assert osint.sanctions_match_address(TORNADO.lower())
    assert osint.sanctions_match_address(GENESIS_BTC) is None
    ctx = _ctx()
    wid = ctx.graph.node("wallet", TORNADO, "probable", "F2")
    out = osint._sanctions_flag_address(ctx, TORNADO, wid, "test")
    assert out is not None
    node = [n for n in ctx.graph.build()[0]["nodes"]
            if n["type"] == "wallet"][0]
    assert node["flag"] == "sanctioned_address"
    assert any(f["confidence"] == "probable" for f in ctx.findings)


def test_sanctions_missing_snapshot_not_evaluated(tmp_path, monkeypatch):
    monkeypatch.setenv("PTK_OSINT_SANCTIONS_SNAPSHOT",
                       str(tmp_path / "nope.json"))
    osint._sanctions_cache.clear()
    osint._sanctions_cache["state"] = None
    state, _d, reason = osint._sanctions_load()
    assert state == "not evaluated" and reason
    assert osint.sanctions_match_name("Fiktif Sanctionedperson") == []
    ctx = _ctx()
    osint._sanctions_check_name(ctx, "Fiktif Sanctionedperson", "test")
    assert ctx.meta["sanctions"]["status"] == "not evaluated"
    assert not [n for n in ctx.graph.build()[0]["nodes"]
                if n["type"] == "sanction"]


def test_sanctions_stale_snapshot_not_evaluated(tmp_path, monkeypatch):
    stale = dict(SNAP, snapshot_date="2020-01-01")
    p = tmp_path / "stale.json"
    p.write_text(json.dumps(stale), encoding="utf-8")
    monkeypatch.setenv("PTK_OSINT_SANCTIONS_SNAPSHOT", str(p))
    osint._sanctions_cache.clear()
    osint._sanctions_cache["state"] = None
    state, _d, reason = osint._sanctions_load()
    assert state == "not evaluated" and "days old" in reason


def test_name_query_sanctions_flow(snap_env):
    with _DohNone():
        res = osint.run_osint_recon(
            "x", log=[], opts={"query": "Fiktif Sanctionedperson"},
            _fetch=EMPTY_FETCH)
    assert res["meta"]["sanctions"]["status"] == "ok"
    assert res["meta"]["sections"]["sanctions"]["status"] == "ok"
    assert any(n["type"] == "sanction"
               for n in res["meta"]["graph"]["nodes"])


# --------------------------------------------------------------- XON

def test_xposedornot_independent_source(snap_env):
    fetch = _fetch_factory({
        "api.xposedornot.com": (200, {}, json.dumps({
            "BreachesSummary": {"site": "BreachOne;BreachTwo"},
            "ExposedBreaches": []}).encode()),
    })
    with _DohNone():
        res = osint.run_osint_recon(
            "x", log=[], opts={"query": "victim@example.org",
                               "breach": True}, _fetch=fetch)
    em = res["meta"]["breach"]["email"]
    assert em["sources"]["xposedornot"] == "reported"
    assert em["sources"]["hudsonrock"] == "not evaluated"  # HR 404'd
    bt = [f for f in res["findings"] if "XposedOrNot" in f["title"]]
    assert bt and bt[0]["confidence"] == "candidate"


def test_xposedornot_not_reported(snap_env):
    fetch = _fetch_factory({
        "api.xposedornot.com": (200, {}, json.dumps({
            "BreachesSummary": {"site": ""},
            "ExposedBreaches": None}).encode()),
        "cavalier.hudsonrock.com": (200, {}, json.dumps(
            {"data": {"total": 0}}).encode()),
    })
    with _DohNone():
        res = osint.run_osint_recon(
            "x", log=[], opts={"query": "clean@example.org",
                               "breach": True}, _fetch=fetch)
    em = res["meta"]["breach"]["email"]
    assert em["sources"] == {"hudsonrock": "not_reported",
                             "xposedornot": "not_reported"}
    assert not [f for f in res["findings"] if "Breach" in f["title"]]


# ------------------------------------------------------------ Telegram

TG_HTML = """
<div class="tgme_channel_info_header_title"><span dir="auto">Fixture
News</span></div>
<div class="tgme_channel_info_counters">
<span class="tgme_channel_info_counter_value">12.4K</span>
<span class="tgme_channel_info_counter_label">subscribers</span>
<span class="tgme_channel_info_counter_value">321</span>
<span class="tgme_channel_info_counter_label">photos</span></div>
<div class="tgme_channel_info_description">A fixture channel<br>about
nothing.</div>"""


def test_telegram_preview_parse(snap_env):
    fetch = _fetch_factory({"t.me/s/": (200, {}, TG_HTML.encode())})
    ctx = _ctx(fetch)
    meta = osint._telegram_channel_meta(ctx, "fixturechan")
    assert meta["title"] == "Fixture News"
    assert meta["subscribers"] == "12.4K"
    assert "fixture channel" in meta["description"]
    assert osint._telegram_channel_meta(ctx, "gone") is not None
    dead = _ctx(EMPTY_FETCH)
    assert osint._telegram_channel_meta(dead, "gone") is None


def test_telegram_extraction_hook(snap_env):
    fetch = _fetch_factory({"t.me/s/": (200, {}, TG_HTML.encode())})
    ctx = _ctx(fetch)
    page = ctx.graph.node("website", "https://site.test/", "candidate",
                          "A6")
    page_html = ('<html><body>Contact us '
                 '<a href="https://t.me/fixturechan">Telegram</a> '
                 'or mail team@site.test</body></html>')
    osint._extract_entities(ctx, page_html, "https://site.test/", page)
    nodes = ctx.graph.build()[0]["nodes"]
    tg = [n for n in nodes if n["type"] == "telegram_channel"]
    assert tg and tg[0]["title"] == "Fixture News"
    assert ctx.meta["telegram"]["channels"][0]["channel"] == \
        "fixturechan"


def test_wallet_extraction_hook(snap_env):
    ctx = _ctx()
    page = ctx.graph.node("website", "https://site.test/", "candidate",
                          "A6")
    body = (f"<html><body>Donate BTC: {GENESIS_BTC} — not this "
            f"fake: {GENESIS_BTC[:-1]}b — sha "
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b"
            "0f00a08</body></html>")
    found = osint._extract_entities(ctx, body, "https://site.test/",
                                    page)
    assert found["wallets"] == {GENESIS_BTC}
    wallets = [n for n in ctx.graph.build()[0]["nodes"]
               if n["type"] == "wallet"]
    assert len(wallets) == 1


# ------------------------------------------------------------- dataset

def test_dataset_growth_and_claimed_handles():
    assert len(osint.PLATFORM_SCHEMA) >= 275
    names = [p["name"] for p in osint.PLATFORM_SCHEMA]
    assert len(names) == len(set(names))
    for expected in ("Codewars", "Kaskus", "Habr", "Wikipedia",
                     "Wakatime", "VirusTotal", "Tistory"):
        assert expected in osint._PLATFORM_BY_NAME
        assert osint._PLATFORM_CLAIMED.get(expected)


def test_self_check_gate_mechanics(monkeypatch):
    by_name = dict(osint._PLATFORM_BY_NAME)
    by_name["FakeGood"] = {"claimed_handle": "realuser",
                           "unclaimed_handle": "zzzznope"}
    by_name["FakeCatch"] = {"claimed_handle": "realuser",
                            "unclaimed_handle": "zzzznope"}
    monkeypatch.setattr(osint, "_PLATFORM_BY_NAME", by_name)

    def fetch(url, timeout=7, verify=False, cap=0, headers=None,
              _hops=0):
        if "fakegood.test" in url:
            if "/u/realuser" in url:
                return (200, {}, b"profile of realuser here")
            return (404, {}, b"no such user")
        if "fakecatch.test" in url:
            handle = url.rsplit("/u/", 1)[-1]
            return (200, {}, f"profile of {handle} here".encode())
        return (404, {}, b"")

    plats = [("FakeGood", "https://fakegood.test/u/{h}", "{h}"),
             ("FakeCatch", "https://fakecatch.test/u/{h}", "{h}")]
    rep = osint.self_check_platforms(fetch=fetch, platforms=plats,
                                     apply_disable=False)
    by_name = {r["platform"]: r["status"] for r in rep}
    assert by_name["FakeGood"] == "pass"
    assert by_name["FakeCatch"] == "fail"  # catch-all claims the junk


def test_handle_query_no_unprovoked_nodes(snap_env):
    with _DohNone():
        res = osint.run_osint_recon(
            "x", log=[], opts={"query": "somehandle42"},
            _fetch=EMPTY_FETCH, _platforms=[])
    types = {n["type"] for n in res["meta"]["graph"]["nodes"]}
    assert "sanction" not in types
    assert "wallet" not in types
    assert res["detected_type"] == "handle"
