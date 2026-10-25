"""v1.3.1: universal OSINT query — identifier detection + pivots.

Hermetic: every network answer comes from a simulated fetch and
monkeypatched DoH helpers, exactly like the v1.3 tests. Rules under
test: type detection per identifier shape; the >=2 independent-signal
corroboration rule for name-derived identities (1 signal MUST stay
candidate); institution domain guesses validated via DoH with failed
guesses reported; legacy payload compatibility (domain target +
handle option, no query) behaving exactly as before.
"""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

GOODHUB = [("GoodHub", "https://good.test/u/{h}", "profile:{h}")]

RDAP_JSON = json.dumps({
    "name": "FIXTURE-NET", "country": "ID",
    "remarks": [{"title": "ASN AS64500"}],
    "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}],
    "entities": [{"roles": ["registrant"],
                  "vcardArray": ["vcard", [["fn", {}, "text",
                                            "Fixture Hosting PT"]]]}]})

DOMAIN_MAP = [
    ("crt.sh", (200, "[]")),
    ("cdx/search", (0, "")),
    ("api.github.com/search/code", (401, "{}")),
    ("api.github.com/search/repositories", (200, '{"items": []}')),
    ("gitlab.com/api", (200, "[]")),
    ("rdap.org/ip/", (200, RDAP_JSON)),
]


def _mk_fetch(mapping, good_bodies=None):
    """fetch stub. good_bodies: {handle: body} served by good.test with
    the A3 marker format; unknown handles/junk get a 404."""
    good_bodies = good_bodies or {}

    def fetch(url, timeout=8, verify=False, cap=0, headers=None, _hops=0):
        if "good.test" in url:
            handle = url.rsplit("/", 1)[-1]
            if handle in good_bodies:
                return 200, [], good_bodies[handle].encode()
            return 404, [], b"no such user"
        for pat, spec in mapping:
            if pat in url:
                st, text = spec(url) if callable(spec) else spec
                return st, [], text.encode()
        return 0, [], b""
    return fetch


class _DohPatch:
    """Monkeypatch osint._doh_ips with a name->ips mapping function.

    v1.5.0: also neutralizes osint._doh_query (the DoH channel of the
    archive/hygiene modules) to 'no records', so typosquat/DNSBL/MX
    legs stay hermetic and deterministic in these tests."""

    def __init__(self, fn):
        self.fn = fn

    def __enter__(self):
        import osint
        self.orig = osint._doh_ips
        self.orig_q = osint._doh_query
        osint._doh_ips = self.fn
        osint._doh_query = lambda name, rrtype: []
        return self

    def __exit__(self, *a):
        import osint
        osint._doh_ips = self.orig
        osint._doh_query = self.orig_q


def _titles(res):
    return " | ".join(f["title"] for f in res["findings"])


# ------------------------------------------------------------- detection

def test_detect_query_types():
    import osint
    d = osint.detect_query_type
    assert d("jane@example.com") == "email"
    assert d("203.0.113.10") == "ip"
    assert d("2001:db8::1") == "ip"
    assert d("example.com") == "domain"
    assert d("https://sub.example.co.id/path?q=1") == "domain"
    assert d("http://203.0.113.10:8080/") == "ip"
    assert d("@janedoe") == "handle"
    assert d("janedoe") == "handle"
    assert d("jane.doe") == "handle"  # .doe is not a known TLD
    assert d("Jane Doe") == "name"
    assert d("Acme Corporation") == "name"
    assert d("") == "empty"


def test_query_subject_host():
    import osint
    h = osint.query_subject_host
    assert h("jane@example.com") == "example.com"
    assert h("203.0.113.10") == "203.0.113.10"
    assert h("https://example.com/x") == "example.com"
    assert h("Jane Doe") == ""
    assert h("@janedoe") == "" and h("janedoe") == ""


def test_generate_username_candidates():
    import osint
    c = osint.generate_username_candidates("Fixture User")
    assert c[0] == "fixtureuser"
    assert "fixture.user" in c and "fuser" in c and "fixture_user" in c
    assert len(c) <= 6
    assert osint.generate_username_candidates("Madonna") == ["madonna"]


# ------------------------------------------------------- legacy contract

def test_legacy_domain_payload_compat():
    import osint
    fetch = _mk_fetch(DOMAIN_MAP,
                      good_bodies={"fixtureuser": "profile:fixtureuser page"})
    with _DohPatch(lambda name: ["203.0.113.10"]):
        res = osint.run_osint_recon(
            "https://fixture.test", [], {"handle": "fixtureuser"},
            _fetch=fetch, _platforms=GOODHUB)
    assert res["detected_type"] == "domain"
    assert res["meta"]["domain"] == "fixture.test"
    assert res["meta"]["username"]["handle"] == "fixtureuser"
    assert res["meta"]["username"]["handle_source"] == "option"
    assert res["meta"]["username"]["probable"] == ["GoodHub"]
    assert res["meta"]["pivots_run"] == ["domain:fixture.test"]
    assert res["meta"]["query"] == "https://fixture.test"


def test_query_payload_domain():
    import osint
    fetch = _mk_fetch(DOMAIN_MAP, good_bodies={})
    with _DohPatch(lambda name: ["203.0.113.10"]):
        res = osint.run_osint_recon(
            "fixture.test", [], {"query": "fixture.test"},
            _fetch=fetch, _platforms=GOODHUB)
    assert res["detected_type"] == "domain"
    assert res["meta"]["domain"] == "fixture.test"


# ------------------------------------------------------------ handle pivot

def test_handle_pivot():
    import osint
    gh_user = {"login": "fixtureuser", "name": "Fixture User",
               "company": "", "blog": "", "public_repos": 3,
               "html_url": "https://github.com/fixtureuser"}
    gh_repos = [{"full_name": "fixtureuser/proj",
                 "html_url": "https://github.com/fixtureuser/proj",
                 "default_branch": "main"}]
    mapping = [
        ("api.github.com/users/fixtureuser/repos",
         (200, json.dumps(gh_repos))),
        ("api.github.com/users/fixtureuser", (200, json.dumps(gh_user))),
        ("raw.githubusercontent.com", (200, "# proj readme")),
        ("gitlab.com/api/v4/users", (200, "[]")),
    ]
    fetch = _mk_fetch(mapping,
                      good_bodies={"fixtureuser": "profile:fixtureuser page"})
    res = osint.run_osint_recon(
        "fixtureuser", [], {"query": "fixtureuser"},
        _fetch=fetch, _platforms=GOODHUB)
    assert res["detected_type"] == "handle"
    assert res["meta"]["username"]["probable"] == ["GoodHub"]
    assert res["meta"]["username"]["handle_source"] == "query"
    ce = res["meta"]["code_exposure"]
    assert ce["github_user"] == "fixtureuser", ce
    assert ce["github_repos"] == ["fixtureuser/proj"], ce
    assert "GitHub profile for handle 'fixtureuser'" in _titles(res)
    assert "username:fixtureuser" in res["meta"]["pivots_run"]
    assert "code_exposure:fixtureuser" in res["meta"]["pivots_run"]


# ------------------------------------------------------------- email pivot

def test_email_pivot():
    import osint
    digest = hashlib.md5(b"fixture@fixture.test").hexdigest()
    grav = {"entry": [{"displayName": "Fixture User",
                       "preferredUsername": "fixture",
                       "profileUrl": "https://gravatar.com/fixture"}]}
    mapping = [(f"gravatar.com/{digest}.json", (200, json.dumps(grav)))]
    mapping += DOMAIN_MAP
    fetch = _mk_fetch(mapping,
                      good_bodies={"fixture": "profile:fixture page"})
    with _DohPatch(lambda name: ["203.0.113.10"]):
        res = osint.run_osint_recon(
            "fixture@fixture.test", [], {"query": "fixture@fixture.test"},
            _fetch=fetch, _platforms=GOODHUB)
    assert res["detected_type"] == "email"
    assert res["meta"]["email"] == {"local_part": "fixture",
                                    "domain": "fixture.test"}
    assert res["meta"]["gravatar"]["profile"]["display_name"] == "Fixture User"
    assert "Gravatar profile" in _titles(res)
    # local part becomes the A3 handle of the domain pivot
    assert res["meta"]["username"]["handle"] == "fixture"
    assert res["meta"]["username"]["handle_source"] == "pivot"
    assert res["meta"]["username"]["probable"] == ["GoodHub"]
    assert "domain:fixture.test" in res["meta"]["pivots_run"]


# ---------------------------------------------------------------- IP pivot

def test_ip_pivot():
    import osint
    import scanners
    crt_rows = [{"name_value": "host.fixture.test\nother.fixture.test",
                 "not_after": "2999-01-01T00:00:00"}]
    mapping = [
        ("crt.sh", (200, json.dumps(crt_rows))),
        ("cdx/search", (0, "")),
        ("api.github.com/search/code", (401, "{}")),
        ("api.github.com/search/repositories", (200, '{"items": []}')),
        ("gitlab.com/api", (200, "[]")),
        ("rdap.org/ip/", (200, RDAP_JSON)),
    ]
    fetch = _mk_fetch(mapping, good_bodies={})
    doh_map = {"host.fixture.test": ["203.0.113.10"],
               "fixture.test": ["203.0.113.10"],
               "other.fixture.test": []}
    orig_doh_query = scanners.doh_query
    scanners.doh_query = (
        lambda name, rrtype="TXT", timeout=6.0:
        ["host.fixture.test."] if rrtype == "PTR" else None)
    try:
        with _DohPatch(lambda name: doh_map.get(name, [])):
            res = osint.run_osint_recon(
                "203.0.113.10", [], {"query": "203.0.113.10"},
                _fetch=fetch, _platforms=GOODHUB)
    finally:
        scanners.doh_query = orig_doh_query
    assert res["detected_type"] == "ip"
    assert res["meta"]["ip"]["ptr"] == ["host.fixture.test"]
    assert res["meta"]["ip"]["same_ip_names"] == ["host.fixture.test"]
    assert "Reverse DNS (PTR)" in _titles(res)
    assert res["meta"]["domain"] == "fixture.test"  # domain pivot ran
    assert "domain:fixture.test" in res["meta"]["pivots_run"]


# ------------------------------------------- person pivot: corroboration

def test_person_single_signal_stays_candidate():
    import osint
    mapping = [
        ("api.github.com/search/users", (200, '{"items": []}')),
        ("crt.sh", (200, "[]")),
    ]
    fetch = _mk_fetch(mapping, good_bodies={
        "fixtureuser": "profile:fixtureuser — Fixture User, engineer"})
    with _DohPatch(lambda name: []):
        res = osint.run_osint_recon(
            "Fixture User", [], {"query": "Fixture User"},
            _fetch=fetch, _platforms=GOODHUB)
    assert res["detected_type"] == "name"
    ident = res["meta"]["identity"]
    assert ident["candidates"][0] == "fixtureuser", ident
    acct = [a for a in ident["accounts"] if a["candidate"] == "fixtureuser"]
    assert acct and acct[0]["confidence"] == "candidate", ident
    assert len(acct[0]["signals"]) == 1, acct  # name display only
    assert ident["corroborated"] == []
    assert "identity NOT verified" in _titles(res)
    prob = [f for f in res["findings"]
            if f["confidence"] == "probable"
            and "fixtureuser" in f["title"].lower()]
    assert prob == [], prob


def test_person_two_signals_probable():
    import osint
    mapping = [
        ("api.github.com/search/users", (200, '{"items": []}')),
        ("crt.sh", (200, "[]")),
    ]
    fetch = _mk_fetch(mapping, good_bodies={
        "fixtureuser": "profile:fixtureuser — Fixture User, based in Jakarta"})
    with _DohPatch(lambda name: []):
        res = osint.run_osint_recon(
            "Fixture User Jakarta", [], {"query": "Fixture User Jakarta"},
            _fetch=fetch, _platforms=GOODHUB)
    ident = res["meta"]["identity"]
    assert ident["context_terms"] == ["jakarta"], ident
    assert ident["corroborated"] == ["fixtureuser"], ident
    hit = [f for f in res["findings"]
           if "identity corroborated" in f["title"]]
    assert hit and hit[0]["confidence"] == "probable", _titles(res)


# ------------------------------------------------------- institution pivot

def test_institution_domain_confirmed():
    import osint
    org_items = {"items": [{"login": "fixturemart",
                            "html_url": "https://github.com/fixturemart"}]}
    mapping = [("type:org", (200, json.dumps(org_items)))] + DOMAIN_MAP
    fetch = _mk_fetch(mapping, good_bodies={})
    with _DohPatch(lambda name: ["203.0.113.10"]
                   if name == "fixturemart.com" else []):
        res = osint.run_osint_recon(
            "Fixturemart Corporation", [],
            {"query": "Fixturemart Corporation"},
            _fetch=fetch, _platforms=GOODHUB)
    assert res["detected_type"] == "name"
    inst = res["meta"]["institution"]
    assert inst["confirmed_domain"] == "fixturemart.com", inst
    assert "fixturemart.net" in inst["failed_guesses"], inst
    assert inst["github_orgs"] == ["fixturemart"], inst
    assert "Likely official domain" in _titles(res)
    assert res["meta"]["domain"] == "fixturemart.com"  # domain pivot ran
    assert "domain:fixturemart.com" in res["meta"]["pivots_run"]


def test_institution_unresolved_reported():
    import osint
    mapping = [
        ("api.github.com/search/users", (200, '{"items": []}')),
        ("crt.sh", (200, "[]")),
    ]
    fetch = _mk_fetch(mapping, good_bodies={})
    with _DohPatch(lambda name: []):
        res = osint.run_osint_recon(
            "Nonexistent Widgets Group", [],
            {"query": "Nonexistent Widgets Group"},
            _fetch=fetch, _platforms=GOODHUB)
    inst = res["meta"]["institution"]
    assert inst["confirmed_domain"] is None
    assert inst["guesses"] and inst["failed_guesses"] == inst["guesses"]
    hit = [f for f in res["findings"] if "could not be confirmed" in f["title"]]
    assert hit and hit[0]["confidence"] == "candidate", _titles(res)


# ------------------------------------------------------ investigation graph

def _edge(g, source, target, relation):
    return [e for e in g["edges"]
            if e["source"] == source and e["target"] == target
            and e["relation"] == relation]


def _assert_dedup(g):
    keys = [(n["type"], n["label"].lower()) for n in g["nodes"]]
    assert len(keys) == len(set(keys)), "graph nodes not deduplicated"
    ids = [n["id"] for n in g["nodes"]]
    assert len(ids) == len(set(ids))


def test_graph_domain_query():
    import osint
    crt_rows = [
        {"name_value": "www.fixture.test", "not_after": "2999-01-01T00:00:00"},
        {"name_value": "old.fixture.test", "not_after": "2020-01-01T00:00:00"},
    ]
    mapping = [
        ("crt.sh", (200, json.dumps(crt_rows))),
        ("cdx/search", (0, "")),
        ("api.github.com/search/code", (401, "{}")),
        ("api.github.com/search/repositories", (200, '{"items": []}')),
        ("gitlab.com/api", (200, "[]")),
        ("rdap.org/ip/", (200, RDAP_JSON)),
    ]
    fetch = _mk_fetch(mapping, good_bodies={})
    doh = {"fixture.test": ["203.0.113.10"],
           "www.fixture.test": ["203.0.113.10"],
           "old.fixture.test": []}
    with _DohPatch(lambda name: doh.get(name, [])):
        res = osint.run_osint_recon(
            "fixture.test", [], {"query": "fixture.test"},
            _fetch=fetch, _platforms=GOODHUB)
    g = res["meta"]["graph"]
    stats = res["meta"]["graph_stats"]
    assert res["meta"]["graph_truncated"] is False
    _assert_dedup(g)
    assert any(n["type"] == "query" for n in g["nodes"]), g["nodes"]
    assert stats["nodes"] == len(g["nodes"])
    assert stats["edges"] == len(g["edges"])
    assert sum(stats["by_type"].values()) == stats["nodes"]
    assert stats["by_type"].get("domain") == 1
    assert stats["by_type"].get("asn") == 1
    e = _edge(g, "domain:fixture.test", "ip:203.0.113.10", "RESOLVES_TO")
    assert e and e[0]["confidence"] == "confirmed", g["edges"]
    e = _edge(g, "ip:203.0.113.10", "asn:as64500", "BELONGS_TO_ASN")
    assert e and e[0]["confidence"] == "probable", g["edges"]
    e = _edge(g, "ip:203.0.113.10", "cidr:203.0.113.0/24", "IN_CIDR")
    assert e, g["edges"]
    e = _edge(g, "domain:fixture.test", "subdomain:www.fixture.test",
              "HAS_SUBDOMAIN")
    assert e and e[0]["confidence"] == "probable", g["edges"]
    e = _edge(g, "domain:fixture.test", "subdomain:old.fixture.test",
              "HAS_SUBDOMAIN")
    assert e and e[0]["confidence"] == "candidate", g["edges"]
    # second degree: live CT name -> IP
    e = _edge(g, "subdomain:www.fixture.test", "ip:203.0.113.10",
              "RESOLVES_TO")
    assert e and e[0]["confidence"] == "confirmed", g["edges"]
    # root edge
    assert _edge(g, "query:fixture.test", "domain:fixture.test",
                 "LINKED_TO"), g["edges"]


def test_graph_name_query():
    import osint
    mapping = [
        ("api.github.com/search/users", (200, '{"items": []}')),
        ("crt.sh", (200, "[]")),
    ]
    fetch = _mk_fetch(mapping, good_bodies={
        "fixtureuser": "profile:fixtureuser — Fixture User, engineer"})
    with _DohPatch(lambda name: []):
        res = osint.run_osint_recon(
            "Fixture User", [], {"query": "Fixture User"},
            _fetch=fetch, _platforms=GOODHUB)
    g = res["meta"]["graph"]
    _assert_dedup(g)
    assert any(n["type"] == "person" for n in g["nodes"]), g["nodes"]
    assert any(n["type"] == "organization" for n in g["nodes"]), g["nodes"]
    e = _edge(g, "person:fixture user", "username:fixtureuser",
              "DERIVED_FROM_NAME")
    assert e and e[0]["confidence"] == "candidate", g["edges"]
    # only 1 identity signal -> FOUND_ON must NOT be probable
    e = _edge(g, "username:fixtureuser", "website:goodhub", "FOUND_ON")
    assert e and e[0]["confidence"] == "candidate", g["edges"]
    node = [n for n in g["nodes"] if n["id"] == "username:fixtureuser"]
    assert node and node[0]["confidence"] == "candidate", g["nodes"]
    stats = res["meta"]["graph_stats"]
    assert stats["nodes"] == len(g["nodes"])
    assert sum(stats["by_type"].values()) == stats["nodes"]


def test_graph_node_cap_truncation():
    import osint
    g = osint._Graph()
    for i in range(osint._Graph.MAX_NODES + 5):
        g.node("domain", f"d{i}.example.com", "info", "A1")
    graph, stats = g.build()
    assert stats["nodes"] == osint._Graph.MAX_NODES
    assert g.truncated is True
    assert len(graph["nodes"]) == osint._Graph.MAX_NODES
