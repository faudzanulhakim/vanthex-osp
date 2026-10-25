"""v1.5.0: OSINT archive & hygiene pack (P1-P3) — hermetic traps.

Every network answer comes from a stub fetch plus doubles for
osint._doh_ips / osint._doh_query (the DoH channel). Rules under
test: archive data is HISTORICAL candidate evidence only, malformed
CDX rows are skipped and caps hold; PassiveDNS is a named single
source, candidate unless corroborated by a current DoH A record;
typosquat existence comes from DoH only, unregistered candidates
never become nodes, the 300 cap holds, and a full DoH outage is
'not evaluated' (not 'nothing registered'); DNSBL blocked-resolver
error codes (127.255.255.x) are NOT listings, zone TXT reasons are
read, and not-listed produces meta only; email checks are signals —
dead domain and disposable are candidate/info findings, an empty MX
is never an 'invalid format' verdict, and a failed MX lookup is
'not evaluated'.
"""
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


def _mk_fetch(mapping):
    def fetch(url, timeout=8, verify=False, cap=0, headers=None, _hops=0):
        if "good.test" in url:
            return 404, [], b"no such user"
        for pat, spec in mapping:
            if pat in url:
                st, text = spec(url) if callable(spec) else spec
                return st, [], text.encode()
        return 0, [], b""
    return fetch


def _base_mapping(**over):
    m = [
        ("crt.sh", (200, "[]")),
        ("cdx/search", (0, "")),
        ("api.hackertarget.com", (0, "")),
        ("api.github.com/search/code", (401, "{}")),
        ("api.github.com/search/repositories", (200, '{"items": []}')),
        ("gitlab.com/api", (200, "[]")),
        ("rdap.org/ip/", (200, RDAP_JSON)),
        ("gravatar.com", (404, "")),
    ]
    for pat, spec in over.items():
        m = [(p, s) for p, s in m if p != pat] + [(pat, spec)]
    return m


class _DoH:
    """Patch osint._doh_ips (name->[ips]) and osint._doh_query
    ((name, rrtype)->answers|None); unlisted names default to the
    given defaults."""

    def __init__(self, ips=None, answers=None, default_ips=(),
                 default_ans=()):
        self.ips = ips or {}
        self.answers = answers or {}
        self.default_ips = list(default_ips)
        self.default_ans = default_ans

    def __enter__(self):
        import osint
        self._o1, self._o2 = osint._doh_ips, osint._doh_query
        osint._doh_ips = lambda name: list(
            self.ips.get(name, self.default_ips))
        osint._doh_query = lambda name, rrtype: (
            self.answers[name, rrtype]
            if (name, rrtype) in self.answers else self.default_ans)
        return self

    def __exit__(self, *a):
        import osint
        osint._doh_ips, osint._doh_query = self._o1, self._o2


def _run(target, mapping, doh, query=None):
    import osint
    fetch = _mk_fetch(mapping)
    with doh:
        return osint.run_osint_recon(
            target, [], {"query": query or target},
            _fetch=fetch, _platforms=GOODHUB)


def _titles(res):
    return " | ".join(f["title"] for f in res["findings"])


def _edges(res, relation):
    return [e for e in res["meta"]["graph"]["edges"]
            if e["relation"] == relation]


# ------------------------------------------------------------------ P1

def test_archive_hosts_paths_and_traps():
    import osint  # noqa: F401
    cdx = [
        ["timestamp", "original", "statuscode", "mimetype"],
        ["20200102030405", "http://fixture.test/", "200", "text/html"],
        ["20230102030405", "http://www.fixture.test/index", "200",
         "text/html"],
        ["20190506070809", "http://fixture.test/.git/config", "200",
         "text/plain"],
        ["20220101000000", "http://fixture.test/backup/site.zip", "200",
         "application/zip"],
        ["20210101000000", "http://fixture.test/static/app.js", "200",
         "text/javascript"],
        ["20240101000000", "http://fixture.test/.git/config", "200",
         "text/plain"],
        ["garbage-row"],                      # malformed: too short
        "not-a-list-row",                     # malformed: not a list
        ["not-a-date", "http://fixture.test/x", "200", "text/html"],
    ]
    res = _run("fixture.test",
               _base_mapping(**{"cdx/search": (200, json.dumps(cdx))}),
               _DoH(ips={"fixture.test": ["203.0.113.10"]}))
    arc = res["meta"]["archive"]
    assert arc["status"] == "evaluated", arc
    assert arc["captures_total"] == 6, arc        # malformed rows skipped
    assert arc["hosts_seen"] == 2, arc
    assert arc["hostnames"] == ["fixture.test", "www.fixture.test"], arc
    assert arc["earliest"] == "2019-05-06", arc
    assert arc["latest"] == "2024-01-01", arc
    paths = {p["url"]: p["captured"] for p in arc["interesting_paths"]}
    assert paths["http://fixture.test/.git/config"] == "2024-01-01", paths
    assert "http://fixture.test/backup/site.zip" in paths, paths
    assert not any("app.js" in u for u in paths), paths
    hit = [f for f in res["findings"]
           if "Historically public exposure-shaped" in f["title"]]
    assert hit and hit[0]["confidence"] == "candidate", _titles(res)
    assert "HISTORICAL" in hit[0]["description"], hit[0]
    e = _edges(res, "SEEN_IN_ARCHIVE")
    assert any(x["target"] == "subdomain:www.fixture.test"
               and x["confidence"] == "candidate" for x in e), e
    www_edge = [x for x in e
                if x["target"] == "subdomain:www.fixture.test"][0]
    assert "captured 2023-01-02" in www_edge["evidence"], www_edge
    nodes = {n["id"]: n for n in res["meta"]["graph"]["nodes"]}
    assert nodes["subdomain:www.fixture.test"].get("archived") is True
    assert nodes["domain:fixture.test"].get("archived") is True  # enriched
    assert not any(x["source"] == x["target"] for x in e)  # no self-edge
    assert "archive" in res["meta"]["sections"]


def test_archive_unavailable_is_not_evaluated():
    res = _run("fixture.test", _base_mapping(),
               _DoH(ips={"fixture.test": ["203.0.113.10"]}))
    arc = res["meta"]["archive"]
    assert arc["status"] == "not evaluated", arc
    assert _edges(res, "SEEN_IN_ARCHIVE") == []
    assert any("archive" in w for w in res["warnings"]), res["warnings"]


def test_archive_host_cap():
    rows = [["timestamp", "original", "statuscode", "mimetype"]]
    rows += [[f"2020{1 + i % 12:02d}01000000",
              f"http://h{i}.fixture.test/x", "200", "text/html"]
             for i in range(150)]
    res = _run("fixture.test",
               _base_mapping(**{"cdx/search": (200, json.dumps(rows))}),
               _DoH(ips={"fixture.test": ["203.0.113.10"]}))
    arc = res["meta"]["archive"]
    assert arc["hosts_seen"] == 150, arc["hosts_seen"]
    assert arc["hosts"] == 100, arc["hosts"]     # cap holds
    assert "capped" in arc.get("note", ""), arc


# ----------------------------------------------------------------- P2a

def test_passivedns_tiers_and_single_source():
    body = ("www.fixture.test,203.0.113.10\n"
            "old.fixture.test,192.0.2.55\n"
            "badline-without-comma\n"
            "noip.fixture.test,not-an-ip\n"
            "www.fixture.test,203.0.113.10\n")   # duplicate pair
    res = _run("fixture.test",
               _base_mapping(
                   **{"api.hackertarget.com": (200, body)}),
               _DoH(ips={"fixture.test": ["203.0.113.10"],
                         "www.fixture.test": ["203.0.113.10"],
                         "old.fixture.test": []}))
    pd = res["meta"]["passivedns"]
    assert pd["status"] == "evaluated", pd
    assert pd["source"] == "hackertarget", pd
    assert pd["pairs"] == 2, pd                    # junk + dup dropped
    assert pd["corroborated"] == 1, pd
    e = {x["target"]: x for x in _edges(res, "PASSIVE_DNS")}
    assert e["subdomain:www.fixture.test"]["confidence"] == "probable", e
    assert e["subdomain:old.fixture.test"]["confidence"] == "candidate", e
    assert "single source" in e["subdomain:www.fixture.test"]["evidence"]
    hit = [f for f in res["findings"]
           if "Passive DNS records" in f["title"]]
    assert hit and hit[0]["confidence"] == "candidate", _titles(res)
    assert "passivedns" in res["meta"]["sections"]


def test_passivedns_error_is_not_evaluated():
    res = _run("fixture.test",
               _base_mapping(
                   **{"api.hackertarget.com":
                      (200, "error API count exceeded")}),
               _DoH(ips={"fixture.test": ["203.0.113.10"]}))
    assert res["meta"]["passivedns"]["status"] == "not evaluated"
    assert _edges(res, "PASSIVE_DNS") == []


# ----------------------------------------------------------------- P2b

def test_typosquat_registered_mail_flag_and_nodes():
    answers = {
        ("fixture.com", "A"): ["192.0.2.1"],
        ("fixture.com", "MX"): [],
        ("fixturee.test", "A"): [],
        ("fixturee.test", "NS"): [],
        ("fixturee.test", "MX"): ["10 mail.fixturee.test."],
    }
    res = _run("fixture.test", _base_mapping(),
               _DoH(ips={"fixture.test": ["203.0.113.10"]},
                    answers=answers))
    tq = res["meta"]["typosquat"]
    assert tq["status"] == "evaluated", tq
    assert tq["generated"] == tq["checked"], tq
    assert tq["registered"] == 2, tq
    assert tq["mail_capable"] == 1, tq
    e = {x["target"]: x for x in _edges(res, "TYPOSQUAT_OF")}
    assert "domain:fixture.com" in e, e
    assert "domain:fixturee.test" in e, e
    assert "mail-capable" in e["domain:fixturee.test"]["evidence"], e
    assert "mail-capable" not in e["domain:fixture.com"]["evidence"], e
    node_ids = {n["id"] for n in res["meta"]["graph"]["nodes"]}
    assert "domain:ixture.test" not in node_ids  # unregistered: no node
    hit = [f for f in res["findings"]
           if "typosquat-candidate" in f["title"]]
    assert hit and hit[0]["confidence"] == "candidate", _titles(res)
    assert "typosquat" in res["meta"]["sections"]


def test_typosquat_cap_300():
    import osint
    domain = "abcdefghij0123456789klmnopqrstuvwxyzabcd.test"
    assert len(osint._typosquat_candidates(domain)) > 300
    res = _run(domain, _base_mapping(), _DoH())
    tq = res["meta"]["typosquat"]
    assert tq["generated"] > 300, tq
    assert tq["checked"] == 300, tq               # cap holds
    assert tq["registered"] == 0, tq


def test_typosquat_doh_outage_is_not_evaluated():
    res = _run("fixture.test", _base_mapping(),
               _DoH(ips={"fixture.test": ["203.0.113.10"]},
                    default_ans=None))
    tq = res["meta"]["typosquat"]
    assert tq["status"] == "not evaluated", tq
    assert tq["registered"] == 0, tq
    assert _edges(res, "TYPOSQUAT_OF") == []


# ----------------------------------------------------------------- P2c

def test_dnsbl_listed_reads_zone_reason():
    answers = {
        ("fixture.test.dbl.spamhaus.org", "A"): ["127.0.1.2"],
        ("fixture.test.dbl.spamhaus.org", "TXT"):
            ['"fixture.test is listed; see https://spamhaus.org/dbl"'],
    }
    res = _run("fixture.test", _base_mapping(),
               _DoH(ips={"fixture.test": ["203.0.113.10"]},
                    answers=answers))
    rep = res["meta"]["reputation"]
    assert rep["status"] == "evaluated", rep
    assert rep["zones_checked"] == 3, rep
    assert rep["listed"] and rep["listed"][0]["zone"] == \
        "dbl.spamhaus.org", rep
    assert "is listed; see" in rep["listed"][0]["reason"], rep
    hit = [f for f in res["findings"] if "is listed in the" in f["title"]]
    assert hit and hit[0]["confidence"] == "probable", _titles(res)
    assert "zone reason" in hit[0]["evidence"], hit[0]


def test_dnsbl_error_code_is_not_a_listing():
    answers = {
        ("fixture.test.dbl.spamhaus.org", "A"): ["127.255.255.254"],
        ("fixture.test.multi.surbl.org", "A"): ["127.255.255.252"],
    }
    res = _run("fixture.test", _base_mapping(),
               _DoH(ips={"fixture.test": ["203.0.113.10"]},
                    answers=answers))
    rep = res["meta"]["reputation"]
    assert rep["listed"] == [], rep
    assert rep["zones_checked"] == 1, rep      # only URIBL really answered
    assert rep["note"] == "not listed in the zones checked", rep
    assert "is listed in the" not in _titles(res)
    # ALL zones erroring -> not evaluated, still no finding
    answers2 = {(f"fixture.test.{z}", "A"): ["127.255.255.254"]
                for z in ("multi.surbl.org", "dbl.spamhaus.org",
                          "multi.uribl.com")}
    res2 = _run("fixture.test", _base_mapping(),
                _DoH(ips={"fixture.test": ["203.0.113.10"]},
                     answers=answers2))
    rep2 = res2["meta"]["reputation"]
    assert rep2["status"] == "not evaluated", rep2
    assert rep2["zones_checked"] == 0, rep2
    assert "is listed in the" not in _titles(res2)


def test_dnsbl_ip_pivot_listing():
    import scanners
    answers = {
        ("9.2.0.192.zen.spamhaus.org", "A"): ["127.0.0.2"],
        ("9.2.0.192.zen.spamhaus.org", "TXT"): ['"SBL reference"'],
    }
    orig = scanners.doh_query
    scanners.doh_query = lambda name, rrtype="TXT", timeout=6.0: []
    try:
        res = _run("192.0.2.9",
                   _base_mapping(**{"rdap.org/ip/": (404, "")}),
                   _DoH(answers=answers),
                   query="192.0.2.9")
    finally:
        scanners.doh_query = orig
    rep = res["meta"]["ip"]["reputation"]
    assert rep["kind"] == "ip", rep
    assert rep["listed"] and rep["listed"][0]["zone"] == \
        "zen.spamhaus.org", rep
    assert res["meta"]["reputation"]["kind"] == "ip"
    hit = [f for f in res["findings"] if "zen.spamhaus.org" in f["title"]]
    assert hit and hit[0]["confidence"] == "probable", _titles(res)


# ------------------------------------------------------------------ P3

def test_email_checks_dead_domain():
    res = _run("someone@deadfixture.test",
               _base_mapping(),
               _DoH(),
               query="someone@deadfixture.test")
    ec = res["meta"]["email_checks"]
    assert ec["format_ok"] is True, ec
    assert ec["domain_resolves"] is False, ec
    assert ec["mx_hosts"] == [], ec
    assert ec["assessment"] == "domain does not resolve", ec
    hit = [f for f in res["findings"] if "does not resolve" in f["title"]]
    assert hit and hit[0]["confidence"] == "candidate", _titles(res)
    assert hit[0]["severity"] == "INFO", hit[0]
    assert "email_checks" in res["meta"]["sections"]


def test_email_checks_disposable():
    res = _run("x@mailinator.com", _base_mapping(),
               _DoH(ips={"mailinator.com": ["203.0.113.10"]},
                    answers={("mailinator.com", "MX"):
                             ["10 mail.mailinator.com."]}),
               query="x@mailinator.com")
    ec = res["meta"]["email_checks"]
    assert ec["disposable"] is True, ec
    assert ec["assessment"] == "disposable provider", ec
    assert ec["mx_hosts"] == ["mail.mailinator.com"], ec
    hit = [f for f in res["findings"]
           if "disposable-mail provider" in f["title"]]
    assert hit and hit[0]["confidence"] == "candidate", _titles(res)


def test_email_checks_plausible_and_no_mx_is_not_invalid():
    res = _run("jane@fixture.test", _base_mapping(),
               _DoH(ips={"fixture.test": ["203.0.113.10"]},
                    answers={("fixture.test", "MX"):
                             ["10 mx1.fixture.test.",
                              "5 mx2.fixture.test."]}),
               query="jane@fixture.test")
    ec = res["meta"]["email_checks"]
    assert ec["assessment"] == "plausible (MX present)", ec
    # preference order respected (5 before 10)
    assert ec["mx_hosts"] == ["mx2.fixture.test", "mx1.fixture.test"], ec
    assert "undeliverable" not in _titles(res)
    # resolves but NO MX at all -> the no-MX tier, NOT a format verdict
    res2 = _run("jane@fixture.test", _base_mapping(),
                _DoH(ips={"fixture.test": ["203.0.113.10"]}),
                query="jane@fixture.test")
    ec2 = res2["meta"]["email_checks"]
    assert ec2["format_ok"] is True, ec2
    assert ec2["assessment"] == "no MX — mail likely undeliverable", ec2
    hit = [f for f in res2["findings"] if "no MX records" in f["title"]]
    assert hit and hit[0]["confidence"] == "candidate", _titles(res2)
    # null MX ("0 .") behaves exactly like no MX
    res3 = _run("jane@fixture.test", _base_mapping(),
                _DoH(ips={"fixture.test": ["203.0.113.10"]},
                     answers={("fixture.test", "MX"): ["0 ."]}),
                query="jane@fixture.test")
    assert res3["meta"]["email_checks"]["mx_hosts"] == []
    assert res3["meta"]["email_checks"]["assessment"] == \
        "no MX — mail likely undeliverable"


def test_email_checks_format_and_mx_outage_units():
    import osint

    class Ctx:
        def __init__(self):
            self.findings, self.warnings = [], []
        def add(self, f):
            self.findings.append(f)
        def warn(self, w):
            self.warnings.append(w)
        def L(self, m):
            pass

    assert osint._email_format_ok("jane.doe+tag@sub.example.co.id")
    assert not osint._email_format_ok("bad..dots@example.com")
    assert not osint._email_format_ok("no-at.example.com")
    assert not osint._email_format_ok("a@-bad.com")
    assert not osint._email_format_ok("a@example.c")
    assert not osint._email_format_ok("a b@example.com")
    # malformed address through the full checker: invalid-format tier,
    # no DNS consulted, no findings
    ctx = Ctx()
    orig_q, orig_i = osint._doh_query, osint._doh_ips
    osint._doh_query = lambda n, t: (_ for _ in ()).throw(
        AssertionError("DoH consulted for a malformed address"))
    osint._doh_ips = lambda n: (_ for _ in ()).throw(
        AssertionError("DoH consulted for a malformed address"))
    try:
        out = osint._email_checks(ctx, "bad..dots@example.com",
                                  "example.com")
    finally:
        osint._doh_query, osint._doh_ips = orig_q, orig_i
    assert out["assessment"] == "invalid format", out
    assert ctx.findings == []
    # MX transport failure -> not evaluated, never a fake 'no MX'
    ctx2 = Ctx()
    osint._doh_query = lambda n, t: None
    osint._doh_ips = lambda n: ["203.0.113.10"]
    try:
        out2 = osint._email_checks(ctx2, "jane@fixture.test",
                                   "fixture.test")
    finally:
        osint._doh_query, osint._doh_ips = orig_q, orig_i
    assert out2["status"] == "not evaluated", out2
    assert out2["assessment"].startswith("not evaluated"), out2
    assert ctx2.findings == []
    # the disposable list is a real curated set, not a stub
    assert len(osint._DISPOSABLE_EMAIL_DOMAINS) >= 200
    assert "gmail.com" not in osint._DISPOSABLE_EMAIL_DOMAINS
    assert "mailinator.com" in osint._DISPOSABLE_EMAIL_DOMAINS
