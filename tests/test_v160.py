"""VANTHEX v1.6.0 — People OSINT Deep (WS-A..F) hermetic tests.

Design traps covered:
  * a web-mention page about the name does NOT raise a name-derived
    identity (mentions are candidates, never signals);
  * an email extracted from an unrelated page stays `candidate`;
  * loosely similar avatars are NOT a same-avatar signal; identical
    avatars are;
  * binary pages are skipped by the WS-B extractor;
  * a failed search engine is reported 'not evaluated' while the
    other modules still run;
  * a platform failing self-check is disabled, an unreachable one
    (UNKNOWN) is not.
"""
import io
import sys

import pytest
from PIL import Image

sys.path.insert(0, __file__.rsplit("/tests/", 1)[0])
import osint  # noqa: E402
import scanners  # noqa: E402


GOODHUB = [("GoodHub", "https://good.test/u/{h}", "profile:{h}")]


class _DohNone:
    def __enter__(self):
        self._orig = scanners.doh_query
        scanners.doh_query = lambda *a, **k: None
        return self

    def __exit__(self, *exc):
        scanners.doh_query = self._orig


class _DohMap:
    def __init__(self, answers):
        self.answers = answers  # {(name, rrtype): [values]}

    def __enter__(self):
        self._orig = scanners.doh_query
        answers = self.answers

        def _fake(name, rrtype="TXT", timeout=6.0):
            return answers.get((name.lower(), rrtype.upper()))
        scanners.doh_query = _fake
        return self

    def __exit__(self, *exc):
        scanners.doh_query = self._orig


def _ddg_html(results):
    """results: [(url, title, snippet)] as a DuckDuckGo html page."""
    parts = []
    for url, title, snip in results:
        parts.append(
            f'<a class="result__a" href="{url}">{title}</a>'
            f'<a class="result__snippet">{snip}</a>')
    return ("<html><body>" + "".join(parts) + "</body></html>").encode()


def _fetch_person(ddg_body=b"", good_bodies=None, extra=None):
    good_bodies = good_bodies or {}

    def fetch(url, timeout=8, verify=False, cap=0, headers=None,
              _hops=0):
        if "good.test/u/" in url:
            h = url.rsplit("/", 1)[-1]
            body = good_bodies.get(h)
            if body:
                return 200, [], body.encode()
            return 404, [], b"no such user"
        if "api.github.com/search/users" in url:
            return 200, [], b'{"items": []}'
        if "crt.sh" in url:
            return 200, [], b"[]"
        if "duckduckgo.com" in url:
            return (200, [], ddg_body) if ddg_body else (0, [], b"")
        if "bing.com" in url:
            return 0, [], b""
        if extra:
            r = extra(url)
            if r is not None:
                return r
        return 0, [], b""
    return fetch


def _graph_node(res, node_id):
    for n in res["meta"]["graph"]["nodes"]:
        if n["id"] == node_id:
            return n
    return None


# ---------------------------------------------------------- WS-A traps

def test_mention_page_does_not_raise_identity():
    """A fetched mention page displaying the full name is NOT an
    identity signal: corroboration comes from platform profiles."""
    ddg = _ddg_html([("https://blog.test/about-fixture",
                      "About Fixture User",
                      "Fixture User is a musician from Oslo")])

    def extra(url):
        if "blog.test/about-fixture" in url:
            return 200, [], (b"<html><body><h1>Fixture User</h1>"
                             b"<p>The other Fixture User.</p>"
                             b"</body></html>")
        return None

    with _DohNone():
        res = osint.run_osint_recon(
            "Fixture User", [], {"query": "Fixture User"},
            _fetch=_fetch_person(ddg, {"fixtureuser": "profile:fixtureuser"},
                                 extra),
            _platforms=GOODHUB)
    ident = res["meta"]["identity"]
    # the GoodHub body carries no full name / context -> 0 signals;
    # the mention page must not have added any
    assert ident["corroborated"] == []
    acct = ident["accounts"][0]
    assert acct["confidence"] == "candidate"
    assert acct["signal_classes"] == []
    men = res["meta"]["mentions"]
    assert men["status"] == "evaluated" and men["total"] == 1


def test_email_from_unrelated_page_stays_candidate():
    ddg = _ddg_html([("https://random.test/page", "Random page",
                      "some page")])

    def extra(url):
        if "random.test/page" in url:
            return 200, [], (b"<html><body>Reach us: "
                             b"fixtureuser@random.test or "
                             b"admin@random.test</body></html>")
        return None

    with _DohNone():
        res = osint.run_osint_recon(
            "fixtureuser", [], {"query": "fixtureuser"},
            _fetch=_fetch_person(ddg, {"fixtureuser": "profile:fixtureuser"},
                                 extra),
            _platforms=GOODHUB)
    node = _graph_node(res, "email:fixtureuser@random.test")
    assert node is not None
    assert node["confidence"] == "candidate"  # never probable
    assert node["module"] == "A6"
    assert not [f for f in res["findings"]
                if f.get("confidence") == "probable"
                and "fixtureuser@random.test" in str(f)]


def test_search_engine_failure_not_evaluated_others_run():
    with _DohNone():
        res = osint.run_osint_recon(
            "Fixture User", [], {"query": "Fixture User"},
            _fetch=_fetch_person(b"", {"fixtureuser":
                                        "profile:fixtureuser — Fixture User"}),
            _platforms=GOODHUB)
    men = res["meta"]["mentions"]
    assert men["status"] == "not evaluated"
    assert men["engines"] == {"duckduckgo": "not evaluated",
                              "bing": "not evaluated"}
    # other modules still ran: identity pivot produced its account
    assert res["meta"]["identity"]["accounts"]
    cov = res["meta"]["coverage"]
    assert cov["search_engines"]["duckduckgo"] == "not evaluated"
    assert any("web mentions" in s
               for s in cov["modules_not_evaluated"])
    assert any("not evaluated" in w for w in res["warnings"])


def test_mentions_dedup_normalized_urls():
    dup = "https://dup.test/page?utm_source=x#frag"
    ddg = _ddg_html([(dup, "Dup", "s1"),
                     ("https://dup.test/page", "Dup again", "s2")])
    with _DohNone():
        res = osint.run_osint_recon(
            "fixtureuser", [], {"query": "fixtureuser"},
            _fetch=_fetch_person(ddg, {"fixtureuser": "profile:fixtureuser"}),
            _platforms=GOODHUB)
    assert res["meta"]["mentions"]["total"] == 1


def test_binary_page_skipped():
    ddg = _ddg_html([("https://files.test/report", "Report", "s")])

    def extra(url):
        if "files.test/report" in url:
            return 200, [], (b"%PDF-1.7 binary \x00\x01 contact "
                             b"admin@files.test")
        return None

    with _DohNone():
        res = osint.run_osint_recon(
            "fixtureuser", [], {"query": "fixtureuser"},
            _fetch=_fetch_person(ddg, {"fixtureuser": "profile:fixtureuser"},
                                 extra),
            _platforms=GOODHUB)
    assert res["meta"]["mentions"]["pages_skipped_binary"] == 1
    assert _graph_node(res, "email:admin@files.test") is None


def test_mention_classification():
    assert osint._classify_mention("https://x.test/a/paper.pdf") \
        == "document"
    assert osint._classify_mention("https://github.com/jdoe") \
        == "profile"
    assert osint._classify_mention("https://blog.test/@jdoe") == "profile"
    assert osint._classify_mention("https://news.test/story") == "mention"


def test_bing_redirector_unwrapped():
    import base64
    real = "https://www.linkedin.com/in/jdoe"
    u = "a1" + base64.urlsafe_b64encode(real.encode()).decode().rstrip("=")
    html = (f'<h2><a href="https://www.bing.com/ck/a?p=x&amp;u={u}">'
            f'J Doe</a></h2><p>snippet</p>')
    parsed = osint._parse_bing(html)
    assert parsed and parsed[0][0] == real
    # the unwrapped URL classifies by its REAL host (a platform
    # profile), not as a bing.com mention; plain non-redirector
    # hrefs pass through untouched
    assert osint._classify_mention(parsed[0][0]) == "profile"
    assert osint._bing_target("https://plain.test/x") \
        == "https://plain.test/x"


# ---------------------------------------------------------- WS-B

def test_entity_extraction_phones_and_emails():
    class _G:
        def __init__(self):
            self.nodes = {}
            self._nodes = self.nodes
            self.edges = []

        def node(self, t, label, conf, mod):
            nid = f"{t}:{label.lower()}"
            self.nodes[nid] = conf
            return nid

        def edge(self, a, b, rel, conf, ev):
            self.edges.append((a, b, rel))

    class _Ctx:
        pass

    ctx = _Ctx()
    ctx.graph = _G()
    ctx.stats = {"entities_extracted": 0}
    ctx.a6_nodes = 0
    ctx.extracted_emails = set()
    ctx.meta = {}
    page = ('<html><body>Contact: Jane.Doe@Example-Corp.com, '
            'call +62 812-3456-7890 or +1 (202) 555-0134. '
            '<a href="https://twitter.com/janedoe">tw</a> '
            '<a href="https://other.test/x">out</a></body></html>')
    found = osint._extract_entities(ctx, page, "https://src.test/p",
                                    "website:src", ())
    assert "jane.doe@example-corp.com" in found["emails"]
    assert len(found["phones"]) == 2
    assert found["handles"].get("X (Twitter)") == "janedoe"
    assert "https://other.test/x" in found["urls"]
    # phone node is a plain candidate labelled with its source page
    assert ctx.graph.nodes.get("phone:+62 812-3456-7890") == "candidate"


# ---------------------------------------------------------- WS-E

def _png(flip=False, jitter=0):
    im = Image.new("L", (32, 32))
    px = im.load()
    for y in range(32):
        for x in range(32):
            dark = x < 16
            if flip:
                dark = not dark
            v = (20 if dark else 230) + (jitter if (x + y) % 7 == 0
                                         else 0)
            px[x, y] = v
    b = io.BytesIO()
    im.save(b, "PNG")
    return b.getvalue()


def _two_hub_platforms():
    return [("HubOne", "https://one.test/u/{h}", "profile:{h}"),
            ("HubTwo", "https://two.test/u/{h}", "profile:{h}")]


def _fetch_avatar(avatar_bytes):
    def fetch(url, timeout=8, verify=False, cap=0, headers=None,
              _hops=0):
        for host in ("one.test/u/", "two.test/u/"):
            if host in url:
                h = url.rsplit("/", 1)[-1]
                if h == "fixtureuser":
                    hostkey = "a" if "one" in host else "b"
                    return 200, [], (
                        f'<html><head>'
                        f'<meta property="og:title" content="Fixture User">'
                        f'<meta property="og:image" content="https://img.test/{hostkey}.png">'
                        f'</head><body>profile:fixtureuser</body></html>'
                    ).encode()
                return 404, [], b"nope"
        if "img.test/" in url:
            return 200, [], avatar_bytes[url.rsplit("/", 1)[-1]]
        if "api.github.com/search/users" in url:
            return 200, [], b'{"items": []}'
        if "duckduckgo" in url or "bing.com" in url:
            return 0, [], b""
        return 0, [], b""
    return fetch


def test_avatar_identical_is_signal_and_corroborates():
    png = _png()
    fetch = _fetch_avatar({"a.png": png, "b.png": png})
    with _DohNone():
        res = osint.run_osint_recon(
            "Fixture User", [], {"query": "Fixture User"},
            _fetch=fetch, _platforms=_two_hub_platforms())
    ident = res["meta"]["identity"]
    assert res["meta"]["avatar_match"]["matched"] == 1
    assert "fixtureuser" in ident["corroborated"]
    acct = ident["accounts"][0]
    # profile-name-match (full name in bodies) + same-avatar = 2 classes
    assert "same-avatar" in acct["signal_classes"]
    assert "profile-name-match" in acct["signal_classes"]
    node = _graph_node(res, "username:fixtureuser")
    assert "same-avatar" in (node.get("signals") or [])


def test_avatar_loose_similarity_not_a_signal():
    fetch = _fetch_avatar({"a.png": _png(), "b.png": _png(flip=True)})
    with _DohNone():
        res = osint.run_osint_recon(
            "Fixture User", [], {"query": "Fixture User"},
            _fetch=fetch, _platforms=_two_hub_platforms())
    assert res["meta"]["avatar_match"]["matched"] == 0
    acct = res["meta"]["identity"]["accounts"][0]
    assert "same-avatar" not in acct["signal_classes"]


def test_ahash_threshold_strict():
    a = osint._ahash16(_png())
    b = osint._ahash16(_png(jitter=1))
    assert bin(a ^ b).count("1") <= osint._AHASH_MAX_DIST
    c = osint._ahash16(_png(flip=True))
    assert bin(a ^ c).count("1") > 10 * osint._AHASH_MAX_DIST
    assert osint._ahash16(b"definitely not an image") is None


# ---------------------------------------------------------- WS-F

def test_jsonld_sameas_crosslink_class():
    body = ('profile:fixtureuser '
            '<script type="application/ld+json">'
            '{"@type":"Person","sameAs":'
            '["https://twitter.com/fixtureuser"]}</script>')
    with _DohNone():
        res = osint.run_osint_recon(
            "Fixture User", [], {"query": "Fixture User"},
            _fetch=_fetch_person(b"", {"fixtureuser": body}),
            _platforms=GOODHUB)
    acct = res["meta"]["identity"]["accounts"][0]
    assert acct["signal_classes"] == ["cross-link"]
    assert res["meta"]["identity"]["corroborated"] == []


def test_dedicated_extractors_registered():
    for kind in ("keybase", "youtube", "tiktok", "twitter", "medium",
                 "substack", "instagram", "linktree", "aboutme"):
        assert kind in osint._EXTRACTORS
    prof = osint.extract_profile(
        "Keybase",
        '<meta property="og:title" content="jdoe (Jane Doe) | Keybase">'
        '<a href="https://github.com/jdoe">gh</a>', "jdoe")
    assert prof.get("fullname") == "Jane Doe"
    assert any(i["platform"] == "GitHub"
               for i in prof.get("identifiers") or [])


# ---------------------------------------------------------- WS-D

def test_email_permutator_candidates_stay_candidate():
    answers = {("fixtureuser.com", "A"): ["203.0.113.9"],
               ("fixtureuser.com", "MX"): ["10 mail.fixtureuser.com."]}
    with _DohMap(answers):
        res = osint.run_osint_recon(
            "Fixture User", [], {"query": "Fixture User"},
            _fetch=_fetch_person(b"", {}), _platforms=GOODHUB)
    ec = res["meta"]["email_candidates"]
    assert ec["status"] == "evaluated"
    assert ec["domains"] == ["fixtureuser.com"]
    assert ec["candidates"], "patterns must be generated"
    assert all(c["confidence"] == "candidate"
               for c in ec["candidates"])
    assert ec["probable"] == []
    assert "fixture.user@fixtureuser.com" in {
        c["email"] for c in ec["candidates"]}


def test_email_permutator_probable_only_via_extraction():
    ddg = _ddg_html([("https://blog.test/fixture", "Fixture",
                      "about fixture")])

    def extra(url):
        if "blog.test/fixture" in url:
            return 200, [], (b"<html><body>Contact the author: "
                             b"fixture@fixtureuser.com</body></html>")
        return None

    answers = {("fixtureuser.com", "A"): ["203.0.113.9"],
               ("fixtureuser.com", "MX"): ["10 mail.fixtureuser.com."]}
    with _DohMap(answers):
        res = osint.run_osint_recon(
            "Fixture User", [], {"query": "Fixture User"},
            _fetch=_fetch_person(ddg, {}, extra), _platforms=GOODHUB)
    ec = res["meta"]["email_candidates"]
    assert ec["probable"] == ["fixture@fixtureuser.com"]


# ---------------------------------------------------------- WS-C

def test_selfcheck_fail_disables_unknown_never(tmp_path):
    by_name = {p[0]: p for p in osint.PLATFORMS}
    claimed = {n: osint._PLATFORM_BY_NAME[n]["claimed_handle"]
               for n in ("GitHub", "Reddit", "GitLab")}
    unclaimed = {n: osint._PLATFORM_BY_NAME[n]["unclaimed_handle"]
                 for n in ("GitHub", "Reddit", "GitLab")}

    def fetch(url, timeout=7, cap=0, **kw):
        handle = url.rstrip("/").rsplit("/", 1)[-1]
        body = ('{"login": "%s", "username": "%s", "profile %s"}'
                % (handle, handle, handle)).encode()
        if "github.com" in url:
            if url.rstrip("/").endswith("/" + claimed["GitHub"]):
                return 200, [], body
            return 404, [], b"no"          # unclaimed + junk: absent
        if "reddit.com" in url:
            return 200, [], body           # catch-all: unclaimed claimed
        if "gitlab.com" in url:
            return 0, [], b""              # unreachable -> UNKNOWN
        return 0, [], b""

    plats = [by_name[n] for n in ("GitHub", "Reddit", "GitLab")]
    state = str(tmp_path / "state.json")
    report = osint.self_check_platforms(fetch, platforms=plats,
                                        apply_disable=True,
                                        state_path=state)
    by = {e["platform"]: e for e in report}
    assert by["GitHub"]["status"] == "pass"
    assert by["Reddit"]["status"] == "fail"
    assert by["GitLab"]["status"] == "unknown"
    disabled = osint._load_platform_state(state)["disabled"]
    assert "Reddit" in disabled
    assert "GitLab" not in disabled and "GitHub" not in disabled


def test_dataset_expanded_with_fixtures():
    assert len(osint.PLATFORMS) >= 170
    for d in osint.PLATFORM_SCHEMA:
        assert d["claimed_handle"], d["name"]
        assert d["unclaimed_handle"], d["name"]


# ---------------------------------------------------------- coverage

def test_coverage_meta_shape():
    with _DohNone():
        res = osint.run_osint_recon(
            "fixtureuser", [], {"query": "fixtureuser"},
            _fetch=_fetch_person(b"", {"fixtureuser": "profile:fixtureuser"}),
            _platforms=GOODHUB)
    cov = res["meta"]["coverage"]
    for key in ("platforms_checked", "platforms_active",
                "search_engines", "pages_fetched",
                "entities_extracted", "modules_not_evaluated"):
        assert key in cov
    assert cov["platforms_checked"] >= 1
    assert cov["platforms_active"] == 1
    assert "coverage" in res["meta"]["sections"]
    assert "mentions" in res["meta"]["sections"]
