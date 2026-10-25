"""v1.3.0: Secrets Engine v2 detector battery + .git history walker +
source maps + decoder layers + OSINT module (A1-A5).

Per-detector battery rule (design Bagian C): every detector ships a
positive case and near-miss traps; the trap corpus must produce ZERO
findings (FP gate). Structural validators are local only — no provider
is ever contacted by these tests either.
"""
import base64
import json
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

PORT = 18098


def _scan(text, config_style=False):
    import vulnscan2
    finds = []
    state = {"seen": set(), "count": 0, "cap": 50}
    vulnscan2._scan_secrets_in(finds.append, text, "/battery", state,
                               config_style=config_style)
    return finds


def _kinds(finds):
    return {f["title"] for f in finds}


def _b64u(obj):
    return base64.urlsafe_b64encode(
        json.dumps(obj).encode()).decode().rstrip("=")


def _jwt(claims, alg="HS256", sig="SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"):
    return (_b64u({"alg": alg, "typ": "JWT"}) + "."
            + _b64u(claims) + "." + sig)


# ------------------------------------------------------- detector battery
# kind -> (positive text, expected title fragment, min confidence rank)
_RANK = {"candidate": 1, "probable": 2, "confirmed": 3}
SAMPLES = {
    "gitlab_runner": ("glrt-Ab3dF6hJ9kL2mN5pQ8rS", "GitLab runner token", "probable"),
    "slack_app": ("xapp-1-A09B8C7D6E-1234567890ab", "Slack app token", "probable"),
    "stripe_webhook": ("whsec_" + "a1" * 16, "Stripe webhook secret", "probable"),
    "twilio": ("SK" + "0123456789abcdef" * 2, "Twilio API key", "probable"),
    "mailchimp": ("0123456789abcdef" * 2 + "-us7", "Mailchimp API key", "probable"),
    "brevo": ("xkeysib-" + "Ab1-" * 21, "Brevo API key", "probable"),
    "postman": ("PMAK-" + "a" * 24 + "-" + "b" * 34, "Postman API key", "probable"),
    "grafana_sa": ("glsa_" + "A" * 32 + "_0123abcd", "Grafana service account", "probable"),
    "grafana_cloud": ("glc_" + "B" * 44, "Grafana Cloud API key", "probable"),
    "linear": ("lin_api_" + "C" * 40, "Linear API key", "probable"),
    "openai": ("sk-proj-" + "D" * 48, "OpenAI API key", "probable"),
    "anthropic": ("sk-ant-api03-" + "E" * 85, "Anthropic API key", "probable"),
    "huggingface": ("hf_" + "F" * 35, "Hugging Face token", "probable"),
    "replicate": ("r8_" + "G" * 37, "Replicate API token", "probable"),
    "groq": ("gsk_" + "H" * 52, "Groq API key", "probable"),
    "db_uri": ("mongodb://dbuser:Sup3rSecretPass@db.internal:27017/app",
               "URI with embedded credentials", "probable"),
    "uri_creds": ("https://deploy:Tr0ub4dorSecret@ci.internal/job",
                  "URL with embedded credentials", "candidate"),
    "docker_hub": ("dckr_pat_" + "I" * 27, "Docker Hub access token", "probable"),
    "vault": ("hvs." + "J" * 25, "Vault token", "probable"),
    "newrelic": ("NRAK-" + "K" * 27, "New Relic API key", "probable"),
    "digitalocean": ("dop_v1_" + "0123456789abcdef" * 4, "DigitalOcean token", "probable"),
    "shopify": ("shpat_" + "0123456789abcdef" * 2, "Shopify access token", "probable"),
    "square": ("sq0atp-" + "L" * 22, "Square access token", "probable"),
    "discord_bot": ("M" + "N" * 23 + "." + "O" * 6 + "." + "P" * 28,
                    "Discord bot token", "probable"),
    "facebook": ("EAACEdEose0cBA" + "Q" * 30, "Facebook access token", "probable"),
    "dropbox": ("sl." + "R" * 135, "Dropbox access token", "probable"),
    "google_oauth_secret": ("GOCSPX-" + "S" * 28, "OAuth client secret", "probable"),
    "google_oauth_token": ("ya29." + "T" * 40, "OAuth access token", "probable"),
    "age_key": ("AGE-SECRET-KEY-1" + "q" * 58, "age encryption secret key", "probable"),
    "mapbox_secret": ("sk.eyJ" + "U" * 12 + "." + "V" * 12, "Mapbox secret token", "probable"),
    "airtable": ("pat" + "W" * 14 + "." + "0123456789abcdef" * 4, "Airtable", "probable"),
    "notion": ("ntn_" + "X9kL2mN5pQ8rS4tU6vW1yZ3aB5cD7eF9gH2jK4mN6pQ", "Notion integration token", "probable"),
    "figma": ("figd_" + "Y" * 42, "Figma access token", "probable"),
    "planetscale": ("pscale_tkn_" + "Z" * 42, "PlanetScale token", "probable"),
    "supabase": ("sbp_" + "0123456789abcdef" * 2 + "01234567", "Supabase access token", "probable"),
    "cloudinary": ("cloudinary://123456789012345:AbC_dEf-12345678901234@mycloud",
                   "Cloudinary URI", "probable"),
    "fcm": ("AAAA" + "a" * 8 + ":" + "b" * 120, "Firebase Cloud Messaging", "probable"),
    "buildkite": ("bkua_" + "0123456789abcdef" * 2, "Buildkite API token", "probable"),
    "doppler": ("dp.st." + "c" * 42, "Doppler token", "probable"),
    "pulumi": ("pul-" + "0123456789abcdef" * 2 + "01234567", "Pulumi access token", "probable"),
    "pypi": ("pypi-" + "d" * 60, "PyPI API token", "probable"),
    "nuget": ("oy2" + "e" * 44, "NuGet API key", "probable"),
    "rubygems": ("rubygems" + "0123456789abcdef" * 3, "RubyGems API key", "probable"),
    "pinecone": ("pcsk_" + "f" * 36, "Pinecone API key", "probable"),
    "langsmith": ("lsv2_pt_" + "g" * 36, "LangSmith API key", "probable"),
    "basic_auth_literal": ("Authorization: Basic dXNlcjpwYXNzd29yZA==",
                           "Basic authorization credential", "candidate"),
    "azure_secret": ('azure client_secret = "' + "Ab3~" * 10 + '"',
                     "Azure client secret", "candidate"),
    "cloudflare_token": ("cloudflare api token: " + "h" * 40,
                         "Cloudflare API token", "candidate"),
    "sentry_token": ("sentry auth token: " + "0123456789abcdef" * 4,
                     "Sentry auth token", "candidate"),
    "eth_privkey": ("wallet private key: 0x" + "0123456789abcdef" * 4,
                    "Ethereum private key", "candidate"),
    "heroku": ("heroku api key: 01234567-89ab-cdef-0123-456789abcdef",
               "Heroku API key", "candidate"),
    "postmark": ("postmark server token: 01234567-89ab-cdef-0123-456789abcdef",
                 "Postmark server token", "candidate"),
    "datadog": ("datadog api key: " + "0123456789abcdef" * 2,
                "Datadog API key", "candidate"),
    "twilio_auth": ("twilio auth token: " + "fedcba9876543210" * 2,
                    "Twilio auth token", "candidate"),
    "slack_signing": ("slack signing secret: " + "a1b2c3d4" * 4,
                      "Slack signing secret", "candidate"),
    "resend": ("resend api key: re_" + "i" * 34, "Resend API key", "candidate"),
}

# Trap lines are separated by long filler: context-window detectors
# (+/-160 chars) must not be cross-contaminated by neighbouring lines.
_FILLER = "\n" + ("lorem ipsum dolor sit amet " * 12) + "\n"
TRAP_CORPUS = _FILLER.join([
    "sha256 = \"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"",
    "md5 = \"098f6bcd4621d373cade4e832627b4f6\"",
    "uuid = \"01234567-89ab-cdef-0123-456789abcdef\"",
    "git sha = da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "wallet address = 0x0123456789abcdef0123456789abcdef01234567",
    "eth hash = 0x" + "ab" * 32,
    "color: #a1b2c3; border: #012345",
    "mongodb://db.internal:27017/app",
    "https://user@ci.internal/job",
    "ftp://files.internal/pub/readme.txt",
    "pk_live_4eC39HqLyjWDarjtT1zdp7dc",
    "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
    "ghp_tooshort123",
    "var token = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln\"",
    "random blob = \"aGVsbG8gd29ybGQgdGhpcyBpcyBqdXN0IHRleHQ\"",
    "hex text = \"" + "hello world this is plain text".encode().hex() + "\"",
    'api_key = "your-api-key-here"',
    'client_secret = "changeme"',
    "azure tenant id = 01234567-89ab-cdef-0123-456789abcdef",
    "sentry dsn = https://abc123@o0.ingest.sentry.io/123456",
    "datadog site = datadoghq.com",
    "the slack channel is #general",
    "sendgrid template id = d-0123456789abcdef0123456789abcdef",
    "-----BEGIN CERTIFICATE-----",
    "ssh public key = ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyMaterialHere user@host",
    "AGE-SECRET-KEY-1TOOSHORT",
    "dckr_pat_short",
    "hvs.short",
])


def test_detector_battery_positives():
    import secretpatterns as sp
    assert len(sp.DETECTORS_V2) >= 70, len(sp.DETECTORS_V2)
    for kind, (text, frag, min_conf) in SAMPLES.items():
        finds = _scan("prefix " + text + " suffix")
        hit = [f for f in finds if frag in f["title"]]
        assert hit, f"{kind}: positive sample produced no finding ({finds})"
        assert _RANK[hit[0]["confidence"]] >= _RANK[min_conf], \
            (kind, hit[0]["confidence"])
        assert text not in repr(finds), f"{kind}: full secret leaked"


def test_detector_battery_traps_zero_fp():
    finds = _scan(TRAP_CORPUS)
    assert finds == [], finds


def test_github_checksum_tiers():
    import secretpatterns as sp
    good = sp.make_github_token("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234")
    finds = _scan(good)
    gh = [f for f in finds if "GitHub token" in f["title"]]
    assert gh and gh[0]["confidence"] == "probable", finds
    assert "checksum" in gh[0]["evidence"]
    bad = good[:-1] + ("A" if good[-1] != "A" else "B")
    finds = _scan(bad)
    gh = [f for f in finds if "GitHub token" in f["title"]]
    assert gh and gh[0]["confidence"] == "candidate", finds
    assert "does NOT verify" in gh[0]["evidence"]


def test_pem_parse_tiers():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    finds = _scan(pem)
    pk = [f for f in finds if "Private key exposed" in f["title"]]
    assert pk and pk[0]["confidence"] == "confirmed", finds
    assert "parses as a valid" in pk[0]["evidence"]
    truncated = pem[:120]
    finds = _scan(truncated)
    pk = [f for f in finds if "Private key exposed" in f["title"]]
    assert pk and pk[0]["confidence"] == "candidate", finds


def test_jwt_structure_and_none_alg():
    tok = _jwt({"sub": "42", "iss": "fixture-issuer", "exp": 1893456000})
    finds = _scan(tok)
    jw = [f for f in finds if "JWT token exposed" in f["title"]]
    assert jw and jw[0]["confidence"] == "probable", finds
    assert "fixture-issuer" in jw[0]["evidence"]
    none_tok = _jwt({"sub": "42", "role": "user-with-a-long-enough-claim"},
                    alg="none", sig="")
    finds = _scan(none_tok)
    jw = [f for f in finds if "JWT token exposed" in f["title"]]
    assert jw and "alg=none" in jw[0]["evidence"], finds
    garbage = "eyJ" + "a" * 30 + ".eyJ" + "b" * 30 + "." + "c" * 40
    assert _scan(garbage) == []


def test_aws_pairing_tier():
    key_id = "AKIA" + "Z9Y8X7W6V5U4T3S2"
    text = (f'aws_key = "{key_id}"\n'
            'aws_secret_access_key = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"')
    finds = _scan(text)
    aw = [f for f in finds if "AWS Access Key ID" in f["title"]]
    assert aw and aw[0]["confidence"] == "confirmed", finds
    assert "complete credential pair" in aw[0]["evidence"]
    solo = _scan(f'aws_key = "{key_id}"')
    aw = [f for f in solo if "AWS Access Key ID" in f["title"]]
    assert aw and aw[0]["confidence"] == "probable", solo


def test_gcp_service_account_structure():
    text = ('{"type": "service_account", "project_id": "demo", '
            '"private_key": "<redacted>"}')
    finds = _scan(text)
    assert any("service account key" in f["title"] for f in finds), finds
    assert _scan('{"type": "service_account"}') == []


def test_profiles_counts_v13():
    import vulnscan2 as v
    assert len(v.PROFILES["passive-quick"]) == 3
    assert len(v.PROFILES["passive-full"]) == 7
    assert len(v.PROFILES["active-standard"]) == 25
    assert len(v.PROFILES["active-deep"]) == 56
    assert len(v.PROFILES["enterprise-full"]) == 59
    assert "c_git_secrets" in v.PROFILES["enterprise-full"]


# ------------------------------------------------------------ integration

class _Fixture:
    def __enter__(self):
        self.p = subprocess.Popen(
            [sys.executable, "tests/fixture_vuln_server.py", str(PORT)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(40):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=2)
                return self
            except Exception:
                time.sleep(0.25)
        raise RuntimeError("fixture tidak start")

    def __exit__(self, *a):
        self.p.terminate()


class _Surf:
    def __init__(self, js_urls):
        self.homepage = None
        self.js_urls = js_urls
        self.param_urls = []
        self.forms = []
        self.pages = []


class _Ctx:
    def __init__(self, js_urls):
        from netclient import Client
        self.target = f"http://127.0.0.1:{PORT}"
        self.client = Client(self.target, timeout=5)
        self._js = js_urls
        self.log = []
        self._secret_feed = []

    def L(self, m):
        self.log.append(m)

    def cancelled(self):
        return False

    def surface(self, full=True):
        return _Surf(self._js)

    def is_missing(self, resp):
        return resp.status == 404


def test_git_secrets_fixture_integration():
    import vulnscan2
    with _Fixture():
        ctx = _Ctx([])
        finds = []
        vulnscan2.c_git_secrets(ctx, finds.append)
        git = [f for f in finds
               if str(f.get("location", "")).startswith("/.git@")]
        assert git, finds
        assert any(f["confidence"] == "confirmed"
                   and "complete credential pair" in f["evidence"]
                   for f in git), git
        assert "config.py" in git[0]["location"]
        import re as _re
        assert not _re.search(r"AKIA[0-9A-Z]{16}", repr(finds)), \
            "full AWS key id leaked into findings"


def test_source_map_and_decoder_layers():
    import vulnscan2
    with _Fixture():
        ctx = _Ctx(["/static/app.js"])
        finds = []
        vulnscan2.c_exposed_secrets(ctx, finds.append)
        sm = [f for f in finds if "app.js.map#" in str(f.get("location", ""))]
        assert sm and any("SendGrid" in f["title"] for f in sm), finds
        ctx2 = _Ctx(["/static/secrets.js"])
        finds2 = []
        vulnscan2.c_exposed_secrets(ctx2, finds2.append)
        dec = [f for f in finds2 if "base64-decoded" in f.get("evidence", "")]
        assert dec and any("Stripe" in f["title"] for f in dec), finds2


# ---------------------------------------------------------------- OSINT

def _stub_fetch(mapping):
    """fetch(url, **kw) -> (status, headers, bytes) from a URL->spec map.
    spec: (status, text) or callable(url)->(status, text)."""
    def fetch(url, timeout=8, verify=False, cap=0, headers=None, _hops=0):
        for pat, spec in mapping:
            if pat in url:
                st, text = spec(url) if callable(spec) else spec
                return st, [], text.encode()
        return 0, [], b""
    return fetch


def test_username_control_gate():
    import osint
    platforms = [
        ("GoodHub", "https://good.test/u/{h}", "profile:{h}"),
        ("CatchAll", "https://catch.test/u/{h}", "profile:{h}"),
        ("DownSite", "https://down.test/u/{h}", "profile:{h}"),
    ]

    def fetch(url, timeout=8, verify=False, cap=0, headers=None, _hops=0):
        if "good.test" in url:
            if url.endswith("/fixtureuser"):
                return 200, [], b"profile:fixtureuser member page"
            return 404, [], b"no such user"
        if "catch.test" in url:
            handle = url.rsplit("/", 1)[-1]
            return 200, [], f"profile:{handle} join us".encode()
        return 0, [], b""

    finds, meta = osint._username_osint(fetch, "fixtureuser", lambda m: None,
                                        [], platforms=platforms)
    assert meta["probable"] == ["GoodHub"], meta
    assert meta["candidate"] == ["CatchAll"], meta
    assert meta["unevaluated"] == ["DownSite"], meta
    assert any(f["confidence"] == "probable" for f in finds)
    assert any(f["confidence"] == "candidate"
               and "UNVERIFIED" in f["description"] for f in finds)


def test_osint_full_hermetic():
    import osint
    crt_rows = [{"name_value": "old.fixture.test",
                 "issuer_name": "Fixture CA",
                 "not_after": "2020-01-01T00:00:00"}]
    gh_items = {"items": [{"full_name": "fixturemart/web",
                           "html_url": "https://github.com/fixturemart/web",
                           "default_branch": "main"}]}
    rdap = {"name": "FIXTURE-NET", "country": "ID",
            "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}],
            "entities": [{"roles": ["registrant"],
                          "vcardArray": ["vcard", [["fn", {}, "text",
                                                    "Fixture Hosting PT"]]]}]}
    cdx = [["timestamp", "original", "statuscode"],
           ["20210101000000", "http://fixture.test/static/old.js", "200"]]
    mapping = [
        ("crt.sh", (200, json.dumps(crt_rows))),
        ("cdx/search", (200, json.dumps(cdx))),
        ("web.archive.org/web/", (200, 'var k = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";')),
        ("api.github.com/search/code", (401, "{}")),
        ("api.github.com/search/repositories", (200, json.dumps(gh_items))),
        ("raw.githubusercontent.com", (200, "# FixtureMart web\n")),
        ("gitlab.com/api", (200, "[]")),
        ("rdap.org/ip/", (200, json.dumps(rdap))),
    ]
    fetch = _stub_fetch(mapping)
    orig_doh = osint._doh_ips
    orig_doh_q = osint._doh_query
    osint._doh_ips = lambda name: ["203.0.113.10"] if name == "fixture.test" else []
    # v1.5.0 hygiene modules: keep their DoH channel hermetic (no records)
    osint._doh_query = lambda name, rrtype: []
    try:
        log = []
        res = osint.run_osint_recon(
            "https://fixture.test", log, {"handle": "fixtureuser"},
            _fetch=fetch,
            _platforms=[("GoodHub", "https://good.test/u/{h}", "profile:{h}")])
    finally:
        osint._doh_ips = orig_doh
        osint._doh_query = orig_doh_q
    # stub for the sim platform must live in the same fetch map:
    assert res["type"] == "osint"
    titles = " | ".join(f["title"] for f in res["findings"])
    assert "hosting network identified" in titles, titles
    assert "shadow subdomains" in titles, titles
    assert "Historical attack surface" in titles, titles
    assert "GitHub repositories referencing" in titles, titles
    assert any("Stripe" in f["title"] for f in res["findings"]), titles
    assert res["meta"]["code_exposure"]["github_code_search"].startswith(
        "not evaluated"), res["meta"]["code_exposure"]
    assert res["meta"]["breach"]["enabled"] is False
    assert any("breach exposure: disabled" in line for line in log), log


def test_osint_sim_platforms_over_http():
    """A3 gate against the fixture's simulated platforms (real HTTP)."""
    import osint
    import passive as passive_mod
    with _Fixture():
        base = f"http://127.0.0.1:{PORT}"
        platforms = [
            ("SimHub", base + "/sim/users/{h}", "profile:{h}"),
            ("SimCatch", base + "/sim/catchall/{h}", "profile:{h}"),
        ]
        finds, meta = osint._username_osint(
            passive_mod._fetch_bytes, "fixtureuser", lambda m: None, [],
            platforms=platforms)
        assert meta["probable"] == ["SimHub"], meta
        assert meta["candidate"] == ["SimCatch"], meta
