"""Tes graphqlsuite — GraphQL attack pack (mixed gating: passive always,
offensive behind PTK_GRAPHQL=1). Fixture port unik (18960). Hermetic."""
import os
import sys
import subprocess
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

PORT = 18960
os.environ.pop("PTK_GRAPHQL", None)  # gate default OFF utk seluruh modul tes


import pytest


def _boot(port):
    p = subprocess.Popen(
        [sys.executable, "tests/fixture_vuln_server.py", str(port)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)
            return p
        except Exception:
            time.sleep(0.25)
    p.terminate()
    raise AssertionError("fixture tidak start")


_PROC = {"p": None}


@pytest.fixture(scope="function")
def server():
    _PROC["p"] = _boot(PORT)
    yield
    _PROC["p"].terminate()


def _run(opts=None, gate=False):
    import vulnscan2
    if gate:
        os.environ["PTK_GRAPHQL"] = "1"
    else:
        os.environ.pop("PTK_GRAPHQL", None)
    ctx = vulnscan2.Ctx(f"http://127.0.0.1:{PORT}/", opts or {"timeout": 8}, [])
    found = []

    def add(f):
        found.append(f)

    vulnscan2.c_graphql_suite(ctx, add)
    os.environ.pop("PTK_GRAPHQL", None)
    return found


def _titles(fs):
    return [f["title"] for f in fs]


def _one(fs, frag):
    for f in fs:
        if frag in f["title"]:
            return f
    return None


# ---------------- passive (always-on) ----------------

def test_passive_findings_without_gate(server):
    fs = _run()
    ts = _titles(fs)
    assert _one(fs, "field suggestion leakage") is not None, ts
    sug = _one(fs, "field suggestion leakage")
    assert sug["confidence"] == "probable"
    assert "Did you mean" in sug["evidence"].lower() or \
        "did you mean" in sug["evidence"].lower()
    assert _one(fs, "introspection enabled") is not None, ts
    intro = _one(fs, "introspection enabled")
    assert intro["confidence"] == "probable"  # content-only, no differential
    assert _one(fs, "query-in-URL") is not None, ts
    # gated probes must NOT run
    assert not _one(fs, "alias batching"), ts
    assert not _one(fs, "depth"), ts
    assert not _one(fs, "without authentication"), ts
    # fp-guard: nothing confirmed without differential evidence
    assert not [f for f in fs if f.get("confidence") == "confirmed"], ts


def test_protected_endpoint_negative(server):
    """Mutations on /gql require auth — the protected endpoint must NOT
    yield an unauthenticated-mutation finding."""
    import vulnscan2
    os.environ["PTK_GRAPHQL"] = "1"
    ctx = vulnscan2.Ctx(f"http://127.0.0.1:{PORT}/", {"timeout": 8}, [])
    found = []

    def add(f):
        found.append(f)

    vulnscan2.c_graphql_suite(ctx, add)
    os.environ.pop("PTK_GRAPHQL", None)
    for f in found:
        if "without authentication" in f["title"]:
            assert f["location"] != "/gql", f["title"]
    # auth header works on the protected endpoint
    r = ctx.client.post("/gql", data='{"query": "mutation { createUser(id: \\"1\\") { __typename } }"}',
                        headers={"Content-Type": "application/json",
                                 "Authorization": "Bearer admin-token"})
    assert "createUser" in (r.body or ""), r.body


# ---------------- gated offensive probes ----------------

def test_gated_alias_and_mutation(server):
    fs = _run(gate=True)
    ts = _titles(fs)
    alias = _one(fs, "alias batching amplification")
    assert alias is not None, ts
    assert alias["confidence"] == "confirmed"
    assert alias.get("verification") == "differential"
    assert "/gql/open" in alias["location"] or "/gql" in alias["location"]
    assert "50 aliases" in alias["evidence"] or "aliases resolved" in alias["evidence"]


def test_gated_depth_probe(server):
    fs = _run(gate=True)
    depth = _one(fs, "depth")
    assert depth is not None, _titles(fs)
    assert depth["confidence"] == "confirmed"
    assert depth.get("verification") == "differential"


def test_gated_get_mutation_and_unauth_mutation(server):
    fs = _run(gate=True)
    ts = _titles(fs)
    gm = _one(fs, "mutations accepted over GET")
    assert gm is not None, ts
    assert gm["confidence"] == "confirmed"
    um = _one(fs, "executes without authentication")
    assert um is not None, ts
    assert um["confidence"] == "confirmed"
    assert um["location"].endswith("/gql/open"), um["location"]


def test_introspection_bypass_silent_when_open(server):
    """Bypass variants must not fire when plain introspection is open."""
    fs = _run(gate=True)
    assert _one(fs, "introspection bypass works") is None, _titles(fs)


# ---------------- registration / profiles ----------------

def test_registered_and_profile_counts():
    import vulnscan2 as V
    assert callable(V.c_graphql_suite)
    assert "c_graphql_suite" in V.PROFILES["enterprise-full"]
    assert "c_graphql_suite" in V.PROFILES["active-deep"]
    assert len(V.PROFILES["enterprise-full"]) == 141
    assert callable(getattr(V, "c_graphql_suite", None))


def test_gate_off_is_stub_only_for_offensive_parts(server):
    """opts gate: graphql_suite=1 in opts also enables offensive probes."""
    fs = _run(opts={"timeout": 8, "graphql_suite": "1"})
    assert _one(fs, "alias batching amplification") is not None, _titles(fs)
