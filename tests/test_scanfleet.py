#!/usr/bin/env python3
"""Integration tests for the distributed scan fleet coordinator.

Self-contained: boots a FleetCoordinator on a tmpdir state file and two
NodeServer instances on loopback ports with a stub job runner returning
canned findings, then exercises join -> dispatch -> job -> result ->
dedupe/risk aggregation end to end. Requires PTK_FLEET=1 (set via
monkeypatch fixture).
"""

import json
import os
import sys
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offensive import scanfleet  # noqa: E402


def _post(url, path, token, payload):
    req = urllib.request.Request(
        url.rstrip("/") + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"},
        method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _canned_results(target, profile):
    """Two nodes report the same finding at different confidences plus
    one node-unique finding each."""
    shared_dup = [
        {"title": "Reflected XSS", "severity": "HIGH", "cvss": 7.5,
         "confidence": "candidate", "location": "/search",
         "param": "q", "origin": "scanfleet-test"},
    ]
    return {
        "findings": shared_dup,
        "target": target,
        "profile": profile,
    }


@pytest.fixture()
def gate(monkeypatch, tmp_path):
    monkeypatch.setenv("PTK_FLEET", "1")
    state = tmp_path / "fleet.json"
    coord = scanfleet.FleetCoordinator(str(state))
    return coord, state


def test_refuses_without_gate(monkeypatch, tmp_path):
    monkeypatch.delenv("PTK_FLEET", raising=False)
    coord = scanfleet.FleetCoordinator(str(tmp_path / "fleet.json"))
    with pytest.raises(PermissionError):
        scanfleet.register_node(coord, "http://127.0.0.1:1", "tok")
    with pytest.raises(PermissionError):
        coord.dispatch({"target": "http://example.com"})
    with pytest.raises(PermissionError):
        scanfleet.NodeServer(coord)


def test_register_hashes_token(gate):
    coord, _ = gate
    nid = scanfleet.register_node(coord, "http://127.0.0.1:9001", "secret-tok")
    node = [n for n in coord._state["nodes"] if n["id"] == nid][0]
    assert node["token_hash"] == scanfleet.hash_token("secret-tok")
    assert "secret-tok" not in json.dumps(coord._state)


def test_dispatch_picks_distinct_idle_nodes(gate):
    coord, _ = gate
    scanfleet.register_node(coord, "http://127.0.0.1:9001", "t1")
    scanfleet.register_node(coord, "http://127.0.0.1:9002", "t2")
    p1 = scanfleet.dispatch(coord, {"target": "http://a.example", "profile": "active-deep"})
    p2 = scanfleet.dispatch(coord, {"target": "http://b.example", "profile": "active-deep"})
    assert p1 and p2
    assert p1["node_url"] != p2["node_url"]
    # fleet full: no third dispatch while both jobs are running
    assert scanfleet.dispatch(coord, {"target": "http://c.example"}) is None


def test_end_to_end_nodeserver_dedupe_and_risk(gate, monkeypatch):
    coord, state_path = gate
    nodes = []
    tokens = {}
    try:
        for _ in range(2):
            # Stub job runner: canned findings instead of a real scan.
            ns = scanfleet.NodeServer(coord, port=0,
                                      job_runner=lambda job: _canned_results(
                                          job["target"], job["profile"]))
            ns.start()
            nodes.append(ns)
            tokens[ns.url] = ns.token

        # Nodes join via their own HTTP endpoint (registered in coordinator).
        for ns in nodes:
            out = _post(ns.url, "/fleet/join", ns.token,
                        {"node_url": ns.url, "token": ns.token})
            assert out["ok"]

        # Heartbeat verifies token auth.
        hb = _post(nodes[0].url, "/fleet/heartbeat", tokens[nodes[0].url],
                   {"node_url": nodes[0].url})
        assert hb["ok"]

        # Bad token is rejected (constant-time path, same 401).
        with pytest.raises(Exception):
            _post(nodes[0].url, "/fleet/heartbeat", "wrong-token",
                  {"node_url": nodes[0].url})

        # Dispatch two jobs and run them on the node servers.
        aggregates = []
        for target in ("http://dup.example", "http://second.example"):
            payload = scanfleet.dispatch(
                coord, {"target": target, "profile": "active-deep"})
            assert payload["job_id"]
            run = _post(payload["node_url"], "/fleet/job",
                        tokens[payload["node_url"]], payload)
            assert run["ok"]
            agg = _post(nodes[0].url, "/fleet/result",
                        tokens[nodes[0].url],
                        {"job_id": payload["job_id"],
                         "results": run["results"]})
            assert agg["ok"]
            aggregates.append(agg["aggregate"])

        # Dedupe: the shared duplicate finding collapses to one entry.
        a = aggregates[0]
        dup = [f for f in a["findings"] if f["title"] == "Reflected XSS"]
        assert len(dup) == 1
        assert dup[0]["confidence"] == "candidate"

        # Risk aggregation via vulnscan2.risk_score (importable here).
        assert "risk_score" in a
        import vulnscan2
        assert a["risk_score"] == vulnscan2.risk_score(a["findings"])

        # Both jobs done and persisted.
        jobs = coord._state["jobs"]
        assert all(j["status"] == "done" for j in jobs)
        saved = json.loads(state_path.read_text())
        assert len(saved["nodes"]) == 2 and len(saved["jobs"]) == 2
    finally:
        for ns in nodes:
            ns.stop()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
