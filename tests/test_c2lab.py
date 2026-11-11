"""
Tests for c2lab.py — hermetic, loopback-only, ephemeral ports.
AUTHORIZED TESTING ONLY - LAB EMULATION (tests run with the gate open).
"""
import json
import os
import urllib.request

import pytest

from offensive import c2lab


@pytest.fixture(autouse=True)
def _gate(monkeypatch):
    monkeypatch.setenv("PTK_C2LAB", "1")


# ------------------------------------------------------------ gate / bind

def test_gate_refusal(monkeypatch):
    monkeypatch.delenv("PTK_C2LAB", raising=False)
    with pytest.raises(c2lab.C2LabError):
        c2lab.LocalTaskServer()
    with pytest.raises(c2lab.C2LabError):
        c2lab.Implant("http://127.0.0.1:9")


def test_nonloopback_bind_refused():
    for bad in ("0.0.0.0", "10.0.0.5", "example.com", "::"):
        with pytest.raises(c2lab.C2LabError):
            c2lab.LocalTaskServer(host=bad)


def test_implant_refuses_nonloopback_url():
    with pytest.raises(c2lab.C2LabError):
        c2lab.Implant("http://198.51.100.7:8000")
    with pytest.raises(c2lab.C2LabError):
        c2lab.Implant("http://intranet.corp.example:8000")


# ------------------------------------------------- roundtrip over loopback

@pytest.fixture()
def server():
    srv = c2lab.LocalTaskServer(port=0)  # ephemeral port, 127.0.0.1
    srv.start()
    yield srv
    srv.stop()


def _handlers():
    def file_stat(params):
        return {"path": params.get("path", "/"), "size": 42}

    def env_probe(params):
        return {"keys": 1}

    def dir_list(params):
        depth = int(params.get("depth", 1))
        return {"depth": min(depth, c2lab.DIR_LIST_MAX_DEPTH), "entries": []}

    return {"file_stat": file_stat, "env_probe": env_probe,
            "dir_list": dir_list}


def test_implant_poll_task_result_roundtrip(server):
    ok, info = server.enqueue_task({"type": "file_stat",
                                    "params": {"path": "/etc/hostname"}})
    assert ok and info["task_id"]
    imp = c2lab.Implant(server.url, implant_id="t1",
                        handlers=_handlers(), max_polls=3, seed=1)
    results = imp.bind_token(server.token).run()
    assert len(results) == 1
    r = results[0]
    assert r["task_id"] == info["task_id"]
    assert r["output"]["ok"] is True
    assert r["output"]["data"]["size"] == 42
    stored = server.results_snapshot()
    assert any(x["task_id"] == info["task_id"] for x in stored)


def test_nonwhitelisted_task_rejected(server):
    ok, info = server.enqueue_task({"type": "run_shell", "params": {}})
    assert not ok and "whitelisted" in info["error"]


def test_task_executed_only_via_handlers(server):
    ok, _ = server.enqueue_task({"type": "env_probe", "params": {}})
    assert ok
    imp = c2lab.Implant(server.url, implant_id="t2", handlers={},
                        max_polls=2, seed=2)
    results = imp.bind_token(server.token).run()
    assert results[0]["output"].get("error") == "no handler for env_probe"


# ------------------------------------------------------------- auth

def test_token_auth_reject(server):
    for body in ({}, {"type": "file_stat"}):
        req = urllib.request.Request(
            server.url + "/tasks", data=json.dumps(body).encode(),
            method="POST",
            headers={"Authorization": "Bearer wrong-token"})
        with pytest.raises(urllib.request.HTTPError) as ei:
            urllib.request.urlopen(req, timeout=5)
        assert ei.value.code == 401
    # no token at all
    req = urllib.request.Request(server.url + "/results")
    with pytest.raises(urllib.request.HTTPError) as ei:
        urllib.request.urlopen(req, timeout=5)
    assert ei.value.code == 401


# ------------------------------------------------------------- DNS codec

def test_dns_codec_roundtrip():
    for payload in (b"", b"hi", b"file_stat result /etc/passwd 42",
                    os.urandom(200), b"\x00\xff" * 57):
        names = c2lab.dns_encode(payload, labels_per_name=2)
        assert c2lab.dns_decode(names) == payload
        for n in names:
            for label in n.split("."):
                assert len(label) <= c2lab.DNS_LABEL_MAX
            assert len(n) <= c2lab.DNS_NAME_MAX
            assert n.endswith(".lab.invalid")


def test_dns_label_entropy():
    low = c2lab.dns_encode(b"aaaa")
    assert c2lab.dns_label_entropy(low) < c2lab.dns_label_entropy(
        c2lab.dns_encode(os.urandom(64)))
    assert c2lab.dns_label_entropy([]) == 0.0


# ------------------------------------------------------------- lateral map

def test_lateral_map_build():
    sessions = [
        {"host": "hostA", "credential_id": "cred1", "implant_id": "i1"},
        {"host": "hostB", "credential_id": "cred1"},
        {"host": "hostC", "credential_id": "cred2"},
        None, {},  # malformed input tolerated
    ]
    g = c2lab.lateral_map_lab(sessions)
    assert g["node_count"] == len(g["nodes"]) == 4
    for n in g["nodes"]:
        assert set(n) == {"id", "kind", "label"}
        assert n["kind"] in ("host", "implant")
    for e in g["edges"]:
        assert set(e) == {"from", "to", "via"}
    reuse = [e for e in g["edges"] if e["via"].startswith("credential reuse")]
    assert len(reuse) == 1
    assert reuse[0]["via"] == "credential reuse: cred1"


# --------------------------------------------------------- detection matrix

def test_detection_matrix():
    sessions = [{"host": "h1", "credential_id": "c1"},
                {"host": "h2", "credential_id": "c1"}]
    names = c2lab.dns_encode(b"x" * 30)
    m = c2lab.detection_matrix(sessions=sessions, dns_names=names)
    channels = [row["channel"] for row in m]
    assert channels == ["http_beacon", "dns_emulation",
                        "lateral_movement_lab"]
    names_all = [h["name"] for row in m for h in row["heuristics"]]
    assert "beacon_interval_fingerprint" in names_all
    assert "dns_label_entropy" in names_all
    assert "task_payload_pattern" in names_all
    assert "credential_reuse_hop" in names_all
    assert m[1]["measured"]["names_emitted"] == len(names)
    assert m[2]["measured"]["credential_reuse_edges"] >= 1
