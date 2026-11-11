"""Hermetic tests for timediff.py (tmpdir sqlite, no network)."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offensive import timediff  # noqa: E402


@pytest.fixture()
def store_path(tmp_path):
    return str(tmp_path / "timediff.db")


def _crawler(*urls, method="GET", status=200, body="hello"):
    return [{"url": u, "method": method, "params": [], "status": status,
             "body": body} for u in urls]


def _crawlers(*specs):
    """specs: (url, method, status, body, params) tuples."""
    return [{"url": u, "method": m, "params": p, "status": s, "body": b}
            for (u, m, s, b, p) in specs]


# ------------------------------------------------------------ SnapshotStore

def test_snapshot_store_schema(tmp_path):
    s = timediff.SnapshotStore(str(tmp_path / "t.db"))
    try:
        meta = s.conn.execute(
            "SELECT schema_version FROM snapshot_meta WHERE id='__schema__'"
        ).fetchone()
        assert meta["schema_version"] == timediff.SCHEMA_VERSION
        sid = s.save_snapshot("http://t", {"endpoints": [], "discovered_at": 0,
                                           "engine_version": "x"})
        rows = s.list_snapshots("http://t")
        assert len(rows) == 1 and rows[0]["id"] == sid
        state = s.latest_snapshot("http://t")
        assert state["engine_version"] == "x"
        assert s.latest_snapshot("http://other") is None
    finally:
        s.close()


# ------------------------------------------------------------ capture

def test_capture_snapshot_normalizes():
    out = timediff.capture_snapshot("http://t", [
        {"url": "/a", "method": "post", "params": ["id", "q"],
         "status": 500, "body": "boom", "headers": {"X-A": "1"}},
        {"url": "/b"},                      # minimal, defaults fill in
        {"url": "", "method": "GET"},       # dropped
        "not-a-dict",                       # dropped
    ])
    eps = out["endpoints"]
    assert len(eps) == 2
    a = eps[0]
    assert a["method"] == "POST"
    assert a["status_class"] == "5xx"
    assert a["params"] == ["id", "q"]
    assert len(a["body_hash"]) == 16
    assert len(a["header_sig"]) == 16
    assert eps[1]["method"] == "GET"
    assert eps[1]["status_class"] == ""
    assert out["engine_version"] == timediff.ENGINE_VERSION
    assert "discovered_at" in out


# ------------------------------------------------------------ diff

def test_diff_added_endpoint_gets_plan_and_rank():
    old = timediff.capture_snapshot("t", _crawler("/a"))
    new = timediff.capture_snapshot("t", _crawlers(
        ("/a", "GET", 200, "hello", []),
        ("/b?q=x&id=y", "POST", 500, "hello", ["q", "id"])))
    d = timediff.diff_snapshots(old, new)
    assert len(d["added_endpoints"]) == 1
    added = d["added_endpoints"][0]
    assert added["url"] == "/b?q=x&id=y"
    # params(2)*2 + POST(3) + 5xx(4) = 11
    assert added["risk_rank"] == 11
    assert d["removed_endpoints"] == []
    assert d["changed_endpoints"] == []
    plans = timediff.plan_attacks(d)
    assert len(plans) == 1
    p = plans[0]
    assert p["url"] == "/b?q=x&id=y"
    assert p["class"] == "sqli/xss"
    assert p["id"] and len(p["probe_steps"]) >= 2


def test_diff_param_change_and_body_change():
    old = timediff.capture_snapshot("t", [
        {"url": "/s", "method": "GET", "params": ["a", "b"], "status": 200,
         "body": "v1"}])
    new = timediff.capture_snapshot("t", [
        {"url": "/s", "method": "GET", "params": ["b", "c"], "status": 404,
         "body": "v2"}])
    d = timediff.diff_snapshots(old, new)
    assert d["added_endpoints"] == [] and d["removed_endpoints"] == []
    ch = d["changed_endpoints"]
    assert len(ch) == 1
    c = ch[0]
    assert c["params_added"] == ["c"] and c["params_removed"] == ["a"]
    assert c["status_class_change"] == ["2xx", "4xx"]
    assert c["body_hash_change"] is True
    assert c["risk_rank"] >= timediff._W_BODY_CHANGE
    plans = timediff.plan_attacks(d)
    assert len(plans) == 1


def test_diff_no_change_is_empty():
    st = timediff.capture_snapshot("t", _crawler("/a", method="POST", body="b"))
    d = timediff.diff_snapshots(st, timediff.capture_snapshot(
        "t", _crawler("/a", method="POST", body="b")))
    assert d["added_endpoints"] == []
    assert d["removed_endpoints"] == []
    assert d["changed_endpoints"] == []
    assert d["risk_rank"] == []
    assert timediff.plan_attacks(d) == []


def test_class_guess_hints():
    g = timediff._class_guess
    assert g(["id"]) == "idor"
    assert g(["q"]) == "sqli/xss"
    assert g(["file"]) == "traversal"
    assert g(["url"]) == "ssrf"
    assert g(["other"]) == "fuzz"


# ------------------------------------------------------------ orchestrator

def test_gate_required(store_path):
    with pytest.raises(PermissionError):
        timediff.run_timediff(store_path, "http://t", _crawler("/a"))


def test_run_baseline_then_diff(store_path, monkeypatch):
    monkeypatch.setenv("PTK_TIMEDIFF", "1")
    # baseline run
    r1 = timediff.run_timediff(store_path, "http://t", _crawler("/a"))
    assert r1["baseline"] is True
    assert r1["finding"]["verification"] == "static-analysis"
    # add endpoint -> added with plan
    r2 = timediff.run_timediff(store_path, "http://t",
                               _crawler("/a", "/b?file=x"))
    assert r2["baseline"] is False
    assert len(r2["diff"]["added_endpoints"]) == 1
    assert len(r2["plans"]) == 1
    assert r2["finding"]["verification"] == "static-analysis"
    # change body on /a -> differential finding
    r3 = timediff.run_timediff(store_path, "http://t", [
        {"url": "/a", "method": "GET", "params": [], "status": 200,
         "body": "CHANGED"}])
    assert any(c["body_hash_change"] for c in r3["diff"]["changed_endpoints"])
    assert r3["finding"]["verification"] == "differential"
    # no change -> empty diff
    r4 = timediff.run_timediff(store_path, "http://t", [
        {"url": "/a", "method": "GET", "params": [], "status": 200,
         "body": "CHANGED"}])
    assert r4["diff"]["added_endpoints"] == []
    assert r4["diff"]["changed_endpoints"] == []
    assert r4["plans"] == []
    # persisted snapshots grow monotonically
    s = timediff.SnapshotStore(store_path)
    try:
        assert len(s.list_snapshots("http://t")) == 4
    finally:
        s.close()
