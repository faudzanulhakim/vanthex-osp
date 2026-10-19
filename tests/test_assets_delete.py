"""Delete aset (v1.9.0): aset adalah agregasi scan per target — menghapus
aset menghapus scan + findings + meta + suppression host-nya, TIDAK
menyentuh aset lain."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import store


def _seed(monkeypatch, tmp_path):
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "t.db"))
    store.init_db()
    f = {"severity": "HIGH", "title": "T", "description": "d", "evidence": "",
         "cwe": "", "owasp": "", "cvss": 7.0, "remediation": "",
         "confidence": "probable", "location": "/", "param": "",
         "origin": "active"}
    r = {"overall_risk": "HIGH", "summary": {"HIGH": 1}, "findings": [f]}
    store.save_scan("https://a.example/app", "vulnscan", "active-deep", r)
    store.save_scan("https://a.example/app", "vulnscan", "active-deep", r)
    store.save_scan("https://b.example/", "vulnscan", "active-deep", r)
    store.set_asset_meta("https://a.example/app", "high", "tim-a")
    store.add_suppression("a.example", "T", "tester")


def test_delete_asset_cascades_only_that_target(monkeypatch, tmp_path):
    _seed(monkeypatch, tmp_path)
    counts = store.delete_asset("https://a.example/app")
    assert counts["scans"] == 2
    assert counts["findings"] == 2
    assert counts["suppressions"] == 1
    targets = [a["target"] for a in store.assets_summary()]
    assert targets == ["https://b.example/"]
    assert "https://a.example/app" not in store.get_asset_meta()
    assert store.list_suppressions() == []


def test_delete_missing_asset_is_zero(monkeypatch, tmp_path):
    _seed(monkeypatch, tmp_path)
    counts = store.delete_asset("https://tidak-ada.example/")
    assert counts == {"scans": 0, "findings": 0, "suppressions": 0}
    assert len(store.assets_summary()) == 2
