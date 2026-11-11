"""Hermetic tests for deeplink.py — fake APK built in a tmp zip,
no network, no adb, no androguard (plaintext manifest path)."""
import json
import subprocess
import sys
import zipfile

import pytest

sys.path.insert(0, ".")

from offensive.deeplink import (analyze_deeplinks, deeplink_fuzz, exported_risk_rank,
                      parse_apk_surface)

MANIFEST_PLAIN = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.vulnapp">
  <application android:label="VulnApp">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name=".WebViewActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="vulnapp" android:host="open"/>
      </intent-filter>
    </activity>
    <service android:name=".SyncService" android:exported="true"
             android:permission="android.permission.BIND_JOB_SERVICE"/>
  </application>
</manifest>
"""


def _fake_apk(tmp_path, manifest_text=MANIFEST_PLAIN):
    p = tmp_path / "fake.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_text)
        zf.writestr("classes.dex", b"")
    return str(p)


@pytest.fixture()
def apk(tmp_path):
    return _fake_apk(tmp_path)


def test_parse_surface_exports_and_schemes(apk):
    surface = parse_apk_surface(apk)
    assert surface["package"] == "com.example.vulnapp"
    by_name = {c["name"]: c for c in surface["components"]}
    assert by_name["com.example.vulnapp.WebViewActivity"]["exported"]
    assert "vulnapp" in surface["schemes"]
    assert any(l["host"] == "open" for c in surface["components"]
               for l in c["deeplinks"])


def test_risk_rank_high_for_exported_scheme_no_permission():
    assert exported_risk_rank(True, None, True) == "high"
    assert exported_risk_rank(True, "android.permission.SOMETHING", True) \
        == "medium"
    assert exported_risk_rank(True, None, False) == "medium"
    assert exported_risk_rank(False, None, True) == "low"


def test_fuzz_emits_adb_with_scheme_and_webview_override(apk):
    surface = parse_apk_surface(apk)
    cases = deeplink_fuzz(surface)
    assert cases, "fuzz should emit cases for the vulnapp:// scheme"
    assert any("adb shell am start -a android.intent.action.VIEW" in c["adb"]
               and "vulnapp" in c["adb"] for c in cases)
    assert any(c["kind"] == "webView-url-override" and "?url=" in c["uri"]
               for c in cases)
    assert any(c["kind"] == "javascript-injection" for c in cases)
    assert any(c["kind"] == "intent-redirection" for c in cases)
    assert any(c["kind"] == "path-traversal" for c in cases)


def test_analyze_deeplinks_finding_and_plan(apk):
    findings, surface, plan = analyze_deeplinks(apk)
    hit = [f for f in findings
           if f["title"] ==
           "Exported component handles external scheme without permission"]
    assert hit, "exported + scheme + no permission must be flagged"
    assert hit[0]["verification"] in ("static-analysis", "manual-required")
    assert hit[0]["manual_check"]["steps"]
    # plan contains an adb command with the scheme and a webView override
    cmds = " ".join(s["command"] for s in plan["steps"])
    assert "vulnapp" in cmds
    assert "?url=" in cmds or "?loadUrl=" in cmds
    assert "adb shell am start" in cmds
    # guarded service must not be flagged as high
    assert not any("SyncService" in f.get("location", "")
                   and f["severity"] == "HIGH" for f in findings)


def test_no_external_calls(apk, monkeypatch):
    def boom(*a, **k):  # any network-ish use would explode
        raise AssertionError("external call attempted")
    monkeypatch.setattr("socket.socket", boom)
    findings, surface, plan = analyze_deeplinks(apk)
    assert isinstance(findings, list) and isinstance(surface, dict)


def test_cli_entry_prints_json(apk, capsys):
    rc = subprocess.run(
        [sys.executable, "offensive/deeplink.py", apk],
        capture_output=True, text=True, cwd=".")
    assert rc.returncode == 0, rc.stderr
    data = json.loads(rc.stdout)
    assert data["surface"]["package"] == "com.example.vulnapp"
    assert data["manual_plan"]["steps"]
