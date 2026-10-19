"""Test analyzer APK (v3.3) melawan fixture nyata + ground truth terverifikasi.
Dua cara jalan: pytest (fungsi test_*) atau langsung: .venv/bin/python tests/test_mobile.py
Fixture: APK uji resmi repo androguard (tests/fixtures/)."""
import io
import logging
import os
import sys
import zipfile
from xml.etree import ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)
logging.disable(logging.CRITICAL)
import mobile

_CACHE = {}


def analyze(name):
    if name not in _CACHE:
        _CACHE[name] = mobile.analyze_apk(f"tests/fixtures/{name}", name)
    return _CACHE[name]


def find(res, frag):
    return [f for f in res["findings"] if frag in f["title"]]


def test_testactivity_debuggable_and_no_fp():
    r = analyze("TestActivity.apk")
    d = find(r, "debuggable")
    assert len(d) == 1 and d[0]["severity"] == "HIGH" and d[0]["confidence"] == "confirmed"
    assert len(find(r, "v1 scheme")) == 1                      # v1-only signature
    assert not find(r, "Dangerous permissions")                # 0 permission
    assert not find(r, "Backup")                              # allowBackup=false
    assert not [f for f in r["findings"] if f["severity"] == "CRITICAL"]
    assert len(find(r, "allowed by default")) == 1                # cleartext default target 16
    assert r["meta"]["package"] == "tests.androguard"


def test_debuggable_boolean_apk():
    r = analyze("debuggable-boolean.apk")
    assert len(find(r, "debuggable")) == 1
    assert not find(r, "v1 scheme")                            # signed v1+v2


def test_a2dp_real_app():
    r = analyze("a2dp.Vol_137.apk")
    p = find(r, "Dangerous permissions")
    assert len(p) == 1 and p[0]["severity"] == "HIGH" and "RECEIVE_SMS" in p[0]["evidence"]
    b = find(r, "App backups allowed")
    assert len(b) == 1 and b[0]["confidence"] == "confirmed"
    hosts = {e["host"] for e in r["endpoints"]}
    assert "github.com" in hosts
    assert "schemas.android.com" not in hosts                 # host skema tersaring
    assert len(find(r, "HTTP endpoint")) == 1
    assert 0 < r["risk_score"] <= 100


def test_repacked_marker_secrets(tmp_path):
    src = open("tests/fixtures/TestActivity.apk", "rb").read()
    buf = io.BytesIO()
    zin = zipfile.ZipFile(io.BytesIO(src))
    zout = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    for item in zin.infolist():
        zout.writestr(item, zin.read(item.filename))
    zout.writestr("assets/config.json",
                  '{"aws_key": "AKIAIOSFODNN7EXAMPLE", '
                  '"db": "https://contoh-app.firebaseio.com", '
                  '"api": "http://api.contoh.internal/v1"}')
    zout.close()
    marker = tmp_path / "marker.apk"
    marker.write_bytes(buf.getvalue())
    r = mobile.analyze_apk(str(marker), "marker.apk")
    aws = find(r, "AWS Access Key")
    assert len(aws) == 1 and aws[0]["confidence"] == "probable"
    assert "AKIA" in aws[0]["evidence"] and "***" in aws[0]["evidence"]
    assert "AKIAIOSFODNN7EXAMPLE" not in aws[0]["evidence"]    # tidak bocor utuh
    assert len(find(r, "Firebase")) == 1
    assert "api.contoh.internal" in {e["host"] for e in r["endpoints"]}


def test_exported_rules_synthetic():
    nsd = 'xmlns:android="http://schemas.android.com/apk/res/android"'
    xml = f'''<manifest {nsd}><application>
    <activity android:name=".Main" android:exported="false"><intent-filter>
    <action android:name="android.intent.action.MAIN"/>
    <category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>
    <activity android:name=".Pub"><intent-filter>
    <action android:name="android.intent.action.VIEW"/></intent-filter></activity>
    <service android:name=".Svc"/>
    <provider android:name=".Prov"/>
    </application></manifest>'''
    comps, _ = mobile._components(ET.fromstring(xml), 25)
    by = {c["name"]: c for c in comps}
    assert by[".Main"]["exported"] is False and by[".Main"]["launcher"]
    assert by[".Pub"]["exported"] is True                     # filter + target<31
    assert by[".Svc"]["exported"] is False
    assert by[".Prov"]["exported"] is False                   # provider target 25
    comps31, _ = mobile._components(ET.fromstring(xml), 34)
    assert {c["name"]: c for c in comps31}[".Pub"]["exported"] is False


if __name__ == "__main__":
    import tempfile
    from pathlib import Path
    test_testactivity_debuggable_and_no_fp(); print("PASS testactivity")
    test_debuggable_boolean_apk(); print("PASS debuggable-boolean")
    test_a2dp_real_app(); print("PASS a2dp")
    with tempfile.TemporaryDirectory() as td:
        test_repacked_marker_secrets(Path(td)); print("PASS marker")
    test_exported_rules_synthetic(); print("PASS exported rules")
    print("\nSEMUA LULUS")


def test_apk_contents_inventory():
    r = analyze("TestActivity.apk")
    ct = r["meta"]["contents"]
    assert r["meta"]["platform"] == "android"
    assert ct["total_files"] > 0 and ct["dex_files"]
    assert ct["dex_classes"] > 0
    info = [f for f in r["findings"] if "Package contents inventoried" in f["title"]]
    assert len(info) == 1 and info[0]["confidence"] == "confirmed"


def test_apk_decompile_output():
    import re as _re
    r = analyze("TestActivity.apk")
    d = r["meta"]["decompile"]
    assert d["classes_total"] > 100
    assert len(d["class_list"]) == d["classes_total"]
    assert d["disassembled"], "kelas aplikasi sendiri harus ter-disassembly"
    lines = [ln for c in d["disassembled"] for m in c["methods"]
             for ln in m["instructions"]]
    assert lines and any(_re.match(r"(invoke|return|const|move|new-instance|iput|iget)", ln)
                         for ln in lines)
    assert "<manifest" in d["resources"]["manifest_xml"]
