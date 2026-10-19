"""Test analyzer IPA (v3.10) melawan fixture sintetis terkontrol.

IPA dibangun di tempat (zip + plist biner + Mach-O rakitan struct) agar
ground truth-nya pasti: ATS mati, get-task-allow, secret AKIA, Firebase,
framework Alamofire. Kontrol negatif: varian cryptid=1 (FairPlay) TIDAK
boleh menghasilkan temuan secret dari executable terenkripsi.
"""
import os
import plistlib
import struct
import sys
import zipfile
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import mobile


def _macho(cryptid=0, pie=True):
    flags = 0x200000 if pie else 0x0
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, flags, 0)
    lc = struct.pack("<IIIIII", 0x2C, 24, 0, 0, cryptid, 0)  # LC_ENCRYPTION_INFO_64
    body = (b"\x00" * 64 + b"AKIAIOSFODNN7EXAMPLE\x00"
            b"http://api.example.com/v1/login\x00"
            b"https://secure.example.com/\x00__stack_chk_guard\x00"
            b"api_key = \"supersecretvalue123\"\x00")
    return hdr + lc + body


def _build_ipa(tmp_path, cryptid=0):
    p = os.path.join(tmp_path, "TestApp.ipa")
    info = {"CFBundleIdentifier": "com.example.testapp",
            "CFBundleName": "TestApp", "CFBundleDisplayName": "TestApp",
            "CFBundleExecutable": "TestApp",
            "CFBundleShortVersionString": "1.2.3", "CFBundleVersion": "42",
            "MinimumOSVersion": "14.0",
            "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["testapp", "http"]}]}
    prov = {"Name": "Dev Profile", "TeamName": "Example Team",
            "AppIDName": "TestApp Dev",
            "ExpirationDate": datetime(2030, 1, 1),
            "ProvisionedDevices": ["00008030-001234567890802E"],
            "Entitlements": {"get-task-allow": True,
                             "application-identifier": "TEAMID.com.example.testapp",
                             "keychain-access-groups": ["TEAMID.com.example.testapp"]}}
    gs = {"DATABASE_URL": "https://testapp-default-rtdb.firebaseio.com",
          "BUNDLE_ID": "com.example.testapp"}
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("Payload/TestApp.app/Info.plist",
                   plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
        z.writestr("Payload/TestApp.app/TestApp", _macho(cryptid))
        z.writestr("Payload/TestApp.app/embedded.mobileprovision",
                   b"\x30\x82CMSJUNK" + plistlib.dumps(prov, fmt=plistlib.FMT_XML)
                   + b"\x00\x00END")
        z.writestr("Payload/TestApp.app/GoogleService-Info.plist",
                   plistlib.dumps(gs, fmt=plistlib.FMT_BINARY))
        z.writestr("Payload/TestApp.app/Frameworks/Alamofire.framework/Alamofire",
                   b"\xcf\xfa\xed\xfe dummy")
        z.writestr("Payload/TestApp.app/Assets.car", b"\x00" * 128)
        z.writestr("Payload/TestApp.app/_CodeSignature/CodeResources", b"<plist/>")
    return p


def _find(r, frag):
    return [f for f in r["findings"] if frag.lower() in f["title"].lower()]


def test_ipa_static_analysis(tmp_path):
    r = mobile.analyze_ipa(_build_ipa(str(tmp_path)), "TestApp.ipa")
    assert r["profile"] == "ipa-static"
    assert r["meta"]["platform"] == "ios"
    assert r["meta"]["package"] == "com.example.testapp"
    assert r["meta"]["ios"]["distribution"] == "development/ad-hoc"
    assert r["meta"]["ios"]["macho"]["archs"] == ["arm64"]
    assert r["meta"]["ios"]["macho"]["pie"] is True
    assert r["meta"]["ios"]["macho"]["encrypted"] is False
    # temuan wajib
    assert len(_find(r, "NSAllowsArbitraryLoads")) == 1
    assert _find(r, "NSAllowsArbitraryLoads")[0]["severity"] == "HIGH"
    assert len(_find(r, "get-task-allow")) == 1
    assert len(_find(r, "AWS Access Key")) == 1
    assert len(_find(r, "Firebase database URL")) == 1
    assert len(_find(r, "HTTP endpoint (unencrypted)")) == 1
    assert len(_find(r, "Custom URL schemes")) == 1
    assert not _find(r, "stack canary")          # __stack_chk_guard hadir
    assert not _find(r, "FairPlay-encrypted")     # cryptid=0
    # inventaris bongkar isi
    assert "Alamofire" in r["meta"]["contents"]["frameworks"]
    assert r["meta"]["contents"]["total_files"] == 7
    hosts = {e["host"] for e in r["endpoints"]}
    assert "api.example.com" in hosts and "secure.example.com" in hosts


def test_ipa_fairplay_encrypted_negative(tmp_path):
    r = mobile.analyze_ipa(_build_ipa(str(tmp_path), cryptid=1), "TestApp.ipa")
    assert r["meta"]["ios"]["macho"]["encrypted"] is True
    assert len(_find(r, "FairPlay-encrypted")) == 1
    # executable terenkripsi: string-nya TIDAK boleh jadi temuan secret/endpoint
    assert not _find(r, "AWS Access Key")
    assert not _find(r, "HTTP endpoint (unencrypted)")


def test_dispatcher_and_rejects(tmp_path):
    p = _build_ipa(str(tmp_path))
    r = mobile.analyze_package(p, "TestApp.ipa")
    assert r["profile"] == "ipa-static"
    junk = os.path.join(str(tmp_path), "junk.apk")
    with zipfile.ZipFile(junk, "w") as z:
        z.writestr("random.txt", "hello")
    try:
        mobile.analyze_package(junk, "junk.apk")
        raise SystemExit("dispatcher menerima paket sampah")
    except ValueError as e:
        assert "neither" in str(e)


def test_ipa_decoded_plists(tmp_path):
    r = mobile.analyze_ipa(_build_ipa(str(tmp_path)), "TestApp.ipa")
    pl = {x["name"]: x["text"] for x in r["meta"]["decompile"]["plists"]}
    assert "Info.plist" in pl and "com.example.testapp" in pl["Info.plist"]
    assert "embedded.mobileprovision" in pl
    assert "get-task-allow" in pl["embedded.mobileprovision"]
    assert "GoogleService-Info.plist" in pl
