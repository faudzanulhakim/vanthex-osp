"""
tests/test_polyglotlab.py — self-contained tests for polyglotlab.py.

Covers:
  * every generator returns (bytes, info) with correct magic bytes + marker,
  * zip-slip archive entries carry ../ traversal paths,
  * validate_polyglot passes for every generated blob,
  * upload_probe_plan emits copy-paste curl multipart commands,
  * c_polyglot scan check: gated no-op without PTK_POLYGLOT=1, gated run
    emits plan findings for an upload-form fixture (capped at 4).

Run: .venv/bin/python -m pytest tests/test_polyglotlab.py -q
"""
import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offensive import polyglotlab as pl                                  # noqa: E402

FIXTURE_HTML = """
<html><body>
<form action="/upload" method="POST" enctype="multipart/form-data">
  <input type="file" name="file">
  <input type="submit" name="submit" value="go">
</form>
</body></html>
"""

MARK = "PTKMK"


# ------------------------------------------------------------ generators
def test_generator_table_complete():
    assert set(pl.GENERATORS) == set(pl.GEN_MAGIC)
    assert len(pl.GENERATORS) == 8


def test_each_generator_magic_and_marker():
    for kind, gen in pl.GENERATORS.items():
        data, info = gen()
        magic = pl.GEN_MAGIC[kind][0]
        assert isinstance(data, bytes) and data, kind
        assert data.startswith(magic), (kind, data[:8])
        if kind in ("zip_jar", "zip_slip", "docx_xxe"):
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                blob = b"".join(z.read(n) for n in z.namelist())
        else:
            blob = data
        assert MARK.encode() in blob, kind
        assert info["name"] == kind
        assert info["mime"] == pl.GEN_MAGIC[kind][1]
        for key in ("polyglot_type", "detection_evasion_notes", "how_to_test"):
            assert info[key], (kind, key)


def test_generate_dispatch_and_unknown_kind():
    data, info = pl.generate("pdf_ejs", marker="XYZZY")
    assert data.startswith(b"%PDF-1.")
    assert b"XYZZY" in data
    try:
        pl.generate("nope")
        raise AssertionError("expected ValueError")
    except ValueError as e:
        assert "nope" in str(e)


def test_gif_php_is_valid_gif_plus_php_tag():
    data, _ = pl.gif_php()
    assert data.startswith(b"GIF89a")
    assert b"<?php" in data and b"PTK-GIFPHP-" in data


def test_gif_js_body_is_html_script():
    data, _ = pl.gif_js()
    assert data.startswith(b"GIF89a")
    assert b"<script>alert('" in data and b"PTKMK" in data


def test_zip_jar_manifest_entry():
    data, _ = pl.zip_jar()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = z.namelist()
    assert "META-INF/MANIFEST.MF" in names
    assert "probe.txt" in names
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        manifest = z.read("META-INF/MANIFEST.MF").decode()
    assert "X-Probe: PTKMK" in manifest


def test_pdf_variants():
    d1, _ = pl.pdf_ejs()
    d2, _ = pl.pdf_xxe()
    for d in (d1, d2):
        assert d.startswith(b"%PDF-1.")
        assert d.rstrip().endswith(b"%%EOF")
    assert b"/JavaScript" in d1 and b"app.alert('PTKMK')" in d1
    assert b"<!ENTITY xxe SYSTEM \"file:///etc/passwd\">" in d2
    assert b"<x-probe>PTKMK</x-probe>" in d2


def test_zip_slip_entries_contain_traversal_paths():
    data, _ = pl.zip_slip()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = z.namelist()
    traversal = [n for n in names if "../" in n]
    assert traversal, names
    assert any(n.startswith("../../") for n in traversal)
    assert any("tmp/ptk-zipslip" in n for n in traversal)
    assert "benign.txt" in names  # one benign entry alongside
    # payload marker lives inside the traversal entry's content too
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        tname = [n for n in names if "../" in n][0]
        assert b"PTK-ZIPSLIP-PTKMK" in z.read(tname)


def test_svg_xxe_structure():
    data, _ = pl.svg_xxe()
    assert data.startswith(b'<?xml version="1.0"')
    assert b"<!DOCTYPE svg [<!ENTITY xxe" in data
    assert b"&xxe;" in data and b"<!-- PTKMK -->" in data


def test_docx_xxe_is_ooxml_zip():
    data, info = pl.docx_xxe()
    assert info["mime"] == pl.DOCX_MIME
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = z.namelist()
        core = z.read("docProps/core.xml").decode()
    assert "[Content_Types].xml" in names
    assert "word/document.xml" in names
    assert "<!ENTITY xxe" in core and "PTK-DOCX-PTKMK" in core


def test_base64_gif_canonical():
    gif = pl.base64_gif()
    assert gif.startswith(b"GIF89a") and gif.endswith(b"\x00;")


# ------------------------------------------------------------ validator
def test_validate_polyglot_passes_for_all_outputs():
    for kind in pl.GENERATORS:
        data, _ = pl.generate(kind)
        res = pl.validate_polyglot(data, pl.GEN_MAGIC[kind])
        assert res["ok"], (kind, res)
        assert res["magic_actual"] == res["magic_expect"]
        # also accept bare-bytes magic and tuple/list forms
        assert pl.validate_polyglot(data, pl.GEN_MAGIC[kind][0])["ok"]
        assert pl.validate_polyglot(data, list(pl.GEN_MAGIC[kind]))["ok"]


def test_validate_polyglot_failure_and_empty():
    res = pl.validate_polyglot(b"NOPE", b"GIF89a")
    assert res["ok"] is False
    assert "mismatch" in res["detail"]
    assert pl.validate_polyglot(None, b"PK")["ok"] is False


def test_validate_all():
    results = pl.validate_all()
    assert set(results) == set(pl.GENERATORS)
    assert all(r["ok"] for r in results.values())


# ------------------------------------------------------------ probe plan
def test_upload_probe_plan_curl_commands():
    plan = pl.upload_probe_plan(finding_context="profile avatar upload",
                                marker="MK9")
    assert isinstance(plan, str)
    assert "profile avatar upload" in plan
    # every generator gets its own curl multipart step
    for kind in pl.GENERATORS:
        assert f"{kind}.bin" in plan, kind
    assert plan.count("curl ") >= 8
    # multipart form field + filename/type variants
    assert "-F 'file=@" in plan
    assert "filename=" in plan and "type=" in plan
    # marker threading + validation tail
    assert "MK9" in plan
    assert "validate_all" in plan


# ------------------------------------------------------------ scan check
class _Ctx:
    """Minimal ctx stub like test_zerodayheur.py's, plus scan-check fields."""
    def __init__(self, html=FIXTURE_HTML, opts=None):
        self.html = html
        self.opts = opts or {}
        self.target = "https://example.test"
        self.marker = MARK
        self.logs = []

    def cancelled(self):
        return False

    def L(self, msg):
        self.logs.append(msg)


def _run_check(env_set, ctx=None):
    if env_set:
        os.environ["PTK_POLYGLOT"] = "1"
    else:
        os.environ.pop("PTK_POLYGLOT", None)
    ctx = ctx or _Ctx()
    added = []
    pl.c_polyglot(ctx, added.append)
    return added


def test_check_gated_noop_without_env():
    os.environ.pop("PTK_POLYGLOT", None)
    assert _run_check(env_set=False) == []
    # gate off but opts polyglot=1 opt-in still runs
    added = _run_check(env_set=False, ctx=_Ctx(opts={"polyglot": "1"}))
    assert len(added) == 1


def test_check_gated_run_emits_plan_finding():
    added = _run_check(env_set=True)
    assert len(added) == 1
    f = added[0]
    assert f["severity"] == "MEDIUM"
    assert f["cwe"] == "CWE-434"
    assert f["confidence"] == "probable"
    assert f["verification"] == "manual"
    assert f["location"] == "/upload"
    # evidence carries the curl plan mentioning each polyglot file
    ev = f["evidence"]
    for kind in pl.GENERATORS:
        assert f"{kind}.bin" in ev, kind
    assert "curl " in ev and "TARGET/upload" in ev


def test_check_no_upload_surface_no_finding():
    added = _run_check(env_set=True, ctx=_Ctx(html="<html><body>hi</body></html>"))
    assert added == []


def test_check_cap_four_findings():
    # even a surface repeating every upload signal many times must never
    # yield more than 4 findings (check itself caps at one call, but the
    # contract is the hard cap — assert the check emits <= 4)
    html = (FIXTURE_HTML * 10) + ("<a href='/upload'>u</a>" * 10)
    added = _run_check(env_set=True, ctx=_Ctx(html=html))
    assert len(added) <= 4


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok {name}")
    print("all passed")
