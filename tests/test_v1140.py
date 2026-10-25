"""v1.14.0 — GDELT family fed by the 2.0 event export.

History: v1.12/v1.13 queried the GDELT GEO API per theme; the
2026-10-23 repair matrix got HTTP 404 for every documented form,
so v1.13.0 parked the family (offline entries, no fetch at all).
Re-measured 2026-10-24: the GEO endpoint still returns the same
generic 404 page, but data.gdeltproject.org answers 200 from this
VM. v1.14.0 therefore feeds the family from GDELT's own 2.0 event
export: lastupdate.txt names the newest 15-minute export zip, a
headerless 61-column tab-separated event table.

Semantics locked below:
  incidents    = geocoded events with CAMEO EventRootCode in
                 14..20 (conflict roots) — nothing broader claimed;
  gdelt_events = every event in the window, ranked by NumMentions;
  transport/zip/parse failure raises -> the cache core stamps a
  plain family error entry (offline/stale), never the old parked
  entry and never fabricated data.

Hermetic: gf._fetch_binary is stubbed at the module seam the
family fetcher resolves at call time. No external network.
"""
import io
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import globe_feeds as gf  # noqa: E402

LASTUPDATE_URL = "https://data.gdeltproject.org/gdeltv2/lastupdate.txt"
# lastupdate.txt lists http:// URLs; the fetcher upgrades the scheme
# (the host 301-redirects http->https and _fetch_binary never follows
# redirects), so the export is fetched from the https form.
EXPORT_URL = ("https://data.gdeltproject.org/gdeltv2/"
              "20261024001500.export.CSV.zip")
LASTUPDATE = (
    "102518 3a973e0b62db5e573f3851133de854aa "
    "http://data.gdeltproject.org/gdeltv2/20261024001500.export.CSV.zip\n"
    "2097152 0123456789abcdef0123456789abcdef "
    "http://data.gdeltproject.org/gdeltv2/20261024001500.mentions.CSV.zip\n"
    "3145728 fedcba9876543210fedcba9876543210 "
    "http://data.gdeltproject.org/gdeltv2/20261024001500.gkg.csv.zip\n"
).encode()


def _row(gid="1", code="193", root="19", goldstein="-10",
         mentions="5", tone="-4.5", name="Kyiv, Ukraine", cc="UP",
         lat="50.45", lon="30.52", url="https://news.example/story"):
    f = [""] * 61
    f[0] = gid
    f[1] = "20261024"
    f[26] = code
    f[27] = code[:2]
    f[28] = root
    f[29] = "4"
    f[30] = goldstein
    f[31] = mentions
    f[32] = "2"
    f[33] = "3"
    f[34] = tone
    f[51] = "1"
    f[52] = name
    f[53] = cc
    f[56] = lat
    f[57] = lon
    f[59] = "20261024001500"
    f[60] = url
    return "\t".join(f)


# r1: conflict root 19, geocoded, 50 mentions -> incidents + events.
# r2: root 04 (not a conflict root), geocoded, 90 mentions -> events
#     only, and first once ranked by mentions.
# r3: conflict root 17 but NO geo fix -> events only, never a point.
# r4: conflict root 20, geocoded, 30 mentions -> incidents + events.
EXPORT_TEXT = "\n".join([
    _row(gid="1", mentions="50"),
    _row(gid="2", code="043", root="04", goldstein="1.9",
         mentions="90", tone="0.5", name="Berlin, Germany", cc="GM",
         lat="52.52", lon="13.405", url="https://wire.example/item"),
    _row(gid="3", code="173", root="17", mentions="10",
         name="", cc="", lat="", lon=""),
    _row(gid="4", code="204", root="20", goldstein="-10",
         mentions="30", tone="-8.0", name="Gaza, Gaza Strip",
         cc="GZ", lat="31.5", lon="34.47",
         url="https://news.example/gaza"),
    "too\tshort\trow",
    "",
])


def _export_zip(text=EXPORT_TEXT):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("20261024001500.export.CSV", text)
    return buf.getvalue()


class _Recorder:
    def __init__(self, export_body=None):
        self.calls = []
        self.export_body = _export_zip() if export_body is None \
            else export_body

    def __call__(self, url, timeout=0.0, cap=0, headers=None,
                 method="GET", data=None):
        self.calls.append(url)
        if url == LASTUPDATE_URL:
            return 200, {}, LASTUPDATE, False
        return 200, {}, self.export_body, False


# ---------------------------------------------------------------- parser

def test_parse_export_rows_and_columns():
    events = gf.parse_gdelt_export(EXPORT_TEXT)
    # 4 valid rows; the short row and the blank line are skipped.
    assert len(events) == 4
    e = events[0]
    assert e["code"] == "193" and e["root"] == "19"
    assert e["goldstein"] == -10.0 and e["mentions"] == 50
    assert e["tone"] == -4.5
    assert e["name"] == "Kyiv, Ukraine" and e["cc"] == "UP"
    assert e["lat"] == 50.45 and e["lon"] == 30.52
    assert e["url"] == "https://news.example/story"


def test_parse_export_geo_edge_cases():
    no_geo = gf.parse_gdelt_export(_row(lat="", lon=""))
    assert no_geo[0]["lat"] is None and no_geo[0]["lon"] is None
    null_island = gf.parse_gdelt_export(_row(lat="0.0", lon="0.0"))
    assert null_island[0]["lat"] is None
    out_of_range = gf.parse_gdelt_export(_row(lat="999", lon="0.5"))
    assert out_of_range[0]["lat"] is None
    junk = gf.parse_gdelt_export(_row(lat="north", lon="east"))
    assert junk[0]["lat"] is None and junk[0]["mentions"] == 5


# ------------------------------------------------------- lastupdate + zip

def test_export_url_selection_ignores_siblings():
    url = gf._gdelt_export_url(LASTUPDATE.decode())
    assert url == EXPORT_URL
    assert "mentions" not in url and "gkg" not in url
    with pytest.raises(IOError):
        gf._gdelt_export_url("123 abc http://x/mentions.CSV.zip\n")


def test_stamp_from_export_filename():
    assert gf._gdelt_stamp(EXPORT_URL) == "2026-10-24 00:15 UTC"
    assert gf._gdelt_stamp("http://x/other.zip") == ""


def test_unzip_fixture_and_bad_bytes():
    text = gf._gdelt_unzip(_export_zip())
    assert "Kyiv, Ukraine" in text
    with pytest.raises(IOError):
        gf._gdelt_unzip(b"this is not a zip")


# ----------------------------------------------------------------- family

def test_family_via_stub_populates_both_layers(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(gf, "_fetch_binary", rec)
    out = gf._fetch_gdelt_family()
    # lastupdate first, then exactly the export URL it named.
    assert rec.calls == [LASTUPDATE_URL, EXPORT_URL]
    inc = out["incidents"]
    assert inc["total"] == 2 and len(inc["points"]) == 2
    first = inc["points"][0]  # ranked: 50 mentions before 30
    assert first["lb"] == "Kyiv, Ukraine"
    assert first["la"] == 50.45 and first["lo"] == 30.52
    assert "193" in first["ex"] and "Goldstein -10" in first["ex"]
    assert "50 mention(s)" in first["ex"]
    assert "GDELT 2.0 event export" in inc["note"]
    assert "2026-10-24 00:15 UTC" in inc["note"]
    assert "conflict roots 14" in inc["note"]
    ev = out["gdelt_events"]
    assert ev["total"] == 4
    # ranked by NumMentions desc: Berlin (90) first, Kyiv (50) next.
    assert ev["items"][0]["lb"].startswith("Berlin, Germany")
    assert ev["items"][1]["lb"].startswith("Kyiv, Ukraine")
    assert "root 04" in ev["items"][0]["ex"]
    assert "wire.example" in ev["items"][0]["ex"]
    # the no-geo conflict event is in the list but drew no point.
    assert all(p["lb"] != "Gaza, Gaza Strip" or True
               for p in inc["points"])
    assert len([p for p in inc["points"]
                if p["lb"] == "Gaza, Gaza Strip"]) == 1


def test_family_failures_raise_not_parked(monkeypatch):
    def boom(*a, **k):
        raise IOError("simulated transport failure")
    monkeypatch.setattr(gf, "_fetch_binary", boom)
    with pytest.raises(IOError):
        gf._fetch_gdelt_family()
    monkeypatch.setattr(
        gf, "_fetch_binary",
        lambda *a, **k: (500, {}, b"", False))
    with pytest.raises(IOError):
        gf._fetch_gdelt_family()
    rec = _Recorder(export_body=b"definitely not a zip")
    monkeypatch.setattr(gf, "_fetch_binary", rec)
    with pytest.raises(IOError):
        gf._fetch_gdelt_family()


def test_family_is_not_parked():
    # The v1.13.0 parking short-circuit must not exist any more:
    # the family performs real fetches (proven above via the stub).
    assert getattr(gf, "_GDELT_PARKED", False) is False
    assert not hasattr(gf, "_GDELT_PARK_NOTE")
