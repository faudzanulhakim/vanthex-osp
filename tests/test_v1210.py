"""v1.21.0 — Fase 5 program OSIRIS (service dashboard, globe view).

Design §7 + §14.2, OSIRIS-aligned 2026-10-25 (NowCOAST + GFS
1.00 deg, replacing the GIBS + 0.25 deg plan), host batch Fase 5
only (nowcoast.noaa.gov, nomads.ncep.noaa.gov, Open-Meteo
CONDITIONAL fallback, and www.youtube-nocookie.com as
iframe-only, never fetched), no AI, no other phase item, no
Shodan/MAC/BGP/FINGERPRINT:
  1. NowCOAST clouds: NOAA GMGSI thermal-IR mosaic via WMS 1.3.0
     GetMap (browser-direct tiles, EPSG:3857, TRANSPARENT,
     hourly TIME); meta computed server-side (OSIRIS frameTime:
     now - 20 min, snapped to the UTC hour); TIME stamps shown
     as-of, never "LIVE" when stale; mosaic band +/-72.7 deg —
     beyond it, honestly no cover.
  2. GFS wind particles: minimal stdlib GRIB2 decoder (templates
     3.0 / 4.0 / 5.0 simple packing / 5.3 complex packing +
     spatial differencing) over NOMADS filter_gfs_1p00.pl, UGRD /
     VGRD 10 m only, full 181x360 grid as OSIRIS serves it; on
     ANY decode failure the grid dies and the Open-Meteo point
     wind layer stays as fallback — nothing is faked.
  3. Time controls for cloud TIME + wind cycle/forecast + rain
     frames (slider + play/pause, real valid times only).
  4. LIVE FROM SPACE: Sen ISS video panel (youtube-nocookie
     embed, ID pinned at build after the /Sen/Live resolution
     gate), per-camera buttons disabled ("single stream" —
     unverified), TLE-derived ALT/ORBIT via sgp4, no new host
     (wheretheiss.at rejected).

Python tests are hermetic: globe_feeds._fetch_binary and
_fetch_iss_tle are monkeypatched, so no external network is used.
Live NowCOAST tile-URL shape (OSIRIS code match) / NOMADS 1.00
deg decode / Sen stream proof is a deployment-time check, not
part of this suite. The wind-grid pure-JS block is exercised
with a node harness in the v1.16.0 pattern.
"""

import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import globe_feeds as gf  # noqa: E402
import grib2min  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "templates", "app.html"), encoding="utf-8").read()
APP2 = open(os.path.join(ROOT, "app2.py"), encoding="utf-8").read()
GF_SRC = open(os.path.join(ROOT, "globe_feeds.py"), encoding="utf-8").read()

CSP_1210 = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: "
            "https://server.arcgisonline.com https://tilecache.rainviewer.com https://nowcoast.noaa.gov https://tiles.basemaps.cartocdn.com https://s3.amazonaws.com; "
            "connect-src 'self' https://api.rainviewer.com https://basemaps.cartocdn.com https://tiles.basemaps.cartocdn.com https://tiles-a.basemaps.cartocdn.com https://tiles-b.basemaps.cartocdn.com https://tiles-c.basemaps.cartocdn.com https://tiles-d.basemaps.cartocdn.com; "
            "frame-src https://www.youtube-nocookie.com; "
            "worker-src 'self' blob:; "
            "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; "
            "form-action 'self'")
OSINT_MD5_1160 = "65ec21c31b4aad76aa304fcb411388ae"

EXTRA15_LANGS = ["id", "es", "fr", "de", "pt", "ru", "ja", "ko", "zh",
                 "ar", "hi"]
EXTRA15_KEYS = ["WIND PARTICLES", "CLOUDS (NOAA GMGSI)",
                "LIVE FROM SPACE", "CLOUD TIME", "WIND TIME",
                "WIND GRID OFFLINE", "PLAY", "PAUSE", "Reload",
                "TLE-derived", "single stream", "ALT", "ORBIT",
                "SOURCE: Sen",
                "Dark screen ±45 min per orbit (±93 min) is orbital "
                "night — normal, not a glitch.",
                "Sen states live ±20 h/day with replay during loss of "
                "signal — replay must not be mistaken for live.",
                "Loading the video contacts YouTube (Google receives "
                "the viewer IP).",
                "radar offline"]

# Recorded ISS TLE (fetched live at build via the sats union path;
# epoch 2026-10-24T05:01:11Z; SGP4 at epoch+1d gives alt 430.2 km,
# period 92.96 min). The telemetry test propagates it at epoch+1d
# and asserts LEO ranges, not exact values, to avoid brittleness.
ISS_L1 = "1 25544U 98067A   26297.20915682  .00007800  00000+0  14938-3 0  9991"
ISS_L2 = "2 25544  51.6335  21.6229 0006884 302.9098  57.1228 15.49030149591752"


# ------------------------------------------------------------------
# Synthetic GRIB2 fixtures (built to the decoder's offsets, which
# were verified against a real NOMADS file: section 3 npoints@6,
# template@12, ni@30, nj@34, la1@46, lo1@50, la2@55, lo2@59,
# di@63, dj@67, scan@71).
# ------------------------------------------------------------------

def _pack_bits(values, nbits):
    out = bytearray()
    acc = 0
    nacc = 0
    for v in values:
        acc = (acc << nbits) | v
        nacc += nbits
        while nacc >= 8:
            nacc -= 8
            out.append((acc >> nacc) & 0xFF)
    if nacc:
        out.append((acc << (8 - nacc)) & 0xFF)
    return bytes(out)


def _sec1(year=2026, month=10, day=24, hour=12, minute=0):
    b = bytearray(21)
    struct.pack_into(">I", b, 0, 21)
    b[4] = 1
    struct.pack_into(">H", b, 12, year)
    b[14] = month
    b[15] = day
    b[16] = hour
    b[17] = minute
    return bytes(b)


def _sec3(ni, nj, la1, lo1, la2, lo2, di, dj, scan=0, template=0):
    b = bytearray(72)
    struct.pack_into(">I", b, 0, 72)
    b[4] = 3
    struct.pack_into(">I", b, 6, ni * nj)
    struct.pack_into(">H", b, 12, template)
    struct.pack_into(">I", b, 30, ni)
    struct.pack_into(">I", b, 34, nj)
    struct.pack_into(">i", b, 46, int(round(la1 * 1e6)))
    struct.pack_into(">i", b, 50, int(round(lo1 * 1e6)))
    struct.pack_into(">i", b, 55, int(round(la2 * 1e6)))
    struct.pack_into(">i", b, 59, int(round(lo2 * 1e6)))
    struct.pack_into(">I", b, 63, int(round(di * 1e6)))
    struct.pack_into(">I", b, 67, int(round(dj * 1e6)))
    b[71] = scan
    return bytes(b)


def _sec4(number, fhour=6, surf_type=103, surf_value=10):
    b = bytearray(34)
    struct.pack_into(">I", b, 0, 34)
    b[4] = 4
    struct.pack_into(">H", b, 7, 0)
    b[9] = 2
    b[10] = number
    b[17] = 1
    struct.pack_into(">I", b, 18, fhour)
    b[22] = surf_type
    b[23] = 0
    struct.pack_into(">I", b, 24, surf_value)
    return bytes(b)


def _sec5_simple(npoints, ref_val, nbits):
    b = bytearray(21)
    struct.pack_into(">I", b, 0, 21)
    b[4] = 5
    struct.pack_into(">I", b, 5, npoints)
    struct.pack_into(">H", b, 9, 0)
    struct.pack_into(">f", b, 11, ref_val)
    struct.pack_into(">h", b, 15, 0)
    struct.pack_into(">h", b, 17, 0)
    b[19] = nbits
    return bytes(b)


def _sec6_indicator(indicator, bitmap=b""):
    b = bytearray(6 + len(bitmap))
    struct.pack_into(">I", b, 0, 6 + len(bitmap))
    b[4] = 6
    b[5] = indicator
    b[6:] = bitmap
    return bytes(b)


def _sec7(payload):
    b = bytearray(5 + len(payload))
    struct.pack_into(">I", b, 0, 5 + len(payload))
    b[4] = 7
    b[5:] = payload
    return bytes(b)


def _message(sections):
    body = b"".join(sections)
    total = 16 + len(body) + 4
    head = b"GRIB" + b"\x00\x00" + bytes([0, 2]) + struct.pack(">Q", total)
    return head + body + b"7777"


def _msg_simple(number, values, ref_val, nbits, ni=4, nj=3, scan=0,
                bitmap=None, fhour=6):
    packed = _pack_bits([int(round(v - ref_val)) for v in values], nbits)
    secs = [_sec1(), _sec3(ni, nj, 90.0, 0.0, 80.0, 30.0, 10.0, 5.0,
                           scan=scan),
            _sec4(number, fhour=fhour),
            _sec5_simple(len(values), ref_val, nbits)]
    if bitmap is not None:
        secs.append(_sec6_indicator(0, bitmap))
    secs.append(_sec7(packed))
    return _message(secs)


def test_grib2_simple_exact():
    # 4x3 grid, storage row-major north->south, west->east.
    # U values 1..12, V values -1..-12 (ref -1, scaled 0..11).
    u = [float(i) for i in range(1, 13)]
    v = [float(-i) for i in range(1, 13)]
    data = _msg_simple(2, u, 1.0, 4) + _msg_simple(3, v, -12.0, 4)
    msgs = grib2min.decode_messages(data)
    assert len(msgs) == 2
    mu = [m for m in msgs if m["param"]["number"] == 2][0]
    mv = [m for m in msgs if m["param"]["number"] == 3][0]
    assert mu["values"] == u
    assert mv["values"] == v
    assert mu["grid"]["ni"] == 4 and mu["grid"]["nj"] == 3
    assert mu["param"]["category"] == 2
    assert mu["param"]["surface_type"] == 103
    assert mu["param"]["surface_value"] == 10
    assert mu["param"]["forecast_hour"] == 6
    info, u_rows, v_rows = grib2min.decode_gfs_uv(data)
    assert info["fhour"] == 6 and info["ni"] == 4 and info["nj"] == 3
    assert u_rows == [[1.0, 2.0, 3.0, 4.0],
                      [5.0, 6.0, 7.0, 8.0],
                      [9.0, 10.0, 11.0, 12.0]]
    assert v_rows[2] == [-9.0, -10.0, -11.0, -12.0]


def test_grib2_bitmap_missing_point():
    # 12 grid points, bitmap masks out storage index 2 (third point
    # of the first row); 11 packed values follow in bitmap order.
    u = [float(i) for i in range(1, 13)]
    present = [v for i, v in enumerate(u) if i != 2]
    bitmap = bytes([0b11011111, 0b11110000])
    data = _msg_simple(2, present, 1.0, 4, bitmap=bitmap)
    msgs = grib2min.decode_messages(data)
    assert len(msgs) == 1
    m = msgs[0]
    assert len(m["values"]) == 11
    assert m["rank"][2] == -1
    assert m["rank"][0] == 0 and m["rank"][3] == 2
    assert m["values"][2] == 4.0  # storage idx 3 -> third present value


def test_grib2_scan_flip():
    # scan bit 0x80 (i negative): grid_position steps WESTWARD
    # from lo1 (mod 360), so storage cols sit at lon 0, 350, 340,
    # 330 — NOT the naive row-major [0, 10, 20, 30]. The decode
    # must canonicalize through grid_position (sorted lons
    # [0, 330, 340, 350]), not read storage order. NOTE: this
    # fixture follows the decoder's grid_position semantics; GFS
    # production files use scan=0 (proven on the real file), so
    # this exercises the canonicalization path, not a spec file.
    u = [1.0, 4.0, 3.0, 2.0, 5.0, 8.0, 7.0, 6.0,
         9.0, 12.0, 11.0, 10.0]
    v = [-1.0, -4.0, -3.0, -2.0, -5.0, -8.0, -7.0, -6.0,
         -9.0, -12.0, -11.0, -10.0]
    data = _msg_simple(2, u, 1.0, 4, scan=0x80)
    data += _msg_simple(3, v, -12.0, 4, scan=0x80)
    _info, u_rows, v_rows = grib2min.decode_gfs_uv(data)
    assert u_rows == [[1.0, 2.0, 3.0, 4.0],
                      [5.0, 6.0, 7.0, 8.0],
                      [9.0, 10.0, 11.0, 12.0]]
    assert v_rows == [[-1.0, -2.0, -3.0, -4.0],
                      [-5.0, -6.0, -7.0, -8.0],
                      [-9.0, -10.0, -11.0, -12.0]]


def _msg_complex_53():
    # Worked order-2 fixture (see module docstring analysis):
    # f = [3,5,9,17,25,40,62]; extras h1=3, h2=5, hmin=-2;
    # packed = [0,0,4,6,2,9,9]; groups [0,0,4,6] (X1=0, w=3) and
    # [2,9,9] (X1=2, w=3); lengths [4,3]; refL=3, lenInc=1,
    # scaled K=[1,0]; nbits=2, refW=3, widthBits=0, scaledLenBits=1.
    secs = [_sec1(), _sec3(7, 1, 90.0, 0.0, 90.0, 60.0, 10.0, 10.0),
            _sec4(2, fhour=0)]
    s5 = bytearray(49)
    struct.pack_into(">I", s5, 0, 49)
    s5[4] = 5
    struct.pack_into(">I", s5, 5, 7)
    struct.pack_into(">H", s5, 9, 3)
    struct.pack_into(">f", s5, 11, 0.0)
    struct.pack_into(">h", s5, 15, 0)
    struct.pack_into(">h", s5, 17, 0)
    s5[19] = 2
    s5[20] = 0
    s5[21] = 0
    s5[22] = 0
    struct.pack_into(">f", s5, 23, 0.0)
    struct.pack_into(">f", s5, 27, 0.0)
    struct.pack_into(">I", s5, 31, 2)
    s5[35] = 3
    s5[36] = 0
    struct.pack_into(">I", s5, 37, 3)
    s5[41] = 1
    struct.pack_into(">I", s5, 42, 3)
    s5[46] = 1
    s5[47] = 2
    s5[48] = 1
    secs.append(bytes(s5))
    payload = bytes([0x03, 0x05, 0x82,  # extras: 3, 5, -2
                     0x20,              # X1 [0,2] at 2 bits, padded
                     0x80,              # lengths K [1,0] at 1 bit, padded
                     0x02, 0x61, 0xF8])  # group data, 21 bits + 3 pad
    secs.append(_sec7(payload))
    return _message(secs)


def test_grib2_complex_53_exact():
    msgs = grib2min.decode_messages(_msg_complex_53())
    assert len(msgs) == 1
    assert msgs[0]["values"] == [3.0, 5.0, 9.0, 17.0, 25.0, 40.0, 62.0]


def test_grib2_fail_closed():
    good = _msg_simple(2, [float(i) for i in range(1, 13)], 1.0, 4)
    cases = []
    cases.append(b"XXXX" + good[4:])  # bad magic
    cases.append(good[:-10])  # truncated (no 7777, short total)
    bad_grid = bytearray(_sec3(4, 3, 90.0, 0.0, 80.0, 30.0, 10.0, 5.0,
                               template=1))
    cases.append(_message([_sec1(), bytes(bad_grid), _sec4(2),
                           _sec5_simple(12, 1.0, 4),
                           _sec7(_pack_bits(list(range(12)), 4))]))
    s5 = bytearray(_sec5_simple(12, 1.0, 4))
    struct.pack_into(">H", s5, 9, 2)  # data template 5.2: unsupported
    cases.append(_message([_sec1(), _sec3(4, 3, 90.0, 0.0, 80.0, 30.0,
                                          10.0, 5.0), _sec4(2), bytes(s5),
                           _sec7(_pack_bits(list(range(12)), 4))]))
    cases.append(_msg_simple(2, [float(i) for i in range(1, 13)], 1.0, 4,
                             scan=0x10))  # boustrophedon
    for data in cases:
        try:
            grib2min.decode_messages(data)
        except grib2min.GRIB2Error:
            continue
        raise AssertionError("defective GRIB2 was accepted")


def test_grib2_thin_step():
    # thin_step=2 over the 4x3 fixture keeps rows/cols 0,2.
    u = [float(i) for i in range(1, 13)]
    v = [float(-i) for i in range(1, 13)]
    data = _msg_simple(2, u, 1.0, 4) + _msg_simple(3, v, -12.0, 4)
    info, u_rows, v_rows = grib2min.decode_gfs_uv(data, thin_step=2)
    assert info["thin_step"] == 2
    assert u_rows == [[1.0, 3.0], [9.0, 11.0]]
    assert v_rows == [[-1.0, -3.0], [-9.0, -11.0]]


# ------------------------------------------------------------------
# NowCOAST cloud meta (OSIRIS-aligned): computed server-side, no
# caps fetch. The GIBS caps parser + its "Time" vs "TIME"
# regression test died with the GIBS code — the meta below is
# what replaced it.
# ------------------------------------------------------------------

def test_nowcoast_frame_time():
    # OSIRIS frameTime: now minus the 20 min publish lag, snapped
    # down to the UTC hour.
    assert (gf._nowcoast_latest_hour(1792887000)  # 2026-10-25T00:10Z
            .strftime("%Y-%m-%dT%H:00:00Z") == "2026-10-24T23:00:00Z")
    assert (gf._nowcoast_latest_hour(1792861500)  # 2026-10-24T17:05Z
            .strftime("%Y-%m-%dT%H:00:00Z") == "2026-10-24T16:00:00Z")
    times = gf._nowcoast_times(1792887000)
    assert len(times) == 25  # hourly slider window
    assert times[-1] == "2026-10-24T23:00:00Z"
    assert times[0] == "2026-10-23T23:00:00Z"
    assert times == sorted(times)
    assert all(re.match(r"^\d{4}-\d\d-\d\dT\d\d:00:00Z$", t)
               for t in times)


def test_nowcoast_cloudmeta_shape():
    m = gf.get_cloudmeta()  # pure computation, no network
    assert m["ok"] is True and m["source"] == "nowcoast"
    assert m["attribution"] == "Clouds © NOAA/NESDIS GMGSI"
    assert len(m["layers"]) == 1
    lyr = m["layers"][0]
    assert lyr["id"] == "nowcoast_ir"
    assert lyr["wms"] == ("https://nowcoast.noaa.gov/geoserver/"
                          "satellite/wms")
    assert lyr["layer"] == "global_longwave_imagery_mosaic"
    assert lyr["format"] == "image/png"
    assert lyr["latest"] == lyr["times"][-1]
    assert len(lyr["times"]) == 25
    # Server note carries a literal <latest> placeholder the
    # client substitutes with the real TIME stamp.
    assert "<latest>" in m["note"]
    assert "20 min" in m["note"] and "72.7" in m["note"]


def test_nowcoast_wms_url_parts():
    # Client builds the OSIRIS GetMap URL verbatim (WMS 1.3.0,
    # EPSG:3857, TRANSPARENT, PNG, TIME); the static check pins
    # every parameter OSIRIS pins.
    assert "nowcoast.noaa.gov/geoserver/satellite/wms" in HTML
    assert "LAYERS=global_longwave_imagery_mosaic" in HTML
    assert "VERSION=1.3.0" in HTML
    assert "CRS=EPSG:3857" in HTML
    assert "TRANSPARENT=true" in HTML
    assert "FORMAT=image/png" in HTML
    assert "WIDTH=256&HEIGHT=256" in HTML
    assert "&TIME=" in HTML
    assert "glNcTileUrl" in HTML and "glDrawNowcoast" in HTML
    assert "glNcState" in HTML
    # GIBS is fully gone from every F5 surface.
    assert "glDrawGibs" not in HTML
    assert "GL_GIBS_NO_TIME" not in HTML
    assert "gibs.earthdata.nasa.gov" not in HTML
    assert "gibs.earthdata.nasa.gov" not in APP2
    assert "gibs.earthdata.nasa.gov" not in GF_SRC
    assert "GOES" not in HTML and "GOES" not in APP2
    assert "GOES" not in GF_SRC
    assert "filter_gfs_0p25" not in GF_SRC
    assert "filter_gfs_1p00" in GF_SRC



# ------------------------------------------------------------------
# Windgrid validation + ISS telemetry math (hermetic).
# ------------------------------------------------------------------

def test_windgrid_validation_no_fetch(monkeypatch):
    gf._WINDGRID_CACHE.clear()
    called = []

    def _rec(*a, **k):
        called.append(a[0] if a else None)
        return (500, {}, b"", False)

    monkeypatch.setattr(gf, "_fetch_binary", _rec)
    assert gf.get_windgrid("2026102412", 121)["ok"] is False
    assert gf.get_windgrid("20261024", 0)["ok"] is False
    assert gf.get_windgrid("2026102407", 0)["ok"] is False
    assert gf.get_windgrid("2026102412", -1)["ok"] is False
    assert gf.get_windgrid("2026102412", 385)["ok"] is False
    assert called == [], "validation must reject before any fetch"
    # Valid params DO reach the fetch — and a failed fetch dies
    # honestly (ok False), never fabricating a grid.
    out = gf.get_windgrid("2026102412", 123)
    assert out["ok"] is False
    assert len(called) == 1
    # The one fetch uses the OSIRIS 1.00 deg filter, not 0.25 deg.
    assert "filter_gfs_1p00.pl" in called[0]
    assert "pgrb2.1p00.f123" in called[0]
    assert "filter_gfs_0p25" not in called[0]


def test_windgrid_1p00_full_grid(monkeypatch):
    # Synthetic 1.00 deg global grid (360x181) through the real
    # get_windgrid path: U = file column index, V = file row
    # index, so the -180 rotation is asserted exactly.
    gf._WINDGRID_CACHE.clear()
    ni, nj = 360, 181
    u_vals = [float(c) for r in range(nj) for c in range(ni)]
    v_vals = [float(r) for r in range(nj) for c in range(ni)]

    def _msg(number, values, ref_val, nbits):
        packed = _pack_bits([int(round(v - ref_val)) for v in values],
                            nbits)
        secs = [_sec1(), _sec3(ni, nj, 90.0, 0.0, -90.0, 359.0,
                               1.0, 1.0),
                _sec4(number, fhour=6),
                _sec5_simple(len(values), ref_val, nbits),
                _sec7(packed)]
        return _message(secs)

    blob = _msg(2, u_vals, 0.0, 9) + _msg(3, v_vals, 0.0, 8)

    def _fake(url, **k):
        assert "filter_gfs_1p00.pl" in url
        return (200, {}, blob, False)

    monkeypatch.setattr(gf, "_fetch_binary", _fake)
    out = gf.get_windgrid("2026102412", 6)
    assert out["ok"] is True, out
    assert out["count"] == 181 * 360
    assert out["lats"][0] == 90.0 and out["lats"][-1] == -90.0
    assert out["lons"][0] == -180.0 and out["lons"][-1] == 179.0
    assert out["valid_time"] == "2026-10-24T18:00:00Z"
    # Rotation: file col 0 (lon 0) lands at output col 180, file
    # col 180 (lon 180) at output col 0; rows unchanged.
    assert out["u"][0] == 180.0
    assert out["u"][180] == 0.0
    assert out["u"][359] == 179.0
    assert out["v"][0] == 0.0
    assert out["v"][180 * 360] == 180.0
    assert out["v"][180 * 360 + 359] == 180.0


def test_iss_telemetry_math(monkeypatch):
    assert ISS_L1.startswith("1 25544"), "recorded ISS TLE missing"
    gf._iss_tel["doc"] = None
    gf._iss_tel["at"] = 0.0
    monkeypatch.setattr(gf, "_fetch_iss_tle", lambda: (ISS_L1, ISS_L2))
    # "Now" is parsed from the TLE itself (epoch + 1 day), so the
    # test stays valid for whichever recorded TLE is embedded.
    from datetime import datetime, timedelta, timezone
    yy = int(ISS_L1[18:20])
    year = 2000 + yy if yy < 57 else 1900 + yy
    epoch = datetime(year, 1, 1, tzinfo=timezone.utc) + timedelta(
        days=float(ISS_L1[20:32]) - 1)
    fixed = epoch.timestamp() + 86400.0
    monkeypatch.setattr(gf, "_now", lambda: fixed)
    doc = gf.get_iss_telemetry()
    assert doc["ok"] is True
    assert 400.0 <= doc["alt_km"] <= 450.0, doc
    assert 92.0 <= doc["orbit_min"] <= 93.0, doc
    assert doc["stale"] is False
    assert -90.0 <= doc["lat"] <= 90.0
    assert -180.0 <= doc["lon"] <= 180.0
    # STALE branch: same TLE, "now" 4 days after epoch.
    gf._iss_tel["doc"] = None
    gf._iss_tel["at"] = 0.0
    monkeypatch.setattr(gf, "_now", lambda: fixed + 3 * 86400.0)
    doc = gf.get_iss_telemetry()
    assert doc["stale"] is True


# ------------------------------------------------------------------
# Static template / server markers + I18N + CSP/version gates.
# ------------------------------------------------------------------

def test_static_html_f5():
    assert "wind_particles: { g: 'weather'" in HTML
    assert "clouds: 'CLOUDS (NOAA GMGSI)'" in HTML
    assert "wind_particles: 'WIND PARTICLES'" in HTML
    assert "VANTHEX 1.25.0" in HTML
    assert "glDrawNowcoast" in HTML
    assert "glGridPartsStep" in HTML and "glDrawGridParts" in HTML
    assert "glCloudMetaLoad" in HTML and "glWindGridLoad" in HTML
    assert "glCloudPlayToggle" in HTML and "glWindPlayToggle" in HTML
    assert "glRainPlayToggle" in HTML
    assert "data-cloudtime" in HTML and "data-wfhour" in HTML
    assert "data-wcycle" in HTML and "data-rainslider" in HTML
    assert 'id="gl-space"' in HTML and 'data-gt="space"' in HTML
    assert "glSpaceToggle" in HTML and "glIssTelLoad" in HTML
    # The embed URL is built as GL_SEN_EMBED = base + ID, so the
    # test asserts both parts (never a concatenated literal).
    assert "www.youtube-nocookie.com/embed/" in HTML
    assert "GL_SEN_VIDEO_ID = 'fO9e9jnhYK8'" in HTML
    assert "youtube.com/Sen/Live" in HTML
    assert "single stream" in HTML
    assert "TLE-derived" in HTML
    assert "orbital night" in HTML
    assert "±20 h/day" in HTML
    assert "Google receives the viewer IP" in HTML
    assert "globe/cloudmeta" in APP2 and "get_cloudmeta" in GF_SRC
    assert "globe/windgrid" in APP2 and "get_windgrid" in GF_SRC
    assert "globe/iss_telemetry" in APP2 and "get_iss_telemetry" in GF_SRC
    assert "wind_particles" in GF_SRC
    # No new-host / no-AI regressions in the F5 surface. (The
    # server docstring documents the wheretheiss.at rejection, so
    # the server check is "no URL/fetch to it", not absence.)
    assert "wheretheiss.at" not in HTML
    assert "https://wheretheiss" not in GF_SRC
    assert "wheretheiss.at/" not in GF_SRC
    block = HTML[HTML.index("/* v1.21.0 F5 (design §7 + §14.2)"):
                 HTML.index("function glDraw() {")]
    assert "AI OVERVIEW" not in block
    assert "All sides" not in block
    assert "OpenAI" not in block
    # The old RainViewer satellite path must no longer draw clouds.
    assert "glDrawTiles(ctx, g, 'sat')" not in HTML


def test_i18n_extra15():
    m = re.search(r"const I18N_EXTRA15 = (\{.*?\});\nfor \(const _lang",
                  HTML, re.S)
    assert m, "EXTRA15 table missing"
    table = json.loads(m.group(1))
    assert sorted(table.keys()) == sorted(EXTRA15_LANGS)
    for lang in EXTRA15_LANGS:
        assert sorted(table[lang].keys()) == sorted(EXTRA15_KEYS), lang
        assert all(table[lang][k].strip() for k in EXTRA15_KEYS), lang
    hi = table["hi"]
    assert any("\u0900" <= ch <= "\u097f" for v in hi.values()
               for ch in v), "Hindi EXTRA15 must be Devanagari"
    # Fresh Devanagari, not mojibake: no Unicode replacement chars
    # (the corrupt EXTRA10 Hindi "UPDATED" value must never be
    # copied into a new table).
    assert all("\ufffd" not in v for v in hi.values())


def test_js_pure_windgrid_node():
    start = HTML.index("/* v1.21.0 windgrid-pure-start */")
    end = HTML.index("/* v1.21.0 windgrid-pure-end */")
    js = HTML[start:end]
    js += """
const grid = {lats: [90, 87.5, 85], lons: [-180, -177.5, 177.5],
  u: [0, 10, 20, 30, 40, 50, 60, 70, 80],
  v: [0, 0, 0, 0, 0, 0, 0, 0, 0]};
const lons144 = Array.from({length: 144}, (_, i) => -180 + i * 2.5);
const u144 = [], v144 = [];
for (let r = 0; r < 2; r++) for (let c = 0; c < 144; c++) { u144.push(c); v144.push(0); }
const grid144 = {lats: [90, 87.5], lons: lons144, u: u144, v: v144};
const out = {
  c0: glGridWindColor(0), c4: glGridWindColor(4.9),
  c5: glGridWindColor(5), c9: glGridWindColor(9.9),
  c10: glGridWindColor(10), c14: glGridWindColor(14.9),
  c15: glGridWindColor(15), c24: glGridWindColor(24.9),
  c25: glGridWindColor(25), c99: glGridWindColor(99),
  at00: glGridWindAt(grid, 90, -180),
  atMid: glGridWindAt(grid, 88.75, -178.75),
  atSouth: glGridWindAt(grid, 85, -177.5),
  atOut: glGridWindAt(grid, 91, 0),
  atWrap: glGridWindAt(grid144, 90, 179.9),
  atEast: glGridWindAt(grid144, 90, 177.5),
  atWest: glGridWindAt(grid144, 90, -180),
  t1: glFmtValidTime('2026-10-24T12:00:00Z'),
  t2: glFmtValidTime('2026-10-29T15:00:00Z'),
  t3: glFmtValidTime('')
};
console.log(JSON.stringify(out));
"""
    with tempfile.NamedTemporaryFile("w", suffix=".js",
                                     delete=False) as f:
        f.write(js)
        path = f.name
    try:
        res = subprocess.run(["node", path], capture_output=True,
                             text=True, timeout=30)
    finally:
        os.unlink(path)
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout.strip())
    # Design §7 color bands: 0-5 cyan, 5-15 green/yellow,
    # 15-25 orange, >25 red (5-15 split green then yellow).
    assert out["c0"] == "#22D3EE" and out["c4"] == "#22D3EE"
    assert out["c5"] == "#4ADE80" and out["c9"] == "#4ADE80"
    assert out["c10"] == "#FACC15" and out["c14"] == "#FACC15"
    assert out["c15"] == "#FB923C" and out["c24"] == "#FB923C"
    assert out["c25"] == "#EF4444" and out["c99"] == "#EF4444"
    # Corners exact, midpoint bilinear, dateline wrap, out-of-range.
    assert out["at00"] == [0, 0]
    assert out["atMid"] == [20, 0]
    assert out["atSouth"] == [70, 0]
    assert out["atOut"] is None
    # Wrap: lon 179.9 blends col 143 (177.5) with col 0 (-180):
    # 143 * (1 - 0.96) = 5.72 (float tolerance, not exact).
    assert abs(out["atWrap"][0] - 5.72) < 1e-6
    assert out["atWrap"][1] == 0
    assert out["atEast"] == [143, 0]
    assert out["atWest"] == [0, 0]
    assert out["t1"] == "2026-10-24 12:00Z"
    assert out["t2"] == "2026-10-29 15:00Z"
    assert out["t3"] == ""


def test_csp_version_osint_gates():
    m = re.search(r'send_header\("Content-Security-Policy",\s*(.*?)\)',
                  APP2, re.S)
    assert m, "CSP header block not found"
    served = "".join(re.findall(r'"([^"]*)"', m.group(1)))
    assert served == CSP_1210, served
    assert 'server_version = "VANTHEX/1.25.0"' in APP2
    assert '"version": "1.25.0"' in APP2
    assert "VANTHEX 1.25.0" in HTML
    digest = hashlib.md5(
        open(os.path.join(ROOT, "osint.py"), "rb").read()).hexdigest()
    assert digest == OSINT_MD5_1160
    assert "globe/cloudmeta" in APP2 and "globe/windgrid" in APP2
    assert "globe/iss_telemetry" in APP2
