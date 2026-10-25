"""v1.13.0 — categorized globe panels: registry, EONET partitions,
adsb.lol flight classification + sweep, all-group satellite union,
wind grid, GDELT parked semantics, key-gated families, and the CCTV
preview-proxy security suite.

Hermetic: parsers run on fixtures recorded in the Fase-0 window
(adsb.lol / Open-Meteo / TfL media are REAL captures; Feodo/URLhaus
fixtures are SYNTHETIC, built to the documented schemas, because the
abuse.ch family is key-gated and was never contacted). Network seams
are patched; no test contacts a feed.
"""
import json
import os
import time

import pytest

import globe_feeds as gf

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "globe")


def _raw(name):
    with open(os.path.join(FIX, name), "rb") as f:
        return f.read()


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    monkeypatch.setattr(gf, "CACHE_PATH", str(tmp_path / "cache.json"))
    gf._cache.clear()
    gf._cam_registry.clear()
    gf._cam_cache.clear()
    gf._cam_brake.clear()
    gf._tle_groups.clear()
    gf._union.update(version="", ids=[], arr=None, meta={})
    gf._sat_memo.update(points=None, at=0.0, total=0)
    gf._tle.update(text="", fetched_at=0.0, ok=False, error="",
                   bad_lines=0)
    monkeypatch.setattr(gf, "_feed_keys",
                        lambda: {"firms": "", "abusech": ""})
    yield
    gf._cache.clear()
    gf._cam_registry.clear()


# ------------------------------------------------------------- registry

def test_manifest_groups_and_counts():
    st = gf.status()
    order = [g["id"] for g in st["groups"]]
    assert order == ["weather", "flights", "maritime", "transit",
                     "space", "surveillance", "hazards", "threats",
                     "network", "display"]
    counts = {g["id"]: len(g["sublayers"]) for g in st["groups"]}
    # v1.19.0 (2026-10-24): SPACE 6 -> 7 — new `launches` sub-layer
    # (Launch Library 2, Phase 3 OSIRIS program). Intentional change.
    # v1.21.0 (2026-10-25): weather 3 -> 4 — new `wind_particles`
    # sub-layer (GFS 1.00 deg, Phase 5 OSIRIS program). Intentional change.
    assert counts == {"weather": 4, "flights": 5, "maritime": 2,
                      "transit": 1, "space": 7, "surveillance": 1,
                      "hazards": 4, "threats": 3, "network": 2,
                      "display": 1}
    for g in st["groups"]:
        for m in g["sublayers"]:
            assert m["group"] == g["id"] and m["label"] and m["kind"]
            assert m["state"] in ("live", "stale", "offline", "static",
                                  "computed", "noteval", "unreachable",
                                  "browser")
    assert "ADSB.LOL" in st["sources_line"]


def test_static_and_pinned_states():
    mar = gf.get_layer("maritime_static")
    assert mar["state"] == "static" and mar["count_total"] == 50
    lines = gf.get_layer("maritime_lines")
    assert lines["state"] == "static" and lines["count_total"] == 2000
    assert all(len(s) == 4 for s in lines["lines"])
    assert all(-90 <= s[0] <= 90 and -90 <= s[2] <= 90
               for s in lines["lines"])
    nuc = gf.get_layer("nuclear")
    # v1.25.0 REPLACED the WRI 195-site layer with the OSIRIS-model
    # curated 64 (§16.6): per-facility fields, Wikipedia links only
    # where sourceUrl exists (7), static — never live status.
    assert nuc["state"] == "static" and nuc["count_total"] == 64
    assert nuc["note"] == ("STATIC DATASET — 64 facilities, "
                          "Wikipedia-sourced; locations approximate; "
                          "NOT live status")
    assert len(nuc["points"]) == 64
    assert all(set(("la", "lo", "lb", "ex", "nuc")) <= set(p)
               for p in nuc["points"])
    assert len({p["nuc"]["id"] for p in nuc["points"]}) == 64
    assert sum(1 for p in nuc["points"]
               if p["nuc"].get("sourceUrl")) == 7
    tr = gf.get_layer("transit_live")
    assert tr["state"] == "noteval" and "NOT EVALUATED" in tr["note"]
    rn = gf.get_layer("rain")
    assert rn["state"] == "browser" and "2D ONLY" in rn["note"]


# ------------------------------------------------------------- hazards

def test_eonet_partitions_sum_to_whole():
    parts = gf.partition_eonet(_raw("eonet_events.json"))
    whole, total, _ = gf.parse_eonet(_raw("eonet_events.json"))
    part_total = sum(v[1] for v in parts.values())
    assert part_total == total
    for sid in ("fires", "severe", "events_other"):
        pts, t, _n = parts[sid]
        assert len(pts) == t


def test_eonet_family_fires_note_without_key(monkeypatch):
    body = _raw("eonet_events.json")
    monkeypatch.setattr(gf, "_fetch",
                        lambda h, p, timeout=30.0: (200, body))
    out = gf.get_layer("fires")
    assert out["state"] == "live"
    assert "not satellite hotspot detections" in out["note"]
    assert "FIRMS" in out["note"]


def test_firms_csv_parser():
    csv_body = (b"latitude,longitude,bright_ti4,acq_date,acq_time,"
                b"satellite,confidence,frp\n"
                b"-25.5,133.7,330.1,2026-10-23,0123,NOAA-20,H,12.5\n"
                b"bad,row,here,,,,,,\n")
    pts, total, _ = gf.parse_firms_csv(csv_body)
    assert total == 1 and pts[0]["la"] == -25.5


# ------------------------------------------------------------- flights

def test_adsb_classification_buckets():
    mil = json.loads(_raw("adsb_mil.json"))
    point = json.loads(_raw("adsb_point.json"))
    mil_hexes = {r["hex"] for r in mil["ac"]}
    pts = gf.parse_adsb_records(point["ac"], mil_hexes)
    cats = {}
    for p in pts:
        cats[p["cat"]] = cats.get(p["cat"], 0) + 1
    assert sum(cats.values()) == len(pts)
    assert cats.get("flights_commercial", 0) >= 50  # London airspace
    # every /v2/mil record is military by construction of the set
    mil_pts = gf.parse_adsb_records(mil["ac"], mil_hexes)
    assert all(p["cat"] == "flights_military" for p in mil_pts)
    # synthetic bucket edges: bizjet type, dbFlags military, residual
    syn = [
        {"hex": "h1", "t": "GLF5", "lat": 1.0, "lon": 2.0,
         "dbFlags": 0},
        {"hex": "h2", "t": "A400", "lat": 1.0, "lon": 2.0,
         "dbFlags": 1},
        {"hex": "h3", "t": "C172", "flight": "N99999", "lat": 1.0,
         "lon": 2.0, "dbFlags": 0},
        {"hex": "h4", "t": "B738", "flight": "RYR123", "lat": 1.0,
         "lon": 2.0, "dbFlags": 0},
    ]
    by_hex = {p["hex"]: p["cat"] for p in gf.parse_adsb_records(syn, set())}
    assert by_hex == {"h1": "flights_jets", "h2": "flights_military",
                      "h3": "flights_private",
                      "h4": "flights_commercial"}


def test_adsb_dedup_by_hex():
    recs = [{"hex": "dup", "lat": 1.0, "lon": 1.0, "dbFlags": 0},
            {"hex": "dup", "lat": 2.0, "lon": 2.0, "dbFlags": 0}]
    pts = gf.parse_adsb_records(recs, set())
    assert len(pts) == 1 and pts[0]["la"] == 1.0


def test_sweep_centers_grid():
    centers, spacing = gf.sweep_centers()
    assert 100 <= len(centers) <= 130
    assert spacing >= 700
    assert all(-55 <= la <= 72 for la, _lo in centers)
    for i in range(len(centers)):
        for j in range(i + 1, len(centers)):
            assert gf._hav_km(centers[i], centers[j]) >= spacing - 1


def test_flights_opensky_fallback_marks_noteval(monkeypatch):
    payload = _raw("opensky_states_SYNTHETIC.json")
    monkeypatch.setattr(gf, "_fetch",
                        lambda h, p, timeout=30.0: (200, payload))
    fam = gf._flights_family_opensky("test reason")
    assert fam["flights_jets"]["state"] == "noteval"
    assert fam["flights_military"]["state"] == "noteval"
    assert fam["flights_all"]["total"] == 2  # synthetic airborne count
    assert "FALLBACK SOURCE" in fam["flights_all"]["note"]


# --------------------------------------------------------------- space

def _mutated_tle(template_objs, count, start_id):
    """Clone TLE objects with fresh NORAD ids (checksum digit is not
    verified by the SGP4 initializer) to build a union-scale set."""
    out = []
    for i in range(count):
        name, l1, l2 = template_objs[i % len(template_objs)]
        nid = f"{start_id + i:05d}"
        out.append((f"SYN-{nid}", "1 " + nid + l1[7:], l2))
    return out


def test_satellite_union_dedup_and_propagation():
    text = _raw("celestrak_stations.tle").decode()
    objs, _bad = gf.parse_tle(text)
    assert objs
    gf._tle_groups["stations"] = {"text": text, "fetched_at": time.time()}
    # second group reusing two of the same NORAD ids + one new object
    extra = objs[:2] + [_mutated_tle(objs, 1, 99000)[0]]
    text2 = "\n".join(f"{n}\n{a}\n{b}" for n, a, b in extra)
    gf._tle_groups["weather"] = {"text": text2, "fetched_at": time.time()}
    gf._build_union()
    assert len(gf._union["ids"]) == len(objs) + 1  # dedup by NORAD id
    pts, total, _secs = gf._propagate_union()
    assert total == len(pts) and total == len(objs) + 1
    assert all("grps" in p and p["grps"] for p in pts)
    both = [p for p in pts if len(p["grps"]) == 2]
    assert len(both) == 2  # the two shared objects carry both groups


def test_satellite_propagation_budget_at_union_scale():
    text = _raw("celestrak_stations.tle").decode()
    objs, _bad = gf.parse_tle(text)
    big = _mutated_tle(objs, 20000, 10000)
    text_big = "\n".join(f"{n}\n{a}\n{b}" for n, a, b in big)
    gf._tle_groups["last-30-days"] = {"text": text_big,
                                      "fetched_at": time.time()}
    t0 = time.time()
    gf._build_union()
    pts, total, secs = gf._propagate_union()
    wall = time.time() - t0
    assert total >= 19000  # near-union scale actually propagated
    assert secs < 20  # design budget: full cycle under 20 s
    assert wall < 60


# ---------------------------------------------------------------- wind

def test_openmeteo_grid_fixture():
    pts, total, _ = gf.parse_openmeteo(_raw("openmeteo_grid.json"))
    assert total == 240 and len(pts) == 240
    assert all(0 <= p["spd"] <= 60 and 0 <= p["dir"] <= 360
               for p in pts)


def test_wind_family(monkeypatch):
    body = _raw("openmeteo_grid.json")
    monkeypatch.setattr(gf, "_fetch",
                        lambda h, p, timeout=30.0: (200, body))
    out = gf.get_layer("wind")
    assert out["state"] == "live" and out["count_total"] == 240
    assert "sampled grid 15" in out["note"]


# --------------------------------------------------------------- gdelt

def test_gdelt_export_failure_is_offline_not_parked(monkeypatch):
    # v1.14.0 replaced the v1.13.0 parking with the GDELT 2.0 event
    # export fetch. A transport failure now surfaces as a plain
    # family error entry (offline), never the old parked/unreachable
    # entry; this test was rewritten from test_gdelt_parked_no_network.
    def boom(*a, **k):
        raise IOError("simulated transport failure")
    monkeypatch.setattr(gf, "_fetch_binary", boom)
    out = gf.get_layer("incidents")
    assert out["state"] == "offline"
    assert out["points"] == [] and out["count_total"] == 0
    assert "NOT REACHABLE FROM THIS VM" not in out["note"]
    ev = gf.get_layer("gdelt_events")
    assert ev["state"] == "offline" and ev["items"] == []


# ------------------------------------------------------------- abuse.ch

def test_abusech_key_missing_is_noteval(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("key-gated family must not fetch")
    monkeypatch.setattr(gf, "_fetch_binary", boom)
    out = gf.get_layer("botnet_c2")
    assert out["state"] == "noteval"
    assert "FREE ABUSE.CH KEY REQUIRED" in out["note"]
    out2 = gf.get_layer("malware_urls")
    assert out2["state"] == "noteval" and out2["items"] == []


def test_feodo_urlhaus_parsers():
    feodo = json.dumps([
        {"ip_address": "203.0.113.7", "port": 8080, "status": "online",
         "malware": "Emotet", "first_seen": "2026-10-01",
         "last_online": "2026-10-23"},
        {"port": 1},
    ]).encode()
    items, total, _ = gf.parse_feodo(feodo)
    assert total == 1 and items[0]["lb"] == "203.0.113.7:8080"
    uh = json.dumps({"urls": [
        {"url": "http://bad.example/" + "x" * 200, "threat": "Emotet",
         "url_status": "online", "date_added": "2026-10-23"},
    ]}).encode()
    items, total, _ = gf.parse_urlhaus(uh)
    assert total == 1 and len(items[0]["lb"]) <= 78


# ------------------------------------------------------- CCTV proxy

_JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 500
_MP4 = b"\x00\x00\x00\x18ftypmp42" + b"\x01" * 2000


def _seed_cam(monkeypatch, cid="tfl:JamCams_1", img="https://s3-eu-west-1.amazonaws.com/x.jpg",
              clip="https://s3-eu-west-1.amazonaws.com/x.mp4"):
    gf._cam_registry[cid] = {"img": img, "clip": clip, "auth": "TfL",
                             "lb": "Test Cam"}
    return cid


def test_cam_unknown_cid_404(monkeypatch):
    _seed_cam(monkeypatch)
    monkeypatch.setattr(gf, "_fetch_binary",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("must not fetch")))
    # the registry-miss path retries one index refresh — keep it
    # hermetic and instant by failing the index feeds
    monkeypatch.setattr(gf, "_fetch", lambda *a, **k: (503, b""))
    monkeypatch.setattr(gf, "_fetch_range", lambda *a, **k: (503, b""))
    out = gf.get_cam_preview("tfl:NOPE", "img")
    assert out["ok"] is False and out["status"] == 404
    assert out["reason"] == "UNKNOWN CAMERA ID"
    # fuzz: path-like / URL-like cids are just registry misses
    out = gf.get_cam_preview("https://evil.example/x.jpg", "img")
    assert out["status"] == 404


def test_cam_img_success_and_cache(monkeypatch):
    cid = _seed_cam(monkeypatch)
    calls = {"n": 0, "url": None}

    def fake(url, timeout=10.0, cap=0, headers=None, method="GET",
             data=None):
        calls["n"] += 1
        calls["url"] = url
        return 200, {"content-type": "image/jpeg"}, _JPEG, False
    monkeypatch.setattr(gf, "_fetch_binary", fake)
    out = gf.get_cam_preview(cid, "img")
    assert out["ok"] and out["status"] == 200
    assert out["body"] == _JPEG and out["content_type"] == "image/jpeg"
    assert calls["url"] == "https://s3-eu-west-1.amazonaws.com/x.jpg"
    out2 = gf.get_cam_preview(cid, "img")
    assert out2["ok"] and calls["n"] == 1  # 60 s cache hit, no refetch


def test_cam_redirect_and_spoof_and_oversize(monkeypatch):
    cid = _seed_cam(monkeypatch)
    monkeypatch.setattr(
        gf, "_fetch_binary",
        lambda *a, **k: (302, {"location": "https://x.example/"}, b"",
                         False))
    out = gf.get_cam_preview(cid, "img")
    assert not out["ok"] and out["reason"] == "UPSTREAM REDIRECT"
    monkeypatch.setattr(
        gf, "_fetch_binary",
        lambda *a, **k: (200, {"content-type": "text/html"}, b"<html>",
                         False))
    out = gf.get_cam_preview(cid, "img")
    assert not out["ok"] and "NOT AN IMAGE" in out["reason"]
    monkeypatch.setattr(
        gf, "_fetch_binary",
        lambda *a, **k: (200, {"content-type": "video/webm"}, _MP4,
                         False))
    out = gf.get_cam_preview(cid, "clip")
    assert not out["ok"] and "NOT VIDEO/MP4" in out["reason"]
    monkeypatch.setattr(
        gf, "_fetch_binary",
        lambda *a, **k: (200, {"content-type": "image/jpeg"}, _JPEG,
                         True))  # cut=True: exceeded the cap
    out = gf.get_cam_preview(cid, "img")
    assert not out["ok"] and out["reason"] == "MEDIA TOO LARGE"


def test_cam_range_requests(monkeypatch):
    cid = _seed_cam(monkeypatch)
    monkeypatch.setattr(
        gf, "_fetch_binary",
        lambda *a, **k: (200, {"content-type": "video/mp4"}, _MP4,
                         False))
    out = gf.get_cam_preview(cid, "clip", "bytes=100-199")
    assert out["status"] == 206 and len(out["body"]) == 100
    assert out["headers"]["Content-Range"] == \
        f"bytes 100-199/{len(_MP4)}"
    out = gf.get_cam_preview(cid, "clip", "bytes=-50")
    assert out["status"] == 206 and len(out["body"]) == 50
    out = gf.get_cam_preview(cid, "clip", "bytes=99999-")
    assert out["status"] == 416


def test_cam_brake_and_kinds(monkeypatch):
    for i in range(3):
        _seed_cam(monkeypatch, cid=f"tfl:C{i}",
                  img=f"https://s3-eu-west-1.amazonaws.com/{i}.jpg",
                  clip="")
    monkeypatch.setattr(
        gf, "_fetch_binary",
        lambda *a, **k: (200, {"content-type": "image/jpeg"}, _JPEG,
                         False))
    monkeypatch.setattr(gf, "CAM_BRAKE_PER_MIN", 2)
    assert gf.get_cam_preview("tfl:C0", "img")["ok"]
    assert gf.get_cam_preview("tfl:C1", "img")["ok"]
    out = gf.get_cam_preview("tfl:C2", "img")
    assert not out["ok"] and out["status"] == 429
    out = gf.get_cam_preview("tfl:C0", "html")
    assert not out["ok"] and out["status"] == 400
    out = gf.get_cam_preview("tfl:C0", "clip")  # no clip seeded
    assert not out["ok"] and "NO CLIP" in out["reason"]


def test_cam_cid_fields_from_parsers():
    tfl_pts, _t, _n = gf.parse_tfl(_raw("tfl_jamcams.json"))
    assert all(p["cid"].startswith("tfl:") for p in tfl_pts)
    cal_pts, _t, _n = gf.parse_caltrans(_raw("caltrans_d3.json"))
    assert all(p["cid"].startswith("cal:") for p in cal_pts)
