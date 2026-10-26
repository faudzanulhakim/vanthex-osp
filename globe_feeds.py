#!/usr/bin/env python3
"""VANTHEX v1.25.0 — OSINT Globe feed engine: categorized sub-layer
registry (design: vanthex-osint-globe-layers-design.md).

Server-side fetch+cache for the public feeds behind the OSINT Search
globe stage. Clients never contact feed sources directly; they read
normalized points / lists / lines from app2 routes backed by this
module, plus camera media through the cctv preview proxy (section 1 of
the design: cid resolved from this module's own CCTV index only).

Declared feed hosts (design section 4 — the complete list; anything
else is a design change, not an improvisation):
  base:    opensky-network.org, earthquake.usgs.gov, celestrak.org,
           services.swpc.noaa.gov, eonet.gsfc.nasa.gov, api.tfl.gov.uk,
           cwwp2.dot.ca.gov, api.gdeltproject.org
  v1.13.0: api.adsb.lol (flights primary), api.open-meteo.com (wind),
           s3-eu-west-1.amazonaws.com (TfL media, preview proxy only)
  v1.14.0: data.gdeltproject.org (GDELT 2.0 event export — replaces
           the GEO API path, which still 404s from this VM)
  v1.21.0: nowcoast.noaa.gov (NOAA NowCOAST WMS, GMGSI thermal
           IR mosaic tiles, browser-direct; meta computed
           server-side, no caps fetch),
           nomads.ncep.noaa.gov (GFS GRIB2 via filter_gfs_1p00.pl,
           daemon-decoded; Open-Meteo stays the point-wind
           fallback, not a new host)
  key-gated (never contacted without ADE's own free key in the 0600
  store outside the package): firms.modaps.eosdis.nasa.gov,
  feodotracker.abuse.ch / *-api.abuse.ch

Honesty contract:
  * every sub-layer carries its own state: live / stale / offline /
    static / computed / noteval (NOT EVALUATED + reason) / unreachable
    (parked after the documented repair matrix failed) / browser
    (2D-only browser tiles);
  * counts are always the numbers actually returned (count_total) and
    actually drawn (count_drawn); sampling is stated in the note;
  * secret validation stays structural/local (D5); feed keys are read
    from the local 0600 store and never logged or packaged.
"""

import base64
import csv
from datetime import date as _date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import gzip
import hashlib
import http.client
import io
import json
import math
import os
import re
import ssl
import struct
import threading
import time
import urllib.request
import zipfile
from urllib.parse import quote, urlparse

import netclient
import grib2min

_HERE = os.path.dirname(os.path.abspath(__file__))
CACHE_PATH = os.path.join(_HERE, "globe_feed_cache.json")
STATIC_PATH = os.path.join(_HERE, "globe_static.json")
LINES_PATH = os.path.join(_HERE, "globe_lines.json")
LAND_PATH = os.path.join(_HERE, "globe_land.b64")

UA = {"User-Agent": "VANTHEX/1.2.1 (OSINT globe; github.com/faudzanulhakim/vanthex-osp)",
      # netclient caps the wire body at 256 KB; gzip keeps the large
      # CCTV index payloads (TfL ~1.1 MB, Caltrans ~0.8 MB) under it.
      "Accept-Encoding": "gzip, deflate"}

# ------------------------------------------------------- sub-layer registry
# group order is the panel order (design section 2). kind:
# points | lines | overlay | computed | static | list.
GROUPS = [
    ("weather", "WEATHER"),
    ("flights", "FLIGHTS"),
    ("maritime", "MARITIME"),
    ("transit", "GROUND TRANSIT"),
    ("space", "SPACE TRACKING"),
    ("surveillance", "SURVEILLANCE"),
    ("hazards", "NATURAL HAZARDS"),
    ("threats", "THREATS & INTEL"),
    ("network", "NETWORK INTEL"),
    ("display", "DISPLAY"),
]

SUBLAYERS = {
    # WEATHER — rain is a browser tile overlay (RainViewer); clouds
    # are NOAA NowCOAST GMGSI thermal-IR browser tiles since
    # v1.21.0, aligned to OSIRIS (the old RainViewer satellite row
    # is superseded, not duplicated).
    # Wind is a server-fetched sample grid; wind_particles is the
    # GFS GRIB2 vector grid (computed, daemon-decoded).
    "rain":    {"group": "weather", "label": "RAIN RADAR",
                "kind": "overlay",
                "src": "RainViewer (browser tiles)", "ttl": 600},
    "clouds":  {"group": "weather", "label": "CLOUDS (NOAA GMGSI)",
                "kind": "overlay",
                "src": "NOAA NowCOAST (GMGSI via WMS)", "ttl": 600},
    "wind":    {"group": "weather", "label": "WIND",
                "kind": "points",
                "src": "Open-Meteo", "ttl": 21600},
    "wind_particles": {"group": "weather", "label": "WIND PARTICLES",
                       "kind": "computed",
                       "src": "NOAA GFS via NOMADS (GRIB2)",
                       "ttl": 3600},
    # FLIGHTS — one adsb.lol sweep family, four exact buckets + ALL.
    "flights_all":        {"group": "flights", "label": "ALL FLIGHTS",
                           "kind": "points", "family": "flights",
                           "src": "adsb.lol (ADSBx) server sweep",
                           "ttl": 300},
    "flights_commercial": {"group": "flights", "label": "COMMERCIAL",
                           "kind": "points", "family": "flights",
                           "src": "adsb.lol (ADSBx) server sweep",
                           "ttl": 300},
    "flights_private":    {"group": "flights", "label": "PRIVATE / OTHER",
                           "kind": "points", "family": "flights",
                           "src": "adsb.lol (ADSBx) server sweep",
                           "ttl": 300},
    "flights_jets":       {"group": "flights", "label": "PRIVATE JETS",
                           "kind": "points", "family": "flights",
                           "src": "adsb.lol (ADSBx) server sweep",
                           "ttl": 300},
    "flights_military":   {"group": "flights", "label": "MILITARY",
                           "kind": "points", "family": "flights",
                           "src": "adsb.lol (ADSBx) server sweep",
                           "ttl": 300},
    # MARITIME — static reference points + compiled static lines.
    "maritime_static": {"group": "maritime",
                        "label": "PORTS & CHOKEPOINTS",
                        "kind": "points",
                        "src": "Static reference (NGA WPI class)",
                        "ttl": None},
    "maritime_lines":  {"group": "maritime", "label": "MARITIME LINES",
                        "kind": "lines",
                        "src": "Eurostat SeaRoute MarNet (EUPL-1.2)",
                        "ttl": None},
    # TRANSIT — K6: not evaluated this release (no keyless
    # vehicle-position feed exists on the approved hosts).
    "transit_live": {"group": "transit", "label": "LIVE BUSES & TRANSIT",
                     "kind": "list", "src": "—", "ttl": None},
    # SPACE — CelesTrak GP union, NORAD-deduped, SGP4-propagated.
    "sats_all":      {"group": "space", "label": "ALL SATELLITES",
                      "kind": "points", "family": "sats",
                      "src": "CelesTrak GP + SGP4", "ttl": 60},
    "sats_comms":    {"group": "space", "label": "STARLINK / COMMS",
                      "kind": "points", "family": "sats",
                      "src": "CelesTrak GP + SGP4", "ttl": 60},
    "sats_military": {"group": "space", "label": "MILITARY / INTEL",
                      "kind": "points", "family": "sats",
                      "src": "CelesTrak GP + SGP4", "ttl": 60},
    "sats_gnss":     {"group": "space", "label": "GPS / NAVIGATION",
                      "kind": "points", "family": "sats",
                      "src": "CelesTrak GP + SGP4", "ttl": 60},
    "sats_eo":       {"group": "space", "label": "EARTH OBSERVATION",
                      "kind": "points", "family": "sats",
                      "src": "CelesTrak GP + SGP4", "ttl": 60},
    "sats_stations": {"group": "space", "label": "STATIONS / TELESCOPES",
                      "kind": "points", "family": "sats",
                      "src": "CelesTrak GP + SGP4", "ttl": 60},
    # SPACE — v1.19.0: upcoming launches (Launch Library 2, TTL 1 h).
    "launches":      {"group": "space", "label": "LAUNCHES",
                      "kind": "points", "family": "launches",
                      "src": "The Space Devs — Launch Library 2",
                      "ttl": 3600},
    # SURVEILLANCE — the CCTV index (preview proxy resolves cids here).
    "cctv":    {"group": "surveillance", "label": "CCTV CAMERAS",
                "kind": "points",
                "src": "TfL JamCam + Caltrans CWWP2", "ttl": 3600},
    # HAZARDS — USGS + the EONET partition family.
    "quakes":       {"group": "hazards", "label": "EARTHQUAKES",
                     "kind": "points", "src": "USGS", "ttl": 120},
    "fires":        {"group": "hazards", "label": "ACTIVE FIRES",
                     "kind": "points", "family": "eonet",
                     "src": "NASA EONET (wildfire events)",
                     "ttl": 1800},
    "severe":       {"group": "hazards", "label": "SEVERE WEATHER",
                     "kind": "points", "family": "eonet",
                     "src": "NASA EONET (severe storms)", "ttl": 1800},
    "events_other": {"group": "hazards", "label": "OTHER EVENTS",
                     "kind": "points", "family": "eonet",
                     "src": "NASA EONET", "ttl": 1800},
    # THREATS & INTEL — GDELT 2.0 event export (v1.14.0), nuclear static.
    "incidents":    {"group": "threats",
                     "label": "CONFLICT & DISASTER INCIDENTS",
                     "kind": "points", "family": "gdelt",
                     "src": "GDELT Project", "ttl": 1800},
    "gdelt_events": {"group": "threats", "label": "GDELT EVENTS",
                     "kind": "list", "family": "gdelt",
                     "src": "GDELT Project", "ttl": 1800},
    "nuclear":      {"group": "threats", "label": "NUCLEAR SITES",
                     "kind": "points",
                     "src": "WRI Global Power Plant Database (CC-BY 4.0)",
                     "ttl": None},
    # NETWORK INTEL — abuse.ch, built but key-gated (K4).
    "botnet_c2":    {"group": "network", "label": "BOTNET C2 SERVERS",
                     "kind": "list", "family": "abusech",
                     "src": "abuse.ch Feodo Tracker", "ttl": 3600},
    "malware_urls": {"group": "network", "label": "LIVE MALWARE URLS",
                     "kind": "list", "family": "abusech",
                     "src": "abuse.ch URLhaus", "ttl": 3600},
    # DISPLAY — day/night terminator, computed (client-side today;
    # the manifest entry is the contract for both surfaces).
    "daynight": {"group": "display", "label": "DAY / NIGHT",
                 "kind": "computed",
                 "src": "Computed (solar position)", "ttl": None},
}

# v1.12 flat names keep working (service route + stored consumers).
LEGACY_ALIASES = {
    "flights": "flights_all",
    "satellites": "sats_all",
    "maritime": "maritime_static",
    "incidents": "incidents",
}
# LAYERS keeps the v1.12 consumer contract (route membership checks):
# every sub-layer id plus the legacy aliases.
LAYERS = dict(SUBLAYERS)
for _alias, _target in LEGACY_ALIASES.items():
    LAYERS.setdefault(_alias, SUBLAYERS[_target])

SAT_GROUPS = ("stations", "visual", "weather", "gps-ops", "gnss",
              "science")
# v1.13.0 (K9): every GP group CelesTrak documents, verified against
# the elements page at Fase 0 (47 slugs). "active" is excluded: it is a
# pure superset duplicate of the categorized union. Slugs the design
# named that CelesTrak no longer offers in the GP era (gorizont,
# raduga, molniya, iridium) cannot be fetched; "experimental-comm" is
# really "x-comm" and "radar-calibration" is really "radar".
SAT_GROUPS_ALL = (
    "stations", "visual", "analyst", "last-30-days",
    "weather", "resource", "sar", "sarsat", "dmc", "tdrss", "argos",
    "planet", "spire",
    "geo", "intelsat", "ses", "eutelsat", "telesat", "starlink",
    "oneweb", "qianfan", "kuiper", "hulianwang", "iridium-NEXT",
    "orbcomm", "globalstar", "amateur", "satnogs", "x-comm",
    "other-comm",
    "gnss", "gps-ops", "glo-ops", "galileo", "beidou", "sbas",
    "science", "geodetic", "engineering", "education",
    "military", "radar", "cubesat",
    "fengyun-1c-debris", "iridium-33-debris", "cosmos-2251-debris",
)
SAT_SUB_GROUPS = {
    "sats_comms": {"geo", "intelsat", "ses", "eutelsat", "telesat",
                   "starlink", "oneweb", "qianfan", "kuiper",
                   "hulianwang", "iridium-NEXT", "orbcomm",
                   "globalstar", "amateur", "satnogs", "x-comm",
                   "other-comm"},
    "sats_military": {"military"},
    "sats_gnss": {"gnss", "gps-ops", "glo-ops", "galileo", "beidou",
                  "sbas"},
    "sats_eo": {"weather", "resource", "sar", "planet", "spire", "dmc",
                "sarsat", "argos", "tdrss"},
    "sats_stations": {"stations", "science"},
}
SAT_TLE_TTL = 2 * 3600
SAT_CAP = 2500            # v1.12 scalar propagate_tle default (kept)
SAT_FAMILY_CAP = 14000    # v1.13 drawn cap for the satellite family
FLIGHT_CAP = 6000         # v1.12 OpenSky parse default (kept)
FLIGHT_FAMILY_CAP = 8000  # v1.13 drawn cap for the flights family
CCTV_CAP = 6000
INCIDENT_CAP = 1000
EVENT_CAP = 1000
LIST_CAP = 200            # items shipped for list sub-layers

# ------------------------------------------------------------------ state
_lock = threading.Lock()
_cache = {}          # sublayer id -> entry dict
_kp = {"value": None, "time_tag": "", "fetched_at": 0.0, "ok": False,
       "error": ""}
# Kp refresh policy (v1.2.1 Kp-nonblocking fix, 2026-10-26): status()
# must never wait on the SWPC fetch. A due refresh runs in a daemon
# thread; the triggering call waits at most _KP_SYNC_GRACE_S so an
# already-fast answer still lands synchronously, while a hung fetch
# costs ~grace instead of the 30 s _fetch timeout (up to ~90 s via
# the daemon helper path). A failed fetch is not retried for
# _KP_FAIL_TTL_S; calls in that window return unavailable at once.
_KP_SUCCESS_TTL_S = 900
_KP_FAIL_TTL_S = 300
_KP_SYNC_GRACE_S = 2.0
_kp_refresh_lock = threading.Lock()
_kp_refresh_in_flight = False
_kp_last_failed_at = 0.0
_tle = {"text": "", "fetched_at": 0.0, "ok": False, "error": "",
        "bad_lines": 0}
_sat_memo = {"points": None, "at": 0.0, "total": 0}
_tle_groups = {}     # slug -> {"text", "fetched_at"}
_union = {"version": "", "ids": [], "arr": None, "meta": {}}
_sat_prop = {"secs": 0.0, "ttl": 60}
_family_locks = {}
_cam_registry = {}   # cid -> {"img", "clip", "auth", "lb"}
_cam_cache = {}      # (cid, kind) -> {"at", "status", "ctype", "body"}
_cam_locks = {}
_cam_brake = []      # timestamps of upstream preview fetches
_PERSIST = {"quakes", "fires", "severe", "events_other", "cctv", "wind",
            # v1.25.0+ opsi B (keputusan ADE 2026-10-25): gdelt, sats,
            # abusech ikut persist agar Live Alerts tidak gelap tiap restart.
            "incidents", "gdelt_events",
            "sats_all", "sats_comms", "sats_military", "sats_gnss",
            "sats_eo", "sats_stations",
            "botnet_c2", "malware_urls"}


def _now():
    return time.time()


def _family_of(sublayer_id):
    return SUBLAYERS[sublayer_id].get("family") or sublayer_id


def _family_lock(fam):
    with _lock:
        return _family_locks.setdefault(fam, threading.Lock())


def family_members(fam):
    return [sid for sid, spec in SUBLAYERS.items()
            if _family_of(sid) == fam]


# ------------------------------------------------------------- feed keys
_KEYS_PATH = os.environ.get(
    "VANTHEX_GLOBE_KEYS_FILE",
    os.path.normpath(os.path.join(
        _HERE, "..", "pentest-toolkit-service", "globe-keys.json")))


def _feed_keys():
    """Optional feed keys (FIRMS MAP_KEY, abuse.ch Auth-Key), read from
    the environment first, else the 0600 store in the service directory
    (outside the package tree). Empty string = not configured. Values
    are never logged, cached to disk, or returned to clients."""
    out = {"firms": os.environ.get("VANTHEX_FIRMS_MAP_KEY", "").strip(),
           "abusech": os.environ.get("VANTHEX_ABUSECH_AUTH_KEY",
                                     "").strip()}
    if out["firms"] and out["abusech"]:
        return out
    try:
        with open(_KEYS_PATH, encoding="utf-8") as f:
            data = json.load(f)
        if not out["firms"]:
            out["firms"] = str(data.get("firms_map_key") or "").strip()
        if not out["abusech"]:
            out["abusech"] = str(data.get("abusech_auth_key") or "").strip()
    except Exception:
        pass
    return out


# ------------------------------------------- fetch delegation (v1.13.1)
# Diagnosis (2026-10-23, measured): the systemd service process
# inherits NO proxy environment (its unit carries only PTK_* vars),
# so its direct fetches die at the sandbox gateway with SSL
# WRONG_VERSION_NUMBER. The runtime egress credential (HTTPS_PROXY)
# rotates per agent session, and a credential copied out of a dead
# session is REJECTED by the proxy (407) — writing it to a file for
# the service cannot work. What works (same pattern as the reverse
# SSH tunnel's mochi-proxy-connect, alive for days): a detached
# long-lived process that inherited the credential AT LAUNCH keeps
# fetching with it after the launching session ends.
#
# So globe fetches are delegated, in order:
#   1. to the fetch daemon (globe_fetch_daemon.py) — a small process
#      launched detached by the 5-minute watchdog (restore-all.sh
#      section 9) from the watchdog's own live session, holding that
#      session's credential in memory only (never on disk). The
#      daemon serves ops over a 0600 unix socket and exits by itself
#      when its credential starts drawing 407s, so the next watchdog
#      run relaunches it with a fresh one.
#   2. to a short-lived helper subprocess that inherits a proxy
#      resolved from THIS process's env (PTK_PROXY / standard proxy
#      vars) — the dev case, and operator deploys that run the
#      service inside a credentialed environment.
#   3. otherwise the caller fetches directly in-process, exactly as
#      before v1.13.1 (correct on hosts with direct egress).
# Delegated ops are only ever the fetches this module itself makes
# (declared feed list + camera URLs from its own index); the daemon
# and helper execute this module's own transport code, so the
# anti-SSRF posture, timeouts and size caps are unchanged. The
# credential is never logged, cached, or returned to clients.
_FETCH_SOCK_PATH = os.environ.get(
    "VANTHEX_GLOBE_FETCH_SOCK",
    os.path.normpath(os.path.join(
        _HERE, "..", "pentest-toolkit-service", "globe-fetch.sock")))
_HELPER_PATH = os.path.join(_HERE, "globe_fetch_helper.py")


def _resolve_proxy():
    """Resolve an egress proxy from THIS process's environment, for
    the subprocess-helper tier. Returns (url, source) or (None, "").
    (The production service resolves nothing here — the daemon tier
    above it is what serves it.)"""
    raw = os.environ.get("PTK_PROXY", "").strip()
    if raw:
        return raw, "ptk-env"
    env = urllib.request.getproxies()
    for scheme in ("https", "http", "all"):
        if env.get(scheme):
            return env[scheme], "env"
    return None, ""


def _raise_helper_error(meta):
    """Re-raise a delegated transport failure with its original type
    name, so callers keep recording the same error strings the
    in-process path produced (e.g. 'SSLError' in cam previews)."""
    et = meta.get("error_type") or "OSError"
    msg = meta.get("error") or "globe fetch failed"
    if et == "SSLError":
        raise ssl.SSLError(msg)
    if et == "TimeoutError":
        raise TimeoutError(msg)
    if et == "ConnectionError":
        raise ConnectionError(msg)
    if et == "URLError":
        raise urllib.error.URLError(msg)
    if et == "ValueError":
        raise ValueError(msg)
    raise IOError(msg)


def _read_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise IOError("fetch daemon closed the connection early")
        buf += chunk
    return buf


def _daemon_fetch(op, payload, http_timeout):
    """Tier 1: ask the fetch daemon over its unix socket. Returns the
    result dict (with 'body' bytes attached), or None when no daemon
    answers (not running, socket gone, framing error) so the caller
    falls through to the next tier."""
    import socket as _socket
    import struct
    if not os.path.exists(_FETCH_SOCK_PATH):
        return None
    req = dict(payload)
    req["op"] = op
    try:
        with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as s:
            s.settimeout((http_timeout or 30.0) + 30.0)
            s.connect(_FETCH_SOCK_PATH)
            blob = json.dumps(req).encode("utf-8")
            s.sendall(struct.pack(">I", len(blob)) + blob)
            (mlen,) = struct.unpack(">I", _read_exactly(s, 4))
            meta = json.loads(_read_exactly(s, mlen).decode("utf-8"))
            (blen,) = struct.unpack(">I", _read_exactly(s, 4))
            meta["body"] = _read_exactly(s, blen) if blen else b""
            return meta
    except Exception:
        return None


def _spawn_helper_fetch(op, payload, http_timeout):
    """Tier 2: run ONE transport op in a short-lived helper process
    that inherits the proxy resolved from this process's env at
    launch. Returns the result dict (with 'body' attached), or None
    when no proxy is resolvable here."""
    import shutil
    import subprocess
    import sys
    import tempfile
    proxy, _src = _resolve_proxy()
    if not proxy:
        return None
    workdir = tempfile.mkdtemp(prefix="globe-fetch-")
    try:
        req = dict(payload)
        req["op"] = op
        req["out"] = os.path.join(workdir, "body.bin")
        env = dict(os.environ)
        for var in ("PTK_PROXY", "HTTPS_PROXY", "HTTP_PROXY",
                    "https_proxy", "http_proxy"):
            env[var] = proxy
        try:
            proc = subprocess.run(
                [sys.executable, _HELPER_PATH],
                input=json.dumps(req).encode("utf-8"),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=(http_timeout or 30.0) + 60.0, env=env)
        except subprocess.TimeoutExpired:
            raise IOError("globe fetch helper timed out")
        if proc.returncode != 0:
            raise IOError(
                "globe fetch helper exited %d: %s" % (
                    proc.returncode,
                    proc.stderr.decode("utf-8", "replace")[-300:]))
        meta = json.loads(proc.stdout.decode("utf-8", "replace"))
        body = b""
        if meta.get("body_file"):
            with open(meta["body_file"], "rb") as f:
                body = f.read()
        meta["body"] = body
        return meta
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _helper_fetch(op, payload, http_timeout):
    """Delegate ONE transport op (daemon tier, then subprocess
    tier). Returns the result dict with 'body' bytes attached, or
    None when no delegation is available — the caller then uses the
    direct in-process path, exactly as before v1.13.1."""
    meta = _daemon_fetch(op, payload, http_timeout)
    if meta is not None:
        return meta
    return _spawn_helper_fetch(op, payload, http_timeout)


# ---------------------------------------------------------------- transport
def _client(host, timeout=30.0, headers=None):
    return netclient.Client("https://" + host, timeout=timeout,
                            extra_headers=headers or UA)


def _fetch(host, path, timeout=30.0, headers=None):
    """One GET via the engine fetch plumbing. Returns (status, raw bytes).
    Raises on transport errors. When a proxy is resolved (v1.13.1
    broker), the GET runs in the short-lived fetch helper. headers
    (v1.23.0, optional) merges over the stock UA — needed for
    DNS-over-HTTPS (Accept: application/dns-json); all pre-v1.23.0
    callers pass nothing and behave exactly as before."""
    hdrs = dict(UA)
    if headers:
        hdrs.update(headers)
    meta = _helper_fetch("client_get",
                         {"host": host, "path": path, "headers": hdrs,
                          "timeout": timeout}, timeout)
    if meta is not None:
        if meta.get("error"):
            raise IOError(meta["error"])
        return meta["status"], meta["body"]
    resp = _client(host, timeout=timeout, headers=hdrs).get(path)
    if resp.error:
        raise IOError(resp.error)
    return resp.status, resp.raw or (resp.body or "").encode("utf-8",
                                                            "replace")


def _fetch_range(host, path, start, end, timeout=30.0):
    """One ranged GET (identity encoding, so byte ranges stay exact).
    Returns (status, raw bytes); raises on transport errors."""
    hdrs = {"User-Agent": UA["User-Agent"],
            "Range": f"bytes={start}-{end}"}
    meta = _helper_fetch("client_get",
                         {"host": host, "path": path, "headers": hdrs,
                          "timeout": timeout}, timeout)
    if meta is not None:
        if meta.get("error"):
            raise IOError(meta["error"])
        return meta["status"], meta["body"]
    resp = netclient.Client("https://" + host, timeout=timeout,
                            extra_headers=hdrs).get(path)
    if resp.error:
        raise IOError(resp.error)
    return resp.status, resp.raw or (resp.body or "").encode("utf-8",
                                                             "replace")


def _fetch_large(host, path, timeout=30.0, cap=4 * 1024 * 1024):
    """Full body for payloads larger than netclient's 256 KB wire cap
    (the CCTV indexes). Reassembles HTTP Range chunks; stops as soon as
    the accumulated body parses as complete JSON. Servers that ignore
    Range and truncate are surfaced honestly — the caller's parser will
    fail on the partial body and the layer note says so."""
    buf = b""
    start = 0
    chunk = netclient.MAX_BODY
    for _ in range(20):
        if len(buf) >= cap:
            break
        status, part = _fetch_range(host, path, start,
                                    start + chunk - 1, timeout)
        if status not in (200, 206):
            if not buf:
                raise IOError(f"HTTP {status}")
            break
        if status == 200 and start > 0:
            break  # Range ignored mid-stream; keep what we have
        buf += part
        try:
            json.loads(buf)
            return buf
        except Exception:
            pass
        if len(part) < chunk:
            break  # short read = end of body
        start += len(part)
    return buf


def _fetch_binary(url, timeout=10.0, cap=1024 * 1024, headers=None,
                  method="GET", data=None):
    """Binary GET/POST for payloads netclient cannot carry (camera
    media, FIRMS CSV). NEVER follows redirects: a 3xx is returned to
    the caller as-is. Reads at most cap+1 bytes. Returns (status,
    headers, body, cut) where cut=True means the body exceeded cap.
    When a proxy is resolved (v1.13.1 broker), the fetch runs in the
    short-lived fetch helper; otherwise in-process, as before."""
    meta = _helper_fetch("binary",
                         {"url": url, "timeout": timeout, "cap": cap,
                          "headers": headers, "method": method,
                          "data_b64": base64.b64encode(data).decode()
                          if isinstance(data, (bytes, bytearray))
                          else None}, timeout)
    if meta is not None:
        if meta.get("error"):
            _raise_helper_error(meta)
        return (meta["status"], meta.get("headers") or {},
                meta["body"], bool(meta.get("cut")))
    return _fetch_binary_direct(url, timeout=timeout, cap=cap,
                                headers=headers, method=method,
                                data=data)


def _fetch_binary_direct(url, timeout=10.0, cap=1024 * 1024,
                         headers=None, method="GET", data=None):
    """In-process implementation of _fetch_binary (also what the
    fetch helper executes, with the launch-time proxy env the parent
    resolved for it). Mirrors netclient's proxy handling."""
    p = urlparse(url)
    host = p.hostname
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path + (("?" + p.query) if p.query else "")
    hdrs = {"User-Agent": UA["User-Agent"]}
    hdrs.update(headers or {})
    proxies = urllib.request.getproxies()
    proxy = proxies.get(p.scheme, "")
    if proxy:
        pp = urlparse(proxy if "//" in proxy else "http://" + proxy)
        if p.scheme == "https":
            conn = http.client.HTTPSConnection(
                pp.hostname, pp.port or 8080, timeout=timeout,
                context=ssl._create_unverified_context())
            th = None
            if pp.username:
                import base64 as _b64
                cred = _b64.b64encode(
                    f"{pp.username}:{pp.password or ''}".encode()).decode()
                th = {"Proxy-Authorization": "Basic " + cred}
            conn.set_tunnel(host, port, headers=th)
            send = path
        else:
            conn = http.client.HTTPConnection(
                pp.hostname, pp.port or 8080, timeout=timeout)
            send = url
            if pp.username:
                import base64 as _b64
                cred = _b64.b64encode(
                    f"{pp.username}:{pp.password or ''}".encode()).decode()
                hdrs.setdefault("Proxy-Authorization", "Basic " + cred)
    elif p.scheme == "https":
        conn = http.client.HTTPSConnection(
            host, port, timeout=timeout,
            context=ssl._create_unverified_context())
        send = path
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        send = path
    conn.request(method, send, body=data, headers=hdrs)
    r = conn.getresponse()
    body = r.read(cap + 1)
    cut = len(body) > cap
    if cut:
        body = body[:cap]
    enc = (r.getheader("Content-Encoding") or "").lower()
    if enc == "gzip" and not cut:
        try:
            body = gzip.decompress(body)
        except Exception:
            pass
    out = (r.status,
           {k.lower(): v for k, v in r.getheaders()}, body, cut)
    conn.close()
    return out


def _parse_cert_der(der):
    """DER -> display dict via cryptography (approved library).
    Returns {} on any parse failure (never raises into callers)."""
    try:
        from cryptography import x509 as _x509
        cert = _x509.load_der_x509_certificate(der)
        try:
            nb = cert.not_valid_before_utc.isoformat()
        except AttributeError:
            nb = cert.not_valid_before.isoformat()
        try:
            na = cert.not_valid_after_utc.isoformat()
        except AttributeError:
            na = cert.not_valid_after.isoformat()
        san = []
        try:
            ext = cert.extensions.get_extension_for_class(
                _x509.SubjectAlternativeName)
            san = [str(v) for v in ext.value.get_values_for_type(
                _x509.DNSName)][:20]
        except Exception:
            pass
        import hashlib as _hl
        return {"subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_before": nb, "not_after": na, "san": san,
                "serial": str(cert.serial_number),
                "sha256": _hl.sha256(der).hexdigest()}
    except Exception:
        return {}


def tls_audit(host, port=443, timeout=15.0):
    """v1.23.0 SSL tool backend. Daemon 'tls' op first (proxied TLS
    through the launch-time proxy — the only path that reaches the
    real target from the service network). When no delegation exists
    or the op errors, fall back to scanners.ssl_audit (the
    same-as-New-Scan path): from the service that fails honestly
    (gateway banner is not a TLS handshake), so a gateway cert can
    never be reported as the target's. Returns a normalized dict
    with ok True/False; cert {} when unavailable."""
    meta = _helper_fetch("tls", {"host": host, "port": port,
                                 "timeout": timeout}, timeout)
    if meta is not None and not meta.get("error") \
            and meta.get("status") == "ok":
        der = None
        if meta.get("der_b64"):
            try:
                der = base64.b64decode(meta["der_b64"])
            except Exception:
                der = None
        return {"ok": True, "host": host, "port": port,
                "tls_version": meta.get("version", ""),
                "cipher": meta.get("cipher", ""),
                "verify_ok": bool(meta.get("verify_ok")),
                "verify_error": meta.get("verify_error", ""),
                "cert": _parse_cert_der(der) if der else {},
                "transport": "daemon"}
    try:
        import scanners as _sc
        raw = _sc.ssl_audit(host, port, timeout=5.0)
        cert = {"subject": str(raw.get("subject", "")),
                "issuer": str(raw.get("issuer", "")),
                "not_before": str(raw.get("not_before", "")),
                "not_after": str(raw.get("not_after", "")),
                "san": raw.get("san", []) or []}
        if not cert["subject"] and not cert["issuer"]:
            return {"ok": False, "host": host, "port": port,
                    "reason": "TLS audit unavailable from the "
                              "service network (daemon path "
                              "required)",
                    "transport": "in-process-failed"}
        return {"ok": True, "host": host, "port": port,
                "tls_version": raw.get("tls_version", ""),
                "cipher": (raw.get("cipher") or [None])[0] or "",
                "verify_ok": bool(raw.get("verify_ok")),
                "verify_error": raw.get("verify_error", ""),
                "cert": cert, "transport": "in-process"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "host": host, "port": port,
                "reason": "TLS audit unavailable: %s" % str(exc)[:160],
                "transport": "in-process-failed"}


# ---------------------------------------------------------------- parsers
# Pure functions (bytes -> (points, total, note)) so hermetic tests can
# drive them from recorded fixtures without any network.

def parse_usgs(raw):
    d = json.loads(raw)
    pts, skipped = [], 0
    for f in d.get("features") or []:
        geom = f.get("geometry") or {}
        coords = geom.get("coordinates") or []
        props = f.get("properties") or {}
        if geom.get("type") != "Point" or len(coords) < 2 \
                or props.get("mag") is None:
            skipped += 1
            continue
        pts.append({"la": round(coords[1], 4), "lo": round(coords[0], 4),
                    "lb": f"M{props['mag']:.1f}",
                    "ex": props.get("place") or "",
                    "mag": props["mag"], "t": props.get("time") or 0})
    note = f"{skipped} feature(s) without geometry/magnitude skipped" \
        if skipped else ""
    return pts, len(pts), note


def parse_opensky(raw, cap=FLIGHT_CAP):
    d = json.loads(raw)
    states = d.get("states") or []
    air = []
    for s in states:
        # state vector: [icao24, callsign, origin_country, time_position,
        # last_contact, longitude(5), latitude(6), baro_alt, on_ground(8),
        # velocity, true_track, ...]
        if len(s) < 9 or s[5] is None or s[6] is None or s[8]:
            continue
        air.append(s)
    total = len(air)
    if total > cap:
        stride = total / float(cap)
        drawn = [air[int(i * stride)] for i in range(cap)]
        note = f"sampled: {total} airborne -> {cap} drawn (stride)"
    else:
        drawn = air
        note = ""
    pts = [{"la": round(s[6], 4), "lo": round(s[5], 4),
            "lb": (s[1] or s[0] or "").strip(),
            "ex": f"{s[2] or ''} · alt {int(s[7]) if s[7] is not None else '?'} m"}
           for s in drawn]
    return pts, total, note


def parse_tle(text):
    """Returns (objects, bad_count). objects: (name, line1, line2)."""
    lines = [ln.rstrip() for ln in text.splitlines()]
    objs, bad, i = [], 0, 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("1 ") and i + 1 < len(lines) \
                and lines[i + 1].startswith("2 "):
            objs.append(("", ln, lines[i + 1]))
            i += 2
            continue
        if ln and not ln.startswith(("1 ", "2 ")):
            if i + 2 < len(lines) and lines[i + 1].startswith("1 ") \
                    and lines[i + 2].startswith("2 "):
                objs.append((ln.strip(), lines[i + 1], lines[i + 2]))
                i += 3
                continue
            bad += 1
        i += 1
    return objs, bad


def _gmst_deg(jd):
    t = (jd - 2451545.0) / 36525.0
    g = 280.46061837 + 360.98564736629 * (jd - 2451545.0) \
        + 0.000387933 * t * t - t * t * t / 38710000.0
    return g % 360.0


def propagate_tle(text, when=None, cap=SAT_CAP):
    """Propagate TLE objects with SGP4 (approved library, K2) to
    lat/lon points. Positions are computed, epoch-labelled — never
    presented as measured telemetry. (Scalar reference path, kept from
    v1.12; the v1.13 family fetcher uses the vectorized union path.)"""
    from sgp4.api import Satrec, jday, SGP4_ERRORS
    when = when or time.time()
    import datetime as _dt
    dt = _dt.datetime.utcfromtimestamp(when)
    jd, fr = jday(dt.year, dt.month, dt.day, dt.hour, dt.minute,
                  dt.second + dt.microsecond / 1e6)
    gmst = math.radians(_gmst_deg(jd + fr))
    objs, bad = parse_tle(text)
    pts, errors = [], 0
    for name, l1, l2 in objs:
        try:
            sat = Satrec.twoline2rv(l1, l2)
            err, r, _v = sat.sgp4(jd, fr)
        except Exception:
            errors += 1
            continue
        if err != 0:
            errors += 1
            continue
        x, y, z = r
        lon = math.degrees(math.atan2(y, x)) - math.degrees(gmst)
        lon = (lon + 540.0) % 360.0 - 180.0
        lat = math.degrees(math.atan2(z, math.hypot(x, y)))
        alt = math.sqrt(x * x + y * y + z * z) - 6371.0
        pts.append({"la": round(lat, 3), "lo": round(lon, 3),
                    "lb": name or l1[2:7].strip(),
                    "ex": f"alt {int(round(alt))} km · computed (SGP4)"})
    total = len(pts)
    note = ""
    if errors or bad:
        note = f"{errors} object(s) failed propagation, {bad} bad TLE line(s) skipped"
    if total > cap:
        stride = total / float(cap)
        pts = [pts[int(i * stride)] for i in range(cap)]
        note = (note + " " if note else "") + \
            f"sampled: {total} propagated -> {cap} drawn"
    return pts, total, note


def _eonet_point(ev):
    """One EONET event -> point or None (latest geometry; polygons are
    placed at their ring centroid, as in v1.12)."""
    geoms = ev.get("geometry") or []
    if not geoms:
        return None
    g = geoms[-1]
    coords = g.get("coordinates")
    la = lo = None
    if g.get("type") == "Point" and coords and len(coords) >= 2:
        lo, la = coords[0], coords[1]
    elif g.get("type") == "Polygon" and coords and coords[0]:
        ring = coords[0]
        lo = sum(p[0] for p in ring) / len(ring)
        la = sum(p[1] for p in ring) / len(ring)
    if la is None:
        return None
    cats = ev.get("categories") or [{}]
    return {"la": round(la, 4), "lo": round(lo, 4),
            "lb": (ev.get("title") or "")[:80],
            "ex": cats[0].get("title") or cats[0].get("id") or "",
            "t": g.get("date") or "",
            "cats": [c.get("id") or "" for c in cats]}


def parse_eonet(raw, cap=EVENT_CAP):
    d = json.loads(raw)
    pts, skipped = [], 0
    for ev in d.get("events") or []:
        p = _eonet_point(ev)
        if p is None:
            skipped += 1
            continue
        p.pop("cats", None)
        pts.append(p)
    note = f"{skipped} event(s) without geometry skipped" if skipped else ""
    return pts[:cap], len(pts), note


def partition_eonet(raw):
    """One EONET body -> the three v1.13 partitions (design 3.3):
    wildfires / severeStorms / everything else. Returns
    {sublayer_id: (points, total, note)}; partitions share one fetch."""
    d = json.loads(raw)
    buckets = {"fires": [], "severe": [], "events_other": []}
    skipped = 0
    for ev in d.get("events") or []:
        p = _eonet_point(ev)
        if p is None:
            skipped += 1
            continue
        cats = set(p.pop("cats", []))
        if "wildfires" in cats:
            buckets["fires"].append(p)
        elif "severeStorms" in cats:
            buckets["severe"].append(p)
        else:
            buckets["events_other"].append(p)
    out = {}
    for sid, pts in buckets.items():
        note = f"{skipped} event(s) without geometry skipped" \
            if skipped else ""
        out[sid] = (pts[:EVENT_CAP], len(pts), note)
    return out


def parse_swpc_kp(raw):
    d = json.loads(raw)
    if not d:
        raise ValueError("empty Kp series")
    last = d[-1]
    return float(last["Kp"]), str(last.get("time_tag") or "")


def parse_tfl(raw):
    d = json.loads(raw)
    pts = []
    for cam in d:
        la, lo = cam.get("lat"), cam.get("lon")
        if la is None or lo is None:
            continue
        props = {p.get("key"): p.get("value")
                 for p in cam.get("additionalProperties") or []}
        cid = "tfl:" + str(cam.get("id") or cam.get("commonName") or "")
        pts.append({"la": round(float(la), 5), "lo": round(float(lo), 5),
                    "lb": cam.get("commonName") or cam.get("id") or "",
                    "ex": "TfL JamCam · London",
                    "img": props.get("imageUrl") or "",
                    "clip": props.get("videoUrl") or "",
                    "cid": cid,
                    "auth": "TfL"})
    return pts, len(pts), ""


def parse_caltrans(raw):
    """One district file. Returns (points, total, note)."""
    d = json.loads(raw)
    pts = []
    for row in d.get("data") or []:
        cam = row.get("cctv") or {}
        loc = cam.get("location") or {}
        try:
            la = float(loc.get("latitude"))
            lo = float(loc.get("longitude"))
        except (TypeError, ValueError):
            continue
        if cam.get("inService") not in (True, "true", "True", 1):
            continue
        img = ((cam.get("imageData") or {}).get("static") or {}) \
            .get("currentImageURL") or ""
        cid = "cal:" + hashlib.md5(
            (img or (loc.get("locationName") or "")).encode()).hexdigest()[:12]
        pts.append({"la": round(la, 5), "lo": round(lo, 5),
                    "lb": loc.get("locationName") or "",
                    "ex": f"Caltrans D{loc.get('district', '?')} · "
                          f"{loc.get('nearbyPlace') or loc.get('county') or ''}",
                    "img": img, "cid": cid, "auth": "Caltrans"})
    return pts, len(pts), ""


def parse_gdelt(raw, cap=INCIDENT_CAP):
    d = json.loads(raw)
    pts, skipped = [], 0
    for f in d.get("features") or []:
        geom = f.get("geometry") or {}
        coords = geom.get("coordinates") or []
        if geom.get("type") != "Point" or len(coords) < 2:
            skipped += 1
            continue
        props = f.get("properties") or {}
        pts.append({"la": round(coords[1], 4), "lo": round(coords[0], 4),
                    "lb": (props.get("name") or "")[:80],
                    "ex": "NEWS-GEOCODED · machine-geocoded news location, "
                          "not a verified event",
                    "n": props.get("count") or 0})
    note = f"{skipped} feature(s) without point geometry skipped" \
        if skipped else ""
    return pts[:cap], len(pts), note


# ----------------------------------------------------- flights (adsb.lol)
# Classification (design 3.1): exactly one bucket per aircraft, in this
# order — MILITARY (dbFlags bit 1 or the /v2/mil hex set) -> PRIVATE
# JETS (ICAO type designator on the compiled business-jet list) ->
# COMMERCIAL (operator name on the compiled scheduled-airline list, or
# callsign prefix on the compiled ICAO designator list) -> PRIVATE /
# OTHER (residual). Heuristic by construction; the layer note says so.
BIZJET_TYPES = {
    "ASTR", "B350", "BE40", "BE9L", "C25A", "C25B", "C25C", "C25M",
    "C500", "C501", "C510", "C525", "C526", "C550", "C551", "C560",
    "C56X", "C650", "C680", "C68A", "C700", "C750", "CL30", "CL35",
    "CL60", "E35L", "E50P", "E55P", "E545", "E550", "EA50", "F2TH",
    "F900", "FA50", "FA7X", "FA8X", "GA5C", "GA6C", "GA7C", "GALX",
    "GC5", "GL5T", "GL7T", "GLEX", "GLF2", "GLF3", "GLF4", "GLF5",
    "GLF6", "GV", "H25A", "H25B", "H25C", "HA4T", "HDJT", "LJ31",
    "LJ35", "LJ40", "LJ45", "LJ55", "LJ60", "LJ70", "LJ75", "PC24",
    "PRM1", "SBR1", "SF50", "TBM8", "TBM9",
}
BIZJET_PREFIXES = ("LJ", "C25")
AIRLINE_OPS = {
    "american airlines", "delta air lines", "united airlines",
    "southwest airlines", "jetblue", "alaska airlines", "spirit airlines",
    "frontier airlines", "hawaiian airlines", "air canada", "westjet",
    "lufthansa", "british airways", "air france", "klm", "virgin atlantic",
    "easyjet", "ryanair", "wizz air", "iberia", "vueling", "air europa",
    "tap portugal", "swiss", "austrian airlines", "brussels airlines",
    "sas", "norwegian", "finnair", "aer lingus", "lot polish",
    "turkish airlines", "aeroflot", "emirates", "qatar airways",
    "etihad airways", "saudia", "oman air", "gulf air", "flydubai",
    "air arabia", "royal jordanian", "el al", "egyptair",
    "ethiopian airlines", "kenya airways", "south african airways",
    "royal air maroc", "qantas", "virgin australia", "jetstar",
    "air new zealand", "singapore airlines", "cathay pacific",
    "ana", "all nippon", "japan airlines", "korean air", "asiana",
    "china airlines", "eva air", "china southern", "china eastern",
    "air china", "hainan airlines", "xiamenair", "shenzhen airlines",
    "air india", "indigo", "spicejet", "vistara", "garuda indonesia",
    "lion air", "batik air", "citilink", "sriwijaya air", "super air jet",
    "malaysia airlines", "airasia", "thai airways", "vietnam airlines",
    "philippine airlines", "cebu pacific", "latam", "avianca",
    "aeromexico", "volaris", "copa airlines", "gol linhas",
    "azul linhas", "aerolineas argentinas", "fedex", "federal express",
    "ups airlines", "dhl", "atlas air", "kalitta air", "cargolux",
    "nippon cargo", "asl airlines", "tnt", "amazon", "prime air",
}
AIRLINE_CODES = {
    "AAL", "AAY", "ABX", "ACA", "ACI", "ADR", "AEA", "AEE", "AFR",
    "AHK", "AIC", "AIQ", "AJX", "ALK", "AMX", "ANA", "ANZ", "ARA",
    "ARG", "ASA", "ASH", "ASL", "AUA", "AVA", "AWC", "AXM", "AZA",
    "AZG", "AZU", "BAW", "BBC", "BCS", "BEL", "BER", "BHA", "BOX",
    "BTI", "CAL", "CAO", "CAY", "CCA", "CCD", "CCO", "CES", "CFG",
    "CHH", "CJT", "CKK", "CLU", "CMP", "CPA", "CQH", "CRK", "CSC",
    "CSN", "CSZ", "CTJ", "CUB", "CXA", "DAL", "DLA", "DLH", "DOY",
    "DSV", "EAL", "EDW", "EIN", "EJU", "EKX", "ELY", "ENY", "ETD",
    "ETH", "ETV", "EVA", "EWG", "EZY", "FDX", "FFT", "FGW", "FIN",
    "FJI", "FLG", "FPY", "GAP", "GEC", "GFA", "GIA", "GJS", "GLG",
    "GLO", "GOW", "GTI", "GWI", "HAL", "HDA", "HFY", "HLF", "HVN",
    "IBE", "ICE", "IGO", "IRA", "ITY", "JAL", "JAS", "JBU", "JIA",
    "JJP", "JNA", "JRE", "JSX", "JTA", "JZR", "KAC", "KAL", "KEN",
    "KLM", "KQA", "LAN", "LCO", "LDA", "LDM", "LGL", "LHG", "LOT",
    "LPE", "LRC", "LTM", "LVL", "MAA", "MAS", "MAU", "MBU", "MEA",
    "MGL", "MLD", "MNB", "MSR", "MXY", "NAC", "NAI", "NAX", "NCA",
    "NDA", "NKS", "NRL", "NSZ", "NWA", "OAL", "OMA", "OMS", "PAL",
    "PBD", "PCA", "PDT", "PGT", "PIA", "PLM", "POE", "PRD", "PSC",
    "PVG", "QFA", "QTR", "RAM", "RBA", "RCH", "RJZ", "ROT", "ROU",
    "RPA", "RPH", "RSY", "RYR", "SAA", "SAS", "SAW", "SBI", "SCX",
    "SDM", "SEH", "SEJ", "SFW", "SIA", "SJX", "SKW", "SLM", "SMX",
    "SOO", "SPR", "SQC", "SRN", "SVA", "SVR", "SWA", "SWR", "SXD",
    "TAM", "TAP", "TAR", "TAX", "TCX", "THA", "THY", "TIV", "TNT",
    "TRA", "TRS", "TSC", "TUI", "TWB", "UAE", "UAL", "UPS", "USA",
    "UTA", "VFN", "VIR", "VJC", "VOE", "VOZ", "VTI", "VUL", "VVC",
    "VXP", "WAL", "WAN", "WIF", "WJA", "WOA", "WON", "WOW", "WSN",
    "WUK", "WZZ", "XAX", "YZR",
}


def classify_adsb(rec, mil_hexes):
    """One adsb.lol record -> exactly one bucket id (design 3.1)."""
    dbf = rec.get("dbFlags") or 0
    if (dbf & 1) or (rec.get("hex") in mil_hexes):
        return "flights_military"
    t = (rec.get("t") or "").upper()
    if t in BIZJET_TYPES or t.startswith(BIZJET_PREFIXES):
        return "flights_jets"
    op = (rec.get("ownOp") or "").strip().lower()
    if op and any(name in op or op in name for name in AIRLINE_OPS):
        return "flights_commercial"
    cs = (rec.get("flight") or "").strip().upper()
    if len(cs) >= 3 and cs[:3] in AIRLINE_CODES:
        return "flights_commercial"
    return "flights_private"


def parse_adsb_records(records, mil_hexes):
    """adsb.lol records -> classified points (points carry their bucket
    in "cat"; hex duplicates are dropped, first sighting wins)."""
    pts, seen = [], set()
    for rec in records or []:
        hx = rec.get("hex")
        if not hx or hx in seen:
            continue
        la, lo = rec.get("lat"), rec.get("lon")
        if la is None or lo is None:
            continue
        seen.add(hx)
        cat = classify_adsb(rec, mil_hexes)
        lb = (rec.get("flight") or "").strip() \
            or (rec.get("r") or "") or hx
        desc = rec.get("desc") or rec.get("t") or ""
        op = rec.get("ownOp") or ""
        alt = rec.get("alt_baro")
        alt_s = f"{int(alt)} ft" if isinstance(alt, (int, float)) \
            else "ground/unknown"
        ex = " · ".join(x for x in [desc, op, alt_s] if x)
        pts.append({"la": round(float(la), 4), "lo": round(float(lo), 4),
                    "lb": lb, "ex": ex, "cat": cat, "hex": hx})
    return pts


def parse_openmeteo(raw):
    """Open-Meteo multi-location response -> wind sample points.
    Positions are the model-grid coordinates the API itself returns."""
    d = json.loads(raw)
    rows = d if isinstance(d, list) else [d]
    pts = []
    for row in rows:
        cur = (row or {}).get("current") or {}
        spd, direc = cur.get("wind_speed_10m"), cur.get("wind_direction_10m")
        la, lo = row.get("latitude"), row.get("longitude")
        if spd is None or direc is None or la is None or lo is None:
            continue
        pts.append({"la": round(float(la), 3), "lo": round(float(lo), 3),
                    "lb": f"{float(spd):.1f} m/s",
                    "ex": f"wind from {int(direc)} deg at 10 m",
                    "spd": float(spd), "dir": float(direc)})
    return pts, len(pts), ""


def parse_firms_csv(raw):
    """FIRMS area CSV (VIIRS/MODIS NRT) -> hotspot points."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) \
        else raw
    pts = []
    for row in csv.DictReader(io.StringIO(text)):
        try:
            la = float(row["latitude"])
            lo = float(row["longitude"])
        except (TypeError, ValueError, KeyError):
            continue
        bright = row.get("bright_ti4") or row.get("brightness") or ""
        pts.append({
            "la": round(la, 4), "lo": round(lo, 4),
            "lb": "VIIRS/MODIS hotspot",
            "ex": (f"brightness {bright} K · "
                   f"{row.get('acq_date', '')} "
                   f"{row.get('acq_time', '')} · "
                   f"{row.get('satellite', '')} · "
                   f"confidence {row.get('confidence', '')}")})
    return pts, len(pts), ""


def parse_feodo(raw):
    """Feodo Tracker ipblocklist JSON -> IOC list items (no coords in
    the source, so this stays a list — design 3.6)."""
    d = json.loads(raw)
    items = []
    for row in d if isinstance(d, list) else []:
        ip = row.get("ip_address") or ""
        if not ip:
            continue
        items.append({
            "lb": f"{ip}:{row.get('port', '?')}",
            "ex": (f"Feodo Tracker · {row.get('malware') or 'C2'} · "
                   f"status {row.get('status') or '?'} · first seen "
                   f"{row.get('first_seen') or '?'} · last online "
                   f"{row.get('last_online') or '?'}")})
    return items, len(items), ""


def parse_urlhaus(raw):
    """URLhaus recent-URLs API JSON -> IOC list items; URLs are shown
    truncated in list labels (full value stays server-side)."""
    d = json.loads(raw)
    urls = d.get("urls") or []
    items = []
    for row in urls:
        u = row.get("url") or ""
        if not u:
            continue
        items.append({
            "lb": u[:77] + "…" if len(u) > 78 else u,
            "ex": (f"URLhaus · {row.get('threat') or 'malware'} · "
                   f"{row.get('url_status') or '?'} · first seen "
                   f"{row.get('date_added') or '?'}")})
    return items, len(items), ""


# ---------------------------------------------------------------- fetchers
# Family fetchers return {sublayer_id: entry} where entry carries
# points|items|lines, total, drawn, note, ok and optionally a pinned
# state / date / src override. They raise on transport failure; the
# cache core converts that to STALE (last good kept) or OFFLINE.

class _KeyMissing(Exception):
    """A key-gated family was refreshed without its key configured."""


def _entry(points=None, items=None, lines=None, total=0, note="",
           state=None, date=None, src=None):
    e = {"total": total, "note": note, "ok": True, "error": "",
         "fetched_at": _now()}
    if points is not None:
        e["points"] = points
        e["drawn"] = len(points)
    if items is not None:
        e["items"] = items
        e["drawn"] = len(items)
    if lines is not None:
        e["lines"] = lines
        e["drawn"] = len(lines)
    if state:
        e["state"] = state
    if date:
        e["date"] = date
    if src:
        e["src"] = src
    return e


def _fetch_quakes():
    _st, raw = _fetch("earthquake.usgs.gov",
                      "/earthquakes/feed/v1.0/summary/2.5_day.geojson")
    return parse_usgs(raw)


def _fetch_wind():
    lats = list(range(-60, 76, 15))
    lons = list(range(-180, 180, 15))
    pairs = [(la, lo) for la in lats for lo in lons]
    path = ("/v1/forecast?latitude=" +
            ",".join(str(p[0]) for p in pairs) +
            "&longitude=" + ",".join(str(p[1]) for p in pairs) +
            "&current=wind_speed_10m,wind_direction_10m"
            "&wind_speed_unit=ms")
    _st, raw = _fetch("api.open-meteo.com", path, timeout=45.0)
    pts, total, note = parse_openmeteo(raw)
    note = (note + " " if note else "") + \
        "sampled grid 15° via Open-Meteo (GFS-class models) — " \
        "indicative, not a forecast product"
    return pts, total, note


_FIRES_EONET_NOTE = ("curated wildfire EVENTS (EONET) — not satellite "
                     "hotspot detections; hotspot density requires "
                     "FIRMS (K3)")


def _fetch_firms_points(key):
    """FIRMS area CSV for the whole world, 1 day, VIIRS SNPP NRT.
    Only ever called when ADE's own MAP_KEY is configured."""
    url = ("https://firms.modaps.eosdis.nasa.gov/api/area/csv/" +
           key + "/VIIRS_SNPP_NRT/world/1")
    st, _h, body, cut = _fetch_binary(url, timeout=60.0,
                                      cap=24 * 1024 * 1024)
    if st != 200:
        raise IOError(f"FIRMS HTTP {st}")
    if cut:
        raise IOError("FIRMS CSV exceeded 24 MiB cap")
    return parse_firms_csv(body)


# EONET resilience (v1.13.2, diagnosis measured 2026-10-23): the
# events feed is a SINGLE all-or-nothing fetch on the joint-shortest
# timeout in the family set (30 s), so one episodic stall on the
# shared egress path took the whole family down — during the observed
# window even the tiny Kp feed needed ~17 s and two consecutive EONET
# attempts died at the 30 s cap, each recorded verbatim as
# 'OSError: timed out', while multi-call families (flights/sats
# sweeps) tolerate individual stalled calls by construction. The
# daemon itself is threaded and was measured NOT to queue ops
# (EONET op: 1.2 s idle, <=4.5 s during a full concurrent
# flights+sats cycle), so the cure is here, not in the plumbing:
# retry the events fetch on transport errors with escalating
# timeouts and backoff that spans a stall window. The last genuine
# error is re-raised verbatim (error fidelity — _refresh_family
# stamps it on the entry unchanged). Parsing stays outside the
# retry: a garbage body fails fast, exactly as before. The payload
# is small (129 KB, ~1.2-2.4 s when the path is healthy), so the
# larger budgets cost nothing in the normal case. (timeout,
# sleep-before-attempt) per try:
_EONET_FETCH_PLAN = ((45.0, 0.0), (60.0, 5.0), (60.0, 15.0))


def _fetch_eonet_events():
    last = None
    for timeout, backoff in _EONET_FETCH_PLAN:
        if backoff:
            time.sleep(backoff)
        try:
            _st, raw = _fetch("eonet.gsfc.nasa.gov",
                              "/api/v3/events?status=open&days=30",
                              timeout=timeout)
            return raw
        except Exception as e:  # noqa: BLE001 — transport only;
            last = e              # parse errors never reach here
    raise last


def _fetch_eonet_family():
    raw = _fetch_eonet_events()
    parts = partition_eonet(raw)
    out = {}
    for sid, (pts, total, note) in parts.items():
        out[sid] = _entry(points=pts, total=total, note=note)
    key = _feed_keys()["firms"]
    if key:
        try:
            pts, total, _n = _fetch_firms_points(key)
            if total > 20000:
                stride = total / 20000.0
                drawn = [pts[int(i * stride)] for i in range(20000)]
                note = (f"sampled: {total} hotspots -> 20000 drawn "
                        "(stride)")
            else:
                drawn, note = pts, ""
            out["fires"] = _entry(
                points=drawn, total=total, note=note,
                src="NASA FIRMS (VIIRS SNPP NRT hotspots)")
        except Exception as e:  # noqa: BLE001
            base = out["fires"]
            base["note"] = (base["note"] + " · " if base["note"] else "") \
                + f"FIRMS fetch failed ({e}) — showing EONET events. " \
                + _FIRES_EONET_NOTE
    else:
        base = out["fires"]
        base["note"] = (base["note"] + " · " if base["note"] else "") \
            + _FIRES_EONET_NOTE
    return out


# ------------------------------------------------------------- flights
_land_memo = {"pts": None}
_sweep_memo = {"centers": None, "spacing": 0}


def _land_points():
    if _land_memo["pts"] is None:
        with open(LAND_PATH, encoding="utf-8") as f:
            raw = base64.b64decode(f.read())
        ints = struct.unpack(f"<{len(raw) // 2}h", raw)
        _land_memo["pts"] = [(ints[i] / 100.0, ints[i + 1] / 100.0)
                             for i in range(0, len(ints) - 1, 2)]
    return _land_memo["pts"]


def _hav_km(a, b):
    la1, lo1 = math.radians(a[0]), math.radians(a[1])
    la2, lo2 = math.radians(b[0]), math.radians(b[1])
    h = (math.sin((la2 - la1) / 2) ** 2 +
         math.cos(la1) * math.cos(la2) *
         math.sin((lo2 - lo1) / 2) ** 2)
    return 12742 * math.asin(math.sqrt(h))


def sweep_centers():
    """Sweep centers for the adsb.lol point queries (design 3.1):
    derived from the globe's own land substrate, greedily thinned to
    >=700 km spacing over land, lat -55..72; the spacing is widened
    until the grid is <=130 centers. Returns (centers, spacing_km)."""
    if _sweep_memo["centers"] is not None:
        return _sweep_memo["centers"], _sweep_memo["spacing"]
    land = [p for p in _land_points() if -55.0 <= p[0] <= 72.0]
    # measured on the real substrate: exact 700 km thinning keeps 341
    # centers (too many for the ±2-minute sweep), so the 700 km set is
    # thinned again at widening spacings until it fits the <=130
    # budget — the result is a subset of the 700 km set, so mutual
    # distances stay >= the final spacing. The layer note declares
    # the spacing actually used.
    kept = _thin(land, 700)
    spacing = 700
    while len(kept) > 130 and spacing < 2000:
        spacing += 100
        kept = _thin(kept, spacing)
    _sweep_memo.update(centers=kept, spacing=spacing)
    return kept, spacing


def _thin(points, spacing):
    """Greedy exact thinning: keep a point only if it is >= spacing
    km from every already-kept point (latitude-band window via
    bisect, so the check is exact, not a grid approximation)."""
    import bisect
    kept, lats = [], []
    band = spacing / 111.0
    for p in points:
        lo_i = bisect.bisect_left(lats, p[0] - band)
        hi_i = bisect.bisect_right(lats, p[0] + band)
        if all(_hav_km(p, kept[i]) >= spacing
               for i in range(lo_i, hi_i)):
            pos = bisect.bisect_left(lats, p[0])
            lats.insert(pos, p[0])
            kept.insert(pos, p)
    return kept


_adsb_last = [0.0]


def _adsb_get(path, timeout=20.0, cap=8 * 1024 * 1024):
    """One adsb.lol GET, Range-reassembled like _fetch_large, with the
    community API's 1 req/s limit paced across every chunk request."""
    buf = b""
    start = 0
    chunk = netclient.MAX_BODY
    for _ in range(40):
        if len(buf) >= cap:
            break
        wait = 1.02 - (time.time() - _adsb_last[0])
        if wait > 0:
            time.sleep(wait)
        _adsb_last[0] = time.time()
        status, part = _fetch_range("api.adsb.lol", path, start,
                                    start + chunk - 1, timeout)
        if status not in (200, 206):
            if not buf:
                raise IOError(f"HTTP {status}")
            break
        if status == 200 and start > 0:
            break
        buf += part
        try:
            json.loads(buf)
            return buf
        except Exception:
            pass
        if len(part) < chunk:
            break
        start += len(part)
    return buf


def _flights_entries(pts, note, src):
    """Split classified points into the five FLIGHTS sub-layers."""
    out = {}
    buckets = {sid: [] for sid in
               ("flights_commercial", "flights_private", "flights_jets",
                "flights_military")}
    for p in pts:
        buckets[p["cat"]].append(p)
    total = len(pts)
    if total > FLIGHT_FAMILY_CAP:
        stride = total / float(FLIGHT_FAMILY_CAP)
        drawn = [pts[int(i * stride)] for i in range(FLIGHT_FAMILY_CAP)]
        note = (note + " " if note else "") + \
            f"sampled: {total} airborne -> {FLIGHT_FAMILY_CAP} drawn"
    else:
        drawn = pts
    out["flights_all"] = _entry(points=drawn, total=total, note=note,
                                src=src)
    for sid, lst in buckets.items():
        out[sid] = _entry(points=lst, total=len(lst), note=note,
                          src=src)
    return out


def _fetch_flights_family():
    centers, spacing = sweep_centers()
    mil_hexes = set()
    mil_note = ""
    try:
        raw = _adsb_get("/v2/mil", timeout=30.0)
        d = json.loads(raw)
        mil_hexes = {r.get("hex") for r in d.get("ac") or []
                     if r.get("hex")}
    except Exception as e:  # noqa: BLE001
        mil_note = f" /v2/mil unavailable ({e}); dbFlags only"
    records, ok_centers = [], 0
    for la, lo in centers:
        try:
            raw = _adsb_get(f"/v2/point/{la:.2f}/{lo:.2f}/250",
                            timeout=25.0)
            d = json.loads(raw)
            records += d.get("ac") or []
            ok_centers += 1
        except Exception:  # noqa: BLE001
            continue
    if ok_centers == 0:
        # the sweep itself is unreachable -> OpenSky fallback
        return _flights_family_opensky(
            "adsb.lol sweep unreachable "
            f"(centers ok 0/{len(centers)})")
    if not records and not mil_hexes:
        # primary source produced nothing at all -> OpenSky fallback
        return _flights_family_opensky(
            "adsb.lol sweep returned no aircraft "
            f"(centers ok {ok_centers}/{len(centers)})")
    pts = parse_adsb_records(records, mil_hexes)
    note = (f"SWEEP GRID n={len(centers)} centers (≥{spacing} km, "
            f"ok {ok_centers}/{len(centers)}) · community receivers — "
            "oceanic/remote airspace underrepresented · classification "
            "by type/operator databases — heuristic" + mil_note)
    return _flights_entries(pts, note, SUBLAYERS["flights_all"]["src"])


def _flights_family_opensky(reason):
    """Fallback (design 3.1): OpenSky states. That source carries no
    type/operator fields, so PRIVATE JETS and MILITARY are honestly
    NOT EVALUATED and the rest is callsign-heuristic only."""
    _st, raw = _fetch("opensky-network.org", "/api/states/all",
                      timeout=45.0)
    pts, total, _n = parse_opensky(raw, cap=FLIGHT_FAMILY_CAP)
    for p in pts:
        cs = (p["lb"] or "").strip().upper()
        p["cat"] = "flights_commercial" if len(cs) >= 3 \
            and cs[:3] in AIRLINE_CODES else "flights_private"
    note = (f"FALLBACK SOURCE — {reason}; OpenSky carries no "
            "type/operator data: classification is callsign-prefix "
            "heuristic only")
    out = _flights_entries(pts, note, "OpenSky Network (fallback)")
    for sid in ("flights_jets", "flights_military"):
        out[sid] = _entry(
            points=[], total=0,
            note="NOT EVALUATED — fallback source (OpenSky) carries "
                 "no type/operator fields",
            state="noteval", src="OpenSky Network (fallback)")
    return out


# ---------------------------------------------------------- satellites
def _ensure_tle_groups():
    stale = []
    for g in SAT_GROUPS_ALL:
        cur = _tle_groups.get(g)
        if cur is None or _now() - cur["fetched_at"] > SAT_TLE_TTL:
            stale.append(g)
    ok = 0
    for g in stale:
        try:
            raw = _fetch_text_large(
                "celestrak.org",
                f"/NORAD/elements/gp.php?GROUP={g}&FORMAT=tle",
                timeout=45.0)
            text = raw.decode("utf-8", "replace")
            if "1 " not in text:
                raise IOError("no TLE lines in body")
            _tle_groups[g] = {"text": text, "fetched_at": _now()}
            ok += 1
        except Exception:  # noqa: BLE001
            if g not in _tle_groups:
                continue  # group stays absent; union note counts it
    return ok, len(SAT_GROUPS_ALL)


def _fetch_text_large(host, path, timeout=30.0, cap=8 * 1024 * 1024):
    """Range-reassembly for large TEXT payloads (TLE files): like
    _fetch_large but stops on a short read instead of a JSON parse."""
    buf = b""
    start = 0
    chunk = netclient.MAX_BODY
    for _ in range(64):
        if len(buf) >= cap:
            break
        status, part = _fetch_range(host, path, start,
                                    start + chunk - 1, timeout)
        if status not in (200, 206):
            if not buf:
                raise IOError(f"HTTP {status}")
            break
        if status == 200 and start > 0:
            break
        buf += part
        if len(part) < chunk:
            break
        start += len(part)
    return buf


def _build_union():
    """Parse every fetched group into a NORAD-deduped union and build
    the vectorized SatrecArray once per TLE version."""
    version = hashlib.sha1(
        "|".join(f"{g}:{len(_tle_groups[g]['text'])}"
                 for g in sorted(_tle_groups)).encode()).hexdigest()
    if _union["arr"] is not None and _union["version"] == version:
        return
    from sgp4.api import Satrec
    members = {}
    bad = 0
    for g, payload in _tle_groups.items():
        objs, b = parse_tle(payload["text"])
        bad += b
        for name, l1, l2 in objs:
            norad = l1[2:7].strip()
            if not norad:
                continue
            m = members.get(norad)
            if m is None:
                members[norad] = {"name": name, "l1": l1, "l2": l2,
                                  "grps": {g}}
            else:
                m["grps"].add(g)
    ids, sats, meta = [], [], {}
    failed = 0
    for norad, m in members.items():
        try:
            sats.append(Satrec.twoline2rv(m["l1"], m["l2"]))
        except Exception:  # noqa: BLE001
            failed += 1
            continue
        ids.append(norad)
        meta[norad] = m
    from sgp4.api import SatrecArray
    _union.update(version=version, ids=ids,
                  arr=SatrecArray(sats) if sats else None, meta=meta)
    _tle.update(
        text="\n".join(meta[n]["l1"] + "\n" + meta[n]["l2"]
                       for n in ids),
        fetched_at=min((p["fetched_at"] for p in _tle_groups.values()),
                       default=0.0),
        ok=bool(ids), error="", bad_lines=bad)
    _sat_memo.update(points=None, at=0.0, total=0)
    _union["build_failed"] = failed


def _propagate_union(when=None):
    """Vectorized SGP4 propagation of the whole union (design 3.2).
    Returns (points, total, prop_seconds). Failed-propagation objects
    are never drawn."""
    when = when or _now()
    if _sat_memo["points"] is not None \
            and when - _sat_memo["at"] <= _sat_prop["ttl"]:
        return _sat_memo["points"], _sat_memo["total"], _sat_prop["secs"]
    import numpy as np
    from sgp4.api import jday
    import datetime as _dt
    t0 = time.time()
    dt = _dt.datetime.utcfromtimestamp(when)
    jd, fr = jday(dt.year, dt.month, dt.day, dt.hour, dt.minute,
                  dt.second + dt.microsecond / 1e6)
    ids = _union["ids"]
    # One epoch for the whole array: jd/fr as 1-element arrays (the
    # wrapper requires ndarrays; longer time arrays would compute a
    # times x satellites outer product — not what a frame needs).
    e, r, _v = _union["arr"].sgp4(np.array([jd]), np.array([fr]))
    _e, _r = np.asarray(e), np.asarray(r)
    errs = _e[:, 0] if _e.ndim == 2 else _e.reshape(-1)
    r = _r[:, 0, :] if _r.ndim == 3 else _r
    gmst = math.radians(_gmst_deg(jd + fr))
    x, y, z = r[:, 0], r[:, 1], r[:, 2]
    lon = np.degrees(np.arctan2(y, x)) - math.degrees(gmst)
    lon = (lon + 540.0) % 360.0 - 180.0
    lat = np.degrees(np.arctan2(z, np.hypot(x, y)))
    alt = np.sqrt(x * x + y * y + z * z) - 6371.0
    pts = []
    for i, norad in enumerate(ids):
        if errs[i] != 0:
            continue
        m = _union["meta"][norad]
        pts.append({"la": round(float(lat[i]), 3),
                    "lo": round(float(lon[i]), 3),
                    "lb": m["name"] or norad,
                    "ex": f"alt {int(round(float(alt[i])))} km · "
                          "computed (SGP4)",
                    "grps": sorted(m["grps"]), "norad": norad})
    secs = time.time() - t0
    _sat_prop.update(secs=secs, ttl=120 if secs > 20 else 60)
    _sat_memo.update(points=pts, at=when, total=len(pts))
    return pts, len(pts), secs


def _stride_cap(pts, cap):
    if len(pts) <= cap:
        return pts, ""
    stride = len(pts) / float(cap)
    return [pts[int(i * stride)] for i in range(cap)], \
        f"sampled: {len(pts)} -> {cap} drawn (stride)"


def _fetch_sats_family():
    ok_groups, total_groups = _ensure_tle_groups()
    if not _tle_groups:
        raise IOError("CelesTrak: every GP group fetch failed")
    _build_union()
    pts, total, secs = _propagate_union()
    try:
        epoch = time.strftime("%Y-%m-%d",
                              time.gmtime(_tle["fetched_at"]))
    except Exception:
        epoch = "?"
    base_note = (f"CelesTrak GP union: {total} objects propagated "
                 f"(NORAD-deduped) from {len(_tle_groups)}/"
                 f"{total_groups} groups · TLE epoch ~{epoch} · "
                 f"propagation {secs:.1f}s")
    if secs > 20:
        base_note += " · cadence 120 s (cycle over the 20 s budget)"
    if _union.get("build_failed"):
        base_note += f" · {_union['build_failed']} object(s) rejected " \
                     "at TLE parse"
    out = {}
    drawn, samp = _stride_cap(pts, SAT_FAMILY_CAP)
    out["sats_all"] = _entry(
        points=drawn, total=total,
        note=(base_note + (" · " + samp if samp else "")))
    for sid, grps in SAT_SUB_GROUPS.items():
        sub = [p for p in pts if grps & set(p["grps"])]
        d2, s2 = _stride_cap(sub, SAT_FAMILY_CAP)
        note = base_note + (f" · {sid.split('_', 1)[1]} subset: "
                            f"{len(sub)} objects")
        if s2:
            note += " · " + s2
        out[sid] = _entry(points=d2, total=len(sub), note=note)
    return out


# ----------------------------------------------------------------- CCTV
def _fetch_cctv():
    pts, notes = [], []
    try:
        raw = _fetch_large("api.tfl.gov.uk", "/Place/Type/JamCam",
                           timeout=45.0)
        p, _t, _n = parse_tfl(raw)
        pts += p
    except Exception as e:  # noqa: BLE001
        notes.append(f"TfL failed: {e}")
    cal_ok = 0
    for dist in range(1, 13):
        try:
            raw = _fetch_large(
                "cwwp2.dot.ca.gov",
                f"/data/d{dist}/cctv/cctvStatusD{dist:02d}.json",
                timeout=30.0)
            p, _t, _n = parse_caltrans(raw)
            pts += p
            cal_ok += 1
        except Exception as e:  # noqa: BLE001
            notes.append(f"Caltrans D{dist} failed: {e}")
    if not pts:
        raise IOError("all CCTV authorities failed (" +
                      "; ".join(notes[:3]) + ")")
    total = len(pts)
    if total > CCTV_CAP:
        stride = total / float(CCTV_CAP)
        pts = [pts[int(i * stride)] for i in range(CCTV_CAP)]
        notes.append(f"sampled: {total} cameras -> {CCTV_CAP} drawn")
    note = f"{total} cameras · Caltrans districts ok: {cal_ok}/12"
    if notes:
        note += " · " + "; ".join(notes[:3])
    _cam_registry.clear()
    for p in pts:
        if p.get("cid") and (p.get("img") or p.get("clip")):
            _cam_registry[p["cid"]] = {
                "img": p.get("img") or "", "clip": p.get("clip") or "",
                "auth": p.get("auth") or "", "lb": p.get("lb") or ""}
    return pts, total, note


# ----------------------------------------------------------------- GDELT
# History: the v1.12/v1.13 fetcher queried the GDELT GEO API
# (api.gdeltproject.org/api/v2/geo/geo) per theme. The 2026-10-23
# repair matrix (design 3.4) got HTTP 404 for every documented query
# form, so v1.13.0 parked the family — it returned offline entries
# without ever fetching. Re-measured 2026-10-24: the GEO endpoint
# still answers the same generic 236-byte 404 page. parse_gdelt and
# the GEO form stay in the tree unused (locked by old tests).
#
# v1.14.0 feeds the family from GDELT's own 2.0 event EXPORT:
# data.gdeltproject.org answers 200 from this VM (measured
# 2026-10-24). lastupdate.txt names the newest 15-minute export zip;
# the export is a headerless 61-column tab-separated event table.
# Column indices follow the official GDELT 2.0 spec; [28] root code,
# [52] ActionGeo full name, [53] country, [56]/[57] ActionGeo
# lat/long were verified empirically on the live file (1,606 rows,
# 1,542 geocoded, 280 with conflict roots 14-20). Semantics:
#   incidents    — geocoded events whose CAMEO EventRootCode is a
#                  conflict root (14..20). Nothing broader is
#                  claimed; the layer note says exactly that.
#   gdelt_events — every event in the window, ranked by NumMentions.
_GDELT_LASTUPDATE_URL = ("https://data.gdeltproject.org/gdeltv2/"
                         "lastupdate.txt")
_GDELT_EXPORT_CAP = 8 * 1024 * 1024
_GDELT_CONFLICT_ROOTS = frozenset(
    {"14", "15", "16", "17", "18", "19", "20"})
_GDELT_COLS = 61
# export columns used (0-based, GDELT 2.0 spec)
_G_EVENT_CODE = 26
_G_ROOT_CODE = 28
_G_GOLDSTEIN = 30
_G_MENTIONS = 31
_G_TONE = 34
_G_GEO_NAME = 52
_G_GEO_CC = 53
_G_GEO_LAT = 56
_G_GEO_LON = 57
_G_SOURCEURL = 60


def _gdelt_num(raw, cast, default):
    try:
        return cast(float(raw))
    except (TypeError, ValueError):
        return default


def _gdelt_fmt(value):
    return f"{value:g}" if value is not None else "?"


def parse_gdelt_export(text):
    """GDELT 2.0 export CSV text -> list of event dicts. Malformed /
    short rows are skipped, never fatal. lat/lon are None when the
    row carries no usable ActionGeo fix (blank, unparseable,
    out of range, or the 0,0 null island)."""
    events = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        f = line.split("\t")
        if len(f) < _GDELT_COLS:
            continue
        lat = _gdelt_num(f[_G_GEO_LAT], float, None)
        lon = _gdelt_num(f[_G_GEO_LON], float, None)
        if lat is not None and lon is not None:
            if (lat == 0.0 and lon == 0.0) \
                    or not (-90.0 <= lat <= 90.0
                            and -180.0 <= lon <= 180.0):
                lat = lon = None
        events.append({
            "code": f[_G_EVENT_CODE].strip(),
            "root": f[_G_ROOT_CODE].strip(),
            "goldstein": _gdelt_num(f[_G_GOLDSTEIN], float, None),
            "mentions": _gdelt_num(f[_G_MENTIONS], int, 0),
            "tone": _gdelt_num(f[_G_TONE], float, None),
            "name": f[_G_GEO_NAME].strip(),
            "cc": f[_G_GEO_CC].strip(),
            "lat": lat, "lon": lon,
            "url": f[_G_SOURCEURL].strip(),
        })
    return events


def _gdelt_export_url(lastupdate_text):
    """Pick the .export.CSV.zip URL out of lastupdate.txt (lines are
    '<size> <md5> <url>'; the mentions/gkg siblings are ignored).
    The listing uses http:// URLs, but the host 301-redirects them
    to https and _fetch_binary never follows redirects, so the
    scheme is upgraded here for the data host (measured live
    2026-10-24: http -> 301, https -> 200)."""
    for line in (lastupdate_text or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and ".export.CSV.zip" in parts[2]:
            url = parts[2]
            if url.startswith("http://data.gdeltproject.org/"):
                url = "https://" + url[len("http://"):]
            return url
    raise IOError("GDELT lastupdate.txt lists no export file")


def _gdelt_stamp(export_url):
    m = re.search(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})"
                  r"\.export\.CSV\.zip", export_url or "")
    if not m:
        return ""
    return (f"{m.group(1)}-{m.group(2)}-{m.group(3)} "
            f"{m.group(4)}:{m.group(5)} UTC")


def _gdelt_unzip(body):
    try:
        zf = zipfile.ZipFile(io.BytesIO(body))
    except zipfile.BadZipFile as e:
        raise IOError(f"GDELT export is not a zip: {e}")
    names = [n for n in zf.namelist() if n.upper().endswith(".CSV")]
    if not names:
        raise IOError("GDELT export zip carries no CSV member")
    return zf.read(names[0]).decode("utf-8", "replace")


def _fetch_gdelt_family():
    st, _h, body, _c = _fetch_binary(_GDELT_LASTUPDATE_URL,
                                     timeout=45.0, cap=64 * 1024)
    if st != 200:
        raise IOError(f"GDELT lastupdate HTTP {st}")
    url = _gdelt_export_url(body.decode("utf-8", "replace"))
    st, _h, body, cut = _fetch_binary(url, timeout=45.0,
                                      cap=_GDELT_EXPORT_CAP)
    if st != 200:
        raise IOError(f"GDELT export HTTP {st}")
    if cut:
        raise IOError("GDELT export exceeded the fetch cap")
    events = parse_gdelt_export(_gdelt_unzip(body))
    if not events:
        raise IOError("GDELT export parsed to zero events")
    stamp = _gdelt_stamp(url)
    src_note = ("GDELT 2.0 event export"
                + (f" {stamp}" if stamp else "")
                + " — latest 15-minute window")
    # ---- incidents: geocoded CAMEO conflict-root events only
    # (roots 14..20); no broader coverage is claimed.
    inc = [e for e in events
           if e["root"] in _GDELT_CONFLICT_ROOTS
           and e["lat"] is not None]
    inc.sort(key=lambda e: e["mentions"], reverse=True)
    drawn, samp = _stride_cap(inc, INCIDENT_CAP)
    pts = [{"la": round(e["lat"], 4), "lo": round(e["lon"], 4),
            "lb": (e["name"] or e["cc"] or "?")[:80],
            "ex": (f"GDELT event {e['code'] or '?'} · Goldstein "
                   f"{_gdelt_fmt(e['goldstein'])} · "
                   f"{e['mentions']} mention(s)")}
           for e in drawn]
    inc_note = (src_note + " · CAMEO conflict roots 14–20, "
                           "geocoded events only")
    if samp:
        inc_note += " · " + samp
    # ---- gdelt_events: the whole window, ranked by mentions.
    ranked = sorted(events, key=lambda e: e["mentions"], reverse=True)
    items = []
    for e in ranked[:LIST_CAP]:
        host = (urlparse(e["url"]).hostname or "") if e["url"] else ""
        ex = (f"root {e['root'] or '?'} · Goldstein "
              f"{_gdelt_fmt(e['goldstein'])} · {e['mentions']} "
              f"mentions · tone {_gdelt_fmt(e['tone'])}")
        if host:
            ex += f" · {host}"
        items.append({
            "lb": (f"{e['name'] or e['cc'] or '?'} · event "
                   f"{e['code'] or '?'}")[:100],
            "ex": ex})
    return {
        "incidents": _entry(points=pts, total=len(inc),
                            note=inc_note),
        "gdelt_events": _entry(
            items=items, total=len(events),
            note=src_note + " · all events in the window, ranked "
                            "by mentions"),
    }


# -------------------------------------------------------------- abuse.ch
def _fetch_abusech_family():
    """Built at v1.13.0 (K4) but key-gated: without ADE's free
    abuse.ch Auth-Key this raises _KeyMissing and both sub-layers sit
    at NOT EVALUATED. Live-verified 2026-10-23 with ADE's key
    installed: URLhaus recent answers 200 (query_status ok) and the
    Feodo blocklist answers 200 — from the plain download host
    feodotracker.abuse.ch. The feodotracker-api.abuse.ch host drops
    the connection on the downloads path (measured 2026-10-23, even
    with a valid key); v1.13.3 corrects that one host. The URLhaus
    recent endpoint is GET-only: a POST is answered 405
    'http_get_expected' (measured the same night), so v1.13.3 also
    switches that call to a plain GET with the Auth-Key header."""
    key = _feed_keys()["abusech"]
    if not key:
        raise _KeyMissing("abusech")
    hdr = {"Auth-Key": key}
    st, _h, body, _c = _fetch_binary(
        "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        timeout=45.0, cap=4 * 1024 * 1024, headers=hdr)
    if st != 200:
        raise IOError(f"Feodo Tracker HTTP {st}")
    c2_items, c2_total, _n = parse_feodo(body)
    st, _h, body, _c = _fetch_binary(
        "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        timeout=45.0, cap=4 * 1024 * 1024, headers=hdr)
    if st != 200:
        raise IOError(f"URLhaus HTTP {st}")
    url_items, url_total, _n = parse_urlhaus(body)
    return {
        "botnet_c2": _entry(
            items=c2_items[:LIST_CAP], total=c2_total,
            note="LIST — source carries no coordinates"),
        "malware_urls": _entry(
            items=url_items[:LIST_CAP], total=url_total,
            note="LIST — source carries no coordinates"),
    }


_FAMILY_FETCH = {
    # lambdas resolve the module-level fetcher at call time, so tests
    # can patch a single family seam (gf._fetch_<name>_family).
    "flights": lambda: _fetch_flights_family(),
    "sats": lambda: _fetch_sats_family(),
    "eonet": lambda: _fetch_eonet_family(),
    "gdelt": lambda: _fetch_gdelt_family(),
    "abusech": lambda: _fetch_abusech_family(),
    "quakes": lambda: _fetch_quakes_family(),
    "cctv": lambda: _cctv_family(),
    "wind": lambda: _wind_family(),
    "launches": lambda: _fetch_launches_family(),
}


def _fetch_quakes_family():
    pts, total, note = _fetch_quakes()
    return {"quakes": _entry(points=pts, total=total, note=note)}


def _cctv_family():
    pts, total, note = _fetch_cctv()
    return {"cctv": _entry(points=pts, total=total, note=note)}


def _wind_family():
    pts, total, note = _fetch_wind()
    return {"wind": _entry(points=pts, total=total, note=note)}


# ------------------------------------------------------- static / pinned
_static_cache = None
_lines_cache = None


def _static_data():
    global _static_cache
    if _static_cache is None:
        try:
            with open(STATIC_PATH, encoding="utf-8") as f:
                _static_cache = json.load(f)
        except Exception:
            _static_cache = {"ports": [], "chokepoints": [],
                             "country_centroids": {}, "nuclear": []}
    return _static_cache


def _lines_data():
    global _lines_cache
    if _lines_cache is None:
        try:
            with open(LINES_PATH, encoding="utf-8") as f:
                _lines_cache = json.load(f)
        except Exception:
            _lines_cache = {"segments": [], "compiled": "?",
                            "dataset": "MarNet", "license": "EUPL-1.2",
                            "selection": ""}
    return _lines_cache


def country_centroids():
    return _static_data().get("country_centroids") or {}


def _local_entry(sid):
    """Sub-layers served from local data or pinned honest states —
    no network, recomputed on read."""
    data = _static_data()
    if sid == "maritime_static":
        pts = []
        for p in data.get("ports") or []:
            pts.append({"la": p["lat"], "lo": p["lon"], "lb": p["name"],
                        "ex": "STATIC PORT — reference point, "
                              "not a vessel", "kind": "port"})
        for cp in data.get("chokepoints") or []:
            pts.append({"la": cp["lat"], "lo": cp["lon"],
                        "lb": cp["name"],
                        "ex": "STATIC CHOKEPOINT — reference point, "
                              "not a vessel", "kind": "chokepoint"})
        return _entry(points=pts, total=len(pts),
                      note=f"STATIC — dataset "
                           f"{data.get('dataset_date', '?')}",
                      state="static",
                      date=str(data.get("dataset_date", "?")))
    if sid == "maritime_lines":
        doc = _lines_data()
        segs = doc.get("segments") or []
        return _entry(
            lines=segs, total=len(segs),
            note=(f"STATIC — {doc.get('selection', '')} · "
                  f"{doc.get('dataset', 'MarNet')} "
                  f"({doc.get('license', '')})"),
            state="static", date=str(doc.get("compiled", "?")))
    if sid == "nuclear":
        # v1.25.0 (§16.6): OSIRIS-model curated list, 64 facilities,
        # Wikipedia-sourced. Replaces the v1.12.0 WRI 195-site dataset
        # (unit rows, no status/owner/source fields): the design
        # orders the curated 64 with verbatim cards + Wikipedia
        # links (link rendered only where sourceUrl exists — never
        # a guessed Wikipedia slug). Seismic-risk override from
        # OSIRIS is NOT copied: this dataset is static, NOT live.
        meta = data.get("nuclear_meta") or {}
        pts = []
        for p in data.get("nuclear") or []:
            nuc = {"id": p["id"], "name": p["name"], "city": p["city"],
                   "country": p["country"], "status": p["status"],
                   "reactors": p["reactors"], "capacityMW": p["capacityMW"],
                   "owner": p["owner"]}
            if p.get("sourceUrl"):
                nuc["sourceUrl"] = p["sourceUrl"]
            pts.append({"la": p["lat"], "lo": p["lon"], "lb": p["name"],
                        "ex": f"{p['city']}, {p['country']} · {p['status']}",
                        "nuc": nuc})
        return _entry(
            points=pts, total=len(pts),
            note=("STATIC DATASET — 64 facilities, Wikipedia-sourced; "
                  "locations approximate; NOT live status"),
            state="static", date=str(meta.get("compiled", "?")))
    if sid == "transit_live":
        return _entry(
            items=[], total=0,
            note=("NOT EVALUATED — no keyless vehicle-position feed "
                  "exists on the approved hosts (TfL publishes "
                  "arrivals, not vehicle positions); a regional "
                  "GTFS-RT key is a future, separately approved step "
                  "(K6)"),
            state="noteval")
    if sid == "rain":
        return _entry(
            note=("2D ONLY — radar tiles load in the browser from "
                  "RainViewer; the service does not fetch this feed. "
                  "Time controls step the tile set ±2 h + nowcast."),
            state="browser")
    if sid == "clouds":
        return _entry(
            note=("2D ONLY — GMGSI thermal-IR mosaic tiles load in "
                  "the browser from NOAA NowCOAST (WMS); hourly "
                  "frames, ~20 min publish lag; the mosaic band "
                  "is +/-72.7 deg — beyond it there is honestly "
                  "no cover. IR shows cloud day and night."),
            state="browser")
    if sid == "daynight":
        return _entry(
            note="Terminator computed locally from solar position — "
                 "no feed.", state="computed")
    raise KeyError(sid)


_LOCAL = {"maritime_static", "maritime_lines", "nuclear", "transit_live",
          "rain", "clouds", "daynight"}

_KEY_NOTES = {
    "botnet_c2": "NOT EVALUATED — FREE ABUSE.CH KEY REQUIRED (K4)",
    "malware_urls": "NOT EVALUATED — FREE ABUSE.CH KEY REQUIRED (K4)",
}


# ------------------------------------------------------------- cache core
_TFL_STEM = re.compile(r"^\d{5}\.\d{5}$")


def _derive_cid(p):
    """Rebuild, deterministically, the cid the v1.13 parsers assign,
    from fields a legacy (pre-cid) snapshot point already carries.
    Mirrors parse_tfl / parse_caltrans exactly:
      TfL      -> "tfl:JamCams_" + the NNNNN.NNNNN stem of the stored
                  image/clip URL (the JamCam id is that stem prefixed;
                  verified against the recorded fixture and the live
                  proof camera 00002.00865).
      Caltrans -> "cal:" + md5(img or locationName)[:12]; a legacy
                  point's lb IS its locationName.
    Returns None when the stored fields cannot reproduce the cid
    safely — such a point simply has no preview until a fresh fetch
    replaces the snapshot; nothing is guessed."""
    if p.get("cid"):
        return p["cid"]
    auth = p.get("auth") or ""
    if auth == "Caltrans":
        seed = p.get("img") or p.get("lb") or ""
        if seed:
            return "cal:" + hashlib.md5(seed.encode()).hexdigest()[:12]
    elif auth == "TfL":
        for u in (p.get("img") or "", p.get("clip") or ""):
            stem = u.rsplit("/", 1)[-1].rsplit(".", 1)[0] if u else ""
            if stem and _TFL_STEM.match(stem):
                return "tfl:JamCams_" + stem
    return None


def _backfill_cctv(entry):
    """Assign derived cids to legacy CCTV points in place and rebuild
    the camera registry from every cid-carrying point. Returns
    (filled, unresolved)."""
    filled = unresolved = 0
    for p in (entry or {}).get("points") or []:
        if not p.get("cid"):
            cid = _derive_cid(p)
            if cid:
                p["cid"] = cid
                filled += 1
            else:
                unresolved += 1
        if p.get("cid") and (p.get("img") or p.get("clip")):
            _cam_registry[p["cid"]] = {
                "img": p.get("img") or "",
                "clip": p.get("clip") or "",
                "auth": p.get("auth") or "",
                "lb": p.get("lb") or ""}
    return filled, unresolved


def _save_snapshot():
    try:
        data = {k: v for k, v in _cache.items()
                if v.get("ok") and k in _PERSIST}
        # Anti-regression merge (v1.13.0 fix): a process whose
        # in-memory snapshot is OLDER than the file on disk must never
        # overwrite the newer data — several processes share this path
        # (the systemd service, builder live-proof instances, suite
        # copies), and the pre-fix blind dump replaced a fresh
        # v1.13.0 snapshot with a stale v1.12-era one (2026-10-23
        # 19:02). Per key, the entry with the newer fetched_at wins.
        try:
            with open(CACHE_PATH, encoding="utf-8") as f:
                disk = json.load(f)
        except Exception:
            disk = {}
        for k, dv in disk.items():
            if k not in _PERSIST or not isinstance(dv, dict):
                continue
            mv = data.get(k)
            if mv is None or (dv.get("fetched_at") or 0) > \
                    (mv.get("fetched_at") or 0):
                data[k] = dv
        data["__schema__"] = 2
        tmp = CACHE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, CACHE_PATH)
    except Exception:
        pass


def _load_snapshot():
    try:
        with open(CACHE_PATH, encoding="utf-8") as f:
            data = json.load(f)
        for k, v in data.items():
            if k in SUBLAYERS and isinstance(v, dict) and \
                    (v.get("points") or v.get("items")):
                _cache[k] = v
        cctv = _cache.get("cctv")
        if cctv:
            # Legacy snapshots (written before cids existed) are
            # backfilled deterministically so the camera proxy can
            # resolve their points exactly like fresh ones.
            _backfill_cctv(cctv)
    except Exception:
        pass


_load_snapshot()


def _ttl_of(sid):
    spec = SUBLAYERS[sid]
    if spec.get("family") == "sats":
        return _sat_prop["ttl"]
    return spec["ttl"]


def _layer_state(sid, entry):
    if entry is None or not entry.get("ok"):
        return "offline"
    if entry.get("state"):
        return entry["state"]
    ttl = _ttl_of(sid)
    if ttl is None:
        return "static"
    if not entry.get("fetched_at"):
        return "offline"
    age = _now() - entry["fetched_at"]
    return "live" if age <= 1.5 * ttl else "stale"


def _public_meta(sid, entry):
    spec = SUBLAYERS[sid]
    state = _layer_state(sid, entry)
    entry = entry or {}
    return {
        "layer": sid,
        "group": spec["group"],
        "label": spec["label"],
        "kind": spec["kind"],
        "status": state,
        "state": state,
        "src": entry.get("src") or spec["src"],
        "ttl_s": _ttl_of(sid),
        "updated_at": entry.get("fetched_at") or None,
        "date": entry.get("date"),
        "count_total": entry.get("total", 0),
        "count_drawn": entry.get("drawn", 0),
        "note": entry.get("note", ""),
        "error": entry.get("error", "")
        if state not in ("live", "static", "computed", "browser")
        else "",
    }


def _entry_fresh(sid, entry):
    if not entry or not entry.get("ok"):
        return False
    if entry.get("state") in ("noteval", "unreachable"):
        # re-checked every 5 min: a key ADE adds later must take
        # effect without a restart, and the parked producer is free
        # (it performs no network contact).
        checked = entry.get("_checked_at") or entry.get("fetched_at") \
            or 0
        return _now() - checked <= 300
    if entry.get("state"):
        return True  # static/computed/browser states are terminal
    ttl = _ttl_of(sid)
    if ttl is None or not entry.get("fetched_at"):
        return False
    return _now() - entry["fetched_at"] <= ttl


def _background_refresh(fam, lock):
    """Background worker for one family refresh (v1.15.1, flights
    only). Owns `lock` from spawn until the fetch + cache update
    finishes, so the family stays single-flight while the requesting
    thread returns immediately. The disk snapshot is written AFTER
    the lock is released: holding a lock across file I/O (the cache
    file is ~1 MB) would stall every concurrent layer read for the
    whole write, and the snapshot merge already tolerates writers
    from other families. Never raises: an unexpected fetch failure
    is stamped on the family entries (mirroring _refresh_family's
    own failure path) and printed to the service log; a snapshot
    failure only prints. A service restart mid-sweep simply kills
    this daemon thread; the next GET starts a fresh sweep, as
    before."""
    try:
        _refresh_family_data(fam)
    except Exception as e:  # noqa: BLE001 — never kill the service
        for sid in family_members(fam):
            prev = dict(_cache.get(sid) or {})
            prev["error"] = f"{type(e).__name__}: {e}"[:200]
            if not prev.get("ok"):
                prev.update(points=[], items=[], lines=[], total=0,
                            drawn=0,
                            fetched_at=prev.get("fetched_at"),
                            note="", ok=False)
            _cache[sid] = prev
        print(f"[globe] background refresh {fam} failed: {e!r}",
              flush=True)
    finally:
        lock.release()
    try:
        _save_snapshot()
    except Exception as e:  # noqa: BLE001 — snapshot is best-effort
        print(f"[globe] background snapshot {fam} failed: {e!r}",
              flush=True)


def _refresh_family(fam):
    # Synchronous path (every family except flights-via-background):
    # fetch + cache update + disk snapshot, exactly as before
    # v1.15.1. Split so the background worker can release the family
    # lock before the (slow, ~1 MB) snapshot write; see
    # _background_refresh.
    _refresh_family_data(fam)
    _save_snapshot()


def _refresh_family_data(fam):
    # One bounded retry (2 s backoff) for transient transport
    # failures — e.g. the egress proxy's intermittent TLS faults
    # (SSL WRONG_VERSION_NUMBER). A double failure keeps the last good
    # snapshot with the error stamped on it (STALE, never dressed up
    # as fresh); _KeyMissing is never retried.
    produced = None
    last_exc = None
    for attempt in range(2):
        try:
            produced = _FAMILY_FETCH[fam]()
            last_exc = None
            break
        except _KeyMissing:
            for sid in family_members(fam):
                _cache[sid] = {"points": [], "items": [], "total": 0,
                               "drawn": 0, "fetched_at": None,
                               "_checked_at": _now(),
                               "note": _KEY_NOTES.get(
                                   sid, "NOT EVALUATED — KEY NOT "
                                        "CONFIGURED"),
                               "ok": True, "state": "noteval",
                               "error": ""}
            return
        except Exception as e:  # noqa: BLE001
            last_exc = e
            if attempt == 0:
                time.sleep(2)
    if last_exc is not None:
        for sid in family_members(fam):
            prev = dict(_cache.get(sid) or {})
            prev["error"] = f"{type(last_exc).__name__}: {last_exc}"[:200]
            if not prev.get("ok"):
                prev.update(points=[], items=[], lines=[], total=0,
                            drawn=0,
                            fetched_at=prev.get("fetched_at"),
                            note="", ok=False)
            _cache[sid] = prev
        return
    for sid, entry in (produced or {}).items():
        _cache[sid] = dict(entry)


def get_layer(name):
    """Demand-driven, single-flight sub-layer read. Fetches (per
    family) when the cache is past TTL; on failure keeps the last good
    snapshot (STALE) or reports OFFLINE with zero points. v1.15.1:
    the flights family refreshes in a background thread holding the
    family lock, so a layer read never blocks on a sweep (~2-4 min,
    past the artifact worker's 120 s cap); every other family still
    refreshes synchronously in the requesting thread, as before."""
    name = LEGACY_ALIASES.get(name, name)
    if name == "events":
        return _events_union()
    if name not in SUBLAYERS:
        return {"error": f"unknown layer {name!r}"}
    if name in _LOCAL:
        entry = _local_entry(name)
        _cache[name] = entry
        return _payload(name, entry)
    if name == "wind_particles":
        # Computed from the daemon-decoded GFS grid state, not a
        # feed family: no fetch is triggered here (the client
        # drives /api/osint/globe/windgrid on toggle/step).
        entry = _wind_particles_entry()
        _cache[name] = entry
        return _payload(name, entry)
    entry = _cache.get(name)
    if not _entry_fresh(name, entry):
        fam = _family_of(name)
        lock = _family_lock(fam)
        if lock.acquire(blocking=False):
            try:
                if not _entry_fresh(name, _cache.get(name)):
                    if fam == "flights":
                        # Ownership of `lock` passes to the worker:
                        # it releases the lock when the sweep lands,
                        # and this thread returns the last snapshot
                        # immediately (STALE or OFFLINE, as today).
                        threading.Thread(
                            target=_background_refresh,
                            args=(fam, lock), daemon=True,
                            name=f"globe-bg-{fam}").start()
                        lock = None
                    else:
                        _refresh_family(fam)
            finally:
                if lock is not None:
                    lock.release()
        entry = _cache.get(name)
    if name == "cctv" and entry and entry.get("points"):
        # Serve-time safety net: any cctv entry, whatever its origin,
        # leaves with cids backfilled and the registry populated.
        if not _cam_registry or \
                any(not p.get("cid") for p in entry["points"]):
            _backfill_cctv(entry)
    return _payload(name, entry)


def _payload(sid, entry):
    out = _public_meta(sid, entry)
    entry = entry or {}
    kind = SUBLAYERS[sid]["kind"]
    if kind == "points":
        out["points"] = entry.get("points") or []
    elif kind == "list":
        out["items"] = entry.get("items") or []
    elif kind == "lines":
        out["lines"] = entry.get("lines") or []
    else:
        out["points"] = []
    return out


def _events_union():
    """Legacy v1.12 'events' read: the union of the EONET partitions."""
    for sid in ("fires", "severe", "events_other"):
        get_layer(sid)
    pts, total = [], 0
    state = "live"
    for sid in ("fires", "severe", "events_other"):
        e = _cache.get(sid) or {}
        pts += e.get("points") or []
        total += e.get("total", 0)
        if _layer_state(sid, e) not in ("live",):
            state = _layer_state(sid, e)
    base = _public_meta("events_other", _cache.get("events_other"))
    base.update({"layer": "events", "label": "EVENTS (ALL)",
                 "status": state, "state": state,
                 "count_total": total, "count_drawn": len(pts),
                 "points": pts})
    return base


def _maritime_layer():
    """v1.12 compat shim (old consumers/tests)."""
    out = get_layer("maritime_static")
    out["layer"] = "maritime"
    return out


# ------------------------------------------------------------------- Kp
def _kp_unavailable():
    """Current Kp view when no fresh value exists: ok False, value
    None — never a stale number presented as current. time_tag /
    fetched_at still describe the last successful fetch, for
    diagnostics only; the HUD gates display on ok."""
    return {"value": None, "time_tag": _kp["time_tag"],
            "fetched_at": _kp["fetched_at"], "ok": False,
            "error": _kp["error"]}


def _kp_refresh_worker(done):
    """Background SWPC fetch for get_kp(). Never raises; always
    signals done and clears the in-flight flag. Success refreshes
    the 900 s cache; failure marks Kp unavailable (value cleared,
    ok False) and starts the 300 s negative TTL so status() is not
    retried on every call."""
    global _kp_refresh_in_flight, _kp_last_failed_at
    try:
        lock = _family_lock("kp")
        with lock:
            try:
                _st, raw = _fetch("services.swpc.noaa.gov",
                                  "/products/noaa-planetary-k-index.json")
                value, tag = parse_swpc_kp(raw)
                _kp.update(value=value, time_tag=tag, fetched_at=_now(),
                           ok=True, error="")
            except Exception as e:  # noqa: BLE001
                _kp.update(value=None, ok=False,
                           error=f"{type(e).__name__}: {e}"[:200])
                with _kp_refresh_lock:
                    _kp_last_failed_at = _now()
    finally:
        done.set()
        with _kp_refresh_lock:
            _kp_refresh_in_flight = False


def get_kp():
    """Solar Kp for the HUD (NOAA SWPC, TTL 900 s). Non-blocking: a
    due refresh runs in a daemon thread and the triggering call waits
    at most _KP_SYNC_GRACE_S for it, so an already-fast answer still
    lands synchronously while a hung fetch costs ~grace, not the
    30 s _fetch timeout (up to ~90 s via the daemon helper path).
    Calls while a refresh is in flight, and calls within
    _KP_FAIL_TTL_S after a failure, return immediately. On failure
    the HUD shows 'Kp —' — never a stale number presented as
    current."""
    global _kp_refresh_in_flight
    now = _now()
    if _kp["ok"] and now - _kp["fetched_at"] < _KP_SUCCESS_TTL_S:
        return dict(_kp)
    with _kp_refresh_lock:
        if _kp_refresh_in_flight or (
                _kp_last_failed_at
                and now - _kp_last_failed_at < _KP_FAIL_TTL_S):
            return _kp_unavailable()
        _kp_refresh_in_flight = True
        done = threading.Event()
    t = threading.Thread(target=_kp_refresh_worker, args=(done,),
                         name="globe-kp-refresh", daemon=True)
    try:
        t.start()
    except RuntimeError:
        # Never leave the in-flight flag stuck: a thread that could
        # not start must not block every later status() call.
        with _kp_refresh_lock:
            _kp_refresh_in_flight = False
        return _kp_unavailable()
    done.wait(_KP_SYNC_GRACE_S)
    if _kp["ok"] and _now() - _kp["fetched_at"] < _KP_SUCCESS_TTL_S:
        return dict(_kp)
    return _kp_unavailable()


# ---------------------------------------------------------------- status
def status():
    """Hierarchical manifest: groups -> sublayers (design 2), plus a
    flat layers dict (sub-layer ids + v1.12 legacy aliases). Reading
    the status never triggers a feed fetch, except Kp (own TTL)."""
    for sid in _LOCAL:
        if sid not in _cache:
            _cache[sid] = _local_entry(sid)
    groups = []
    flat = {}
    any_ok = False
    all_live = True
    for gid, glabel in GROUPS:
        subs = []
        for sid, spec in SUBLAYERS.items():
            if spec["group"] != gid:
                continue
            meta = _public_meta(sid, _cache.get(sid))
            subs.append(meta)
            flat[sid] = meta
            st = meta["state"]
            if st in ("live", "stale", "static", "computed"):
                any_ok = True
            if st not in ("live", "static", "computed"):
                all_live = False
        groups.append({"id": gid, "label": glabel, "sublayers": subs})
    for alias, target in LEGACY_ALIASES.items():
        if target in flat:
            m = dict(flat[target])
            m["layer"] = alias
            m["alias_of"] = target
            flat[alias] = m
    # legacy "events" meta = the EONET partitions summed (meta only —
    # status() never triggers a fetch to build it)
    ev_total = sum(flat[s]["count_total"]
                   for s in ("fires", "severe", "events_other"))
    ev_drawn = sum(flat[s]["count_drawn"]
                   for s in ("fires", "severe", "events_other"))
    ev = dict(flat["events_other"])
    ev.update({"layer": "events", "label": "EVENTS (ALL)",
               "count_total": ev_total, "count_drawn": ev_drawn})
    flat["events"] = ev
    kp = get_kp()
    aggregate = "OFFLINE"
    if any_ok:
        aggregate = "LIVE" if all_live and kp["ok"] else "PARTIAL"
    return {
        "aggregate": aggregate,
        "server_time": _now(),
        "kp": {"value": kp["value"] if kp["ok"] else None,
               "time_tag": kp["time_tag"], "ok": kp["ok"],
               "updated_at": kp["fetched_at"] or None},
        "groups": groups,
        "layers": flat,
        "sources_line": "ADSB.LOL · OPENSKY · USGS · CELESTRAK · "
                        "NOAA SWPC · NASA EONET · TFL · CALTRANS · "
                        "GDELT · OPEN-METEO · RAINVIEWER (BROWSER) · "
                        "WRI · EUROSTAT — PUBLIC FEEDS, "
                        "ATTRIBUTION APPLIES",
    }


# --------------------------------------------------------- CCTV preview
# Design section 1 (K1): the ONLY path from a browser to camera media.
# cid resolves exclusively against this module's own CCTV index; the
# upstream URL is never client-supplied (anti-SSRF by construction).
CAM_IMG_CAP = 1 * 1024 * 1024
CAM_CLIP_CAP = 6 * 1024 * 1024
CAM_TTL = 60
CAM_BRAKE_PER_MIN = 30


def _cam_lock(key):
    with _lock:
        return _cam_locks.setdefault(key, threading.Lock())


def _cam_err(status_, reason):
    return {"ok": False, "status": status_, "reason": reason}


def _cam_serve(hit, range_header):
    body = hit["body"]
    total = len(body)
    if range_header:
        m = None
        try:
            unit, rng = range_header.split("=", 1)
            if unit.strip() == "bytes":
                a, _, b = rng.partition("-")
                if a == "":
                    n = int(b)
                    start, end = max(0, total - n), total - 1
                else:
                    start = int(a)
                    end = int(b) if b else total - 1
                m = (start, min(end, total - 1))
        except Exception:  # noqa: BLE001
            m = None
        if m is not None:
            start, end = m
            if start >= total:
                return {"ok": True, "status": 416,
                        "content_type": hit["ctype"], "body": b"",
                        "headers": {"Content-Range":
                                    f"bytes */{total}"}}
            part = body[start:end + 1]
            return {"ok": True, "status": 206,
                    "content_type": hit["ctype"], "body": part,
                    "headers": {
                        "Content-Range":
                            f"bytes {start}-{end}/{total}",
                        "Accept-Ranges": "bytes"}}
    return {"ok": True, "status": 200, "content_type": hit["ctype"],
            "body": body, "headers": {"Accept-Ranges": "bytes"}}


def get_cam_preview(cid, kind, range_header=None):
    """Fetch (or serve from the 60 s cache) one camera still/clip.
    Returns a serve dict {ok, status, content_type, body, headers} or
    an error dict {ok: False, status, reason} — reasons are the exact
    strings the card prints after 'PREVIEW UNAVAILABLE — '."""
    if kind not in ("img", "clip"):
        return _cam_err(400, "BAD PREVIEW KIND")
    cam = _cam_registry.get(cid)
    if cam is None:
        get_layer("cctv")  # builds the registry (TTL/single-flight)
        cam = _cam_registry.get(cid)
    if cam is None:
        return _cam_err(404, "UNKNOWN CAMERA ID")
    url = cam.get("img") if kind == "img" else cam.get("clip")
    if not url:
        return _cam_err(404, "NO " + kind.upper() + " FOR THIS CAMERA")
    key = (cid, kind)
    hit = _cam_cache.get(key)
    if hit and _now() - hit["at"] <= CAM_TTL:
        out = _cam_serve(hit, range_header)
        out["auth"] = hit["auth"]
        out["fetched_at"] = hit["fetched"]
        return out
    with _cam_lock(cid + ":" + kind):
        hit = _cam_cache.get(key)
        if hit and _now() - hit["at"] <= CAM_TTL:
            out = _cam_serve(hit, range_header)
            out["auth"] = hit["auth"]
            out["fetched_at"] = hit["fetched"]
            return out
        now = _now()
        while _cam_brake and now - _cam_brake[0] > 60:
            _cam_brake.pop(0)
        if len(_cam_brake) >= CAM_BRAKE_PER_MIN:
            return _cam_err(429, "RATE LIMIT — TOO MANY PREVIEW "
                                 "FETCHES")
        _cam_brake.append(now)
        cap = CAM_IMG_CAP if kind == "img" else CAM_CLIP_CAP
        try:
            st, hdrs, body, cut = _fetch_binary(url, timeout=10.0,
                                                cap=cap)
        except Exception as e:  # noqa: BLE001
            return _cam_err(502, f"UPSTREAM UNREACHABLE — "
                                 f"{type(e).__name__}")
        if 300 <= st < 400:
            return _cam_err(502, "UPSTREAM REDIRECT")
        if st != 200:
            return _cam_err(502, f"UPSTREAM HTTP {st}")
        ctype = (hdrs.get("content-type") or "") \
            .split(";")[0].strip().lower()
        if kind == "img" and not ctype.startswith("image/"):
            return _cam_err(502, "UPSTREAM CONTENT IS NOT AN IMAGE")
        if kind == "clip" and ctype != "video/mp4":
            return _cam_err(502, "UPSTREAM CONTENT IS NOT VIDEO/MP4")
        if cut:
            return _cam_err(502, "MEDIA TOO LARGE")
        hit = {"at": _now(), "ctype": ctype, "body": body,
               "auth": cam.get("auth") or "", "fetched": _now()}
        _cam_cache[key] = hit
        out = _cam_serve(hit, range_header)
        out["auth"] = hit["auth"]
        out["fetched_at"] = hit["fetched"]
        return out


# --------------------------------------------------------------- entities
def entities_from_result(result, centroids=None):
    """Investigation ENTITIES layer (design §7 of the v1.12 design).

    Only nodes with a real coordinate path are placed: IP nodes whose
    RDAP record (already collected by the engine) carries a country are
    placed at that country's centroid with a mandatory precision label;
    domain nodes are placed through their RESOLVES_TO edge to a placed
    IP. Everything else is honestly NOT placed. Returns
    (points, located, total_nodes).
    """
    centroids = centroids if centroids is not None else country_centroids()
    result = result or {}
    meta = result.get("meta") or {}
    graph = meta.get("graph") or {}
    nodes = graph.get("nodes") or []
    total = len(nodes)
    sections = meta.get("sections") or {}
    rdap = ((sections.get("infra") or {}).get("rdap")) or []
    ip_country = {}
    for rec in rdap:
        if isinstance(rec, dict) and rec.get("ip"):
            cc = str(rec.get("country") or "").strip().upper()
            if cc:
                ip_country[str(rec["ip"])] = cc
    by_id = {n.get("id"): n for n in nodes if isinstance(n, dict)}
    points, ip_point = [], {}
    for n in nodes:
        if not isinstance(n, dict) or n.get("type") != "ip":
            continue
        ip = str(n.get("label") or n.get("id", "").split(":", 1)[-1])
        cc = ip_country.get(ip) or ""
        if cc in centroids:
            la, lo = centroids[cc]
            p = {"la": la, "lo": lo, "lb": ip,
                 "ex": "IP HOSTING — COUNTRY-LEVEL (RDAP) — "
                       "NOT A SUBJECT LOCATION",
                 "cc": cc, "kind": "entity"}
            points.append(p)
            ip_point[n.get("id")] = p
    for e in graph.get("edges") or []:
        if not isinstance(e, dict):
            continue
        if e.get("relation") == "RESOLVES_TO" and e.get("target") in ip_point:
            src = by_id.get(e.get("source")) or {}
            if src.get("type") == "domain":
                base = ip_point[e["target"]]
                points.append({
                    "la": base["la"], "lo": base["lo"],
                    "lb": src.get("label") or src.get("id"),
                    "ex": "DOMAIN — HOSTED AT COUNTRY-LEVEL (RDAP) — "
                          "NOT A SUBJECT LOCATION",
                    "cc": base["cc"], "kind": "entity"})
    return points, len(points), total


def get_entities(result, scan_id=""):
    points, located, total = entities_from_result(result)
    return {"layer": "entities", "scan_id": scan_id,
            "points": points, "located": located, "total": total,
            "note": "" if total else "NO INVESTIGATION LOADED"}


# ------------------------------------------------- v1.18.0: Search places + Directions (design §4)
# Daemon-side on-demand fetch (design §2.1): the service builds a
# FIXED upstream template and only validated parameters vary — never
# a free-form user URL (anti-SSRF by construction, same rule as the
# CCTV proxy). Throttle 1 req/s per host (OSMF + OSRM demo policies);
# cache 24 h (per query / per profile + waypoints rounded to 1e-5).
# Only two hosts are ever contacted here: nominatim.openstreetmap.org
# and router.project-osrm.org. Raw coordinate input is handled by the
# UI locally and never sent here.

_NOMINATIM_HOST = "nominatim.openstreetmap.org"
_OSRM_HOST = "router.project-osrm.org"
_SR_TTL = 86400.0
_SR_MAX_WAYPOINTS = 10
_sr_lock = threading.Lock()
_sr_throttle = {}   # host -> last request epoch
_sr_search = {}     # query -> {"at": float, "result": dict}
_sr_route = {}      # cache key -> {"at": float, "result": dict}


def _sr_throttle_wait(host):
    """Enforce at most 1 request/second to a host. The lock is held
    across the sleep so concurrent callers serialize instead of
    bursting together after the same wait."""
    with _sr_lock:
        now = time.time()
        wait = 1.0 - (now - _sr_throttle.get(host, 0.0))
        if wait > 0:
            time.sleep(wait)
        _sr_throttle[host] = time.time()


def _sr_cached(cache, key):
    with _sr_lock:
        hit = cache.get(key)
        if hit and (_now() - hit["at"]) < _SR_TTL:
            return dict(hit["result"], cached=True)
    return None


def search_places(query):
    """Nominatim place search (design §4 item 3, submit-based — no
    autocomplete, per OSMF policy). Returns {"ok", "query",
    "results": [{display_name, lat, lon}], "cached"} with at most 5
    results, display_name verbatim, or {"ok": False, "reason"}.
    Queries shorter than 3 characters never touch the network."""
    q = (query or "").strip()
    if len(q) < 3:
        return {"ok": False, "reason": "query too short (min 3 characters)"}
    if len(q) > 500:
        return {"ok": False, "reason": "query too long (max 500 characters)"}
    hit = _sr_cached(_sr_search, q)
    if hit is not None:
        return hit
    path = ("/search?format=jsonv2&limit=5&addressdetails=0&q="
            + quote(q))
    try:
        _sr_throttle_wait(_NOMINATIM_HOST)
        status, raw = _fetch(_NOMINATIM_HOST, path, timeout=30.0)
    except Exception as e:  # noqa: BLE001 — surfaced honestly
        return {"ok": False, "reason": "geocoder offline (%s)"
                % (e.__class__.__name__,)}
    if status != 200:
        return {"ok": False, "reason": "geocoder offline (HTTP %d)" % status}
    try:
        rows = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {"ok": False, "reason": "geocoder returned an unreadable reply"}
    results = []
    if isinstance(rows, list):
        for r in rows[:5]:
            try:
                la = float(r["lat"])
                lo = float(r["lon"])
            except Exception:
                continue
            if not (-90.0 <= la <= 90.0 and -180.0 <= lo <= 180.0):
                continue
            results.append({"display_name": str(r.get("display_name") or ""),
                            "lat": la, "lon": lo})
    res = {"ok": True, "query": q, "results": results, "cached": False}
    with _sr_lock:
        _sr_search[q] = {"at": _now(), "result": res}
    return res


_OSRM_PROFILES = {"driving": "DRIVE", "cycling": "BIKE", "foot": "WALK"}


def get_route(profile, waypoints):
    """OSRM demo directions (design §4 item 5). waypoints: iterable of
    (lat, lon) numbers, 2..10 points. Returns {"ok", "profile",
    "distance_m", "duration_s", "geometry": GeoJSON LineString,
    "waypoints": [[lat, lon], ...], "cached"} or {"ok": False,
    "reason"}. A straight line is NEVER returned as a route: NoRoute,
    offline, and timeout all surface as honest errors, and the UI
    marks any previous line STALE instead of drawing a fake one."""
    prof = (profile or "").strip()
    if prof not in _OSRM_PROFILES:
        return {"ok": False, "reason": "unknown route profile"}
    try:
        wps = [(round(float(la), 5), round(float(lo), 5))
               for la, lo in waypoints]
    except Exception:
        return {"ok": False, "reason": "waypoints must be [lat, lon] numbers"}
    if len(wps) < 2:
        return {"ok": False, "reason": "route needs at least start and destination"}
    if len(wps) > _SR_MAX_WAYPOINTS:
        return {"ok": False, "reason": "too many waypoints (max 10)"}
    for la, lo in wps:
        if not (-90.0 <= la <= 90.0 and -180.0 <= lo <= 180.0):
            return {"ok": False, "reason": "waypoint out of range"}
    key = prof + "|" + ";".join("%r,%r" % (lo, la) for la, lo in wps)
    hit = _sr_cached(_sr_route, key)
    if hit is not None:
        return hit
    coords = ";".join("%r,%r" % (lo, la) for la, lo in wps)
    path = ("/route/v1/%s/%s?overview=full&geometries=geojson"
            % (prof, coords))
    try:
        _sr_throttle_wait(_OSRM_HOST)
        status, raw = _fetch(_OSRM_HOST, path, timeout=30.0)
    except Exception as e:  # noqa: BLE001 — surfaced honestly
        return {"ok": False, "reason": "route service offline (%s)"
                % (e.__class__.__name__,)}
    if status != 200:
        return {"ok": False, "reason": "route service offline (HTTP %d)" % status}
    try:
        doc = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {"ok": False, "reason": "route service returned an unreadable reply"}
    if not isinstance(doc, dict) or doc.get("code") != "Ok":
        return {"ok": False, "reason": "no route"}
    routes = doc.get("routes") or []
    if not routes:
        return {"ok": False, "reason": "no route"}
    r0 = routes[0]
    geom = r0.get("geometry") or {}
    if geom.get("type") != "LineString" or not geom.get("coordinates"):
        return {"ok": False, "reason": "no route"}
    res = {"ok": True, "profile": prof,
           "distance_m": r0.get("distance"),
           "duration_s": r0.get("duration"),
           "geometry": {"type": "LineString",
                        "coordinates": geom["coordinates"]},
           "waypoints": [[la, lo] for la, lo in wps],
           "cached": False}
    with _sr_lock:
        _sr_route[key] = {"at": _now(), "result": res}
    return res

# ------------------------------------------------- v1.19.0: GitHub Recon + Launches + NEWS (design §5 + §14.5)
# All three ride the daemon tier (no CSP change): GitHub and RSS via
# _fetch_binary (headers preserved for the GitHub rate limit; gzip +
# 512 KB cap for feeds), LL2 via _fetch like the other families.
# No AI anywhere: headlines are verbatim, descriptors are a static
# factual table, the ROCKET counter is a deterministic window count.

# ------------------------------------------------------------------ LL2
_LL2_HOST = "ll.thespacedevs.com"
_LL2_WINDOW_S = 30 * 86400
_LL2_CAP = 20
_LL2_ATTRIBUTION = "Launch data: The Space Devs — Launch Library 2"


def _ll2_parse_net(value):
    """ISO-8601 net -> epoch ms, or None (never raises, never
    invents a time)."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        txt = value.strip()
        if txt.endswith("Z"):
            txt = txt[:-1] + "+00:00"
        dt = datetime.fromisoformat(txt)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except Exception:
        return None


def parse_ll2_upcoming(raw, now_ms=None):
    """Pure: one LL2 upcoming page -> (records, points, note).
    records: verbatim launch rows whose net falls inside the 30-day
    window ahead, in net order, cap 20. points: the subset with pad
    coordinates (map pins). Launches without a parseable net fall
    outside the window and are excluded; launches without pad coords
    are records-only (detail-only, no invented coords). A launch
    flagged tbddate/tbdtime carries tbd=True and is displayed as
    TBD, never with an invented countdown."""
    now = now_ms if now_ms is not None else int(_now() * 1000)
    try:
        doc = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return [], [], "unreadable LL2 reply"
    results = doc.get("results") if isinstance(doc, dict) else None
    if not isinstance(results, list):
        return [], [], "unreadable LL2 reply"
    pairs = []
    for r in results:
        if not isinstance(r, dict):
            continue
        net_ms = _ll2_parse_net(r.get("net"))
        if net_ms is None or net_ms < now or \
                net_ms > now + _LL2_WINDOW_S * 1000:
            continue
        status = r.get("status") or {}
        provider = r.get("launch_service_provider") or {}
        pad = r.get("pad") or {}
        try:
            pla = float(pad["latitude"]) if pad.get("latitude") is not None else None
            plo = float(pad["longitude"]) if pad.get("longitude") is not None else None
        except (TypeError, ValueError):
            pla = plo = None
        if pla is not None and not (-90.0 <= pla <= 90.0):
            pla = None
        if plo is not None and not (-180.0 <= plo <= 180.0):
            plo = None
        rec = {
            "name": str(r.get("name") or ""),
            "net": str(r.get("net") or ""),
            "net_ms": net_ms,
            "tbd": bool(r.get("tbddate") or r.get("tbdtime")),
            "status": str(status.get("name") or status.get("abbrev") or ""),
            "provider": str(provider.get("name") or ""),
            "pad": str(pad.get("name") or ""),
            "lat": pla, "lon": plo,
        }
        point = None
        if pla is not None and plo is not None:
            ex = " · ".join(p for p in (rec["provider"], rec["pad"],
                                        rec["status"]) if p)
            if rec["tbd"]:
                ex = (ex + " · TBD") if ex else "TBD"
            point = {"la": round(pla, 4), "lo": round(plo, 4),
                     "lb": rec["name"][:80], "ex": ex, "t": net_ms}
        pairs.append((rec, point))
    # Net order first, then the cap: the API page is already
    # net-ascending, but the contract must not depend on it.
    pairs.sort(key=lambda rp: rp[0]["net_ms"])
    pairs = pairs[:_LL2_CAP]
    records = [rec for rec, _pt in pairs]
    points = [pt for _rec, pt in pairs if pt is not None]
    return records, points, ""


def _fetch_launches_family():
    """Launches family fetch (TTL 3600 s via the sub-layer spec, so
    at most ~1 fetch/hour — far inside LL2's 15 req/hour keyless
    limit). limit=20 is exactly sufficient for the counter contract
    (upcoming within 30 days, cap 20, net-ascending): if more than 20
    launches fall in the window, the first 20 are the cap; if fewer,
    the window filter keeps them all. The binary transport (512 KB
    cap) is used because one LL2 page runs ~10 KB per launch and
    netclient's 256 KB wire cap is too tight. Raises on
    transport/HTTP/truncation failure so the family refresh keeps the
    last snapshot STALE, exactly like other families."""
    status, _hdrs, raw, cut = _fetch_binary(
        "https://" + _LL2_HOST
        + "/2.3.0/launches/upcoming/?limit=20&ordering=net",
        timeout=30.0, cap=512 * 1024)
    if status != 200:
        raise IOError(f"LL2 HTTP {status}")
    if cut:
        raise IOError("LL2 reply truncated")
    records, points, note = parse_ll2_upcoming(raw)
    entry = _entry(points=points, total=len(records), note=note)
    entry["records"] = records
    return {"launches": entry}


def get_launches():
    """Thin read over the launches family cache for the ROCKET chip
    (design §5 item 8). Demand-driven: get_layer refreshes when
    stale. Offline = count 0 + honest state; a stale snapshot is
    served with state 'stale', never dressed up as fresh."""
    payload = get_layer("launches")
    entry = _cache.get("launches") or {}
    records = entry.get("records") or []
    state = payload.get("state") or "offline"
    return {"ok": state != "offline",
            "state": state,
            "count": len(records),
            "launches": records,
            "updated_at": entry.get("fetched_at"),
            "error": payload.get("error", ""),
            "attribution": _LL2_ATTRIBUTION}


# ---------------------------------------------------------------- GitHub
_GH_HOST = "api.github.com"
_GH_TTL = 86400.0
_GH_USER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_gh_lock = threading.Lock()
_gh_cache = {}   # login-lower -> {"at": float, "result": dict}
_gh_state = {"throttle": 0.0, "remaining": None, "reset": None}


def _gh_throttle_wait():
    """At most 1 GitHub request/second (burst guard; the binding
    limit is 60/hour, enforced by the cache + rate-limit guard)."""
    with _gh_lock:
        now = time.time()
        wait = 1.0 - (now - _gh_state["throttle"])
        if wait > 0:
            time.sleep(wait)
        _gh_state["throttle"] = time.time()


def _gh_get(path):
    """One GitHub API GET via the daemon tier. Returns (status,
    headers, parsed JSON or None). Transport errors raise. Rate
    limit headers are recorded for the guard in github_recon."""
    _gh_throttle_wait()
    status, hdrs, body, _cut = _fetch_binary(
        "https://" + _GH_HOST + path, timeout=30.0, cap=1024 * 1024,
        headers={"Accept": "application/vnd.github+json"})
    with _gh_lock:
        try:
            if hdrs.get("x-ratelimit-remaining") is not None:
                _gh_state["remaining"] = int(hdrs["x-ratelimit-remaining"])
        except (TypeError, ValueError):
            pass
        try:
            if hdrs.get("x-ratelimit-reset") is not None:
                _gh_state["reset"] = int(hdrs["x-ratelimit-reset"])
        except (TypeError, ValueError):
            pass
    try:
        doc = json.loads(body.decode("utf-8", "replace"))
    except Exception:
        doc = None
    return status, hdrs, doc


def github_recon(username):
    """GitHub Recon (design §5 item 9): public profile + repo list,
    TEXT ONLY — profile photos are never returned or rendered (K9,
    no new img-src).
    Max 2 requests per lookup (profile + one repo page), 24 h cache
    per username, local validation first (invalid input never burns
    quota), search endpoint never used, no scraping. An exhausted
    rate limit serves stale cache labeled STALE, or an honest reset
    time when no cache exists."""
    login = (username or "").strip()
    if not _GH_USER_RE.match(login):
        return {"ok": False, "reason": "invalid username"}
    key = login.lower()
    with _gh_lock:
        hit = _gh_cache.get(key)
    if hit and (_now() - hit["at"]) < _GH_TTL:
        return dict(hit["result"], cached=True, stale=False)
    cached = hit["result"] if hit else None
    with _gh_lock:
        rem, rst = _gh_state["remaining"], _gh_state["reset"]
    if rem == 0 and rst and _now() < rst:
        if cached is not None:
            return dict(cached, cached=True, stale=True,
                        rate={"remaining": 0, "reset": rst})
        return {"ok": False, "reason": "rate limit",
                "rate": {"remaining": 0, "reset": rst}, "cached": False}
    try:
        status, _h, prof = _gh_get("/users/" + quote(login))
    except Exception as e:  # noqa: BLE001 — surfaced honestly
        if cached is not None:
            return dict(cached, cached=True, stale=True)
        return {"ok": False,
                "reason": "github offline (%s)" % type(e).__name__}
    if status == 404:
        return {"ok": False, "reason": "user not found"}
    if status in (403, 429):
        with _gh_lock:
            rem, rst = _gh_state["remaining"], _gh_state["reset"]
        if rem == 0:
            if cached is not None:
                return dict(cached, cached=True, stale=True,
                            rate={"remaining": 0, "reset": rst})
            return {"ok": False, "reason": "rate limit",
                    "rate": {"remaining": 0, "reset": rst},
                    "cached": False}
        if cached is not None:
            return dict(cached, cached=True, stale=True)
        return {"ok": False, "reason": "github offline (HTTP %d)" % status}
    if status != 200 or not isinstance(prof, dict):
        if cached is not None:
            return dict(cached, cached=True, stale=True)
        return {"ok": False, "reason": "github offline (HTTP %d)" % status}
    try:
        _st2, _h2, repos = _gh_get("/users/" + quote(login)
                                   + "/repos?per_page=100&sort=updated")
    except Exception:
        repos = []
    repo_rows = []
    if isinstance(repos, list):
        for r in repos[:100]:
            if not isinstance(r, dict):
                continue
            repo_rows.append({
                "name": str(r.get("name") or ""),
                "description": str(r.get("description") or ""),
                "language": str(r.get("language") or ""),
                "stars": r.get("stargazers_count") or 0,
                "forks": r.get("forks_count") or 0,
                "updated_at": str(r.get("updated_at") or ""),
                "url": str(r.get("html_url") or ""),
            })
    with _gh_lock:
        rem, rst = _gh_state["remaining"], _gh_state["reset"]
    res = {"ok": True,
           "profile": {
               "login": str(prof.get("login") or login),
               "name": str(prof.get("name") or ""),
               "bio": str(prof.get("bio") or ""),
               "location": str(prof.get("location") or ""),
               "company": str(prof.get("company") or ""),
               "blog": str(prof.get("blog") or ""),
               "public_repos": prof.get("public_repos") or 0,
               "followers": prof.get("followers") or 0,
               "created_at": str(prof.get("created_at") or ""),
           },
           "repos": repo_rows,
           "rate": {"remaining": rem, "reset": rst},
           "cached": False, "stale": False}
    with _gh_lock:
        _gh_cache[key] = {"at": _now(), "result": res}
    return res


# ------------------------------------------------------------------- NEWS
_NEWS_TTL = 900.0
_NEWS_CAP = 50
_NEWS_TIMEOUT = 15.0
_NEWS_BODY_CAP = 512 * 1024
# Outlet table (design §5 item 11 + §14.5): every path was verified
# live at v1.19.0 build time via the fetch daemon (BBC 200, Al
# Jazeera www 200, DW 200, NPR 200, France 24 www 200). NHK World
# DROPPED at build: both candidate paths 404'd
# (www3.nhk.or.jp/nhkworld/en/news/rss/ and
# .../nhkworld/data/rss/topstories.xml) and no documented NHK World
# RSS feed URL was found — per the design gate, the outlet is
# removed, not left as a dead button. The descriptor column is a
# static factual table (about-page facts, not classification, not
# bias labels) and is rendered in English only.
_NEWS_OUTLETS = [
    {"id": "bbc", "name": "BBC World", "host": "feeds.bbci.co.uk",
     "path": "/news/world/rss.xml",
     "descriptor": "British public broadcaster"},
    {"id": "aljazeera", "name": "Al Jazeera English",
     "host": "www.aljazeera.com", "path": "/xml/rss/all.xml",
     "descriptor": "Qatari state-funded broadcaster"},
    {"id": "dw", "name": "DW", "host": "rss.dw.com",
     "path": "/xml/rss-en-all",
     "descriptor": "German public broadcaster"},
    {"id": "npr", "name": "NPR", "host": "feeds.npr.org",
     "path": "/1001/rss.xml",
     "descriptor": "American public broadcaster"},
    {"id": "france24", "name": "France 24", "host": "www.france24.com",
     "path": "/en/rss",
     "descriptor": "French state-owned broadcaster"},
]
_NEWS_DECLARED_HOSTS = {o["host"] for o in _NEWS_OUTLETS}
# v1.23.0 §16.2 perspective filter: STATIC per-outlet metadata, NOT
# AI. BBC -> western and Al Jazeera -> regional are the OSIRIS
# values; DW / NPR / France 24 -> western is VANTHEX curation from
# their F3-verified descriptors (German / American / French public
# or state broadcasters = Western public/state newsrooms under
# §16.2's bloc semantics). Unknown outlets -> unclassified
# (ALL-only; no empty chips). The filter applies to NEWS rows only.
_NEWS_BLOC = {"bbc": "western", "aljazeera": "regional",
              "dw": "western", "npr": "western", "france24": "western"}
_news_lock = threading.Lock()
_news_state = {}  # id -> {"items", "fetched_at", "attempted_at",
#                  #        "live", "error"}


def _strip_tags(text):
    return re.sub(r"<[^>]*>", "", text or "")


def parse_rss_items(raw, cap=_NEWS_CAP):
    """Pure: RSS 2.0 bytes -> [{title, link, tms}] (tms = epoch ms or
    None). Titles are tag-stripped plain text; items without a valid
    pubDate keep tms None (sorted last by the caller, never given an
    invented time). Raises on unparseable XML."""
    import defusedxml.ElementTree as DET
    root = DET.fromstring(raw)

    def _local(tag):
        return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""

    items = []
    for el in root.iter():
        if _local(el.tag) != "item":
            continue
        title = link = ""
        tms = None
        for ch in el:
            lt = _local(ch.tag)
            # itertext, not .text: a title like <b>Bold</b> headline
            # must survive as "Bold headline", not drop to empty.
            txt = "".join(ch.itertext()).strip()
            if lt == "title":
                title = _strip_tags(txt)
            elif lt == "link":
                link = txt
            elif lt == "pubDate" and txt:
                try:
                    dt = parsedate_to_datetime(txt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    tms = int(dt.timestamp() * 1000)
                except Exception:
                    tms = None
        if title:
            items.append({"title": title, "link": link, "tms": tms})
        if len(items) >= cap:
            break
    return items


def _fetch_news_outlet(outlet):
    """One outlet fetch+parse. Returns (items, error); failures are
    per-outlet and never propagate — a dead outlet hides only
    itself. The 512 KB cap + no-redirect posture match the other
    binary fetches; a truncated body is an honest error, not a
    partial feed."""
    try:
        status, _hdrs, body, cut = _fetch_binary(
            "https://" + outlet["host"] + outlet["path"],
            timeout=_NEWS_TIMEOUT, cap=_NEWS_BODY_CAP)
    except Exception as e:  # noqa: BLE001
        return [], type(e).__name__
    if status != 200:
        return [], "HTTP %d" % status
    if cut:
        return [], "feed too large"
    try:
        items = parse_rss_items(body)
    except Exception as e:  # noqa: BLE001
        return [], "unreadable feed (%s)" % type(e).__name__
    return items, ""


def get_news():
    """NEWS route read (design §5 item 11): refresh stale outlets
    (TTL 900 s, at most one attempt per outlet per TTL even when the
    last attempt failed), serve items ONLY from live outlets, newest
    first, null-time items last, cap 200. All dead -> items [] +
    all_offline True (never 'no news' dressed up as an empty world).
    updated_at is the newest SUCCESSFUL outlet fetch, never a failed
    attempt's timestamp."""
    now = _now()
    with _news_lock:
        stale = [o for o in _NEWS_OUTLETS
                 if now - ((_news_state.get(o["id"]) or {})
                           .get("attempted_at") or 0) > _NEWS_TTL]
    for outlet in stale:
        items, err = _fetch_news_outlet(outlet)
        with _news_lock:
            prev = _news_state.get(outlet["id"]) or {}
            if err:
                _news_state[outlet["id"]] = {
                    "items": [], "fetched_at": prev.get("fetched_at"),
                    "attempted_at": now, "live": False, "error": err}
            else:
                _news_state[outlet["id"]] = {
                    "items": items, "fetched_at": now,
                    "attempted_at": now, "live": True, "error": ""}
    with _news_lock:
        snap = {o["id"]: dict(_news_state.get(o["id"]) or {})
                for o in _NEWS_OUTLETS}
    outlets = []
    merged = []
    updated_at = None
    for o in _NEWS_OUTLETS:
        st = snap[o["id"]]
        live = bool(st.get("live"))
        outlets.append({"id": o["id"], "name": o["name"],
                        "live": live,
                        "updated_at": st.get("fetched_at"),
                        "count": len(st.get("items") or []) if live else 0,
                        "error": "" if live else (st.get("error") or "")})
        if live:
            fa = st.get("fetched_at")
            if fa and (updated_at is None or fa > updated_at):
                updated_at = fa
            for it in st.get("items") or []:
                merged.append({"title": it["title"], "link": it["link"],
                               "tms": it["tms"], "outlet": o["name"],
                               "outlet_id": o["id"],
                               "bloc": _NEWS_BLOC.get(o["id"],
                                                     "unclassified"),
                               "descriptor": o["descriptor"]})
    merged.sort(key=lambda r: (r["tms"] is None, -(r["tms"] or 0)))
    live_n = sum(1 for x in outlets if x["live"])
    return {"ok": True, "outlets": outlets, "items": merged[:200],
            "updated_at": updated_at, "live_count": live_n,
            "total_count": len(_NEWS_OUTLETS),
            "all_offline": live_n == 0}


# ------------------------------------------------- v1.20.0: MARKETS (design §6 + §14.4)
# Daemon-side only (no CSP change). FRED daily series via the public
# fredgraph.csv download (keyless); Coinbase spot (keyless); Stooq
# daily CSV (CONDITIONAL: a CAPTCHA/interstitial body marks Stooq
# BLOCKED and the whole Stooq block — world indices, ticker box,
# DEF/NRG Stooq rows — drops with it; never any circumvention
# attempt). CoinGecko K15 fallback is INACTIVE (no key from ADE) and
# is not wired anywhere in this section. No AI. Breadth stays dropped
# (K25: no keyless advance/decline source; constituent counting is
# fabrication). Dollar is the Fed Broad Index DTWEXBGS, NEVER "DXY".

_MK_FRED_TTL = 21600.0
_MK_CB_TTL = 900.0
_MK_STQ_TTL = 86400.0
_MK_TIMEOUT = 30.0
_MK_CAP = 1024 * 1024

_MK_FRED_SERIES = [
    # (series, display name, category chips, source note)
    ("SP500", "S&P 500", [], "Source: FRED"),
    ("DJIA", "Dow Jones Industrial Average", ["DOW"],
     "Source: S&P Dow Jones Indices via FRED"),
    ("NASDAQCOM", "NASDAQ Composite", [], "Source: FRED"),
    ("VIXCLS", "VIX", [], "Source: FRED"),
    ("DGS10", "US 10Y", [], "Source: FRED"),
    ("DTWEXBGS", "US Dollar \u2014 Fed Broad Index", ["FX"],
     "Source: FRED"),
    ("DCOILWTICO", "WTI Crude Oil", ["NRG", "CMDTY"], "Source: FRED"),
    ("GOLDAMGBD228NLBM", "Gold", ["CMDTY"], "Source: FRED"),
    ("DEXUSEU", "USD/EUR", ["FX"], "Source: FRED"),
    ("DEXJPUS", "JPY/USD", ["FX"], "Source: FRED"),
    # CHF/USD is DEXSZUS on FRED (verified live at build: last obs
    # 2026-10-16, 0.8243). DEXCHUS is Chinese Yuan, NOT Swiss francs,
    # and is therefore NOT listed — the design's FX pair is CHF/USD.
    ("DEXSZUS", "CHF/USD", ["FX"], "Source: FRED"),
]

_MK_CB_PAIRS = [
    # (pair, display name, category chips)
    ("BTC-USD", "Bitcoin", ["CRYPTO"]),
    ("ETH-USD", "Ethereum", ["CRYPTO"]),
]

_MK_STQ_WORLD = [
    # (region, symbol, display name) — symbols verified live at build;
    # an unverified symbol is removed from this list, never shipped.
    ("AMERICAS", "^SPX", "S&P 500"),
    ("AMERICAS", "^NDQ", "Nasdaq 100"),
    ("EMEA", "^UK100", "FTSE 100"),
    ("EMEA", "^DE30", "DAX"),
    ("EMEA", "^EU50", "Euro Stoxx 50"),
    ("ASIA-PACIFIC", "^JP225", "Nikkei 225"),
    ("ASIA-PACIFIC", "^HK45", "Hang Seng"),
]

_MK_STQ_DEF = [
    # VANTHEX-curated defense symbols (K30: the OSIRIS meaning of
    # "DEF" is unverified — suspected defense sector — and is never
    # stated as fact; the quotes themselves are Stooq data).
    ("LMT.US", "Lockheed Martin"),
    ("RTX.US", "RTX"),
    ("NOC.US", "Northrop Grumman"),
]

_MK_STQ_NRG = [
    ("XOM.US", "Exxon Mobil"),
    ("CVX.US", "Chevron"),
]

_MK_TICKER_RE = re.compile(r"^[A-Z0-9.^:-]{1,20}$")

_mk_lock = threading.Lock()
_mk_fred = {}   # series -> {obs, fetched_at, attempted_at, live, error}
_mk_cb = {}     # pair -> {amount, fetched_at, attempted_at, live, error}
_mk_stq = {}    # symbol -> {obs, fetched_at, attempted_at, live, error}
_mk_stq_blocked_at = None


_MK_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def parse_fred_csv(raw):
    """Pure: fredgraph.csv bytes -> [(date, value)] in file order.
    Only rows whose first field is a YYYY-MM-DD date are kept, so
    the header ('observation_date,SERIES') and junk rows are skipped
    by construction; '.'/empty values are skipped. An empty list
    means 'no data'."""
    try:
        txt = raw.decode("utf-8", "replace")
    except Exception:
        return []
    obs = []
    for ln in txt.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        parts = ln.split(",")
        if len(parts) < 2 or not _MK_DATE_RE.match(parts[0].strip()):
            continue
        v = parts[1].strip()
        if v in ("", "."):
            continue
        try:
            obs.append((parts[0].strip(), float(v)))
        except ValueError:
            continue
    # Date-ascending by construction: FRED already ships ascending,
    # Stooq's order is not guaranteed — sorting makes last/prev/1M
    # arithmetic independent of source order.
    obs.sort(key=lambda dv: dv[0])
    return obs


def _stooq_blocked_body(txt):
    """True when a Stooq reply is an interstitial/CAPTCHA page, not
    CSV: an HTML body or the word captcha in the first 2 KB."""
    head = txt[:2048].lower()
    return ("captcha" in head) or txt.lstrip().startswith("<")


def parse_stooq_csv(raw):
    """Pure: Stooq daily CSV bytes -> (obs, blocked). obs is
    [(date, close)] in file order; blocked=True means the reply was
    an interstitial page (Stooq drops entirely, K15). A header-only
    CSV is ([], False) — 'symbol not found', not a block."""
    try:
        txt = raw.decode("utf-8", "replace")
    except Exception:
        return [], False
    if _stooq_blocked_body(txt):
        return [], True
    obs = []
    for ln in txt.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        parts = ln.split(",")
        if len(parts) < 5 or not _MK_DATE_RE.match(parts[0].strip()):
            continue
        c = parts[4].strip()
        if c in ("", "."):
            continue
        try:
            obs.append((parts[0].strip(), float(c)))
        except ValueError:
            continue
    obs.sort(key=lambda dv: dv[0])
    return obs, False


def parse_coinbase_spot(raw):
    """Pure: Coinbase spot JSON bytes -> float amount or None."""
    try:
        doc = json.loads(raw.decode("utf-8", "replace"))
        return float((doc.get("data") or {}).get("amount"))
    except Exception:
        return None


def _mk_change(obs):
    """Daily change % from the last two observations, or None when
    fewer than two exist (a single observation shows no change —
    never a 0% dressed up as a flat move)."""
    if len(obs) < 2:
        return None
    prev = obs[-2][1]
    last = obs[-1][1]
    if prev == 0:
        return None
    return (last - prev) / prev * 100.0


def _mk_change_1m(obs):
    """1-month change %: last value vs the latest observation on or
    before (last date - 30 days); when no observation is that old,
    the earliest one. None when fewer than two observations exist.
    Pure arithmetic on real observations, never an interpolated or
    estimated month-ago value."""
    if len(obs) < 2:
        return None
    try:
        last_d = _date.fromisoformat(obs[-1][0])
    except ValueError:
        return None
    target = last_d - timedelta(days=30)
    base = None
    for d, v in obs:
        try:
            dd = _date.fromisoformat(d)
        except ValueError:
            continue
        if dd <= target:
            base = v
        else:
            break
    if base is None:
        base = obs[0][1]
    if base == 0:
        return None
    return (obs[-1][1] - base) / base * 100.0


def _mk_spark(obs):
    """Last 30 closes, for the world-table mini sparkline. Empty
    when fewer than two observations exist (no line to draw)."""
    if len(obs) < 2:
        return []
    return [v for _d, v in obs[-30:]]


def _mk_fred_url(series):
    """fredgraph.csv for one series, 90-day window (cosd/coed are
    ignored by FRED if unsupported — the parser takes the last two
    observations either way, so the result is identical)."""
    now = time.gmtime(_now())
    start = time.gmtime(_now() - 90 * 86400)
    return ("https://fred.stlouisfed.org/graph/fredgraph.csv?id="
            + series + "&cosd=%04d-%02d-%02d&coed=%04d-%02d-%02d"
            % (start.tm_year, start.tm_mon, start.tm_mday,
               now.tm_year, now.tm_mon, now.tm_mday))


def _mk_fetch_fred(series):
    """One FRED series fetch+parse. Returns (obs, error)."""
    try:
        st, _h, body, cut = _fetch_binary(
            _mk_fred_url(series), timeout=_MK_TIMEOUT, cap=_MK_CAP)
    except Exception as e:  # noqa: BLE001
        return [], type(e).__name__
    if st != 200:
        return [], "HTTP %d" % st
    if cut:
        return [], "reply too large"
    obs = parse_fred_csv(body)
    if not obs:
        return [], "no data"
    return obs, ""


def _mk_fetch_cb(pair):
    """One Coinbase spot fetch+parse. Returns (amount|None, error)."""
    try:
        st, _h, body, cut = _fetch_binary(
            "https://api.coinbase.com/v2/prices/" + pair + "/spot",
            timeout=_MK_TIMEOUT, cap=_MK_CAP)
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__
    if st != 200:
        return None, "HTTP %d" % st
    amt = parse_coinbase_spot(body)
    if amt is None:
        return None, "unreadable spot reply"
    return amt, ""


def _mk_fetch_stq(symbol):
    """One Stooq symbol fetch+parse. Returns (obs, error, blocked)."""
    try:
        st, _h, body, cut = _fetch_binary(
            "https://stooq.com/q/d/l/?s=" + symbol + "&i=d",
            timeout=_MK_TIMEOUT, cap=_MK_CAP)
    except Exception as e:  # noqa: BLE001
        return [], type(e).__name__, False
    if st != 200:
        return [], "HTTP %d" % st, False
    if cut:
        return [], "reply too large", False
    obs, blocked = parse_stooq_csv(body)
    if blocked:
        return [], "captcha/blocked", True
    if not obs:
        return [], "no data", False
    return obs, "", False


_MK_STQ_BLOCK_TTL = 86400.0


def _mk_stq_blocked(now):
    """Stooq block state with a 24 h expiry: a lifted wall is
    re-probed at most once a day (one request), never on every panel
    open; a fresh wall re-blocks immediately."""
    return (_mk_stq_blocked_at is not None
            and now - _mk_stq_blocked_at < _MK_STQ_BLOCK_TTL)


def _mk_refresh():
    """Refresh stale market sources (FRED 6 h, Coinbase 15 min,
    Stooq 1 day/symbol). Failures keep the last snapshot (STALE);
    one attempt per TTL even when failed (mirrors get_news). A Stooq
    CAPTCHA body marks Stooq blocked globally and stops further
    Stooq attempts. Fetches run outside the state lock."""
    global _mk_stq_blocked_at
    now = _now()
    with _mk_lock:
        blocked = _mk_stq_blocked(now)
        fred_stale = [s for s, _n, _c, _t in _MK_FRED_SERIES
                      if now - ((_mk_fred.get(s) or {})
                                .get("attempted_at") or 0) > _MK_FRED_TTL]
        cb_stale = [p for p, _n, _c in _MK_CB_PAIRS
                    if now - ((_mk_cb.get(p) or {})
                              .get("attempted_at") or 0) > _MK_CB_TTL]
        stq_syms = ([sym for _r, sym, _n in _MK_STQ_WORLD]
                    + [sym for sym, _n in _MK_STQ_DEF]
                    + [sym for sym, _n in _MK_STQ_NRG])
        stq_stale = [] if blocked else [
            sym for sym in stq_syms
            if now - ((_mk_stq.get(sym) or {})
                      .get("attempted_at") or 0) > _MK_STQ_TTL]
    for s in fred_stale:
        obs, err = _mk_fetch_fred(s)
        with _mk_lock:
            prev = _mk_fred.get(s) or {}
            _mk_fred[s] = {
                "obs": obs if not err else prev.get("obs", []),
                "fetched_at": now if not err else prev.get("fetched_at"),
                "attempted_at": now, "live": not err, "error": err}
    for p in cb_stale:
        amt, err = _mk_fetch_cb(p)
        with _mk_lock:
            prev = _mk_cb.get(p) or {}
            _mk_cb[p] = {
                "amount": amt if not err else prev.get("amount"),
                "fetched_at": now if not err else prev.get("fetched_at"),
                "attempted_at": now, "live": not err, "error": err}
    for sym in stq_stale:
        obs, err, blk = _mk_fetch_stq(sym)
        with _mk_lock:
            if blk:
                _mk_stq_blocked_at = now
            prev = _mk_stq.get(sym) or {}
            _mk_stq[sym] = {
                "obs": obs if not err else prev.get("obs", []),
                "fetched_at": now if not err else prev.get("fetched_at"),
                "attempted_at": now, "live": not err, "error": err}
        if blk:
            break


def _mk_fmt_z(epoch_s):
    """Epoch seconds -> 'HH:MMZ' (UTC), or '' when unknown."""
    if not epoch_s:
        return ""
    t = time.gmtime(epoch_s)
    return "%02d:%02dZ" % (t.tm_hour, t.tm_min)


def _mk_breadth(rows):
    """Breadth basket (§16.1, K31): up/down/flat over the panel's own
    rows with a computed daily change. Rows without a computed change
    — including spot-only rows, because the daemon stores no >=24h
    spot history — are EXCLUDED, never counted flat. Hidden when
    fewer than 2 rows count. Exchange breadth stays dropped (K25).
    Pure function: no fetch, no state."""
    counted = [r for r in rows if r.get("change_pct") is not None]
    up = sum(1 for r in counted if r["change_pct"] > 0)
    down = sum(1 for r in counted if r["change_pct"] < 0)
    flat = sum(1 for r in counted if r["change_pct"] == 0)
    excluded = [r for r in rows if r.get("change_pct") is None]
    excluded_spot = [r for r in excluded
                     if r.get("as_of_kind") == "spot"]
    by_chg = sorted(counted, key=lambda r: r["change_pct"])
    best = [{"id": r["id"], "name": r["name"],
             "change_pct": r["change_pct"]} for r in by_chg[::-1][:5]]
    worst = [{"id": r["id"], "name": r["name"],
              "change_pct": r["change_pct"]} for r in by_chg[:5]]
    return {"up": up, "down": down, "flat": flat,
            "total": len(counted), "excluded": len(excluded),
            "excluded_spot": len(excluded_spot),
            "hidden": len(counted) < 2, "best": best, "worst": worst}


def get_markets():
    """MARKETS panel read (design §6 + §14.4 + §16.1): refresh stale
    sources, serve rows with per-row as-of + source. Stooq rows only
    when not blocked. Breadth basket (K31, v1.25.0): up/down/flat over
    rows with a computed daily change; spot-only rows excluded, never
    counted flat; hidden when fewer than 2 rows count. Exchange
    breadth stays dropped (K25). Dollar is DTWEXBGS, never labelled
    DXY. All offline -> rows [] + all_offline True (never 'no market
    movement' dressed up as an empty world)."""
    _mk_refresh()
    with _mk_lock:
        fred = {s: dict(_mk_fred.get(s) or {})
                for s, _n, _c, _t in _MK_FRED_SERIES}
        cb = {p: dict(_mk_cb.get(p) or {})
              for p, _n, _c in _MK_CB_PAIRS}
        stq = dict(_mk_stq)
        blocked = _mk_stq_blocked(_now())
    rows = []
    unavailable = []
    for series, name, cats, note in _MK_FRED_SERIES:
        st = fred.get(series) or {}
        obs = st.get("obs") or []
        if not obs:
            unavailable.append(name)
            continue
        rows.append({"id": series, "symbol": series, "name": name,
                     "value": obs[-1][1], "change_pct": _mk_change(obs),
                     "change_1m": _mk_change_1m(obs),
                     "spark": _mk_spark(obs),
                     "as_of": obs[-1][0], "as_of_kind": "date",
                     "source": "FRED", "source_note": note,
                     "cats": cats, "stale": not st.get("live", False)})
    for pair, name, cats in _MK_CB_PAIRS:
        st = cb.get(pair) or {}
        amt = st.get("amount")
        if amt is None:
            unavailable.append(name)
            continue
        rows.append({"id": pair, "symbol": pair, "name": name,
                     "value": amt, "change_pct": None,
                     "change_1m": None, "spark": [],
                     "as_of": _mk_fmt_z(st.get("fetched_at")),
                     "as_of_kind": "spot",
                     "source": "Coinbase",
                     "source_note": "Source: Coinbase (spot)",
                     "cats": cats, "stale": not st.get("live", False)})
    if not blocked:
        for region, sym, name in _MK_STQ_WORLD:
            st = stq.get(sym) or {}
            obs = st.get("obs") or []
            if not obs:
                unavailable.append(name)
                continue
            rows.append({"id": sym, "symbol": sym, "name": name,
                         "value": obs[-1][1],
                         "change_pct": _mk_change(obs),
                         "change_1m": _mk_change_1m(obs),
                         "spark": _mk_spark(obs),
                         "as_of": obs[-1][0], "as_of_kind": "date",
                         "source": "Stooq",
                         "source_note": "Source: Stooq (delayed)",
                         "cats": ["WEI"], "region": region,
                         "stale": not st.get("live", False)})
        for sym, name in _MK_STQ_DEF:
            st = stq.get(sym) or {}
            obs = st.get("obs") or []
            if not obs:
                unavailable.append(name)
                continue
            rows.append({"id": sym, "symbol": sym, "name": name,
                         "value": obs[-1][1],
                         "change_pct": _mk_change(obs),
                         "change_1m": _mk_change_1m(obs),
                         "spark": _mk_spark(obs),
                         "as_of": obs[-1][0], "as_of_kind": "date",
                         "source": "Stooq",
                         "source_note": "Source: Stooq (delayed)",
                         "cats": ["DEF"],
                         "stale": not st.get("live", False)})
        for sym, name in _MK_STQ_NRG:
            st = stq.get(sym) or {}
            obs = st.get("obs") or []
            if not obs:
                unavailable.append(name)
                continue
            rows.append({"id": sym, "symbol": sym, "name": name,
                         "value": obs[-1][1],
                         "change_pct": _mk_change(obs),
                         "change_1m": _mk_change_1m(obs),
                         "spark": _mk_spark(obs),
                         "as_of": obs[-1][0], "as_of_kind": "date",
                         "source": "Stooq",
                         "source_note": "Source: Stooq (delayed)",
                         "cats": ["NRG"],
                         "stale": not st.get("live", False)})
    upd = None
    for st in (list(fred.values()) + list(cb.values())
               + list(stq.values())):
        fa = st.get("fetched_at")
        if fa and (upd is None or fa > upd):
            upd = fa
    stq_live = (not blocked) and any(
        (stq.get(sym) or {}).get("live")
        for sym in ([s for _r, s, _n in _MK_STQ_WORLD]
                    + [s for s, _n in _MK_STQ_DEF]
                    + [s for s, _n in _MK_STQ_NRG]))
    breadth = _mk_breadth(rows)
    return {"ok": True, "rows": rows, "unavailable": unavailable,
            "stooq": {"alive": stq_live, "blocked": blocked},
            "upd": upd, "all_offline": not rows, "breadth": breadth}


def get_ticker(sym):
    """Ticker lookup via Stooq daily CSV (design §14.4): direct
    symbol only, no autocomplete. Blocked Stooq -> unavailable;
    header-only CSV -> symbol not found; else close + date + daily
    change from the last two observations. 24 h cache per symbol,
    shared with the basket store."""
    global _mk_stq_blocked_at
    s = (sym or "").strip().upper()
    if not _MK_TICKER_RE.match(s):
        return {"ok": False, "reason": "invalid symbol"}
    with _mk_lock:
        blocked = _mk_stq_blocked(_now())
    if blocked:
        return {"ok": False, "reason": "stooq unavailable"}
    now = _now()
    with _mk_lock:
        st = _mk_stq.get(s) or {}
        fresh = bool(st.get("obs")) and \
            now - (st.get("attempted_at") or 0) <= _MK_STQ_TTL
    if not fresh:
        obs, err, blk = _mk_fetch_stq(s)
        with _mk_lock:
            if blk:
                _mk_stq_blocked_at = now
            prev = _mk_stq.get(s) or {}
            _mk_stq[s] = {
                "obs": obs if not err else prev.get("obs", []),
                "fetched_at": now if not err else prev.get("fetched_at"),
                "attempted_at": now, "live": not err, "error": err}
        st = _mk_stq[s]
    obs = st.get("obs") or []
    if not obs:
        return {"ok": False, "reason": "symbol not found"}
    return {"ok": True, "symbol": s, "close": obs[-1][1],
            "date": obs[-1][0], "change_pct": _mk_change(obs),
            "change_1m": _mk_change_1m(obs),
            "spark": _mk_spark(obs),
            "stale": not st.get("live", False)}


# ------------------------------------------------------- v1.21.0 Fase 5
# Design section 7 + addendum 14.2, OSIRIS-aligned 2026-10-25:
# NowCOAST WMS clouds meta (computed server-side; tiles are
# browser-direct), GFS 1.00 deg wind grid (NOMADS GRIB2, decoded
# by grib2min, full grid), ISS telemetry from TLE via SGP4 (no
# new host). The wind grid degrades to the existing Open-Meteo
# point layer on any fetch/decode failure — particles die,
# nothing is fabricated.

_WINDGRID_CACHE = {}  # (cycle, fhour) -> grid dict (immutable)
_windgrid_state = {"grid": None, "fetched_at": 0.0, "error": ""}

_iss_tel = {"at": 0.0, "doc": None}


# NowCOAST WMS clouds (OSIRIS-aligned, 2026-10-25 redirection):
# OSIRIS src/lib/live-clouds.ts — WMS 1.3.0 GetMap, CRS EPSG:3857,
# TRANSPARENT=true, BGCOLOR=0x000000, FORMAT=image/png, TIME=hourly
# frame. Two bands exist: global_longwave_imagery_mosaic (thermal
# IR) and global_visible_imagery_mosaic (visible). VANTHEX draws
# the IR mosaic only: IR shows cloud day and night, while VIS is
# day-side only, and OSIRIS composites both bands through a WebGL
# worker VANTHEX's 2D canvas does not have. The VIS layer name is
# recorded here so a future band toggle needs no re-research.
# The meta is COMPUTED server-side (OSIRIS frameTime rule: now -
# 20 min, snapped to the UTC hour) — no caps fetch, no new-host
# contact from the VM; tiles are browser-direct from NowCOAST.
_NOWCOAST_WMS = "https://nowcoast.noaa.gov/geoserver/satellite/wms"
_NOWCOAST_LAYER_IR = "global_longwave_imagery_mosaic"
_NOWCOAST_LAYER_VIS = "global_visible_imagery_mosaic"  # day-side only, not drawn
_NOWCOAST_ATTRIBUTION = "Clouds © NOAA/NESDIS GMGSI"
_NOWCOAST_FRAME_COUNT = 25  # hourly frames offered by the time slider


def _nowcoast_latest_hour(now):
    """OSIRIS frameTime: newest hourly frame NOAA should have
    published by `now` — now minus the 20 min publish lag, snapped
    down to the UTC hour. Returns an aware-UTC datetime."""
    t = datetime.fromtimestamp(now - 20 * 60, tz=timezone.utc)
    return t.replace(minute=0, second=0, microsecond=0)


def _nowcoast_times(now, count=_NOWCOAST_FRAME_COUNT):
    """Hourly TIME strings, ascending, ending at the latest frame:
    ['YYYY-MM-DDTHH:00:00Z', ...]. The WMS snaps to the nearest
    frame it holds, so a requested hour never fabricates data."""
    latest = _nowcoast_latest_hour(now)
    return [(latest - timedelta(hours=i)).strftime("%Y-%m-%dT%H:00:00Z")
            for i in reversed(range(count))]


def get_cloudmeta():
    """NowCOAST cloud metadata (computed, no fetch): one IR mosaic
    layer with hourly TIME steps. The panel MUST show the real TIME
    stamp, never 'LIVE' — frames lag ~20 min behind real time and
    the mosaic band is +/-72.7 deg (beyond it, honestly no cover)."""
    now = _now()
    times = _nowcoast_times(now)
    latest = times[-1]
    doc = {"ok": True, "source": "nowcoast",
           "layers": [{"id": "nowcoast_ir",
                       "wms": _NOWCOAST_WMS,
                       "layer": _NOWCOAST_LAYER_IR,
                       "format": "image/png",
                       "times": times, "latest": latest}],
           "note": ("NOAA GMGSI thermal-IR mosaic via NowCOAST "
                    "WMS — as of <latest>; hourly frames, ~20 min "
                    "publish lag; mosaic band +/-72.7 deg (beyond "
                    "it, no cover)"),
           "attribution": _NOWCOAST_ATTRIBUTION,
           "fetched_at": now}
    return doc


def _valid_cycle(cycle):
    return isinstance(cycle, str) \
        and re.fullmatch(r"\d{10}", cycle) is not None \
        and cycle[8:10] in ("00", "06", "12", "18")


def _valid_fhour(fhour):
    if not isinstance(fhour, int) or fhour < 0 or fhour > 384:
        return False
    if fhour <= 120:
        return True
    return fhour % 3 == 0


def get_windgrid(cycle, fhour):
    """NOMADS GFS 1.00 deg wind grid for one cycle + forecast hour
    (OSIRIS filter_gfs_1p00.pl, full global grid, no lon/lat cuts),
    decoded by grib2min and served WHOLE (181x360, like OSIRIS —
    no thinning invented). Cycles are immutable once published, so
    the cache never expires. On ANY failure returns {ok: False} —
    the client keeps the previous grid and the Open-Meteo point
    layer stays as fallback; nothing is faked."""
    if not _valid_cycle(cycle) or not _valid_fhour(fhour):
        return {"ok": False, "reason": "invalid cycle or forecast hour"}
    key = (cycle, fhour)
    if key in _WINDGRID_CACHE:
        return dict(_WINDGRID_CACHE[key], ok=True, cached=True)
    date, hh = cycle[:8], cycle[8:10]
    url = ("https://nomads.ncep.noaa.gov/cgi-bin/filter_gfs_1p00.pl"
           "?dir=%2Fgfs." + date + "%2F" + hh + "%2Fatmos"
           "&file=gfs.t" + hh + "z.pgrb2.1p00.f" + ("%03d" % fhour) +
           "&var_UGRD=on&var_VGRD=on&lev_10_m_above_ground=on")
    try:
        status, _headers, body, cut = _fetch_binary(
            url, timeout=120.0, cap=16 * 1024 * 1024,
            headers={"Accept-Encoding": "gzip"})
        if status != 200 or cut or not body \
                or not body.startswith(b"GRIB"):
            raise IOError("NOMADS HTTP %s cut=%s bytes=%d"
                          % (status, cut, len(body)))
        info, u_rows, v_rows = grib2min.decode_gfs_uv(body)
        if info["cycle"].strftime("%Y%m%d%H") != cycle \
                or info["fhour"] != fhour:
            raise IOError("NOMADS returned cycle %s fhour %s, "
                          "requested %s fhour %s"
                          % (info["cycle"].strftime("%Y%m%d%H"),
                             info["fhour"], cycle, fhour))
        if len(u_rows) != 181 or len(u_rows[0]) != 360 \
                or len(v_rows) != 181 or len(v_rows[0]) != 360:
            raise IOError("grid is %dx%d, expected 181x360"
                          % (len(u_rows), len(u_rows[0])))
        lons = [round(-180.0 + i * 1.0, 4) for i in range(360)]
        lats = [round(90.0 - i * 1.0, 4) for i in range(181)]
        u_flat, v_flat = [], []
        for r in range(181):
            for c in range(360):
                # Rotate 0..359 longitudes to a -180 base.
                uu = u_rows[r][(c + 180) % 360]
                vv = v_rows[r][(c + 180) % 360]
                if uu is None or vv is None:
                    raise grib2min.GRIB2Error(
                        "missing vector in wind grid")
                u_flat.append(round(uu, 1))
                v_flat.append(round(vv, 1))
        valid = info["cycle"] + timedelta(hours=info["fhour"])
        valid_s = valid.strftime("%Y-%m-%dT%H:%M:%SZ")
        grid = {"cycle": cycle, "fhour": fhour,
                "valid_time": valid_s, "lats": lats, "lons": lons,
                "u": u_flat, "v": v_flat, "count": 181 * 360,
                "note": ("NOAA GFS via NOMADS (GRIB2, 1.00 deg) — "
                         "valid %s UTC" % valid_s)}
        _WINDGRID_CACHE[key] = grid
        _windgrid_state.update(grid=grid, fetched_at=_now(), error="")
        return dict(grid, ok=True, cached=False)
    except Exception as e:  # noqa: BLE001 — grid dies, fallback lives
        _windgrid_state["error"] = ("%s: %s"
                                    % (type(e).__name__, e))[:200]
        return {"ok": False, "reason": str(e)[:200]}


def _wind_particles_entry():
    """Layer-route entry for WIND_PARTICLES, built from the grid
    state (no fetch triggered here)."""
    st = _windgrid_state
    grid = st.get("grid")
    if not grid:
        return {"points": [], "total": 0, "drawn": 0,
                "fetched_at": None,
                "note": ("WIND GRID OFFLINE — no GFS grid decoded "
                         "yet; the Open-Meteo point wind layer "
                         "still runs."),
                "ok": False, "error": st.get("error") or "no grid"}
    age = _now() - (st.get("fetched_at") or 0)
    state = "live" if age <= 1.5 * 3600 else "stale"
    return {"points": [], "total": grid["count"], "drawn": 0,
            "fetched_at": st.get("fetched_at"),
            "note": ("GFS wind particles — valid %s UTC · cycle %s "
                     "fhour %d · %d vectors (1.00 deg grid)"
                     % (grid["valid_time"], grid["cycle"],
                        grid["fhour"], grid["count"])),
            "ok": True, "state": state, "error": ""}


def _fetch_iss_tle():
    """ISS TLE lines (NORAD 25544): prefer the sats union text; else
    fetch ONLY the CelesTrak stations group (one fetch — never the
    full ~45-group sweep) and cache it for the union's later use."""
    text = _tle.get("text") or ""
    if _tle.get("ok") and text:
        objs, _bad = parse_tle(text)
        for _name, l1, l2 in objs:
            if l1[2:7].strip() == "25544":
                return l1, l2
    raw = _fetch_text_large(
        "celestrak.org",
        "/NORAD/elements/gp.php?GROUP=stations&FORMAT=tle",
        timeout=45.0)
    stext = raw.decode("utf-8", "replace")
    if "1 " not in stext:
        raise IOError("no TLE lines in stations group")
    _tle_groups["stations"] = {"text": stext, "fetched_at": _now()}
    objs, _bad = parse_tle(stext)
    for _name, l1, l2 in objs:
        if l1[2:7].strip() == "25544":
            return l1, l2
    raise IOError("ISS (NORAD 25544) not in stations group")


def get_iss_telemetry():
    """ISS altitude + orbital period from its own TLE via SGP4 (no
    new host; wheretheiss.at rejected, K22). 60 s cache. Both values
    are labeled 'TLE-derived' in the UI; TLE age > 3 days -> STALE."""
    now = _now()
    if _iss_tel["doc"] is not None and now - _iss_tel["at"] <= 60:
        return _iss_tel["doc"]
    try:
        l1, l2 = _fetch_iss_tle()
        from sgp4.api import Satrec, jday
        dt = datetime.utcfromtimestamp(now)
        jd, fr = jday(dt.year, dt.month, dt.day, dt.hour, dt.minute,
                      dt.second + dt.microsecond / 1e6)
        sat = Satrec.twoline2rv(l1, l2)
        err, r, _v = sat.sgp4(jd, fr)
        if err != 0:
            raise IOError("SGP4 error %d" % err)
        gmst = math.radians(_gmst_deg(jd + fr))
        x, y, z = r
        lon = math.degrees(math.atan2(y, x)) - math.degrees(gmst)
        lon = (lon + 540.0) % 360.0 - 180.0
        lat = math.degrees(math.atan2(z, math.hypot(x, y)))
        alt = math.sqrt(x * x + y * y + z * z) - 6371.0
        mm = float(l2[52:63])
        period = 1440.0 / mm if mm else 0.0
        yy = int(l1[18:20])
        year = 2000 + yy if yy < 57 else 1900 + yy
        day = float(l1[20:32])
        epoch = datetime(year, 1, 1) + timedelta(days=day - 1)
        age = (dt - epoch).total_seconds() / 86400.0
        doc = {"ok": True, "alt_km": round(alt, 1),
               "orbit_min": round(period, 1),
               "lat": round(lat, 3), "lon": round(lon, 3),
               "tle_epoch": epoch.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "tle_age_days": round(age, 1),
               "stale": age > 3}
    except Exception as e:  # noqa: BLE001 — telemetry reports off
        doc = {"ok": False,
               "reason": ("%s: %s" % (type(e).__name__, e))[:200]}
    _iss_tel["doc"] = doc
    _iss_tel["at"] = now
    return doc
