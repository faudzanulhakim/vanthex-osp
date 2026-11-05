"""
SelfTune v1 — Self-Tuning Scanner untuk VANTHEX (v1.8.0).
AUTHORIZED TESTING ONLY.

Engine belajar dari target SEBELUM scanning: latensi respons, indikasi WAF,
tipe aplikasi → rekomendasi parameter scan (timeout, concurrency, profil
evasion, skip-list). Murni observasi pasif + rekomendasi deterministik.
"""
import time as _time


def probe_target(client, base):
    """Probe pasif: latensi HOME 3x, header server/WAF, robots.txt.
    Return {latency_s, waf, server, tech}. Tidak mengubah apa pun."""
    lat = []
    waf_markers = ("cloudflare", "sucuri", "incapsula", "imperva",
                   "akamai", "f5", "barracuda", "mod_security")
    waf, server, blob = False, "", ""
    for i in range(3):
        t0 = _time.time()
        try:
            r = client.get("/" if i == 0 else f"/?vhxtune={i}")
            lat.append(_time.time() - t0)
            blob += (r.body or "")[:4000].lower()
            hdrs = {k.lower(): v for k, v in (r.headers or {}).items()}
            server = hdrs.get("server", server)
            joined = " ".join([str(v) for v in hdrs.values()]).lower()
            if any(m in joined for m in waf_markers):
                waf = True
        except Exception:
            lat.append(5.0)
    lat = lat or [5.0]
    return {
        "latency_s": round(sum(lat) / len(lat), 3),
        "waf": waf,
        "server": server[:60],
        "tech": ("spa" if "<script src" in blob else "classic"),
    }


def recommend(probe, opts=None):
    """Deterministik: latensi lambat → timeout naik & concurrency turun;
    WAF terdeteksi → evasion aktif; teknologi dikenali → profil check."""
    opts = dict(opts or {})
    lat = probe.get("latency_s", 0.5)
    notes = []
    if lat > 2.0:
        opts["timeout"] = max(int(opts.get("timeout", 8)), 20)
        opts["max_workers"] = 2
        notes.append(f"lambat ({lat}s): timeout ditingkatkan, worker=2")
    elif lat > 0.8:
        opts["timeout"] = max(int(opts.get("timeout", 8)), 12)
        opts["max_workers"] = 4
        notes.append(f"sedang ({lat}s): timeout=12, worker=4")
    else:
        opts.setdefault("timeout", 8)
        notes.append(f"cepat ({lat}s): profil default")
    if probe.get("waf"):
        opts["evasion"] = True
        opts["payload_mode"] = "mutated"
        notes.append("WAF terdeteksi: payload mutation AKTIF")
    if probe.get("tech") == "spa":
        opts["spa_mode"] = True
        notes.append("SPA terdeteksi: crawling via bundle/js_endpoints")
    opts["selftune"] = {"probe": probe, "notes": notes}
    return opts, notes
