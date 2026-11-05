"""
BeaconSim v1 — C2 Beacon Simulator (Red-Team Grade) untuk VANTHEX (v1.8.0).
AUTHORIZED TESTING ONLY — ENGAGEMENT ONLY.

TUJUAN: mengukur *deteksiabilitas* implant di jaringan target — bukan alat
C2 sungguhan. Simulator MENGIRIM beacon dari HOST SCAN (operator) ke
LISTENER MILIK OPERATOR (canary), dengan pola trafik implant nyata:
jitter, UA rotasi, exfil chunked. Output: laporan dwell-time & pola —
dipakai untuk menguji apakah SOC/NDR menangkap pola ini.

Tidak ada persistence, tidak menyentuh target: hanya klien HTTP ke canary.
"""
import random as _random
import time as _time
import urllib.request as _urllib

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0",
]
CHUNK = 48  # byte per potongan exfil (chunked style)


class BeaconSim:
    def __init__(self, listener_url, beacon_id=None, seed=None,
                 interval_s=2.0, jitter=0.5, max_beacons=8):
        self.url = listener_url
        self.id = beacon_id or "bx" + _random.Random(seed).randbytes(4).hex()
        self.interval = interval_s
        self.jitter = jitter
        self.max = max_beacons
        self.rng = _random.Random(seed or _time.time())
        self.log = []          # [{t, ua, path, status, ms}]
        self.detected = []     # pola yang (mungkin) memicu alert

    def beacon(self, extra_path=""):
        ua = self.rng.choice(UA_POOL)
        t0 = _time.time()
        req = _urllib.Request(self.url + extra_path, method="GET",
                              headers={"User-Agent": ua,
                                       "X-Beacon-Id": self.id})
        try:
            with _urllib.urlopen(req, timeout=5) as r:
                status, ms = r.status, round((_time.time() - t0) * 1000)
        except Exception as e:
            status, ms = 0, round((_time.time() - t0) * 1000)
            self.detected.append(f"beacon failed: {e}")
        self.log.append({"t": round(_time.time(), 3), "ua": ua[:40],
                         "path": extra_path or "/", "status": status,
                         "ms": ms})
        return status

    def exfil(self, payload):
        """Exfil chunked: pecah payload → kirim bertahap sebagai query
        chunk index. Mengukur: apakah reassembly logis terdeteksi."""
        data = str(payload).encode()
        chunks = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)][:8]
        for i, c in enumerate(chunks):
            self.beacon(f"/x?i={i}&d={c.hex()}")
            _time.sleep(self.interval * self.rng.uniform(1 - self.jitter,
                                                         1 + self.jitter))

    def run(self, cancel=lambda: False):
        """Loop beacon terjadwal + jitter; return rekap dwell-time."""
        for _ in range(self.max):
            if cancel():
                break
            self.beacon()
            _time.sleep(self.interval *
                        self.rng.uniform(1 - self.jitter, 1 + self.jitter))
        gaps = [round(self.log[i + 1]["t"] - self.log[i]["t"], 2)
                for i in range(len(self.log) - 1)]
        return {"beacon_id": self.id, "beacons": len(self.log),
                "success": sum(1 for l in self.log if l["status"] == 200),
                "interval_set": self.interval, "jitter": self.jitter,
                "gaps_s": gaps, "issues": self.detected,
                "verdict": ("standard jittered-beacon pattern; measure whether "
                            "NDR/SOC flags these should-not-be-equal intervals")}
