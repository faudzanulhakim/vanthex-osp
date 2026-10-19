#!/usr/bin/env python3
"""
Pentest Toolkit — command-line interface (cli.py, v3.14).

argparse front-end over the same self-built engines the web service runs,
for headless/terminal use (e.g. on the operator's own Kali box where the
package is deployed directly). Output is JSON on stdout; the human log
goes to stderr. Exit code 0 = the scan ran (findings may exist), 2 =
usage/runtime error. Active scanning stays behind --authorized, exactly
like the web UI's authorization gate.
"""
import argparse
import json
import sys


def _emit(obj):
    json.dump(obj, sys.stdout, indent=1, default=str)
    sys.stdout.write("\n")


class _TeeLog(list):
    """Log berbentuk list (protokol engine) yang juga menggema ke stderr."""
    def append(self, msg):
        super().append(msg)
        print(msg, file=sys.stderr)


def _log_to_stderr():
    tee = _TeeLog()
    return tee, tee


def cmd_passive(args):
    import passive
    log, _lines = _log_to_stderr()
    _emit(passive.run_passive_recon(args.target, log))
    return 0


def cmd_scan(args):
    if not args.authorized and not args.profile.startswith("passive"):
        print("active scanning requires --authorized (you confirm the target "
              "is yours / you hold written authorization)", file=sys.stderr)
        return 2
    import vulnscan2
    if args.profile not in vulnscan2.PROFILES:
        print(f"unknown profile {args.profile}; choices: "
              f"{', '.join(vulnscan2.PROFILES)}", file=sys.stderr)
        return 2
    log, _lines = _log_to_stderr()
    opts = {"timeout": args.timeout}
    if getattr(args, "canary_port", 0):
        import canary as canary_mod
        _srv, _reg = canary_mod.serve(port=args.canary_port)
        opts["canary"] = {"registry": _reg,
                          "base": f"http://127.0.0.1:{args.canary_port}"}
        print(f"canary listening on :{args.canary_port} (loopback base — "
              "targets must be able to reach this host)", file=sys.stderr)
    res = vulnscan2.run_vulnscan(args.target, args.profile, log=log,
                                 opts=opts)
    _emit(res)
    return 0


def cmd_ports(args):
    import scanners
    ports = None
    if args.ports:
        ports = []
        for part in args.ports.replace(" ", "").split(","):
            if "-" in part:
                a, b = part.split("-", 1)
                ports.extend(range(int(a), int(b) + 1))
            elif part:
                ports.append(int(part))
    det = scanners.tcp_scan_detailed(args.host, ports, timeout=args.timeout)
    _emit({"host": args.host, **det})
    if det.get("intercepted"):
        print("WARNING: egress interception detected — these results do NOT "
              "reflect the target", file=sys.stderr)
    return 0


def cmd_canary(args):
    import canary
    srv, reg = canary.serve(port=args.port)
    tok = reg.issue(args.label or "cli")
    print(f"canary listening on :{args.port} — token {tok} — "
          f"URL form: http://<reachable-host>:{args.port}/{tok}",
          file=sys.stderr)
    print("note: callbacks only arrive if targets can route to this host",
          file=sys.stderr)
    try:
        import time
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.shutdown()
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="vanthex", description="VANTHEX (self-built engine) — CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("passive", help="passive reconnaissance (public lookups)")
    p.add_argument("target", help="URL or host, e.g. https://example.com")
    p.set_defaults(fn=cmd_passive)

    p = sub.add_parser("scan", help="web vulnerability scan (active engine)")
    p.add_argument("target")
    p.add_argument("--profile", default="active-deep")
    p.add_argument("--timeout", type=float, default=6.0)
    p.add_argument("--authorized", action="store_true",
                   help="confirm written authorization for active testing")
    p.add_argument("--canary-port", type=int, default=0, help="start a canary OOB listener on this port for blind SSRF/XXE checks")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("ports", help="TCP port scan with banner verification")
    p.add_argument("host")
    p.add_argument("--ports", default="",
                   help="e.g. 22,80,443,8000-8100 (empty = common ports)")
    p.add_argument("--timeout", type=float, default=1.5)
    p.set_defaults(fn=cmd_ports)

    p = sub.add_parser("canary", help="run the blind-callback listener")
    p.add_argument("--port", type=int, default=8899)
    p.add_argument("--label", default="")
    p.set_defaults(fn=cmd_canary)

    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
