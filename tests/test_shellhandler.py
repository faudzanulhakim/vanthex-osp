"""Test ShellHandler + postex — integration via fake TCP shell server.

Fake server melayani banyak koneksi (accept loop + thread per koneksi),
meniru shell target yang mengeksekusi perintah dan mengembalikan output
lalu menandai selesai dengan marker __VHX_DONE__.
"""
import base64
import os
import socket
import subprocess
import sys
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from shellhandler import ShellHandler, HandlerError, DONE_MARK


class _FakeShell:
    def __init__(self, port):
        self.port = port
        self._sock = None
        self._stop = False
        self._clients = []
        self._accept_t = None

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", self.port))
        s.listen(5)
        s.settimeout(0.3)
        self._sock = s
        self._accept_t = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_t.start()

    def _accept_loop(self):
        while not self._stop:
            try:
                c, _ = self._sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            c.settimeout(3)
            t = threading.Thread(target=self._serve, args=(c,), daemon=True)
            t.start()
            self._clients.append(c)

    def _serve(self, c):
        buf = b""
        try:
            while not self._stop:
                chunk = c.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    resp = self._respond(line.decode("utf-8", "replace"))
                    try:
                        c.sendall(resp.encode())
                    except Exception:
                        break
        except Exception:
            pass

    def _respond(self, line):
        cmd = line.split("; echo")[0].strip()
        if "VHXB64S" in line:
            b64 = base64.b64encode(b"fake-file-content-42\n").decode()
            return f"VHXB64S{b64}VHXB64E\n{DONE_MARK}0\n{DONE_MARK}end\n"
        if ">/dev/tcp/" in line:
            return f"22 open\n80 open\n443 open\n{DONE_MARK}0\n{DONE_MARK}end\n"
        if cmd.startswith("base64"):
            return f"OK\n{DONE_MARK}0\n{DONE_MARK}end\n"
        if "id" in cmd:
            return f"uid=0(root) gid=0(root) groups=0(root)\n{DONE_MARK}0\n{DONE_MARK}end\n"
        if "uname" in cmd:
            return f"Linux testhost 6.1.0 x86_64 GNU/Linux\n{DONE_MARK}0\n{DONE_MARK}end\n"
        return f"output-of: {cmd[:40]}\n{DONE_MARK}0\n{DONE_MARK}end\n"

    def stop(self):
        self._stop = True
        for c in self._clients:
            try:
                c.close()
            except Exception:
                pass
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass


def _open_h(port):
    """Buka koneksi dari sisi handler (seolah mode reverse sudah accept)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(3)
    h = ShellHandler(host="127.0.0.1", port=port, mode="reverse")
    h._conn = s
    return h


class TestShellHandler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._port = 19842
        cls._srv = _FakeShell(cls._port)
        cls._srv.start()

    @classmethod
    def tearDownClass(cls):
        cls._srv.stop()
        time.sleep(0.1)

    def test_command_returns_output(self):
        h = _open_h(self._port)
        out = h.command("id")
        self.assertIn("uid=", out)

    def test_alive_and_stop(self):
        h = _open_h(self._port)
        self.assertTrue(h.alive())
        h.stop()
        self.assertFalse(h.alive())

    def test_send_file(self):
        f = "/tmp/postex_upload.txt"
        with open(f, "w") as fh:
            fh.write("test content 123\n")
        h = _open_h(self._port)
        size = h.send_file(f, "/tmp/recv.txt")
        self.assertGreater(size, 0)
        os.unlink(f)

    def test_recv_file(self):
        h = _open_h(self._port)
        local = "/tmp/postex_download.txt"
        if os.path.exists(local):
            os.unlink(local)
        size = h.recv_file("/tmp/fake.txt", local)
        self.assertGreater(size, 0)
        with open(local) as fh:
            self.assertEqual(fh.read(), "fake-file-content-42\n")
        os.unlink(local)

    def test_enum_returns_basic(self):
        h = _open_h(self._port)
        info = h.enum()
        self.assertIn("basic", info)
        self.assertIn("uid=", info["basic"])

    def test_sweep_returns_open_ports(self):
        h = _open_h(self._port)
        res = h.sweep(host="10.0.0.5", ports=(22, 80, 443))
        self.assertIn("ports", res)
        self.assertIn(22, res["ports"])
        self.assertIn(80, res["ports"])
        self.assertEqual(sorted(res["ports"]), [22, 80, 443])


class TestPostexCLI(unittest.TestCase):
    def test_help_shows_subcommands(self):
        # jalankan lewat modul agar path absolut (pytest cwd bisa beda)
        r = subprocess.run(
            [sys.executable, "postex.py", "--help"],
            cwd=ROOT, capture_output=True, text=True, timeout=10)
        stdout = r.stdout or ""
        self.assertIn("usage:", stdout)
        for sub in ("listen", "connect", "enum", "exec", "upload", "download",
                    "grab", "exfil", "sweep"):
            self.assertIn(sub, stdout)

    def test_connect_requires_target(self):
        r = subprocess.run([sys.executable, "postex.py", "connect"],
                           capture_output=True, text=True, timeout=10)
        self.assertNotEqual(r.returncode, 0)

    def test_exec_requires_mode(self):
        r = subprocess.run([sys.executable, "postex.py", "exec", "id"],
                           capture_output=True, text=True, timeout=10)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
