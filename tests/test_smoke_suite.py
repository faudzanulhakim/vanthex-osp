"""Wrapper pytest untuk smoke test engine web (script mandiri tests/test_smoke.py
yang menjalankan fixture server lokal + 41 check). Dijalankan sebagai subprocess
agar perilakunya identik dengan menjalankan script-nya langsung."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_smoke_script_passes():
    p = subprocess.run([sys.executable, "tests/test_smoke.py"],
                       cwd=ROOT, capture_output=True, text=True, timeout=600)
    assert "SEMUA TEST LULUS" in p.stdout, p.stdout[-2000:] + p.stderr[-1000:]
    assert p.returncode == 0
