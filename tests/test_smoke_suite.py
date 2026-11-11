"""Pytest wrapper for the web engine smoke test (standalone script tests/test_smoke.py,
which runs a local fixture server + 41 checks). Runs as a subprocess so its
behavior is identical to running the script directly."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_smoke_script_passes():
    p = subprocess.run([sys.executable, "tests/test_smoke.py"],
                       cwd=ROOT, capture_output=True, text=True, timeout=600)
    assert "ALL TESTS PASSED" in p.stdout, p.stdout[-2000:] + p.stderr[-1000:]
    assert p.returncode == 0
