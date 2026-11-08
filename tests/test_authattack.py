"""Tes authattack v1 — login attack engine (operator-gated).
Fixture port unik (18940+N). Semuanya hermetic (server lokal)."""
import os
import sys
import subprocess
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

PORT = 18940
os.environ.pop("PTK_AUTHATTACK", None)  # gate default OFF utk seluruh modul tes


def _boot(port):
    p = subprocess.Popen(
        [sys.executable, "tests/fixture_vuln_server.py", str(port)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)
            return p
        except Exception:
            time.sleep(0.25)
    p.terminate()
    raise AssertionError("fixture tidak start")


def _ctx(port, opts=None):
    import vulnscan2
    return vulnscan2.Ctx(f"http://127.0.0.1:{port}/", opts or {}, [])


import pytest

_PROC = {"p": None}


@pytest.fixture(scope="function")
def server():
    _PROC["p"] = _boot(PORT)
    yield
    _PROC["p"].terminate()


def _run(opts=None):
    """context menunjuk server modul; server dimulai via fixture `server`."""
    return _ctx(PORT, opts)


# ---------------- wordlist unit ----------------

def test_wordlist_bounds_and_determinism():
    import authattack
    u1, p1 = authattack.build_login_wordlist()
    u2, p2 = authattack.build_login_wordlist()
    assert u1 == u2 and p1 == p2, "wordlist tidak deterministik"
    assert len(u1) >= 250, len(u1)
    assert len(p1) >= 450, len(p1)
    assert len(u1) + len(p1) < 2000, len(u1) + len(p1)
    assert len(set(u1)) == len(u1) and len(set(p1)) == len(p1)
    assert "admin" in u1 and "admin123" in p1


def test_mutate_deterministic():
    import authattack
    m1 = authattack.mutate("Summer")
    m2 = authattack.mutate("Summer")
    assert m1 == m2 and m1
    joined = " ".join(m1)
    assert "2024" in joined and "2025" in joined and "2026" in joined
    assert "Summer!" in m1 and "Summer123" in m1
    assert "Summer" not in m1  # varian saja, tanpa aslinya
    assert "Summ3r" in m1 or "5umm3r" in m1  # leet swap


# ---------------- gated engine di fixture ----------------

def test_gate_off_noop(server):
    import authattack
    ctx = _run()
    found = []
    authattack.c_auth_attack(ctx, found.append)
    assert found == [], [f["title"] for f in found]
    assert authattack.run_login_attack(ctx, "/auth/login",
                                       opts={}) == []
    assert authattack.run_otp_attack(ctx, "/auth/otp", opts={}) == []


def test_brute_finds_valid_creds_confirmed(server):
    import authattack
    ctx = _run()
    found = authattack.run_login_attack(
        ctx, "/auth/login", opts={"auth_attack": True})
    crit = [f for f in found
            if f["title"] == "Login Compromised — Valid Credentials Found"]
    assert crit, [f["title"] for f in found]
    f = crit[0]
    assert f["confidence"] == "confirmed"
    assert f["severity"] == "CRITICAL" and f["cvss"] == 9.8
    assert f["cwe"] == "CWE-521"
    assert "admin:admin123" in f["evidence"], f["evidence"]
    assert "SESS-authattack" in f["evidence"]  # response marker


def test_lockout_bypass_confirmed(server):
    import authattack
    ctx = _run()
    found = authattack.run_login_attack(
            ctx, "/auth/login", opts={"auth_attack": True})
    b = [f for f in found if f["title"] ==
         "Login Rate-Limit Bypass via Header/Path Evasion"]
    assert b, [f["title"] for f in found]
    f = b[0]
    assert f["confidence"] == "confirmed"
    assert f["severity"] == "HIGH" and f["cvss"] == 7.5
    assert f["cwe"] == "CWE-307"
    assert "X-Forwarded-For" in f["evidence"]


def test_no_lockout_medium(server):
    import authattack
    ctx = _run()
    found = authattack.run_login_attack(
            ctx, "/auth/open-login", opts={"auth_attack": True})
    m = [f for f in found if f["title"] == "No Rate Limit on Login"]
    assert m, [f["title"] for f in found]
    assert m[0]["severity"] == "MEDIUM" and m[0]["cvss"] == 5.3
    # tidak ada bypass / brute finding di endpoint ini
    assert not [f for f in found if f["severity"] == "CRITICAL"]


def test_mass_assignment_probable(server):
    import authattack
    ctx = _run()
    found = authattack.run_login_attack(
            ctx, "/auth/login", opts={"auth_attack": True})
    ma = [f for f in found if f["title"] ==
          "Mass Assignment in Login/Registration"]
    assert ma, [f["title"] for f in found]
    f = ma[0]
    assert f["confidence"] == "probable"
    assert f["severity"] == "HIGH" and f["cvss"] == 7.4
    assert f["location"] == "/auth/register"


def test_sqli_negative_on_safe_fixture(server):
    import authattack
    ctx = _run()
    found = authattack.run_login_attack(
            ctx, "/auth/login", opts={"auth_attack": True})
    assert not [f for f in found
                if "Injection" in f["title"]], \
        [f["title"] for f in found]
    # dan pada route safe: tidak ada temuan sama sekali
    found_safe = authattack.run_login_attack(
        ctx, "/safe/auth/login", opts={"auth_attack": True})
    assert found_safe == [], [f["title"] for f in found_safe]


def test_otp_brute_window_confirmed(server):
    import authattack
    ctx = _run()
    found = authattack.run_otp_attack(ctx, "/auth/otp",
                                      opts={"auth_attack": True})
    otp = [f for f in found if f["title"] == "OTP Brute-Force Window Open"]
    assert otp, [f["title"] for f in found]
    f = otp[0]
    assert f["confidence"] == "confirmed"
    assert f["severity"] == "HIGH" and f["cvss"] == 7.5


def test_c_auth_attack_end_to_end(server):
    import authattack
    assert authattack.CHECKS == [authattack.c_auth_attack]
    ctx = _run({"auth_attack": True})
    found = []
    authattack.c_auth_attack(ctx, found.append)
    titles = [f["title"] for f in found]
    assert any("Login Compromised" in t for t in titles), titles
    assert any("Rate-Limit Bypass" in t for t in titles), titles
    assert any("OTP Brute-Force" in t for t in titles), titles
    # semua finding hanya pada route /auth/* rentan — tidak ada pada /safe
    assert all("/safe" not in str(f["location"]) for f in found)
    assert all(f["origin"] == "authattack" for f in found)
