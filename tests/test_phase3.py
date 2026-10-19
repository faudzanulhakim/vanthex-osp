"""Test Fase 3 (v3.18): sandbox subprocess untuk analisis paket +
secrets management terenkripsi (Fernet) di store.

Sandbox diuji terhadap APK fixture asli dan worker palsu (tidur/crash/
output rusak) — timeout & kegagalan harus jadi SandboxError yang jelas,
bukan fallback diam-diam.
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import sandbox
import secretsmgr
import store

FIXTURE_APK = "tests/fixtures/TestActivity.apk"


# ---------------------------------------------------------------- sandbox --

def test_sandbox_analyzes_fixture_apk():
    r = sandbox.analyze_package_sandboxed(FIXTURE_APK, "TestActivity.apk",
                                          timeout=120)
    assert isinstance(r["findings"], list) and len(r["findings"]) > 0
    assert r["meta"]["sandbox"]["enabled"] is True
    assert r["meta"]["package"] == "tests.androguard"


def test_sandbox_timeout_kills_worker(tmp_path):
    fake = tmp_path / "sleepy_worker.py"
    fake.write_text("import time; time.sleep(30)\n")
    t0 = time.time()
    with pytest.raises(sandbox.SandboxError) as ei:
        sandbox.run_worker(str(fake), [], timeout=1)
    assert "exceeded" in str(ei.value)
    assert time.time() - t0 < 8          # proses benar-benar dibunuh


def test_sandbox_crash_and_garbage(tmp_path):
    crash = tmp_path / "crash_worker.py"
    crash.write_text("import sys; sys.stderr.write('boom'); sys.exit(1)\n")
    with pytest.raises(sandbox.SandboxError):
        sandbox.run_worker(str(crash), [], timeout=10)
    junk = tmp_path / "junk_worker.py"
    junk.write_text("print('bukan json')\n")
    with pytest.raises(sandbox.SandboxError):
        sandbox.run_worker(str(junk), [], timeout=10)


# ---------------------------------------------------------------- secrets --

@pytest.fixture()
def vault(tmp_path, monkeypatch):
    monkeypatch.setattr(secretsmgr, "KEY_FILE", str(tmp_path / "k.key"))
    monkeypatch.delenv("PTK_SECRETS_KEY", raising=False)
    return tmp_path


def test_secrets_roundtrip_and_keyfile(vault):
    tok = secretsmgr.encrypt("s3cret-value-123")
    assert tok != "s3cret-value-123"
    assert secretsmgr.decrypt(tok) == "s3cret-value-123"
    kf = vault / "k.key"
    assert kf.exists()
    assert (kf.stat().st_mode & 0o777) == 0o600     # kunci privat


def test_secrets_tamper_and_wrong_key(vault, tmp_path, monkeypatch):
    from cryptography.fernet import InvalidToken
    tok = secretsmgr.encrypt("abc123")
    bad = tok[:-2] + ("AA" if not tok.endswith("AA") else "BB")
    with pytest.raises(InvalidToken):
        secretsmgr.decrypt(bad)
    # kunci lain tidak bisa membuka token
    monkeypatch.setattr(secretsmgr, "KEY_FILE", str(tmp_path / "lain.key"))
    with pytest.raises(InvalidToken):
        secretsmgr.decrypt(tok)


def test_store_secrets_metadata_only(tmp_path):
    old = store.DB_PATH
    store.DB_PATH = str(tmp_path / "t.db")
    try:
        store.init_db()
        enc = secretsmgr.encrypt("token-rahasia")
        sid = store.secret_create("staging", "stg.example.com", "bearer",
                                  "", enc, "admin")
        rows = store.secret_list()
        assert len(rows) == 1 and rows[0]["name"] == "staging"
        assert "secret_enc" not in rows[0]          # API tidak bocor
        full = store.secret_get(sid)
        assert full["secret_enc"] == enc            # internal saja
        assert secretsmgr.decrypt(full["secret_enc"]) == "token-rahasia"
        store.secret_delete(sid)
        assert store.secret_list() == []
    finally:
        store.DB_PATH = old
