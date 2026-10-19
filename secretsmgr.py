"""Secrets management (Fase 3): enkripsi-at-rest untuk kredensial target.

Memakai Fernet (cryptography) — AES + HMAC, terautentikasi: token yang
diutak-atik gagal dekripsi dengan InvalidToken, tidak diam-diam salah.
Kunci master: env PTK_SECRETS_KEY (Fernet key base64) bila ada; selain
itu file kunci `secrets.key` (0600) di folder aplikasi, dibuat sekali
secara otomatis. Nilai rahasia TIDAK pernah keluar lewat API — hanya
dipakai di sisi server saat scan berjalan.
"""
import os

from cryptography.fernet import Fernet, InvalidToken  # noqa: F401

_HERE = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(_HERE, "secrets.key")


def _key():
    env = os.environ.get("PTK_SECRETS_KEY")
    if env:
        return env.strip().encode()
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, "rb").read().strip()
    key = Fernet.generate_key()
    try:
        fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, key)
        os.close(fd)
        return key
    except FileExistsError:                      # balapan proses pertama
        return open(KEY_FILE, "rb").read().strip()


def encrypt(plain):
    return Fernet(_key()).encrypt(plain.encode()).decode()


def decrypt(token):
    """Melempar InvalidToken bila token rusak / kunci salah."""
    return Fernet(_key()).decrypt(token.encode()).decode()
