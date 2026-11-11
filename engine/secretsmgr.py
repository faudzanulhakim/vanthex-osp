"""Secrets management (Phase 3): encryption-at-rest for target credentials.

Uses Fernet (cryptography) — AES + HMAC, authenticated: a tampered token
fails decryption with InvalidToken rather than silently decrypting wrong.
Master key: env PTK_SECRETS_KEY (base64 Fernet key) if set; otherwise the
`secrets.key` file (0600) in the app folder, generated once
automatically. Secret values NEVER leave via the API — they are only
used server-side while a scan runs.
"""
import os

from cryptography.fernet import Fernet, InvalidToken  # noqa: F401

_HERE = os.path.dirname(os.path.abspath(__file__))
if not os.path.exists(os.path.join(_HERE, "requirements.txt")):
    _HERE = os.path.dirname(_HERE)  # project root when module lives in engine/
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
    except FileExistsError:                      # first-process race
        return open(KEY_FILE, "rb").read().strip()


def encrypt(plain):
    return Fernet(_key()).encrypt(plain.encode()).decode()


def decrypt(token):
    """Raises InvalidToken if the token is corrupt / the key is wrong."""
    return Fernet(_key()).decrypt(token.encode()).decode()
