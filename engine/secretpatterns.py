"""
secretpatterns.py — shared secret patterns for VANTHEX (Step 0, Priority 1).

One source of secret patterns, used by both the mobile analyzer
(mobile.py: APK/IPA static analysis) and the web engine
(vulnscan2.py: c_exposed_secrets). Extracted from mobile.py WITHOUT
changing mobile behavior: _SECRET_PATTERNS, _GENERIC_SECRET_RE and
_mask below are the exact definitions mobile.py used before.

Rules that apply to every consumer:
- Evidence is ALWAYS masked with _mask(); a full secret value must
  never enter a finding, a log line, the database, or a report.
- A matched secret is NEVER validated against its provider (design
  decision D5) — a match is a lead (probable/candidate), never a
  confirmed live credential.
"""
import math
import re

# --- Mobile patterns (exact copy of the former mobile.py definitions) ---
_SECRET_PATTERNS = [
    ("aws", re.compile(r"AKIA[0-9A-Z]{16}"), "HIGH", 7.4,
     'AWS Access Key ID embedded in the APK',
     'An AWS access key is exposed inside an APK that anyone can download. Revoke/rotate this key immediately and never embed cloud credentials in a mobile app.'),
    ("gcp_api", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "MEDIUM", 5.3,
     'Google API Key embedded in the APK',
     'A Google API key is exposed in the APK. Restrict the key per API + per app in Google Cloud Console and rotate it if it was ever used outside the official app.'),
    ("privkey", re.compile(r"BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY"), "CRITICAL", 9.1,
     'Private key embedded in the APK',
     'A private key was found inside the app package — anyone who downloads the APK has it. Treat this key as permanently leaked: revoke and replace it, and move signing operations to a server/HSM.'),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
     "MEDIUM", 6.5, 'JWT token embedded in the APK',
     'A JWT token (likely a long-lived session/API credential) is embedded in the APK. Revoke this token and never embed static tokens in a mobile app.'),
]
_GENERIC_SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|app[_-]?secret|client[_-]?secret|password|passwd|auth[_-]?token)"
    r"\s*[:=]\s*[\"'][^\"'\s]{8,64}[\"']")

# Public aliases for new consumers.
SECRET_PATTERNS = _SECRET_PATTERNS
GENERIC_SECRET_RE = _GENERIC_SECRET_RE


def _mask(s):
    return s[:4] + "***" + s[-2:] if len(s) > 8 else "***"


mask_secret = _mask


def shannon_entropy(s):
    """Shannon entropy in bits per character (0.0 for empty input)."""
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(s))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# --- Web Tier A: provider-specific patterns -> probable -------------------
# Conservative set (13 patterns). Adding a pattern requires a battery case;
# never bulk-import external pattern databases (false-positive policy).
# Tuple: (kind, regex, severity, cvss, title, description)
WEB_TIER_A_PATTERNS = [
    ("aws", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"), "HIGH", 7.4,
     'AWS Access Key ID exposed in web content',
     'An AWS access key ID is embedded in content served to any visitor. Treat it as leaked: revoke/rotate it and move AWS calls behind a backend.'),
    ("gcp_api", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "MEDIUM", 5.3,
     'Google API Key exposed in web content',
     'A Google API key is embedded in content served to any visitor. Restrict the key per API and per application/referrer in Google Cloud Console and rotate it if it was ever used elsewhere.'),
    ("github", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}"), "HIGH", 7.4,
     'GitHub token exposed in web content',
     'A GitHub access token is embedded in content served to any visitor. Revoke it immediately and never ship source-control credentials to the browser.'),
    ("gitlab", re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"), "HIGH", 7.4,
     'GitLab token exposed in web content',
     'A GitLab access token is embedded in content served to any visitor. Revoke it immediately and never ship source-control credentials to the browser.'),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "HIGH", 7.4,
     'Slack token exposed in web content',
     'A Slack API token is embedded in content served to any visitor. Revoke it in the Slack app configuration and move Slack calls behind a backend.'),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]{8,}/B[A-Za-z0-9]{8,}/[A-Za-z0-9]{24}"), "MEDIUM", 5.3,
     'Slack webhook URL exposed in web content',
     'A Slack incoming-webhook URL is embedded in content served to any visitor — anyone can post messages to that channel with it. Regenerate the webhook and keep it server-side.'),
    ("stripe_live", re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{16,}"), "HIGH", 7.4,
     'Stripe live secret key exposed in web content',
     'A Stripe LIVE secret/restricted key is embedded in content served to any visitor. Roll the key in the Stripe dashboard immediately; only publishable keys may ever ship to the browser.'),
    ("sendgrid", re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"), "HIGH", 7.4,
     'SendGrid API key exposed in web content',
     'A SendGrid API key is embedded in content served to any visitor. Revoke it in SendGrid and send mail from a backend instead.'),
    ("telegram_bot", re.compile(r"[0-9]{6,}:[A-Za-z0-9_\-]{35}"), "MEDIUM", 6.5,
     'Telegram bot token exposed in web content',
     'A Telegram bot token is embedded in content served to any visitor — it gives full control of the bot. Revoke it via BotFather and keep it server-side.'),
    ("discord_webhook", re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,}/[A-Za-z0-9_\-]{60,}"), "MEDIUM", 5.3,
     'Discord webhook URL exposed in web content',
     'A Discord webhook URL is embedded in content served to any visitor — anyone can post to that channel with it. Delete/regenerate the webhook and keep it server-side.'),
    ("npm", re.compile(r"npm_[A-Za-z0-9]{36}"), "HIGH", 7.4,
     'npm token exposed in web content',
     'An npm access token is embedded in content served to any visitor. Revoke it in npm and never ship registry credentials to the browser.'),
    ("mailgun", re.compile(r"key-[0-9a-f]{32}"), "MEDIUM", 5.3,
     'Mailgun API key exposed in web content',
     'A Mailgun API key is embedded in content served to any visitor. Roll the key in Mailgun and send mail from a backend instead.'),
    ("privkey", re.compile(r"BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY"), "CRITICAL", 9.1,
     'Private key exposed in web content',
     'Private key material is served to any visitor. Treat this key as permanently leaked: revoke and replace it, and move signing operations to a server/HSM.'),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
     "MEDIUM", 6.5, 'JWT token exposed in web content',
     'A JWT token (likely a long-lived session/API credential) is embedded in content served to any visitor. Revoke this token and never embed static tokens in client-side code.'),
]

# --- Web Tier B: generic assignment -> candidate ---------------------------
# Group 1 = key name, group 2 = the assigned value (used for the
# denylist + entropy gates; the mobile regex has no value group).
WEB_GENERIC_SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|client[_-]?secret|app[_-]?secret|auth[_-]?token|"
    r"access[_-]?token|private[_-]?key|db[_-]?password|database[_-]?password|"
    r"password|passwd)"
    r"\s*[:=]\s*[\"']([^\"'\s]{12,64})[\"']")

# Canonical published example keys and test-mode keys: never a finding.
GLOBAL_DENIED_VALUES = {
    "AKIAIOSFODNN7EXAMPLE",
}
_DENIED_SUBSTRINGS = (
    "example", "sample", "dummy", "your-", "your_", "xxxx", "****",
    "changeme", "placeholder",
)
_DENIED_PREFIXES = (
    "process.env", "import.meta.env", "config.", "${",
    "sk_test_", "rk_test_", "pk_test_", "whsec_test_",
)
_LOW_ENTROPY_WORDS = ("test", "demo")


def is_denied_secret(value):
    """True when a matched value is a published example, a test-mode key,
    an environment reference, or a placeholder — never a real finding."""
    if not value:
        return True
    if value in GLOBAL_DENIED_VALUES:
        return True
    low = value.lower()
    if any(value.startswith(p) or low.startswith(p) for p in _DENIED_PREFIXES):
        return True
    if any(s in low for s in _DENIED_SUBSTRINGS):
        return True
    if any(w in low for w in _LOW_ENTROPY_WORDS) and len(value) < 24:
        return True
    return False


# =====================================================================
# Secrets Engine v2 (v1.3.0) — TruffleHog-class breadth, VANTHEX proof
# =====================================================================
# Every detector carries: a specific regex, an optional mandatory
# context regex (must match within +/-160 chars), a base tier, and an
# optional LOCAL structural validator. Validators never contact the
# provider (decision D5/K1): they prove the *format* (CRC checksum,
# parseable key material, decodable JWT structure, credential pairing),
# never liveness. Tier ladder: pattern-only = candidate; structurally
# valid format = probable; parsed material / complete pair = confirmed
# EXPOSURE (the description always states liveness was NOT verified).
import zlib

_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _b62_encode(n, width=6):
    out = ""
    while n:
        n, r = divmod(n, 62)
        out = _B62[r] + out
    return out.rjust(width, "0")[-width:]


def github_token_structurally_valid(token):
    """Classic GitHub tokens (ghp_/gho_/ghu_/ghs_/ghr_) end with a
    6-char base62 CRC32 checksum of the preceding 30 chars. Returns
    True (checksum matches), False (right shape, checksum broken), or
    None (shape not checkable). Fine-grained PATs (github_pat_) are
    checkable since v1.7.0 via the same CRC32-Base62 scheme."""
    m = re.match(r"^(?:ghp|gho|ghu|ghs|ghr)_([A-Za-z0-9]{36})$", token or "")
    if m:
        body = m.group(1)
        expect = _b62_encode(zlib.crc32(body[:30].encode("ascii")))
        return body[30:] == expect
    # Fine-grained PAT (v1.7.0, WS3): github_pat_ + a body whose final
    # 6 chars are the CRC32-Base62 checksum of every preceding body
    # char. Same offline structural check as the classic format.
    m = re.match(r"^github_pat_([A-Za-z0-9_]{20,255})$", token or "")
    if not m:
        return None
    body = m.group(1)
    expect = _b62_encode(zlib.crc32(body[:-6].encode("ascii")))
    return body[-6:] == expect


def make_github_pat(payload_len=76):
    """Test helper (v1.7.0): build a structurally valid fine-grained
    PAT with a correct CRC32-Base62 checksum."""
    import random as _r
    chars = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
             "0123456789")
    payload = "".join(_r.choice(chars) for _ in range(payload_len))
    return "github_pat_" + payload + _b62_encode(
        zlib.crc32(payload.encode("ascii")))


def luhn_valid(digits):
    """Luhn checksum over a digit string (v1.7.0, WS3): 12-19 digits,
    not all identical. Offline structural check only — a pass means
    the value is shaped like a real card number, nothing more."""
    ds = [int(c) for c in (digits or "") if c.isdigit()]
    if not (12 <= len(ds) <= 19) or len(set(ds)) == 1:
        return False
    tot = 0
    for i, d in enumerate(reversed(ds)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        tot += d
    return tot % 10 == 0


def bip39_phrase_status(phrase):
    """BIP-39 mnemonic checksum status (v1.7.0, WS3), fully offline:
    "valid" (every word on the official 2048-word list AND the
    checksum embedded in the phrase verifies), "bad_checksum" (all
    words are wordlist words but the checksum does not verify),
    "not_mnemonic" (wrong length or a word is not on the list), or
    None when the vendored wordlist cannot be loaded."""
    try:
        from bip39_words import WORD_INDEX
    except Exception:
        return None
    import hashlib as _hl
    words = (phrase or "").lower().split()
    if len(words) not in (12, 15, 18, 21, 24):
        return "not_mnemonic"
    idx = []
    for w in words:
        i = WORD_INDEX.get(w)
        if i is None:
            return "not_mnemonic"
        idx.append(i)
    bits = "".join(f"{i:011b}" for i in idx)
    ent_len = len(bits) * 32 // 33
    ent = int(bits[:ent_len], 2).to_bytes(ent_len // 8, "big")
    cs = f"{_hl.sha256(ent).digest()[0]:08b}"[:len(bits) - ent_len]
    return "valid" if bits[ent_len:] == cs else "bad_checksum"


def make_github_token(payload30):
    """Test helper: build a classic GitHub token with a valid checksum."""
    body = payload30[:30].ljust(30, "x")
    return "ghp_" + body + _b62_encode(zlib.crc32(body.encode("ascii")))


def parse_jwt(value):
    """Decode a JWT's header/payload locally. Returns a dict with
    alg/claims when the structure is genuinely a JWT, else None.
    Signatures are never verified (no key, no provider contact)."""
    import base64 as _b64
    import json as _json
    parts = (value or "").split(".")
    if len(parts) != 3:
        return None

    def _dec(seg):
        pad = "=" * (-len(seg) % 4)
        return _b64.urlsafe_b64decode((seg + pad).encode("ascii"))

    try:
        header = _json.loads(_dec(parts[0]))
        payload = _json.loads(_dec(parts[1]))
    except Exception:
        return None
    if not isinstance(header, dict) or "alg" not in header:
        return None
    if not isinstance(payload, dict):
        return None
    sig = parts[2]
    # v1.7.0 (WS3): signature FORMAT check only — the segment must be
    # non-empty base64url of a plausible length. This never verifies
    # the signature cryptographically (no key is available or used).
    sig_wellformed = bool(
        sig and re.fullmatch(r"[A-Za-z0-9_-]+", sig) and len(sig) >= 16)
    return {"alg": header.get("alg"), "typ": header.get("typ"),
            "header": header, "claims": payload,
            "signature_empty": len(sig) == 0,
            "signature_wellformed": sig_wellformed}


# AWS secret access key candidate: exactly 40 base64 chars, isolated.
AWS_SECRET_RE = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")


def _D(kind, rx, sev, cvss, title, desc, base="probable", context=None,
       validator=None):
    return {"kind": kind, "regex": re.compile(rx), "severity": sev,
            "cvss": cvss, "title": title, "desc": desc, "base": base,
            "context": re.compile(context, re.I) if context else None,
            "validator": validator}


_REM = ('Revoke/rotate this credential now and move it to a backend or a '
        'secrets manager; never ship secrets in client-side code.')

# The 14 v1.2.0 Tier A detectors, carried over with validator tags.
_V2_CORE = [
    _D("aws", r"(?:AKIA|ASIA)[0-9A-Z]{16}", "HIGH", 7.4,
       'AWS Access Key ID exposed in web content',
       'An AWS access key ID is embedded in content served to any visitor. Treat it as leaked: revoke/rotate it and move AWS calls behind a backend.',
       validator="aws_pair"),
    _D("gcp_api", r"AIza[0-9A-Za-z\-_]{35}", "MEDIUM", 5.3,
       'Google API Key exposed in web content',
       'A Google API key is embedded in content served to any visitor. Restrict the key per API and per application/referrer in Google Cloud Console.'),
    _D("github", r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}",
       "HIGH", 7.4, 'GitHub token exposed in web content',
       'A GitHub access token is embedded in content served to any visitor. Revoke it immediately and never ship source-control credentials to the browser.',
       base="candidate", validator="github_crc"),
    _D("gitlab", r"glpat-[A-Za-z0-9\-_]{20,}", "HIGH", 7.4,
       'GitLab token exposed in web content',
       'A GitLab access token is embedded in content served to any visitor. Revoke it immediately.'),
    _D("slack_token", r"xox[baprs]-[A-Za-z0-9\-]{10,}", "HIGH", 7.4,
       'Slack token exposed in web content',
       'A Slack API token is embedded in content served to any visitor. Revoke it in the Slack app configuration.'),
    _D("slack_webhook", r"https://hooks\.slack\.com/services/T[A-Za-z0-9]{8,}/B[A-Za-z0-9]{8,}/[A-Za-z0-9]{24}",
       "MEDIUM", 5.3, 'Slack webhook URL exposed in web content',
       'A Slack incoming-webhook URL is embedded in content served to any visitor — anyone can post to that channel with it.'),
    _D("stripe_live", r"(?:sk|rk)_live_[A-Za-z0-9]{16,}", "HIGH", 7.4,
       'Stripe live secret key exposed in web content',
       'A Stripe LIVE secret/restricted key is embedded in content served to any visitor. Roll it immediately; only publishable keys may ship to the browser.'),
    _D("sendgrid", r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "HIGH", 7.4,
       'SendGrid API key exposed in web content',
       'A SendGrid API key is embedded in content served to any visitor. Revoke it and send mail from a backend.'),
    _D("telegram_bot", r"[0-9]{6,}:[A-Za-z0-9_\-]{35}", "MEDIUM", 6.5,
       'Telegram bot token exposed in web content',
       'A Telegram bot token is embedded in content served to any visitor — it gives full control of the bot. Revoke it via BotFather.'),
    _D("discord_webhook", r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,}/[A-Za-z0-9_\-]{60,}",
       "MEDIUM", 5.3, 'Discord webhook URL exposed in web content',
       'A Discord webhook URL is embedded in content served to any visitor — anyone can post to that channel.'),
    _D("npm", r"npm_[A-Za-z0-9]{36}", "HIGH", 7.4,
       'npm token exposed in web content',
       'An npm access token is embedded in content served to any visitor. Revoke it in npm.'),
    _D("mailgun", r"key-[0-9a-f]{32}", "MEDIUM", 5.3,
       'Mailgun API key exposed in web content',
       'A Mailgun API key is embedded in content served to any visitor. Roll it and send mail from a backend.'),
    _D("privkey", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
       "CRITICAL", 9.1, 'Private key exposed in web content',
       'Private key material is served to any visitor. Treat this key as permanently leaked: revoke and replace it.',
       base="candidate", validator="pem_parse"),
    _D("jwt", r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{0,}",
       "MEDIUM", 6.5, 'JWT token exposed in web content',
       'A JWT token is embedded in content served to any visitor. Revoke this token and never embed static tokens in client-side code.',
       base="candidate", validator="jwt_struct"),
]

_V2_NEW = [
    _D("gitlab_runner", r"glrt-[A-Za-z0-9\-_]{20,}", "HIGH", 7.4,
       'GitLab runner token exposed in web content',
       'A GitLab runner registration/authentication token is publicly served. Revoke it in GitLab.'),
    _D("slack_app", r"xapp-[A-Za-z0-9\-]{20,}", "HIGH", 7.4,
       'Slack app token exposed in web content',
       'A Slack app-level token (xapp-) is publicly served; it can manage app connections. Revoke it.'),
    _D("stripe_webhook", r"whsec_[A-Za-z0-9]{32,}", "MEDIUM", 5.3,
       'Stripe webhook secret exposed in web content',
       'A Stripe webhook signing secret is publicly served; anyone can forge webhook events. Roll it in Stripe.'),
    _D("twilio", r"SK[0-9a-f]{32}", "HIGH", 7.4,
       'Twilio API key exposed in web content',
       'A Twilio API key SID is publicly served together with its secret context. Revoke it in Twilio.'),
    _D("mailchimp", r"[0-9a-f]{32}-us[0-9]{1,2}", "MEDIUM", 5.3,
       'Mailchimp API key exposed in web content',
       'A Mailchimp API key is publicly served. Revoke it in Mailchimp.'),
    _D("brevo", r"xkeysib-[A-Za-z0-9\-]{80,}", "HIGH", 7.4,
       'Brevo API key exposed in web content',
       'A Brevo (Sendinblue) API key is publicly served. Revoke it in Brevo.'),
    _D("postman", r"PMAK-[0-9a-fA-F]{24}-[0-9a-fA-F\-]{30,}", "HIGH", 7.4,
       'Postman API key exposed in web content',
       'A Postman API key is publicly served; it grants access to the owner\'s Postman workspaces. Revoke it.'),
    _D("grafana_sa", r"glsa_[A-Za-z0-9]{32}_[0-9a-f]{8}", "HIGH", 7.4,
       'Grafana service account token exposed in web content',
       'A Grafana service account token is publicly served. Revoke it in Grafana.'),
    _D("grafana_cloud", r"glc_[A-Za-z0-9+/=_-]{40,}", "HIGH", 7.4,
       'Grafana Cloud API key exposed in web content',
       'A Grafana Cloud API key is publicly served. Revoke it in Grafana Cloud.'),
    _D("linear", r"lin_api_[A-Za-z0-9]{40}", "HIGH", 7.4,
       'Linear API key exposed in web content',
       'A Linear API key is publicly served. Revoke it in Linear settings.'),
    _D("anthropic", r"sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_\-]{80,}", "HIGH", 7.4,
       'Anthropic API key exposed in web content',
       'An Anthropic API key is publicly served. Revoke it in the Anthropic console.'),
    _D("openai", r"sk-(?!live_|test_)(?:proj-)?[A-Za-z0-9_\-]{48,}", "HIGH", 7.4,
       'OpenAI API key exposed in web content',
       'An OpenAI API key is publicly served; anyone can spend the account\'s quota. Revoke it in OpenAI.'),
    _D("huggingface", r"hf_[A-Za-z0-9]{34,}", "HIGH", 7.4,
       'Hugging Face token exposed in web content',
       'A Hugging Face access token is publicly served. Revoke it in Hugging Face settings.'),
    _D("replicate", r"r8_[A-Za-z0-9]{30,}", "HIGH", 7.4,
       'Replicate API token exposed in web content',
       'A Replicate API token is publicly served. Revoke it in Replicate.'),
    _D("groq", r"gsk_[A-Za-z0-9]{48,}", "HIGH", 7.4,
       'Groq API key exposed in web content',
       'A Groq API key is publicly served. Revoke it in the Groq console.'),
    _D("db_uri", r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|rediss?|amqp)://[^\s:/@]{1,64}:[^\s/@]{3,64}@[^\s/\"']+",
       "HIGH", 8.1, 'Database/service URI with embedded credentials exposed',
       'A connection URI containing a plaintext password is publicly served. Rotate the credential and remove it from client-visible content.'),
    _D("uri_creds", r"(?:https?|ftp)://[^\s:/@]{1,64}:[^\s/@]{3,64}@[^\s/\"']+",
       "MEDIUM", 5.3, 'URL with embedded credentials exposed',
       'A URL embedding a username and password is publicly served. Rotate the password and use a secrets manager instead.',
       base="candidate"),
    _D("docker_hub", r"dckr_pat_[A-Za-z0-9_\-]{27,}", "HIGH", 7.4,
       'Docker Hub access token exposed in web content',
       'A Docker Hub personal access token is publicly served. Revoke it in Docker Hub.'),
    _D("vault", r"(?:hvs|hvb)\.[A-Za-z0-9]{24,}", "HIGH", 8.1,
       'HashiCorp Vault token exposed in web content',
       'A Vault service/batch token is publicly served. Revoke it immediately in Vault.'),
    _D("newrelic", r"NRAK-[A-Za-z0-9]{27}", "HIGH", 7.4,
       'New Relic API key exposed in web content',
       'A New Relic user API key is publicly served. Revoke it in New Relic.'),
    _D("digitalocean", r"dop_v1_[0-9a-f]{64}", "HIGH", 7.4,
       'DigitalOcean token exposed in web content',
       'A DigitalOcean personal access token is publicly served. Revoke it in DigitalOcean.'),
    _D("shopify", r"shp(?:at|ca|pa|ss)_[0-9a-f]{32}", "HIGH", 7.4,
       'Shopify access token exposed in web content',
       'A Shopify app/admin access token is publicly served. Revoke it in Shopify.'),
    _D("square", r"sq0(?:atp|csp)-[A-Za-z0-9_\-]{22,}", "HIGH", 7.4,
       'Square access token exposed in web content',
       'A Square access token is publicly served. Revoke it in the Square developer dashboard.'),
    _D("discord_bot", r"[MN][A-Za-z0-9]{23,28}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}",
       "HIGH", 7.4, 'Discord bot token exposed in web content',
       'A Discord bot token is publicly served — it gives full control of the bot. Reset it in the Discord developer portal.'),
    _D("facebook", r"EAACEdEose0cBA[A-Za-z0-9]{20,}", "MEDIUM", 5.3,
       'Facebook access token exposed in web content',
       'A Facebook access token is publicly served. Invalidate it and review the app\'s token handling.'),
    _D("dropbox", r"sl\.[A-Za-z0-9_\-]{130,}", "MEDIUM", 5.3,
       'Dropbox access token exposed in web content',
       'A Dropbox short-lived access token is publicly served. Revoke the app authorization in Dropbox.'),
    _D("google_oauth_secret", r"GOCSPX-[A-Za-z0-9_\-]{28,}", "HIGH", 7.4,
       'Google OAuth client secret exposed in web content',
       'A Google OAuth client secret is publicly served. Reset it in Google Cloud Console.'),
    _D("google_oauth_token", r"ya29\.[A-Za-z0-9_\-]{20,}", "MEDIUM", 6.5,
       'Google OAuth access token exposed in web content',
       'A Google OAuth access token is publicly served. Revoke it and never embed user tokens in client code.'),
    _D("age_key", r"AGE-SECRET-KEY-1[0-9a-z]{58}", "HIGH", 8.1,
       'age encryption secret key exposed in web content',
       'An age secret key is publicly served; all data encrypted to its recipient can be decrypted. Treat it as leaked.'),
    _D("pgp_privkey", r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
       "CRITICAL", 9.1, 'PGP private key exposed in web content',
       'PGP private key material is served to any visitor. Treat this key as permanently leaked: revoke and replace it.',
       base="candidate", validator="pem_parse"),
    # v1.7.0 (WS3): checksum-validated look-alike classes. Both are
    # context-gated and validator-driven (K4: a failed checksum
    # demotes the tier, it never deletes the finding).
    _D("card_number",
       r"(?<![0-9A-Za-z])(?:\d{4}[ -]?){3}\d{4}(?![0-9A-Za-z])"
       r"|(?<![0-9])\d{13,19}(?![0-9])",
       "HIGH", 7.4, 'Payment card number exposed in web content',
       'A value shaped like a payment card number appears in publicly served content, near payment/card wording. The Luhn checksum is checked locally only; the value was NOT validated with any issuer.',
       base="probable",
       context=r"(?i)\b(card|credit|visa|mastercard|amex|payment|cc[-_ ]?num)\b",
       validator="luhn"),
    _D("seed_phrase",
       r"(?:\b[a-z]{3,8}\b[ \t]+){11,23}[a-z]{3,8}\b",
       "CRITICAL", 9.1, 'Cryptocurrency seed phrase exposed in web content',
       'A word sequence near seed/mnemonic wording consists entirely of BIP-39 wordlist words. If the embedded BIP-39 checksum verifies, this is a structurally valid wallet seed phrase: anyone who sees it controls the wallet. The checksum is verified locally only.',
       base="candidate",
       context=r"(?i)\b(seed phrase|mnemonic|recovery phrase|backup phrase|wallet)\b",
       validator="bip39"),
    _D("mapbox_secret", r"sk\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
       "MEDIUM", 5.3, 'Mapbox secret token exposed in web content',
       'A Mapbox secret-scoped token is publicly served. Revoke it in Mapbox.'),
    _D("airtable", r"pat[A-Za-z0-9]{14}\.[0-9a-f]{64}", "HIGH", 7.4,
       'Airtable personal access token exposed in web content',
       'An Airtable PAT is publicly served. Revoke it in Airtable.'),
    _D("notion", r"(?:ntn|secret)_[A-Za-z0-9]{43,50}", "HIGH", 7.4,
       'Notion integration token exposed in web content',
       'A Notion integration token is publicly served. Regenerate it in Notion.'),
    _D("figma", r"figd_[A-Za-z0-9_\-]{40,}", "HIGH", 7.4,
       'Figma access token exposed in web content',
       'A Figma personal access token is publicly served. Revoke it in Figma.'),
    _D("planetscale", r"pscale_(?:tkn|pw)_[A-Za-z0-9]{40,}", "HIGH", 7.4,
       'PlanetScale token exposed in web content',
       'A PlanetScale token/password is publicly served. Revoke it in PlanetScale.'),
    _D("supabase", r"sbp_[0-9a-f]{40}", "HIGH", 7.4,
       'Supabase access token exposed in web content',
       'A Supabase management access token is publicly served. Revoke it in Supabase.'),
    _D("cloudinary", r"cloudinary://[0-9]{10,}:[A-Za-z0-9_\-]{20,}@[^\s/\"']+",
       "MEDIUM", 5.3, 'Cloudinary URI with credentials exposed',
       'A Cloudinary environment URI containing the API secret is publicly served. Rotate the secret.'),
    _D("fcm", r"AAAA[A-Za-z0-9_\-]{7,}:[A-Za-z0-9_\-]{100,}", "MEDIUM", 5.3,
       'Firebase Cloud Messaging server key exposed in web content',
       'An FCM legacy server key is publicly served; anyone can push messages to the app. Rotate it in Firebase.'),
    _D("buildkite", r"bkua_[0-9a-f]{32,}", "HIGH", 7.4,
       'Buildkite API token exposed in web content',
       'A Buildkite API token is publicly served. Revoke it in Buildkite.'),
    _D("doppler", r"dp\.(?:st|sa)\.[A-Za-z0-9_\-]{40,}", "HIGH", 7.4,
       'Doppler token exposed in web content',
       'A Doppler service token is publicly served; it reads project secrets. Revoke it in Doppler.'),
    _D("pulumi", r"pul-[0-9a-f]{40}", "HIGH", 7.4,
       'Pulumi access token exposed in web content',
       'A Pulumi access token is publicly served. Revoke it in Pulumi Cloud.'),
    _D("pypi", r"pypi-[A-Za-z0-9_\-]{50,}", "HIGH", 7.4,
       'PyPI API token exposed in web content',
       'A PyPI upload token is publicly served. Revoke it in PyPI.'),
    _D("nuget", r"oy2[a-z0-9]{43,}", "MEDIUM", 5.3,
       'NuGet API key exposed in web content',
       'A NuGet API key is publicly served. Revoke it in NuGet.'),
    _D("rubygems", r"rubygems[0-9a-f]{48}", "HIGH", 7.4,
       'RubyGems API key exposed in web content',
       'A RubyGems API key is publicly served. Revoke it in RubyGems.'),
    _D("pinecone", r"pcsk_[A-Za-z0-9_\-]{30,}", "MEDIUM", 5.3,
       'Pinecone API key exposed in web content',
       'A Pinecone API key is publicly served. Revoke it in Pinecone.'),
    _D("langsmith", r"lsv2_(?:pt|sk)_[A-Za-z0-9_\-]{30,}", "MEDIUM", 5.3,
       'LangSmith API key exposed in web content',
       'A LangSmith API key is publicly served. Revoke it in LangSmith.'),
    _D("gcp_service_account", r"\"type\"\s*:\s*\"service_account\"",
       "HIGH", 8.1, 'GCP service account key file exposed in web content',
       'A Google Cloud service account key document is publicly served. Revoke the key and audit the account.',
       base="candidate", validator="gcp_sa"),
    _D("basic_auth_literal", r"(?i)authorization[\"'\s:=]+basic\s+[A-Za-z0-9+/]{16,}={0,2}",
       "MEDIUM", 5.3, 'Hardcoded Basic authorization credential in web content',
       'A literal Basic authorization credential is embedded in publicly served content. Rotate the password.',
       base="candidate"),
    # --- context-mandatory detectors (bare formats, keyword-gated) ---
    _D("azure_secret", r"(?<![A-Za-z0-9~._\-])[A-Za-z0-9~._\-]{40}(?![A-Za-z0-9~._\-])", "HIGH", 7.4,
       'Possible Azure client secret exposed in web content',
       'A 40-char value in an explicit Azure/client-secret context is publicly served. Verify and rotate it in Entra ID if real.',
       base="candidate", context=r"azure|client[_ ]?secret|tenant[_ ]?id"),
    _D("cloudflare_token", r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{40}(?![A-Za-z0-9_\-])", "MEDIUM", 5.3,
       'Possible Cloudflare API token exposed in web content',
       'A 40-char value in an explicit Cloudflare context is publicly served. Verify and rotate it if real.',
       base="candidate", context=r"cloudflare|cf[_-]?api[_-]?token"),
    _D("sentry_token", r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", "MEDIUM", 5.3,
       'Possible Sentry auth token exposed in web content',
       'A 64-hex value in an explicit Sentry context is publicly served. Verify and rotate it if real.',
       base="candidate", context=r"sentry"),
    _D("eth_privkey", r"0x[0-9a-fA-F]{64}", "HIGH", 8.1,
       'Possible Ethereum private key exposed in web content',
       'A 32-byte hex value in an explicit private-key/wallet context is publicly served. If real, move the funds and rotate.',
       base="candidate", context=r"private[_ ]?key|wallet|seed phrase|mnemonic"),
    _D("heroku", r"(?<![0-9a-f\-])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f\-])",
       "MEDIUM", 5.3, 'Possible Heroku API key exposed in web content',
       'A UUID in an explicit Heroku context is publicly served. Verify and rotate it if real.',
       base="candidate", context=r"heroku"),
    _D("postmark", r"(?<![0-9a-f\-])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f\-])",
       "MEDIUM", 5.3, 'Possible Postmark server token exposed in web content',
       'A UUID in an explicit Postmark context is publicly served. Verify and rotate it if real.',
       base="candidate", context=r"postmark"),
    _D("datadog", r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", "MEDIUM", 5.3,
       'Possible Datadog API key exposed in web content',
       'A 32-hex value in an explicit Datadog context is publicly served. Verify and rotate it if real.',
       base="candidate", context=r"datadog|dd[_-]?api[_-]?key"),
    _D("twilio_auth", r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", "MEDIUM", 5.3,
       'Possible Twilio auth token exposed in web content',
       'A 32-hex value in an explicit Twilio context is publicly served. Verify and rotate it if real.',
       base="candidate", context=r"twilio"),
    _D("slack_signing", r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", "MEDIUM", 5.3,
       'Possible Slack signing secret exposed in web content',
       'A 32-hex value in an explicit Slack context is publicly served. Verify and rotate it if real.',
       base="candidate", context=r"slack"),
    _D("resend", r"re_[A-Za-z0-9]{32,}", "MEDIUM", 5.3,
       'Possible Resend API key exposed in web content',
       'An re_-prefixed value in an explicit Resend context is publicly served. Verify and rotate it if real.',
       base="candidate", context=r"resend"),
]

# Full v2 detector list: 14 core + new = the web secrets battery.
DETECTORS_V2 = _V2_CORE + _V2_NEW

# Extra published-example values per provider (never findings).
EXTRA_DENIED_VALUES = {
    "<redacted>", "<redacted>",
    "<redacted>", "sk_live_1234567890abcdefghij",
    "whsec_1234567890abcdefghijklmnopqrstuv", "xoxb-123456789012-1234567890123",
    "GOCSPX-1234567890abcdefghijklmnopqrstuv",
    "AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE",
}
GLOBAL_DENIED_VALUES |= EXTRA_DENIED_VALUES

