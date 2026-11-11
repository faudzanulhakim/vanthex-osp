"""
WordMint v1 — target-specific wordlist generator for VANTHEX. Read-only.

Builds password/subdomain candidates TAILORED to the target (company
name, years, leetspeak, domain scheme) from OSINT seeds — far more
efficient than generic wordlists. Pure module (no network), all
generators bounded.
"""

LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
SUB_PREFIXES = ("www", "mail", "remote", "vpn", "dev", "test", "staging",
                "api", "admin", "portal", "git", "jenkins", "old", "backup",
                "intranet", "crm", "erp", "files", "share", "support")
YEARS = (2023, 2024, 2025, 2026)
SYMBOLS = ("!", "@", "#", "1!", "123", "!123")

MAX_PASSWORDS = 400      # hard candidate limit
MAX_SUBDOMAINS = 60


def _leet(word):
    out = word
    for a, b in LEET.items():
        out = out.replace(a, b)
    return out


def mint_passwords(company, extra_seeds=(), years=YEARS, leet=True):
    """Target-specific password candidates: <name><year><symbol>, capitalization
    variants, leetspeak. Bounded (max MAX_PASSWORDS, unique, stable order)."""
    base = re_clean(company or "")
    seeds = [base] + [re_clean(s) for s in extra_seeds if s]
    seeds = [s for s in seeds if s][:6]
    out, seen = [], set()
    for seed in seeds:
        variants = [seed, seed.capitalize(), seed.upper()]
        if leet:
            variants.append(_leet(seed))
            variants.append(_leet(seed).capitalize())
        for v in variants:
            for y in years:
                for sym in SYMBOLS:
                    cand = f"{v}{y}{sym}"
                    if cand not in seen:
                        seen.add(cand)
                        out.append(cand)
                        if len(out) >= MAX_PASSWORDS:
                            return out
    return out


def mint_subdomains(domain):
    """Subdomain candidates: common prefixes + <prefix>-<env> combos + digits.
    Bounded (max MAX_SUBDOMAINS) — for external resolver/DNS brute-forcing."""
    # domain: keep dots (re_clean strips them — regression from v1.5.0)
    import re as _re2
    d = _re2.sub(r"[^a-z0-9.-]", "", str(domain or "").lower()).strip(".")
    if not d or "." not in d:
        return []
    out, seen = [], set()
    for p in SUB_PREFIXES:
        for cand in (f"{p}.{d}", f"{p}2.{d}", f"{p}-dev.{d}"):
            if cand not in seen:
                seen.add(cand)
                out.append(cand)
                if len(out) >= MAX_SUBDOMAINS:
                    return out
    return out


def re_clean(s):
    """Normalize seed: alphanumeric only, lowercase, strip whitespace."""
    import re as _re
    return _re.sub(r"[^a-z0-9]", "", str(s).lower())
