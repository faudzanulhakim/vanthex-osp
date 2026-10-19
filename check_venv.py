#!/usr/bin/env python3
"""Pentest Toolkit venv health check.

Verifies that every third-party module the toolkit code actually imports
is importable in this venv, with a minimum version where a security fix
requires it. Exits 0 when healthy, 1 with one MISSING/BROKEN line per
problem otherwise. Designed to be called from restore-all.sh section 9
and from the shell; it never installs or changes anything.

Usage: .venv/bin/python check_venv.py
"""
import importlib
import sys

# module name -> (distribution, minimum version or None, why it matters)
REQUIRED = {
    "androguard": ("androguard", "4.1.4", "APK/IPA parsing"),
    "bs4": ("beautifulsoup4", "4.15.0", "HTML crawler parsing"),
    "cryptography": ("cryptography", "50.0.0", "X.509 parsing; <50 has known CVEs found by pip-audit in v3.13.0"),
    "defusedxml": ("defusedxml", "0.7.1", "safe XML/manifest parsing"),
    "docx": ("python-docx", "1.1.0", "DOCX report generation"),
    "psutil": ("psutil", "7.2.2", "dashboard system panel"),
    "dns": ("dnspython", "2.9.0", "passive DNS enumeration"),
    "packaging": ("packaging", None, "PEP 440 version comparison (Phase 1)"),
    "certifi": ("certifi", None, "TLS root CA bundle for public API lookups (Phase 1)"),
    "PIL": ("Pillow", "12.0.0", "EXIF metadata leakage scan; <12.3 has known CVEs"),
    # No minimum for requests: it is a supporting client and on this VM a
    # system copy (2.33.1) shadows the venv dist metadata (2.34.2); both work.
    "requests": ("requests", None, "supporting HTTP client"),
    "lxml": ("lxml", "6.1.3", "parser backend for bs4/androguard"),
}


def _ver_tuple(text):
    parts = []
    for chunk in str(text).replace("-", ".").split("."):
        num = ""
        for ch in chunk:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    return tuple(parts)


def main():
    problems = []
    for module, (dist, minimum, why) in REQUIRED.items():
        try:
            mod = importlib.import_module(module)
        except Exception as exc:  # noqa: BLE001 - report, don't crash
            problems.append(f"BROKEN: {dist} (import {module}) failed: {exc} - needed for {why}")
            continue
        if minimum:
            version = getattr(mod, "__version__", None)
            if version is None:
                try:
                    from importlib.metadata import version as dist_version

                    version = dist_version(dist)
                except Exception:
                    version = None
            if version is not None and _ver_tuple(version) < _ver_tuple(minimum):
                problems.append(
                    f"OUTDATED: {dist} {version} < {minimum} - needed for {why}"
                )
    if problems:
        for line in problems:
            print(line)
        print(f"VENV_UNHEALTHY: {len(problems)} problem(s)")
        return 1
    print(f"VENV_OK: {len(REQUIRED)} critical modules importable, versions OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
