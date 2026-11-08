"""SARIF 2.1.0 export for VANTHEX findings.

AUTHORIZED TESTING ONLY. Converts the platform's finding dicts into a
SARIF 2.1.0 log so results can be ingested by GitHub Code Scanning,
Visual Studio, and other SARIF-aware tooling.

Level mapping:
    CRITICAL / HIGH -> "error"
    MEDIUM          -> "warning"
    everything else -> "note"

ruleId comes from the finding's CWE when present, otherwise a slugified
title. severity / cvss / priority are preserved under result.properties.
"""
import re

SARIF_SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                "master/Schemata/sarif-schema-2.1.0.json")

_LEVELS = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning"}


def _slug(title):
    s = re.sub(r"[^a-z0-9]+", "-", str(title or "finding").lower()).strip("-")
    return s or "finding"


def _level(f):
    return _LEVELS.get(str(f.get("severity") or "").upper(), "note")


def _uri(location):
    """Return the location string when it looks like a URL/path URI."""
    loc = str(location or "")
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", loc):
        return loc
    if loc.startswith("/") and ("@" not in loc) and ("#" not in loc):
        return loc
    return ""


def _rule_for(f):
    cwe = str(f.get("cwe") or "")
    m = re.search(r"(\d{2,5})", cwe)
    if m:
        return "CWE-" + m.group(1)
    return _slug(f.get("title"))


def findings_to_sarif(findings, scan_meta=None):
    """Convert a findings list into a SARIF 2.1.0 dict.

    scan_meta (optional dict) may carry: target, profile, started_at,
    tool (tool name), version. Never raises on individual findings.
    """
    findings = findings if isinstance(findings, list) else []
    meta = scan_meta if isinstance(scan_meta, dict) else {}

    rules = {}
    results = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        rule_id = _rule_for(f)
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": str(f.get("title") or rule_id)[:200]},
                "helpUri": (f"https://cwe.mitre.org/data/definitions/"
                            f"{rule_id.split('-')[1]}.html"
                            if rule_id.startswith("CWE-") else ""),
            }
        msg = " ".join(x for x in [str(f.get("title") or ""),
                                   str(f.get("description") or "")] if x).strip()
        result = {
            "ruleId": rule_id,
            "level": _level(f),
            "message": {"text": msg or "(no description)"},
            "properties": {
                "severity": f.get("severity"),
                "cvss": f.get("cvss"),
                "priority": f.get("priority"),
            },
        }
        uri = _uri(f.get("location"))
        if uri:
            physical = {"artifactLocation": {"uri": uri}}
            if f.get("param"):
                physical["region"] = {
                    "snippet": {"text": str(f.get("param"))[:200]}}
            result["locations"] = [{"physicalLocation": physical}]
        results.append(result)

    tool_meta = {"name": str(meta.get("tool") or "VANTHEX")}
    if meta.get("version"):
        tool_meta["version"] = str(meta["version"])

    invocations = []
    driver_props = {}
    if meta.get("target"):
        driver_props["target"] = str(meta["target"])
    if meta.get("profile"):
        driver_props["profile"] = str(meta["profile"])
    if driver_props:
        invocations.append({"properties": driver_props})

    driver = dict(tool_meta)
    if rules:
        driver["rules"] = list(rules.values())
    run = {
        "tool": {"driver": driver},
        "results": results,
    }
    if invocations:
        run["invocations"] = invocations
    if meta.get("started_at"):
        run.setdefault("properties", {})["startedAt"] = str(meta["started_at"])

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }
