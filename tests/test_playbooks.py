"""Tests for playbooks.py — runbook generator (no execution)."""
import pytest

from offensive import playbooks
from offensive.playbooks import (
    generate_runbook,
    render_runbook_markbook,
    render_runbook_markdown,
)


TARGET = "https://test.example.com"


def _cmdi_finding():
    return {"id": "F-1", "severity": "CRITICAL",
            "title": "Command injection in /api/exec",
            "description": "User input passed to os.system allows command "
                           "execution (CMDi)."}


def test_cmdi_runbook_structure():
    rb = generate_runbook(_cmdi_finding(), TARGET)
    assert rb["finding_ref"] == "F-1"
    assert rb["class"] == "rce"
    assert rb["authorized_only"] is True
    assert "AUTHORIZED TESTING ONLY" in rb["header"]
    steps = rb["playbook_steps"]
    assert len(steps) >= 4
    # ordered steps
    assert [s["n"] for s in steps] == list(range(1, len(steps) + 1))
    for s in steps:
        assert s["description"] and s["command"]
        assert s["authorized_only"] is True
    # opsec notes, cleanup, evidence all present
    assert rb["opsec_notes"] and rb["cleanup_steps"] and rb["evidence_to_capture"]


def test_cmdi_header_and_every_step_has_command():
    rb = generate_runbook(_cmdi_finding(), TARGET)
    assert rb["header"].startswith("AUTHORIZED TESTING ONLY")
    assert all(s.get("command") for s in rb["playbook_steps"])


def test_sqli_maps_db_enum():
    rb = generate_runbook({"id": "F-2", "title": "SQL injection (error-based)",
                           "description": "Error-based SQLi on /item id param"},
                          TARGET)
    assert rb["class"] == "sqli"
    joined = " ".join(s["title"] + " " + s["description"] for s in rb["playbook_steps"])
    assert "enumerat" in joined.lower()
    assert "dump scope" in joined.lower()
    assert "blast radius" in joined.lower()
    assert any("CONVERT" in s["command"] for s in rb["playbook_steps"])


def test_ssrf_maps_cloud_metadata_per_provider():
    rb = generate_runbook({"id": "F-3", "title": "SSRF to cloud metadata",
                           "description": "Server-side request forgery can "
                                          "reach the metadata endpoint"},
                          TARGET)
    assert rb["class"] == "ssrf_cloud"
    cmds = " ".join(s["command"] for s in rb["playbook_steps"])
    assert "169.254.169.254" in cmds          # AWS / Azure
    assert "metadata.google.internal" in cmds  # GCP
    assert "Metadata: true" in cmds            # Azure header
    assert "Metadata-Flavor: Google" in cmds   # GCP header
    assert any("IAM role" in s["title"] or "IAM" in s["description"]
               for s in rb["playbook_steps"])
    assert rb["opsec_notes"]  # guardrail notes present


def test_xss_runbook():
    rb = generate_runbook({"title": "Stored XSS in comment field",
                           "description": "Cross-site scripting (XSS) via comment"},
                          TARGET)
    assert rb["class"] == "xss"
    joined = " ".join(s["title"] for s in rb["playbook_steps"]).lower()
    assert "session" in joined and "admin" in joined


def test_idor_runbook():
    rb = generate_runbook({"title": "IDOR on order object",
                           "description": "Insecure direct object reference "
                                          "allows access control bypass"},
                          TARGET)
    assert rb["class"] == "idor"
    joined = " ".join(s["title"] + s["description"] for s in rb["playbook_steps"]).lower()
    assert "enumeration" in joined and "classif" in joined


def test_generic_default():
    rb = generate_runbook({"title": "Unusual header", "description": "Odd behavior"},
                          TARGET)
    assert rb["class"] == "generic"
    assert rb["playbook_steps"]


def test_never_raises_on_bad_input():
    assert generate_runbook(None, None)["authorized_only"] is True
    assert generate_runbook({}, "")["class"] == "generic"


def test_render_produces_markdown():
    rb = generate_runbook(_cmdi_finding(), TARGET)
    md = render_runbook_markdown(rb)
    assert "# Post-exploitation runbook" in md
    assert "AUTHORIZED TESTING ONLY" in md
    assert "## Playbook steps" in md
    assert "## OPSEC notes" in md
    assert "## Cleanup steps" in md
    assert "## Evidence to capture" in md
    assert "```" in md
    assert TARGET in md


def test_render_markbook_alias():
    rb = generate_runbook(_cmdi_finding(), TARGET)
    assert render_runbook_markbook(rb) == render_runbook_markdown(rb)


def test_render_never_raises():
    assert render_runbook_markdown(None) != ""
    assert render_runbook_markdown({}) != ""
