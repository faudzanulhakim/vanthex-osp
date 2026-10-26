"""v1.2.1 docker routing — artifact UI as the default at /.

REWRITTEN 2026-10-26 (artifact-UI port, ADE 09:50 WIB). This file
previously pinned the classic dashboard (templates/app.html) as the
default at / with /classic as its alias. That is SUPERSEDED:
- / serves the artifact UI bundle (artifact-ui/index.html, currently
  a marked placeholder until the coordinator integrates the real
  bundle — see tests/test_v1_2_1_artifact_docker.py);
- /classic is REMOVED entirely (no route branch; it falls through to
  the 404 tail) and templates/app.html is DELETED;
- /webui keeps the legacy SPA under the same admin + ACTIONS_OK gate;
  its fallback is now the artifact UI, not classic (classic no longer
  exists to fall back to).

What is retained from the old file, unchanged: the compose feed-key
env vars, the .env.example comment-only placeholders, the webui
bundle/index pins, and the osint.py pin.

Hermetic: reads files from this tree only. Live behaviour
(authenticated fetch of /, /classic, /webui) is verified separately
at deploy time, not in this file.
"""
import hashlib
import os

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP2 = os.path.join(TREE, "app2.py")
COMPOSE = os.path.join(TREE, "docker-compose.deploy.yml")
ENV_EXAMPLE = os.path.join(TREE, ".env.example")

MD5_OSINT = "65ec21c31b4aad76aa304fcb411388ae"
MD5_WEBUI_BUNDLE = "1751c095c5decc17c80907283fb6635d"
MD5_WEBUI_INDEX = "d67036f15cbaf4efaac6f2153a910260"


def md5_of(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def route_branch(src, header):
    """Source lines of one routing branch, from its header line up to
    (not including) the next elif at the same indent."""
    lines = src.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip() == header:
            start = i
            break
    assert start is not None, "missing route branch: %s" % header
    block = [lines[start]]
    for line in lines[start + 1:]:
        if line.startswith("        elif path"):
            break
        block.append(line)
    return "\n".join(block)


def test_root_serves_artifact_ui_not_classic():
    with open(APP2, encoding="utf-8") as fh:
        src = fh.read()
    block = route_branch(src, 'if path == "/":')
    assert 'artifact_file("index.html")' in block
    assert '("Cache-Control", "no-store")' in block
    assert "app.html" not in block
    assert "webui_file" not in block


def test_classic_removed_entirely():
    with open(APP2, encoding="utf-8") as fh:
        src = fh.read()
    assert 'path == "/classic"' not in src
    assert not os.path.exists(os.path.join(TREE, "templates", "app.html"))
    # No route may still reference the deleted template.
    assert 'load_template("app.html")' not in src


def test_webui_moved_gate_unchanged_fallback_is_artifact():
    with open(APP2, encoding="utf-8") as fh:
        src = fh.read()
    block = route_branch(src, 'elif path == "/webui":')
    assert 'sess.get("role") == "admin" and ACTIONS_OK' in block
    assert 'webui_file("index.html")' in block
    assert '("Cache-Control", "no-store")' in block
    # Fallback is the artifact UI now (classic is gone).
    assert 'artifact_file("index.html")' in block


def test_artifact_assets_route_present():
    with open(APP2, encoding="utf-8") as fh:
        src = fh.read()
    assert 'elif path.startswith("/artifact-assets/"):' in src
    assert "artifact_file" in src
    assert "_artifact_cache_header" in src


def test_webui_index_served_from_exactly_one_place():
    with open(APP2, encoding="utf-8") as fh:
        src = fh.read()
    assert src.count('webui_file("index.html")') == 1


def test_other_routes_untouched():
    with open(APP2, encoding="utf-8") as fh:
        src = fh.read()
    assert 'if path == "/login":' in src
    # /actions lives in the POST handler (if, not elif) — untouched.
    assert 'if path == "/actions":' in src
    assert 'elif path.startswith("/assets/"):' in src
    assert 'elif path.startswith("/vendor/"):' in src


def test_compose_deploy_has_feed_key_env():
    with open(COMPOSE, encoding="utf-8") as fh:
        content = fh.read()
    assert "VANTHEX_FIRMS_MAP_KEY: ${VANTHEX_FIRMS_MAP_KEY:-}" in content
    assert "VANTHEX_ABUSECH_AUTH_KEY: ${VANTHEX_ABUSECH_AUTH_KEY:-}" in content


def test_env_example_documents_keys_as_empty_assignments():
    # 2026-10-26 (ADE order): feed keys are EMPTY assignments, not
    # comments-only, so `cp .env.example .env` yields fillable lines.
    # The standing security rule is unchanged: NO VALUE may ever be
    # committed here — values live only in the deployer's own .env.
    with open(ENV_EXAMPLE, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    for key in ("VANTHEX_FIRMS_MAP_KEY", "VANTHEX_ABUSECH_AUTH_KEY"):
        hits = [ln for ln in lines if key in ln]
        assert hits, "missing placeholder for %s" % key
        assigns = [ln for ln in hits if not ln.lstrip().startswith("#")]
        assert assigns == [key + "="], key


def test_protected_files_byte_identical():
    assert md5_of(os.path.join(TREE, "osint.py")) == MD5_OSINT
    assert md5_of(os.path.join(TREE, "webui", "assets",
                                "index-ac460ghg.js")) == MD5_WEBUI_BUNDLE
    assert md5_of(os.path.join(TREE, "webui",
                                "index.html")) == MD5_WEBUI_INDEX


def test_docs_match_new_routing_keys_version():
    """User-facing root docs describe the CURRENT state: / = artifact
    UI, /classic removed (404), /webui = legacy SPA; both feed keys
    documented (no values anywhere); product version 1.2.1, no stale
    1.9.0. History files (ENTERPRISE_NOTES.md etc.) are deliberately
    NOT covered here — old release notes stay as written."""
    docs = {}
    for name in ("README.md", "DOCKER.md", "INSTALL.md"):
        with open(os.path.join(TREE, name), encoding="utf-8") as fh:
            docs[name] = fh.read()
    for name, text in docs.items():
        assert "VANTHEX_FIRMS_MAP_KEY" in text, name
        assert "VANTHEX_ABUSECH_AUTH_KEY" in text, name
        assert "/webui" in text, name
        assert "1.9.0" not in text, name
        assert "previous classic UI remains available" not in text, name
        # /classic is mentioned only as removed, never as an alias.
        assert "removed" in text, name
        assert "alias for it" not in text, name
    assert "version-1.2.1" in docs["README.md"]
    assert "**Version 1.2.1**" in docs["DOCKER.md"]
    assert "**Version 1.2.1**" in docs["INSTALL.md"]
    for name, text in docs.items():
        for line in text.splitlines():
            if ("VANTHEX_FIRMS_MAP_KEY" in line
                    or "VANTHEX_ABUSECH_AUTH_KEY" in line):
                stripped = line.strip()
                assert (stripped.startswith("#")
                        or stripped.startswith("|")
                        or stripped.startswith("VANTHEX_TAG")
                        or "=" not in line), (name, line)
