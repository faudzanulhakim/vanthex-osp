"""v1.2.1 docker 1:1 — classic dashboard as the default at /.

ADE 2026-10-25 21:31 WIB ordered full 1:1 for the docker deploy.
Until this change, / served the legacy webui SPA for admin sessions
while the artifact-parity dashboard (templates/app.html) lived only
at /classic — so the docker default view was NOT the artifact's
counterpart. The webui SPA has no globe at all (0 MapLibre / Live
Alerts / Buildings in its bundle); it is a different, older
generation frontend, not the parity surface.

Scope of this change (and nothing else):
- app2.py routing: / always serves templates/app.html for an
  authenticated session; /classic is unchanged; the legacy webui
  moves to /webui (same admin + ACTIONS_OK gate, same classic
  fallback when the gate fails or the file is missing).
- docker-compose.deploy.yml gains the two globe-feed key env vars
  (values stay in ADE's own .env; no value is written anywhere).
- .env.example documents the two keys as comment placeholders.

Protected (pinned by hash, must NOT change here): osint.py,
templates/app.html, webui bundle, webui index.html.

Hermetic: reads files from this tree only. Live behaviour
(authenticated fetch of /, /webui, /classic) is verified
separately at deploy time, not in this file.
"""
import hashlib
import os

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP2 = os.path.join(TREE, "app2.py")
COMPOSE = os.path.join(TREE, "docker-compose.deploy.yml")
ENV_EXAMPLE = os.path.join(TREE, ".env.example")

# Pre-change baselines, verified 2026-10-25 before editing.
MD5_OSINT = "65ec21c31b4aad76aa304fcb411388ae"
# 2026-10-25 total parity port (Command Deck, shell extras, card-only
# alert clicks) superseded the 21:37 routing-flip template; the pin now
# tracks the post-port template, verified by test_v1_2_1_total_parity.py.
MD5_APP_HTML = "e7c6a4c07f0bb788f8a84d398748a9b8"
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
        if line.startswith("        elif path =="):
            break
        block.append(line)
    return "\n".join(block)


def test_root_serves_classic_not_webui():
    with open(APP2, encoding="utf-8") as fh:
        src = fh.read()
    block = route_branch(src, 'if path == "/":')
    assert 'load_template("app.html")' in block
    assert "webui_file" not in block


def test_classic_unchanged():
    with open(APP2, encoding="utf-8") as fh:
        src = fh.read()
    block = route_branch(src, 'elif path == "/classic":')
    assert 'load_template("app.html")' in block
    assert "webui_file" not in block


def test_webui_moved_to_webui_route_with_same_gate():
    with open(APP2, encoding="utf-8") as fh:
        src = fh.read()
    block = route_branch(src, 'elif path == "/webui":')
    assert 'sess.get("role") == "admin" and ACTIONS_OK' in block
    assert 'webui_file("index.html")' in block
    assert '("Cache-Control", "no-store")' in block
    # Same fallback as the old / behaviour: classic when the gate
    # fails or the webui file is missing.
    assert 'load_template("app.html")' in block


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


def test_env_example_documents_keys_as_comments_only():
    with open(ENV_EXAMPLE, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    for key in ("VANTHEX_FIRMS_MAP_KEY", "VANTHEX_ABUSECH_AUTH_KEY"):
        hits = [ln for ln in lines if key in ln]
        assert hits, "missing placeholder for %s" % key
        # Documentation only: every mentioning line must be a comment,
        # so no value can leak through the example file.
        assert all(ln.lstrip().startswith("#") for ln in hits), key


def test_protected_files_byte_identical():
    assert md5_of(os.path.join(TREE, "osint.py")) == MD5_OSINT
    assert md5_of(os.path.join(TREE, "templates", "app.html")) == MD5_APP_HTML
    assert md5_of(os.path.join(TREE, "webui", "assets",
                                "index-ac460ghg.js")) == MD5_WEBUI_BUNDLE
    assert md5_of(os.path.join(TREE, "webui",
                                "index.html")) == MD5_WEBUI_INDEX


def test_docs_match_new_routing_keys_version():
    """User-facing root docs describe the CURRENT state: / = classic,
    /classic = alias, /webui = legacy SPA; both feed keys documented
    (no values anywhere); product version 1.2.1, no stale 1.9.0.
    History files (ENTERPRISE_NOTES.md etc.) are deliberately NOT
    covered here — old release notes stay as written."""
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
    assert "version-1.2.1" in docs["README.md"]
    assert "**Version 1.2.1**" in docs["DOCKER.md"]
    assert "**Version 1.2.1**" in docs["INSTALL.md"]
    # No key value can leak through the docs: every line mentioning a
    # feed key is a comment, a table row, or a bare name — never an
    # assignment with a value.
    for name, text in docs.items():
        for line in text.splitlines():
            if ("VANTHEX_FIRMS_MAP_KEY" in line
                    or "VANTHEX_ABUSECH_AUTH_KEY" in line):
                stripped = line.strip()
                assert (stripped.startswith("#")
                        or stripped.startswith("|")
                        or stripped.startswith("VANTHEX_TAG")
                        or "=" not in line), (name, line)
