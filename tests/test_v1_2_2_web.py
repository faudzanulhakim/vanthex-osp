"""v1.2.2 web lock — consolidated source locks for the new UI state.

Supersedes the v1.2.1-era lock files (test_v1_2_1_webui,
test_v1_2_1_default_classic, test_v1_2_1_total_parity,
test_v1_2_1_visual_parity, test_v1_2_1_scan_parity) which pinned the
state that the 2026-11-04 changes deliberately superseded:
  * the legacy webui SPA was REMOVED (folder gone; /webui is now an
    alias serving the artifact UI);
  * the UI bundle folder was renamed artifact-ui/ -> web/;
  * the product version is 1.2.2 everywhere.

Hermetic: reads files from this tree only.
"""
import os

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(TREE, "web")


def read(rel):
    with open(os.path.join(TREE, rel), encoding="utf-8") as fh:
        return fh.read()


def app2_src():
    return read("app2.py")


# ------------------------------------------------------- webui is gone
def test_legacy_webui_removed():
    assert not os.path.exists(os.path.join(TREE, "webui"))
    src = app2_src()
    for gone in ("webui_file", "vendor_file", "WEBUI_DIR",
                 "_WEBUI_CACHE", '_path.startswith("/assets/")',
                 '_path.startswith("/vendor/")'):
        assert gone not in src, gone
    # /webui survives only as an alias that serves the artifact UI.
    webui = src[src.index('elif path == "/webui":'):]
    webui = webui[:webui.index('elif path.startswith("/assets/"):')]
    assert 'artifact_file("index.html")' in webui


def test_bundle_folder_is_web():
    assert os.path.isdir(WEB)
    assert not os.path.exists(os.path.join(TREE, "artifact-ui"))
    assert 'ARTIFACT_DIR = os.path.join(HERE, "web")' in app2_src()


def test_bundle_index_references_artifact_assets():
    idx = read(os.path.join("web", "index.html"))
    assert "/assets/index-zx0p0xvc.js" in idx
    assert "/assets/index-p2xspqab.css" in idx
    for name in ("index-zx0p0xvc.js", "index-p2xspqab.css"):
        assert os.path.exists(os.path.join(WEB, "assets", name)), name


# ------------------------------------------------------- version 1.2.2
def test_version_pins_are_1_2_2():
    src = app2_src()
    assert '"version": "1.2.2"' in src
    assert 'server_version = "VANTHEX/1.2.2"' in src
    assert "VANTHEX Offensive Security Platform v1.2.2" in src
    for name in ("README.md", "DOCKER.md", "INSTALL.md"):
        txt = read(name)
        assert "1.2.2" in txt
        assert "1.2.1" not in txt, name


def test_readme_badge_is_1_2_2():
    badge = "badge/version-1.2.2-crimson"
    assert badge in read("README.md")
    assert "1.2.1" not in read("README.md").replace("v1.2.1", "")


def test_docker_config_synced():
    compose = read("docker-compose.yml")
    assert "image: vanthex:1.2.2" in compose
    assert 'ARTIFACT' not in compose
    # OSINT watcher state env vars removed with the OSINT feature
    assert "PTK_OSINT_WATCH_PATH" not in compose
    assert "Version 1.2.2" in read("DOCKER.md")
    assert "VANTHEX_TAG=1.2.2" in read("DOCKER.md")


def test_archive_docs_under_docs():
    for name in ("AUDIT.md", "ENTERPRISE_NOTES.md", "UPGRADE_NOTES.md"):
        assert os.path.exists(os.path.join(TREE, "docs", name))


def test_actions_count_65():
    # OSINT intelligence actions removed with the OSINT feature.
    import actions
    assert len(actions._ACTIONS) == 50
