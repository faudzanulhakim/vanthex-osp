"""v1.2.1 webui SPA relabel — bundle version display 1.5.0 -> 1.2.1.

ADE 2026-10-25 21:18 WIB opened / and still saw V1.5.0 while the API
already reported 1.2.1. Root cause: hardcoded version strings in the
webui bundle. The classic dashboard (templates/app.html) was already
1.2.1; only the webui SPA bundle lagged.

Scope: only webui/assets/index-ac460ghg.js display strings changed
(4 badge-form occurrences). The two lowercase "v1.5.0 hygiene &
history pack" references are HISTORICAL release references (the pack
shipped in v1.5.0) and are intentionally left untouched — they are
not the product version. The bundle filename is unchanged
(index.html must keep resolving it).

Hermetic: reads files from this tree only.
"""
import os

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLE = os.path.join(TREE, "webui", "assets", "index-ac460ghg.js")
INDEX = os.path.join(TREE, "webui", "index.html")


def read_bundle():
    with open(BUNDLE, encoding="utf-8") as fh:
        return fh.read()


def test_bundle_filename_unchanged_and_referenced():
    assert os.path.basename(BUNDLE) == "index-ac460ghg.js"
    with open(INDEX, encoding="utf-8") as fh:
        html = fh.read()
    assert "index-ac460ghg.js" in html
    # index.html itself carries no version string (verified 21:18 WIB).
    assert "1.5.0" not in html
    assert "1.2.1" not in html


def test_no_stale_badge_version():
    assert "V1.5.0" not in read_bundle()


def test_display_version_is_1_2_1():
    js = read_bundle()
    assert js.count("V1.2.1") == 4
    assert js.count("1.2.1") == 4
    assert "VANTHEX V1.2.1" in js
    assert "Offensive Security Platform · V1.2.1" in js


def test_historical_pack_references_untouched():
    # Deliberately NOT scrubbed: these name the release that shipped
    # the pack, they are not the displayed product version.
    js = read_bundle()
    assert js.count("v1.5.0 hygiene & history pack") == 2
