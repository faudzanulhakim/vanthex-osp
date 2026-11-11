"""UI/backend action-sync regression: every action in webapp/actions.py
_ACTIONS must be referenced by the minified web bundle (web/assets/
index-zx0p0xvc.js). The bundle's API client is a Proxy that dispatches
any B.<name> property to POST /actions {"action": name}, so a missing
literal means no UI affordance exists for that backend capability.

Known exception: analyzeMobile is superseded by finishMobileUpload
(the package-analysis job is started server-side when the upload
finishes; no client-side call site exists).
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

BUNDLE = os.path.join(ROOT, "web", "assets", "index-zx0p0xvc.js")
ACTIONS = os.path.join(ROOT, "webapp", "actions.py")

# Actions intentionally without a direct bundle call site.
ALLOWED_MISSING = {"analyzeMobile"}


def _action_names() -> list:
    src = open(ACTIONS, encoding="utf-8").read()
    block = src[src.index("_ACTIONS = {"):]
    block = block[:block.index("\n}\n")]
    names = re.findall(r'"([A-Za-z][A-Za-z0-9]*)":\s*_a_', block)
    assert len(names) >= 50, f"unexpectedly few _ACTIONS entries: {len(names)}"
    return names


def test_bundle_references_every_backend_action():
    bundle = open(BUNDLE, encoding="utf-8").read()
    names = _action_names()
    missing = [n for n in names
               if n not in bundle and n not in ALLOWED_MISSING]
    assert not missing, (
        "backend actions with no UI affordance in the web bundle: "
        f"{missing}"
    )


def test_all_four_new_affordances_present():
    bundle = open(BUNDLE, encoding="utf-8").read()
    for name, marker in [
        ("sarifExport", 'B.sarifExport({scanId:e})'),
        ("pocboxRun", 'B.pocboxRun({scanId:e.scanId,findingIndex:d})'),
        ("importHar", 'B.importHar({name:f.name,data:X})'),
        ("replayCapture", 'B.replayCapture({id:P.id})'),
    ]:
        assert name in bundle, f"{name} absent from bundle"
        assert marker in bundle, f"call site for {name} changed shape"


def test_bundle_size_sane():
    size = os.path.getsize(BUNDLE)
    # no duplicated giant blocks / runaway growth
    assert 1.3e6 < size < 1.5e6, f"bundle size out of expected range: {size}"
