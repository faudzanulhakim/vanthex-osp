"""
Hermetic tests for supplyiblis.py — pure offline/static, no network.

Everything operates on inline fixture text; vulnscan2 is imported normally
(it is a local module, no network on import). PTK_SUPPLY gating is tested
with monkeypatched env.
"""
import json

import pytest

from offensive import supplyiblis as sb


# ------------------------------------------------------------ fixtures
CYCLONEDX = json.dumps({
    "bomFormat": "CycloneDX", "specVersion": "1.4",
    "metadata": {"component": {"name": "acme-app", "version": "2.0"}},
    "components": [
        {"name": "lodash", "version": "4.17.21",
         "purl": "pkg:npm/lodash@4.17.21"},
        {"name": "acme-internal-utils", "version": "1.2.3",
         "purl": "pkg:npm/acme-internal-utils@1.2.3"},
    ],
})

SPDX_JSON = json.dumps({
    "spdxVersion": "SPDX-2.3",
    "packages": [
        {"name": "flask", "versionInfo": "2.3.2",
         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                           "referenceType": "purl",
                           "referenceLocator": "pkg:pypi/flask@2.3.2"}]},
        {"name": "acme-private-core", "versionInfo": "0.9.1",
         "purl": "pkg:pypi/acme-private-core@0.9.1"},
    ],
})

SPDX_TEXT = """SPDXVersion: SPDX-2.2
PackageName: requests
PackageVersion: 2.31.0
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/requests@2.31.0

PackageName: acme-secret-lib
PackageVersion: 3.1.4
"""


def _wf(body):
    return ("name: ci\non:\n  pull_request:\n    branches: [main]\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n" + body)


WF_PRT_HEAD = (
    "name: deploy\non: pull_request_target\njobs:\n  b:\n"
    "    runs-on: ubuntu-latest\n    steps:\n"
    "      - uses: actions/checkout@v4\n"
    "        with:\n"
    "          ref: ${{ github.event.pull_request.head.ref }}\n"
    "      - run: ./build.sh\n")

WF_UNPINNED = _wf("      - uses: actions/checkout@v4\n"
                  "      - uses: some/action@main\n")

WF_SECRET_PR = _wf(
    "      - run: ./deploy.sh --token ${{ secrets.DEPLOY_TOKEN }}\n")

WF_CURL_SH = _wf(
    "      - run: curl -sSL https://get.example.com/install.sh | sh\n")

WF_CACHE_PR = _wf(
    "      - uses: actions/cache@v4\n"
    "        with:\n"
    "          path: ~/.cache\n"
    "          key: deps-${{ runner.os }}\n")


# ------------------------------------------------------- 1. SBOM parsing
def test_parse_sbom_cyclonedx():
    comps = sb.parse_sbom(CYCLONEDX)
    names = {c["name"]: c for c in comps}
    assert "lodash" in names and "acme-app" in names
    assert names["lodash"]["version"] == "4.17.21"
    assert names["lodash"]["purl"] == "pkg:npm/lodash@4.17.21"


def test_parse_sbom_spdx_json():
    comps = sb.parse_sbom(SPDX_JSON)
    by = {c["name"]: c for c in comps}
    assert by["flask"]["version"] == "2.3.2"
    assert by["flask"]["purl"] == "pkg:pypi/flask@2.3.2"
    assert by["acme-private-core"]["version"] == "0.9.1"


def test_parse_sbom_spdx_text():
    comps = sb.parse_sbom(SPDX_TEXT)
    by = {c["name"]: c for c in comps}
    assert by["requests"]["version"] == "2.31.0"
    assert by["requests"]["purl"] == "pkg:pypi/requests@2.31.0"
    assert by["acme-secret-lib"]["version"] == "3.1.4"


def test_parse_sbom_garbage():
    assert sb.parse_sbom("") == []
    assert sb.parse_sbom("not json at all {") == []
    assert sb.parse_sbom("{not valid") == []


# ---------------------------------------------- 2. dependency confusion
def test_confusion_finding_for_internal_name():
    comps = sb.parse_sbom(CYCLONEDX)
    findings = sb.dependency_confusion_check(comps)
    flagged = {f["location"] for f in findings}
    assert "acme-internal-utils" in flagged
    assert "lodash" not in flagged  # allow-listed
    f = next(f for f in findings if f["location"] == "acme-internal-utils")
    assert "squatting surface" in f["title"]
    assert f["confidence"] == "candidate"
    assert f["verification"] == "manual-required"
    assert "npm view acme-internal-utils" in f["remediation"]


def test_confusion_ecosystem_from_purl():
    comps = sb.parse_sbom(SPDX_JSON)
    f = next(f for f in sb.dependency_confusion_check(comps)
             if f["location"] == "acme-private-core")
    assert "pip index versions acme-private-core" in f["remediation"]


# --------------------------------------------------------- 3. typosquat
def test_typosquat_distance_evidence():
    comps = [{"name": "lodasg", "version": "1", "purl": ""},
             {"name": "requsts", "version": "1", "purl": ""}]
    findings = sb.typosquat_scan(comps)
    assert {f["location"] for f in findings} == {"lodasg", "requsts"}
    f = next(f for f in findings if f["location"] == "lodasg")
    assert "levenshtein_distance=1" in f["evidence"]
    assert "matches=lodash" in f["evidence"]
    # exact public names are never typosquats
    assert not sb.typosquat_scan([{"name": "lodash", "version": "1",
                                   "purl": ""}])


def test_levenshtein_basics():
    assert sb.levenshtein("kitten", "sitting") == 3
    assert sb.levenshtein("abc", "abc") == 0
    assert sb.levenshtein("", "ab") == 2


# ------------------------------------------------- 4. workflow anti-patterns
def test_workflow_prt_head_checkout():
    f = sb.github_workflow_audit(WF_PRT_HEAD)
    assert any("PR-head" in x["title"] for x in f)
    hit = next(x for x in f if "PR-head" in x["title"])
    assert hit["confidence"] == "probable"
    assert "pull_request.head.ref" in hit["evidence"]


def test_workflow_unpinned_actions():
    f = sb.github_workflow_audit(WF_UNPINNED)
    unpinned = [x for x in f if "not pinned" in x["title"]]
    assert any("some/action@main" in x["evidence"] for x in unpinned)
    # checkout@v4 is tag-referenced too -> also unpinned (no SHA)
    assert any("actions/checkout@v4" in x["evidence"] for x in unpinned)


def test_workflow_secret_in_pr_context():
    f = sb.github_workflow_audit(WF_SECRET_PR)
    assert any("secret" in x["title"].lower() and
               "pull-request" in x["title"].lower() for x in f)


def test_workflow_curl_sh():
    f = sb.github_workflow_audit(WF_CURL_SH)
    hit = next(x for x in f if "piped straight into a shell" in x["title"])
    assert "curl" in hit["evidence"] and "sh" in hit["evidence"]
    assert hit["remediation"].startswith("Download to a file")


def test_workflow_cache_poisoning_candidate():
    f = sb.github_workflow_audit(WF_CACHE_PR)
    assert any("cache poisoning" in x["title"].lower() for x in f)


def test_clean_workflow_no_findings():
    clean = _wf("      - uses: actions/checkout@"
                "8f4b7f84864484a7bf31766abe9204da3cbe65b3\n"
                "      - run: make test\n")
    assert sb.github_workflow_audit(clean) == []


def test_workflow_audit_accepts_list_and_regex_fallback(monkeypatch):
    # force the regex path even if PyYAML is installed
    import builtins
    real_import = builtins.__import__

    def no_yaml(name, *a, **k):
        if name == "yaml":
            raise ImportError("blocked for test")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", no_yaml)
    f = sb.github_workflow_audit([WF_UNPINNED, WF_CURL_SH])
    assert f  # both docs audited without yaml


# ------------------------------------------------------- 5. orchestrator
def test_run_supplycheck_gated(monkeypatch):
    monkeypatch.delenv("PTK_SUPPLY", raising=False)
    with pytest.raises(PermissionError):
        sb.run_supplycheck([], [])


def test_run_supplycheck(monkeypatch):
    monkeypatch.setenv("PTK_SUPPLY", "1")
    res = sb.run_supplycheck(sb.parse_sbom(CYCLONEDX) +
                             [{"name": "lodasg", "version": "1",
                               "purl": ""}],
                             [WF_PRT_HEAD, WF_UNPINNED, WF_SECRET_PR,
                              WF_CURL_SH, WF_CACHE_PR])
    titles = [f["title"] for f in res["findings"]]
    assert res["type"] == "supplyiblis"
    assert any("acme-internal-utils" in t for t in titles)
    assert any("Typosquat" in t for t in titles)
    assert any("PR-head" in t for t in titles)
    assert any("not pinned" in t for t in titles)
    assert res["summary"].get("HIGH", 0) >= 1
    # dedupe: no duplicated (title, location)
    keys = [(f["title"], f["location"]) for f in res["findings"]]
    assert len(keys) == len(set(keys))
