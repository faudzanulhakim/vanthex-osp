"""
Pentest Toolkit — Supply-Chain Attack Surface (supplyiblis.py).

Static, fully offline analysis of dependency / build-pipeline material:

  1. parse_sbom(text)                  -> normalized components (CycloneDX
                                        JSON, SPDX JSON, SPDX tag-value)
  2. dependency_confusion_check(comps) -> internal-name squatting-surface
                                        candidates with the exact
                                        human publish-check command
  3. typosquat_scan(comps)             -> levenshtein <= 2 look-alikes of
                                        curated public package names
  4. github_workflow_audit(text|list)  -> regex/PyYAML detections of the
                                        classic workflow anti-patterns
                                        (pull_request_target + PR-head
                                        checkout, unpinned actions,
                                        secrets in untrusted scripts,
                                        curl|sh, cache-poisoning setups)
  5. run_supplycheck(components, workflows) — orchestrator, gated by
                                        env PTK_SUPPLY=1 (PermissionError
                                        otherwise).

Everything is pure text analysis: no network, no execution of the analysed
content. Findings are produced through the shared F() factory (vulnscan2,
imported lazily so this module loads without it) and always carry the
offending line as evidence plus a one-line fix.
"""
import json
import os
import re

__version__ = "1.0.0"

# Curated allow-list of well-known public-registry package names (inline,
# deliberately small — same philosophy as reconiblis: cut obvious FPs only;
# an allow-list can never prove a name is legitimate).
_KNOWN_PACKAGES = {
    "react", "react-dom", "vue", "angular", "express", "lodash", "axios",
    "jquery", "moment", "chalk", "debug", "commander", "requests", "flask",
    "django", "numpy", "pandas", "boto3", "urllib3", "certifi", "setuptools",
    "pip", "wheel", "gunicorn", "celery", "sqlalchemy", "rails", "rake",
    "devise", "puma", "rspec", "webpack", "typescript", "eslint", "prettier",
    "jest", "mocha", "chai", "core-js", "babel", "@babel/core",
}

# Publish-check commands an investigator runs by hand to prove/disprove
# that a name is claimable in the public registry (never executed here).
PUBLISH_CHECK_COMMANDS = {
    "npm": 'npm view {name} version   # 404/E404 = name claimable',
    "pypi": 'pip index versions {name} 2>&1 | grep -i "no matching" || '
            'pip download {name}==999.999 --no-deps -d /tmp/probe',
    "gem": 'gem info {name}   # "(*): Unable to find gem" = name claimable',
}


def _lazy_F():
    """F() factory imported lazily so the module loads without vulnscan2."""
    from vulnscan2 import F
    return F


def levenshtein(a, b):
    """Classic edit distance (iterative DP, two rows)."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# ------------------------------------------------------------------ 1. SBOM
def _norm_component(name, version="", purl="", extra=None):
    return {"name": (name or "").strip(), "version": (version or "").strip(),
            "purl": (purl or "").strip(), **(extra or {})}


def _parse_cyclonedx(doc):
    out = []
    for c in doc.get("components") or []:
        out.append(_norm_component(c.get("name"), c.get("version"),
                                   c.get("purl"),
                                   {"sbom_format": "cyclonedx"}))
    meta = (doc.get("metadata") or {}).get("component") or {}
    if meta.get("name"):
        out.append(_norm_component(meta.get("name"), meta.get("version"),
                                   meta.get("purl"),
                                   {"sbom_format": "cyclonedx",
                                    "role": "metadata.component"}))
    return out


def _parse_spdx_json(doc):
    out = []
    for p in doc.get("packages") or []:
        ver = str(p.get("versionInfo") or "")
        # SPDX purl field or externalRefs of type purl
        purl = str(p.get("purl") or "")
        if not purl:
            for ref in p.get("externalRefs") or []:
                if (ref.get("referenceType") or "").lower() == "purl":
                    purl = str(ref.get("referenceLocator") or "")
                    break
        out.append(_norm_component(p.get("name"), ver, purl,
                                   {"sbom_format": "spdx"}))
    return out


_SPDX_TAG_RE = re.compile(
    r"(?m)^(PackageName|PackageVersion|ExternalRef)\s*:\s*(.*)$")


def _parse_spdx_text(text):
    out, cur = [], {}
    for m in _SPDX_TAG_RE.finditer(text or ""):
        tag, val = m.group(1), m.group(2).strip()
        if tag == "PackageName":
            if cur.get("name"):
                out.append(_norm_component(cur["name"], cur.get("version"),
                                           cur.get("purl"),
                                           {"sbom_format": "spdx"}))
            cur = {"name": val}
        elif tag == "PackageVersion":
            cur["version"] = val
        elif tag == "ExternalRef" and "PURL" in val.upper():
            parts = val.split()
            if len(parts) >= 3:
                cur["purl"] = parts[2]
    if cur.get("name"):
        out.append(_norm_component(cur["name"], cur.get("version"),
                                   cur.get("purl"), {"sbom_format": "spdx"}))
    return out


def parse_sbom(text):
    """Parse CycloneDX JSON / SPDX JSON / SPDX tag-value text into a
    normalized component list [{name, version, purl, sbom_format}].
    Unparseable/unknown input -> []. Pure text — no network."""
    text = (text or "").strip()
    if not text:
        return []
    if text.startswith("{"):
        try:
            doc = json.loads(text)
        except Exception:
            return []
        if not isinstance(doc, dict):
            return []
        fmt = str(doc.get("bomFormat") or "").lower()
        if fmt == "cyclonedx" or "components" in doc:
            return _parse_cyclonedx(doc)
        if "spdxVersion" in doc or "packages" in doc:
            return _parse_spdx_json(doc)
        return []
    return _parse_spdx_text(text)


# ------------------------------------------------- 2. dependency confusion
def dependency_confusion_check(components):
    """For each private-looking name (absent from the curated allow-list)
    emit an investigator finding candidate: 'possible internal name
    published registry squatting surface'. Verification is manual-required
    — the module never probes a registry; the finding carries the exact
    publish-check command a human would run."""
    F = _lazy_F()
    findings, seen = [], set()
    for c in components or []:
        name = (c.get("name") or "").strip()
        if not name or name.lower() in _KNOWN_PACKAGES or name in seen:
            continue
        seen.add(name)
        eco = "npm"
        purl = c.get("purl") or ""
        m = re.match(r"pkg:([^/]+)/", purl)
        if m:
            eco = {"pypi": "pypi", "deb": "pypi", "gem": "gem",
                   "rubygems": "gem"}.get(m.group(1), "npm")
        cmd = PUBLISH_CHECK_COMMANDS[eco].format(name=name)
        findings.append(F(
            "LOW",
            f"possible internal name published registry squatting surface: "
            f"{name}",
            "The dependency name is not a known public-registry package. If "
            "it is an internal-only package, an attacker can register the "
            "same name in the public registry and have any environment "
            "without an internal-registry override pull attacker code "
            "(dependency confusion). Static candidacy only — this module "
            "never contacts a registry.",
            evidence=f"name={name} ecosystem={eco} "
                     f"version={c.get('version', '')} purl={purl} "
                     f"source={c.get('source', '')}",
            cwe="CWE-1357", owasp="ASVS V14", cvss=3.1,
            remed=f"Verify the name with: {cmd}. Pin exact versions and "
                  "scope private dependencies through an internal registry "
                  "with a namespace/registry override.",
            confidence="candidate", location=name, origin="passive",
            verification="manual-required",
            verification_note="Publish-check command provided for manual "
                              "execution; no registry was contacted."))
    return findings


# ------------------------------------------------------------- 3. typosquat
_TYPO_MAX_DISTANCE = 2


def typosquat_scan(components):
    """Flag dependency names whose edit distance to a curated public package
    name is <= 2 — the classic typosquat window. Findings carry the matched
    public name and the measured distance as evidence."""
    F = _lazy_F()
    findings = []
    for c in components or []:
        name = (c.get("name") or "").strip()
        if not name:
            continue
        best, best_d = None, None
        for known in _KNOWN_PACKAGES:
            if name.lower() == known:
                best, best_d = None, None
                break  # exact public name: not a typo of anything
            d = levenshtein(name.lower(), known)
            if d <= _TYPO_MAX_DISTANCE and (best_d is None or d < best_d):
                best, best_d = known, d
        if best is not None:
            findings.append(F(
                "MEDIUM",
                f"Typosquat candidate: '{name}' is {best_d} edit(s) from "
                f"public package '{best}'",
                "The dependency name is a near-match of a well-known public "
                "package within the small typo window (edit distance <= 2). "
                "Whoever registers the look-alike name receives traffic from "
                "typo'd install commands and confused resolvers.",
                evidence=f"name={name} matches={best} "
                         f"levenshtein_distance={best_d} "
                         f"(threshold {_TYPO_MAX_DISTANCE})",
                cwe="CWE-1357", owasp="ASVS V14", cvss=6.5,
                remed=f"Confirm the intended package is exactly '{best}' "
                      "(or the genuinely intended internal package); fix the "
                      "spelling in the manifest/SBOM and pin the version.",
                confidence="candidate",
                location=name, origin="passive",
                verification="static-analysis",
                verification_note="Deterministic edit-distance computation "
                                  "against the curated allow-list; no "
                                  "registry contacted."))
    return findings


# ------------------------------------------- 4. GitHub workflow audit
_UNTRUSTED_CTX_RE = re.compile(
    r"\$\{\{\s*github\.event\.(pull_request|head_commit|issues|"
    r"discussion|comment|review|pages)\b")


def _workflow_line_iterator(text):
    for i, line in enumerate(text.splitlines(), 1):
        yield i, line


def _strip_inline_comment(line):
    return re.sub(r"\s+#.*$", "", line)


def github_workflow_audit(text_or_list):
    """Audit GitHub Actions workflow YAML (one or several documents) for
    classic CI anti-patterns. Tries PyYAML for structure, falls back to
    line-regex when unavailable; every detection is line-based either way.
    Returns findings (vulnscan2.F shape), all 'probable', each with the
    offending line as evidence and a one-line fix."""
    F = _lazy_F()
    docs = ([text_or_list] if isinstance(text_or_list, str)
            else list(text_or_list or []))
    findings = []
    try:
        import yaml  # noqa: F401  (availability probe; regex path is primary)
        _HAS_YAML = True
    except Exception:
        _HAS_YAML = False

    def add(doc_idx, sev, title, desc, lineno, line, fix, cwe, cvss,
            note=""):
        findings.append(F(
            sev, title, desc,
            evidence=f"workflow#{doc_idx + 1} line {lineno}: "
                     f"{line.strip()[:200]}",
            cwe=cwe, owasp="ASVS V14", cvss=cvss, remed=fix,
            confidence="probable", location=f"workflow#{doc_idx + 1}:"
                                            f"{lineno}",
            origin="static-analysis", verification="static-analysis",
            verification_note=note or
            "Static line-level pattern in workflow YAML; "
            "confirm the workflow's actual trigger context."))

    for di, text in enumerate(docs):
        if not text:
            continue

        # (a) pull_request_target + checkout of PR head
        if re.search(r"\bpull_request_target\b", text):
            for i, line in _workflow_line_iterator(text):
                if re.search(r"ref:\s*\$\{\{[^}]*pull_request\.head", line):
                    add(di, "HIGH",
                        "Workflow on pull_request_target checks out "
                        "PR-head code",
                        "pull_request_target grants write permissions and "
                        "secrets while the checked-out code is the "
                        "attacker-controlled PR head — a fork can execute "
                        "arbitrary code with repository secrets.",
                        i, line,
                        "Checkout the base ref (or use a two-workflow "
                        "pattern: unprivileged build on pull_request, "
                        "privileged merge via workflow_run/artifact).",
                        "CWE-829", 8.8)
            # also: bare actions/checkout in a pull_request_target workflow
            if not re.search(r"ref:", text) and \
                    re.search(r"uses:\s*actions/checkout", text):
                for i, line in _workflow_line_iterator(text):
                    if re.search(r"uses:\s*actions/checkout", line):
                        add(di, "HIGH",
                            "pull_request_target workflow runs a bare "
                            "checkout (no ref pinning)",
                            "In a pull_request_target workflow a default "
                            "checkout is frequently paired with steps that "
                            "execute PR-supplied scripts; without an "
                            "explicit base-ref pin the trigger context is "
                            "ambiguous and easily abused.",
                            i, line,
                            "Pin `ref: ${{ github.event.pull_request.base."
                            "sha }}` explicitly and never run PR-supplied "
                            "scripts from privileged workflows.",
                            "CWE-829", 8.8)
                        break

        # (b) unpinned actions (uses: without @sha)
        for i, line in _workflow_line_iterator(text):
            m = re.search(r"uses:\s*([^\s#]+)", line)
            if not m:
                continue
            ref = m.group(1)
            if ref.startswith(("./", "docker/")):
                continue
            if not re.search(r"@[0-9a-fA-F]{40}\s*$", line):
                tag = ref.split("@")[-1] if "@" in ref else "(no ref)"
                add(di, "MEDIUM",
                    f"Action not pinned to a full commit SHA: {ref}",
                    "An action referenced by mutable tag/branch can be "
                    "re-pointed by its maintainer (or via a hijacked "
                    "release) to attacker code that runs inside your "
                    "workflow with the job's permissions and secrets.",
                    i, line,
                    f"Pin the action to a full 40-char commit SHA "
                    f"(currently '{tag}') and keep it updated via "
                    "reviewed dependabot PRs.",
                    "CWE-1354", 7.2,
                    note="Static pattern: only `uses: owner/action@"
                         "<40-hex>` counts as pinned.")

        # (c) secrets passed into untrusted scripts (run: + secrets + PR ctx)
        run_lines = [(i, ln) for i, ln in _workflow_line_iterator(text)
                     if re.match(r"\s*(?:-\s+)?run:\s*", ln)]
        for i, line in run_lines:
            body = _strip_inline_comment(line)
            has_secret = "${{ secrets." in body
            untrusted = bool(_UNTRUSTED_CTX_RE.search(body)) or \
                bool(re.search(r"\bpull_request\b", text))
            if has_secret and untrusted:
                add(di, "HIGH",
                    "Secret interpolated into a run script reachable from "
                    "pull-request context",
                    "A secret is injected via ${{ secrets.* }} into a shell "
                    "step in a workflow whose trigger includes pull-request "
                    "content; PR-controlled code or environment in the same "
                    "job can read the process environment and exfiltrate it.",
                    i, line,
                    "Pass secrets via an environment variable consumed only "
                    "in trusted jobs (never interpolate into shell in "
                    "pull-request-triggered workflows).",
                    "CWE-522", 8.2)
        # also: secrets used anywhere in a pull_request_target workflow
        if re.search(r"\bpull_request_target\b", text):
            for i, line in run_lines:
                if "${{ secrets." in _strip_inline_comment(line):
                    add(di, "HIGH",
                        "pull_request_target workflow interpolates a secret "
                        "into a run step",
                        "The privileged trigger runs PR-head code (directly "
                        "or via the build system), so any secret "
                        "interpolated into a run step is exfiltratable by a "
                        "malicious fork PR.",
                        i, line,
                        "Move the secret-consuming step to a "
                        "workflow_run-triggered job that runs on the base "
                        "branch only.",
                        "CWE-522", 9.1)

        # (d) curl | sh patterns
        for i, line in _workflow_line_iterator(text):
            body = _strip_inline_comment(line)
            if re.search(r"(curl|wget)[^|]*\|\s*(sudo\s+)?(ba)?sh", body):
                add(di, "MEDIUM",
                    "Remote script piped straight into a shell",
                    "curl|sh executes whatever the remote endpoint returns "
                    "at run time with the runner's permissions — a hijacked "
                    "endpoint or compromised CDN poisons every build here.",
                    i, line,
                    "Download to a file, verify a pinned checksum/signature, "
                    "then execute the verified artifact.",
                    "CWE-494", 7.5,
                    note="Static pattern on run: lines and script blocks.")

        # (e) cache-poisoning candidates: actions/cache restored in PR context
        for i, line in _workflow_line_iterator(text):
            if re.search(r"uses:\s*actions/cache", _strip_inline_comment(line)):
                pr_ctx = bool(re.search(r"\bpull_request(_target)?\b", text))
                broad_keys = bool(re.search(
                    r"(?m)^\s*restore-keys:\s*\|?\s*$|"
                    r"restore-keys:\s*\S*\$\{", text))
                if pr_ctx or broad_keys:
                    add(di, "MEDIUM",
                        "Cache poisoning candidate: actions/cache reachable "
                        "from pull-request context",
                        "A cache saved during (or influenced by) "
                        "pull-request execution can be restored into "
                        "privileged builds — planted artifacts or "
                        "dependency archives execute downstream.",
                        i, line,
                        "Scope cache keys to the branch, avoid restoring "
                        "PR-saved caches in privileged workflows, and "
                        "prefer cache with explicit prefix restore-keys.",
                        "CWE-453", 7.1)
                    break  # one candidate per workflow is enough

    return findings


# ------------------------------------------------------- 5. orchestrator
def run_supplycheck(components, workflows=None, log=None):
    """Full static supply-chain sweep -> engine dict (findings + summary).
    Gated: requires env PTK_SUPPLY=1, otherwise PermissionError. The scan
    itself is offline/static — the gate marks operator approval for
    processing dependency/CI material."""
    if os.environ.get("PTK_SUPPLY") != "1":
        raise PermissionError(
            "run_supplycheck is operator-gated: set PTK_SUPPLY=1 to enable "
            "supply-chain analysis")

    def L(msg):
        if log is None:
            return
        if callable(log):
            log(msg)
        else:
            log.append(msg)

    F = _lazy_F()
    findings = []

    comps = list(components or [])
    L(f"[supplyiblis] static supply-chain sweep: {len(comps)} component(s), "
      f"{len(workflows or [])} workflow(s)")

    # inventory finding (INFO, always)
    findings.append(F(
        "INFO", f"Supply-chain inventory: {len(comps)} component(s), "
                f"{len(workflows or [])} workflow(s) analysed",
        "Normalized dependency/CI inventory from the provided SBOM and "
        "workflow material; all analysis offline/static.",
        evidence=json.dumps({"components": len(comps),
                             "workflows": len(workflows or []),
                             "names": [c.get("name") for c in comps][:20]
                             })[:400],
        cwe="CWE-1357", owasp="ASVS V14", cvss=0.0,
        remed="Keep SBOMs refreshed and CI workflows pinned; re-run after "
              "dependency or pipeline changes.",
        confidence="confirmed", origin="passive",
        verification="static-analysis",
        verification_note="Assembled from the caller-supplied SBOM/ "
                          "workflow text; nothing fetched."))

    findings += dependency_confusion_check(comps)
    findings += typosquat_scan(comps)
    findings += github_workflow_audit(workflows)

    # dedupe by (title, location)
    dedup, seen = [], set()
    for f in findings:
        key = (f["title"], f.get("location", ""))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(f)
    findings = dedup

    summary = {}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    risk = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                 if summary.get(s)), "CLEAN")
    from vulnscan2 import risk_score
    score = risk_score(findings)
    L(f"[supplyiblis] done: {len(findings)} findings | risk {risk} | "
      f"score {score}/100")
    return {"type": "supplyiblis", "target": "supply-chain",
            "profile": "supply-chain-static", "method": "static",
            "findings": findings, "summary": summary,
            "overall_risk": risk, "risk_score": score,
            "meta": {"components": comps,
                     "workflows_analysed": len(workflows or [])},
            "endpoints": [], "warnings": [], "errors": []}
