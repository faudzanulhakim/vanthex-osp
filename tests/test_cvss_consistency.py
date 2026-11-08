"""Hermetic AST invariant test: CVSS v3.1 base score must agree with the
severity band of every static finding in the check modules, and no non-INFO
finding may carry cvss == 0.0.

Rules enforced (per repo convention):
  CRITICAL 9.0-10.0 | HIGH 7.0-8.9 | MEDIUM 4.0-6.9 | LOW 0.1-3.9 | INFO 0.0

Exceptions:
  * Calls whose severity or cvss are computed at runtime (names, IfExp on
    names, subscripts) are skipped — the static tree cannot judge them.
  * IfExp whose BOTH branches are numeric constants is evaluated per-branch.
  * A call whose span references a CVE literal is exempt from the band check
    when its score equals the published NVD base score for that CVE
    (NVD score takes precedence over the severity label); it is still
    checked for the no-zero rule unless the NVD score is 0.0.

The test is fully static: no imports of the modules, no network.
"""
import ast
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get("CVSS_ROOT", os.path.dirname(HERE))

SKIP_DIRS = {".venv", "__pycache__", ".git", "tests", "node_modules"}

BANDS = {
    "CRITICAL": (9.0, 10.0),
    "HIGH": (7.0, 8.9),
    "MEDIUM": (4.0, 6.9),
    "LOW": (0.1, 3.9),
    "INFO": (0.0, 0.0),
}

# Well-known published NVD v3.1 base scores used for CVE-anchored findings.
NVD = {
    "CVE-2021-41773": 7.5,
    "CVE-2021-42013": 9.8,
    "CVE-2021-44228": 10.0,
    "CVE-2014-6271": 10.0,
    "CVE-2012-1823": 9.8,
    "CVE-2021-23017": 7.7,
    "CVE-2021-22205": 10.0,
    "CVE-2020-1938": 7.5,
    "CVE-2022-22965": 9.8,
    "CVE-2018-7600": 9.8,
    "CVE-2021-3129": 9.8,
    "CVE-2015-9251": 6.1,
    "CVE-2019-11358": 6.1,
    "CVE-2020-11022": 6.1,
    "CVE-2021-28169": 5.3,
    "CVE-2025-29927": 9.1,
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
SEV_KEYS = ("severity", "sev", "level")


def _const_str(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.upper()
    return None


def _num(node):
    """Return list of (lineno, value) for a static numeric cvss expression,
    or None if the value is computed at runtime."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return [(node.lineno, float(node.value))]
    if (isinstance(node, ast.IfExp)
            and isinstance(node.body, ast.Constant)
            and isinstance(node.body.value, (int, float))
            and isinstance(node.orelse, ast.Constant)
            and isinstance(node.orelse.value, (int, float))):
        return [(node.body.lineno, float(node.body.value)),
                (node.orelse.lineno, float(node.orelse.value))]
    return None


def _severity(call):
    for key in SEV_KEYS:
        for kw in call.keywords:
            if kw.arg == key:
                s = _const_str(kw.value)
                if s:
                    return s
    for arg in call.args:
        s = _const_str(arg)
        if s in BANDS:
            return s
    return None


def check_modules():
    violations = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, ROOT)
            with open(path, "r", encoding="utf-8") as fh:
                src = fh.read()
            try:
                tree = ast.parse(src, filename=path)
            except SyntaxError as exc:  # pragma: no cover
                violations.append(f"{rel}: syntax error: {exc}")
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                kw = {k.arg: k.value for k in node.keywords if k.arg}
                if "cvss" not in kw:
                    continue
                sev = _severity(node)
                nums = _num(kw["cvss"])
                if sev is None or nums is None:
                    continue  # dynamic severity/score — out of static scope
                span = ast.get_source_segment(src, node) or ""
                cves = set(CVE_RE.findall(span))
                for line, cvss in nums:
                    if cvss == 0.0 and sev != "INFO":
                        violations.append(
                            f"{rel}:{line}: cvss=0.0 on {sev} finding "
                            f"(band {sev} is {BANDS[sev]})")
                        continue
                    if cvss == 0.0 and sev == "INFO":
                        continue
                    nvd_scores = [NVD[c] for c in cves if c in NVD]
                    if nvd_scores:
                        # CVE-anchored: the NVD-published score takes
                        # precedence over the severity label's band.
                        if not any(abs(cvss - s) < 1e-9 for s in nvd_scores):
                            violations.append(
                                f"{rel}:{line}: cvss={cvss:g} differs from "
                                f"published NVD score for {sorted(cves)} "
                                f"(NVD: {nvd_scores})")
                        continue
                    lo, hi = BANDS[sev]
                    if lo <= cvss <= hi:
                        continue
                    violations.append(
                        f"{rel}:{line}: {sev} finding with cvss={cvss:g} "
                        f"outside band {lo}-{hi}")
    return violations


def test_cvss_band_matches_severity():
    assert not check_modules()


if __name__ == "__main__":
    v = check_modules()
    for line in v:
        print(line, file=sys.stderr)
    sys.exit(1 if v else 0)
