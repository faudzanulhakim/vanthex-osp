"""
Pentest Toolkit v3.3 — Analyzer statis APK Android (mobile.py)

Check DITULIS SENDIRI (aturan, severity, confidence, remediasi), mengikuti
standar bukti yang sama dengan engine web: fakta terverifikasi = confirmed,
indikasi kuat = probable, pola mencurigakan = candidate (tidak pernah
dibulatkan jadi confirmed). Parsing biner APK (manifest AXML, DEX, sertifikat)
dibantu androguard — library yang sama yang dipakai tools analisis APK lain
(mis. MobSF) — sesuai keputusan pemilik: TANPA tool scanner jadi (nmap/
nuclei/dll tidak dipanggil), engine tetap hasil build sendiri, library
pihak ketiga dipakai sebagai bahan baku parsing.

Cakupan: analisis STATIS saja. Uji dinamis/runtime (Frida, intercept trafik
dari perangkat) di luar cakupan modul ini dan tidak diklaim di sini.
Pemetaan standar: OWASP MASVS/MASTG untuk mobile.
"""
import hashlib
import re
import zipfile
from datetime import datetime, timezone
from urllib.parse import urlsplit

try:
    # Manifest APK adalah XML TAK TEpercaya (bisa berasal dari aplikasi pihak
    # ketiga yang jahat) — parse dengan defusedxml agar analyzer sendiri tidak
    # kena XXE/billion-laughs dari file yang ia periksa.
    from defusedxml import ElementTree as ET
except Exception:  # fallback bila defusedxml belum terpasang
    from xml.etree import ElementTree as ET

from vulnscan2 import F, risk_score

NS = "{http://schemas.android.com/apk/res/android}"

# Permission berbahaya (protectionLevel=dangerous, AOSP). VERY = paling sensitif.
_PERM_VERY = {
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS", "android.permission.WRITE_SMS",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.BODY_SENSORS",
    "android.permission.PROCESS_OUTGOING_CALLS", "android.permission.ANSWER_PHONE_CALLS",
}
_PERM_DANGEROUS = _PERM_VERY | {
    "android.permission.ACCESS_COARSE_LOCATION", "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS", "android.permission.CALL_PHONE",
    "android.permission.USE_SIP", "android.permission.GET_ACCOUNTS",
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO", "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.RECEIVE_MMS", "android.permission.RECEIVE_WAP_PUSH",
}
# Host yang muncul di string APK sebagai REFERENSI skema/namespace, bukan endpoint.
_NON_ENDPOINT_HOSTS = {"schemas.android.com", "www.w3.org", "schemas.microsoft.com",
                       "xml.apache.org", "java.sun.com", "xmlpull.org",
                       "localhost", "127.0.0.1", "www.apache.org", "ns.adobe.com"}

# Charset URL dibatasi rentang printable: DEX menyimpan string berurutan dengan
# pemisah \x00 — regex negasi longgar akan melebur beberapa URL jadi satu sampah.
_URL_RE = re.compile(rb"https?://[\x21-\x7e]{4,220}")
_STR_RE = re.compile(rb"[\x20-\x7e]{5,}")
_SECRET_PATTERNS = [
    ("aws", re.compile(r"AKIA[0-9A-Z]{16}"), "HIGH", 7.4,
     'AWS Access Key ID embedded in the APK',
     'An AWS access key is exposed inside an APK that anyone can download. Revoke/rotate this key immediately and never embed cloud credentials in a mobile app.'),
    ("gcp_api", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "MEDIUM", 5.3,
     'Google API Key embedded in the APK',
     'A Google API key is exposed in the APK. Restrict the key per API + per app in Google Cloud Console and rotate it if it was ever used outside the official app.'),
    ("privkey", re.compile(r"BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY"), "CRITICAL", 9.1,
     'Private key embedded in the APK',
     'A private key was found inside the app package — anyone who downloads the APK has it. Treat this key as permanently leaked: revoke and replace it, and move signing operations to a server/HSM.'),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
     "MEDIUM", 6.5, 'JWT token embedded in the APK',
     'A JWT token (likely a long-lived session/API credential) is embedded in the APK. Revoke this token and never embed static tokens in a mobile app.'),
]
_GENERIC_SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|app[_-]?secret|client[_-]?secret|password|passwd|auth[_-]?token)"
    r"\s*[:=]\s*[\"'][^\"'\s]{8,64}[\"']")


def _mask(s):
    return s[:4] + "***" + s[-2:] if len(s) > 8 else "***"


def _extract_strings_and_urls(zf, names):
    """Kumpulkan string ASCII + URL dari dex/assets/raw/.so (dibatasi ukuran)."""
    strings = set()
    urls = set()
    budget = 90 * 1024 * 1024
    for name in names:
        low = name.lower()
        if not (low.endswith(".dex") or low.startswith("assets/")
                or low.startswith("res/raw/") or low.endswith(".so")
                or low.endswith(".json")):
            continue
        try:
            data = zf.read(name)
        except Exception:
            continue
        if len(data) > budget:
            data = data[:budget]
        budget -= len(data)
        for m in _URL_RE.findall(data):
            u = m.decode("utf-8", "replace").rstrip(")]>\"'.,;")
            urls.add(u)
        for m in _STR_RE.findall(data):
            try:
                strings.add(m.decode("utf-8"))
            except Exception:
                pass
        if budget <= 0:
            break
    return strings, urls


def _manifest_tree(apk):
    try:
        xml = apk.get_android_manifest_axml().get_xml()
        return ET.fromstring(xml)
    except Exception:
        return None


def _components(root, target_sdk):
    """Daftar komponen + status exported efektif (aturan default Android)."""
    app = root.find("application") if root is not None else None
    comps = []
    if app is None:
        return comps, None
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for el in app.findall(tag):
            name = el.get(NS + "name") or ""
            exported_attr = el.get(NS + "exported")
            filters = el.findall("intent-filter")
            launcher = any(
                any(a.get(NS + "name") == "android.intent.action.MAIN"
                    for a in f.findall("action"))
                and any(c.get(NS + "name") == "android.intent.category.LAUNCHER"
                        for c in f.findall("category"))
                for f in filters)
            if exported_attr is not None:
                exported = exported_attr == "true"
            elif tag == "provider":
                exported = (target_sdk or 0) < 17
            else:
                exported = bool(filters) and (target_sdk or 0) < 31
            guarded = bool(el.get(NS + "permission") or el.get(NS + "readPermission")
                           or el.get(NS + "writePermission"))
            deeplinks = []
            for f in filters:
                for d in f.findall("data"):
                    scheme = d.get(NS + "scheme")
                    if scheme:
                        deeplinks.append((scheme, d.get(NS + "host") or ""))
            comps.append({"tag": tag, "name": name, "exported": exported,
                          "guarded": guarded, "launcher": launcher,
                          "deeplinks": deeplinks})
    return comps, app


def _cert_info(apk):
    info = {"signed": apk.is_signed(),
            "schemes": [s for s, fn in (("v1", apk.is_signed_v1), ("v2", apk.is_signed_v2),
                                        ("v3", apk.is_signed_v3)) if _safe(fn)],
            "subject": "", "issuer": "", "not_after": "", "hash_alg": "",
            "debug": False, "expired": False}
    try:
        from cryptography import x509 as _x509
        for cert in apk.get_certificates():
            try:
                c = _x509.load_der_x509_certificate(cert.dump())
            except Exception:
                continue
            info["subject"] = c.subject.rfc4514_string()
            info["issuer"] = c.issuer.rfc4514_string()
            try:
                info["hash_alg"] = c.signature_hash_algorithm.name
            except Exception:
                pass
            na = c.not_valid_after_utc
            info["not_after"] = na.strftime("%Y-%m-%d")
            info["expired"] = na < datetime.now(timezone.utc)
            info["debug"] = "Android Debug" in info["subject"] or \
                            "Android Debug" in info["issuer"]
            break
    except Exception:
        pass
    return info


def _safe(fn):
    try:
        return bool(fn())
    except Exception:
        return False


def _contents_inventory(zf, names, strip_prefix=""):
    """Bongkar isi paket: inventaris file dari arsip ZIP (APK/IPA)."""
    files = [n for n in names if not n.endswith("/")]
    sizes = {}
    for n in files:
        try:
            sizes[n] = zf.getinfo(n).file_size
        except Exception:
            sizes[n] = 0
    dex = [{"name": n, "size": sizes[n]} for n in sorted(files)
           if re.fullmatch(r"classes\d*\.dex", n.rsplit("/", 1)[-1])]
    native_libs = {}
    assets = []
    frameworks = set()
    groups = {}
    for n in files:
        rel = n[len(strip_prefix):] if strip_prefix and n.startswith(strip_prefix) else n
        m = re.match(r"lib/([^/]+)/([^/]+\.so)$", rel)
        if m:
            native_libs.setdefault(m.group(1), []).append(m.group(2))
        if rel.startswith("assets/"):
            assets.append(rel)
        mf = re.match(r"Frameworks/([^/]+)\.framework/", rel)
        if mf:
            frameworks.add(mf.group(1))
        top = rel.split("/")[0] if "/" in rel else "(root)"
        groups[top] = groups.get(top, 0) + 1
    largest = [{"name": n, "size": sz}
               for n, sz in sorted(sizes.items(), key=lambda kv: -kv[1])[:10]]
    return {"total_files": len(files),
            "total_uncompressed": sum(sizes.values()),
            "dex_files": dex, "native_libs": native_libs,
            "assets": assets[:100], "frameworks": sorted(frameworks),
            "groups": groups, "largest": largest}


def _dex_packages(zf, names):
    """Histogram paket kelas DEX -> library/SDK yang tertanam di APK."""
    pkgs, total = {}, 0
    try:
        from androguard.core.dex import DEX
    except Exception:
        return {"classes": 0, "packages": []}
    for n in names:
        if not re.fullmatch(r"classes\d*\.dex", n.rsplit("/", 1)[-1]):
            continue
        try:
            d = DEX(zf.read(n))
            cls = d.get_classes_names()
        except Exception:
            continue
        for c in cls:
            total += 1
            raw = c[1:-1] if c.startswith("L") and c.endswith(";") else c
            seg = raw.split("/")
            key = ".".join(seg[:3]) if len(seg) >= 3 else ".".join(seg)
            if key:
                pkgs[key] = pkgs.get(key, 0) + 1
    top = sorted(pkgs.items(), key=lambda kv: -kv[1])[:15]
    return {"classes": total,
            "packages": [{"package": k, "classes": v} for k, v in top if v >= 5]}


_DISASM_MAX_CLASSES = 40
_DISASM_MAX_METHODS = 40
_DISASM_MAX_INS = 120
_DISASM_BUDGET = 520000
_CLASSLIST_CAP = 2000


def _scf(obj, *names):
    """Panggil accessor androguard dengan aman (coba beberapa nama) -> string."""
    for name in names:
        fn = getattr(obj, name, None)
        if fn is None:
            continue
        try:
            v = fn()
        except Exception:
            continue
        return v if isinstance(v, str) else ("" if v is None else str(v))
    return ""


_LIB_PREFIXES = ("Landroid/", "Landroidx/", "Ljava/", "Ljavax/", "Lkotlin/",
                 "Lkotlinx/", "Lcom/google/", "Lokhttp3/", "Lokio/",
                 "Lretrofit2/", "Lcom/android/")


def _decompile_apk(apk, zf, names, pkg):
    """Decompile terbaca (build sendiri di atas parser androguard):
    - AndroidManifest.xml ter-decode (AXML -> XML teks)
    - sampel res/*.xml biner ter-decode + string resources.arsc (best-effort)
    - disassembly DEX (opcode + operand, gaya smali) untuk kelas-kelas paket
      aplikasi sendiri — dibatasi keras agar hasil scan tetap ringkas.
    Kelas library pihak ketiga hanya didaftar namanya (class_list)."""
    out = {"classes_total": 0, "class_list": [], "disassembled": [],
           "resources": {"manifest_xml": "", "xml_samples": [], "strings": {}},
           "truncated": False}
    try:
        out["resources"]["manifest_xml"] = apk.get_android_manifest_axml() \
            .get_xml().decode("utf-8", "replace")[:12000]
    except Exception:
        pass
    try:
        from androguard.core.axml import AXMLPrinter
        for n in names:
            if len(out["resources"]["xml_samples"]) >= 6:
                break
            if n.startswith("res/") and n.endswith(".xml"):
                try:
                    x = AXMLPrinter(zf.read(n)).get_buff().decode("utf-8", "replace")
                    if x.strip():
                        out["resources"]["xml_samples"].append(
                            {"name": n, "text": x[:6000]})
                except Exception:
                    continue
    except Exception:
        pass
    try:
        arsc = apk.get_android_resources()
        pkgs = arsc.get_packages_names() or []
        got = {}
        for pname in pkgs[:1]:
            fn = getattr(arsc, "get_string_resources", None)
            if fn is None:
                break
            try:
                d = fn(pname)
            except Exception:
                d = None
            if isinstance(d, dict):
                for k, v in list(d.items())[:100]:
                    got[str(k)] = str(v)[:120]
            break
        out["resources"]["strings"] = got
    except Exception:
        pass
    try:
        from androguard.core.dex import DEX
    except Exception:
        return out
    prefix = "L" + (pkg or "").replace(".", "/") + "/"
    budget = _DISASM_BUDGET
    all_classes = []
    for n in names:
        if not re.fullmatch(r"classes\d*\.dex", n.rsplit("/", 1)[-1]):
            continue
        try:
            d = DEX(zf.read(n))
        except Exception:
            continue
        for c in d.get_classes():
            cname = _scf(c, "get_name")
            out["classes_total"] += 1
            try:
                mcount = len(c.get_methods())
            except Exception:
                mcount = 0
            if len(out["class_list"]) < _CLASSLIST_CAP:
                out["class_list"].append({"name": cname, "methods": mcount})
            all_classes.append((cname, c))
    own = [x for x in all_classes if x[0].startswith(prefix)]
    rest = [x for x in all_classes
            if not x[0].startswith(prefix)
            and not x[0].startswith(_LIB_PREFIXES)]
    for cname, c in own + rest:
        if len(out["disassembled"]) >= _DISASM_MAX_CLASSES or budget <= 0:
            out["truncated"] = True
            break
        entry = {"name": cname,
                 "superclass": _scf(c, "get_superclassname"),
                 "source_file": _scf(c, "get_source", "get_source_ext"),
                 "methods": []}
        try:
            methods = c.get_methods()
        except Exception:
            methods = []
        for m in methods[:_DISASM_MAX_METHODS]:
            lines = []
            try:
                code = m.get_code()
                if code is not None:
                    for i, ins in enumerate(code.get_bc().get_instructions()):
                        if i >= _DISASM_MAX_INS:
                            lines.append("... (instruction list truncated)")
                            break
                        lines.append(f"{_scf(ins, 'get_name')} {_scf(ins, 'get_output')}".strip())
            except Exception:
                lines = []
            budget -= sum(len(x) + 1 for x in lines)
            entry["methods"].append(
                {"name": _scf(m, "get_name"),
                 "descriptor": _scf(m, "get_descriptor"),
                 "access": _scf(m, "get_access_flags_string"),
                 "instructions": lines})
        out["disassembled"].append(entry)
    return out


def _plist_text(data):
    try:
        obj = plistlib.loads(data)
        return json.dumps(obj, indent=1, default=str)[:12000]
    except Exception:
        return ""


def analyze_apk(path, filename="app.apk", log=None):
    """Analisis statis satu file APK -> result dict kompatibel store.save_scan."""
    def L(msg):
        if log is not None:
            log.append(msg)
    try:
        from androguard.core.apk import APK
    except Exception as e:
        raise RuntimeError(f"androguard is not available in this environment: {e}")
    import logging as _lg
    _lg.getLogger("androguard").setLevel(_lg.CRITICAL)
    try:  # androguard 4 memakai loguru — bungkam agar log service tidak banjir
        from loguru import logger as _lgr
        _lgr.disable("androguard")
    except Exception:
        pass

    raw = open(path, "rb").read()
    if len(raw) > 60 * 1024 * 1024:
        raise ValueError("Package too large (max 60 MB)")
    sha = hashlib.sha256(raw).hexdigest()
    apk = APK(path)
    pkg = apk.get_package() or "(unknown)"
    app_name = apk.get_app_name() or ""
    ver_name, ver_code = apk.get_androidversion_name(), apk.get_androidversion_code()
    min_sdk = int(apk.get_min_sdk_version() or 0)
    target_sdk = int(apk.get_target_sdk_version() or 0)
    perms = sorted(set(apk.get_permissions()))
    L(f"[mobile] {filename}: {pkg} v{ver_name} (min {min_sdk} / target {target_sdk}), "
      f"{len(perms)} permission")

    root = _manifest_tree(apk)
    comps, app_el = _components(root, target_sdk)
    def app_attr(k):
        return app_el.get(NS + k) if app_el is not None else None

    zf = zipfile.ZipFile(path)
    names = zf.namelist()
    strings, raw_urls = _extract_strings_and_urls(zf, names)
    L(f"[mobile] {len(strings)} unique strings, {len(raw_urls)} raw URLs")

    endpoints, http_hosts = [], set()
    seen_hosts = {}
    for u in sorted(raw_urls):
        try:
            sp = urlsplit(u)
        except Exception:
            continue
        host = (sp.hostname or "").lower()
        if not host or host in _NON_ENDPOINT_HOSTS:
            continue
        if sp.path.endswith((".xsd", ".dtd")) or "schemas." in host:
            continue
        endpoints.append({"url": u[:220], "host": host, "scheme": sp.scheme})
        seen_hosts[host] = seen_hosts.get(host, 0) + 1
        if sp.scheme == "http":
            http_hosts.add(host)
    endpoints = endpoints[:300]

    findings = []
    def add(f):
        key = (f["title"], f.get("location", ""), f.get("param", ""))
        if not any((x["title"], x.get("location", ""), x.get("param", "")) == key
                   for x in findings):
            findings.append(f)

    M = "AndroidManifest.xml"
    # ---- 1. debuggable
    if app_attr("debuggable") == "true":
        add(F("HIGH", 'App is debuggable (android:debuggable=true)',
              'The release APK carries the debuggable flag, so anyone can attach a debugger, read process memory, and bypass many runtime controls.',
              evidence="android:debuggable=\"true\" on <application>",
              cwe="CWE-489", owasp="MASVS-RESILIENCE", cvss=5.5,
              remed='Set android:debuggable="false" (default for release builds) and make sure the CI pipeline never ships debug builds.',
              confidence="confirmed", location=M))
    # ---- 2. allowBackup
    ab = app_attr("allowBackup")
    if ab == "true":
        add(F("MEDIUM", 'App backups allowed (android:allowBackup=true)',
              'App data can be extracted via ADB/cloud backup by anyone holding the device or the backup account.',
              evidence="android:allowBackup=\"true\"", cwe="CWE-359",
              owasp="MASVS-STORAGE", cvss=5.3,
              remed='Set allowBackup="false" or define backup rules that exclude sensitive data.',
              confidence="confirmed", location=M))
    elif ab is None and target_sdk and target_sdk <= 30:
        add(F("LOW", 'allowBackup not set — backups allowed by default (targetSdk <= 30)',
              'Without an explicit attribute, Android allows backups for this targetSdk.',
              evidence=f"targetSdkVersion={target_sdk}, allowBackup absent",
              cwe="CWE-359", owasp="MASVS-STORAGE", cvss=3.1,
              remed="Set allowBackup explicitly according to the app's data policy.",
              confidence="candidate", location=M))
    # ---- 3. cleartext: network security config > atribut manifest > default target
    nsc_name = None
    nsc_ref = app_attr("networkSecurityConfig")
    if nsc_ref and nsc_ref.startswith("@xml/"):
        cand = f"res/xml/{nsc_ref[5:]}.xml"
        if cand in names:
            nsc_name = cand
    nsc_clear, nsc_domains, nsc_pinning = None, [], False
    if nsc_name:
        try:
            from androguard.core.axml import AXMLPrinter
            x = AXMLPrinter(zf.read(nsc_name)).get_buff().decode("utf-8", "replace")
            m = re.search(r'cleartextTrafficPermitted="([^"]+)"', x)
            nsc_clear = (m.group(1) == "true") if m else None
            nsc_domains = re.findall(r"<domain[^>]*>([^<]+)</domain>", x)
            nsc_pinning = "<pin-set" in x or "<pin " in x
        except Exception:
            nsc_name = None
    ct_attr = app_attr("usesCleartextTraffic")
    if nsc_clear is True:
        add(F("HIGH", 'Cleartext traffic allowed by network security config',
              'The network security configuration explicitly allows unencrypted HTTP, so traffic can be intercepted/modified on the network.',
              evidence=f"{nsc_name}: cleartextTrafficPermitted=true"
                       + (f" domain: {', '.join(nsc_domains[:5])}" if nsc_domains else ""),
              cwe="CWE-319", owasp="MASVS-NETWORK", cvss=7.4,
              remed='Set cleartextTrafficPermitted=false; use HTTPS for all endpoints.',
              confidence="confirmed", location=nsc_name))
    elif nsc_clear is None and ct_attr == "true":
        add(F("HIGH", "Cleartext traffic allowed (usesCleartextTraffic=true)",
              'The app allows unencrypted HTTP connections to all domains.',
              evidence="android:usesCleartextTraffic=\"true\"", cwe="CWE-319",
              owasp="MASVS-NETWORK", cvss=7.4,
              remed='Set usesCleartextTraffic=false and use HTTPS; if exceptions are needed, scope them per domain via network security config.',
              confidence="confirmed", location=M))
    elif nsc_clear is None and ct_attr is None and target_sdk and target_sdk < 28:
        add(F("MEDIUM", "Cleartext traffic allowed by default (targetSdk < 28)",
              'For targetSdk below 28, Android allows HTTP by default unless the app states otherwise.',
              evidence=f"targetSdkVersion={target_sdk}, usesCleartextTraffic absent",
              cwe="CWE-319", owasp="MASVS-NETWORK", cvss=5.3,
              remed='Raise targetSdk and/or set usesCleartextTraffic=false explicitly.',
              confidence="probable", location=M))
    # ---- 4. permission berbahaya
    very = [p for p in perms if p in _PERM_VERY]
    dang = [p for p in perms if p in _PERM_DANGEROUS]
    if dang:
        add(F("HIGH" if very else "MEDIUM",
              f"Dangerous permissions requested: {len(dang)} sensitive permissions",
              'The app requests permissions categorized as dangerous. Every permission is attack surface & a privacy risk if the app/device is compromised; make sure each one is truly required by a feature.',
              evidence=", ".join(dang[:12]) + (" ..." if len(dang) > 12 else ""),
              cwe="CWE-276", owasp="MASVS-PRIVACY", cvss=6.5 if very else 5.0,
              remed='Apply least-privilege: revoke non-essential permissions and explain sensitive permission needs to users.',
              confidence="confirmed", location=M))
    # ---- 5. komponen exported tanpa proteksi
    exposed = [c for c in comps if c["exported"] and not c["guarded"] and not c["launcher"]]
    if exposed:
        worst = "HIGH" if any(c["tag"] in ("service", "receiver", "provider")
                              for c in exposed) else "MEDIUM"
        add(F(worst, f"Exported components without permission protection: {len(exposed)} components",
              'Activities/services/receivers/providers that are exported without android:permission can be invoked by other apps — a classic Android attack surface (intent spoofing, provider data theft, unauthorized service triggering).',
              evidence="; ".join(f"{c['tag']}:{c['name']}" for c in exposed[:8]),
              cwe="CWE-926", owasp="MASVS-PLATFORM", cvss=7.5 if worst == "HIGH" else 5.3,
              remed='Set exported=false for internal components, or protect them with a signature-level permission for those that must be public.',
              confidence="confirmed", location=M))
    http_links = [(c, s, h) for c in comps for (s, h) in c["deeplinks"] if s == "http"]
    if http_links:
        add(F("LOW", "Deep link uses the http scheme (not https)",
              'Deep links/app links over http can be hijacked by other apps and their traffic is unencrypted.',
              evidence="; ".join(f"{c['name']} -> http://{h}" for c, _, h in http_links[:5]),
              cwe="CWE-319", owasp="MASVS-NETWORK", cvss=3.7,
              remed='Use https app links with domain verification (assetlinks.json).',
              confidence="probable", location=M))
    # ---- 6. secrets di dalam string APK
    joined_hits = []
    for kind, rx, sev, cvss, title, desc in _SECRET_PATTERNS:
        hits = [s for s in strings if rx.search(s)]
        if hits:
            m = rx.search(hits[0])
            add(F(sev, title, desc, evidence=_mask(m.group(0)) + f" (found in {len(hits)} matching strings)",
                  cwe="CWE-798", owasp="MASVS-STORAGE", cvss=cvss,
                  remed='Revoke/rotate this credential right now; long-lived credentials must never be embedded in an APK.',
                  confidence="probable", location="classes.dex/assets"))
    generic = [s for s in strings if _GENERIC_SECRET_RE.search(s)]
    if generic:
        add(F("LOW", f"Hardcoded credential indication in APK strings ({len(generic)} patterns)",
              'A credential assignment pattern (api key/secret/password/token) was found among the strings inside the APK. Manual verification is required to determine whether the value is a real, still-active credential.',
              evidence="; ".join(_mask(g[:48]) for g in list(generic)[:3]),
              cwe="CWE-798", owasp="MASVS-STORAGE", cvss=3.7,
              remed='Manually verify each pattern; if active, revoke it and move it to the backend.',
              confidence="candidate", location="classes.dex/assets"))
    fb = [u for u in endpoints if "firebaseio.com" in u["host"] or
          "firebasedatabase.app" in u["host"]]
    if fb:
        add(F("LOW", 'Firebase database URL exposed in the APK',
              'The Realtime Database/Firestore URL is exposed (normal for client configuration) — security depends entirely on the security rules; open rules = public data leak.',
              evidence=fb[0]["url"][:140], cwe="CWE-200", owasp="MASVS-STORAGE",
              cvss=3.1, remed='Audit the Firebase security rules: ensure there is no public read/write without authentication.',
              confidence="candidate", location="classes.dex/assets"))
    # ---- 7. endpoint http (cleartext) nyata
    if http_hosts:
        add(F("MEDIUM", f"HTTP endpoint (unencrypted) found: {len(http_hosts)} host",
              'The APK contains http:// URLs to real hosts. If actually called at runtime, the traffic (including tokens) can be intercepted on the network.',
              evidence=", ".join(sorted(http_hosts)[:8]), cwe="CWE-319",
              owasp="MASVS-NETWORK", cvss=5.3,
              remed='Migrate all endpoints to https and enable HSTS on the server side.',
              confidence="probable", location="classes.dex/assets"))
    # ---- 8. indikasi API berisiko (kandidat — perlu verifikasi kode)
    if any("addJavascriptInterface" in s for s in strings):
        add(F("INFO", 'Indication of addJavascriptInterface usage (WebView)',
              'The DEX strings reference addJavascriptInterface. Misconfigured, this opens a JavaScript -> native code bridge (potential RCE from web content). Manual source-code verification is required.',
              evidence="the 'addJavascriptInterface' string was found in the DEX",
              cwe="CWE-749", owasp="MASVS-PLATFORM", cvss=2.0,
              remed='Restrict @JavascriptInterface to trusted pages only; disable it if not needed.',
              confidence="candidate", location="classes.dex"))
    if any("ECB" in s and ("AES" in s or "DESede" in s) for s in strings):
        add(F("LOW", 'Indication of ECB encryption mode usage',
              'A cryptographic transformation string for ECB was found. ECB leaks plaintext patterns and must not be used for structured data.',
              evidence="an '*/ECB/*' transformation string in the DEX", cwe="CWE-327",
              owasp="MASVS-CRYPTO", cvss=3.7,
              remed='Use AES-GCM (or ChaCha20-Poly1305) with a random IV per message.',
              confidence="candidate", location="classes.dex"))
    # ---- 9. sertifikat & tanda tangan
    cert = _cert_info(apk)
    if not cert["signed"]:
        add(F("HIGH", 'APK is not signed',
              "The package has no valid signature — the app's integrity & origin cannot be verified.",
              evidence='no v1/v2/v3 signature scheme', cwe="CWE-345",
              owasp="MASVS-RESILIENCE", cvss=7.0,
              remed='Sign the APK with a protected release keystore (Play App Signing recommended).',
              confidence="confirmed", location="META-INF"))
    else:
        if cert["debug"]:
            add(F("MEDIUM", 'APK signed with the Android debug certificate',
                  "The 'Android Debug' certificate means this is a development build — its key is public and identical on every developer machine.",
                  evidence=cert["subject"][:120], cwe="CWE-321",
                  owasp="MASVS-RESILIENCE", cvss=5.3,
                  remed="Release only with the organization's release certificate.",
                  confidence="confirmed", location="META-INF"))
        if cert["expired"]:
            add(F("MEDIUM", 'Signing certificate has expired',
                  f"The signing certificate expired on {cert['not_after']} — app updates and installation verification may be disrupted.",
                  evidence=f"notAfter={cert['not_after']}", cwe="CWE-324",
                  owasp="MASVS-RESILIENCE", cvss=5.3,
                  remed='Renew/rotate the certificate per Play App Signing policy.',
                  confidence="confirmed", location="META-INF"))
        if cert["hash_alg"] in ("sha1", "md5"):
            add(F("LOW", f"Weak signature hash algorithm ({cert['hash_alg']})",
                  'The certificate uses a hash that is no longer considered safe for long-term signatures.',
                  evidence=f"signature_hash_algorithm={cert['hash_alg']}", cwe="CWE-327",
                  owasp="MASVS-RESILIENCE", cvss=3.7,
                  remed='Migrate to a SHA-256 or stronger certificate.',
                  confidence="probable", location="META-INF"))
        if cert["schemes"] == ["v1"]:
            add(F("LOW", "APK signed with the v1 scheme only (JAR signing)",
                  'Without the v2+ scheme, the APK is vulnerable to the Janus attack class on old Android versions and lacks full integrity protection.',
                  evidence="signature schemes: v1 only", cwe="CWE-345",
                  owasp="MASVS-RESILIENCE", cvss=3.7,
                  remed='Enable the v2/v3 scheme when signing (modern apksigner default).',
                  confidence="candidate", location="META-INF"))
    # ---- 10. versi SDK
    if target_sdk and target_sdk < 33:
        add(F("LOW", f"Outdated targetSdkVersion ({target_sdk})",
              "An old target SDK means the app does not get modern Android default security behaviors (exported restrictions, runtime permissions, cleartext defaults) and violates Google Play's minimum policy.",
              evidence=f"targetSdkVersion={target_sdk}", cwe="CWE-1104",
              owasp="MASVS-CODE", cvss=3.7,
              remed="Raise targetSdkVersion to meet the latest Google Play requirements.",
              confidence="probable", location=M))
    if min_sdk and min_sdk < 24:
        add(F("LOW", f"Very old minSdkVersion ({min_sdk})",
              'The app still supports very old Android versions that no longer receive security patches and lack many modern platform controls.',
              evidence=f"minSdkVersion={min_sdk}", cwe="CWE-1104",
              owasp="MASVS-CODE", cvss=3.1,
              remed='Consider raising minSdkVersion (Android 7.0/API 24+ as a common baseline).',
              confidence="candidate", location=M))

    summary = {}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    risk = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if summary.get(s)), "CLEAN")
    score = risk_score(findings)
    contents = _contents_inventory(zf, names)
    dex_pkgs = _dex_packages(zf, names)
    contents["dex_classes"] = dex_pkgs["classes"]
    decomp = _decompile_apk(apk, zf, names, pkg)
    contents["bundled_packages"] = dex_pkgs["packages"]
    abi_txt = ", ".join(f"{a} ({len(v)} lib)" for a, v in sorted(contents["native_libs"].items()))
    add(F("INFO", f"Package contents inventoried: {contents['total_files']} files, "
                  f"{len(contents['dex_files'])} DEX, {dex_pkgs['classes']} classes",
          'Full static unpacking inventory of the APK: every file, DEX bytecode, native library and asset was enumerated (see the scan metadata contents section).',
          evidence=f"{contents['total_uncompressed']} bytes uncompressed; DEX: "
                   + ", ".join(d["name"] for d in contents["dex_files"])[:120]
                   + (f"; native ABIs: {abi_txt}" if abi_txt else "; no native libraries"),
          cwe="CWE-200", owasp="MASVS-CODE", cvss=0.0,
          remed='No action required — inventory recorded for attack-surface mapping.',
          confidence="confirmed", location=filename))
    meta = {"platform": "android", "contents": contents, "decompile": decomp,
            "package": pkg, "app_name": app_name, "version_name": ver_name,
            "version_code": ver_code, "min_sdk": min_sdk, "target_sdk": target_sdk,
            "file_name": filename, "file_size": len(raw), "sha256": sha,
            "permissions": perms, "dangerous_permissions": dang,
            "components": {"total": len(comps),
                           "exported": [f"{c['tag']}:{c['name']}" for c in comps if c["exported"]]},
            "cert": cert, "pinning_detected": nsc_pinning,
            "endpoints": endpoints, "endpoint_hosts": sorted(seen_hosts)}
    L(f"[mobile] done: {len(findings)} findings | risk {risk} | score {score}/100 | {len(endpoints)} endpoint ({len(seen_hosts)} host)")
    target_label = f"{pkg} ({filename})"
    return {"type": "mobile", "target": target_label, "profile": "apk-static",
            "method": "static", "findings": findings, "summary": summary,
            "overall_risk": risk, "risk_score": score, "meta": meta,
            "endpoints": endpoints, "warnings": [], "errors": []}


# =====================================================================
# iOS IPA — analyzer statis (v3.10). IPA = ZIP berisi Payload/<App>.app:
# Info.plist (plistlib menangani format biner), embedded.mobileprovision
# (plist di dalam blob CMS), dan executable Mach-O (header di-parse manual
# dengan struct — tanpa tool decompiler jadi, sesuai aturan build sendiri).
# Batas jujur: IPA dari App Store terenkripsi FairPlay (cryptid=1) — string
# executable tidak dapat dibaca; analisis dibatasi ke plist & aset. IPA
# development/decrypted (cryptid=0) terbaca penuh.
# =====================================================================
import json
import plistlib
import struct

_MACHO_CPU = {7: "x86", 0x01000007: "x86_64", 12: "armv7", 14: "armv7s",
              9: "armv6", 0x0100000C: "arm64", 0x0200000C: "arm64_32"}


def _macho_info(data):
    """Parse header Mach-O (thin/fat): arsitektur, flag PIE, cryptid."""
    out = {"archs": [], "pie": None, "cryptid": None, "encrypted": None}
    if not data or len(data) < 4:
        return out
    magic = bytes(data[:4])
    if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):  # FAT
        fmt = ">" if magic == b"\xca\xfe\xba\xbe" else "<"
        try:
            n = struct.unpack(fmt + "I", data[4:8])[0]
            off, slices = 8, []
            for _ in range(min(n, 8)):
                cputype, _s, offset, _sz, _a = struct.unpack(
                    fmt + "IIIII", data[off:off + 20])
                out["archs"].append(_MACHO_CPU.get(cputype, hex(cputype)))
                slices.append(offset)
                off += 20
            if slices:
                sub = _macho_info(data[slices[0]:])
                out["pie"], out["cryptid"] = sub["pie"], sub["cryptid"]
        except Exception:
            pass
        out["encrypted"] = (out["cryptid"] == 1) if out["cryptid"] is not None else None
        return out
    if magic == b"\xcf\xfa\xed\xfe":
        endian, is64 = "<", True
    elif magic == b"\xce\xfa\xed\xfe":
        endian, is64 = "<", False
    elif magic == b"\xfe\xed\xfa\xcf":
        endian, is64 = ">", True
    elif magic == b"\xfe\xed\xfa\xce":
        endian, is64 = ">", False
    else:
        return out
    try:
        cputype, _st, _ft, ncmds, _szc, flags = struct.unpack(
            endian + "IIIIII", data[4:28])
        out["archs"] = [_MACHO_CPU.get(cputype, hex(cputype))]
        out["pie"] = bool(flags & 0x200000)  # MH_PIE
        off = 32 if is64 else 28
        for _ in range(min(ncmds, 300)):
            cmd, cmdsize = struct.unpack(endian + "II", data[off:off + 8])
            if cmd in (0x21, 0x2C) and cmdsize >= 20:  # LC_ENCRYPTION_INFO(_64)
                out["cryptid"] = struct.unpack(endian + "I", data[off + 16:off + 20])[0]
            if cmdsize < 8:
                break
            off += cmdsize
    except Exception:
        pass
    out["encrypted"] = (out["cryptid"] == 1) if out["cryptid"] is not None else None
    return out


def _provision_info(zf, names):
    cand = [n for n in names if n.endswith("embedded.mobileprovision")]
    if not cand:
        return None
    raw = zf.read(cand[0])
    a, b = raw.find(b"<?xml"), raw.find(b"</plist>")
    if a < 0 or b < 0:
        return {"parse_error": True}
    try:
        pl = plistlib.loads(raw[a:b + len(b"</plist>")])
    except Exception:
        return {"parse_error": True}
    ent = pl.get("Entitlements") or {}
    devices = pl.get("ProvisionedDevices") or []
    exp = pl.get("ExpirationDate")
    info = {"name": pl.get("Name", ""), "team_name": pl.get("TeamName", ""),
            "app_id_name": pl.get("AppIDName", ""),
            "expires": exp.strftime("%Y-%m-%d") if isinstance(exp, datetime) else "",
            "expired": bool(exp and isinstance(exp, datetime)
                            and exp.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)),
            "get_task_allow": bool(ent.get("get-task-allow")),
            "application_identifier": ent.get("application-identifier", ""),
            "keychain_groups": len(ent.get("keychain-access-groups") or []),
            "devices": len(devices)}
    if pl.get("ProvisionsAllDevices"):
        info["distribution"] = "enterprise"
    elif devices:
        info["distribution"] = "development/ad-hoc"
    else:
        info["distribution"] = "app-store"
    return info


def analyze_ipa(path, filename="app.ipa", log=None):
    """Analisis statis satu file IPA -> result dict kompatibel store.save_scan."""
    def L(msg):
        if log is not None:
            log.append(msg)
    raw = open(path, "rb").read()
    if len(raw) > 60 * 1024 * 1024:
        raise ValueError("Package too large (max 60 MB)")
    sha = hashlib.sha256(raw).hexdigest()
    zf = zipfile.ZipFile(path)
    names = zf.namelist()
    app_prefix = None
    for n in names:
        parts = n.split("/")
        if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
            app_prefix = "/".join(parts[:2]) + "/"
            break
    if not app_prefix:
        raise ValueError("Not a valid IPA: no Payload/<App>.app bundle found")
    try:
        info = plistlib.loads(zf.read(app_prefix + "Info.plist"))
    except Exception as e:
        raise ValueError(f"Info.plist could not be parsed: {e}")
    bundle_id = info.get("CFBundleIdentifier") or "(unknown)"
    app_name = info.get("CFBundleDisplayName") or info.get("CFBundleName") or ""
    ver_name = info.get("CFBundleShortVersionString") or ""
    ver_code = str(info.get("CFBundleVersion") or "")
    min_os = info.get("MinimumOSVersion") or ""
    exe_name = info.get("CFBundleExecutable") or ""
    L(f"[mobile] {filename}: {bundle_id} v{ver_name} (min iOS {min_os})")

    contents = _contents_inventory(zf, names, strip_prefix=app_prefix)
    prov = _provision_info(zf, names)
    signed = any(n.startswith(app_prefix + "_CodeSignature/") for n in names)

    macho = {"archs": [], "pie": None, "cryptid": None, "encrypted": None}
    exe_data = b""
    if exe_name and (app_prefix + exe_name) in names:
        exe_data = zf.read(app_prefix + exe_name)
        macho = _macho_info(exe_data)
    encrypted = macho.get("encrypted") is True

    # ---- string & URL: executable hanya bila TIDAK terenkripsi FairPlay
    strings, raw_urls = set(), set()
    scan_blobs = []
    if exe_data and not encrypted:
        scan_blobs.append(exe_data)
    for n in names:
        if not n.startswith(app_prefix) or n.endswith("/"):
            continue
        low = n.lower()
        if low.endswith((".plist", ".json", ".js", ".txt", ".strings", ".xml")) \
                and not low.endswith("info.plist"):
            try:
                if zf.getinfo(n).file_size <= 4 * 1024 * 1024:
                    scan_blobs.append(zf.read(n))
            except Exception:
                pass
    budget = 90 * 1024 * 1024
    for data in scan_blobs:
        if len(data) > budget:
            data = data[:budget]
        budget -= len(data)
        for m in _URL_RE.findall(data):
            raw_urls.add(m.decode("utf-8", "replace").rstrip(")]>\"'.,;"))
        for m in _STR_RE.findall(data):
            try:
                strings.add(m.decode("utf-8"))
            except Exception:
                pass
        if budget <= 0:
            break
    L(f"[mobile] {len(strings)} unique strings, {len(raw_urls)} raw URLs"
      + (" (executable encrypted — strings skipped)" if encrypted else ""))

    endpoints, http_hosts, seen_hosts = [], set(), {}
    for u in sorted(raw_urls):
        try:
            sp = urlsplit(u)
        except Exception:
            continue
        host = (sp.hostname or "").lower()
        if not host or host in _NON_ENDPOINT_HOSTS or "schemas." in host:
            continue
        if sp.path.endswith((".xsd", ".dtd")):
            continue
        endpoints.append({"url": u[:220], "host": host, "scheme": sp.scheme})
        seen_hosts[host] = seen_hosts.get(host, 0) + 1
        if sp.scheme == "http":
            http_hosts.add(host)
    endpoints = endpoints[:300]

    findings = []
    def add(f):
        key = (f["title"], f.get("location", ""), f.get("param", ""))
        if not any((x["title"], x.get("location", ""), x.get("param", "")) == key
                   for x in findings):
            findings.append(f)
    IP = "Info.plist"
    # ---- inventaris (fakta bongkar isi)
    add(F("INFO", f"Package contents inventoried: {contents['total_files']} files, "
                  f"{len(contents['frameworks'])} frameworks",
          'Full static unpacking inventory of the IPA: every file in the .app bundle was enumerated (see the scan metadata contents section).',
          evidence=f"{contents['total_uncompressed']} bytes uncompressed; archs: "
                   + (", ".join(macho['archs']) or "?")
                   + (f"; frameworks: {', '.join(contents['frameworks'][:8])}" if contents["frameworks"] else ""),
          cwe="CWE-200", owasp="MASVS-CODE", cvss=0.0,
          remed='No action required — inventory recorded for attack-surface mapping.',
          confidence="confirmed", location=filename))
    # ---- enkripsi FairPlay (batas analisis — dinyatakan jujur)
    if encrypted:
        add(F("INFO", "Main binary is FairPlay-encrypted (App Store build)",
              'The executable carries cryptid=1, so its strings/code cannot be read statically. String-based checks in this report cover only the plist/asset files; analyze a decrypted/development build for full coverage.',
              evidence="LC_ENCRYPTION_INFO cryptid=1", cwe="CWE-200",
              owasp="MASVS-CODE", cvss=0.0,
              remed='No action required — platform protection working as intended.',
              confidence="confirmed", location=exe_name or "Mach-O"))
    # ---- ATS / cleartext
    ats = info.get("NSAppTransportSecurity") or {}
    if ats.get("NSAllowsArbitraryLoads") is True:
        add(F("HIGH", "Cleartext traffic allowed for all domains (NSAllowsArbitraryLoads)",
              'App Transport Security is fully disabled: the app may load unencrypted HTTP from any domain, exposing traffic to interception/modification.',
              evidence="NSAppTransportSecurity.NSAllowsArbitraryLoads = true",
              cwe="CWE-319", owasp="MASVS-NETWORK", cvss=7.4,
              remed='Remove NSAllowsArbitraryLoads; use HTTPS everywhere and scope any exception per domain with a justification.',
              confidence="confirmed", location=IP))
    for dom, cfg in (ats.get("NSExceptionDomains") or {}).items():
        if isinstance(cfg, dict) and cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True:
            add(F("MEDIUM", f"ATS exception allows insecure HTTP loads: {dom}",
                  'This domain is exempted from ATS and may be contacted over plaintext HTTP.',
                  evidence=f"NSExceptionDomains.{dom}.NSExceptionAllowsInsecureHTTPLoads = true",
                  cwe="CWE-319", owasp="MASVS-NETWORK", cvss=5.3,
                  remed='Serve this domain over HTTPS and remove the exception.',
                  confidence="confirmed", location=IP))
    # ---- URL scheme kustom (deep link)
    schemes = []
    for t in info.get("CFBundleURLTypes") or []:
        if isinstance(t, dict):
            schemes += [s for s in (t.get("CFBundleURLSchemes") or []) if isinstance(s, str)]
    custom = [s for s in schemes if s.lower() not in ("http", "https", "mailto", "tel")]
    if custom:
        add(F("LOW", f"Custom URL schemes registered: {', '.join(custom[:6])}",
              'Custom URL schemes can be claimed by any app on the device (deep-link hijacking / invocation by other apps). Sensitive actions must not be triggerable via scheme alone.',
              evidence=f"CFBundleURLSchemes: {', '.join(schemes[:8])}",
              cwe="CWE-939", owasp="MASVS-PLATFORM", cvss=3.7,
              remed='Use universal links (https + associated domains) for sensitive flows and validate parameters of incoming URLs.',
              confidence="probable", location=IP))
    if "http" in [s.lower() for s in schemes]:
        add(F("LOW", "Deep link uses the http scheme (not https)",
              'An http URL scheme handler exposes deep links to hijacking and plaintext interception.',
              evidence="CFBundleURLSchemes contains http", cwe="CWE-319",
              owasp="MASVS-NETWORK", cvss=3.7,
              remed='Use https universal links with domain verification.',
              confidence="probable", location=IP))
    # ---- provisioning & entitlements
    if prov and not prov.get("parse_error"):
        if prov["get_task_allow"]:
            add(F("HIGH", "Development build: get-task-allow entitlement is enabled",
                  'This IPA can be debugged by anyone (get-task-allow=true) — it is a development build whose process can be attached, dumped, and instrumented.',
                  evidence="Entitlements.get-task-allow = true in embedded.mobileprovision",
                  cwe="CWE-489", owasp="MASVS-RESILIENCE", cvss=5.5,
                  remed='Distribute only App Store/enterprise builds signed without get-task-allow.',
                  confidence="confirmed", location="embedded.mobileprovision"))
        if prov["distribution"] == "enterprise":
            add(F("MEDIUM", "Enterprise distribution provisioning profile",
                  'The profile allows installation on any device (ProvisionsAllDevices) — if this IPA leaks, anyone can install and analyze the production app.',
                  evidence=f"profile '{prov['name']}' (team {prov['team_name']})",
                  cwe="CWE-359", owasp="MASVS-RESILIENCE", cvss=5.3,
                  remed='Control enterprise IPA distribution strictly; prefer managed deployment/MDM.',
                  confidence="confirmed", location="embedded.mobileprovision"))
        if prov["expired"]:
            add(F("MEDIUM", "Provisioning profile has expired",
                  f"The embedded provisioning profile expired on {prov['expires']} — the app can no longer be installed/run under this profile.",
                  evidence=f"ExpirationDate={prov['expires']}", cwe="CWE-324",
                  owasp="MASVS-RESILIENCE", cvss=5.3,
                  remed='Renew the provisioning profile and re-sign the app.',
                  confidence="confirmed", location="embedded.mobileprovision"))
    # ---- Mach-O hardening
    if macho["archs"] and macho["pie"] is False:
        add(F("LOW", "Main binary is not position-independent (MH_PIE missing)",
              'Without PIE, the executable loads at a fixed address, weakening ASLR for the main image.',
              evidence=f"archs={', '.join(macho['archs'])}, MH_PIE flag absent",
              cwe="CWE-338", owasp="MASVS-RESILIENCE", cvss=3.7,
              remed='Build with PIE enabled (Xcode default for modern targets).',
              confidence="probable", location=exe_name or "Mach-O"))
    if not encrypted and strings and not any("__stack_chk_guard" in s for s in strings):
        add(F("LOW", "No stack canary indication in the main binary",
              'The __stack_chk_guard symbol was not found among the binary strings — the main executable may be built without stack smashing protection. Symbol presence is string-based, so manual verification is required.',
              evidence="__stack_chk_guard not found in executable strings",
              cwe="CWE-121", owasp="MASVS-RESILIENCE", cvss=3.7,
              remed='Enable -fstack-protector-strong (Xcode default) and verify with a binary analysis tool.',
              confidence="candidate", location=exe_name or "Mach-O"))
    # ---- secrets & endpoint (pola yang sama dengan APK)
    for kind, rx, sev, cvss, title, desc in _SECRET_PATTERNS:
        hits = [s for s in strings if rx.search(s)]
        if hits:
            m = rx.search(hits[0])
            add(F(sev, title.replace("in the APK", "in the IPA"), desc.replace("APK", "IPA"),
                  evidence=_mask(m.group(0)) + f" (found in {len(hits)} matching strings)",
                  cwe="CWE-798", owasp="MASVS-STORAGE", cvss=cvss,
                  remed='Revoke/rotate this credential right now; long-lived credentials must never be embedded in an app package.',
                  confidence="probable", location="executable/assets"))
    generic = [s for s in strings if _GENERIC_SECRET_RE.search(s)]
    if generic:
        add(F("LOW", f"Hardcoded credential indication in IPA strings ({len(generic)} patterns)",
              'A credential assignment pattern (api key/secret/password/token) was found among the strings inside the IPA. Manual verification is required.',
              evidence="; ".join(_mask(g[:48]) for g in list(generic)[:3]),
              cwe="CWE-798", owasp="MASVS-STORAGE", cvss=3.7,
              remed='Manually verify each pattern; if active, revoke it and move it to the backend.',
              confidence="candidate", location="executable/assets"))
    gs = app_prefix + "GoogleService-Info.plist"
    if gs in names:
        try:
            g = plistlib.loads(zf.read(gs))
        except Exception:
            g = {}
        dburl = g.get("DATABASE_URL") or ""
        if dburl:
            add(F("LOW", 'Firebase database URL exposed in the IPA',
                  'The Realtime Database/Firestore URL is exposed (normal for client configuration) — security depends entirely on the security rules; open rules = public data leak.',
                  evidence=str(dburl)[:140], cwe="CWE-200", owasp="MASVS-STORAGE",
                  cvss=3.1, remed='Audit the Firebase security rules: ensure there is no public read/write without authentication.',
                  confidence="candidate", location="GoogleService-Info.plist"))
    if http_hosts:
        add(F("MEDIUM", f"HTTP endpoint (unencrypted) found: {len(http_hosts)} host",
              'The IPA contains http:// URLs to real hosts. If actually called at runtime, the traffic (including tokens) can be intercepted on the network.',
              evidence=", ".join(sorted(http_hosts)[:8]), cwe="CWE-319",
              owasp="MASVS-NETWORK", cvss=5.3,
              remed='Migrate all endpoints to https and enable HSTS on the server side.',
              confidence="probable", location="executable/assets"))

    summary = {}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    risk = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if summary.get(s)), "CLEAN")
    score = risk_score(findings)
    privacy = sorted(k for k in info.keys() if k.endswith("UsageDescription"))
    plists_dec = []
    _ip = _plist_text(zf.read(app_prefix + "Info.plist"))
    if _ip:
        plists_dec.append({"name": "Info.plist", "text": _ip})
    _pv = [n for n in names if n.endswith("embedded.mobileprovision")]
    if _pv:
        _rawp = zf.read(_pv[0])
        _a, _b = _rawp.find(b"<?xml"), _rawp.find(b"</plist>")
        if _a >= 0 and _b > _a:
            _pt = _plist_text(_rawp[_a:_b + len(b"</plist>")])
            if _pt:
                plists_dec.append({"name": "embedded.mobileprovision", "text": _pt})
    if gs in names:
        _gt = _plist_text(zf.read(gs))
        if _gt:
            plists_dec.append({"name": "GoogleService-Info.plist", "text": _gt})
    meta = {"platform": "ios", "contents": contents,
            "decompile": {"plists": plists_dec,
                          "note": "Mach-O disassembly is not included: only "
                                  "decoded plist resources are shown for IPA."},
            "package": bundle_id, "app_name": app_name, "version_name": ver_name,
            "version_code": ver_code, "min_sdk": 0, "target_sdk": 0,
            "min_os": min_os, "file_name": filename, "file_size": len(raw),
            "sha256": sha, "permissions": [], "dangerous_permissions": [],
            "components": {"total": len(contents["frameworks"]),
                           "exported": []},
            "cert": {"signed": signed, "schemes": [],
                     "subject": (prov or {}).get("team_name", ""),
                     "issuer": "", "not_after": (prov or {}).get("expires", ""),
                     "hash_alg": "", "debug": bool((prov or {}).get("get_task_allow")),
                     "expired": bool((prov or {}).get("expired"))},
            "pinning_detected": False,
            "ios": {"distribution": (prov or {}).get("distribution", ""),
                    "provisioning": prov, "macho": macho,
                    "url_schemes": schemes, "privacy_descriptions": privacy,
                    "ats": ats},
            "endpoints": endpoints, "endpoint_hosts": sorted(seen_hosts)}
    L(f"[mobile] done: {len(findings)} findings | risk {risk} | score {score}/100 | {len(endpoints)} endpoint ({len(seen_hosts)} host)")
    target_label = f"{bundle_id} ({filename})"
    return {"type": "mobile", "target": target_label, "profile": "ipa-static",
            "method": "static", "findings": findings, "summary": summary,
            "overall_risk": risk, "risk_score": score, "meta": meta,
            "endpoints": endpoints, "warnings": [], "errors": []}


def analyze_package(path, filename="app.apk", log=None):
    """Dispatcher format: APK (AndroidManifest/DEX) atau IPA (Payload/*.app)."""
    try:
        zf = zipfile.ZipFile(path)
        names = zf.namelist()
        zf.close()
    except Exception:
        raise ValueError("Not a valid package (not a ZIP archive)")
    if any(n == "AndroidManifest.xml" for n in names) or \
            any(re.fullmatch(r"classes\d*\.dex", n.rsplit("/", 1)[-1]) for n in names):
        return analyze_apk(path, filename, log=log)
    if any(n.startswith("Payload/") and ".app/" in n for n in names):
        return analyze_ipa(path, filename, log=log)
    raise ValueError("Unrecognized package: neither an Android APK nor an iOS IPA "
                     "structure was found")
