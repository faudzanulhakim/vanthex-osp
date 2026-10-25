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
# v1.9.0 (Mobile Deep): the shared v2 secret detectors + the web engine's
# structural validators / context scoring / baseline helpers are reused for
# mobile parity (WS2) — validation stays structural/local, providers are
# never contacted (decision D5).
from vulnscan2 import (_TIER_DOWN, _apply_baseline, _aws_pair_secret,
                       _pem_material_parses, _secret_context_adjust)
from secretpatterns import (DETECTORS_V2, WEB_GENERIC_SECRET_RE,
                            bip39_phrase_status, github_token_structurally_valid,
                            is_denied_secret, luhn_valid, parse_jwt,
                            shannon_entropy)

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

# Secret patterns live in the shared module (Priority 1, Step 0) so the
# mobile analyzer and the web engine can never diverge. Behavior here is
# unchanged: these are the exact patterns mobile.py defined before.
from secretpatterns import _SECRET_PATTERNS, _GENERIC_SECRET_RE, _mask  # noqa: E402,F401


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


_PROTECTION_RANK = {"normal": 0, "dangerous": 1, "signature": 2,
                    "signatureorsystem": 2, "signatureprivileged": 2}


def _permission_levels(root):
    """protectionLevel per permission DECLARED in this manifest."""
    levels = {}
    if root is None:
        return levels
    for el in root.findall("permission"):
        name = el.get(NS + "name") or ""
        if name:
            levels[name] = (el.get(NS + "protectionLevel") or "normal").lower()
    return levels


def _resolve_protection(perm, levels):
    """(level, note) for a guard permission. A permission attribute alone
    never protected a component (v1.9.0/WS5): normal/dangerous permissions
    are grantable to any app, so only signature-level guards count.
    Undeclared custom permissions default to normal (Android Developers)."""
    if not perm:
        return None, ""
    if perm in levels:
        return levels[perm], "declared in this manifest"
    if perm.startswith("android.permission."):
        return "signature", "platform permission"
    return "normal", "not declared in this manifest (defaults to normal)"


def _components(root, target_sdk):
    """Daftar komponen + status exported efektif (aturan default Android)."""
    app = root.find("application") if root is not None else None
    comps = []
    if app is None:
        return comps, None
    levels = _permission_levels(root)
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
            # WS5: guard dinilai dari protectionLevel NYATA dari permission
            # penjaga terlemah yang berlaku (provider: read & write terpisah).
            guard_perms = [el.get(NS + "permission")]
            if tag == "provider":
                guard_perms = [el.get(NS + "readPermission"),
                               el.get(NS + "writePermission"),
                               el.get(NS + "permission")]
            resolved = [_resolve_protection(p, levels) for p in guard_perms if p]
            if resolved:
                weakest = min(resolved,
                              key=lambda r: _PROTECTION_RANK.get(r[0], 0))
                protection, protection_note = weakest
                guarded = _PROTECTION_RANK.get(protection, 0) >= 2
                permission = next((p for p in guard_perms if p), None)
            else:
                protection, protection_note = None, ""
                guarded, permission = False, None
            deeplinks = []
            autoverify = False
            for f in filters:
                schemes, hosts = [], []
                for d in f.findall("data"):
                    s = d.get(NS + "scheme")
                    h = d.get(NS + "host")
                    if s and s not in schemes:
                        schemes.append(s)
                    if h and h not in hosts:
                        hosts.append(h)
                # <data> elements inside ONE intent-filter merge: every
                # scheme pairs with every host (Android Developers).
                pairs = [(s, h) for s in schemes for h in (hosts or [""])]
                for p in pairs:
                    if p not in deeplinks and len(deeplinks) < 24:
                        deeplinks.append(p)
                if f.get(NS + "autoVerify") == "true" and \
                        any(s in ("http", "https") for s, _h in pairs):
                    autoverify = True
            comps.append({"tag": tag, "name": name, "exported": exported,
                          "guarded": guarded, "launcher": launcher,
                          "deeplinks": deeplinks, "permission": permission,
                          "protection": protection,
                          "protection_note": protection_note,
                          "autoverify": autoverify})
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


# =====================================================================
# v1.9.0 — Mobile Deep. Evidence model: every mobile finding carries an
# evidence tier (T0 raw string / T1 parsed config or structure / T2 code
# reference with a backward-sliced constant argument / T3 dataflow — T3
# is intentionally NOT implemented, decision K1) and an owner label
# (app / library / unknown). Library-owned code findings are demoted to
# candidate and labelled, never silently dropped (K4). The labels live
# in the finding evidence text so they survive storage and reporting.
# =====================================================================

def _tag(f, tier, owner):
    f["evidence_tier"] = tier
    f["owner"] = owner
    return f


def _finalize_tags(findings, default_tier="T1", default_owner="app"):
    for f in findings:
        tier = f.get("evidence_tier", default_tier)
        owner = f.get("owner", default_owner)
        f["evidence_tier"], f["owner"] = tier, owner
        tag = f"[{tier} · owner={owner}] "
        if f.get("evidence") and not f["evidence"].startswith("[T"):
            f["evidence"] = tag + f["evidence"]
    return findings


def _extract_pools(zf, names, apk=None):
    """Segmented string pools (v1.9.0): each pool knows its source so a
    finding can be attributed (DEX string table / shipped asset file /
    string resources / native binary) instead of one undifferentiated
    pool. Returns (pools, strings, urls, truncated) where pools are
    dicts {kind, source, texts} — texts are individual strings for DEX /
    .so / arsc pools and whole-file text for asset/config files."""
    pools, strings, urls = [], set(), set()
    truncated = False
    budget = 90 * 1024 * 1024

    def take(nbytes):
        nonlocal budget, truncated
        if nbytes > budget:
            truncated = True
            return False
        budget -= nbytes
        return True

    dex_names = [n for n in names
                 if re.fullmatch(r"classes\d*\.dex", n.rsplit("/", 1)[-1])]
    try:
        from androguard.core.dex import DEX as _DEX
    except Exception:
        _DEX = None
    for n in dex_names:
        try:
            data = zf.read(n)
        except Exception:
            continue
        if not take(len(data)):
            break
        for m in _URL_RE.findall(data):
            urls.add(m.decode("utf-8", "replace").rstrip(")]>\"'.,;"))
        ss = None
        if _DEX is not None:
            try:
                ss = list(_DEX(data).get_strings())
            except Exception:
                ss = None
        if ss is None:  # fallback: byte-regex strings (coarser pool)
            ss = [m.decode("utf-8") for m in _STR_RE.findall(data)]
        strings.update(ss)
        pools.append({"kind": "dex", "source": n, "texts": ss})
    text_ext = (".json", ".xml", ".properties", ".txt", ".pem", ".key",
                ".env", ".js", ".html", ".cfg", ".ini", ".yaml", ".yml")
    for n in names:
        low = n.lower()
        is_asset = low.startswith(("assets/", "res/raw/"))
        is_cfg = ("/" not in n or n.startswith("res/")) and low.endswith(text_ext)
        if not (is_asset or is_cfg):
            continue
        try:
            info = zf.getinfo(n)
            data = zf.read(n)
        except Exception:
            continue
        if not take(len(data)):
            break
        for m in _URL_RE.findall(data):
            urls.add(m.decode("utf-8", "replace").rstrip(")]>\"'.,;"))
        for m in _STR_RE.findall(data):
            try:
                strings.add(m.decode("utf-8"))
            except Exception:
                pass
        if low.endswith(text_ext) and info.file_size <= 512 * 1024:
            pools.append({"kind": "file", "source": n,
                          "texts": [data.decode("utf-8", "replace")]})
    for n in names:  # native binaries: T0 strings only (endpoints/context)
        if not n.lower().endswith(".so"):
            continue
        try:
            data = zf.read(n)
        except Exception:
            continue
        if not take(len(data)):
            break
        ss = []
        for m in _URL_RE.findall(data):
            urls.add(m.decode("utf-8", "replace").rstrip(")]>\"'.,;"))
        for m in _STR_RE.findall(data):
            try:
                s = m.decode("utf-8")
            except Exception:
                continue
            ss.append(s)
            strings.add(s)
        pools.append({"kind": "so", "source": n, "texts": ss})
    if apk is not None:  # string resources (previously never in the pool)
        try:
            arsc = apk.get_android_resources()
            pkgs = arsc.get_packages_names() or []
            fn = getattr(arsc, "get_string_resources", None)
            if fn is not None:
                for pname in pkgs[:1]:
                    d = fn(pname)
                    if isinstance(d, dict):
                        vals = [str(v) for v in d.values()]
                        strings.update(vals)
                        pools.append({"kind": "arsc",
                                      "source": "resources.arsc",
                                      "texts": vals})
                    break
        except Exception:
            pass
    return pools, strings, urls, truncated


def _parse_nsc(zf, nsc_name):
    """Full network-security-config parse (v1.9.0/WS3): base-config and
    per-domain configs kept SEPARATE (a domain-scoped cleartext grant is
    not a global one), pin-sets with expiration, user-CA trust anchors,
    debug-overrides identified (they never apply to release builds)."""
    out = {"parsed": False, "base_cleartext": None, "domain_cleartext": [],
           "pinsets": [], "user_ca": [], "debug_overrides": False}
    if not nsc_name:
        return out
    try:
        from androguard.core.axml import AXMLPrinter
        x = AXMLPrinter(zf.read(nsc_name)).get_buff().decode("utf-8", "replace")
        root = ET.fromstring(x)
    except Exception:
        return out
    if root is None or not str(root.tag).endswith("network-security-config"):
        return out
    return _nsc_from_root(root)


def _nsc_from_root(root):
    """NSC semantics over a parsed <network-security-config> element."""
    out = {"parsed": True, "base_cleartext": None, "domain_cleartext": [],
           "pinsets": [], "user_ca": [], "debug_overrides": False}

    def attr(el, name):
        # AXMLPrinter renders android-namespace attributes with the
        # "android:" prefix, which ElementTree expands to {uri}name.
        v = el.get(name)
        if v is not None:
            return v
        v = el.get(NS + name)
        if v is not None:
            return v
        for k, val in el.attrib.items():
            if k.endswith("}" + name):
                return val
        return None

    def walk(cfg, domains):
        ct = attr(cfg, "cleartextTrafficPermitted")
        if ct is not None:
            if domains:
                if ct == "true":
                    out["domain_cleartext"].extend(domains)
            else:
                out["base_cleartext"] = (ct == "true")
        for ta in cfg.iter("trust-anchors"):
            for cert in ta.iter("certificates"):
                if attr(cert, "src") == "user":
                    out["user_ca"].append(
                        ", ".join(domains) if domains else "(base-config)")
        for ps in cfg.iter("pin-set"):
            pins = [p.text or "" for p in ps.iter("pin")]
            if pins:
                out["pinsets"].append({"domains": list(domains),
                                       "pins": len(pins),
                                       "expiration": attr(ps, "expiration")})

    for bc in root.iter("base-config"):
        walk(bc, [])
    for dc in root.iter("domain-config"):
        doms = [(d.text or "").strip() for d in dc.iter("domain")]
        walk(dc, [d for d in doms if d])
    for _do in root.iter("debug-overrides"):
        out["debug_overrides"] = True
    return out


# ------------------------------------------------------- ELF (.so) parser
_ELF_MACH = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64", 8: "MIPS",
             20: "PPC", 243: "RISC-V"}


def _elf_info(data):
    """Self-built ELF parser (v1.9.0/WS7, mirrors _macho_info): per-.so
    PIE (ET_DYN), NX stack (PT_GNU_STACK), RELRO (PT_GNU_RELRO + BIND_NOW),
    stack canary (imported __stack_chk_fail in .dynsym). Facts only —
    no external binary tools are invoked (K3)."""
    out = {"arch": "", "pie": None, "nx": None, "relro": None,
           "canary": None, "stripped": None}
    if not data or len(data) < 52 or data[:4] != b"\x7fELF":
        return out
    is64 = data[4] == 2
    en = "<" if data[5] != 2 else ">"
    try:
        if is64:
            (_t, mach, _v, _e, phoff, shoff, _f, ehsz, phentsize, phnum,
             shentsize, shnum, _sstr) = struct.unpack_from(en + "HHIQQQIHHHHHH", data, 16)
        else:
            (_t, mach, _v, _e, phoff, shoff, _f, ehsz, phentsize, phnum,
             shentsize, shnum, _sstr) = struct.unpack_from(en + "HHIIIIIHHHHHH", data, 16)
        out["arch"] = _ELF_MACH.get(mach, hex(mach))
        out["pie"] = (_t == 3)  # ET_DYN
        loads, dyn_off, dyn_sz, has_relro, bind_now = [], None, 0, False, False
        for i in range(min(phnum, 128)):
            o = phoff + i * phentsize
            if is64:
                p_type, p_flags, p_off, p_va, _pa, p_filesz = struct.unpack_from(en + "IIQQQQ", data, o)
            else:
                p_type, p_off, p_va, _pa, p_filesz, _msz, p_flags = struct.unpack_from(en + "IIIIIIII", data, o)[:7]
                p_type, p_off, p_va, p_filesz, p_flags = p_type, p_off, p_va, p_filesz, p_flags
            if p_type == 1:
                loads.append((p_va, p_off, p_filesz))
            elif p_type == 2:
                dyn_off, dyn_sz = p_off, p_filesz
            elif p_type == 0x6474E551:  # PT_GNU_STACK
                out["nx"] = not (p_flags & 1)
            elif p_type == 0x6474E552:  # PT_GNU_RELRO
                has_relro = True
        symtab = strtab = None
        strsz = syment = 0
        hashva = None
        if dyn_off is not None:
            esz = 16 if is64 else 8
            for j in range(0, max(0, dyn_sz - esz + 1), esz):
                if is64:
                    tag, val = struct.unpack_from(en + "qQ", data, dyn_off + j)
                else:
                    tag, val = struct.unpack_from(en + "iI", data, dyn_off + j)
                if tag == 0:
                    break
                if tag == 6:
                    symtab = val
                elif tag == 5:
                    strtab = val
                elif tag == 4:
                    hashva = val
                elif tag == 10:
                    strsz = val
                elif tag == 11:
                    syment = val
                elif tag == 24 or (tag == 30 and val & 0x8) or \
                        (tag == 0x6FFFFFFB and val & 0x2):
                    bind_now = True
        if has_relro:
            out["relro"] = "full" if bind_now else "partial"
        elif out["pie"] is not None:
            out["relro"] = "absent"

        def v2o(va):
            for (lva, loff, lsz) in loads:
                if lva <= va < lva + lsz:
                    return loff + (va - lva)
            return None

        # symbol names: prefer section headers (.dynsym), else DT_HASH nchain
        names_found = None
        if shoff and shnum and shentsize:
            for i in range(min(shnum, 96)):
                o = shoff + i * shentsize
                if is64:
                    _nm, s_type, _fl, _ad, s_off, s_size, s_link, _inf, _al, s_ent = \
                        struct.unpack_from(en + "IIQQQQIIQQ", data, o)
                else:
                    _nm, s_type, _fl, _ad, s_off, s_size, s_link, _inf, _al, s_ent = \
                        struct.unpack_from(en + "IIIIIIIIII", data, o)
                if s_type == 11 and s_ent:  # SHT_DYNSYM
                    strsh = None
                    so2 = shoff + s_link * shentsize
                    if is64:
                        strsh = struct.unpack_from(en + "IIQQQQIIQQ", data, so2)[4:6]
                    else:
                        strsh = struct.unpack_from(en + "IIIIIIIIII", data, so2)[4:6]
                    names_found = set()
                    for k in range(0, s_size - s_ent + 1, s_ent):
                        noff = struct.unpack_from(en + "I", data, s_off + k)[0]
                        if strsh and noff < strsh[1]:
                            end = data.find(b"\x00", strsh[0] + noff)
                            if end > 0:
                                names_found.add(data[strsh[0] + noff:end]
                                                .decode("utf-8", "replace"))
                    break
        if names_found is None and symtab and strtab and syment and hashva:
            so, to, hoff = v2o(symtab), v2o(strtab), v2o(hashva)
            if so is not None and to is not None and hoff is not None:
                nchain = struct.unpack_from(en + "I", data, hoff + 4)[0]
                names_found = set()
                for k in range(min(nchain, 20000)):
                    noff = struct.unpack_from(en + "I", data, so + k * syment)[0]
                    if noff and noff < strsz:
                        end = data.find(b"\x00", to + noff)
                        if end > 0:
                            names_found.add(data[to + noff:end]
                                            .decode("utf-8", "replace"))
        if names_found is not None:
            out["canary"] = "__stack_chk_fail" in names_found
        out["stripped"] = (shnum == 0) if shoff is not None else None
    except Exception:
        pass
    return out


# ------------------------------------------------- WS1: DEX evidence layer
_LIB_OWNER_PREFIXES = (
    "Landroid/support/", "Landroidx/", "Lcom/google/", "Lcom/facebook/",
    "Lcom/squareup/", "Lokhttp3/", "Lokio/", "Lretrofit2/", "Lcom/android/",
    "Lkotlin/", "Lkotlinx/", "Lorg/apache/", "Lcom/unity3d/", "Lcom/adjust/",
    "Lcom/appsflyer/", "Lcom/bumptech/", "Ldagger/", "Lio/reactivex/",
    "Lorg/greenrobot/", "Lcom/crashlytics/", "Lcom/mixpanel/", "Lio/sentry/",
    "Lcom/onesignal/", "Lcom/inmobi/", "Lcom/applovin/", "Lcom/vungle/")
_FRAMEWORK_PREFIXES = ("Landroid/", "Ljava/", "Ljavax/", "Ldalvik/",
                       "Lorg/json/", "Lorg/xmlpull/", "Lorg/w3c/",
                       "Lorg/xml/", "Llibcore/", "Lsun/")
_CALLBACK_NAMES = {"onCreate", "onStart", "onResume", "onPause", "onStop",
                   "onDestroy", "onReceive", "onHandleIntent", "onBind",
                   "onStartCommand", "onCreateView", "onViewCreated",
                   "onActivityCreated", "onAttach", "onDetach", "onLoadFinished",
                   "<init>", "<clinit>"}
_SLICE_CLASSNAMES = {"Cipher", "MessageDigest", "Mac", "SecretKeySpec",
                     "IvParameterSpec", "PBEKeySpec", "PBEParameterSpec",
                     "SecureRandom", "SSLContext", "KeyStore"}
_SLICE_NAMES = {"getInstance", "setSeed", "getSharedPreferences",
                "openFileOutput", "setJavaScriptEnabled", "setAllowFileAccess",
                "setAllowFileAccessFromFileURLs",
                "setAllowUniversalAccessFromFileURLs",
                "setWebContentsDebuggingEnabled", "sslSocketFactory", "init",
                "<init>", "getBytes"}
_CONST_STRING_RE = re.compile(r'^v(\d+), "(.*)"$', re.S)
_CONST_INT_RE = re.compile(r"^v(\d+), (-?\d+)$")
_REG_RE = re.compile(r"^v(\d+), (\S.*)$")
_INVOKE_REF_RE = re.compile(r"(L\S+;->.+)$")


def _owner_of(cls, app_prefix):
    if app_prefix and cls.startswith(app_prefix):
        return "app"
    if cls.startswith(_LIB_OWNER_PREFIXES) or cls.startswith(_FRAMEWORK_PREFIXES):
        return "library"
    return "unknown"


def _desc_params(desc):
    try:
        s = desc[desc.index("(") + 1:desc.index(")")]
    except Exception:
        return []
    out, k = [], 0
    while k < len(s):
        c = s[k]
        if c == "[":
            st = k
            while k < len(s) and s[k] == "[":
                k += 1
            if k < len(s) and s[k] == "L":
                k = s.index(";", k) + 1
            else:
                k += 1
            out.append(s[st:k])
        elif c == "L":
            e = s.index(";", k) + 1
            out.append(s[k:e])
            k = e
        else:
            out.append(c)
            k += 1
    return out


def _wants_slice(ccls, cname):
    if cname in ("getInstance", "init"):
        return ccls.rsplit("/", 1)[-1].rstrip(";") in _SLICE_CLASSNAMES
    if cname == "<init>":
        return ccls.rsplit("/", 1)[-1].rstrip(";") in _SLICE_CLASSNAMES
    return cname in _SLICE_NAMES


def _slice_method(insns):
    """One pass over a method's instructions: build the sensitive-API call
    census and backward-slice constant arguments for target call sites.
    Register state is deliberately simple (const-string / const int /
    const-class / sget / new-instance / move chains) — this is the T2
    evidence ceiling set by decision K1, NOT a dataflow engine."""
    invokes, news, fields = [], [], []
    state = {}
    last = {"callee": None, "recv": None, "args": None}
    throws = False
    branches = 0
    returns_const1 = False
    for ins in insns:
        op = _scf(ins, "get_name")
        out = _scf(ins, "get_output")
        if op in ("const-string", "const-string/jumbo"):
            m = _CONST_STRING_RE.match(out)
            if m:
                state[int(m.group(1))] = ("str", m.group(2))
            continue
        if op in ("const/4", "const/16", "const", "const/high16",
                  "const-wide/16", "const-wide/32", "const-wide"):
            m = _CONST_INT_RE.match(out)
            if m:
                state[int(m.group(1))] = ("int", int(m.group(2)))
            continue
        if op == "const-class":
            m = _REG_RE.match(out)
            if m:
                state[int(m.group(1))] = ("cls", m.group(2))
            continue
        if op.startswith("sget"):
            m = _REG_RE.match(out)
            if m:
                ref = m.group(2).split(" ")[0]
                state[int(m.group(1))] = ("field", ref)
                fields.append(ref)
            continue
        if op == "new-instance":
            m = _REG_RE.match(out)
            if m:
                state[int(m.group(1))] = ("new", m.group(2))
                news.append(m.group(2))
            continue
        if op == "new-array":
            m = _REG_RE.match(out)
            if m:
                state[int(m.group(1))] = ("array", m.group(2))
            continue
        if op.startswith("move-result"):
            reg = None
            m = re.match(r"^v(\d+)$", out)
            if m:
                reg = int(m.group(1))
            if reg is not None:
                cal = last["callee"]
                if cal and cal[1] == "getBytes" and \
                        isinstance(last["recv"], tuple) and last["recv"][0] == "str":
                    state[reg] = ("bytes", last["recv"][1])
                elif cal:
                    state[reg] = ("ret", cal[0])
                else:
                    state.pop(reg, None)
            continue
        if op.startswith("move"):
            m = re.match(r"^v(\d+), v(\d+)$", out)
            if m:
                src = state.get(int(m.group(2)))
                if src is None:
                    state.pop(int(m.group(1)), None)
                else:
                    state[int(m.group(1))] = src
            continue
        if op == "check-cast":
            continue
        if op.startswith("invoke"):
            m = _INVOKE_REF_RE.search(out)
            if not m:
                continue
            ref = m.group(1)
            ccls, rest = ref.split("->", 1)
            cname = rest.split("(", 1)[0]
            # androguard renders multi-parameter descriptors with spaces
            # between the parameter types — normalize them away.
            cdesc = ("(" + rest.split("(", 1)[1].replace(" ", "")
                     if "(" in rest else "")
            regs_part = out[:m.start()].rstrip().rstrip(",")
            regs = [int(x) for x in re.findall(r"v(\d+)", regs_part)]
            if ".." in regs_part and len(regs) >= 2:
                regs = list(range(regs[0], regs[-1] + 1))
            is_static = "static" in op
            arg_regs = regs if is_static else regs[1:]
            params = _desc_params(cdesc)
            args, ri = [], 0
            for p in params:
                if ri < len(arg_regs):
                    args.append(state.get(arg_regs[ri]))
                    ri += 2 if p in ("J", "D") else 1
                else:
                    args.append(None)
            recv = None if is_static or not regs else state.get(regs[0])
            sliced = tuple(args) if _wants_slice(ccls, cname) else None
            invokes.append((ccls, cname, cdesc, sliced))
            last = {"callee": (ccls, cname, cdesc), "recv": recv,
                    "args": args}
            continue
        if op == "throw":
            throws = True
            continue
        if op.startswith("if-"):
            branches += 1
            continue
        if op == "return":
            m = re.match(r"^v(\d+)$", out)
            if m and state.get(int(m.group(1))) == ("int", 1):
                returns_const1 = True
            continue
        # any other instruction writing a leading register invalidates it
        m = re.match(r"^v(\d+),", out)
        if m:
            state.pop(int(m.group(1)), None)
    return {"invokes": invokes, "news": news, "fields": fields,
            "throws": throws, "branches": branches,
            "returns_const1": returns_const1, "insns": len(insns)}


class _DexEvidence:
    """androguard Analysis census over all DEX files (WS1). Built once per
    APK; every structure is capped and failures degrade honestly to
    'unavailable' in the coverage header instead of aborting the scan."""

    MAX_CLASSES = 60000

    def __init__(self, zf, names, pkg):
        self.ok = False
        self.reason = ""
        self.methods = {}       # (cls, name, desc) -> digest dict
        self.classes = {}       # cls -> {"interfaces": [...], "super": str}
        self.string_refs = {}   # string value -> [(cls, method)] (capped)
        self.callers = {}       # (cls, name, desc) -> bool(has xref_from)
        self.app_prefix = "L" + (pkg or "").replace(".", "/") + "/" if pkg else ""
        self.total_classes = 0
        try:
            from androguard.core.dex import DEX
            from androguard.core.analysis.analysis import Analysis
        except Exception as e:
            self.reason = f"androguard unavailable: {e}"
            return
        dex_names = [n for n in names
                     if re.fullmatch(r"classes\d*\.dex", n.rsplit("/", 1)[-1])]
        dxs = []
        try:
            for n in dex_names:
                d = DEX(zf.read(n))
                dx = Analysis(d)
                dx.create_xref()
                dxs.append(dx)
                for cname in d.get_classes_names():
                    self.total_classes += 1
                if self.total_classes > self.MAX_CLASSES:
                    self.reason = (f"class count exceeds the evidence-layer "
                                   f"cap ({self.MAX_CLASSES})")
                    return
                for c in d.get_classes():
                    cn = _scf(c, "get_name")
                    if not cn:
                        continue
                    try:
                        _ifaces = list(c.get_interfaces() or [])
                    except Exception:
                        _ifaces = []
                    self.classes[cn] = {
                        "interfaces": _ifaces,
                        "super": _scf(c, "get_superclassname")}
                    for em in c.get_methods():
                        key = (cn, _scf(em, "get_name"),
                               _scf(em, "get_descriptor"))
                        digest = {"cls": cn, "name": key[1], "desc": key[2],
                                  "owner": _owner_of(cn, self.app_prefix),
                                  "invokes": [], "news": [], "fields": [],
                                  "throws": False, "branches": 0,
                                  "returns_const1": False, "insns": 0}
                        try:
                            code = em.get_code()
                            if code is not None:
                                digest.update(_slice_method(
                                    list(code.get_bc().get_instructions())))
                        except Exception:
                            pass
                        self.methods[key] = digest
                for ma in dx.get_methods():
                    key = (ma.class_name, ma.name, ma.descriptor)
                    try:
                        self.callers[key] = bool(ma.get_xref_from())
                    except Exception:
                        self.callers[key] = False
                try:
                    for val, sa in dx.get_strings_analysis().items():
                        refs = []
                        for ca, ma in list(sa.get_xref_from())[:6]:
                            refs.append((ca.name, ma.name))
                        if refs:
                            self.string_refs[val] = refs
                except Exception:
                    pass
            self.ok = True
        except Exception as e:
            self.reason = f"code evidence layer failed: {e}"
            self.methods, self.classes = {}, {}

    def reachable(self, key, component_classes=frozenset()):
        if self.callers.get(key):
            return True
        cls, name, _d = key
        if cls in component_classes:
            return True
        return name in _CALLBACK_NAMES

    def owner(self, cls):
        return _owner_of(cls, self.app_prefix)

    def string_usage(self, value):
        """(usage, owner, where) for a DEX string: usage is 'xref-app',
        'xref-library' or 'none' (K1/K4 tiering input)."""
        refs = self.string_refs.get(value)
        if not refs:
            return "none", "unknown", ""
        owners = [self.owner(c) for c, _m in refs]
        where = f"{refs[0][0]}->{refs[0][1]}"
        if "app" in owners:
            return "xref-app", "app", where
        if all(o == "library" for o in owners):
            return "xref-library", "library", where
        return "xref-unknown", "unknown", where

    def calls(self, cls_suffix=None, name=None):
        """Yield (key, digest, invoke) for invokes matching a callee."""
        for key, dg in self.methods.items():
            for inv in dg["invokes"]:
                if cls_suffix and not inv[0].endswith(cls_suffix):
                    continue
                if name and inv[1] != name:
                    continue
                yield key, dg, inv


# ------------------------------------------------- WS2: secrets parity
_AIZA_RE = re.compile(r"AIza[0-9A-Za-z_\-]{35}")
_COGNITO_RE = re.compile(r"\b(?:us|eu|ap|sa|ca|me|af|mx)-[a-z]+-\d:"
                         r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b")
_SECRET_PF_TOKENS = ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
                     "AKIA", "ASIA", "AIza", "xoxb-", "xoxp-", "xoxa-",
                     "sk_live", "rk_live", "npm_", "-----BEGIN", "eyJ",
                     "glpat-", "dop_v1_", "SG.", "AIza")
_SECRET_PF_WORDS = ("secret", "password", "passwd", "api_key", "apikey",
                    "api-key", "access_token", "auth_token", "private_key",
                    "client_secret", "bearer", "webhook", "credential",
                    "mnemonic")
_SECRET_REM = ('Revoke/rotate this credential now and move it to a backend '
               'or a secrets manager; never ship secrets in a mobile app.')


def _secret_candidate(s):
    """Cheap prefilter so the 72-detector set only runs on plausible
    strings (DEX pools hold tens of thousands of entries)."""
    if len(s) < 10:
        return False
    if any(t in s for t in _SECRET_PF_TOKENS):
        return True
    low = s.lower()
    if any(wd in low for wd in _SECRET_PF_WORDS):
        return True
    if re.search(r"\d[\d \-]{11,}\d", s):
        return True
    if s.count(" ") >= 11:
        return True
    return ("=" in s and len(s) >= 16) or ('":' in s and len(s) >= 16)


def _emit_mobile_secret(emit, det, val, unit, state, conf, note,
                        title=None, severity=None, cvss=None):
    from vulnscan2 import _NOT_VALIDATED
    key = (det["kind"], _mask(val), unit["location"])
    if key in state["seen"] or state["count"] >= state["cap"]:
        return
    state["seen"].add(key)
    state["emitted"].add((_mask(val), unit["location"]))
    ev = f"{_mask(val)} in {unit['location']}"
    if note:
        ev += f" — {note}"
    f = F(severity or det["severity"], title or det["title"],
          det["desc"] + _NOT_VALIDATED, evidence=ev, cwe="CWE-798",
          owasp="MASVS-STORAGE", cvss=cvss if cvss is not None else det["cvss"],
          remed=_SECRET_REM, confidence=conf, location=unit["location"],
          param=_mask(val))
    _tag(f, unit["tier"], unit["owner"])
    emit(_apply_baseline(f, state, val))
    state["count"] += 1


def _scan_secrets_mobile(units, baseline_map, emit, identifiers):
    """DETECTORS_V2 over segmented mobile units with the SAME structural
    validators + context scoring as the web pipeline (WS2 parity), plus
    the mobile tiering rules: provider client identifiers (Firebase AIza
    keys, Cognito pool IDs) are reported as identifiers, never as secret
    findings; a secret in code needs a usage xref for probable+; shipped
    config assets count as usage evidence (T1)."""
    state = {"count": 0, "cap": 30, "seen": set(), "emitted": set(),
             "baseline": baseline_map or {}}
    for unit in units:
        if state["count"] >= state["cap"]:
            break
        body = (unit["text"] or "")[:512 * 1024]
        if not body:
            continue
        for m in _AIZA_RE.finditer(body):
            identifiers.append(("Google/Firebase API key", m.group(0),
                                  unit["location"]))
        for m in _COGNITO_RE.finditer(body):
            identifiers.append(("AWS Cognito identity pool ID", m.group(0),
                                  unit["location"]))
        claimed = []
        for det in DETECTORS_V2:
            if state["count"] >= state["cap"]:
                break
            kind = det["kind"]
            for m in det["regex"].finditer(body):
                if state["count"] >= state["cap"]:
                    break
                if any(m.start() < e and s < m.end() for s, e in claimed):
                    continue
                val = m.group(0)
                if val.startswith("AIza"):
                    claimed.append(m.span())  # identifier — handled above
                    continue
                if is_denied_secret(val) and not (
                        det["validator"] == "aws_pair" and unit.get("shipped")):
                    # Documented divergence (repo fixture contract): the
                    # canonical AWS documentation example planted inside a
                    # SHIPPED app package stays a finding — inside a
                    # binary, the pattern match is the detection contract;
                    # the web text denylist does not apply to it.
                    continue
                if det["context"] is not None:
                    win = body[max(0, m.start() - 160):m.end() + 160]
                    if not det["context"].search(win):
                        continue
                conf, note = det["base"], ""
                v = det["validator"]
                if v == "github_crc":
                    ok = github_token_structurally_valid(val)
                    if ok is True:
                        conf = "probable"
                        note = "token checksum (CRC32) verified locally — format is structurally genuine"
                    elif ok is False:
                        conf = _TIER_DOWN.get(conf, conf)
                        note = "token checksum does NOT verify — likely altered or fabricated; tier demoted one step per policy K4"
                    else:
                        note = "token format is not checksum-verifiable"
                elif v == "pem_parse":
                    keytype = _pem_material_parses(body, m.start())
                    if keytype:
                        conf = "confirmed"
                        note = (f"private key material parses as a valid {keytype} "
                                "— the EXPOSURE is confirmed; a private key has "
                                "no provider liveness to verify")
                    else:
                        note = "key header present but the material does not parse (truncated or corrupt)"
                elif v == "jwt_struct":
                    if len(val) < 80:
                        continue
                    parsed = parse_jwt(val)
                    if parsed is None:
                        continue
                    if parsed["alg"] == "none" or parsed["signature_empty"]:
                        _c2, _n2 = _secret_context_adjust(
                            body, m.start(), m.end(), unit["location"],
                            unit["config_style"], "probable",
                            "JWT uses alg=none / carries no signature")
                        claimed.append(m.span())
                        _emit_mobile_secret(emit, det, val, unit, state,
                                            _c2, _n2)
                        continue
                    conf = "probable"
                    bits = [f"JWT structure decoded locally (alg={parsed['alg']}"]
                    if parsed.get("signature_wellformed"):
                        bits.append("signature segment is well-formed base64url (format check only — NOT cryptographically verified)")
                    elif not parsed["signature_empty"]:
                        bits.append("signature segment is not well-formed base64url")
                    if parsed["claims"].get("iss"):
                        bits.append(f"iss={str(parsed['claims']['iss'])[:40]}")
                    if isinstance(parsed["claims"].get("exp"), (int, float)):
                        bits.append(f"exp={int(parsed['claims']['exp'])}")
                    note = ", ".join(bits) + ")"
                elif v == "aws_pair":
                    pair = _aws_pair_secret(body, m.start())
                    if pair:
                        conf = "confirmed"
                        note = (f"complete credential pair: this access key ID "
                                f"appears together with a 40-char secret ({pair}) "
                                "in the same content — the EXPOSURE is confirmed; "
                                "liveness NOT verified")
                elif v == "gcp_sa":
                    if '"private_key"' not in body:
                        continue
                    conf = "probable"
                    note = "service-account document structure present (type + private_key fields)"
                elif v == "luhn":
                    if luhn_valid(re.sub(r"\D", "", val)):
                        conf = "probable"
                        note = "Luhn checksum PASSES locally — the value is structurally a valid payment card number (offline check only; never validated with an issuer)"
                    else:
                        conf = _TIER_DOWN.get(det["base"], "candidate")
                        note = "Luhn checksum FAILS — tier demoted one step per policy K4 (a failed checksum never deletes a finding)"
                elif v == "bip39":
                    _bs = bip39_phrase_status(val)
                    if _bs is None or _bs == "not_mnemonic":
                        continue
                    if _bs == "valid":
                        conf = "probable"
                        note = "BIP-39 checksum VERIFIES locally — a structurally valid mnemonic seed phrase (offline check only)"
                    else:
                        conf = "candidate"
                        note = "every word is a BIP-39 wordlist word but the embedded checksum does NOT verify — tier demoted per policy K4"
                conf, note = _secret_context_adjust(
                    body, m.start(), m.end(), unit["location"],
                    unit["config_style"], conf, note)
                if unit["tier"] == "T0" and unit["usage"] == "none" \
                        and conf == "probable":
                    # Evidence ladder: a bare string-table match (T0) with
                    # no usage evidence never exceeds candidate in a
                    # shipped binary (structural proofs — PEM parse, AWS
                    # pair — stay confirmed; they cannot arise from a
                    # single DEX string anyway).
                    conf = "candidate"
                    note = (note + "; " if note else "") + \
                        "string-table match only (T0), no usage evidence — tier capped at candidate"
                if unit["usage"] == "xref-app" and conf == "candidate":
                    conf = "probable"
                    note = (note + "; " if note else "") + \
                        f"usage evidence: referenced from app code at {unit['where']} (T2)"
                elif unit["usage"] == "config" and conf == "candidate":
                    conf = "probable"
                    note = (note + "; " if note else "") + \
                        "usage evidence: ships inside the packaged app configuration (T1)"
                elif unit["usage"] == "xref-library" and conf != "candidate":
                    conf = "candidate"
                    note = (note + "; " if note else "") + \
                        "referenced only from library code — demoted per policy K4"
                claimed.append(m.span())
                _emit_mobile_secret(emit, det, val, unit, state, conf, note)
        for m in WEB_GENERIC_SECRET_RE.finditer(body):
            if state["count"] >= state["cap"]:
                break
            val = m.group(2)
            if is_denied_secret(val) or shannon_entropy(val) < 3.5:
                continue
            key = ("generic", _mask(val), unit["location"])
            if key in state["seen"] or \
                    (_mask(val), unit["location"]) in state["emitted"]:
                continue
            state["seen"].add(key)
            state["emitted"].add((_mask(val), unit["location"]))
            f = F("LOW", "Hardcoded credential indication in app package",
                  "A credential assignment pattern with a high-entropy value was found inside the app package. Manual verification is required to determine whether the value is a real, still-active credential. The value was NOT validated against any provider.",
                  evidence=f"{m.group(1)} = {_mask(val)} in {unit['location']}",
                  cwe="CWE-798", owasp="MASVS-STORAGE", cvss=3.7,
                  remed='Manually verify whether this value is an active credential; if so, revoke it and move it to a backend or a secrets manager.',
                  confidence="candidate", location=unit["location"],
                  param=_mask(val))
            _tag(f, unit["tier"], unit["owner"])
            emit(_apply_baseline(f, state, val))
            state["count"] += 1
    return state["count"]


# ------------------------------------------- WS3/WS4/WS5 code-check drivers
def _bucket_sites(evd, key, dg):
    """Bucket a code finding site: 'app' (app-owned + reachable), 'lib'
    (library-owned) or 'dead' (app-owned but no caller found — K1 gate)."""
    if dg["owner"] == "library":
        return "lib"
    return "app" if evd.reachable(key, _bucket_sites.components) else "dead"


_bucket_sites.components = frozenset()


def _emit_bucketed(add, buckets, spec):
    """spec: {issue: (title, desc, sev_app, conf_app, sev_other, cwe, owasp, cvss, remed)}"""
    for issue, (title, desc, sev, conf, sev_o, cwe, owasp, cvss, remed) in spec.items():
        b = buckets.get(issue)
        if not b:
            continue
        if b.get("app"):
            sites = b["app"]
            f = F(sev, title, desc,
                  evidence=f"{len(sites)} call site(s) in app code: "
                           + "; ".join(sites[:5]),
                  cwe=cwe, owasp=owasp, cvss=cvss, remed=remed,
                  confidence=conf, location=sites[0].split(" at ")[-1])
            _tag(f, "T2", "app")
            add(f)
        for bucket, extra in (("lib", "library code — demoted to candidate per policy K4"),
                              ("dead", "no caller found in the call graph — possibly dead code or a reflection entry point; kept as a labelled candidate per policy K1")):
            if b.get(bucket):
                sites = b[bucket]
                f = F(sev_o, title, desc,
                      evidence=f"{len(sites)} call site(s): "
                               + "; ".join(sites[:5]) + f" [{extra}]",
                      cwe=cwe, owasp=owasp, cvss=cvss, remed=remed,
                      confidence="candidate",
                      location=sites[0].split(" at ")[-1])
                _tag(f, "T2", "library" if bucket == "lib" else "app")
                add(f)


def _ws3_tls_checks(evd, add, component_classes):
    _bucket_sites.components = component_classes
    tm_iface = "Ljavax/net/ssl/X509TrustManager;"
    hv_iface = "Ljavax/net/ssl/HostnameVerifier;"
    tms = {c for c, ci in evd.classes.items() if tm_iface in ci["interfaces"]}
    hvs = {c for c, ci in evd.classes.items() if hv_iface in ci["interfaces"]}
    installed_tm, installed_hv = {}, {}
    instantiated = set()
    for key, dg in evd.methods.items():
        instantiated.update(dg["news"])
        newt = [n for n in dg["news"] if n in tms]
        newh = [n for n in dg["news"] if n in hvs]
        for (ccls, cname, cdesc, args) in dg["invokes"]:
            if newt and ((cname == "init" and "TrustManager;" in cdesc)
                         or cname in ("setSSLSocketFactory", "sslSocketFactory")):
                for t in newt:
                    installed_tm.setdefault(t, key)
            if cname == "sslSocketFactory" and args and len(args) > 1 \
                    and isinstance(args[1], tuple) and args[1][0] == "new":
                installed_tm.setdefault(args[1][1], key)
            if newh and cname in ("setHostnameVerifier", "hostnameVerifier"):
                for t in newh:
                    installed_hv.setdefault(t, key)
            if cname == "hostnameVerifier" and args \
                    and isinstance(args[0], tuple) and args[0][0] == "new":
                installed_hv.setdefault(args[0][1], key)

    def verdict(cls, installed):
        owner = evd.owner(cls)
        if cls in installed:
            return ("confirmed" if owner == "app" else "probable"), \
                f"installed into the TLS stack at {installed[cls][0]}->{installed[cls][1]}"
        if cls in instantiated:
            return "probable", "instantiated in code, but no TLS installation site was found in the call census"
        return "candidate", "defined but never installed or instantiated in the call census — labelled candidate, not a verdict"

    for cls in sorted(tms):
        for mname in ("checkServerTrusted", "checkClientTrusted"):
            key = next((k for k in evd.methods
                        if k[0] == cls and k[1] == mname), None)
            if key is None:
                continue
            dg = evd.methods[key]
            if not (dg["insns"] <= 5 and not dg["throws"] and not dg["invokes"]):
                continue  # body validates or delegates — not accept-all
            conf, why = verdict(cls, installed_tm)
            if evd.owner(cls) == "library":
                conf = "candidate"
            f = F("HIGH" if conf != "candidate" else "MEDIUM",
                  "TrustManager that accepts all certificates",
                  'A custom X509TrustManager whose check method has an empty/non-validating body accepts any certificate, defeating TLS authentication (MITM). The verdict tier follows the installation evidence: installed into an SSLContext/factory = confirmed/probable; defined-but-never-installed stays a labelled candidate.',
                  evidence=f"{cls}->{mname}: empty body ({dg['insns']} instructions, no throw, no delegation call); {why}",
                  cwe="CWE-295", owasp="MASVS-NETWORK", cvss=7.4,
                  remed='Remove the custom TrustManager and use the platform default; if pinning is intended, validate the chain and compare pins.',
                  confidence=conf, location=f"{cls}->{mname}", param=mname)
            _tag(f, "T2", evd.owner(cls))
            add(f)
    for cls in sorted(hvs):
        key = next((k for k in evd.methods
                    if k[0] == cls and k[1] == "verify"), None)
        if key is None:
            continue
        dg = evd.methods[key]
        if not (dg["returns_const1"] and dg["branches"] == 0):
            continue
        conf, why = verdict(cls, installed_hv)
        if evd.owner(cls) == "library":
            conf = "candidate"
        f = F("HIGH" if conf != "candidate" else "MEDIUM",
              "HostnameVerifier that accepts all hosts",
              'A HostnameVerifier whose verify() unconditionally returns true accepts certificates for any hostname (MITM).',
              evidence=f"{cls}->verify returns constant true with no conditional branch; {why}",
              cwe="CWE-295", owasp="MASVS-NETWORK", cvss=7.4,
              remed='Use the platform default hostname verification (or OkHttp defaults); never return true unconditionally.',
              confidence=conf, location=f"{cls}->verify", param="verify")
        _tag(f, "T2", evd.owner(cls))
        add(f)
    for cls, ci in sorted(evd.classes.items()):
        if ci.get("super") != "Landroid/webkit/WebViewClient;":
            continue
        key = next((k for k in evd.methods
                    if k[0] == cls and k[1] == "onReceivedSslError"), None)
        if key is None:
            continue
        dg = evd.methods[key]
        called = {(i[0], i[1]) for i in dg["invokes"]}
        if ("Landroid/webkit/SslErrorHandler;", "proceed") in called and \
                ("Landroid/webkit/SslErrorHandler;", "cancel") not in called:
            conf = "probable" if cls in instantiated else "candidate"
            if evd.owner(cls) == "library":
                conf = "candidate"
            f = F("HIGH" if conf == "probable" else "MEDIUM",
                  "WebView ignores SSL errors (onReceivedSslError calls proceed())",
                  'The WebViewClient proceeds on any TLS error, so WebView traffic can be intercepted with any certificate.',
                  evidence=f"{cls}->onReceivedSslError calls SslErrorHandler.proceed() and never cancel()",
                  cwe="CWE-295", owasp="MASVS-NETWORK", cvss=7.4,
                  remed='Cancel on SSL errors (the platform default); never call proceed() in production.',
                  confidence=conf, location=f"{cls}->onReceivedSslError",
                  param="onReceivedSslError")
            _tag(f, "T2", evd.owner(cls))
            add(f)


_PIN_CLASSES = ("Lokhttp3/CertificatePinner;",
                "Lokhttp3/CertificatePinner$Builder;",
                "Lcom/datatheorem/android/trustkit/pinning/PinningSSLSocketFactory;")


def _code_pinning(evd):
    hits = []
    for key, dg in evd.methods.items():
        for inv in dg["invokes"]:
            if inv[0] in _PIN_CLASSES or "CertificatePinner" in inv[0] \
                    or "TrustKit" in inv[0] or inv[1] == "certificatePinner":
                hits.append(f"{key[0]}->{key[1]}")
                break
    return hits


_SEC_CTX_RE = re.compile(r"(?i)(auth|token|password|passwd|sign|encrypt|"
                         r"session|login|credential|hash)")


def _ws4_crypto_checks(evd, add, component_classes):
    _bucket_sites.components = component_classes
    buckets = {}

    def site(issue, key, dg, text):
        buckets.setdefault(issue, {}).setdefault(
            _bucket_sites(evd, key, dg), []).append(text)

    for key, dg in evd.methods.items():
        sec_ctx = bool(_SEC_CTX_RE.search(dg["name"] or "")) or any(
            i[0].rsplit("/", 1)[-1].rstrip(";") in
            ("Cipher", "Mac", "Signature", "SecretKeySpec", "KeyStore",
             "KeyFactory", "KeyPairGenerator", "KeyGenerator")
            for i in dg["invokes"])
        for (ccls, cname, cdesc, args) in dg["invokes"]:
            simple = ccls.rsplit("/", 1)[-1].rstrip(";")
            at = f"{key[0]}->{key[1]}"
            if cname == "getInstance" and args and isinstance(args[0], tuple) \
                    and args[0][0] == "str":
                val = args[0][1]
                up = val.upper()
                parts = up.split("/")
                algo = parts[0]
                if simple in ("Cipher", "KeyPairGenerator", "KeyGenerator"):
                    if len(parts) == 1 or (len(parts) > 1 and parts[1] == "ECB"):
                        site("ecb", key, dg,
                             f"transformation '{val}' at {at}")
                    elif algo in ("DES", "RC4", "ARC4", "BLOWFISH"):
                        site("weakalgo", key, dg,
                             f"algorithm '{val}' at {at}")
                elif simple == "MessageDigest" and algo in ("MD5", "SHA1", "SHA-1"):
                    if sec_ctx:
                        site("weakhash", key, dg,
                             f"MessageDigest.getInstance('{val}') in a security context at {at}")
            if cname == "<init>" and simple == "SecretKeySpec" and args \
                    and isinstance(args[0], tuple) and args[0][0] in ("str", "bytes"):
                site("constkey", key, dg,
                     f"SecretKeySpec built from the constant '{str(args[0][1])[:24]}' at {at}")
            if cname == "<init>" and simple == "IvParameterSpec" and args \
                    and isinstance(args[0], tuple) and args[0][0] in ("str", "bytes"):
                site("constiv", key, dg,
                     f"IvParameterSpec built from a constant at {at}")
            if cname == "<init>" and simple in ("PBEKeySpec", "PBEParameterSpec") and args:
                ints = [a[1] for a in args if isinstance(a, tuple) and a[0] == "int"]
                salts = [a for a in args if isinstance(a, tuple) and a[0] in ("str", "bytes")]
                low = [i for i in ints if 0 < i < 1000]
                if low:
                    site("pbe", key, dg,
                         f"PBE iteration count {low[0]} (< 1000) at {at}")
                elif salts:
                    site("pbe", key, dg,
                         f"PBE with a constant salt at {at}")
            if simple == "SecureRandom" and (cname == "setSeed" or cname == "<init>") \
                    and args and isinstance(args[0], tuple) \
                    and args[0][0] in ("int", "str", "bytes"):
                site("seed", key, dg,
                     f"SecureRandom seeded with a constant at {at}")
    spec = {
        "ecb": ("ECB cipher mode used in code (sliced transformation constant)",
                'Code evidence (T2): Cipher.getInstance is called with an ECB or mode-less transformation constant. ECB leaks plaintext structure; a mode-less transformation defaults to ECB with most JCE providers.',
                "MEDIUM", "probable", "LOW", "CWE-327", "MASVS-CRYPTO", 5.3,
                'Use AES-GCM (or ChaCha20-Poly1305) with a random IV per message.'),
        "weakalgo": ("Weak cipher algorithm used in code",
                     'Code evidence (T2): a broken/legacy cipher algorithm (DES/RC4/Blowfish) is requested with a constant algorithm name.',
                     "MEDIUM", "probable", "LOW", "CWE-327", "MASVS-CRYPTO", 5.3,
                     'Migrate to AES-GCM or ChaCha20-Poly1305.'),
        "weakhash": ("Weak hash (MD5/SHA-1) used in a security context",
                     'Code evidence (T2): MD5/SHA-1 is used in a method that also performs cryptographic operations or handles credentials/tokens. Weak hashes outside a security context (cache keys, checksums of non-sensitive data) are intentionally not reported.',
                     "LOW", "probable", "LOW", "CWE-327", "MASVS-CRYPTO", 3.7,
                     'Use SHA-256+ for integrity and a password KDF (PBKDF2/bcrypt/argon2) for credentials.'),
        "constkey": ("Hard-coded cryptographic key in code (SecretKeySpec constant)",
                     'Code evidence (T2): a SecretKeySpec is constructed from a constant byte string sliced out of the call site — the key ships inside the APK and can be extracted by anyone.',
                     "HIGH", "probable", "MEDIUM", "CWE-321", "MASVS-CRYPTO", 7.4,
                     'Generate keys at runtime (Android Keystore) or derive them with a KDF; never embed raw key material.'),
        "constiv": ("Constant IV in code (IvParameterSpec constant)",
                    'Code evidence (T2): an IvParameterSpec is constructed from a constant — CBC/GCM IV reuse breaks confidentiality guarantees.',
                    "MEDIUM", "probable", "LOW", "CWE-323", "MASVS-CRYPTO", 5.3,
                    'Generate a fresh random IV per message and transmit it with the ciphertext.'),
        "pbe": ("Weak password-based encryption parameters in code",
                'Code evidence (T2): PBE is used with an iteration count below 1000 or a constant salt, both sliced from the call site.',
                "LOW", "probable", "LOW", "CWE-916", "MASVS-CRYPTO", 3.7,
                'Use >= 10000 iterations (OWASP) and a random per-record salt.'),
        "seed": ("SecureRandom seeded with a constant in code",
                 'Code evidence (T2): SecureRandom.setSeed / constructor receives a constant seed, making its output predictable.',
                 "LOW", "probable", "LOW", "CWE-338", "MASVS-CRYPTO", 3.7,
                 'Never seed SecureRandom with constants; let the OS entropy source seed it.'),
    }
    _emit_bucketed(add, buckets, spec)


def _ws5_webview_checks(evd, add, component_classes):
    _bucket_sites.components = component_classes
    buckets = {}
    for key, dg in evd.methods.items():
        js = bridge = fileurl = debug = fileacc = False
        for (ccls, cname, cdesc, args) in dg["invokes"]:
            const1 = bool(args) and args[0] == ("int", 1)
            if cname == "setJavaScriptEnabled" and const1:
                js = True
            elif cname == "addJavascriptInterface":
                bridge = True
            elif cname in ("setAllowFileAccessFromFileURLs",
                          "setAllowUniversalAccessFromFileURLs") and const1:
                fileurl = True
            elif cname == "setAllowFileAccess" and const1:
                fileacc = True
            elif cname == "setWebContentsDebuggingEnabled" and const1:
                debug = True
        at = f"{key[0]}->{key[1]}"
        bucket = _bucket_sites(evd, key, dg)
        if js and bridge:
            buckets.setdefault("jsbridge", {}).setdefault(bucket, []).append(at)
        elif bridge:
            buckets.setdefault("deadbridge", {}).setdefault(bucket, []).append(at)
        if js and fileurl:
            buckets.setdefault("jsfile", {}).setdefault(bucket, []).append(at)
        elif fileacc and bucket == "app":
            buckets.setdefault("fileaccess", {}).setdefault(bucket, []).append(at)
        if debug:
            buckets.setdefault("wvdebug", {}).setdefault(bucket, []).append(at)
    spec = {
        "jsbridge": ("WebView JavaScript bridge enabled together with JavaScript",
                     'Code evidence (T2): the SAME method enables JavaScript and registers a JavaScript interface on a WebView — any web content the view loads can call into native code (the classic addJavascriptInterface attack surface).',
                     "HIGH", "probable", "MEDIUM", "CWE-749", "MASVS-PLATFORM", 7.5,
                     'Expose @JavascriptInterface methods only to first-party trusted pages; prefer a native bridge with origin checks.'),
        "jsfile": ("WebView JavaScript combined with file-URL access",
                   'Code evidence (T2): the SAME method enables JavaScript and allows file-URL access (setAllowFileAccessFromFileURLs / setAllowUniversalAccessFromFileURLs) — a malicious page can read local files.',
                   "HIGH", "probable", "MEDIUM", "CWE-200", "MASVS-PLATFORM", 6.5,
                   'Disable file-URL access from WebView content unless strictly required.'),
        "deadbridge": ("JavaScript interface registered while JavaScript is disabled in the same method",
                       'Code evidence (T2): addJavascriptInterface is called but JavaScript is not enabled in the same method — the bridge appears inactive (informational; the flags may be set on another instance elsewhere).',
                       "INFO", "candidate", "INFO", "CWE-749", "MASVS-PLATFORM", 0.0,
                       'No action if intentional; remove dead bridges to reduce confusion.'),
        "fileaccess": ("WebView file access enabled (single flag)",
                       'Code evidence (T2): setAllowFileAccess(true) alone — informational at this tier; it becomes dangerous combined with JavaScript or file-URL access, which are reported separately.',
                       "LOW", "candidate", "LOW", "CWE-200", "MASVS-PLATFORM", 3.1,
                       'Keep WebView file access disabled unless the feature requires it.'),
        "wvdebug": ("WebView contents debugging enabled in code",
                    'Code evidence (T2): WebView.setWebContentsDebuggingEnabled(true) is called with a constant — in a release build this lets anyone with USB access inspect and drive WebView content.',
                    "MEDIUM", "probable", "LOW", "CWE-489", "MASVS-RESILIENCE", 5.3,
                    'Gate the call behind BuildConfig.DEBUG.'),
    }
    _emit_bucketed(add, buckets, spec)


def analyze_apk(path, filename="app.apk", log=None, baseline=None):
    """Analisis statis satu file APK -> result dict kompatibel store.save_scan.
    baseline: operator secret baseline entries (list of dicts with 'hash',
    or a ready {hash: entry} map) — WS2/WS5 parity with the web engine."""
    def L(msg):
        if log is not None:
            log.append(msg)
    baseline_map = {}
    if isinstance(baseline, dict):
        baseline_map = baseline
    elif baseline:
        for _e in baseline:
            if isinstance(_e, dict) and _e.get("hash"):
                baseline_map[_e["hash"]] = _e
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
    pools, strings, raw_urls, pool_truncated = _extract_pools(zf, names, apk)
    L(f"[mobile] {len(strings)} unique strings, {len(raw_urls)} raw URLs")
    evd = _DexEvidence(zf, names, pkg)
    if evd.ok:
        L(f"[mobile] code evidence: {len(evd.methods)} methods across "
          f"{evd.total_classes} classes")
    elif evd.reason:
        L(f"[mobile] code evidence unavailable: {evd.reason}")
    component_classes = set()
    for _c in comps:
        _nm = _c["name"] or ""
        if _nm.startswith("."):
            _full = pkg + _nm
        elif "." not in _nm:
            _full = pkg + "." + _nm
        else:
            _full = _nm
        component_classes.add("L" + _full.replace(".", "/") + ";")

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
    # ---- 3. cleartext & pinning & trust anchors (WS3: parse NSC penuh;
    # base-config vs domain-config DIPISAH; bila NSC ter-parse, ia menimpa
    # usesCleartextTraffic sepenuhnya — aturan platform API 24+)
    nsc_name = None
    nsc_ref = app_attr("networkSecurityConfig")
    if nsc_ref and nsc_ref.startswith("@xml/"):
        cand = f"res/xml/{nsc_ref[5:]}.xml"
        if cand in names:
            nsc_name = cand
    nsc = _parse_nsc(zf, nsc_name)
    nsc_pinning = bool(nsc["pinsets"])
    legacy_clear = None
    if nsc_name and not nsc["parsed"]:
        try:  # fallback warisan bila AXML NSC gagal ter-parse terstruktur
            from androguard.core.axml import AXMLPrinter
            x = AXMLPrinter(zf.read(nsc_name)).get_buff().decode("utf-8", "replace")
            m = re.search(r'cleartextTrafficPermitted="([^"]+)"', x)
            legacy_clear = (m.group(1) == "true") if m else None
            nsc_pinning = "<pin-set" in x or "<pin " in x
        except Exception:
            pass
    ct_attr = app_attr("usesCleartextTraffic")
    if nsc["parsed"]:
        if nsc["base_cleartext"] is True:
            add(F("HIGH", 'Cleartext traffic allowed by network security config',
                  'The network security configuration explicitly allows unencrypted HTTP for all domains (base-config), so traffic can be intercepted/modified on the network.',
                  evidence=f"{nsc_name}: base-config cleartextTrafficPermitted=true",
                  cwe="CWE-319", owasp="MASVS-NETWORK", cvss=7.4,
                  remed='Set cleartextTrafficPermitted=false; use HTTPS for all endpoints.',
                  confidence="confirmed", location=nsc_name))
        elif nsc["domain_cleartext"]:
            add(F("MEDIUM", 'Cleartext traffic allowed for specific domains by network security config',
                  'The network security configuration allows unencrypted HTTP only for the listed domains (domain-config) — the exposure is scoped, not global.',
                  evidence=f"{nsc_name}: cleartextTrafficPermitted=true for domains: "
                           + ", ".join(nsc["domain_cleartext"][:8]),
                  cwe="CWE-319", owasp="MASVS-NETWORK", cvss=5.3,
                  remed='Serve these domains over HTTPS and remove the cleartext exception.',
                  confidence="confirmed", location=nsc_name))
        for uca in nsc["user_ca"]:
            add(F("MEDIUM", 'App trusts user-installed CA certificates',
                  'The network security config adds user-installed CAs to the trust anchors, so a user (or an attacker who can add a CA) can intercept the app traffic with a proxy.',
                  evidence=f"{nsc_name}: trust-anchors certificates src=\"user\" in {uca}",
                  cwe="CWE-295", owasp="MASVS-NETWORK", cvss=5.3,
                  remed='Trust only system CAs in release builds; scope user-CA trust to debug-overrides.',
                  confidence="probable", location=nsc_name))
        for ps in nsc["pinsets"]:
            exp = ps.get("expiration")
            if exp:
                try:
                    exp_d = datetime.strptime(exp[:10], "%Y-%m-%d").date()
                except Exception:
                    exp_d = None
                if exp_d and exp_d < datetime.now().date():
                    add(F("LOW", 'Certificate pin-set in network security config has expired',
                          'An expired pin-set is silently ignored by the platform — pinning appears configured but no longer protects anything.',
                          evidence=f"{nsc_name}: pin-set expiration={exp} ({ps['pins']} pin(s), domains: {', '.join(ps['domains'][:4]) or 'base-config'})",
                          cwe="CWE-295", owasp="MASVS-NETWORK", cvss=3.7,
                          remed='Renew the pin-set expiration and rotate pins before they lapse.',
                          confidence="probable", location=nsc_name))
    elif legacy_clear is True:
        add(F("HIGH", 'Cleartext traffic allowed by network security config',
              'The network security configuration explicitly allows unencrypted HTTP, so traffic can be intercepted/modified on the network.',
              evidence=f"{nsc_name}: cleartextTrafficPermitted=true",
              cwe="CWE-319", owasp="MASVS-NETWORK", cvss=7.4,
              remed='Set cleartextTrafficPermitted=false; use HTTPS for all endpoints.',
              confidence="confirmed", location=nsc_name))
    elif legacy_clear is None and ct_attr == "true":
        add(F("HIGH", "Cleartext traffic allowed (usesCleartextTraffic=true)",
              'The app allows unencrypted HTTP connections to all domains.',
              evidence="android:usesCleartextTraffic=\"true\"", cwe="CWE-319",
              owasp="MASVS-NETWORK", cvss=7.4,
              remed='Set usesCleartextTraffic=false and use HTTPS; if exceptions are needed, scope them per domain via network security config.',
              confidence="confirmed", location=M))
    elif legacy_clear is None and ct_attr is None and target_sdk and target_sdk < 28:
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
              'Activities/services/receivers/providers that are exported without a signature-level permission guard can be invoked by other apps — a classic Android attack surface (intent spoofing, provider data theft, unauthorized service triggering). The verdict uses the resolved protectionLevel of the guard permission (v1.9.0): a component guarded only by a normal/dangerous permission is still exposed, because any app can obtain those.',
              evidence="; ".join(
                  f"{c['tag']}:{c['name']}"
                  + (f" [guard {c['permission']} protectionLevel={c['protection']} — not signature-level]"
                     if c["permission"] else " [no guard permission]")
                  for c in exposed[:8]),
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
    # ---- 6. secrets (WS2: pipeline DETECTORS_V2 yang sama dengan engine
    # web — validator struktural lokal + skor konteks + baseline operator —
    # di atas kolam string tersegmentasi; identifier provider BUKAN secret)
    identifiers = []
    units = []
    for pool in pools:
        if pool["kind"] == "dex":
            for s in pool["texts"]:
                if not _secret_candidate(s):
                    continue
                usage, owner, where = "none", "unknown", ""
                if evd.ok:
                    usage, owner, where = evd.string_usage(s)
                units.append({"text": s, "location": pool["source"],
                              "config_style": False,
                              "tier": "T2" if usage.startswith("xref") else "T0",
                              "owner": owner,
                              "usage": usage if usage != "xref-unknown" else "none",
                              "where": where, "shipped": True})
        elif pool["kind"] == "file":
            units.append({"text": pool["texts"][0], "location": pool["source"],
                          "config_style": True, "tier": "T1", "owner": "app",
                          "usage": "config", "where": "", "shipped": True})
        elif pool["kind"] == "arsc":
            for s in pool["texts"]:
                if _secret_candidate(s):
                    units.append({"text": s, "location": pool["source"],
                                  "config_style": False, "tier": "T0",
                                  "owner": "app", "usage": "none",
                                  "where": "", "shipped": True})
    _scan_secrets_mobile(units, baseline_map, add, identifiers)
    if identifiers:
        _by_kind = {}
        for _kind, _val, _loc in identifiers:
            _by_kind.setdefault(_kind, []).append((_val, _loc))
        _parts = [f"{k} x{len(v)} (e.g. {_mask(v[0][0])} in {v[0][1]})"
                  for k, v in sorted(_by_kind.items())]
        _idf = F("INFO", "Client identifiers embedded in the app (not credentials)",
                 'Google/Firebase API keys (AIza…) and AWS Cognito identity pool IDs are client identifiers BY DESIGN: they identify the app/project to the provider, they are not credentials, and their presence alone is not a leak. Firebase data security depends entirely on the database security rules. They are listed here so they are never mistaken for exposed secrets.',
                 evidence="; ".join(_parts), cwe="CWE-200",
                 owasp="MASVS-STORAGE", cvss=0.0,
                 remed='No rotation needed for the identifiers themselves; audit the Firebase/Cognito security rules and API-key restrictions (app + API scoping) instead.',
                 confidence="confirmed", location="classes.dex/assets")
        _tag(_idf, "T1", "app")
        add(_idf)
    fb = [u for u in endpoints if "firebaseio.com" in u["host"] or
          "firebasedatabase.app" in u["host"]]
    if fb:
        _fbf = F("LOW", 'Firebase database URL exposed in the APK',
                 'The Realtime Database/Firestore URL is exposed (normal for client configuration) — security depends entirely on the security rules; open rules = public data leak.',
                 evidence=fb[0]["url"][:140], cwe="CWE-200", owasp="MASVS-STORAGE",
                 cvss=3.1, remed='Audit the Firebase security rules: ensure there is no public read/write without authentication.',
                 confidence="candidate", location="classes.dex/assets")
        _tag(_fbf, "T0", "app")
        add(_fbf)
    # ---- 7. endpoint http (cleartext) nyata
    if http_hosts:
        _hf = F("MEDIUM", f"HTTP endpoint (unencrypted) found: {len(http_hosts)} host",
                'The APK contains http:// URLs to real hosts. If actually called at runtime, the traffic (including tokens) can be intercepted on the network.',
                evidence=", ".join(sorted(http_hosts)[:8]), cwe="CWE-319",
                owasp="MASVS-NETWORK", cvss=5.3,
                remed='Migrate all endpoints to https and enable HSTS on the server side.',
                confidence="probable", location="classes.dex/assets")
        _tag(_hf, "T0", "app")
        add(_hf)
    # ---- 8. pemeriksaan berbasis bukti kode (WS1/WS3/WS4/WS5/WS6) —
    # menggantikan indikasi string mentah lama: vonis sekarang mengikuti
    # referensi kode + argumen konstanta terslice (T2), gerbang
    # keterjangkauan K1, dan demosi library K4.
    elf_rows = []
    if evd.ok:
        _ws3_tls_checks(evd, add, component_classes)
        _ws4_crypto_checks(evd, add, component_classes)
        _ws5_webview_checks(evd, add, component_classes)
        # WS6a: MODE_WORLD_* dari konstanta mode terslice / referensi field
        _mw_buckets = {}
        for _key, _dg in evd.methods.items():
            _hit = any(fd.endswith(("MODE_WORLD_READABLE", "MODE_WORLD_WRITEABLE"))
                       for fd in _dg["fields"])
            if not _hit:
                for (_cc, _cn, _cd, _args) in _dg["invokes"]:
                    if _cn in ("getSharedPreferences", "openFileOutput") and _args:
                        if any(isinstance(a, tuple) and a[0] == "int" and a[1] & 0x3
                               for a in _args):
                            _hit = True
            if _hit:
                _mw_buckets.setdefault("world", {}).setdefault(
                    _bucket_sites(evd, _key, _dg), []).append(
                    f"{_key[0]}->{_key[1]}")
        _emit_bucketed(add, _mw_buckets, {
            "world": ("World-readable/writable app data access (MODE_WORLD_*)",
                      'Code evidence (T2): getSharedPreferences/openFileOutput is called with a MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE constant (sliced from the call site, or the mode field reference). Any app can read/write such files on rooted or old devices; the flags are deprecated precisely because they silently share app data.',
                      "MEDIUM", "probable", "LOW", "CWE-200", "MASVS-STORAGE", 5.3,
                      'Use MODE_PRIVATE (the default) for all app files and preferences.')})
        # pemuatan kode dinamis (INFO — permukaan serangan runtime)
        _dl_buckets = {}
        for _key, _dg in evd.methods.items():
            if any(i[0] in ("Ldalvik/system/DexClassLoader;",
                            "Ldalvik/system/PathClassLoader;",
                            "Ldalvik/system/InMemoryDexClassLoader;")
                   for i in _dg["invokes"]):
                _dl_buckets.setdefault("dynload", {}).setdefault(
                    _bucket_sites(evd, _key, _dg), []).append(
                    f"{_key[0]}->{_key[1]}")
        _emit_bucketed(add, _dl_buckets, {
            "dynload": ("Dynamic code loading in use (DexClassLoader)",
                        'Code evidence (T2): the app loads DEX code dynamically. Legitimate for plugin architectures, but code loaded from writable/network locations bypasses the installed package signature boundary.',
                        "INFO", "candidate", "INFO", "CWE-829", "MASVS-CODE", 0.0,
                        'Load only signature-verified code from read-only locations; prefer Play Feature Delivery for modules.')})
    # ---- WS6b. file sensitif yang ikut ter-ship di dalam paket
    _ship_ks, _ship_db, _ship_cred = [], [], []
    for _n in names:
        _low = _n.lower()
        if _low.startswith("meta-inf/"):
            continue
        _base = _low.rsplit("/", 1)[-1]
        if _base.endswith((".keystore", ".jks", ".bks", ".p12", ".pfx")):
            _ship_ks.append(_n)
        elif _base.endswith((".db", ".sqlite", ".sqlite3")) and \
                _low.startswith(("assets/", "res/raw/")):
            _ship_db.append(_n)
        elif _base in ("credentials.json", "secrets.json", ".env") or \
                _base.startswith("id_rsa"):
            _ship_cred.append(_n)
    if _ship_ks:
        _kf = F("HIGH", "Keystore file shipped inside the app package",
                'A cryptographic keystore ships inside the APK. Its protection reduces to the keystore password — if that password is weak, embedded, or the store is unprotected, the private keys are compromised for anyone who downloads the app.',
                evidence="; ".join(_ship_ks[:6]), cwe="CWE-798",
                owasp="MASVS-STORAGE", cvss=7.4,
                remed='Never ship keystores in the app; use Android Keystore generated on-device or Play App Signing.',
                confidence="probable", location=_ship_ks[0])
        _tag(_kf, "T1", "app")
        add(_kf)
    if _ship_db:
        _df = F("MEDIUM", "Database file shipped in app assets",
                'A pre-populated database ships inside the package — its contents are readable by anyone who extracts the APK.',
                evidence="; ".join(_ship_db[:6]), cwe="CWE-200",
                owasp="MASVS-STORAGE", cvss=5.3,
                remed='Ship only non-sensitive seed data; keep user/credential data out of bundled databases.',
                confidence="candidate", location=_ship_db[0])
        _tag(_df, "T1", "app")
        add(_df)
    if _ship_cred:
        _cf = F("LOW", "Possible credential file shipped in the app package",
                'A file whose name indicates credentials ships inside the package. Its contents are readable by anyone who extracts the APK — verify whether it holds live secrets.',
                evidence="; ".join(_ship_cred[:6]), cwe="CWE-798",
                owasp="MASVS-STORAGE", cvss=3.7,
                remed='Remove credential files from the package; inject configuration at runtime from a backend.',
                confidence="candidate", location=_ship_cred[0])
        _tag(_cf, "T1", "app")
        add(_cf)
    # ---- WS7. hardening ELF untuk library native (parser tulisan sendiri)
    _native = {}
    for _n in names:
        _m = re.match(r"lib/([^/]+)/([^/]+\.so)$", _n)
        if _m:
            _native.setdefault(_m.group(1), []).append(_n)
    _elf_no_pie, _elf_no_nx, _elf_no_canary, _elf_no_relro = [], [], [], []
    for _abi, _libs in sorted(_native.items()):
        for _ln in _libs[:24]:
            try:
                _info = _elf_info(zf.read(_ln))
            except Exception:
                continue
            elf_rows.append({"name": _ln, "arch": _info["arch"],
                             "pie": _info["pie"], "nx": _info["nx"],
                             "relro": _info["relro"],
                             "canary": _info["canary"]})
            if _info["pie"] is False:
                _elf_no_pie.append(_ln)
            if _info["nx"] is False:
                _elf_no_nx.append(_ln)
            if _info["canary"] is False:
                _elf_no_canary.append(_ln)
            if _info["relro"] == "absent":
                _elf_no_relro.append(_ln)
    if _elf_no_pie:
        _pf = F("LOW", "Native libraries are not position-independent (ET_EXEC, no PIE)",
                'ELF evidence (T1): these .so files are ET_EXEC rather than ET_DYN, so they load at fixed addresses and weaken ASLR.',
                evidence="; ".join(_elf_no_pie[:8]), cwe="CWE-338",
                owasp="MASVS-RESILIENCE", cvss=3.7,
                remed='Build native code with -fPIE/-pie (default in modern NDK).',
                confidence="probable", location=_elf_no_pie[0])
        _tag(_pf, "T1", "app")
        add(_pf)
    if _elf_no_nx:
        _xf = F("MEDIUM", "Native library has an executable stack (PT_GNU_STACK RWE)",
                'ELF evidence (T1): PT_GNU_STACK is marked executable in these libraries — a classic memory-corruption exploitation aid.',
                evidence="; ".join(_elf_no_nx[:8]), cwe="CWE-693",
                owasp="MASVS-RESILIENCE", cvss=5.3,
                remed='Link with -z noexecstack (NDK default) and remove trampolines that require an executable stack.',
                confidence="probable", location=_elf_no_nx[0])
        _tag(_xf, "T1", "app")
        add(_xf)
    if _elf_no_canary:
        _nf = F("LOW", "Native libraries without a stack canary (__stack_chk_fail)",
                'ELF evidence (T1): no __stack_chk_fail import was found in the .dynsym of these libraries, so they were likely built without -fstack-protector.',
                evidence="; ".join(_elf_no_canary[:8]), cwe="CWE-121",
                owasp="MASVS-RESILIENCE", cvss=3.7,
                remed='Compile native code with -fstack-protector-strong.',
                confidence="candidate", location=_elf_no_canary[0])
        _tag(_nf, "T1", "app")
        add(_nf)
    if _elf_no_relro:
        _rf = F("LOW", "Native libraries without RELRO (PT_GNU_RELRO absent)",
                'ELF evidence (T1): these libraries have no PT_GNU_RELRO segment, leaving the GOT writable after relocation.',
                evidence="; ".join(_elf_no_relro[:8]), cwe="CWE-693",
                owasp="MASVS-RESILIENCE", cvss=3.7,
                remed='Link with -z relro -z now (full RELRO).',
                confidence="candidate", location=_elf_no_relro[0])
        _tag(_rf, "T1", "app")
        add(_rf)
    # ---- WS9. indikator resilience (INFO — keberadaan != efektivitas)
    if evd.ok:
        _app_classes = [c for c in evd.classes if evd.owner(c) == "app"]
        if len(_app_classes) >= 20:
            _short = sum(1 for c in _app_classes
                         if any(seg.islower() and seg.isalpha() and len(seg) <= 2
                                for seg in c[1:-1].split("/")))
            _obf = _short / len(_app_classes)
            if _obf >= 0.5:
                _of = F("INFO", "Class names appear obfuscated (resilience indicator)",
                        'A majority of app class names are short/meaningless (R8/ProGuard-style). Obfuscation weakens purely string-based detection; the code-evidence verdicts in this report therefore rely on API shapes and call structure, not names. Recorded as an indicator, not a vulnerability.',
                        evidence=f"{_obf:.0%} of {len(_app_classes)} app classes have obfuscated-style names",
                        cwe="CWE-200", owasp="MASVS-RESILIENCE", cvss=0.0,
                        remed='No action required — indicator recorded for analysis scoping.',
                        confidence="candidate", location="classes.dex")
                _tag(_of, "T1", "app")
                add(_of)
    _root_ind = [s for s in strings
                 if "rootbeer" in s.lower() or "magisk" in s.lower()
                 or s in ("/system/xbin/su", "/system/bin/su", "/sbin/su")]
    if _root_ind:
        _uf = F("INFO", "Root-detection indicators present (presence is not effectiveness)",
                'Strings associated with root detection (RootBeer/Magisk/su paths) are present. This records PRESENCE only — whether the checks are enforced, and whether they can be bypassed, cannot be determined statically.',
                evidence="; ".join(sorted(set(_root_ind))[:5]),
                cwe="CWE-200", owasp="MASVS-RESILIENCE", cvss=0.0,
                remed='No action required — verify enforcement dynamically if root detection is part of the security model.',
                confidence="candidate", location="classes.dex/assets")
        _tag(_uf, "T0", "app")
        add(_uf)
    if any("play.core.integrity" in s or "IntegrityManager" in s for s in strings):
        _gf = F("INFO", "Play Integrity API present (presence is not effectiveness)",
                'The Play Integrity API is referenced. Presence says nothing about whether verdicts are enforced server-side, which is where integrity decisions belong.',
                evidence="Play Integrity API references found in strings",
                cwe="CWE-200", owasp="MASVS-RESILIENCE", cvss=0.0,
                remed='Enforce integrity verdicts on the backend; never trust a client-side verdict alone.',
                confidence="candidate", location="classes.dex/assets")
        _tag(_gf, "T0", "app")
        add(_gf)
    elif any("safetynet" in s.lower() for s in strings):
        _gf = F("INFO", "Deprecated SafetyNet attestation referenced",
                'SafetyNet attestation is deprecated and replaced by Play Integrity; new integrations should not rely on it.',
                evidence="SafetyNet references found in strings",
                cwe="CWE-1104", owasp="MASVS-RESILIENCE", cvss=0.0,
                remed='Migrate attestation to Play Integrity with backend-side verdict checks.',
                confidence="candidate", location="classes.dex/assets")
        _tag(_gf, "T0", "app")
        add(_gf)
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
    pinning_code = _code_pinning(evd) if evd.ok else []
    if nsc_pinning or pinning_code:
        pinning_detected = True
    elif nsc["parsed"] or evd.ok:
        pinning_detected = False
    else:
        pinning_detected = None  # unknown — never claim absence unmeasured
    _packed = any(any(mk in n for mk in ("libDexHelper", "libtosprotection",
                                          "libjiagu", "libSecShell",
                                          "libapkprotect", "libDexProtector"))
                  for n in names)
    _obf_score = None
    if evd.ok:
        _ac = [c for c in evd.classes if evd.owner(c) == "app"]
        if len(_ac) >= 20:
            _obf_score = round(sum(
                1 for c in _ac
                if any(seg.islower() and seg.isalpha() and len(seg) <= 2
                       for seg in c[1:-1].split("/"))) / len(_ac), 2)
    _nsv = ["Runtime behavior and the actual network traffic (dynamic "
            "analysis only)",
            "Server-side authorization, business logic and API abuse",
            "Reflection/JNI-only call paths that leave no DEX call-graph edge",
            "Whether any embedded credential is still active (never "
            "validated against its provider, decision D5)"]
    if not evd.ok:
        _nsv.append("Code-evidence (T2) checks — the DEX code layer was "
                    f"unavailable: {evd.reason}")
    if nsc_name and not nsc["parsed"]:
        _nsv.append("Network security config semantics (the NSC file could "
                    "not be parsed structurally)")
    coverage = {
        "engine": "vanthex-mobile-deep/1.13.0",
        "dex_files": [d["name"] for d in contents["dex_files"]],
        "classes_total": evd.total_classes if evd.ok else contents["dex_classes"],
        "app_classes": (sum(1 for c in evd.classes if evd.owner(c) == "app")
                        if evd.ok else None),
        "library_classes": (sum(1 for c in evd.classes
                                if evd.owner(c) == "library") if evd.ok else None),
        "methods_censused": len(evd.methods) if evd.ok else 0,
        "code_evidence": "full (T2: xref census + sliced constants)"
                         if evd.ok else "unavailable",
        "code_evidence_note": evd.reason,
        "string_pools": [{"kind": p["kind"], "source": p["source"],
                          "strings": len(p["texts"])} for p in pools],
        "pool_truncated": pool_truncated,
        "pinning": {"nsc_pinset": nsc_pinning, "code_pinning": bool(pinning_code),
                    "code_sites": pinning_code[:5]},
        "native_libs": elf_rows,
        "obfuscation_score": _obf_score,
        "packed_suspected": _packed,
        "not_statically_verifiable": _nsv}
    _finalize_tags(findings)
    meta = {"platform": "android", "contents": contents, "decompile": decomp,
            "coverage": coverage,
            "package": pkg, "app_name": app_name, "version_name": ver_name,
            "version_code": ver_code, "min_sdk": min_sdk, "target_sdk": target_sdk,
            "file_name": filename, "file_size": len(raw), "sha256": sha,
            "permissions": perms, "dangerous_permissions": dang,
            "components": {"total": len(comps),
                           "exported": [f"{c['tag']}:{c['name']}" for c in comps if c["exported"]]},
            "cert": cert, "pinning_detected": pinning_detected,
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
            "entitlements": ent,
            "devices": len(devices)}
    if pl.get("ProvisionsAllDevices"):
        info["distribution"] = "enterprise"
    elif devices:
        info["distribution"] = "development/ad-hoc"
    else:
        info["distribution"] = "app-store"
    return info


_MACHO_FILETYPE = {1: "MH_OBJECT", 2: "MH_EXECUTE", 3: "MH_FVMLIB",
                   4: "MH_CORE", 5: "MH_PRELOAD", 6: "MH_DYLIB",
                   7: "MH_DYLINKER", 8: "MH_BUNDLE", 9: "MH_DYLIB_STUB",
                   10: "MH_DSYM", 11: "MH_KEXT_BUNDLE"}


def _macho_primary_slice(data):
    """(slice_bytes, cputype) of the primary slice — arm64 preferred for
    fat binaries (NOT blindly the first slice)."""
    if not data or len(data) < 4:
        return b"", 0
    magic = bytes(data[:4])
    if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        fmt = ">" if magic == b"\xca\xfe\xba\xbe" else "<"
        try:
            n = struct.unpack(fmt + "I", data[4:8])[0]
            off, slices = 8, []
            for _ in range(min(n, 8)):
                cputype, _s, offset, size, _a = struct.unpack(
                    fmt + "IIIII", data[off:off + 20])
                slices.append((cputype, offset, size))
                off += 20
            for want in (0x0100000C, 0x0200000C):
                for (ct, o, sz) in slices:
                    if ct == want:
                        return data[o:o + sz], ct
            if slices:
                ct, o, sz = slices[0]
                return data[o:o + sz], ct
        except Exception:
            pass
        return b"", 0
    return data, None


def _macho_full(data):
    """Extended self-built Mach-O parse of the PRIMARY slice (WS8):
    filetype, code signature, rpaths, sections (for the ObjC walk)."""
    out = {"filetype": "", "pie": None, "cryptid": None, "arch": "",
           "has_code_signature": False, "rpaths": [], "cs": None,
           "sections": [], "endian": "<", "is64": True, "slice": b""}
    sl, cpu = _macho_primary_slice(data)
    if not sl or len(sl) < 4:
        return out
    out["slice"] = sl
    if cpu:
        out["arch"] = _MACHO_CPU.get(cpu, hex(cpu))
    magic = bytes(sl[:4])
    if magic == b"\xcf\xfa\xed\xfe":
        en, is64 = "<", True
    elif magic == b"\xce\xfa\xed\xfe":
        en, is64 = "<", False
    elif magic == b"\xfe\xed\xfa\xcf":
        en, is64 = ">", True
    elif magic == b"\xfe\xed\xfa\xce":
        en, is64 = ">", False
    else:
        return out
    out["endian"], out["is64"] = en, is64
    try:
        cputype, _st, ftype, ncmds, _szc, flags = struct.unpack(
            en + "IIIIII", sl[4:28])
        if not out["arch"]:
            out["arch"] = _MACHO_CPU.get(cputype, hex(cputype))
        out["filetype"] = _MACHO_FILETYPE.get(ftype, hex(ftype))
        out["pie"] = bool(flags & 0x200000)
        off = 32 if is64 else 28
        for _ in range(min(ncmds, 300)):
            cmd, cmdsize = struct.unpack(en + "II", sl[off:off + 8])
            if cmdsize < 8:
                break
            if cmd in (0x21, 0x2C) and cmdsize >= 20:
                out["cryptid"] = struct.unpack(en + "I", sl[off + 16:off + 20])[0]
            elif cmd == 0x1D and cmdsize >= 16:  # LC_CODE_SIGNATURE
                doff, dsize = struct.unpack(en + "II", sl[off + 8:off + 16])
                out["has_code_signature"] = True
                out["cs"] = (doff, dsize)
            elif cmd in (0x8000001C, 0x0000001C) and cmdsize > 12:  # LC_RPATH
                raw = sl[off + 12:off + cmdsize].split(b"\x00")[0]
                out["rpaths"].append(raw.decode("utf-8", "replace"))
            elif cmd in (0x19, 0x1):  # LC_SEGMENT_64 / LC_SEGMENT
                if is64 and cmd == 0x19:
                    nsec = struct.unpack(en + "I", sl[off + 64:off + 68])[0]
                    so = off + 72
                    for _i in range(min(nsec, 64)):
                        sb = sl[so + _i * 80: so + _i * 80 + 80]
                        if len(sb) < 80:
                            break
                        sname = sb[0:16].split(b"\x00")[0].decode("utf-8", "replace")
                        gname = sb[16:32].split(b"\x00")[0].decode("utf-8", "replace")
                        saddr, ssize = struct.unpack(en + "QQ", sb[32:48])
                        soff = struct.unpack(en + "I", sb[48:52])[0]
                        out["sections"].append((gname, sname, saddr, ssize, soff))
            off += cmdsize
    except Exception:
        pass
    return out


def _macho_entitlements(mf):
    """Entitlements CLAIMED by the code signature of the primary slice
    (CS superblob is big-endian; slot 5 = XML entitlements)."""
    if not mf or not mf.get("cs"):
        return None
    sl = mf["slice"]
    doff, dsize = mf["cs"]
    blob = sl[doff:doff + dsize]
    if len(blob) < 12:
        return None
    try:
        magic, _len, count = struct.unpack(">III", blob[:12])
        if magic != 0xFADE0CC0:
            return None
        for i in range(min(count, 32)):
            typ, boff = struct.unpack(">II", blob[12 + i * 8:20 + i * 8])
            if typ != 5:
                continue
            bmagic, blen = struct.unpack(">II", blob[boff:boff + 8])
            if bmagic != 0xFADE7171:
                return None
            raw = blob[boff + 8:boff + blen]
            try:
                obj = plistlib.loads(raw)
                return obj if isinstance(obj, dict) else None
            except Exception:
                a, b = raw.find(b"<?xml"), raw.find(b"</plist>")
                if a >= 0 and b > a:
                    try:
                        obj = plistlib.loads(raw[a:b + len(b"</plist>")])
                        return obj if isinstance(obj, dict) else None
                    except Exception:
                        return None
            return None
    except Exception:
        return None
    return None


def _objc_inventory(mf):
    """Bounded ObjC metadata walk (WS8/K2): __objc_classlist -> class_ro ->
    class name + baseMethods counts (metaclass included). Inventory and
    API attribution ONLY — no selector semantics are inferred. arm64e
    chained fixups make some binaries unreadable this way; those return
    None and the coverage header says so honestly."""
    if not mf or not mf.get("is64") or not mf.get("sections"):
        return None
    data, en = mf["slice"], mf["endian"]
    secs = {(g, s): (a, z, o) for (g, s, a, z, o) in mf["sections"]}

    def v2o(va):
        for (a, z, o) in secs.values():
            if a <= va < a + z:
                return o + (va - a)
        return None

    def u64(o):
        return struct.unpack_from(en + "Q", data, o)[0]

    def u32(o):
        return struct.unpack_from(en + "I", data, o)[0]

    def i32(o):
        return struct.unpack_from(en + "i", data, o)[0]

    def cstr(o, cap=160):
        if o is None or o < 0 or o >= len(data):
            return None
        end = data.find(b"\x00", o, o + cap)
        if end < 0:
            return None
        try:
            s = data[o:end].decode("utf-8")
        except Exception:
            return None
        if not s or any(ord(ch) < 32 for ch in s):
            return None
        return s

    def method_list_count(ptr):
        o = v2o(ptr & 0xFFFFFFFFFFFFFFF8)
        if o is None or o + 8 > len(data):
            return 0, []
        flags = u32(o)
        count = min(u32(o + 4), 100000)
        names = []
        if flags & 0x80000000:  # relative (small) method list
            for i in range(min(count, 2000)):
                eo = o + 8 + i * 12
                if eo + 12 > len(data):
                    break
                noff = i32(eo)
                field_va = None
                # address of the name field itself: rebuild from file off
                # via the containing section
                for (a, z, fo) in secs.values():
                    if fo <= eo < fo + z:
                        field_va = a + (eo - fo)
                        break
                if field_va is None:
                    continue
                selref = v2o(field_va + noff)
                if selref is None:
                    continue
                try:
                    sp = u64(selref)
                except Exception:
                    continue
                nm = cstr(v2o(sp))
                if nm is None:  # direct-selector lists point at the string
                    nm = cstr(v2o(field_va + noff))
                if nm:
                    names.append(nm)
        else:
            for i in range(min(count, 2000)):
                eo = o + 8 + i * 24
                if eo + 8 > len(data):
                    break
                nm = cstr(v2o(u64(eo)))
                if nm:
                    names.append(nm)
        return count, names

    key = None
    for cand in (("__DATA_CONST", "__objc_classlist"),
                 ("__DATA", "__objc_classlist"),
                 ("__DATA_DIRTY", "__objc_classlist")):
        if cand in secs:
            key = cand
            break
    if key is None:
        return None
    _addr, size, off = secs[key]
    names, total_methods, selectors = [], 0, []
    PMASK = 0xFFFFFFFFFFFFFFF8  # struct pointers: strip low flag bits only
    try:
        for i in range(size // 8):
            if len(names) >= 4000:
                break
            cls_ptr = u64(off + i * 8)
            co = v2o(cls_ptr & PMASK)
            if co is None or co + 40 > len(data):
                continue
            ro_ptr = u64(co + 32)
            ro = v2o(ro_ptr & PMASK)
            if ro is None or ro + 40 > len(data):
                continue
            nm = cstr(v2o(u64(ro + 24)))
            if nm:
                names.append(nm)
            bm = u64(ro + 32)
            if bm:
                cnt, mn = method_list_count(bm)
                total_methods += cnt
                selectors.extend(mn[:20])
            isa = u64(co)
            mo = v2o(isa & PMASK)
            if mo and mo + 40 <= len(data):
                mro_ptr = u64(mo + 32)
                mro = v2o(mro_ptr & PMASK)
                if mro and mro + 40 <= len(data):
                    mbm = u64(mro + 32)
                    if mbm:
                        cnt, mn = method_list_count(mbm)
                        total_methods += cnt
                        selectors.extend(mn[:20])
    except Exception:
        return None
    if not names:
        return None
    return {"classes": len(names), "methods": total_methods,
            "class_names": names[:60], "selectors_sample": selectors[:60]}


def analyze_ipa(path, filename="app.ipa", log=None, baseline=None):
    """Analisis statis satu file IPA -> result dict kompatibel store.save_scan.
    baseline: operator secret baseline entries (WS2 parity, as in APK)."""
    def L(msg):
        if log is not None:
            log.append(msg)
    baseline_map = {}
    if isinstance(baseline, dict):
        baseline_map = baseline
    elif baseline:
        for _e in baseline:
            if isinstance(_e, dict) and _e.get("hash"):
                baseline_map[_e["hash"]] = _e
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
    mf = None
    claimed_ent = None
    if exe_name and (app_prefix + exe_name) in names:
        exe_data = zf.read(app_prefix + exe_name)
        macho = _macho_info(exe_data)
        mf = _macho_full(exe_data)
        claimed_ent = _macho_entitlements(mf)
    encrypted = macho.get("encrypted") is True

    # ---- string & URL tersegmentasi (WS8): string executable terpisah dari
    # string file aset agar atribusi sumbernya jelas; executable hanya bila
    # TIDAK terenkripsi FairPlay
    strings, raw_urls = set(), set()
    exe_strings, file_units = set(), []
    pool_truncated = False
    budget = 90 * 1024 * 1024

    def _harvest(data):
        nonlocal budget, pool_truncated
        if budget <= 0:
            pool_truncated = True
            return set()
        if len(data) > budget:
            data = data[:budget]
            pool_truncated = True
        budget -= len(data)
        out = set()
        for m in _URL_RE.findall(data):
            raw_urls.add(m.decode("utf-8", "replace").rstrip(")]>\"'.,;"))
        for m in _STR_RE.findall(data):
            try:
                out.add(m.decode("utf-8"))
            except Exception:
                pass
        return out

    if exe_data and not encrypted:
        exe_strings = _harvest(exe_data)
        strings |= exe_strings
    for n in names:
        if not n.startswith(app_prefix) or n.endswith("/"):
            continue
        low = n.lower()
        if low.endswith((".plist", ".json", ".js", ".txt", ".strings", ".xml")) \
                and not low.endswith("info.plist"):
            try:
                if zf.getinfo(n).file_size <= 4 * 1024 * 1024:
                    _d = zf.read(n)
                    strings |= _harvest(_d)
                    if zf.getinfo(n).file_size <= 512 * 1024:
                        file_units.append((n, _d.decode("utf-8", "replace")))
            except Exception:
                pass
        if budget <= 0:
            pool_truncated = True
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
    # ---- ATS / cleartext (WS8: kunci penimpa iOS 10+ — InWebContent /
    # ForMedia / LocalNetworking — MENIMPA NSAllowsArbitraryLoads untuk
    # domain masing-masing; arbitrary-loads tidak lagi dibaca sebagai
    # cleartext global membabi buta)
    ats = info.get("NSAppTransportSecurity") or {}
    _override_keys = [k for k in ("NSAllowsArbitraryLoadsInWebContent",
                                  "NSAllowsArbitraryLoadsForMedia",
                                  "NSAllowsLocalNetworking")
                      if ats.get(k) is True]
    if ats.get("NSAllowsArbitraryLoads") is True and not _override_keys:
        add(F("HIGH", "Cleartext traffic allowed for all domains (NSAllowsArbitraryLoads)",
              'App Transport Security is fully disabled: the app may load unencrypted HTTP from any domain, exposing traffic to interception/modification.',
              evidence="NSAppTransportSecurity.NSAllowsArbitraryLoads = true",
              cwe="CWE-319", owasp="MASVS-NETWORK", cvss=7.4,
              remed='Remove NSAllowsArbitraryLoads; use HTTPS everywhere and scope any exception per domain with a justification.',
              confidence="confirmed", location=IP))
    elif ats.get("NSAllowsArbitraryLoads") is True and _override_keys:
        add(F("MEDIUM", "ATS arbitrary loads set, but iOS 10+ override keys take precedence",
              'NSAllowsArbitraryLoads is present together with override keys. Since iOS 10 the override keys win for their content types, so arbitrary HTTP is NOT globally enabled — the exposure is limited to the override scopes listed in the evidence. The legacy key should still be removed to avoid ambiguity.',
              evidence="NSAllowsArbitraryLoads = true; override keys present: "
                       + ", ".join(_override_keys),
              cwe="CWE-319", owasp="MASVS-NETWORK", cvss=5.3,
              remed='Remove NSAllowsArbitraryLoads and keep only the narrowly scoped overrides that are genuinely needed.',
              confidence="probable", location=IP))
    elif _override_keys:
        add(F("LOW", "ATS relaxed for specific content scopes (iOS override keys)",
              'Specific ATS override keys relax transport security for web content, media, or local networking only — not a global cleartext allowance.',
              evidence="override keys present: " + ", ".join(_override_keys),
              cwe="CWE-319", owasp="MASVS-NETWORK", cvss=3.7,
              remed='Keep overrides only where the content genuinely requires them.',
              confidence="probable", location=IP))
    ats_exception_domains = []
    for dom, cfg in (ats.get("NSExceptionDomains") or {}).items():
        if not isinstance(cfg, dict):
            continue
        ats_exception_domains.append(dom)
        _insecure_key = None
        if cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True:
            _insecure_key = "NSExceptionAllowsInsecureHTTPLoads"
        elif cfg.get("NSThirdPartyExceptionAllowsInsecureHTTPLoads") is True:
            _insecure_key = "NSThirdPartyExceptionAllowsInsecureHTTPLoads"
        if _insecure_key:
            add(F("MEDIUM", f"ATS exception allows insecure HTTP loads: {dom}",
                  'This domain is exempted from ATS and may be contacted over plaintext HTTP.',
                  evidence=f"NSExceptionDomains.{dom}.{_insecure_key} = true",
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
    # ---- WS8: entitlements dua sisi — yang DIKLAIM tanda tangan kode vs
    # yang DIIZINKAN profile adalah dua hal yang berbeda
    if claimed_ent and prov and not prov.get("parse_error"):
        _pent = prov.get("entitlements") or {}
        _mismatch = []
        _c_appid = claimed_ent.get("application-identifier") or ""
        _p_appid = _pent.get("application-identifier") or ""
        if _c_appid and _p_appid:
            if _p_appid.endswith(".*"):
                if not _c_appid.startswith(_p_appid[:-1]):
                    _mismatch.append(
                        f"application-identifier: binary claims '{_c_appid}' "
                        f"outside the profile wildcard '{_p_appid}'")
            elif _c_appid != _p_appid:
                _mismatch.append(
                    f"application-identifier: binary claims '{_c_appid}' but "
                    f"the profile allows '{_p_appid}'")
        _c_kg = claimed_ent.get("keychain-access-groups") or []
        _p_kg = _pent.get("keychain-access-groups") or []

        def _kg_allowed(g):
            for pg in _p_kg:
                if pg == g:
                    return True
                if pg.endswith(".*") and g.startswith(pg[:-1]):
                    return True
            return False

        _extra_kg = [g for g in _c_kg if not _kg_allowed(g)]
        if _extra_kg:
            _mismatch.append("keychain-access-groups claimed beyond the "
                             "profile allowlist: " + ", ".join(_extra_kg[:4]))
        if _mismatch:
            _ef = F("MEDIUM", "Binary claims entitlements beyond the provisioning profile",
                    'The entitlements embedded in the code signature exceed what the embedded provisioning profile allows (claimed vs allowed are different things). A mismatch signals a signing-pipeline problem — or a re-signed build carrying more privilege than the profile grants.',
                    evidence="; ".join(_mismatch), cwe="CWE-863",
                    owasp="MASVS-RESILIENCE", cvss=5.3,
                    remed='Re-sign with a profile whose entitlements exactly match the binary, and audit the signing pipeline.',
                    confidence="probable", location="CodeSignature")
            _tag(_ef, "T1", "app")
            add(_ef)
        if any(g == "*" for g in _c_kg):
            _wf = F("LOW", "Wildcard keychain access group claimed by the binary",
                    'The code signature claims a wildcard keychain-access-group, which would let the app reach keychain items outside its own groups.',
                    evidence="keychain-access-groups contains '*'",
                    cwe="CWE-732", owasp="MASVS-STORAGE", cvss=3.7,
                    remed='Scope keychain access groups to the app identifier prefix.',
                    confidence="candidate", location="CodeSignature")
            _tag(_wf, "T1", "app")
            add(_wf)
        if claimed_ent.get("aps-environment") == "development" and \
                prov.get("distribution") == "app-store":
            _af = F("LOW", "Development push entitlement in an App Store-profile build",
                    'The binary claims aps-environment=development while the provisioning profile is an App Store profile — push notifications will fail in production and the mismatch signals a signing mix-up.',
                    evidence="aps-environment=development (claimed) with an app-store profile",
                    cwe="CWE-1104", owasp="MASVS-CODE", cvss=3.1,
                    remed='Rebuild with the production aps-environment for distribution.',
                    confidence="candidate", location="CodeSignature")
            _tag(_af, "T1", "app")
            add(_af)
    # ---- Mach-O hardening
    if macho["archs"] and macho["pie"] is False:
        add(F("LOW", "Main binary is not position-independent (MH_PIE missing)",
              'Without PIE, the executable loads at a fixed address, weakening ASLR for the main image.',
              evidence=f"archs={', '.join(macho['archs'])}, MH_PIE flag absent",
              cwe="CWE-338", owasp="MASVS-RESILIENCE", cvss=3.7,
              remed='Build with PIE enabled (Xcode default for modern targets).',
              confidence="probable", location=exe_name or "Mach-O"))
    if mf and mf.get("rpaths"):
        _bad_rp = [r for r in mf["rpaths"]
                   if (r.startswith("/") and not r.startswith("@"))
                   or "../.." in r]
        if _bad_rp:
            _rf2 = F("LOW", "Main binary contains a suspicious runpath (LC_RPATH)",
                     'The binary searches for libraries in an absolute path outside the app bundle or via deep parent traversal — a dylib hijack surface if that location is writable.',
                     evidence="LC_RPATH: " + ", ".join(_bad_rp[:4]),
                     cwe="CWE-426", owasp="MASVS-RESILIENCE", cvss=3.7,
                     remed='Restrict runpaths to @executable_path/… and @loader_path/… inside the bundle.',
                     confidence="candidate", location=exe_name or "Mach-O")
            _tag(_rf2, "T1", "app")
            add(_rf2)
    if not encrypted and strings and not any("__stack_chk_guard" in s for s in strings):
        _cnf = F("LOW", "No stack canary indication in the main binary",
                 'The __stack_chk_guard symbol was not found among the binary strings — the main executable may be built without stack smashing protection. Symbol presence is string-based, so manual verification is required.',
                 evidence="__stack_chk_guard not found in executable strings",
                 cwe="CWE-121", owasp="MASVS-RESILIENCE", cvss=3.7,
                 remed='Enable -fstack-protector-strong (Xcode default) and verify with a binary analysis tool.',
                 confidence="candidate", location=exe_name or "Mach-O")
        _tag(_cnf, "T0", "app")
        add(_cnf)
    # ---- secrets (WS2 parity: pipeline yang sama dengan APK/web —
    # validator struktural + konteks + baseline; identifier bukan secret)
    _identifiers = []
    _units = []
    for _s in exe_strings:
        if _secret_candidate(_s):
            _units.append({"text": _s, "location": exe_name or "executable",
                           "config_style": False, "tier": "T0",
                           "owner": "app", "usage": "none", "where": "",
                           "shipped": True})
    for _fn, _txt in file_units:
        _units.append({"text": _txt, "location": _fn, "config_style": True,
                       "tier": "T1", "owner": "app", "usage": "config",
                       "where": "", "shipped": True})
    _scan_secrets_mobile(_units, baseline_map, add, _identifiers)
    if _identifiers:
        _bk = {}
        for _k, _v, _l in _identifiers:
            _bk.setdefault(_k, []).append((_v, _l))
        _parts = [f"{k} x{len(v)} (e.g. {_mask(v[0][0])} in {v[0][1]})"
                  for k, v in sorted(_bk.items())]
        _idf = F("INFO", "Client identifiers embedded in the app (not credentials)",
                 'Google/Firebase API keys (AIza…) and AWS Cognito identity pool IDs are client identifiers BY DESIGN: they identify the app/project to the provider, they are not credentials, and their presence alone is not a leak. Firebase data security depends entirely on the database security rules. They are listed here so they are never mistaken for exposed secrets.',
                 evidence="; ".join(_parts), cwe="CWE-200",
                 owasp="MASVS-STORAGE", cvss=0.0,
                 remed='No rotation needed for the identifiers themselves; audit the Firebase/Cognito security rules and API-key restrictions instead.',
                 confidence="confirmed", location="executable/assets")
        _tag(_idf, "T1", "app")
        add(_idf)
    gs = app_prefix + "GoogleService-Info.plist"
    if gs in names:
        try:
            g = plistlib.loads(zf.read(gs))
        except Exception:
            g = {}
        dburl = g.get("DATABASE_URL") or ""
        if dburl:
            _gff = F("LOW", 'Firebase database URL exposed in the IPA',
                     'The Realtime Database/Firestore URL is exposed (normal for client configuration) — security depends entirely on the security rules; open rules = public data leak.',
                     evidence=str(dburl)[:140], cwe="CWE-200", owasp="MASVS-STORAGE",
                     cvss=3.1, remed='Audit the Firebase security rules: ensure there is no public read/write without authentication.',
                     confidence="candidate", location="GoogleService-Info.plist")
            _tag(_gff, "T1", "app")
            add(_gff)
    if http_hosts:
        _hf2 = F("MEDIUM", f"HTTP endpoint (unencrypted) found: {len(http_hosts)} host",
                 'The IPA contains http:// URLs to real hosts. If actually called at runtime, the traffic (including tokens) can be intercepted on the network.',
                 evidence=", ".join(sorted(http_hosts)[:8]), cwe="CWE-319",
                 owasp="MASVS-NETWORK", cvss=5.3,
                 remed='Migrate all endpoints to https and enable HSTS on the server side.',
                 confidence="probable", location="executable/assets")
        _tag(_hf2, "T0", "app")
        add(_hf2)
    # ---- WS8 tambahan: versi OS minimum, keluasan privasi, konstanta
    # keychain, indikator jailbreak/anti-debug (INFO; keberadaan saja)
    try:
        _min_os_f = float(".".join((min_os or "0").split(".")[:2]))
    except Exception:
        _min_os_f = 0
    if _min_os_f and _min_os_f < 12:
        _mf2 = F("LOW", f"App supports very old iOS versions (MinimumOSVersion {min_os})",
                 'Devices on iOS versions this old no longer receive security updates and lack modern platform protections (including current ATS/TLS defaults).',
                 evidence=f"MinimumOSVersion={min_os}", cwe="CWE-1104",
                 owasp="MASVS-CODE", cvss=3.1,
                 remed='Raise the minimum deployment target to a supported iOS release.',
                 confidence="candidate", location=IP)
        _tag(_mf2, "T1", "app")
        add(_mf2)
    _weak_kc = [s for s in exe_strings
                if "kSecAttrAccessibleAlways" in s
                or "kSecAttrAccessibleAfterFirstUnlock" in s]
    if _weak_kc:
        _kf2 = F("LOW", "Weak keychain accessibility constant referenced",
                 'The binary references a permissive keychain accessibility class (Always / AfterFirstUnlock, including ThisDeviceOnly variants being the safer form). Whether items are actually stored with it cannot be determined statically — the constant is reported as a lead.',
                 evidence="; ".join(sorted(set(_weak_kc))[:4]),
                 cwe="CWE-311", owasp="MASVS-STORAGE", cvss=3.7,
                 remed='Store sensitive items with kSecAttrAccessibleWhenUnlockedThisDeviceOnly.',
                 confidence="candidate", location=exe_name or "Mach-O")
        _tag(_kf2, "T0", "app")
        add(_kf2)
    _jb = [s for s in exe_strings
           if "/Applications/Cydia.app" in s or "cydia://" in s
           or "/var/jb/" in s or "/usr/sbin/frida-server" in s]
    if _jb:
        _jf = F("INFO", "Jailbreak / instrumentation detection indicators present (presence is not effectiveness)",
                'Paths associated with jailbreak or instrumentation detection are present in the binary. This records PRESENCE only — enforcement quality cannot be judged statically.',
                evidence="; ".join(sorted(set(_jb))[:5]),
                cwe="CWE-200", owasp="MASVS-RESILIENCE", cvss=0.0,
                remed='No action required — verify enforcement dynamically if it is part of the security model.',
                confidence="candidate", location=exe_name or "Mach-O")
        _tag(_jf, "T0", "app")
        add(_jf)

    _priv_keys = sorted(k for k in info.keys() if k.endswith("UsageDescription"))
    if len(_priv_keys) >= 4:
        _pf3 = F("INFO", f"Broad privacy-sensitive capability declarations ({len(_priv_keys)} usage descriptions)",
                 'The app declares usage descriptions for many sensitive capabilities. Each declared capability is attack/privacy surface; the breadth is recorded so unused declarations can be pruned (App Store review also rejects unused ones).',
                 evidence=", ".join(_priv_keys[:10]), cwe="CWE-276",
                 owasp="MASVS-PRIVACY", cvss=0.0,
                 remed='Remove usage descriptions for capabilities the app does not actually use.',
                 confidence="candidate", location=IP)
        _tag(_pf3, "T1", "app")
        add(_pf3)
    # pinning iOS: kehadiran dinilai dari string SDK pinning pada binary
    # yang TERBACA; cryptid=1 = tidak dievaluasi (None), bukan "tidak ada"
    if encrypted:
        pinning_detected_ios = None
    else:
        pinning_detected_ios = any(
            ("TrustKit" in s or "TSKPinning" in s or "CertificatePinning" in s)
            for s in exe_strings)
    objc = _objc_inventory(mf) if (mf and not encrypted) else None
    fw_detail = []
    for _n in names:
        _fm = re.match(re.escape(app_prefix) + r"Frameworks/([^/]+)\.framework/([^/]+)$", _n)
        if _fm and _fm.group(1) == _fm.group(2) and len(fw_detail) < 20:
            try:
                _mi = _macho_info(zf.read(_n))
                fw_detail.append({"name": _fm.group(1), "archs": _mi["archs"],
                                  "pie": _mi["pie"], "cryptid": _mi["cryptid"]})
            except Exception:
                pass
    summary = {}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    risk = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if summary.get(s)), "CLEAN")
    score = risk_score(findings)
    _finalize_tags(findings)
    privacy = _priv_keys
    _nsv_ios = ["Runtime behavior and the actual network traffic (dynamic "
                "analysis only)",
                "Server-side authorization and business logic",
                "Keychain accessibility classes actually applied at "
                "runtime (not statically determinable unless an explicit "
                "constant is referenced)",
                "Whether any embedded credential is still active (never "
                "validated against its provider, decision D5)"]
    if encrypted:
        _nsv_ios.append("All executable string/code checks — the main "
                        "binary is FairPlay-encrypted (cryptid=1)")
    elif objc is None:
        _nsv_ios.append("ObjC class/method inventory — the metadata layout "
                        "could not be followed (possibly chained fixups / "
                        "Swift-only binary); Swift coverage is partial")
    coverage = {
        "engine": "vanthex-mobile-deep/1.13.0", "platform": "ios",
        "executable": exe_name, "archs": macho["archs"],
        "filetype": (mf or {}).get("filetype", ""),
        "fairplay_encrypted": encrypted,
        "code_signature_present": bool((mf or {}).get("has_code_signature")),
        "entitlements_claimed": claimed_ent is not None,
        "entitlements_profile": bool(prov and not prov.get("parse_error")),
        "objc_inventory": ({"classes": objc["classes"],
                            "methods": objc["methods"]} if objc else None),
        "ats": {"override_keys": _override_keys,
                "exception_domains": ats_exception_domains},
        "pinning_detected": pinning_detected_ios,
        "pinning_evaluated": not encrypted,
        "frameworks_detailed": len(fw_detail),
        "pool_truncated": pool_truncated,
        "not_statically_verifiable": _nsv_ios}
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
    meta = {"platform": "ios", "contents": contents, "coverage": coverage,
            "decompile": {"plists": plists_dec,
                          "objc": objc,
                          "macho": {"filetype": (mf or {}).get("filetype", ""),
                                    "rpaths": (mf or {}).get("rpaths", []),
                                    "has_code_signature": bool((mf or {}).get("has_code_signature"))},
                          "frameworks_detail": fw_detail,
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
            "pinning_detected": pinning_detected_ios,
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


def analyze_package(path, filename="app.apk", log=None, baseline=None):
    """Dispatcher format: APK (AndroidManifest/DEX) atau IPA (Payload/*.app)."""
    try:
        zf = zipfile.ZipFile(path)
        names = zf.namelist()
        zf.close()
    except Exception:
        raise ValueError("Not a valid package (not a ZIP archive)")
    if any(n == "AndroidManifest.xml" for n in names) or \
            any(re.fullmatch(r"classes\d*\.dex", n.rsplit("/", 1)[-1]) for n in names):
        return analyze_apk(path, filename, log=log, baseline=baseline)
    if any(n.startswith("Payload/") and ".app/" in n for n in names):
        return analyze_ipa(path, filename, log=log, baseline=baseline)
    raise ValueError("Unrecognized package: neither an Android APK nor an iOS IPA "
                     "structure was found")
