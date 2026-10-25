"""v1.9.0 Mobile Deep — hermetic fixture tests.

A planted-vulnerable synthetic app vs a clean app loaded with
false-positive traps (Firebase AIza identifier, sensitive APIs only in
library code, unreachable dead code, pinning via code instead of NSC,
a TrustManager that is defined but never installed, a single safe
WebView flag). Expected tiers are stated explicitly per fixture; traps
must never fire above a labelled candidate.

DEX fixtures are assembled in-test by a minimal hand-rolled DEX builder
(no decompiler/toolchain is invoked — the same self-built rule as the
engine). APKs reuse the repo's TestActivity.apk as the manifest/signature
template and replace classes.dex with the fixture DEX.
"""
import hashlib
import io
import plistlib
import struct
import zipfile
import zlib

import pytest

import mobile
from secretpatterns import make_github_token

FIX = "tests/fixtures/TestActivity.apk"
APP = "Ltests/androguard/"  # TestActivity.apk package = tests.androguard


# ---------------------------------------------------------- DEX assembler
def _uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _sh(p):
    return "L" if p.startswith(("L", "[")) else p


class DexBuilder:
    def __init__(self):
        self._strset = set()
        self._types = set()
        self._protos = {}
        self._methods = {}
        self.classes = []

    def S(self, s):
        self._strset.add(s)
        return s

    def T(self, d):
        self.S(d)
        self._types.add(d)
        return d

    def P(self, ret, params=()):
        key = (ret, tuple(params))
        self.S(_sh(ret) + "".join(_sh(p) for p in params))
        self.T(ret)
        for p in params:
            self.T(p)
        self._protos.setdefault(key)
        return key

    def M(self, cls, name, pkey):
        self.T(cls)
        self.S(name)
        self._methods.setdefault((cls, name, pkey))
        return (cls, name, pkey)

    def add_class(self, desc, super_desc="Ljava/lang/Object;", interfaces=(),
                  methods=()):
        self.T(desc)
        self.T(super_desc)
        for i in interfaces:
            self.T(i)
        for (name, pk, af, cf, r, i2, o) in methods:
            self.M(desc, name, pk)
        self.classes.append({"desc": desc, "super": super_desc,
                             "interfaces": tuple(interfaces),
                             "methods": list(methods)})

    def _resolve(self):
        self._strs = sorted(self._strset)
        self.sidx = {s: i for i, s in enumerate(self._strs)}
        self._tys = sorted(self._types, key=lambda t: self.sidx[t])
        self.tidx = {t: i for i, t in enumerate(self._tys)}
        self._prs = sorted(self._protos, key=lambda k: (self.tidx[k[0]], k[0]))
        self.pidx = {k: i for i, k in enumerate(self._prs)}
        self._mtds = sorted(self._methods,
                            key=lambda m: (self.tidx[m[0]], self.sidx[m[1]],
                                           self.pidx[m[2]]))
        self.midx = {m: i for i, m in enumerate(self._mtds)}

    def build(self):
        self._resolve()
        sidx, tidx, pidx, midx = self.sidx, self.tidx, self.pidx, self.midx
        strs, types, protos, methods = self._strs, self._tys, self._prs, self._mtds
        n_str, n_type = len(strs), len(types)
        n_proto, n_meth, n_cls = len(protos), len(methods), len(self.classes)
        data_start = 112 + 4 * n_str + 4 * n_type + 12 * n_proto \
            + 8 * n_meth + 32 * n_cls
        data = bytearray()
        off = data_start

        def align4():
            nonlocal off
            while off % 4:
                data.append(0)
                off += 1

        string_offs = []
        code_off_list, class_data_off_list, typelist_off_list = [], [], []
        for s in strs:
            b = s.encode("utf-8")
            string_offs.append(off)
            chunk = _uleb(len(s)) + b + b"\x00"
            data += chunk
            off += len(chunk)
        typelists = {}

        def typelist_off(params):
            nonlocal off, data
            key = tuple(params)
            if key in typelists:
                return typelists[key]
            align4()
            o = off
            chunk = struct.pack("<I", len(params)) + b"".join(
                struct.pack("<H", tidx[p]) for p in params)
            if len(params) % 2:
                chunk += b"\x00\x00"
            data += chunk
            off += len(chunk)
            typelists[key] = o
            typelist_off_list.append(o)
            return o

        proto_param_offs = {k: (typelist_off(k[1]) if k[1] else 0)
                            for k in protos}
        iface_offs = {}
        for c in self.classes:
            if c["interfaces"]:
                iface_offs[c["desc"]] = typelist_off(c["interfaces"])
        class_defs = []
        pending = []
        for c in sorted(self.classes, key=lambda c: tidx[c["desc"]]):
            code_offs = {}
            for (name, pk, af, cf, regs, ins, outs) in c["methods"]:
                if cf is None:
                    code_offs[(name, pk)] = 0
                    continue
                code = cf(self)
                if len(code) % 4:
                    code += b"\x00\x00"  # trailing nop keeps items contiguous
                align4()
                co = off
                chunk = struct.pack("<HHHHII", regs, ins, outs, 0, 0,
                                    len(code) // 2) + code
                data += chunk
                off += len(chunk)
                code_offs[(name, pk)] = co
                code_off_list.append(co)
            pending.append((c, code_offs))
        for (c, code_offs) in pending:
            def is_direct(m):
                return bool(m[2] & 0x8) or m[0] in ("<init>", "<clinit>")
            dm = sorted([m for m in c["methods"] if is_direct(m)],
                        key=lambda m: midx[(c["desc"], m[0], m[1])])
            vm = sorted([m for m in c["methods"] if not is_direct(m)],
                        key=lambda m: midx[(c["desc"], m[0], m[1])])
            # NO alignment padding here: androguard parses class_data
            # items strictly sequentially from the map offset.
            cdo = off
            body = _uleb(0) + _uleb(0) + _uleb(len(dm)) + _uleb(len(vm))
            prev = 0
            for m in dm:
                mi = midx[(c["desc"], m[0], m[1])]
                body += _uleb(mi - prev) + _uleb(m[2]) \
                    + _uleb(code_offs[(m[0], m[1])])
                prev = mi
            prev = 0
            for m in vm:
                mi = midx[(c["desc"], m[0], m[1])]
                body += _uleb(mi - prev) + _uleb(m[2]) \
                    + _uleb(code_offs[(m[0], m[1])])
                prev = mi
            data += body
            off += len(body)
            class_data_off_list.append(cdo)
            class_defs.append((tidx[c["desc"]], 0x1, tidx[c["super"]],
                               iface_offs.get(c["desc"], 0), 0xFFFFFFFF, 0,
                               cdo, 0))
        hdr = struct.pack(
            "<20I", 0, 112, 0x12345678, 0, 0, 0,
            n_str, 112, n_type, 112 + 4 * n_str,
            n_proto, 112 + 4 * n_str + 4 * n_type,
            0, 0, n_meth, 112 + 4 * n_str + 4 * n_type + 12 * n_proto,
            n_cls, 112 + 4 * n_str + 4 * n_type + 12 * n_proto + 8 * n_meth,
            0, data_start)
        out = bytearray(b"dex\n035\x00" + b"\x00" * 24 + hdr)
        for o in string_offs:
            out += struct.pack("<I", o)
        for t in types:
            out += struct.pack("<I", sidx[t])
        for k in protos:
            out += struct.pack("<IHHI",
                               sidx[_sh(k[0]) + "".join(_sh(p) for p in k[1])],
                               tidx[k[0]], 0, proto_param_offs[k])
        for m in methods:
            out += struct.pack("<HHI", tidx[m[0]], pidx[m[2]], sidx[m[1]])
        for cd in class_defs:
            out += struct.pack("<8I", *cd)
        out += data
        entries = [(0x0000, 1, 0), (0x0001, n_str, 112),
                   (0x0002, n_type, 112 + 4 * n_str),
                   (0x0003, n_proto, 112 + 4 * n_str + 4 * n_type),
                   (0x0005, n_meth, 112 + 4 * n_str + 4 * n_type + 12 * n_proto),
                   (0x0006, n_cls,
                    112 + 4 * n_str + 4 * n_type + 12 * n_proto + 8 * n_meth)]
        if string_offs:
            entries.append((0x2002, len(string_offs), string_offs[0]))
        if typelist_off_list:
            entries.append((0x1001, len(typelist_off_list),
                            typelist_off_list[0]))
        if class_data_off_list:
            entries.append((0x2000, len(class_data_off_list),
                            class_data_off_list[0]))
        if code_off_list:
            entries.append((0x2001, len(code_off_list), code_off_list[0]))
        while len(out) % 4:
            out += b"\x00"
        map_off = len(out)
        entries.append((0x1000, 1, map_off))
        entries.sort(key=lambda e: e[0])
        out += struct.pack("<I", len(entries))
        for (t, sz, o) in entries:
            out += struct.pack("<HHII", t, 0, sz, o)
        struct.pack_into("<I", out, 52, map_off)
        struct.pack_into("<I", out, 32, len(out))
        struct.pack_into("<I", out, 104, len(out) - data_start)
        out[12:32] = hashlib.sha1(bytes(out[32:])).digest()
        struct.pack_into("<I", out, 8, zlib.adler32(bytes(out[12:])))
        return bytes(out)


def _w(*words):
    return b"".join(struct.pack("<H", x & 0xFFFF) for x in words)


def cs(reg, sidx):
    return _w(0x1a | (reg << 8), sidx)


def c4(reg, lit):
    return _w(0x12 | (reg << 8) | ((lit & 0xF) << 12))


def c16(reg, lit):
    return _w(0x13 | (reg << 8), lit)


def rv():
    return _w(0x000e)


def ro(reg):
    return _w(0x11 | (reg << 8))


def mro(reg):
    return _w(0x0c | (reg << 8))


def ni(reg, tidx):
    return _w(0x22 | (reg << 8), tidx)


def inv(kind, regs, midx):
    # DEX format 35c: word0 = op | G<<8 | A<<12 (A = arg count);
    # word2 = C | D<<4 | E<<8 | F<<12 (argument registers in order).
    padded = list(regs) + [0] * (5 - len(regs))
    C, D, E, F, G = padded
    return _w(kind | (G << 8) | (len(regs) << 12), midx,
              C | (D << 4) | (E << 8) | (F << 12))


PUB, PRIV, STATIC = 0x1, 0x2, 0x8
CTOR = 0x10000


def _protos(b):
    return {
        "V": b.P("V"),
        "INIT": b.P("V"),
        "BUNDLE_V": b.P("V", ("Landroid/os/Bundle;",)),
        "SSL_GET": b.P("Ljavax/net/ssl/SSLContext;", ("Ljava/lang/String;",)),
        "SSL_INIT": b.P("V", ("[Ljavax/net/ssl/KeyManager;",
                              "[Ljavax/net/ssl/TrustManager;",
                              "Ljava/security/SecureRandom;")),
        "CHECK": b.P("V", ("[Ljava/security/cert/X509Certificate;",
                           "Ljava/lang/String;")),
        "ISSUERS": b.P("[Ljava/security/cert/X509Certificate;"),
        "CIPHER_GET": b.P("Ljavax/crypto/Cipher;", ("Ljava/lang/String;",)),
        "MD_GET": b.P("Ljava/security/MessageDigest;", ("Ljava/lang/String;",)),
        "GETBYTES": b.P("[B"),
        "SKS_INIT": b.P("V", ("[B", "Ljava/lang/String;")),
        "IV_INIT": b.P("V", ("[B",)),
        "PBE_INIT": b.P("V", ("[C", "[B", "I", "I")),
        "SEED_J": b.P("V", ("J",)),
        "BOOL_V": b.P("V", ("Z",)),
        "ADDJS": b.P("V", ("Ljava/lang/Object;", "Ljava/lang/String;")),
        "GSP": b.P("Landroid/content/SharedPreferences;",
                   ("Ljava/lang/String;", "I")),
        "PIN_ADD": b.P("Lokhttp3/CertificatePinner$Builder;",
                       ("Ljava/lang/String;", "Ljava/lang/String;")),
    }


PIN_STR = "sha256/" + "A" * 43 + "="
GH_TOKEN_USED = make_github_token("A" * 30)
GH_TOKEN_ORPHAN = make_github_token("B" * 30)
AIZA = "AIza" + "C" * 35
COGNITO = "us-east-1:12345678-1234-1234-1234-123456789012"


def _common_methods(b, P):
    b.M("Ljava/lang/Object;", "<init>", P["INIT"])
    b.M("Ljavax/net/ssl/SSLContext;", "getInstance", P["SSL_GET"])
    b.M("Ljavax/net/ssl/SSLContext;", "init", P["SSL_INIT"])
    b.M("Ljavax/crypto/Cipher;", "getInstance", P["CIPHER_GET"])
    b.M("Ljava/security/MessageDigest;", "getInstance", P["MD_GET"])
    b.M("Ljava/lang/String;", "getBytes", P["GETBYTES"])
    b.M("Ljavax/crypto/spec/SecretKeySpec;", "<init>", P["SKS_INIT"])
    b.M("Ljavax/crypto/spec/IvParameterSpec;", "<init>", P["IV_INIT"])
    b.M("Ljavax/crypto/spec/PBEKeySpec;", "<init>", P["PBE_INIT"])
    b.M("Ljava/security/SecureRandom;", "setSeed", P["SEED_J"])
    b.M("Ljava/security/SecureRandom;", "<init>", P["INIT"])
    b.M("Landroid/webkit/WebView;", "setJavaScriptEnabled", P["BOOL_V"])
    b.M("Landroid/webkit/WebView;", "addJavascriptInterface", P["ADDJS"])
    b.M("Landroid/content/Context;", "getSharedPreferences", P["GSP"])
    b.M("Lokhttp3/CertificatePinner$Builder;", "add", P["PIN_ADD"])
    b.M("Lokhttp3/CertificatePinner$Builder;", "<init>", P["INIT"])


def _trustall_class(b, P, cls_name, install=True):
    def _init(bb):
        return inv(0x70, [0], bb.midx[("Ljava/lang/Object;", "<init>",
                                       P["INIT"])]) + rv()

    def _check(bb):
        return rv()

    def _issuers(bb):
        return c4(0, 0) + ro(0)
    b.add_class(cls_name, interfaces=("Ljavax/net/ssl/X509TrustManager;",),
                methods=[("<init>", P["INIT"], PUB | CTOR, _init, 1, 1, 1),
                         ("checkServerTrusted", P["CHECK"], PUB, _check, 3, 3, 0),
                         ("getAcceptedIssuers", P["ISSUERS"], PUB, _issuers,
                          2, 1, 0)])


def _pin_code(b, P):
    def pin(bb):
        return (ni(0, bb.tidx["Lokhttp3/CertificatePinner$Builder;"])
                + inv(0x70, [0], bb.midx[("Lokhttp3/CertificatePinner$Builder;",
                                          "<init>", P["INIT"])])
                + cs(1, bb.sidx["example.com"])
                + cs(2, bb.sidx[PIN_STR])
                + inv(0x6e, [0, 1, 2],
                      bb.midx[("Lokhttp3/CertificatePinner$Builder;", "add",
                               P["PIN_ADD"])])
                + rv())
    return pin


def build_vuln_dex():
    b = DexBuilder()
    P = _protos(b)
    _common_methods(b, P)
    for s in ("TLS", "AES", "AES/ECB/PKCS5Padding", "AES/GCM/NoPadding",
              "DES/ECB/PKCS5Padding", "MD5", "supersecretkey12",
              "1234567890123456", "example.com",
              PIN_STR,
              GH_TOKEN_USED, AIZA, COGNITO, "prefs"):
        b.S(s)
    b.S(GH_TOKEN_ORPHAN)  # string-table only: never referenced by code
    _trustall_class(b, P, APP + "TrustAll;")

    def net_install(bb):
        return (ni(0, bb.tidx[APP + "TrustAll;"])
                + inv(0x70, [0], bb.midx[(APP + "TrustAll;", "<init>", P["INIT"])])
                + cs(1, bb.sidx["TLS"])
                + inv(0x71, [1], bb.midx[("Ljavax/net/ssl/SSLContext;",
                                          "getInstance", P["SSL_GET"])])
                + mro(2)
                + inv(0x6e, [2, 0, 0, 0],
                      bb.midx[("Ljavax/net/ssl/SSLContext;", "init",
                               P["SSL_INIT"])])
                + rv())
    b.add_class(APP + "Net;", methods=[
        ("install", P["V"], PUB | STATIC, net_install, 3, 0, 4),
        ("pin", P["V"], PUB | STATIC, _pin_code(b, P), 3, 0, 3)])

    def crypto_weak(bb):
        return (cs(0, bb.sidx["AES"])
                + inv(0x71, [0], bb.midx[("Ljavax/crypto/Cipher;",
                                          "getInstance", P["CIPHER_GET"])])
                + cs(0, bb.sidx["AES/ECB/PKCS5Padding"])
                + inv(0x71, [0], bb.midx[("Ljavax/crypto/Cipher;",
                                          "getInstance", P["CIPHER_GET"])])
                + cs(0, bb.sidx["MD5"])
                + inv(0x71, [0], bb.midx[("Ljava/security/MessageDigest;",
                                          "getInstance", P["MD_GET"])])
                + cs(0, bb.sidx["supersecretkey12"])
                + inv(0x6e, [0], bb.midx[("Ljava/lang/String;", "getBytes",
                                          P["GETBYTES"])])
                + mro(1)
                + ni(2, bb.tidx["Ljavax/crypto/spec/SecretKeySpec;"])
                + cs(3, bb.sidx["AES"])
                + inv(0x70, [2, 1, 3],
                      bb.midx[("Ljavax/crypto/spec/SecretKeySpec;", "<init>",
                               P["SKS_INIT"])])
                + cs(0, bb.sidx["1234567890123456"])
                + inv(0x6e, [0], bb.midx[("Ljava/lang/String;", "getBytes",
                                          P["GETBYTES"])])
                + mro(1)
                + ni(2, bb.tidx["Ljavax/crypto/spec/IvParameterSpec;"])
                + inv(0x70, [2, 1],
                      bb.midx[("Ljavax/crypto/spec/IvParameterSpec;", "<init>",
                               P["IV_INIT"])])
                + ni(4, bb.tidx["Ljavax/crypto/spec/PBEKeySpec;"])
                + c16(5, 100)
                + c16(6, 128)
                + inv(0x70, [4, 0, 1, 5, 6],
                      bb.midx[("Ljavax/crypto/spec/PBEKeySpec;", "<init>",
                               P["PBE_INIT"])])
                + ni(0, bb.tidx["Ljava/security/SecureRandom;"])
                + inv(0x70, [0], bb.midx[("Ljava/security/SecureRandom;",
                                          "<init>", P["INIT"])])
                + c16(1, 42)
                + inv(0x6e, [0, 1],
                      bb.midx[("Ljava/security/SecureRandom;", "setSeed",
                               P["SEED_J"])])
                + rv())

    def crypto_dead(bb):
        return (cs(0, bb.sidx["DES/ECB/PKCS5Padding"])
                + inv(0x71, [0], bb.midx[("Ljavax/crypto/Cipher;",
                                          "getInstance", P["CIPHER_GET"])])
                + rv())
    b.add_class(APP + "Crypto;", methods=[
        ("weak", P["V"], PUB | STATIC, crypto_weak, 7, 0, 5),
        ("dead", P["V"], PUB | STATIC, crypto_dead, 1, 0, 1)])

    def web_use(bb):
        return (c4(1, 1)
                + inv(0x6e, [0, 1], bb.midx[("Landroid/webkit/WebView;",
                                             "setJavaScriptEnabled",
                                             P["BOOL_V"])])
                + cs(2, bb.sidx["bridge"])
                + inv(0x6e, [0, 0, 2],
                      bb.midx[("Landroid/webkit/WebView;",
                               "addJavascriptInterface", P["ADDJS"])])
                + rv())
    b.S("bridge")
    b.add_class(APP + "Web;", methods=[
        ("useWeb", P["V"], PUB | STATIC, web_use, 3, 0, 3)])

    def prefs_world(bb):
        return (cs(0, bb.sidx["prefs"])
                + c4(1, 1)  # MODE_WORLD_READABLE
                + inv(0x6e, [3, 0, 1],
                      bb.midx[("Landroid/content/Context;",
                               "getSharedPreferences", P["GSP"])])
                + rv())
    b.add_class(APP + "Prefs;", methods=[
        ("world", P["V"], PUB | STATIC, prefs_world, 4, 0, 3)])

    def store_keys(bb):
        return (cs(0, bb.sidx[GH_TOKEN_USED])
                + cs(1, bb.sidx[AIZA])
                + cs(2, bb.sidx[COGNITO])
                + rv())
    b.add_class(APP + "Store;", methods=[
        ("keys", P["V"], PUB | STATIC, store_keys, 3, 0, 1)])

    def sdk_weak(bb):
        return (cs(0, bb.sidx["DES/ECB/PKCS5Padding"])
                + inv(0x71, [0], bb.midx[("Ljavax/crypto/Cipher;",
                                          "getInstance", P["CIPHER_GET"])])
                + rv())
    b.add_class("Lcom/google/android/gms/ads/CryptoSdk;", methods=[
        ("weakSdk", P["V"], PUB | STATIC, sdk_weak, 1, 0, 1)])

    def on_create(bb):
        out = b""
        for cls, mth in (("Net;", "install"), ("Net;", "pin"),
                         ("Crypto;", "weak"), ("Web;", "useWeb"),
                         ("Prefs;", "world"), ("Store;", "keys")):
            out += inv(0x71, [], bb.midx[(APP + cls, mth, P["V"])])
        return out + rv()
    b.add_class(APP + "TestActivity;", super_desc="Landroid/app/Activity;",
                methods=[("onCreate", P["BUNDLE_V"], PUB, on_create, 2, 2, 1)])
    return b.build()


def build_clean_dex():
    b = DexBuilder()
    P = _protos(b)
    _common_methods(b, P)
    for s in ("TLS", "AES/GCM/NoPadding", "SHA-256", "example.com",
              PIN_STR, AIZA):
        b.S(s)
    # TRAP: accept-all TrustManager defined but NEVER installed/instantiated
    _trustall_class(b, P, APP + "LaxTrustManager;")

    def safe_web(bb):
        # TRAP: single safe flag — setJavaScriptEnabled(true) alone
        return (c4(1, 1)
                + inv(0x6e, [0, 1], bb.midx[("Landroid/webkit/WebView;",
                                             "setJavaScriptEnabled",
                                             P["BOOL_V"])])
                + rv())

    def safe_crypto(bb):
        return (cs(0, bb.sidx["AES/GCM/NoPadding"])
                + inv(0x71, [0], bb.midx[("Ljavax/crypto/Cipher;",
                                          "getInstance", P["CIPHER_GET"])])
                + cs(0, bb.sidx["SHA-256"])
                + inv(0x71, [0], bb.midx[("Ljava/security/MessageDigest;",
                                          "getInstance", P["MD_GET"])])
                + rv())

    def safe_misc(bb):
        # identifier string referenced by code — still just an identifier
        return cs(0, bb.sidx[AIZA]) + rv()
    b.add_class(APP + "Safe;", methods=[
        ("web", P["V"], PUB | STATIC, safe_web, 2, 0, 2),
        ("crypto", P["V"], PUB | STATIC, safe_crypto, 1, 0, 1),
        ("misc", P["V"], PUB | STATIC, safe_misc, 1, 0, 1),
        ("pin", P["V"], PUB | STATIC, _pin_code(b, P), 3, 0, 3)])

    def on_create(bb):
        out = b""
        for mth in ("web", "crypto", "misc", "pin"):
            out += inv(0x71, [], bb.midx[(APP + "Safe;", mth, P["V"])])
        return out + rv()
    b.add_class(APP + "TestActivity;", super_desc="Landroid/app/Activity;",
                methods=[("onCreate", P["BUNDLE_V"], PUB, on_create, 2, 2, 1)])
    return b.build()


def make_apk(tmp_path, name, dex_bytes, extra=None):
    src = open(FIX, "rb").read()
    buf = io.BytesIO()
    zin = zipfile.ZipFile(io.BytesIO(src))
    zout = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    for item in zin.infolist():
        if item.filename == "classes.dex":
            continue
        zout.writestr(item, zin.read(item.filename))
    zout.writestr("classes.dex", dex_bytes)
    for k, v in (extra or {}).items():
        zout.writestr(k, v)
    zout.close()
    p = tmp_path / name
    p.write_bytes(buf.getvalue())
    return str(p)


# ---------------------------------------------------------- ELF fixtures
def build_elf(canary=False, nx=True, relro=True, pie=True):
    """Minimal ELF64 AArch64 shared object with the segments/sections the
    WS7 parser reads: PT_LOAD (identity map), PT_DYNAMIC, PT_GNU_STACK,
    optional PT_GNU_RELRO, .dynsym/.dynstr via section headers."""
    dynstr = b"\x00__stack_chk_fail\x00some_func\x00" if canary \
        else b"\x00some_func\x00"
    strtab_off = 0x300
    symtab_off = 0x340
    hash_off = 0x3C0
    dyn_off = 0x200
    nsyms = 3 if canary else 2
    syms = b"\x00" * 24
    if canary:
        syms += struct.pack("<IBBH", 1, 0x12, 0, 0) + b"\x00" * 16
        syms += struct.pack("<IBBH", 18, 0x12, 0, 0) + b"\x00" * 16
    else:
        syms += struct.pack("<IBBH", 1, 0x12, 0, 0) + b"\x00" * 16
    dyn = b""
    dyn += struct.pack("<qQ", 4, hash_off)        # DT_HASH
    dyn += struct.pack("<qQ", 6, symtab_off)      # DT_SYMTAB
    dyn += struct.pack("<qQ", 5, strtab_off)      # DT_STRTAB
    dyn += struct.pack("<qQ", 10, len(dynstr))    # DT_STRSZ
    dyn += struct.pack("<qQ", 11, 24)             # DT_SYMENT
    if relro:
        dyn += struct.pack("<qQ", 30, 0x8)        # DT_FLAGS BIND_NOW
    dyn += struct.pack("<qQ", 0, 0)
    phdrs = []
    phdrs.append((1, 5, 0, 0, 0, 0x500, 0x500, 0x1000))          # PT_LOAD
    phdrs.append((2, 4, dyn_off, dyn_off, dyn_off, len(dyn),
                  len(dyn), 8))                                    # PT_DYNAMIC
    phdrs.append((0x6474E551, 6 if nx else 7, 0, 0, 0, 0, 0, 16))  # GNU_STACK
    if relro:
        phdrs.append((0x6474E552, 4, 0, 0, 0, 0x100, 0x100, 1))   # GNU_RELRO
    ehsize, phentsize = 64, 56
    shoff = 0x400
    data = bytearray(b"\x00" * 0x500)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = ident + struct.pack("<HHIQQQIHHHHHH", 3 if pie else 2, 183, 1,
                                0, ehsize, shoff, 0, ehsize, phentsize,
                                len(phdrs), 64, 3, 0)
    data[0:64] = ehdr
    for i, ph in enumerate(phdrs):
        data[ehsize + i * phentsize: ehsize + (i + 1) * phentsize] = \
            struct.pack("<IIQQQQQQ", *ph)
    data[dyn_off:dyn_off + len(dyn)] = dyn
    data[strtab_off:strtab_off + len(dynstr)] = dynstr
    data[symtab_off:symtab_off + len(syms)] = syms
    data[hash_off:hash_off + 8] = struct.pack("<II", 1, nsyms)
    sh = b"\x00" * 64
    sh += struct.pack("<IIQQQQIIQQ", 0, 11, 0, symtab_off, symtab_off,
                      len(syms), 2, 1, 8, 24)          # .dynsym (link=2)
    sh += struct.pack("<IIQQQQIIQQ", 0, 3, 0, strtab_off, strtab_off,
                      len(dynstr), 0, 0, 1, 0)         # .dynstr
    data[shoff:shoff + len(sh)] = sh
    return bytes(data)


# ---------------------------------------------------------- Mach-O fixtures
def build_macho(cryptid=0, entitlements=None, rpath=None, objc=False,
                body_strings=b""):
    """Thin arm64 Mach-O with LC_SEGMENT_64 (+ optional __objc_classlist
    section), LC_ENCRYPTION_INFO_64, optional LC_RPATH and an optional
    LC_CODE_SIGNATURE superblob carrying XML entitlements."""
    BASE = 0x100000000
    cmds = []
    seg_cmdsize = 72 + (160 if objc else 0)
    cmds_meta = []  # (cmd, cmdsize, payload_fn)
    blobs = bytearray()
    blob_base = 32  # after header; commands appended first, sized below
    # We compute layout iteratively: header(32) + cmds, then blobs.
    ncmds = 1 + 1 + (1 if rpath else 0) + (1 if entitlements else 0)
    rp = (rpath.encode() + b"\x00") if rpath else b""
    rp_size = (12 + len(rp) + 7) // 8 * 8 if rpath else 0
    cs_size = 16
    sizeofcmds = seg_cmdsize + 24 + rp_size + (cs_size if entitlements else 0)
    blob_off = 32 + sizeofcmds
    objc_blob = b""
    cs_off = 0
    if objc:
        name = b"FixtureViewController\x00"
        sel1 = b"viewDidLoad\x00"
        sel2 = b"loadData\x00"
        # offsets (relative to blob_off)
        o_list = 0
        o_cls = 8
        o_ro = 48
        o_mlist = 88
        o_name = 88 + 8 + 48
        o_sel1 = o_name + len(name)
        o_sel2 = o_sel1 + len(sel1)
        objc_blob = bytearray(o_sel2 + len(sel2))
        struct.pack_into("<Q", objc_blob, o_list, BASE + blob_off + o_cls)
        struct.pack_into("<Q", objc_blob, o_cls + 32, BASE + blob_off + o_ro)
        struct.pack_into("<Q", objc_blob, o_ro + 24, BASE + blob_off + o_name)
        struct.pack_into("<Q", objc_blob, o_ro + 32,
                         BASE + blob_off + o_mlist)
        struct.pack_into("<II", objc_blob, o_mlist, 24, 2)
        struct.pack_into("<Q", objc_blob, o_mlist + 8,
                         BASE + blob_off + o_sel1)
        struct.pack_into("<Q", objc_blob, o_mlist + 8 + 24,
                         BASE + blob_off + o_sel2)
        objc_blob[o_name:o_name + len(name)] = name
        objc_blob[o_sel1:o_sel1 + len(sel1)] = sel1
        objc_blob[o_sel2:o_sel2 + len(sel2)] = sel2
    blobs += objc_blob
    blobs += body_strings
    if entitlements is not None:
        while (blob_off + len(blobs)) % 4:
            blobs += b"\x00"
        cs_off = blob_off + len(blobs)
        xml = plistlib.dumps(entitlements, fmt=plistlib.FMT_XML)
        blob = struct.pack(">II", 0xFADE7171, 8 + len(xml)) + xml
        total = 12 + 8 + len(blob)
        superblob = struct.pack(">III", 0xFADE0CC0, total, 1) \
            + struct.pack(">II", 5, 20) + blob
        assert len(superblob) == total, (len(superblob), total)
        blobs += superblob
        cs_datasize = len(superblob)
    else:
        cs_datasize = 0
    total_size = blob_off + len(blobs)
    out = bytearray()
    out += struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, ncmds,
                       sizeofcmds, 0x200000, 0)
    seg = struct.pack("<II16sQQQQiiII", 0x19, seg_cmdsize, b"__DATA_CONST",
                      BASE, 0x1000, 0, total_size, 3, 3, 2 if objc else 0, 0)
    if objc:
        seg += struct.pack("<16s16sQQIIIIIIII", b"__objc_classlist",
                           b"__DATA_CONST", BASE + blob_off, 8, blob_off,
                           3, 0, 0, 0, 0, 0, 0)
        seg += struct.pack("<16s16sQQIIIIIIII", b"__objc_data",
                           b"__DATA_CONST", BASE + blob_off + 8,
                           len(objc_blob) - 8, blob_off + 8,
                           3, 0, 0, 0, 0, 0, 0)
    out += seg
    out += struct.pack("<IIIIII", 0x2C, 24, 0, 0, cryptid, 0)
    if rpath:
        cmd = struct.pack("<III", 0x8000001C, rp_size, 12) + rp
        cmd += b"\x00" * (rp_size - len(cmd))
        out += cmd
    if entitlements is not None:
        out += struct.pack("<IIII", 0x1D, 16, cs_off, cs_datasize)
    out += blobs
    return bytes(out)


def make_ipa(tmp_path, name, exe_bytes, info, prov=None):
    files = {
        "Payload/Fixture.app/Info.plist":
            plistlib.dumps(info, fmt=plistlib.FMT_BINARY),
        "Payload/Fixture.app/FixtureApp": exe_bytes,
        "Payload/Fixture.app/_CodeSignature/CodeResources": b"sig",
    }
    if prov is not None:
        xml = plistlib.dumps(prov, fmt=plistlib.FMT_XML)
        files["Payload/Fixture.app/embedded.mobileprovision"] = \
            b"\x30\x82junk" + xml + b"junk"
    p = tmp_path / name
    with zipfile.ZipFile(p, "w") as z:
        for k, v in files.items():
            z.writestr(k, v)
    return str(p)


def find(res, frag):
    return [f for f in res["findings"] if frag in f["title"]]


@pytest.fixture(scope="module")
def vuln_apk(tmp_path_factory):
    d = tmp_path_factory.mktemp("v190")
    return make_apk(d, "vuln.apk", build_vuln_dex())


@pytest.fixture(scope="module")
def vuln_res(vuln_apk):
    return mobile.analyze_apk(vuln_apk, "vuln.apk")


# ------------------------------------------------------------- APK verdicts
def test_vuln_trustmanager_installed_is_confirmed(vuln_res):
    tm = find(vuln_res, "TrustManager that accepts all certificates")
    assert len(tm) == 1
    assert tm[0]["confidence"] == "confirmed"
    assert tm[0]["severity"] == "HIGH"
    assert tm[0]["evidence"].startswith("[T2 · owner=app]")
    assert "installed into the TLS stack" in tm[0]["evidence"]


def test_vuln_crypto_buckets_and_tiers(vuln_res):
    ecb = find(vuln_res, "ECB cipher mode used in code")
    by_conf = {f["confidence"]: f for f in ecb}
    assert by_conf["probable"]["evidence"].startswith("[T2 · owner=app]")
    cand = [f for f in ecb if f["confidence"] == "candidate"]
    assert any("library code — demoted to candidate per policy K4"
               in f["evidence"] for f in cand)
    assert any("no caller found in the call graph" in f["evidence"]
               for f in cand)
    for frag in ("Hard-coded cryptographic key", "Constant IV",
                 "Weak password-based encryption", "SecureRandom seeded",
                 "Weak hash (MD5/SHA-1)"):
        hits = find(vuln_res, frag)
        assert hits and hits[0]["confidence"] == "probable", frag


def test_vuln_storage_and_webview(vuln_res):
    mw = find(vuln_res, "MODE_WORLD")
    assert mw and mw[0]["confidence"] == "probable"
    bridge = find(vuln_res, "JavaScript bridge enabled together")
    assert bridge and bridge[0]["confidence"] == "probable" \
        and bridge[0]["severity"] == "HIGH"


def test_vuln_coverage_and_pinning(vuln_res):
    cov = vuln_res["meta"]["coverage"]
    assert cov["code_evidence"].startswith("full")
    assert cov["classes_total"] >= 8
    assert cov["pinning"]["code_pinning"] is True
    assert vuln_res["meta"]["pinning_detected"] is True
    assert cov["not_statically_verifiable"]


def test_vuln_secrets_tiers_and_identifiers(vuln_res):
    gh = find(vuln_res, "GitHub")
    prob = [f for f in gh if f["confidence"] == "probable"]
    cand = [f for f in gh if f["confidence"] == "candidate"]
    assert len(prob) == 1 and "checksum (CRC32) verified" in prob[0]["evidence"]
    assert len(cand) == 1 and "string-table match only (T0)" in cand[0]["evidence"]
    ids = find(vuln_res, "Client identifiers embedded")
    assert len(ids) == 1 and ids[0]["severity"] == "INFO"
    assert "Google/Firebase API key x1" in ids[0]["evidence"]
    assert "Cognito identity pool ID x1" in ids[0]["evidence"]
    non_info = [f for f in vuln_res["findings"]
                if f["severity"] != "INFO" and "AIza" in f["evidence"]]
    assert not non_info


def test_vuln_baseline_suppression(vuln_apk):
    h = hashlib.sha256(GH_TOKEN_USED.encode()).hexdigest()
    r = mobile.analyze_apk(vuln_apk, "vuln.apk",
                           baseline=[{"hash": h, "label": "fixture",
                                      "reason": "hermetic test"}])
    gh = [f for f in find(r, "GitHub") if f["confidence"] == "probable"]
    assert gh and gh[0].get("baseline_suppressed", {}).get("label") == "fixture"


def test_sandbox_baseline_roundtrip(vuln_apk):
    import sandbox
    h = hashlib.sha256(GH_TOKEN_USED.encode()).hexdigest()
    r = sandbox.analyze_package_sandboxed(
        vuln_apk, "vuln.apk",
        baseline=[{"hash": h, "label": "fixture", "reason": "sandbox test"}])
    gh = [f for f in find(r, "GitHub") if f["confidence"] == "probable"]
    assert gh and gh[0].get("baseline_suppressed")
    assert r["meta"]["coverage"]["code_evidence"].startswith("full")


# ------------------------------------------------------------- clean traps
@pytest.fixture(scope="module")
def clean_res(tmp_path_factory):
    d = tmp_path_factory.mktemp("v190c")
    p = make_apk(d, "clean.apk", build_clean_dex())
    return mobile.analyze_apk(p, "clean.apk")


def test_clean_traps_never_above_candidate(clean_res):
    tm = find(clean_res, "TrustManager that accepts all certificates")
    assert tm and all(f["confidence"] == "candidate" for f in tm)
    assert "never installed" in tm[0]["evidence"]
    assert not find(clean_res, "JavaScript bridge enabled together")
    assert not find(clean_res, "ECB cipher mode")
    assert not find(clean_res, "Weak hash (MD5/SHA-1)")
    assert not find(clean_res, "MODE_WORLD")
    hot = [f for f in clean_res["findings"]
           if f["confidence"] in ("confirmed", "probable")
           and any(k in f["title"] for k in ("TrustManager", "ECB", "bridge",
                                             "MODE_WORLD", "Constant IV",
                                             "cryptographic key"))]
    assert not hot


def test_clean_identifiers_and_code_pinning(clean_res):
    ids = find(clean_res, "Client identifiers embedded")
    assert len(ids) == 1
    assert clean_res["meta"]["pinning_detected"] is True
    assert clean_res["meta"]["coverage"]["pinning"]["code_pinning"] is True


# ------------------------------------------------------------- unit: NSC
def test_nsc_semantics():
    from defusedxml import ElementTree as ET
    xml = """<network-security-config
      xmlns:android="http://schemas.android.com/apk/res/android">
      <base-config cleartextTrafficPermitted="false">
        <trust-anchors><certificates src="system"/></trust-anchors>
      </base-config>
      <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">api.example.com</domain>
        <trust-anchors><certificates src="user"/></trust-anchors>
      </domain-config>
      <domain-config>
        <domain>pay.example.com</domain>
        <pin-set expiration="2020-01-01"><pin digest="SHA-256">AAAA</pin></pin-set>
      </domain-config>
      <debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides>
    </network-security-config>"""
    r = mobile._nsc_from_root(ET.fromstring(xml))
    assert r["parsed"] is True
    assert r["base_cleartext"] is False           # domain grant is NOT global
    assert r["domain_cleartext"] == ["api.example.com"]
    assert r["user_ca"] == ["api.example.com"]     # debug-overrides excluded
    assert r["pinsets"][0]["expiration"] == "2020-01-01"
    assert r["debug_overrides"] is True


# ------------------------------------------------------- unit: components
def test_components_protection_levels():
    from defusedxml import ElementTree as ET
    NSD = 'xmlns:android="http://schemas.android.com/apk/res/android"'
    xml = f"""<manifest {NSD}>
      <permission android:name="com.example.SIG" android:protectionLevel="signature"/>
      <permission android:name="com.example.NORM" android:protectionLevel="normal"/>
      <application>
        <activity android:name=".A" android:exported="true" android:permission="com.example.SIG"/>
        <activity android:name=".B" android:exported="true" android:permission="com.example.NORM"/>
        <service android:name=".C" android:exported="true" android:permission="com.example.UNDECLARED"/>
        <provider android:name=".D" android:exported="true"
                  android:readPermission="com.example.SIG"
                  android:writePermission="com.example.NORM"/>
        <activity android:name=".E" android:exported="true">
          <intent-filter android:autoVerify="true">
            <action android:name="android.intent.action.VIEW"/>
            <data android:scheme="https"/>
            <data android:host="a.example.com"/>
          </intent-filter>
        </activity>
      </application>
    </manifest>"""
    comps, _app = mobile._components(ET.fromstring(xml), 34)
    by = {c["name"]: c for c in comps}
    assert by[".A"]["guarded"] is True and by[".A"]["protection"] == "signature"
    # the pre-1.9.0 bug: a permission attribute alone counted as protection
    assert by[".B"]["guarded"] is False and by[".B"]["protection"] == "normal"
    assert by[".C"]["guarded"] is False and by[".C"]["protection"] == "normal"
    # provider verdict follows the WEAKEST applicable guard (write=normal)
    assert by[".D"]["guarded"] is False
    # <data> elements cross-merge inside one intent-filter + autoVerify flag
    assert ("https", "a.example.com") in by[".E"]["deeplinks"]
    assert by[".E"]["autoverify"] is True


# ------------------------------------------------------------- unit: ELF
def test_elf_info_facts():
    good = mobile._elf_info(build_elf(canary=True, nx=True, relro=True))
    assert good["pie"] is True and good["nx"] is True
    assert good["relro"] == "full" and good["canary"] is True
    bad = mobile._elf_info(build_elf(canary=False, nx=False, relro=False))
    assert bad["pie"] is True and bad["nx"] is False
    assert bad["relro"] == "absent" and bad["canary"] is False


def test_apk_native_lib_findings(tmp_path):
    p = make_apk(tmp_path, "elf.apk", build_clean_dex(), extra={
        "lib/arm64-v8a/libbad.so": build_elf(canary=False, nx=False,
                                             relro=False),
        "lib/arm64-v8a/libgood.so": build_elf(canary=True, nx=True,
                                              relro=True)})
    r = mobile.analyze_apk(p, "elf.apk")
    nx = find(r, "executable stack")
    assert nx and nx[0]["confidence"] == "probable"
    elf_findings = [f for f in r["findings"]
                    if "Native librar" in f["title"]]
    assert elf_findings
    assert all("libgood.so" not in f["evidence"] for f in elf_findings)
    assert any("libbad.so" in f["evidence"] for f in elf_findings)
    rows = {x["name"]: x for x in r["meta"]["coverage"]["native_libs"]}
    assert rows["lib/arm64-v8a/libgood.so"]["canary"] is True
    assert rows["lib/arm64-v8a/libbad.so"]["relro"] == "absent"


# ------------------------------------------------------------- IPA (WS8)
def _ipa_info(**kw):
    info = {"CFBundleIdentifier": "com.example.app",
            "CFBundleExecutable": "FixtureApp",
            "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1",
            "MinimumOSVersion": "13.0"}
    info.update(kw)
    return info


def _ipa_prov(entitlements):
    return {"Name": "Fixture Profile", "TeamName": "Example Team",
            "AppIDName": "Fixture App",
            "Entitlements": entitlements}


def test_ipa_ats_override_precedence(tmp_path):
    exe = build_macho(cryptid=0, body_strings=b"__stack_chk_guard\x00")
    info = _ipa_info(NSAppTransportSecurity={
        "NSAllowsArbitraryLoads": True,
        "NSAllowsArbitraryLoadsInWebContent": True})
    p = make_ipa(tmp_path, "ats.ipa", exe, info)
    r = mobile.analyze_ipa(p, "ats.ipa")
    assert not find(r, "Cleartext traffic allowed for all domains")
    ov = find(r, "override keys take precedence")
    assert len(ov) == 1 and ov[0]["confidence"] == "probable"
    assert r["meta"]["coverage"]["ats"]["override_keys"] == [
        "NSAllowsArbitraryLoadsInWebContent"]


def test_ipa_entitlement_mismatch(tmp_path):
    claimed = {"application-identifier": "TEAMID.com.example.other",
               "keychain-access-groups": ["TEAMID.com.example.other"]}
    allowed = {"application-identifier": "TEAMID.com.example.app",
               "keychain-access-groups": ["TEAMID.com.example.app"],
               "get-task-allow": False}
    exe = build_macho(cryptid=0, entitlements=claimed,
                      body_strings=b"__stack_chk_guard\x00")
    p = make_ipa(tmp_path, "ent.ipa", exe, _ipa_info(),
                 prov=_ipa_prov(allowed))
    r = mobile.analyze_ipa(p, "ent.ipa")
    mm = find(r, "claims entitlements beyond the provisioning profile")
    assert len(mm) == 1 and mm[0]["confidence"] == "probable"
    assert "application-identifier" in mm[0]["evidence"]
    assert "keychain-access-groups" in mm[0]["evidence"]
    cov = r["meta"]["coverage"]
    assert cov["entitlements_claimed"] is True
    assert cov["entitlements_profile"] is True
    # cryptid=0 and no pinning SDK strings: pinning was EVALUATED -> False
    assert r["meta"]["pinning_detected"] is False
    assert cov["pinning_evaluated"] is True


def test_ipa_encrypted_pinning_not_evaluated(tmp_path):
    exe = build_macho(cryptid=1,
                      body_strings=b"AKIAIOSFODNN7EXAMPLE\x00"
                                   b"__stack_chk_guard\x00")
    p = make_ipa(tmp_path, "enc.ipa", exe, _ipa_info())
    r = mobile.analyze_ipa(p, "enc.ipa")
    assert len(find(r, "FairPlay-encrypted")) == 1
    assert r["meta"]["pinning_detected"] is None  # NOT a claim of absence
    assert r["meta"]["coverage"]["pinning_evaluated"] is False
    assert not find(r, "AWS Access Key")  # encrypted strings are not read


def test_ipa_objc_inventory_rpath_keychain_min_os(tmp_path):
    exe = build_macho(cryptid=0, objc=True, rpath="/tmp/evil",
                      body_strings=b"__stack_chk_guard\x00"
                                   b"kSecAttrAccessibleAlways\x00")
    p = make_ipa(tmp_path, "objc.ipa", exe,
                 _ipa_info(MinimumOSVersion="11.0"))
    r = mobile.analyze_ipa(p, "objc.ipa")
    objc = r["meta"]["decompile"]["objc"]
    assert objc is not None
    assert objc["classes"] == 1 and objc["methods"] == 2
    assert "FixtureViewController" in objc["class_names"]
    assert "viewDidLoad" in objc["selectors_sample"]
    assert r["meta"]["coverage"]["objc_inventory"] == {"classes": 1,
                                                        "methods": 2}
    rp = find(r, "suspicious runpath")
    assert rp and rp[0]["confidence"] == "candidate"
    kc = find(r, "Weak keychain accessibility")
    assert kc and kc[0]["confidence"] == "candidate"
    mo = find(r, "very old iOS versions")
    assert mo and mo[0]["confidence"] == "candidate"
    # every finding carries the tier/owner evidence label
    assert all(f["evidence"].startswith("[T") for f in r["findings"])
