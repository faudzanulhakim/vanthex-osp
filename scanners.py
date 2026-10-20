"""
Pentest Toolkit - scanner modules (for AUTHORIZED testing only).
Standard library only.

Upgrade v3:
- tcp_scan kini mengirim PROBE per jenis port (HTTP HEAD untuk port web, CRLF generik
  untuk service lain) sebelum membaca banner — banner tidak lagi kosong untuk
  service yang menunggu request lebih dulu.
- Port umum diperluas (Docker, Elasticsearch, etcd, kubelet, Kibana, RabbitMQ-mgmt, dll).
- ssl_audit ditulis ulang: deteksi TLSv1.0/1.1/1.2 dengan handshake ter-pin yang benar
  (loop mati di versi lama dibuang), + hasil verifikasi sertifikat standar
  (self-signed/expired/hostname mismatch masuk verify_error), cipher bits, not_before.
"""
import socket
import time
import ssl
import http.client
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
                8888, 9090, 27017, 27018, 11211,
                # tambahan v3: API service & dashboard yang sering bocor
                2375, 2376, 2379, 5601, 6443, 8009, 8086, 9000, 9200, 9300,
                10250, 15672, 5000, 7001,
                # tambahan enterprise: DB enterprise, direktori, manajemen Windows
                389, 636, 1433, 1521, 2049, 4848, 5985, 5986]

_HTTP_PORTS = {80, 443, 5000, 7001, 8009, 8080, 8443, 8888, 9000, 9090,
               5601, 9200, 2375, 2379, 10250, 15672, 8086}


# ------------------------------------------------------------ verifikasi layanan (v3.2.2)
# Pelajaran insiden FP 2026-10-16: TCP connect sukses + banner APA PUN bukan bukti
# layanan. Di jaringan dengan interceptor/tarpit (mis. gateway sandbox yang menjawab
# SEMUA port dengan teks pemberitahuan), scanner lama melaporkan 27 port "confirmed"
# yang tidak pernah mencapai target. Kini:
# - klaim layanan WAJIB lolos signature protokol asli (probe aktif per layanan);
# - connect saja -> verified=False (caller hanya boleh menjadikannya kandidat);
# - banner interceptor / banner identik massal -> seluruh scan port TIDAK KONKLUSIF.

_TLS_PORTS = {443, 636, 2376, 5986, 6443, 8443}
_HTTP_PROBE_PORTS = _HTTP_PORTS | {5985, 4848}
_INTERCEPT_TEXTS = ("turned off for this assistant", "open Muse settings",
                    "connections is turned off", "is turned off for this assistant")


def _match_banner_signature(port, raw):
    """Signature dari banner sambutan (layanan yang bicara lebih dulu).
    Kembalikan nama layanan bila cocok, else None. Murni bytes — bisa di-unit-test."""
    if not raw:
        return None
    low = raw.lower()
    if raw.startswith(b"SSH-"):
        return "ssh"
    if raw.startswith(b"RFB "):
        return "vnc"
    if raw[:1] in (b"\x0a", b"\x09") and (b"mysql" in low or b"mariadb" in low
                                          or b"not allowed to connect" in low
                                          or _re_ver(raw[:48])):
        return "mysql"
    if raw.startswith(b"220") and port in (21, 25, 587):
        return "ftp" if port == 21 else "smtp"
    if raw.startswith(b"+OK") and port in (110, 995):
        return "pop3"
    if raw.startswith(b"* OK") and port in (143, 993):
        return "imap"
    if b"\xff\xfb" in raw[:8] or b"\xff\xfd" in raw[:8]:
        return "telnet"
    return None


def _re_ver(raw):
    import re as _r
    return bool(_r.search(rb"\d+\.\d+\.\d+", raw or b""))


def _match_probe_response(port, resp):
    """Signature dari respons probe aktif per layanan. None bila tidak cocok."""
    if not resp:
        return None
    low = resp.lower()
    if port == 6379 and (resp.startswith(b"+PONG") or resp.startswith(b"-NOAUTH")
                         or resp.startswith(b"-ERR") or resp.startswith(b"-DENIED")):
        return "redis"
    if port == 11211 and resp.startswith(b"VERSION "):
        return "memcached"
    if port == 5432 and resp[:1] in (b"S", b"N") and len(resp) <= 2:
        return "pgsql"
    if port == 3389 and resp.startswith(b"\x03\x00") and b"\x0e\xd0" in resp[:12]:
        return "rdp"
    if port == 1433 and resp[:1] == b"\x12":
        return "mssql"
    if port in (27017, 27018) and b"mongodb" in low:
        return "mongodb"
    if port == 389 and resp[:1] == b"\x30" and b"\x61" in resp[:6]:
        return "ldap"
    if port == 2049 and len(resp) >= 12 and resp[8:12] == b"\x00\x00\x00\x01":
        return "nfs"
    if port == 1723 and b"\x1a\x2b\x3c\x4d" in resp[:16]:
        return "pptp"
    if port in _HTTP_PROBE_PORTS and resp.startswith(b"HTTP/"):
        return _guess(port)
    return None


def _active_probe(port):
    """Bytes probe aktif per port (None = tidak ada probe khusus)."""
    import struct
    if port == 6379:
        return b"PING\r\n"
    if port == 11211:
        return b"version\r\n"
    if port == 5432:
        return struct.pack("!II", 8, 80877103)  # PostgreSQL SSLRequest
    if port == 3389:
        return bytes.fromhex("030000130ee000000000000100080003000000")  # X.224 CR
    if port == 1433:
        return bytes.fromhex(  # TDS prelogin minimal
            "1201003400000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000")
    if port in (27017, 27018):
        return b"GET / HTTP/1.0\r\n\r\n"  # mongod menjawab teks identitasnya
    if port == 389:
        return bytes.fromhex("300c020101600702010304008000")  # LDAP bind v3 anonim
    if port == 2049:
        xid = b"\x2a\x4d\x3f\x11"
        return (xid + struct.pack("!IIIIII", 0, 2, 100003, 3, 0, 0)
                + struct.pack("!II", 0, 0) + struct.pack("!II", 0, 0))  # RPC NULL nfs v3
    if port == 1723:
        return (struct.pack("!HHI", 156, 1, 0x1A2B3C4D)
                + struct.pack("!HHI", 1, 0, 0) + b"\x00" * 138)  # PPTP SCCRQ
    return None


def _verify_exchange(s, host, port, raw):
    """Tentukan (verified, service, evidence_bytes) dari koneksi yang sudah terbuka."""
    svc = _match_banner_signature(port, raw)
    if svc:
        return True, svc, raw
    probe = _active_probe(port)
    resp = b""
    if probe is not None:
        try:
            s.sendall(probe)
            resp = s.recv(512)
        except Exception:
            resp = b""
        svc = _match_probe_response(port, resp)
        if svc:
            return True, svc, resp
    if port in _HTTP_PROBE_PORTS:
        try:
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: " +
                      host.encode("utf-8", "replace") + b"\r\n\r\n")
            resp = s.recv(512)
        except Exception:
            resp = resp or b""
        if resp.startswith(b"HTTP/"):
            return True, _guess(port), resp
    else:
        # Fallback generik: layanan HTTP di port non-standar (mis. 8899, 3000)
        # tetap harus bisa terverifikasi. Syarat ketat: respons diawali "HTTP/".
        try:
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: " +
                      host.encode("utf-8", "replace") + b"\r\n\r\n")
            resp2 = s.recv(512)
        except Exception:
            resp2 = b""
        if resp2.startswith(b"HTTP/"):
            return True, "http", resp2
    return False, None, (resp or raw)


def detect_interception(open_ports):
    """Deteksi interceptor/tarpit: banner gateway yang dikenal, atau banner yang
    IDENTIK di banyak port yang layanannya berbeda-beda. -> (bool, alasan, contoh)."""
    for r in open_ports:
        banner = r.get("banner") or ""
        low = banner.lower()
        if low.startswith("muse:") or any(t in low for t in _INTERCEPT_TEXTS):
            return True, 'interceptor gateway banner detected', banner
    if len(open_ports) >= 4:
        from collections import Counter
        banners = Counter(r["banner"] for r in open_ports if r.get("banner"))
        if banners and not any(r.get("verified") for r in open_ports):
            txt, n = banners.most_common(1)[0]
            if txt and n >= max(3, int(0.6 * len(open_ports))):
                return True, 'identical banner on many ports (tarpit/interceptor indication)', txt
    return False, "", ""


def _connect_opens_selectors(host, ports, timeout=1.5, max_inflight=256):
    """Pra-filter connect massal non-blocking via selectors (stdlib): ratusan
    socket connect berjalan serentak tanpa thread per port. Mengembalikan
    himpunan port yang connect-nya selesai (calon open) — verifikasi banner/
    signature TETAP dilakukan probe() tcp_scan_detailed setelahnya, jadi
    semantik 'verified' tidak berubah."""
    import selectors
    import errno as _errno
    sel = selectors.DefaultSelector()
    addr = (host, 0)
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        ip = infos[0][4][0]
    except Exception:
        ip = host
    openish, pending = set(), {}
    queue = list(ports)
    deadline = time.time() + timeout
    def _launch(port):
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.setblocking(False)
        err = sk.connect_ex((ip, port))
        if err in (0,):
            openish.add(port)
            sk.close()
            return
        if err not in (_errno.EINPROGRESS, _errno.EWOULDBLOCK, _errno.EALREADY):
            sk.close()
            return
        sel.register(sk, selectors.EVENT_WRITE, port)
        pending[sk.fileno()] = (sk, port)
    while queue or pending:
        while queue and len(pending) < max_inflight:
            _launch(queue.pop())
        if not pending:
            break
        left = deadline - time.time()
        if left <= 0:
            break
        for key, _mask in sel.select(timeout=max(0.0, min(0.25, left))):
            sk, port = pending.pop(key.fileobj.fileno(),
                                    (key.fileobj, key.data))
            try:
                err = sk.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err == 0:
                    openish.add(port)
            except Exception:
                pass
            try:
                sel.unregister(sk)
            except Exception:
                pass
            sk.close()
        if time.time() >= deadline and queue:
            # port yang belum sempat di-launch TIDAK dibuang: kembalikan agar
            # diprobe langsung oleh jalur thread (tidak ada port yang hilang).
            openish.update(queue)
            queue = []
    for fd, (sk, port) in list(pending.items()):
        try:
            sel.unregister(sk)
        except Exception:
            pass
        sk.close()
        openish.add(port)   # tak terputuskan dalam tenggat -> probe menentukan
    sel.close()
    return openish


def tcp_scan_detailed(host, ports=None, timeout=1.5, workers=100):
    """Seperti tcp_scan + metadata keabsahan. Open port kini membawa 'verified'
    (layanan lolos signature protokol) — connect saja menghasilkan verified=False."""
    ports = ports or COMMON_PORTS

    def probe(port):
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(1.0)
                if port in _TLS_PORTS:
                    try:
                        ctx = ssl._create_unverified_context()
                        with ctx.wrap_socket(s, server_hostname=host):
                            return {"port": port, "state": "open",
                                    "service": _guess(port), "verified": True,
                                    "banner": "TLS handshake sukses"}
                    except Exception:
                        return {"port": port, "state": "open",
                                "service": _guess(port), "verified": False,
                                "banner": ""}
                raw = b""
                try:
                    raw = s.recv(512)
                except Exception:
                    pass
                verified, svc, evidence = _verify_exchange(s, host, port, raw)
                banner = (evidence or b"").decode("utf-8", "replace").strip()
                return {"port": port, "state": "open",
                        "service": svc or _guess(port), "verified": verified,
                        "banner": banner[:200]}
        except (socket.timeout, ConnectionRefusedError, OSError):
            return {"port": port, "state": "closed", "service": "",
                    "banner": "", "verified": False}

    probe_ports = ports
    if len(ports) > 120:
        # Jalur cepat selectors untuk rentang besar; probe penuh hanya pada
        # calon open (+ port yang tak terputuskan dalam tenggat).
        candidates = _connect_opens_selectors(host, ports, timeout=timeout)
        probe_ports = [pt for pt in ports if pt in candidates]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(probe, probe_ports))
    open_ports = [r for r in results if r["state"] == "open"]
    intercepted, reason, sample = detect_interception(open_ports)
    return {"open": open_ports, "intercepted": intercepted,
            "intercept_reason": reason, "banner_sample": sample}


def tcp_scan(host, ports=None, timeout=1.5, workers=100):
    """Returns list of dicts (hanya yang open): {port, state, service, banner, verified}."""
    return tcp_scan_detailed(host, ports, timeout, workers)["open"]


def _guess(port):
    known = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
             80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
             143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
             1723: "pptp", 2375: "docker-api", 2376: "docker-api-tls",
             2379: "etcd", 3306: "mysql", 3389: "rdp", 5432: "pgsql",
             5601: "kibana", 5900: "vnc", 6379: "redis", 6443: "k8s-api",
             7001: "weblogic", 8009: "ajp13", 8080: "http-alt",
             8086: "influxdb", 8443: "https-alt", 8888: "http-alt2",
             9000: "cslistener", 9090: "zeus/prometheus", 9200: "elasticsearch",
             9300: "es-cluster", 10250: "kubelet", 11211: "memcached",
             15672: "rabbitmq-mgmt", 27017: "mongodb", 27018: "mongodb-shard",
             5000: "http-dev", 389: "ldap", 636: "ldaps", 1433: "mssql",
             1521: "oracle", 2049: "nfs", 4848: "glassfish", 5985: "winrm-http",
             5986: "winrm-https"}
    return known.get(port, str(port) + "/tcp")


def is_synthetic_ip(ip):
    """198.18.0.0/15 = rentang benchmarking (RFC 2544) yang dipakai resolver
    sintetis/fake-IP sandbox — tidak pernah IP hosting asli."""
    try:
        import ipaddress
        return ipaddress.ip_address(str(ip)) in ipaddress.ip_network("198.18.0.0/15")
    except Exception:
        return False


def resolve_host(host):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except (socket.gaierror, UnicodeError, TypeError):
        return []


def resolve_subdomain(domain, subs, workers=16, timeout=6.0):
    """Enumerasi subdomain dengan resolver yang dapat dipercaya.

    Resolver sistem di host ini SINTETIS (menjawab IP fake-IP 198.18.x.x untuk
    nama apa pun, termasuk yang tidak ada), jadi jawaban sistem tidak pernah
    dijadikan bukti. Sumber kebenaran: DNS-over-HTTPS (Cloudflare/Google via
    HTTPS proxy). Bila DoH mati DAN resolver sistem terbukti sintetis ->
    inconclusive (found kosong), bukan daftar palsu.
    Return: {"found": [{sub, ips}], "inconclusive": bool, "reason": str,
             "wildcard_ips": [...], "resolver": "doh"|"system"|"none"}"""
    import secrets as _sec
    probes = [f"vx{_sec.token_hex(5)}", f"vx{_sec.token_hex(5)}"]
    probe_doh = [doh_a(f"{p}.{domain}", timeout) for p in probes]
    found = []
    if any(p is not None for p in probe_doh):
        wildcard_ips = set()
        for p in probe_doh:
            if p and p["status"] == 0:
                wildcard_ips.update(p["ips"])
        fails = []

        def check(sub):
            fqdn = f"{sub}.{domain}"
            r = doh_a(fqdn, timeout)
            if r is None:
                fails.append(1)
                return None
            if r["status"] != 0:
                return None
            ips = r["ips"]
            if not ips and not r["cname"]:
                return None
            if ips and not r["cname"] and wildcard_ips and set(ips) <= wildcard_ips:
                return None
            return {"sub": fqdn, "ips": ips}

        with ThreadPoolExecutor(max_workers=workers) as ex:
            for r in ex.map(check, subs):
                if r:
                    found.append(r)
        found.sort(key=lambda x: x["sub"])
        if subs and len(fails) > len(subs) * 0.5:
            return {"found": [], "inconclusive": True,
                    "reason": "most DNS-over-HTTPS lookups failed — subdomain results cannot be trusted",
                    "wildcard_ips": sorted(wildcard_ips), "resolver": "doh"}
        return {"found": found, "inconclusive": False, "reason": "",
                "wildcard_ips": sorted(wildcard_ips), "resolver": "doh"}
    # DoH tidak terjangkau: uji apakah resolver sistem sintetis
    if resolve_host(f"{probes[0]}.{domain}"):
        return {"found": [], "inconclusive": True,
                "reason": ("the system resolver returns synthetic answers for "
                           "nonexistent names and DNS-over-HTTPS is unreachable "
                           "— subdomain results from this host cannot be trusted"),
                "wildcard_ips": [], "resolver": "none"}
    sys_wild = set(resolve_host(f"{probes[1]}.{domain}"))

    def check_sys(sub):
        fqdn = f"{sub}.{domain}"
        ips = [ip for ip in resolve_host(fqdn) if not is_synthetic_ip(ip)]
        if not ips:
            return None
        if sys_wild and set(ips) <= sys_wild:
            return None
        return {"sub": fqdn, "ips": ips}

    with ThreadPoolExecutor(max_workers=min(workers, 32)) as ex:
        for r in ex.map(check_sys, subs):
            if r:
                found.append(r)
    found.sort(key=lambda x: x["sub"])
    return {"found": found, "inconclusive": False, "reason": "",
            "wildcard_ips": sorted(sys_wild), "resolver": "system"}


DEFAULT_SUBS = ["www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "ns1",
                "ns2", "vpn", "remote", "portal", "intranet", "dev", "staging",
                "test", "qa", "api", "app", "admin", "cpanel", "git", "jenkins",
                "jira", "confluence", "sso", "auth", "blog", "shop", "cdn",
                "static", "assets", "db", "sql", "mysql", "backup", "old", "grafana",
                "kibana", "monitor", "prometheus", "gitlab", "ci", "docker",
                "registry", "k8s", "kube", "es", "elastic", "redis", "mq"]


DEFAULT_WORDLIST = ["admin", "login", "backup", "config", "db", "test", "old",
                    ".git", ".env", ".htaccess", "phpinfo.php", "wp-admin",
                    "uploads", "api", "dashboard", "robots.txt", "sitemap.xml",
                    "index.php", "server-status", "actuator", "console",
                    "swagger-ui.html", "openapi.json", "graphql", ".well-known",
                    "health", "metrics", "debug", "trace", "api/docs"]


def _tcp_connect(host, port, timeout=5.0):
    """TCP connect sadar proxy: bila env proxy HTTP tersedia, bangun tunnel
    HTTP CONNECT ke target asli (jalur keluar yang benar dari host beregress
    proxy). Tanpa proxy env -> direct."""
    import os
    # Target loopback/private selalu direct — proxy egress hanya untuk
    # alamat publik (menembus proxy untuk localhost merusak audit lokal).
    try:
        import ipaddress
        _ip = ipaddress.ip_address(host)
        if _ip.is_loopback or _ip.is_private or _ip.is_link_local:
            return socket.create_connection((host, port), timeout=timeout)
    except Exception:
        if host in ("localhost",):
            return socket.create_connection((host, port), timeout=timeout)
    proxy = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
             or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"))
    if not proxy:
        return socket.create_connection((host, port), timeout=timeout)
    from urllib.parse import urlparse as _up
    p = _up(proxy if "://" in proxy else "http://" + proxy)
    sock = socket.create_connection((p.hostname, p.port or 8080), timeout=timeout)
    try:
        sock.sendall((f"CONNECT {host}:{port} HTTP/1.1\r\n"
                      f"Host: {host}:{port}\r\n"
                      "Proxy-Connection: Keep-Alive\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        status_line = buf.split(b"\r\n", 1)[0]
        if b" 200" not in status_line:
            raise OSError("proxy CONNECT failed: "
                          + status_line.decode("utf-8", "replace")[:80])
        return sock
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise


def http_probe(base_url, paths=None, timeout=5.0, user_agent="VANTHEX/1.1.0"):
    """Probe path di root target lewat klien sadar-proxy (netclient).
    Dua path acak menjadi baseline soft-404: hasil yang menandatangani
    signature yang sama ditandai catch_all agar shell SPA tidak dilaporkan
    sebagai direktori yang ditemukan."""
    paths = paths if paths is not None else DEFAULT_WORDLIST
    from netclient import Client
    import secrets as _sec
    url = base_url if "://" in base_url else "https://" + base_url
    client = Client(url, timeout=timeout)

    def fetch(path):
        r = client.get("/" + path.lstrip("/"))
        server = r.hdr("server", "") if hasattr(r, "hdr") else ""
        return {"path": "/" + path.lstrip("/"), "status": r.status,
                "length": len(r.body or ""), "server": server}

    base_sigs = []
    for rnd in (f"vx-notfound-{_sec.token_hex(4)}", f"vx-notfound-{_sec.token_hex(5)}"):
        b = fetch(rnd)
        if b["status"]:
            base_sigs.append((b["status"], b["length"]))

    def is_catch_all(o):
        if not o["status"]:
            return False
        for st, ln in base_sigs:
            if o["status"] == st and abs(o["length"] - ln) <= max(8, int(0.03 * max(ln, 1))):
                return True
        return False

    with ThreadPoolExecutor(max_workers=10) as ex:
        out = list(ex.map(fetch, paths))
    for o in out:
        o["catch_all"] = is_catch_all(o)
    return out


def _try_tls_version(host, port, version, timeout):
    """True bila handshake dengan versi TLS yang di-pin berhasil."""
    try:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.minimum_version = version
        c.maximum_version = version
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        with _tcp_connect(host, port, timeout) as sock:
            with c.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def ssl_audit(host, port=443, timeout=5.0):
    """Inspect TLS cert + protocol of an HTTPS host (ditulis ulang di v3)."""
    out = {"host": host, "port": port}
    # 1) verifikasi standar (CA bawaan + hostname) — menangkap self-signed/expired/mismatch
    try:
        vctx = ssl.create_default_context()
        with _tcp_connect(host, port, timeout) as sock:
            with vctx.wrap_socket(sock, server_hostname=host):
                out["verify_ok"] = True
    except Exception as e:
        out["verify_ok"] = False
        out["verify_error"] = str(e)[:200]
    # 2) ambil detail sertifikat tanpa verifikasi
    try:
        ctx = ssl._create_unverified_context()
        with _tcp_connect(host, port, timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert(binary_form=False) or {}
                # getpeercert dengan context unverified mengembalikan {} di bbrp versi;
                # fallback: pakai context default-verification dimatikan hostname saja.
                if not cert:
                    c2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    c2.check_hostname = False
                    c2.verify_mode = ssl.CERT_NONE
                    with _tcp_connect(host, port, timeout) as sock2:
                        with c2.wrap_socket(sock2, server_hostname=host) as s2:
                            cert = s2.getpeercert() or {}
                            out["tls_version"] = s2.version()
                            out["cipher"] = s2.cipher()
                else:
                    out["tls_version"] = s.version()
                    out["cipher"] = s.cipher()
                out["subject"] = dict(x[0] for x in cert.get("subject", []))
                out["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                out["not_after"] = cert.get("notAfter")
                out["not_before"] = cert.get("notBefore")
                out["san"] = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"][:20]
                if not out["subject"]:
                    # getpeercert() teks kosong pada konteks CERT_NONE ->
                    # parse form DER (selalu tersedia) via cryptography.
                    try:
                        der = s.getpeercert(binary_form=True)
                    except Exception:
                        der = None
                    if der:
                        try:
                            from cryptography import x509 as _x509
                            c = _x509.load_der_x509_certificate(der)
                            _OID_KEYS = {"2.5.4.3": "commonName",
                                         "2.5.4.10": "organizationName",
                                         "2.5.4.6": "countryName",
                                         "2.5.4.7": "localityName",
                                         "2.5.4.8": "stateOrProvinceName",
                                         "2.5.4.11": "organizationalUnitName"}
                            def _nm(n):
                                return {_OID_KEYS.get(a.oid.dotted_string,
                                                      a.oid.dotted_string): a.value
                                        for a in n}
                            out["subject"] = _nm(c.subject)
                            out["issuer"] = _nm(c.issuer)
                            import datetime as _dtmod
                            na = getattr(c, "not_valid_after_utc", None) or c.not_valid_after
                            nb = getattr(c, "not_valid_before_utc", None) or c.not_valid_before
                            out["not_after"] = na.strftime("%b %d %H:%M:%S %Y GMT")
                            out["not_before"] = nb.strftime("%b %d %H:%M:%S %Y GMT")
                            try:
                                san = c.extensions.get_extension_for_class(
                                    _x509.SubjectAlternativeName).value
                                out["san"] = san.get_values_for_type(_x509.DNSName)[:20]
                            except Exception:
                                pass
                        except Exception:
                            pass
        out["ok"] = True
    except Exception as e:
        out["ok"] = False
        out["error"] = str(e)[:200]
        return out
    # 3) protokol legacy — handshake ter-pin per versi
    legacy = []
    for name in ("TLSv1", "TLSv1_1"):
        ver = getattr(ssl.TLSVersion, name, None)
        if ver is not None and _try_tls_version(host, port, ver, timeout):
            legacy.append(name.replace("_", "."))
    out["legacy_protocols_enabled"] = legacy
    out["tls12_ok"] = _try_tls_version(host, port, ssl.TLSVersion.TLSv1_2, timeout)
    return out


SECURITY_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy",
                    "X-Frame-Options", "X-Content-Type-Options",
                    "Referrer-Policy", "Permissions-Policy"]


def header_audit(url, timeout=5.0):
    """Check security headers on a URL (lewat klien sadar-proxy).
    Returns {headers, missing, score}."""
    from netclient import Client
    full = url if "://" in url else "https://" + url
    from urllib.parse import urlparse as _up
    path = _up(full).path or "/"
    client = Client(full, timeout=timeout)
    r = client.get(path)
    if not r.status:
        return {"ok": False, "error": "target unreachable (no response)"}
    present = {str(k): str(v) for k, v in (r.headers or [])}
    missing = [h for h in SECURITY_HEADERS
               if h.lower() not in {k.lower() for k in present}]
    score = round(100 * (len(SECURITY_HEADERS) - len(missing)) / len(SECURITY_HEADERS))
    return {"ok": True, "status": r.status, "headers": present,
            "missing": missing, "score": score}


# ------------------------------------------------------------ DNS-over-HTTPS
# stdlib tidak punya query TXT/CNAME; DoH (RFC 8484, format JSON Cloudflare)
# memberi kita itu lewat HTTPS biasa — dan urllib menghormati env proxy,
# jadi tetap jalan di jaringan beregress proxy. Fallback: kembalikan None
# (caller WAJIB memperlakukan None sebagai "tidak dapat diverifikasi", bukan "tidak ada record").

def _doh_json(name, rrtype="TXT", timeout=6.0):
    """Satu query DoH JSON (Cloudflare, fallback Google). None = transport gagal."""
    import json as _json
    import urllib.request as _u
    import urllib.parse as _up
    q = _up.urlencode({"name": name, "type": rrtype})
    for base in ("https://cloudflare-dns.com/dns-query?",
                 "https://dns.google/resolve?"):
        req = _u.Request(base + q, headers={"Accept": "application/dns-json",
                                            "User-Agent": "VANTHEX/1.1.0"})
        try:
            with _u.urlopen(req, timeout=timeout) as r:
                return _json.loads(r.read().decode("utf-8", "replace"))
        except Exception:
            continue
    return None


def doh_query(name, rrtype="TXT", timeout=6.0):
    """Kembalikan list string data record (TXT digabung per record), atau None bila gagal."""
    data = _doh_json(name, rrtype, timeout)
    if data is None:
        return None
    out = []
    for ans in data.get("Answer", []) or []:
        out.append(str(ans.get("data", "")).strip())
    return out


def doh_a(name, timeout=6.0):
    """Record A via DoH. None = transport gagal; selain itu dict
    {status, ips, cname} dari jawaban resolver publik asli."""
    data = _doh_json(name, "A", timeout)
    if data is None:
        return None
    ips, cname = [], False
    for ans in data.get("Answer", []) or []:
        if ans.get("type") == 1:
            ips.append(str(ans.get("data", "")).strip())
        elif ans.get("type") == 5:
            cname = True
    return {"status": int(data.get("Status", 0)), "ips": ips, "cname": cname}


def org_domain(host):
    """Heuristik domain organisasi (tanpa PSL): tangani sufiks 2-level umum
    (co.id, com.au, co.uk, ac.id, go.id, ...)."""
    parts = (host or "").lower().split(".")
    if len(parts) <= 2:
        return host
    two_level = {"co", "com", "net", "org", "ac", "go", "or", "ne", "re"}
    if len(parts[-1]) == 2 and parts[-2] in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ---------------------------------------------------------------------------
# FASE 2 (v3.17) — active pack: UDP probe protokol, cipher TLS, SYN, vhost.
# Semua buatan sendiri (socket/ssl mentah), tanpa tool luar.

UDP_PORTS = [53, 67, 69, 123, 137, 161, 500, 514, 631, 1194, 1900, 4500,
             5060, 5353]


def _dns_query_packet(qname="example.com"):
    import struct as _st
    tid = 0x5047
    hdr = _st.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(x)]) + x.encode() for x in qname.split(".")) + b"\x00"
    return hdr + q + _st.pack(">HH", 1, 1)


def _snmp_probe():
    # SNMPv1 GetRequest, community "public", OID sysDescr 1.3.6.1.2.1.1.1.0
    return bytes.fromhex(
        "302602010004067075626c6963a019020101020100020100300e300c06082b0601020101"
        "01000500")


def _udp_probe_for(port):
    if port == 53:
        return _dns_query_packet(), "dns"
    if port == 161:
        return _snmp_probe(), "snmp"
    if port == 123:
        return b"\x1b" + b"\x00" * 47, "ntp"
    return b"\x00", "generic"


def _udp_response_valid(service, data, payload=None):
    if not data:
        return False
    if service == "dns":
        # Bukti DNS yang sah: QR + TXID cocok dengan probe + RCODE 0 +
        # minimal 1 answer. Respons error (REFUSED/NXDOMAIN dari resolver
        # perantara) BUKAN bukti port target terbuka.
        if len(data) < 12 or not (data[2] & 0x80):
            return False
        if payload is not None and data[0:2] != payload[0:2]:
            return False
        if (data[3] & 0x0F) != 0:
            return False
        # NOERROR (dengan atau tanpa answer) + echo question yang sama =
        # server DNS asli menjawab. Error (REFUSED/dll) sudah gugur di RCODE.
        if payload is not None and len(payload) > 12:
            return len(data) >= len(payload) and data[12:len(payload)] == payload[12:]
        return True
    if service == "snmp":
        return data[0] == 0x30                                # BER SEQUENCE
    if service == "ntp":
        return len(data) >= 48 and (data[0] & 0x07) in (4, 5)
    return True


def udp_scan(host, ports=None, timeout=1.4):
    """UDP scan dengan probe spesifik-protokol. Semantik UDP yang jujur:
    respons valid = open; ICMP unreachable = closed; diam = open|filtered
    (tidak pernah diklaim tertutup). Bila SEMUA port diam pada host remote,
    hasilnya ambigu (egress UDP bisa saja dicegat) dan ditandai."""
    ports = ports or UDP_PORTS
    ip = host
    import re as _re
    if not _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or ""):
        _r = doh_a(host)
        if _r and _r["ips"]:
            ip = _r["ips"][0]
        else:
            try:
                cand = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
                if is_synthetic_ip(cand):
                    return {"host": host, "results": [], "open": [],
                            "ambiguous": True, "inconclusive": True,
                            "note": ("target resolved only to a synthetic "
                                     "sandbox IP and DoH was unreachable — "
                                     "UDP verdicts cannot be measured from "
                                     "this host")}
                ip = cand
            except Exception:
                return {"host": host, "results": [], "open": [],
                        "ambiguous": True, "inconclusive": True,
                        "note": ("target could not be resolved via DoH or a "
                                 "real resolver — UDP scan inconclusive")}
    results = []
    for port in ports:
        payload, service = _udp_probe_for(port)
        state, evidence = "open|filtered", ""
        try:
            sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sk.settimeout(timeout)
            sk.connect((ip, port))
            sk.send(payload)
            data = sk.recv(2048)
            if _udp_response_valid(service, data, payload):
                state, evidence = "open", f"{service} response {len(data)}B"
            elif service in ("dns", "snmp", "ntp"):
                # Ada datagram tapi GAGAL validasi protokol -> bukan bukti
                # layanan terbuka (bisa jawaban error perantara); jujur di
                # open|filtered dengan catatan.
                state, evidence = ("open|filtered",
                                   f"unverified response {len(data)}B "
                                   f"(failed {service} validation)")
            else:
                state, evidence = "open", f"unrecognized response {len(data)}B"
            sk.close()
        except ConnectionRefusedError:
            state = "closed"                     # ICMP port unreachable
        except (socket.timeout, TimeoutError):
            pass
        except OSError:
            pass
        results.append({"port": port, "service": service, "state": state,
                        "evidence": evidence})
    opens = [r for r in results if r["state"] == "open"]
    silent = all(r["state"] == "open|filtered" for r in results)
    is_local = ip.startswith(("127.", "10.", "192.168.", "172."))
    return {"host": host, "results": results, "open": opens,
            "ambiguous": bool(silent and not is_local),
            "note": ("all UDP probes silent on a remote host — egress UDP "
                     "may be intercepted; treat open|filtered as unproven"
                     if silent and not is_local else "")}


_WEAK_CIPHER_WORDS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "EXP",
                      "MD5", "ADH", "AECDH", "anon")
_CANDIDATE_CIPHERS = [
    "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-SHA256", "ECDHE-RSA-AES128-SHA256",
    "ECDHE-ECDSA-AES128-SHA", "ECDHE-RSA-AES128-SHA",
    "ECDHE-ECDSA-AES256-SHA", "ECDHE-RSA-AES256-SHA",
    "DHE-RSA-AES128-SHA", "DHE-RSA-AES256-SHA", "AES128-GCM-SHA256",
    "AES256-GCM-SHA384", "AES128-SHA256", "AES256-SHA256",
    "AES128-SHA", "AES256-SHA", "DES-CBC3-SHA", "RC4-SHA", "RC4-MD5",
    "DES-CBC-SHA", "EXP-RC4-MD5", "NULL-SHA", "NULL-MD5",
]


def _tls_try(host, port, proto_ver, ciphers, timeout):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = proto_ver
    ctx.maximum_version = proto_ver
    if ciphers:
        try:
            ctx.set_ciphers(ciphers)
        except ssl.SSLError:
            return None
    try:
        with _tcp_connect(host, port, timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.cipher()
    except Exception:
        return None


def tls_cipher_audit(host, port=443, timeout=3.0):
    """Enumerasi protokol & cipher TLS manual: handshake per versi, lalu
    per cipher kandidat untuk versi <= 1.2. Mengembalikan peta protokol,
    cipher yang didukung, yang lemah, dan protokol deprecated yang aktif."""
    versions = [("tls1_0", ssl.TLSVersion.TLSv1),
                ("tls1_1", ssl.TLSVersion.TLSv1_1),
                ("tls1_2", ssl.TLSVersion.TLSv1_2),
                ("tls1_3", ssl.TLSVersion.TLSv1_3)]
    protocols, supported, weak = {}, [], []
    for name, ver in versions:
        got = _tls_try(host, port, ver, "ALL:@SECLEVEL=0"
                       if name != "tls1_3" else None, timeout)
        protocols[name] = bool(got)
        if not got:
            continue
        if name == "tls1_3":
            supported.append({"protocol": name, "cipher": got[0]})
            continue
        for cand in _CANDIDATE_CIPHERS:
            one = _tls_try(host, port, ver, cand + ":@SECLEVEL=0", timeout)
            if one:
                entry = {"protocol": name, "cipher": one[0]}
                supported.append(entry)
                if any(w in one[0].upper() for w in _WEAK_CIPHER_WORDS):
                    weak.append(entry)
    deprecated = [n for n in ("tls1_0", "tls1_1") if protocols.get(n)]
    return {"host": host, "port": port, "protocols": protocols,
            "supported": supported, "weak": weak, "deprecated": deprecated,
            "sslv3": "not testable with this OpenSSL build"}


def syn_scan(host, ports, timeout=1.4):
    """SYN scan raw-socket manual (checksum IPv4/TCP sendiri). Tanpa
    CAP_NET_RAW/root hasilnya 'available: False' — dinyatakan, bukan
    dipaksakan. SYN-ACK = open (kernel host membalas RST karena SYN bukan dari socket kernel), RST = closed."""
    import struct as _st
    def _cksum(data):
        if len(data) % 2:
            data += b"\x00"
        tot = sum(_st.unpack(">%dH" % (len(data) // 2), data))
        tot = (tot >> 16) + (tot & 0xFFFF)
        tot += tot >> 16
        return (~tot) & 0xFFFF
    try:
        dst = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except Exception as e:
        return {"available": False, "reason": f"resolve failed: {e}",
                "open": [], "results": []}
    try:
        rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        rx.settimeout(timeout)
        tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        tx.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except (PermissionError, OSError) as e:
        return {"available": False,
                "reason": f"raw socket unavailable ({type(e).__name__}) — "
                          "needs root/CAP_NET_RAW", "open": [], "results": []}
    # alamat sumber: dari route ke tujuan
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect((dst, 80))
        src = probe.getsockname()[0]
        probe.close()
    except Exception:
        src = "127.0.0.1"
    results, opens = [], []
    try:
        for i, port in enumerate(ports):
            sport = 41000 + (i % 2000)
            pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + \
                _st.pack(">BBH", 0, 6, 20)
            tcp = _st.pack(">HHLLBBHHH", sport, port, 1000 + i, 0,
                           5 << 4, 0x02, 65535, 0, 0)
            tcp = _st.pack(">HHLLBBHHH", sport, port, 1000 + i, 0, 5 << 4,
                           0x02, 65535, _cksum(pseudo + tcp), 0)
            ip_hdr = _st.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 2000 + i, 0x4000,
                              64, 6, 0, socket.inet_aton(src),
                              socket.inet_aton(dst))
            ip_hdr = _st.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 2000 + i, 0x4000,
                              64, 6, _cksum(ip_hdr), socket.inet_aton(src),
                              socket.inet_aton(dst))
            state = "filtered"
            try:
                tx.sendto(ip_hdr + tcp, (dst, 0))
            except OSError as e:
                # Kirim raw DIBLOKIR environment (EPERM sandbox) — scan tidak
                # sah sama sekali: nyatakan tidak tersedia, jangan pura-pura
                # semua port 'filtered'.
                rx.close()
                tx.close()
                return {"available": False,
                        "reason": f"raw send blocked by environment ({e})",
                        "open": [], "results": []}
            try:
                deadline = time.time() + timeout
                while time.time() < deadline:
                    rx.settimeout(max(0.05, deadline - time.time()))
                    pkt, _addr = rx.recvfrom(65535)
                    ihl = (pkt[0] & 0x0F) * 4
                    if pkt[9] != 6:
                        continue
                    s_port, d_port = _st.unpack(">HH", pkt[ihl:ihl + 4])
                    if s_port != port or d_port != sport:
                        continue
                    flags = pkt[ihl + 13]
                    if flags & 0x12 == 0x12:            # SYN+ACK
                        state = "open"
                    elif flags & 0x04:                  # RST
                        state = "closed"
                    break
            except (socket.timeout, TimeoutError):
                state = "filtered"
            except OSError:
                state = "filtered"
            results.append({"port": port, "state": state})
            if state == "open":
                opens.append(port)
    finally:
        rx.close()
        tx.close()
    return {"available": True, "host": host, "open": opens,
            "results": results}


_VHOST_WORDS = ["www", "admin", "api", "dev", "staging", "test", "mail",
                "portal", "app", "internal", "vpn", "blog", "shop", "cdn",
                "static", "beta", "old", "backup", "git", "jenkins"]


def vhost_enum(target, candidates=None, timeout=5.0):
    """Enumerasi virtual host: bandingkan respons kandidat Host header vs
    baseline host-acak. Kandidat yang berbeda material = temuan probable."""
    import secrets as _sec
    from netclient import Client, similarity
    import passive as _passive
    scheme_host = target if "://" in target else "https://" + target
    from urllib.parse import urlparse as _up
    host = (_up(scheme_host).hostname or "").lower()
    domain = _passive._registrable(host)
    client = Client(scheme_host, timeout=timeout)
    base = client.get("/")
    rand_host = f"ptk-rand-{_sec.token_hex(4)}.{domain}"
    rb = client.get("/", headers={"Host": rand_host})
    out = []
    for word in (candidates or _VHOST_WORDS):
        if word == host.split(".")[0] and host != domain:
            continue
        vh = f"{word}.{domain}"
        if vh == host:
            continue
        r = client.get("/", headers={"Host": vh})
        sim_rand = similarity(r.body or "", rb.body or "")
        len_diff = abs(len(r.body or "") - len(rb.body or ""))
        interesting = (r.status != rb.status) or sim_rand < 0.70 or \
            (sim_rand < 0.92 and len_diff > 120)
        out.append({"vhost": vh, "status": r.status,
                    "length": len(r.body or ""), "interesting": interesting})
    return {"host": host, "domain": domain,
            "baseline_status": base.status,
            "random_baseline_status": rb.status,
            "candidates": out,
            "interesting": [o for o in out if o["interesting"]]}
