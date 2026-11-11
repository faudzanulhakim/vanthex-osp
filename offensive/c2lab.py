"""
C2Lab — C2 Infrastructure Emulator for VANTHEX (v1.8.0).
AUTHORIZED TESTING ONLY - LAB EMULATION.

PURPOSE: emulate command-and-control concepts entirely on the loopback
interface (127.0.0.1) so defenders and detection rules can be tested
against realistic C2 behaviors WITHOUT any external network activity.
This is not a real C2 tool: implants only talk to a LocalTaskServer on
loopback, tasks are whitelisted read-only probes executed by operator-
supplied handler callables (this module never spawns processes itself),
and the "DNS channel" is a pure string codec.

OPERATOR GATE: every server/client constructor refuses to start unless
the environment variable PTK_C2LAB=1 is set. LOOPBACK ONLY: every
network-facing component binds 127.0.0.1 and refuses any non-loopback
bind address (localhost resolves to a loopback address and is accepted).

Components:
  LocalTaskServer — stdlib http.server on loopback, bearer-token auth
                    (constant-time compare), task queue, result store,
                    sleep/jitter hints to the implant.
  Implant         — loopback-only beacon client: polls the server,
                    executes whitelisted task types (file_stat, env_probe,
                    dir_list with depth cap) via injected handlers,
                    reports results.
  DNS channel     — dns_encode/dns_decode: encode result bytes into
                    subdomain-label sequences and decode them back
                    (emulation of DNS C2 for detection-testing only).
  lateral_map_lab — graph dict over lab session records (nodes = hosts,
                    edges = credential-reuse hops) reusing lateralmap.py
                    node/edge shapes {"id","kind","label"} / {"from","to","via"}.
  detection_matrix— per-channel yara-like detection heuristics a defender
                    would deploy.

Stdlib only, loopback-only, never raises on malformed input in the pure
helpers; server/implant constructors raise C2LabError on gate/bind
violations.
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AUTHORIZED_BANNER = "AUTHORIZED TESTING ONLY - LAB EMULATION"
GATE_ENV = "PTK_C2LAB"
LOOPBACK_HOST = "127.0.0.1"

ALLOWED_TASKS = ("file_stat", "env_probe", "dir_list")
DIR_LIST_MAX_DEPTH = 3
MAX_QUEUE = 64
MAX_RESULTS = 256

DEFAULT_SLEEP_S = 0.5
MAX_JITTER = 0.5


class C2LabError(Exception):
    """Refusal to start: operator gate not set, or non-loopback bind."""


def gate_open():
    """True only when the operator explicitly enabled the lab (env)."""
    return os.environ.get(GATE_ENV) == "1"


def _require_gate():
    if not gate_open():
        raise C2LabError(
            f"c2lab is operator-gated: set {GATE_ENV}=1 to enable "
            f"({AUTHORIZED_BANNER})")


def require_loopback(host):
    """Raise unless host resolves to a loopback address. Lab safety."""
    h = str(host or "").strip().lower()
    try:
        addr = ipaddress.ip_address(h)
    except ValueError:
        if h in ("localhost",):
            return "127.0.0.1"
        raise C2LabError(f"non-loopback bind refused: {host!r}")
    if not addr.is_loopback:
        raise C2LabError(
            f"non-loopback bind refused: {host!r} ({AUTHORIZED_BANNER})")
    return str(addr)


def _slug(s, prefix):
    base = re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")[:40]
    return f"{prefix}-{base}" or prefix


def _jittered(base, jitter, rng):
    j = min(max(float(jitter), 0.0), MAX_JITTER)
    return max(0.01, float(base) * (1.0 + rng.uniform(-j, j)))


# ---------------------------------------------------------------- server

class _Handler(BaseHTTPRequestHandler):
    server_version = "C2Lab/1.0"

    def log_message(self, fmt, *args):  # keep lab runs quiet
        pass

    def _authed(self):
        expected = self.server.token
        got = (self.headers.get("Authorization") or "").strip()
        if got.lower().startswith("bearer "):
            got = got[7:].strip()
        return hmac.compare_digest(str(expected), str(got))

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._authed():
            self._send(401, {"error": "unauthorized"})
            return
        path = self.path.split("?")[0]
        srv = self.server.lab
        if path == "/poll":
            implant = self.headers.get("X-Implant-Id") or "anon"
            task, sleep_s = srv.poll_task(implant)
            self._send(200, {"task": task, "sleep_s": sleep_s})
        elif path == "/results":
            self._send(200, {"results": srv.results_snapshot()})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authed():
            self._send(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._send(400, {"error": "bad json"})
            return
        srv = self.server.lab
        path = self.path.split("?")[0]
        if path == "/tasks":
            ok, info = srv.enqueue_task(payload)
            self._send(200 if ok else 400, info)
        elif path == "/results":
            ok, info = srv.store_result(payload)
            self._send(200 if ok else 400, info)
        else:
            self._send(404, {"error": "not found"})


class LocalTaskServer:
    """Loopback-only task server (stdlib http.server).

    Binds 127.0.0.1 (refuses anything else), bearer-token auth with
    constant-time comparison, FIFO task queue, result store, and
    per-implant sleep/jitter hints so implants can emulate realistic
    beacon cadence.
    """

    def __init__(self, host=LOOPBACK_HOST, port=0, token=None,
                 default_sleep_s=DEFAULT_SLEEP_S, jitter=0.25):
        _require_gate()
        self.host = require_loopback(host)
        self.port = int(port)
        self.token = token or secrets.token_hex(16)
        self.default_sleep_s = max(0.01, float(default_sleep_s))
        self.jitter = min(max(float(jitter), 0.0), MAX_JITTER)
        self._queue = []            # pending tasks (dicts)
        self._results = []          # stored results
        self._next_poll = {}        # implant_id -> earliest next poll (ts)
        self._rng = __import__("random").Random()
        self._lock = threading.Lock()
        self.httpd = ThreadingHTTPServer((self.host, self.port), _Handler)
        self.httpd.token = self.token
        self.httpd.lab = self
        self.host, self.port = self.httpd.server_address[:2]
        self.url = f"http://{self.host}:{self.port}"

    # -- queue / store API (thread-safe, also usable in-process) --
    def enqueue_task(self, task):
        """Accept {'type': <whitelisted>, 'params': {...}}; returns
        (ok, {'task_id':..., 'queued': n} or {'error':...})."""
        with self._lock:
            if not isinstance(task, dict) or task.get("type") not in ALLOWED_TASKS:
                return False, {"error": "task type not whitelisted"}
            if len(self._queue) >= MAX_QUEUE:
                return False, {"error": "queue full"}
            t = {"task_id": hashlib.sha1(
                    (str(time.time()) + str(len(self._queue))).encode()
                 ).hexdigest()[:12],
                 "type": task["type"],
                 "params": task.get("params") or {}}
            self._queue.append(t)
            return True, {"task_id": t["task_id"], "queued": len(self._queue)}

    def poll_task(self, implant_id):
        """Next task for an implant + sleep hint (respects cadence)."""
        now = time.time()
        with self._lock:
            earliest = self._next_poll.get(implant_id, 0)
            sleep_s = _jittered(self.default_sleep_s, self.jitter, self._rng)
            self._next_poll[implant_id] = now + sleep_s
            task = self._queue.pop(0) if self._queue else None
        return task, round(sleep_s, 3)

    def store_result(self, result):
        with self._lock:
            if not isinstance(result, dict) or "task_id" not in result:
                return False, {"error": "result needs task_id"}
            if len(self._results) >= MAX_RESULTS:
                self._results.pop(0)
            self._results.append(dict(result))
            return True, {"stored": len(self._results)}

    def results_snapshot(self):
        with self._lock:
            return [dict(r) for r in self._results]

    def start(self):
        t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        t.start()
        return t

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


# --------------------------------------------------------------- implant

class Implant:
    """Loopback-only beacon client (lab emulation).

    Polls a LocalTaskServer on 127.0.0.1, executes ONLY whitelisted
    read-only task types through operator-injected handler callables —
    the module itself never spawns processes. The server URL must be a
    loopback address or construction is refused.
    """

    def __init__(self, server_url, implant_id=None, handlers=None,
                 max_polls=8, seed=None):
        _require_gate()
        from urllib.parse import urlsplit
        parts = urlsplit(str(server_url or ""))
        host = require_loopback(parts.hostname or "")
        if parts.scheme != "http" or not host:
            raise C2LabError(f"implant refuses non-loopback url: {server_url!r}")
        self.url = f"http://{host}:{parts.port or 80}"
        self.id = implant_id or "imp" + secrets.token_hex(4)
        self.handlers = dict(handlers or {})
        self.max_polls = max(1, int(max_polls))
        self.rng = __import__("random").Random(seed or time.time())
        self.log = []   # [{t, action, detail}]
        self.results = []

    def _call(self, path, method="GET", payload=None, extra=None,
              timeout=5):
        headers = {"Authorization": "Bearer lab",  # set by bind_token()
                   "X-Implant-Id": self.id}
        if extra:
            headers.update(extra)
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.url + path, data=data,
                                     method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")

    def bind_token(self, token):
        """Point the implant at a server token (constant-time compare
        happens server-side; the client just sends the bearer value)."""
        self._token = str(token)
        self._call_orig = None

        def _call(path, method="GET", payload=None, extra=None, timeout=5):
            headers = {"Authorization": f"Bearer {self._token}",
                       "X-Implant-Id": self.id}
            if extra:
                headers.update(extra)
            data = json.dumps(payload).encode() if payload is not None else None
            req = urllib.request.Request(self.url + path, data=data,
                                         method=method, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read() or b"{}")
        self._call = _call
        return self

    def _execute(self, task):
        ttype = task.get("type")
        handler = self.handlers.get(ttype)
        if ttype not in ALLOWED_TASKS:
            return {"error": "task type not whitelisted"}
        if not callable(handler):
            return {"error": f"no handler for {ttype}"}
        try:
            return {"ok": True, "data": handler(task.get("params") or {})}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def run(self, cancel=lambda: False):
        """Poll -> execute -> report loop; returns the collected results."""
        for _ in range(self.max_polls):
            if cancel():
                break
            try:
                resp = self._call("/poll")
            except Exception as e:
                self.log.append({"t": round(time.time(), 3),
                                 "action": "poll_error", "detail": str(e)})
                break
            self.log.append({"t": round(time.time(), 3), "action": "poll",
                             "detail": resp.get("sleep_s")})
            task = resp.get("task")
            if not task:
                time.sleep(min(float(resp.get("sleep_s") or 0.05), 0.5))
                continue
            result = {"task_id": task.get("task_id"),
                      "implant_id": self.id,
                      "type": task.get("type"),
                      "output": self._execute(task)}
            self._call("/results", method="POST", payload=result)
            self.results.append(result)
            self.log.append({"t": round(time.time(), 3), "action": "result",
                             "detail": task.get("task_id")})
            time.sleep(min(float(resp.get("sleep_s") or 0.05), 0.5))
        return self.results


# -------------------------------------------------- DNS channel emulator

DNS_LABEL_MAX = 63
DNS_NAME_MAX = 253
DNS_PREFIX = "c2lab"
LABEL_DATA_MAX = DNS_LABEL_MAX - len(DNS_PREFIX)  # room for the prefix
_B32 = "abcdefghijklmnopqrstuvwxyz234567"


def dns_encode(data, prefix=DNS_PREFIX, labels_per_name=4):
    """Encode bytes as subdomain-label sequences (base32).

    Returns a list of fake domain names like
    'c2labaabbccdd.c2lab....example.test'. PURE STRING CODEC — an
    emulation of DNS C2 for detection-testing purposes; nothing is ever
    resolved or sent over the network.
    """
    raw = base64.b32encode(bytes(data)).decode().rstrip("=").lower()
    if not raw:
        return []  # empty payload encodes to no names; decode([]) == b""
    chunk = max(1, min(int(labels_per_name), 8)) * DNS_LABEL_MAX
    names, i = [], 0
    while i < len(raw):
        block = raw[i:i + chunk]
        labels = [block[j:j + LABEL_DATA_MAX]
                  for j in range(0, len(block), LABEL_DATA_MAX)]
        name = ".".join(f"{prefix}{l}" if k == 0 else prefix + l
                        for k, l in enumerate(labels)) + ".lab.invalid"
        names.append(name[:DNS_NAME_MAX])
        i += chunk
    return names


def dns_decode(names):
    """Inverse of dns_encode — decode label sequences back to bytes."""
    try:
        raw = ""
        for name in (names or []):
            for label in str(name).split("."):
                if label.startswith(DNS_PREFIX):
                    raw += label[len(DNS_PREFIX):]
        pad = (-len(raw)) % 8
        return base64.b32decode(raw.upper() + "=" * pad)
    except Exception:
        return b""


def dns_label_entropy(names):
    """Shannon entropy (bits/char) of a decoded label set — the metric
    a defender's DNS-analytics rule would compute. Pure."""
    text = "".join(str(n).split(".")[0] for n in (names or []))
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return round(-sum((v / n) * math.log2(v / n) for v in freq.values()), 3)


# ------------------------------------------------------- lateral map lab

def lateral_map_lab(sessions):
    """Build a lab lateral-movement graph from session records.

    sessions: [{'host': 'hostA', 'credential_id': 'cred1', ...}, ...]
    Reuses the lateralmap.py node/edge shapes:
      nodes: {'id', 'kind', 'label'}  (kind: host|implant)
      edges: {'from', 'to', 'via'}    (via: 'credential reuse: <cred>')
    A credential observed on two hosts produces a hop edge between them.
    Pure; never raises on malformed input.
    """
    nodes, edges = [], []
    nkeys, ekeys = set(), set()

    def add_node(kind, label):
        if not label:
            return None
        nid = _slug(label, kind)
        if nid in nkeys:
            return nid
        nkeys.add(nid)
        nodes.append({"id": nid, "kind": kind, "label": str(label)[:120]})
        return nid

    def add_edge(frm, to, via):
        if not frm or not to or frm == to or len(edges) >= 80:
            return
        if (frm, to) in ekeys:
            return
        ekeys.add((frm, to))
        edges.append({"from": frm, "to": to, "via": str(via)[:120]})

    cred_hosts = {}   # credential_id -> [host node ids]
    for s in (sessions or []):
        if not isinstance(s, dict):
            continue
        host = str(s.get("host") or "").strip()
        cred = str(s.get("credential_id") or "").strip()
        hid = add_node("host", host)
        if s.get("implant_id"):
            iid = add_node("implant", f"implant {s['implant_id']} on {host}")
            if hid and iid:
                add_edge(iid, hid, "implant resident on host")
        if hid and cred:
            cred_hosts.setdefault(cred, [])
            if hid not in cred_hosts[cred]:
                cred_hosts[cred].append(hid)

    for cred, hosts in cred_hosts.items():
        for a, b in zip(hosts, hosts[1:]):
            add_edge(a, b, f"credential reuse: {cred}")

    return {"nodes": nodes, "edges": edges,
            "node_count": len(nodes), "edge_count": len(edges)}


# ----------------------------------------------------- detection matrix

def detection_matrix(sessions=None, dns_names=None):
    """Yara-like detection heuristics a defender would deploy, one set
    per emulated channel. Pure; output feeds report/blue-team tooling."""
    matrix = []
    matrix.append({
        "channel": "http_beacon",
        "heuristics": [
            {"id": "C2LAB-HTTP-001", "name": "beacon_interval_fingerprint",
             "pattern": "inter-request gaps within jitter band of a fixed "
                        "base interval (stddev/max-gap < jitter*1.5)",
             "condition": "3+ consecutive loopback polls at near-equal "
                          "intervals with identical X-Implant-Id",
             "severity": "MEDIUM"},
            {"id": "C2LAB-HTTP-002", "name": "task_payload_pattern",
             "pattern": 'POST /tasks body matching {"type": "file_stat"|"env_probe"|"dir_list"}',
             "condition": "whitelisted task JSON with task_id hash prefix",
             "severity": "LOW"},
        ]})
    matrix.append({
        "channel": "dns_emulation",
        "heuristics": [
            {"id": "C2LAB-DNS-001", "name": "dns_label_entropy",
             "pattern": "subdomain labels with entropy > 3.5 bits/char",
             "condition": "dns_label_entropy(decoded labels) above "
                          "threshold, or labels longer than 40 chars",
             "severity": "HIGH"},
            {"id": "C2LAB-DNS-002", "name": "dns_prefix_fingerprint",
             "pattern": f"labels beginning '{DNS_PREFIX}' under a "
                        ".lab.invalid zone",
             "condition": "repeated base32 labels to a non-routable TLD",
             "severity": "MEDIUM"},
        ]})
    matrix.append({
        "channel": "lateral_movement_lab",
        "heuristics": [
            {"id": "C2LAB-LAT-001", "name": "credential_reuse_hop",
             "pattern": "same credential_id observed on 2+ hosts within "
                        "the lab window",
             "condition": "lateral_map_lab produces a 'credential reuse' "
                          "edge",
             "severity": "HIGH"},
        ]})
    # evidence-derived notes: attach measured values when caller provides
    if dns_names:
        matrix[1]["measured"] = {
            "label_entropy": dns_label_entropy(dns_names),
            "names_emitted": len(dns_names)}
    if sessions:
        g = lateral_map_lab(sessions)
        matrix[2]["measured"] = {"credential_reuse_edges": g["edge_count"],
                                 "hosts": g["node_count"]}
    return matrix
