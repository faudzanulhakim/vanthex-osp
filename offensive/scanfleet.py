#!/usr/bin/env python3
"""Distributed scan fleet coordinator for VANTHEX.

A tiny coordinator + node-server pair so several VANTHEX hosts can share
scan work. All mutating operations are gated behind the environment
variable PTK_FLEET=1 — without it every entry point refuses, so the
module is inert by default on any host that did not explicitly opt in.

State lives in a small JSON file (fleet.json):
    {"nodes": [{"id", "url", "token_hash", "last_seen", "capacity"}],
     "jobs":  [{"id", "target", "profile", "status", "node",
                "started", "results_path"}]}

No dependency on store.py or the toolkit DB — deliberately self-contained.
"""

import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GATE_ENV = "PTK_FLEET"

# Confidence ranking used when deduplicating findings across nodes:
# the strongest observation wins.
CONFIDENCE_RANK = {"confirmed": 3, "probable": 2, "candidate": 1}

FLEET_LOG_PREFIX = "[fleet]"


def _log(msg):
    print(f"{FLEET_LOG_PREFIX} {msg}", flush=True)


def fleet_enabled():
    """True only when the operator opted in via PTK_FLEET=1."""
    return os.environ.get(GATE_ENV) == "1"


def hash_token(token):
    """SHA-256 hex digest of a bearer token — only the hash is persisted."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _require_gate():
    if not fleet_enabled():
        raise PermissionError(
            f"fleet operations are disabled; set {GATE_ENV}=1 to enable "
            "(safe by default)")


def _dedupe_findings(findings):
    """Merge findings, keeping the strongest confidence per
    (title, location, param). First-seen wins ties (stable)."""
    best = {}
    order = []
    for f in findings:
        key = (f.get("title", ""), f.get("location", ""),
               f.get("param", ""))
        rank = CONFIDENCE_RANK.get(f.get("confidence", "candidate"), 1)
        if key not in best:
            best[key] = (rank, f)
            order.append(key)
        else:
            cur_rank = best[key][0]
            if rank > cur_rank:
                best[key] = (rank, f)
    return [best[k][1] for k in order]


class FleetCoordinator:
    """Persists fleet state to a JSON file and hands out dispatches."""

    def __init__(self, state_path="fleet.json"):
        self.state_path = state_path
        self._lock = threading.Lock()
        self._state = {"nodes": [], "jobs": []}
        self._load()

    # -- persistence ---------------------------------------------------

    def _load(self):
        if os.path.exists(self.state_path):
            try:
                with open(self.state_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    self._state["nodes"] = data.get("nodes", [])
                    self._state["jobs"] = data.get("jobs", [])
            except (OSError, ValueError) as e:
                _log(f"could not load state {self.state_path}: {e}; "
                     "starting fresh")

    def save(self):
        with self._lock:
            tmp = self.state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._state, fh, indent=2)
            os.replace(tmp, self.state_path)

    # -- node management -------------------------------------------------

    def register_node(self, node_url, token, capacity=1):
        """Register (or refresh) a node; the token is stored hashed."""
        _require_gate()
        nid = hashlib.sha256(node_url.encode("utf-8")).hexdigest()[:12]
        with self._lock:
            for n in self._state["nodes"]:
                if n["id"] == nid:
                    n["url"] = node_url
                    n["token_hash"] = hash_token(token)
                    n["capacity"] = capacity
                    n["last_seen"] = time.time()
                    break
            else:
                self._state["nodes"].append({
                    "id": nid, "url": node_url,
                    "token_hash": hash_token(token),
                    "last_seen": time.time(), "capacity": capacity,
                })
        self.save()
        _log(f"node registered: {node_url} (id {nid}, capacity {capacity})")
        return nid

    def heartbeat(self, node_url, token):
        """Update last_seen for a node whose token matches. Returns bool."""
        _require_gate()
        nid = hashlib.sha256(node_url.encode("utf-8")).hexdigest()[:12]
        h = hash_token(token)
        with self._lock:
            for n in self._state["nodes"]:
                if n["id"] == nid and hmac.compare_digest(n["token_hash"], h):
                    n["last_seen"] = time.time()
                    seen = True
                    break
        if seen:
            self.save()
        return seen

    def _pick_idle_node(self):
        busy = {j.get("node") for j in self._state["jobs"]
                if j.get("status") == "running"}
        for n in self._state["nodes"]:
            cap = int(n.get("capacity", 1) or 1)
            running = sum(1 for j in self._state["jobs"]
                          if j.get("node") == n["id"]
                          and j.get("status") == "running")
            if n["id"] not in busy and running < cap:
                return n
        return None

    # -- jobs ------------------------------------------------------------

    def dispatch(self, job):
        """Pick an idle node with free capacity, mark the job, and return
        the dispatch payload to send to that node."""
        _require_gate()
        with self._lock:
            node = self._pick_idle_node()
            if node is None:
                _log("dispatch refused: no idle node with capacity")
                return None
            job_id = str(uuid.uuid4())[:8]
            record = {
                "id": job_id,
                "target": job.get("target", ""),
                "profile": job.get("profile", "active-deep"),
                "status": "running",
                "node": node["id"],
                "started": time.time(),
                "results_path": None,
            }
            self._state["jobs"].append(record)
        self.save()
        payload = {
            "job_id": job_id,
            "target": record["target"],
            "profile": record["profile"],
            "node_url": node["url"],
        }
        _log(f"job {job_id} ({record['target']}) dispatched to "
             f"node {node['id']}")
        return payload

    def collect(self, job_id, results):
        """Merge node results into the job record: dedupe findings by
        (title, location, param) keeping the strongest confidence, and
        aggregate risk via vulnscan2.risk_score when importable."""
        _require_gate()
        job = self.get_job(job_id)
        if job is None:
            raise KeyError(f"unknown job {job_id}")
        findings = list(results.get("findings", []))
        existing = list(results.get("existing_findings", []))
        merged = _dedupe_findings(existing + findings)
        aggregate = {
            "job_id": job_id,
            "target": results.get("target", job["target"]),
            "profile": results.get("profile", job["profile"]),
            "findings": merged,
        }
        try:
            import vulnscan2
            aggregate["risk_score"] = vulnscan2.risk_score(merged)
            aggregate["overall_risk"] = (
                "HIGH" if aggregate["risk_score"] >= 50
                else "MEDIUM" if aggregate["risk_score"] >= 20 else "LOW")
        except Exception as e:  # standalone deployments without vulnscan2
            _log(f"risk aggregation skipped (vulnscan2 unavailable: {e})")
        with self._lock:
            job["status"] = "done"
            job["results_path"] = results.get("results_path")
        self.save()
        _log(f"job {job_id} collected: {len(merged)} findings "
             f"(risk {aggregate.get('risk_score', 'n/a')})")
        return aggregate

    def get_job(self, job_id):
        with self._lock:
            for j in self._state["jobs"]:
                if j["id"] == job_id:
                    return j
        return None


# Module-level convenience wrappers (also gate-checked).

def register_node(coordinator, node_url, token, capacity=1):
    return coordinator.register_node(node_url, token, capacity=capacity)


def dispatch(coordinator, job):
    return coordinator.dispatch(job)


def collect(coordinator, job_id, results):
    return coordinator.collect(job_id, results)


def default_job_runner(job):
    """Runs the same scan entry the CLI uses (cli.cmd_scan path):
    vulnscan2.run_vulnscan, imported lazily so importing scanfleet stays
    cheap and side-effect free."""
    import vulnscan2
    log = _log
    return vulnscan2.run_vulnscan(
        job["target"], job.get("profile", "active-deep"), log=log,
        opts={"timeout": float(job.get("timeout", 6.0))})


class NodeServer:
    """Minimal stdlib HTTP node: join / heartbeat / job / result endpoints
    with bearer-token auth (constant-time compare)."""

    def __init__(self, coordinator, port=0, token=None, job_runner=None,
                 host="127.0.0.1"):
        _require_gate()
        self.coordinator = coordinator
        self.token = token or uuid.uuid4().hex
        self.job_runner = job_runner or default_job_runner
        self.host = host

        coordinator_ref = coordinator
        node_token = self.token
        runner = self.job_runner

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # quieter default logging
                _log(f"node :{self.server.server_port} {fmt % args}")

            def _authed(self):
                auth = self.headers.get("Authorization", "")
                if not auth.startswith("Bearer "):
                    return False
                supplied = auth[len("Bearer "):].strip()
                return hmac.compare_digest(hash_token(supplied),
                                           hash_token(node_token))

            def _read_json(self):
                try:
                    length = int(self.headers.get("Content-Length", 0) or 0)
                    return json.loads(self.rfile.read(length) or b"{}")
                except (ValueError, OSError):
                    return {}

            def _send(self, code, obj):
                body = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                if not self._authed():
                    self._send(401, {"error": "unauthorized"})
                    return
                data = self._read_json()
                if self.path == "/fleet/join":
                    nid = coordinator_ref.register_node(
                        data.get("node_url", ""),
                        data.get("token", node_token),
                        capacity=int(data.get("capacity", 1)))
                    self._send(200, {"ok": True, "node_id": nid})
                elif self.path == "/fleet/heartbeat":
                    ok = coordinator_ref.heartbeat(
                        data.get("node_url", ""), data.get("token", node_token))
                    self._send(200, {"ok": ok})
                elif self.path == "/fleet/job":
                    try:
                        res = runner(data)
                        self._send(200, {"ok": True, "results": res})
                    except Exception as e:
                        _log(f"job {data.get('job_id')} failed on node: {e}")
                        self._send(500, {"ok": False, "error": str(e)})
                elif self.path == "/fleet/result":
                    try:
                        agg = coordinator_ref.collect(
                            data.get("job_id"), data.get("results", {}))
                        self._send(200, {"ok": True, "aggregate": agg})
                    except Exception as e:
                        self._send(400, {"ok": False, "error": str(e)})
                else:
                    self._send(404, {"error": "not found"})

        self.httpd = ThreadingHTTPServer((host, port), Handler)
        self.port = self.httpd.server_address[1]
        self.url = f"http://{host}:{self.port}"

    def start(self):
        t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        t.start()
        _log(f"node server listening on {self.url}")
        return t

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
