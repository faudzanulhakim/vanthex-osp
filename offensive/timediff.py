"""Time-travel differential scanner for VANTHEX. OPERATOR-GATED.

Captures versioned snapshots of an application surface (per-target endpoint
state) into a standalone sqlite store, diffs the new snapshot against the
previous one, ranks changes by attack priori, and emits concrete probe step
plans for the added/changed endpoints.

    python3 timediff.py --store timediff.db --target http://t --crawler c.json

All pure python + stdlib sqlite3. run_timediff() requires the
PTK_TIMEDIFF=1 environment gate, mirroring monitor.py's operator-gated
design. Findings use the vulnscan2.F pattern (lazy import) so the results
integrate with the findings storage later.
"""
import argparse
import hashlib
import json as _json
import os
import sqlite3
import sys
import time
import uuid

SCHEMA_VERSION = 1
ENGINE_VERSION = "timediff-1"

# attack-priori weights used by diff_snapshots' risk ranking
_W_PARAMS = 2      # per parameter
_W_POST = 3        # POST methods carry state-changing payloads
_W_5XX = 4         # 5xx responses hint at injectable/incomplete handling
_W_4XX = 1
_W_BODY_CHANGE = 5  # body actually changed between snapshots


# ------------------------------------------------------------- SnapshotStore

def _db(store_path):
    conn = sqlite3.connect(store_path)
    conn.row_factory = sqlite3.Row
    return conn


def _body_hash(body):
    if body is None:
        return ""
    return hashlib.sha256(str(body).encode("utf-8", "replace")).hexdigest()[:16]


def _header_sig(headers):
    if not headers:
        return ""
    if isinstance(headers, dict):
        items = sorted((str(k).lower(), str(v)) for k, v in headers.items())
    else:
        items = [(str(k).lower(), str(v)) for k, v in headers]
    raw = "\n".join(f"{k}:{v}" for k, v in items)
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


def _status_class(status):
    """200 -> '2xx'; non-numeric/absent -> ''."""
    try:
        return f"{int(status) // 100}xx"
    except (TypeError, ValueError):
        return ""


class SnapshotStore:
    """sqlite-backed snapshot of an application surface.

    Tables:
      snapshot_meta(id TEXT PK, target TEXT, captured_at REAL,
                    engine_version TEXT, schema_version INTEGER, state TEXT)
    The per-target JSON state lives in snapshot_meta.state:
      {endpoints: [{url, method, params, status_class, body_hash, header_sig}],
       discovered_at, engine_version}
    """

    def __init__(self, store_path):
        self.store_path = store_path
        self.conn = _db(store_path)
        self._init_schema()

    def _init_schema(self):
        with self.conn:
            self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS snapshot_meta(
                id TEXT PRIMARY KEY, target TEXT, captured_at REAL,
                engine_version TEXT, schema_version INTEGER, state TEXT);
            """)
            self.conn.execute(
                "INSERT OR REPLACE INTO snapshot_meta(id, target, captured_at,"
                " engine_version, schema_version, state)"
                " VALUES('__schema__', '', 0, '', ?, '')",
                (SCHEMA_VERSION,))

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

    # -- snapshot persistence -------------------------------------------

    def save_snapshot(self, target, state):
        """Insert a new snapshot row for target. Returns its id."""
        sid = (f"{int(time.time())}-"
               f"{hashlib.sha256(target.encode()).hexdigest()[:8]}-"
               f"{uuid.uuid4().hex[:6]}")
        with self.conn:
            self.conn.execute(
                "INSERT INTO snapshot_meta(id, target, captured_at,"
                " engine_version, schema_version, state) VALUES(?,?,?,?,?,?)",
                (sid, target, time.time(), ENGINE_VERSION, SCHEMA_VERSION,
                 _json.dumps(state, sort_keys=True)))
        return sid

    def latest_snapshot(self, target):
        """Return the state dict of the most recent snapshot for target,
        or None when no snapshot exists yet."""
        row = self.conn.execute(
            "SELECT state FROM snapshot_meta WHERE target=? AND id<>'__schema__' "
            "ORDER BY captured_at DESC LIMIT 1", (target,)).fetchone()
        if not row:
            return None
        try:
            return _json.loads(row["state"])
        except Exception:
            return None

    def list_snapshots(self, target=None):
        sql = ("SELECT id, target, captured_at, engine_version, schema_version"
               " FROM snapshot_meta WHERE id<>'__schema__'")
        args = []
        if target:
            sql += " AND target=?"
            args.append(target)
        sql += " ORDER BY captured_at DESC"
        return [dict(r) for r in self.conn.execute(sql, args)]


# ------------------------------------------------------------ capture

def capture_snapshot(target, crawler_output):
    """Normalize crawler output (a list of endpoint dicts, as the ctx surface
    produces: url/params/method, plus optional status/body/headers) into a
    snapshot state dict."""
    endpoints = []
    for raw in crawler_output or []:
        if not isinstance(raw, dict):
            continue
        url = str(raw.get("url") or raw.get("endpoint") or "").strip()
        if not url:
            continue
        method = str(raw.get("method") or "GET").upper()
        params = raw.get("params") or []
        if isinstance(params, str):
            params = [params]
        endpoints.append({
            "url": url,
            "method": method,
            "params": [str(p) for p in params],
            "status_class": _status_class(raw.get("status")),
            "body_hash": _body_hash(raw.get("body")),
            "header_sig": _header_sig(raw.get("headers")),
        })
    return {
        "endpoints": endpoints,
        "discovered_at": time.time(),
        "engine_version": ENGINE_VERSION,
    }


# ------------------------------------------------------------ diff

def _ep_key(ep):
    return (ep.get("url", ""), ep.get("method", ""))


def _rank_score(ep, body_changed=False):
    """Attack-priori heuristic score for an endpoint record."""
    score = len(ep.get("params") or []) * _W_PARAMS
    if (ep.get("method") or "").upper() == "POST":
        score += _W_POST
    sc = ep.get("status_class") or ""
    if sc == "5xx":
        score += _W_5XX
    elif sc == "4xx":
        score += _W_4XX
    if body_changed:
        score += _W_BODY_CHANGE
    return score


def diff_snapshots(old, new):
    """Diff two snapshot state dicts.

    Returns {added_endpoints, removed_endpoints, changed_endpoints, risk_rank}
    where changed_endpoints entries carry params added/removed, status_class
    change, body_hash change. added/changed entries get a 'risk_rank' score
    (higher = more attack-worthy first)."""
    old = old or {"endpoints": []}
    new = new or {"endpoints": []}
    old_eps = {_ep_key(e): e for e in old.get("endpoints", [])}
    new_eps = {_ep_key(e): e for e in new.get("endpoints", [])}

    added = sorted(
        ({"url": e.get("url"), "method": e.get("method"),
          "params": e.get("params") or [], "status_class": e.get("status_class"),
          "body_hash": e.get("body_hash"),
          "risk_rank": _rank_score(e)} for k, e in new_eps.items()
         if k not in old_eps),
        key=lambda d: -d["risk_rank"])

    removed = [{"url": e.get("url"), "method": e.get("method")}
               for k, e in old_eps.items() if k not in new_eps]

    changed = []
    for k, ne in new_eps.items():
        oe = old_eps.get(k)
        if oe is None:
            continue
        old_params = set(oe.get("params") or [])
        new_params = set(ne.get("params") or [])
        p_added = sorted(new_params - old_params)
        p_removed = sorted(old_params - new_params)
        sc_change = oe.get("status_class") != ne.get("status_class")
        body_change = (oe.get("body_hash") != ne.get("body_hash")
                       and bool(ne.get("body_hash")))
        if not (p_added or p_removed or sc_change or body_change):
            continue
        changed.append({
            "url": ne.get("url"), "method": ne.get("method"),
            "params_added": p_added, "params_removed": p_removed,
            "status_class_change": [oe.get("status_class"),
                                    ne.get("status_class")] if sc_change else None,
            "body_hash_change": body_change,
            "risk_rank": _rank_score(ne, body_changed=body_change),
        })
    changed.sort(key=lambda d: -d["risk_rank"])

    return {"added_endpoints": added, "removed_endpoints": removed,
            "changed_endpoints": changed,
            "risk_rank": sorted(
                [d["risk_rank"] for d in added + changed], reverse=True)}


# ------------------------------------------------------------ attack plans

# param-name -> vulnerability class guesses, checked case-insensitively
_PARAM_CLASS_HINTS = [
    (("id", "uid", "user_id", "userid"), "idor"),
    (("q", "query", "search", "keyword"), "sqli/xss"),
    (("file", "path", "filename", "doc"), "traversal"),
    (("url", "uri", "redirect", "target", "next"), "ssrf"),
]


def _class_guess(params):
    for p in params:
        pl = str(p).lower()
        for hints, cls in _PARAM_CLASS_HINTS:
            if pl in hints:
                return cls
    return "fuzz"


def plan_attacks(diff):
    """For each added/changed endpoint emit attack plan dicts:
    {id, url, method, class, params, probe_steps}."""
    plans = []
    n = 0

    def _plan(ep, params, note):
        nonlocal n
        n += 1
        plans.append({
            "id": f"td-{n:03d}",
            "url": ep["url"],
            "method": ep.get("method") or "GET",
            "class": _class_guess(params),
            "params": params,
            "note": note,
            "probe_steps": [
                {"step": 1, "action": "baseline-request",
                 "spec": f"Send a benign {ep.get('method') or 'GET'} to "
                         f"{ep['url']} and record status/body as baseline."},
                {"step": 2, "action": "param-probe",
                 "spec": f"Probe parameters {params or '[]'} with class-"
                         f"appropriate payloads ({_class_guess(params)})."},
                {"step": 3, "action": "compare",
                 "spec": "Compare status_class and body against the baseline; "
                         "report only differences confirmed against baseline."},
            ],
        })

    for ep in diff.get("added_endpoints", []):
        _plan(ep, ep.get("params") or [], "newly discovered endpoint")
    for ch in diff.get("changed_endpoints", []):
        _plan(ch, ch.get("params_added") or [], "endpoint changed since last snapshot")
    return plans


# ------------------------------------------------------------ orchestrator

def run_timediff(store_path, target, crawler_output, log=None):
    """Capture a snapshot for target, diff it against the previous snapshot,
    emit attack plans and a summary finding. Requires env PTK_TIMEDIFF=1.

    The summary finding uses vulnscan2.F (lazy import):
      - verification 'differential' when a body_hash actually changed,
      - 'static-analysis' for new endpoints,
      - 'manual-required' when only the risk rank justifies attention."""
    if os.environ.get("PTK_TIMEDIFF") != "1":
        raise PermissionError(
            "run_timediff is operator-gated: set PTK_TIMEDIFF=1 to allow it")

    log = log if log is not None else []
    store = SnapshotStore(store_path)
    try:
        prev = store.latest_snapshot(target)
        state = capture_snapshot(target, crawler_output)
        sid = store.save_snapshot(target, state)
        if prev is None:
            diff = {"added_endpoints": [], "removed_endpoints": [],
                    "changed_endpoints": [], "risk_rank": []}
            baseline = True
        else:
            diff = diff_snapshots(prev, state)
            baseline = False
        plans = plan_attacks(diff)
    finally:
        store.close()

    body_changed = any(c.get("body_hash_change")
                       for c in diff["changed_endpoints"])
    n_added = len(diff["added_endpoints"])
    n_changed = len(diff["changed_endpoints"])
    log.append(f"[timediff] {target}: snapshot {sid} captured "
               f"({len(state['endpoints'])} endpoints, "
               f"{'first baseline' if baseline else 'diff vs previous'})")

    import vulnscan2
    if baseline:
        finding = vulnscan2.F(
            "info",
            f"Time-diff baseline established for {target}",
            f"First snapshot captured with {len(state['endpoints'])} endpoints "
            f"(snapshot {sid}). Subsequent runs will be diffed against it.",
            evidence=f"snapshot={sid}", location=target,
            confidence="candidate",
            verification="static-analysis",
            verification_note="Baseline capture only: no differential evidence exists yet.")
    elif not (n_added or n_changed):
        finding = vulnscan2.F(
            "info",
            f"Time-diff: no surface changes for {target}",
            f"Snapshot {sid} matches the previous snapshot — no added, removed "
            f"or changed endpoints.",
            evidence=f"snapshot={sid}", location=target,
            confidence="confirmed", verification="differential")
    else:
        if body_changed:
            verif, conf = "differential", "confirmed"
            ver_note = ("Response body hashes actually changed between "
                        "snapshots — differential evidence, not a static guess.")
        elif n_added:
            verif, conf = "static-analysis", "probable"
            ver_note = ("New endpoints detected by crawl comparison only; "
                        "probes required to confirm exploitability.")
        else:
            verif, conf = "manual-required", "candidate"
            ver_note = ("Only a risk-rank heuristic justified attention; "
                        "manual verification required before reporting.")
        finding = vulnscan2.F(
            "medium" if body_changed else "low",
            f"Time-diff: {n_added} new / {n_changed} changed endpoints on {target}",
            f"Differential scan of the application surface: {n_added} added, "
            f"{n_changed} changed, {len(diff['removed_endpoints'])} removed "
            f"endpoints versus the previous snapshot.",
            evidence=f"snapshot={sid}; risk_rank={diff['risk_rank'][:5]}",
            location=target, confidence=conf,
            verification=verif, verification_note=ver_note)
        finding["attack_plans"] = plans

    return {"snapshot_id": sid, "baseline": baseline,
            "diff": diff, "plans": plans, "finding": finding,
            "endpoint_count": len(state["endpoints"]), "log": log}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Time-travel differential scanner (operator-gated)")
    ap.add_argument("--store", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--crawler", required=True, help="JSON file with crawler output")
    ap.add_argument("--json-out", action="store_true")
    ns = ap.parse_args(argv)
    if os.environ.get("PTK_TIMEDIFF") != "1":
        print("timediff: set PTK_TIMEDIFF=1 to run", file=sys.stderr)
        return 3
    with open(ns.crawler, encoding="utf-8") as fh:
        crawler_output = _json.load(fh)
    rep = run_timediff(ns.store, ns.target, crawler_output)
    if ns.json_out:
        print(_json.dumps(rep, indent=1, ensure_ascii=False, default=str))
    else:
        f = rep["finding"]
        print(f"[timediff] {ns.target}: {rep['endpoint_count']} endpoints, "
              f"{len(rep['diff']['added_endpoints'])} added, "
              f"{len(rep['diff']['changed_endpoints'])} changed, "
              f"{len(rep['plans'])} attack plans")
        print(f"  [{f.get('severity')}] {f.get('title')} "
              f"(verification: {f.get('verification')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
