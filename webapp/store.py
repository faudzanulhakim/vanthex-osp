"""SQLite storage layer (stdlib only).

Upgrade v3:
- verify_user uses hmac.compare_digest (anti timing-attack).
- The findings table migrates automatically: confidence + location + param columns
  (old v2 DBs stay open; ALTER runs only if the column does not exist yet).
- dashboard_stats extended: unique targets, risk trend across the last 10 scans.
- diff_scans(): compare a scan with the previous scan for the same target+profile.
"""
import hmac
import json
import os
import sqlite3
import time
import uuid

_BASE = os.path.dirname(os.path.abspath(__file__))
if not os.path.exists(os.path.join(_BASE, "requirements.txt")):
    _BASE = os.path.dirname(_BASE)  # project root when module lives in webapp/
DB_PATH = os.path.join(_BASE, "toolkit.db")

# Set by init_db() when the first admin is seeded without PTK_ADMIN_PW:
# a generated random password, surfaced once at startup by the caller.
GENERATED_ADMIN_PW = None


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _migrate(c):
    cols = {r[1] for r in c.execute("PRAGMA table_info(findings)")}
    for col, ddl in [("confidence", "ALTER TABLE findings ADD COLUMN confidence TEXT DEFAULT 'probable'"),
                     ("location", "ALTER TABLE findings ADD COLUMN location TEXT DEFAULT ''"),
                     ("param", "ALTER TABLE findings ADD COLUMN param TEXT DEFAULT ''"),
                     ("origin", "ALTER TABLE findings ADD COLUMN origin TEXT DEFAULT 'active'")]:
        if col not in cols:
            c.execute(ddl)


def init_db():
    with _db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS scans(
            id TEXT PRIMARY KEY, target TEXT, scan_type TEXT, profile TEXT,
            started_at REAL, finished_at REAL, status TEXT,
            overall_risk TEXT, summary TEXT, result TEXT);
        CREATE TABLE IF NOT EXISTS findings(
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, severity TEXT,
            title TEXT, description TEXT, evidence TEXT, cwe TEXT, owasp TEXT,
            cvss REAL, remediation TEXT,
            confidence TEXT DEFAULT 'probable', location TEXT DEFAULT '',
            param TEXT DEFAULT '', origin TEXT DEFAULT 'active');
        CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY, salt TEXT, hash TEXT, role TEXT);
        CREATE TABLE IF NOT EXISTS cve_cache(
            cve_id TEXT PRIMARY KEY, published TEXT, modified TEXT,
            description TEXT, cvss REAL, severity TEXT, weaknesses TEXT,
            refs TEXT, fetched_at TEXT);
        CREATE TABLE IF NOT EXISTS suppressions(
            id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT, title TEXT,
            created_by TEXT, ts TEXT);
        CREATE TABLE IF NOT EXISTS schema_meta(k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE IF NOT EXISTS target_secrets(
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, host TEXT,
            kind TEXT, username TEXT, secret_enc TEXT, created_by TEXT,
            ts TEXT);
        """)
        _migrate(c)
        # v1.2.4 roles: legacy rows (pre-roles 'analyst' default, NULL, or
        # any unknown value) become 'operator'; 'admin' rows are untouched,
        # so existing single-admin installs keep working unchanged.
        c.execute("UPDATE users SET role='operator' "
                  "WHERE role IS NULL OR role NOT IN ('admin','operator','viewer')")
        c.execute("INSERT OR REPLACE INTO schema_meta(k, v) VALUES"
                  "('schema_version', '3')")
        if not c.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            import hashlib, secrets
            pw = os.environ.get("PTK_ADMIN_PW", "").strip()
            if not pw:
                # No known default password: generate a strong random
                # one; app2 surfaces it once at this first startup.
                global GENERATED_ADMIN_PW
                pw = secrets.token_urlsafe(18)
                GENERATED_ADMIN_PW = pw
            salt = secrets.token_hex(16)
            h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()
            c.execute("INSERT INTO users VALUES('admin',?,?, 'admin')", (salt, h))

        # One-time audit chain repair: pre-v3.15.0 forks/legacy rows made
        # the walk below fail -> the chain is recomputed from the stored
        # fields (log content is not changed). The next startup passes
        # without repair.
        try:
            _ensure_audit_chain(c)
            rows = c.execute("SELECT id,ts,username,action,detail,hash,prev "
                             "FROM audit_log ORDER BY id").fetchall()
            prev, broken = "GENESIS", False
            for r in rows:
                if r["hash"] is None or r["prev"] != prev or \
                        r["hash"] != _audit_digest(r["prev"], r["ts"],
                                                   r["username"], r["action"],
                                                   r["detail"]):
                    broken = True
                    break
                prev = r["hash"]
            if broken and rows:
                _rechain_audit(c)
        except Exception:
            pass


def create_user(username, password, role="operator"):
    import hashlib, secrets
    # v1.2.4 roles: only known roles are storable; unknown values collapse
    # to the least-privilege default instead of silently escalating.
    import rbac as _rbac
    role = _rbac.normalize_role(role if str(role).strip() else "operator")
    # An account with no name or an empty/weak password must never
    # come into being: the PBKDF2 hash of an empty password can still be
    # used to log in, so validation must also live in the storage layer —
    # not only at the endpoint.
    if not str(username).strip():
        raise ValueError("username is required")
    if not password or len(str(password)) < 8:
        raise ValueError("password must be at least 8 characters")
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()
    with _db() as c:
        c.execute("INSERT INTO users VALUES(?,?,?,?)", (username, salt, h, role))


def verify_user(username, password):
    import hashlib
    with _db() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        # still do a dummy pbkdf2 so timing does not leak whether the user exists
        hashlib.pbkdf2_hmac("sha256", password.encode(), b"0" * 16, 200_000)
        return None
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), row["salt"].encode(), 200_000).hex()
    if hmac.compare_digest(h, row["hash"]):
        return {"username": row["username"], "role": row["role"]}
    return None


def save_scan(target, scan_type, profile, result):
    scan_id = uuid.uuid4().hex[:12]
    now = time.time()
    with _db() as c:
        _migrate_v32(c)  # findings.status must exist for baseline rows
        c.execute("INSERT INTO scans VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (scan_id, target, scan_type, profile, now, now, "completed",
                   result.get("overall_risk", "-"),
                   json.dumps(result.get("summary", {})),
                   json.dumps(result, default=str)))
        for f in result.get("findings", []):
            cur = c.execute("INSERT INTO findings(scan_id,severity,title,description,"
                      "evidence,cwe,owasp,cvss,remediation,confidence,location,param,origin,verification) "
                      "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (scan_id, f.get("severity"), f.get("title"), f.get("description"),
                       f.get("evidence", ""), f.get("cwe", ""), f.get("owasp", ""),
                       f.get("cvss", 0), f.get("remediation", ""),
                       f.get("confidence", "probable"), f.get("location", ""),
                       f.get("param", ""), f.get("origin", "active"),
                       f.get("verification", "")))
            if f.get("baseline_suppressed"):
                # K3 (v1.7.0): the finding stays listed, with the
                # auditable triage status 'suppressed' (baseline).
                c.execute("UPDATE findings SET status='suppressed' "
                          "WHERE id=?", (cur.lastrowid,))
    return scan_id


# ------------------------------------------------------- secret baseline
# Operator baseline for known/accepted secret values (WS5, v1.7.0),
# detect-secrets style: entries keyed by the SHA-256 of the value.
# Raw secret values are NEVER stored — only their hashes, a label and
# a reason. A scan finding whose value hashes to a baseline entry is
# kept and displayed with status 'suppressed' (see save_scan).

def list_secret_baseline():
    with _db() as c:
        _migrate_v34(c)
        return [dict(r) for r in c.execute(
            "SELECT hash,kind,label,reason,added_by,added_at "
            "FROM secret_baseline ORDER BY added_at DESC")]


def add_secret_baseline(hash_, kind, label, reason, added_by):
    with _db() as c:
        _migrate_v34(c)
        c.execute("INSERT INTO secret_baseline(hash,kind,label,reason,"
                  "added_by,added_at) VALUES(?,?,?,?,?,?) "
                  "ON CONFLICT(hash) DO UPDATE SET kind=excluded.kind,"
                  "label=excluded.label, reason=excluded.reason,"
                  "added_by=excluded.added_by, added_at=excluded.added_at",
                  (str(hash_)[:64], str(kind)[:40], str(label)[:120],
                   str(reason)[:300], str(added_by)[:60], time.time()))
    return True


def remove_secret_baseline(hash_):
    with _db() as c:
        _migrate_v34(c)
        cur = c.execute("DELETE FROM secret_baseline WHERE hash=?",
                        (str(hash_)[:64],))
        return cur.rowcount > 0


def list_scans(limit=100):
    with _db() as c:
        rows = c.execute("SELECT id,target,scan_type,profile,started_at,status,"
                         "overall_risk,summary FROM scans ORDER BY started_at DESC LIMIT ?",
                         (limit,)).fetchall()
        return [dict(r) for r in rows]


def get_scan(scan_id):
    with _db() as c:
        row = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None


def get_findings(scan_id):
    with _db() as c:
        rows = c.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY cvss DESC",
                         (scan_id,)).fetchall()
        return [dict(r) for r in rows]


def cleanup_orphan_findings():
    """Delete findings whose scan no longer exists (legacy DB leftovers /
    non-cascading deletions). Called from delete_scan and
    delete_asset so the findings list never shows orphans."""
    with _db() as c:
        n = c.execute(
            "DELETE FROM findings WHERE scan_id NOT IN (SELECT id FROM scans)"
        ).rowcount
    return n


def delete_scan(scan_id):
    with _db() as c:
        c.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        c.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    cleanup_orphan_findings()
    return True


def _key(f):
    return (f["title"], f.get("location") or "", f.get("param") or "")


def diff_scans(scan_id):
    """Compare this scan vs the previous scan (same target+scan_type+profile)."""
    cur = get_scan(scan_id)
    if not cur:
        return None
    with _db() as c:
        prev = c.execute(
            "SELECT id, started_at FROM scans WHERE target=? AND scan_type=? "
            "AND profile=? AND started_at<? ORDER BY started_at DESC LIMIT 1",
            (cur["target"], cur["scan_type"], cur["profile"], cur["started_at"])).fetchone()
    cur_f = {_key(f): f for f in get_findings(scan_id)}
    if not prev:
        return {"previous_scan_id": None,
                "new": [f["title"] for f in cur_f.values()],
                "resolved": [], "unchanged": 0}
    prev_f = {_key(f): f for f in get_findings(prev["id"])}
    new = [cur_f[k]["title"] for k in cur_f.keys() - prev_f.keys()]
    resolved = [prev_f[k]["title"] for k in prev_f.keys() - cur_f.keys()]
    unchanged = len(cur_f.keys() & prev_f.keys())
    return {"previous_scan_id": prev["id"], "previous_started_at": prev["started_at"],
            "new": new, "resolved": resolved, "unchanged": unchanged}


def dashboard_stats():
    with _db() as c:
        total = c.execute("SELECT COUNT(*) n FROM scans").fetchone()["n"]
        targets = c.execute("SELECT COUNT(DISTINCT target) n FROM scans").fetchone()["n"]
        by_sev = {}
        for r in c.execute("SELECT severity, COUNT(*) n FROM findings GROUP BY severity"):
            by_sev[r["severity"]] = r["n"]
        by_conf = {}
        try:
            for r in c.execute("SELECT confidence, COUNT(*) n FROM findings GROUP BY confidence"):
                by_conf[r["confidence"] or "probable"] = r["n"]
        except sqlite3.OperationalError:
            pass
        by_owasp = {}
        for r in c.execute("SELECT owasp, COUNT(*) n FROM findings GROUP BY owasp"):
            if r["owasp"]:
                by_owasp[r["owasp"]] = r["n"]
        recent = c.execute("SELECT target, overall_risk, started_at, profile FROM scans "
                           "ORDER BY started_at DESC LIMIT 10").fetchall()
        return {"total_scans": total, "total_targets": targets,
                "by_severity": by_sev, "by_confidence": by_conf,
                "by_owasp": by_owasp,
                "recent": [dict(r) for r in recent]}


# ------------------------------------------------------------ v3.2 enterprise

FINDING_STATUSES = ("open", "confirmed", "false_positive", "fixed",
                    "suppressed")


def _migrate_v32(c):
    cols = {r[1] for r in c.execute("PRAGMA table_info(findings)")}
    if "status" not in cols:
        c.execute("ALTER TABLE findings ADD COLUMN status TEXT DEFAULT 'open'")
    c.executescript("""
    CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, username TEXT,
        action TEXT, detail TEXT);
    CREATE TABLE IF NOT EXISTS schedules(
        id TEXT PRIMARY KEY, target TEXT, profile TEXT, interval_h REAL,
        next_run REAL, enabled INTEGER DEFAULT 1, created_by TEXT, created_at REAL);
    """)
    # v1.2.3 scheduler windows: optional 'window' (JSON) + 'diff_mode' flag
    # on existing schedules tables (backward compatible ALTER).
    scols = {r[1] for r in c.execute("PRAGMA table_info(schedules)")}
    if scols and "window" not in scols:
        c.execute("ALTER TABLE schedules ADD COLUMN window TEXT")
    if scols and "diff_mode" not in scols:
        c.execute("ALTER TABLE schedules ADD COLUMN diff_mode INTEGER DEFAULT 0")
    # v1.2.3: operator-facing verification result on findings (nullable).
    if "verification" not in cols:
        c.execute("ALTER TABLE findings ADD COLUMN verification TEXT")



def init_v32():
    with _db() as c:
        _migrate_v32(c)


def set_finding_status(finding_id, status):
    if status not in FINDING_STATUSES:
        raise ValueError('invalid status')
    with _db() as c:
        cur = c.execute("UPDATE findings SET status=? WHERE id=?", (status, finding_id))
        return cur.rowcount > 0


def list_findings_global(limit=200, severity="", status="", q=""):
    sql = ("SELECT f.*, s.target, s.profile, s.started_at FROM findings f "
           "JOIN scans s ON s.id=f.scan_id WHERE 1=1")
    args = []
    if severity:
        sql += " AND f.severity=?"; args.append(severity)
    if status:
        sql += " AND COALESCE(f.status,'open')=?"; args.append(status)
    if q:
        sql += " AND (f.title LIKE ? OR s.target LIKE ? OR f.cwe LIKE ?)"
        args += [f"%{q}%"] * 3
    sql += " ORDER BY f.cvss DESC LIMIT ?"; args.append(int(limit))
    with _db() as c:
        _migrate_v32(c)
        return [dict(r) for r in c.execute(sql, args)]


import threading as _threading
_AUDIT_LOCK = _threading.Lock()


def _audit_digest(prev, ts, username, action, detail):
    import hashlib as _hl
    return _hl.sha256(
        f"{prev}|{ts}|{username}|{action}|{detail}".encode()).hexdigest()


def _rechain_audit(c):
    """Recompute the hash chain of the entire audit_log from the stored fields
    (ts/username/action/detail are NOT changed — only the hash/prev links).
    Repairs forks caused by pre-v3.15.0 concurrent writers and assigns hashes
    to old pre-chain rows. Returns the number of rows chained."""
    rows = c.execute("SELECT id,ts,username,action,detail FROM audit_log "
                     "ORDER BY id").fetchall()
    prev = "GENESIS"
    n = 0
    for r in rows:
        h = _audit_digest(prev, r["ts"], r["username"], r["action"],
                          r["detail"])
        c.execute("UPDATE audit_log SET hash=?, prev=? WHERE id=?",
                  (h, prev, r["id"]))
        prev = h
        n += 1
    return n


def _ensure_audit_chain(c):
    cols = [r[1] for r in c.execute("PRAGMA table_info(audit_log)")]
    if "hash" not in cols:
        c.execute("ALTER TABLE audit_log ADD COLUMN hash TEXT")
        c.execute("ALTER TABLE audit_log ADD COLUMN prev TEXT")


def audit(username, action, detail=""):
    ts = time.time()
    detail = str(detail)[:300]
    # Mandatory lock: without it, two concurrent requests read the same prev
    # and the chain forks (verified fork on pre-v3.15.0 data).
    with _AUDIT_LOCK:
        with _db() as c:
            _migrate_v32(c)
            _ensure_audit_chain(c)
            row = c.execute("SELECT hash FROM audit_log WHERE hash IS NOT NULL "
                            "ORDER BY id DESC LIMIT 1").fetchone()
            prev = (row[0] if row and row[0] else "GENESIS")
            h = _audit_digest(prev, ts, username, action, detail)
            c.execute("INSERT INTO audit_log(ts,username,action,detail,hash,prev) "
                      "VALUES(?,?,?,?,?,?)", (ts, username, action, detail, h, prev))


def verify_audit_chain():
    """Verify the audit log hash chain -> (ok, broken_row_id_or_None)."""
    import hashlib as _hl
    with _db() as c:
        _ensure_audit_chain(c)
        rows = c.execute("SELECT id,ts,username,action,detail,hash,prev "
                         "FROM audit_log ORDER BY id").fetchall()
    prev = "GENESIS"
    for r in rows:
        if r["hash"] is None:      # old row from before hash-chaining: skip
            continue
        expect = _audit_digest(r["prev"], r["ts"], r["username"],
                               r["action"], r["detail"])
        if r["prev"] != prev or r["hash"] != expect:
            return False, r["id"]
        prev = r["hash"]
    return True, None


def list_audit(limit=100):
    with _db() as c:
        _migrate_v32(c)
        return [dict(r) for r in c.execute(
            "SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,))]


def list_users():
    with _db() as c:
        return [{"username": r["username"], "role": r["role"]}
                for r in c.execute("SELECT username, role FROM users ORDER BY username")]


def assets_summary():
    """Per-target aggregation: scan count, last scan, latest risk & score, open findings."""
    with _db() as c:
        _migrate_v32(c)
        _migrate_v34(c)
        scans = [dict(r) for r in c.execute(
            "SELECT id,target,profile,started_at,overall_risk,result FROM scans "
            "ORDER BY started_at DESC")]
        open_counts = {}
        for r in c.execute("SELECT s.target t, COUNT(*) n FROM findings f JOIN scans s "
                           "ON s.id=f.scan_id WHERE COALESCE(f.status,'open') NOT IN "
                           "('false_positive','fixed','suppressed') GROUP BY s.target"):
            open_counts[r["t"]] = r["n"]
    assets = {}
    for s in scans:
        a = assets.setdefault(s["target"], {"target": s["target"], "scans": 0,
                                            "last_scan": 0, "latest_risk": "-",
                                            "latest_score": None, "latest_scan_id": None,
                                            "profile": s["profile"]})
        a["scans"] += 1
        if s["started_at"] > a["last_scan"]:
            a["last_scan"] = s["started_at"]
            a["latest_risk"] = s["overall_risk"]
            a["latest_scan_id"] = s["id"]
            a["profile"] = s["profile"]
            try:
                a["latest_score"] = json.loads(s["result"] or "{}").get("risk_score")
            except Exception:
                a["latest_score"] = None
    for a in assets.values():
        a["open_findings"] = open_counts.get(a["target"], 0)
    return sorted(assets.values(), key=lambda x: -x["last_scan"])


def create_schedule(target, profile, interval_h, created_by,
                    window=None, diff_mode=False):
    sid = uuid.uuid4().hex[:10]
    now = time.time()
    win_json = json.dumps(window) if window else None
    with _db() as c:
        _migrate_v32(c)
        c.execute("INSERT INTO schedules(id,target,profile,interval_h,next_run,"
                  "enabled,created_by,created_at,window,diff_mode) "
                  "VALUES(?,?,?,?,?,1,?,?,?,?)",
                  (sid, target, profile, float(interval_h),
                   now + float(interval_h) * 3600, created_by, now,
                   win_json, 1 if diff_mode else 0))
    return sid


def list_schedules():
    with _db() as c:
        _migrate_v32(c)
        out = []
        for r in c.execute("SELECT * FROM schedules ORDER BY created_at DESC"):
            d = dict(r)
            try:
                d["window"] = json.loads(d["window"]) if d.get("window") else None
            except Exception:
                d["window"] = None
            d["diff_mode"] = bool(d.get("diff_mode"))
            out.append(d)
        return out


def delete_schedule(sid):
    with _db() as c:
        _migrate_v32(c)
        c.execute("DELETE FROM schedules WHERE id=?", (sid,))


def set_schedule_enabled(sid, enabled):
    with _db() as c:
        _migrate_v32(c)
        c.execute("UPDATE schedules SET enabled=? WHERE id=?", (1 if enabled else 0, sid))


def due_schedules():
    now = time.time()
    with _db() as c:
        _migrate_v32(c)
        return [dict(r) for r in c.execute(
            "SELECT * FROM schedules WHERE enabled=1 AND next_run<=?", (now,))]


def mark_schedule_ran(sid, interval_h):
    with _db() as c:
        _migrate_v32(c)
        c.execute("UPDATE schedules SET next_run=? WHERE id=?",
                  (time.time() + float(interval_h) * 3600, sid))


# ------------------------------------------------- schedule windows (v1.2.3)
# Days use Python weekday numbering: 0=Monday .. 6=Sunday, matching
# time.localtime().tm_wday. Times are server local time, 'HH:MM'.

_WINDOW_RE = __import__("re").compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")


def parse_schedule_window(raw):
    """Normalize a schedule window. Returns {'days': [...], 'start': 'HH:MM',
    'end': 'HH:MM'} or None when absent/invalid. Invalid raises nothing at
    the parse level — callers distinguish absent (raw falsy) vs invalid."""
    if not isinstance(raw, dict):
        return None
    start = str(raw.get("start", ""))
    end = str(raw.get("end", ""))
    if not _WINDOW_RE.match(start) or not _WINDOW_RE.match(end):
        return None
    days = raw.get("days", [0, 1, 2, 3, 4, 5, 6])
    if not isinstance(days, list):
        return None
    try:
        days = sorted({int(d) for d in days})
    except (TypeError, ValueError):
        return None
    if not days or any(d < 0 or d > 6 for d in days):
        return None
    return {"days": days, "start": start, "end": end}


def _window_minutes(hhmm):
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def _in_window(window, ts):
    """Is local timestamp ts inside the window? Start inclusive, end
    exclusive; end < start means an overnight window spanning midnight —
    the early-morning part belongs to the previous day's slot."""
    lt = time.localtime(ts)
    days = set(window["days"])
    t = lt.tm_hour * 60 + lt.tm_min
    s = _window_minutes(window["start"])
    e = _window_minutes(window["end"])
    if s <= e:
        return lt.tm_wday in days and s <= t < e
    # overnight: late-evening side on the start day ...
    if t >= s and lt.tm_wday in days:
        return True
    # ... early-morning side on the day after the start day.
    if t < e:
        return (lt.tm_wday - 1) % 7 in days
    return False


def window_fire(window, next_run, now=None):
    """Decide whether a due schedule should fire now.

    Returns (fire, catchup). Without a window everything is (True, False) —
    fully backward compatible. With a window:
      - inside the window right now -> fire normally;
      - outside the window but a full window slot already elapsed since
        next_run (e.g. server was down) -> fire once with catchup=True;
      - otherwise -> wait for the next window."""
    now = time.time() if now is None else now
    w = parse_schedule_window(window)
    if not w:
        return True, False
    if _in_window(w, now):
        return True, False
    import datetime as _dt
    base = _dt.datetime.fromtimestamp(now)
    for back in range(0, 8):
        day = base - _dt.timedelta(days=back)
        if day.weekday() not in set(w["days"]):
            continue
        s = _window_minutes(w["start"])
        e = _window_minutes(w["end"])
        wstart = day.replace(hour=s // 60, minute=s % 60,
                             second=0, microsecond=0).timestamp()
        wend_day = day if e > s or e == s else day + _dt.timedelta(days=1)
        wend = wend_day.replace(hour=e // 60, minute=e % 60,
                                second=0, microsecond=0).timestamp()
        if wstart >= float(next_run) and wend <= now:
            return True, True
    return False, False


def scan_diff_summary(scan_id, max_items=20):
    """Compact diff summary for the scheduler: {'new': n, 'resolved': n,
    'by_severity': {...}, 'new_titles': [...], 'resolved_titles': [...]}
    with the title lists bounded to max_items (diff summary max 20 lines)."""
    d = diff_scans(scan_id)
    if d is None:
        return None
    by_sev = {}
    if d["new"]:
        sev_by_title = {}
        for f in get_findings(scan_id):
            sev_by_title.setdefault(f["title"], f.get("severity") or "info")
        for title in d["new"]:
            s = sev_by_title.get(title, "info")
            by_sev[s] = by_sev.get(s, 0) + 1
    return {"new": len(d["new"]), "resolved": len(d["resolved"]),
            "by_severity": by_sev,
            "new_titles": d["new"][:max_items],
            "resolved_titles": d["resolved"][:max_items]}


def stats_extended():
    """14-day scan trend + top targets + recent findings for the enterprise dashboard.
    v3.3+: posture_trend (risk score per scan, chronological) + a
    cross-check matrix of severity x confidence (joint distribution, not two
    separate aggregates) + aggregate triage status — all from real DB data."""
    import datetime
    with _db() as c:
        _migrate_v32(c)
        rows = c.execute("SELECT started_at FROM scans").fetchall()
        recent_f = [dict(r) for r in c.execute(
            "SELECT f.severity, f.title, f.confidence, f.cvss, s.target, s.started_at "
            "FROM findings f JOIN scans s ON s.id=f.scan_id ORDER BY s.started_at DESC, "
            "f.cvss DESC LIMIT 8")]
        scan_rows = [dict(r) for r in c.execute(
            "SELECT id, target, scan_type, profile, started_at, overall_risk, result "
            "FROM scans ORDER BY started_at ASC")]
        matrix_rows = [dict(r) for r in c.execute(
            "SELECT severity, COALESCE(confidence,'probable') conf, COUNT(*) n "
            "FROM findings GROUP BY severity, conf")]
        triage_rows = [dict(r) for r in c.execute(
            "SELECT COALESCE(status,'open') st, COUNT(*) n FROM findings GROUP BY st")]
    days = {}
    today = datetime.date.today()
    for i in range(13, -1, -1):
        days[(today - datetime.timedelta(days=i)).isoformat()] = 0
    for r in rows:
        d = datetime.date.fromtimestamp(r["started_at"]).isoformat()
        if d in days:
            days[d] += 1
    trend = [{"date": k, "scans": v} for k, v in days.items()]
    posture_trend = []
    for s in scan_rows:
        try:
            score = json.loads(s["result"] or "{}").get("risk_score")
        except Exception:
            score = None
        if score is None:
            continue
        posture_trend.append({"scan_id": s["id"], "target": s["target"],
                              "scan_type": s["scan_type"], "profile": s["profile"],
                              "started_at": s["started_at"],
                              "overall_risk": s["overall_risk"], "score": score})
    posture_trend = posture_trend[-40:]
    crosscheck = {}
    for r in matrix_rows:
        crosscheck.setdefault(r["severity"], {})[r["conf"]] = r["n"]
    triage = {r["st"]: r["n"] for r in triage_rows}
    assets = assets_summary()
    scores = [a["latest_score"] for a in assets if a["latest_score"] is not None]
    posture = round(sum(scores) / len(scores)) if scores else None
    return {"trend": trend, "top_targets": assets[:5],
            "recent_findings": recent_f, "posture_score": posture,
            "posture_trend": posture_trend, "crosscheck_matrix": crosscheck,
            "by_triage_status": triage}


# ------------------------------------------------------------ v3.4 enterprise+

SLA_DAYS = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180, "INFO": 365}
ASSET_CRITICALITY = ("critical", "high", "medium", "low")


def _migrate_v34(c):
    cols = {r[1] for r in c.execute("PRAGMA table_info(findings)")}
    for col, ddl in [
            ("assignee", "ALTER TABLE findings ADD COLUMN assignee TEXT DEFAULT ''"),
            ("due_date", "ALTER TABLE findings ADD COLUMN due_date TEXT DEFAULT ''"),
            ("status_changed_at",
             "ALTER TABLE findings ADD COLUMN status_changed_at REAL")]:
        if col not in cols:
            c.execute(ddl)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS asset_meta(
        host TEXT PRIMARY KEY, criticality TEXT DEFAULT 'medium',
        owner TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE IF NOT EXISTS api_tokens(
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, token_hash TEXT,
        created_by TEXT, created_at REAL, last_used REAL);
    CREATE TABLE IF NOT EXISTS secret_baseline(
        hash TEXT PRIMARY KEY, kind TEXT DEFAULT '', label TEXT DEFAULT '',
        reason TEXT DEFAULT '', added_by TEXT DEFAULT '',
        added_at REAL);
    """)


def update_finding(finding_id, status=None, assignee=None, due_date=None,
                   confidence=None, poc_proof=None):
    """Extended triage update: status (with a change timestamp for MTTR),
    assignee, remediation due date — and (PoC sandbox v1.2.3)
    confidence upgrade + PoC proof (stored in the evidence column)."""
    sets, args = [], []
    if status is not None:
        if status not in FINDING_STATUSES:
            raise ValueError('invalid status')
        sets += ["status=?", "status_changed_at=?"]
        args += [status, time.time()]
    if assignee is not None:
        sets.append("assignee=?"); args.append(str(assignee)[:80])
    if due_date is not None:
        sets.append("due_date=?"); args.append(str(due_date)[:10])
    if confidence in ("confirmed", "probable", "candidate"):
        sets.append("confidence=?"); args.append(confidence)
    if poc_proof:
        sets.append("evidence=?")
        args.append(f"PoC proof: {str(poc_proof)[:300]}")
    if not sets:
        return False
    args.append(finding_id)
    with _db() as c:
        _migrate_v34(c)
        cur = c.execute(f"UPDATE findings SET {', '.join(sets)} WHERE id=?", args)
        return cur.rowcount > 0


def insights():
    """Panel enterprise: kepatuhan SLA remediasi, MTTR, tren postur per aset."""
    now = time.time()
    with _db() as c:
        _migrate_v34(c)
        rows = [dict(r) for r in c.execute(
            "SELECT f.id, f.severity, f.title, f.status, f.assignee, f.due_date, "
            "f.status_changed_at, s.target, s.started_at FROM findings f "
            "JOIN scans s ON s.id=f.scan_id")]
        trend_rows = [dict(r) for r in c.execute(
            "SELECT target, started_at, overall_risk, result FROM scans "
            "WHERE overall_risk IS NOT NULL AND overall_risk<>'' "
            "ORDER BY target, started_at")]
    overdue, sla_counts = [], {}
    mttr_acc = {}
    for f in rows:
        status = f.get("status") or "open"
        age_d = max(0.0, (now - (f["started_at"] or now)) / 86400)
        if status not in ("false_positive", "fixed"):
            sla = SLA_DAYS.get(f["severity"], 180)
            over_by = age_d - sla
            if f.get("due_date"):
                try:
                    due_ts = time.mktime(time.strptime(f["due_date"], "%Y-%m-%d"))
                    over_by = max(over_by, (now - due_ts) / 86400)
                except Exception:
                    pass
            if over_by > 0:
                sla_counts[f["severity"]] = sla_counts.get(f["severity"], 0) + 1
                overdue.append({"id": f["id"], "severity": f["severity"],
                                "title": f["title"], "target": f["target"],
                                "age_days": round(age_d, 1),
                                "overdue_days": round(over_by, 1),
                                "assignee": f.get("assignee") or "",
                                "due_date": f.get("due_date") or ""})
        if status == "fixed" and f.get("status_changed_at") and f.get("started_at"):
            days = (f["status_changed_at"] - f["started_at"]) / 86400
            if days >= 0:
                mttr_acc.setdefault(f["severity"], []).append(days)
                mttr_acc.setdefault("ALL", []).append(days)
    overdue.sort(key=lambda x: -x["overdue_days"])
    mttr = {k: round(sum(v) / len(v), 1) for k, v in mttr_acc.items() if v}
    trend = {}
    for r in trend_rows:
        try:
            score = json.loads(r["result"] or "{}").get("risk_score")
        except Exception:
            score = None
        trend.setdefault(r["target"], []).append(
            {"t": r["started_at"], "risk": r["overall_risk"], "score": score})
    for k in trend:
        trend[k] = trend[k][-12:]
    return {"sla_days": SLA_DAYS, "overdue_counts": sla_counts,
            "overdue": overdue[:15], "mttr_days": mttr, "trend_by_target": trend}


def get_asset_meta():
    with _db() as c:
        _migrate_v34(c)
        return {r["host"]: {"criticality": r["criticality"], "owner": r["owner"]}
                for r in c.execute("SELECT * FROM asset_meta")}


def set_asset_meta(host, criticality, owner):
    if criticality not in ASSET_CRITICALITY:
        raise ValueError('invalid criticality')
    with _db() as c:
        _migrate_v34(c)
        c.execute("INSERT INTO asset_meta(host,criticality,owner) VALUES(?,?,?) "
                  "ON CONFLICT(host) DO UPDATE SET criticality=excluded.criticality, "
                  "owner=excluded.owner",
                  (host[:200], criticality, str(owner)[:80]))


def delete_asset(host):
    """Delete an asset: all scans owned by that target + their findings + meta +
    the host's suppressions (one transaction). Vault secrets are NOT touched —
    they are independent entries managed from Settings.
    Returns a dict of deleted counts."""
    from urllib.parse import urlparse
    host_part = ""
    if "://" in host:
        host_part = urlparse(host).hostname or ""
    elif "/" in host:
        host_part = host.split("/")[0]
    host_part = (host_part or host).lower().rstrip(".")

    def _same_host(target: str) -> bool:
        t = (target or "").strip().lower()
        if t in (host.lower(), host_part):
            return True
        try:
            return (urlparse(t).hostname or "").lower().rstrip(".") == host_part
        except Exception:
            return False

    with _db() as c:
        # Match scans by HOSTNAME, not by exact string — targets are stored
        # verbatim (scheme, path, trailing slash) while the asset view shows
        # the bare host; exact matching left sibling scans and their findings
        # behind (field-reported bug).
        ids = [r[0] for r in c.execute(
            "SELECT id,target FROM scans").fetchall()
            if _same_host(r["target"])]
        nf = 0
        if ids:
            q = ",".join("?" * len(ids))
            nf = c.execute(
                f"SELECT COUNT(*) FROM findings WHERE scan_id IN ({q})",
                ids).fetchone()[0]
            c.execute(f"DELETE FROM findings WHERE scan_id IN ({q})", ids)
            c.execute(f"DELETE FROM scans WHERE id IN ({q})", ids)
        c.execute("DELETE FROM asset_meta WHERE host=? OR host=?",
                  (host, host_part))
        keys = [k for k in {host, host_part} if k]
        ns = 0
        if keys:
            q = ",".join("?" * len(keys))
            ns = c.execute(
                f"DELETE FROM suppressions WHERE host IN ({q})", keys).rowcount
        orphans = c.execute(
            "DELETE FROM findings WHERE scan_id NOT IN (SELECT id FROM scans)"
        ).rowcount
    return {"scans": len(ids), "findings": nf + orphans, "suppressions": ns}


def get_setting(key, default=""):
    with _db() as c:
        _migrate_v34(c)
        r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default


def set_setting(key, value):
    with _db() as c:
        _migrate_v34(c)
        c.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, str(value)[:500]))


def create_token(name, created_by):
    import hashlib
    import secrets as _sec
    raw = "ptk_" + _sec.token_urlsafe(32)
    with _db() as c:
        _migrate_v34(c)
        c.execute("INSERT INTO api_tokens(name,token_hash,created_by,created_at) "
                  "VALUES(?,?,?,?)",
                  (str(name)[:60], hashlib.sha256(raw.encode()).hexdigest(),
                   created_by, time.time()))
    return raw


def verify_token(raw):
    import hashlib
    if not raw:
        return None
    h = hashlib.sha256(raw.encode()).hexdigest()
    with _db() as c:
        _migrate_v34(c)
        r = c.execute("SELECT id, name FROM api_tokens WHERE token_hash=?",
                      (h,)).fetchone()
        if not r:
            return None
        c.execute("UPDATE api_tokens SET last_used=? WHERE id=?",
                  (time.time(), r["id"]))
        return r["name"]


def list_tokens():
    with _db() as c:
        _migrate_v34(c)
        return [dict(r) for r in c.execute(
            "SELECT id, name, created_by, created_at, last_used FROM api_tokens "
            "ORDER BY id DESC")]


def delete_token(token_id):
    with _db() as c:
        _migrate_v34(c)
        return c.execute("DELETE FROM api_tokens WHERE id=?",
                         (int(token_id),)).rowcount > 0


def scan_finding_keys(scan_id):
    with _db() as c:
        return {f"{r['title']}|{r['location']}|{r['param']}" for r in c.execute(
            "SELECT title, location, param FROM findings WHERE scan_id=?",
            (scan_id,))}


def previous_scan(target, before_started_at, exclude_id):
    with _db() as c:
        r = c.execute(
            "SELECT id FROM scans WHERE target=? AND id<>? AND started_at<=? "
            "AND overall_risk IS NOT NULL ORDER BY started_at DESC LIMIT 1",
            (target, exclude_id, before_started_at)).fetchone()
        return r["id"] if r else None

# ---------------------------------------------------------------- Fase 2 --

def cve_upsert(rows):
    """Save/update CVE rows from nvd.sync into the local cache."""
    import json as _json
    from datetime import datetime as _dt
    now = _dt.now().isoformat(timespec="seconds")
    n = 0
    with _db() as c:
        for r in rows:
            c.execute(
                "INSERT OR REPLACE INTO cve_cache(cve_id, published,"
                " modified, description, cvss, severity, weaknesses, refs,"
                " fetched_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (r["cve_id"], r.get("published", ""), r.get("modified", ""),
                 r.get("description", ""), r.get("cvss"),
                 r.get("severity", ""),
                 _json.dumps(r.get("weaknesses", [])),
                 _json.dumps(r.get("refs", [])), now))
            n += 1
    return n


def cve_stats():
    with _db() as c:
        cnt = c.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0]
        last = c.execute(
            "SELECT MAX(fetched_at) FROM cve_cache").fetchone()[0]
    return {"count": cnt, "last_fetched": last}


def cve_search(q, limit=50):
    q = f"%{q}%"
    with _db() as c:
        rows = c.execute(
            "SELECT cve_id, published, description, cvss, severity FROM"
            " cve_cache WHERE cve_id LIKE ? OR description LIKE ?"
            " ORDER BY published DESC LIMIT ?", (q, q, limit)).fetchall()
    return [dict(r) for r in rows]


def list_suppressions():
    with _db() as c:
        rows = c.execute(
            "SELECT * FROM suppressions ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def add_suppression(host, title, user=""):
    from datetime import datetime as _dt
    with _db() as c:
        cur = c.execute(
            "INSERT INTO suppressions(host, title, created_by, ts)"
            " VALUES(?,?,?,?)",
            (host.strip().lower(), title.strip(), user,
             _dt.now().isoformat(timespec="seconds")))
        return cur.lastrowid


def delete_suppression(sid):
    with _db() as c:
        c.execute("DELETE FROM suppressions WHERE id=?", (sid,))


def is_suppressed(host, title):
    """True when a suppression rule exists for this host (empty host =
    all hosts) whose title is a (case-insensitive) substring of the title."""
    host = (host or "").lower()
    tl = (title or "").lower()
    with _db() as c:
        rows = c.execute("SELECT host, title FROM suppressions").fetchall()
    for r in rows:
        h = (r["host"] or "").lower()
        if h and h != host and not host.endswith("." + h):
            continue
        t = (r["title"] or "").lower()
        if t and t in tl:
            return True
    return False

# ---------------------------------------------------------------- Fase 3 --

def secret_create(name, host, kind, username, secret_enc, user=""):
    from datetime import datetime as _dt
    with _db() as c:
        cur = c.execute(
            "INSERT INTO target_secrets(name, host, kind, username,"
            " secret_enc, created_by, ts) VALUES(?,?,?,?,?,?,?)",
            (name.strip()[:80], host.strip().lower()[:120], kind,
             username.strip()[:80], secret_enc, user,
             _dt.now().isoformat(timespec="seconds")))
        return cur.lastrowid


def secret_list():
    """Metadata only — secret_enc is NOT returned."""
    with _db() as c:
        rows = c.execute(
            "SELECT id, name, host, kind, username, created_by, ts"
            " FROM target_secrets ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def secret_get(sid):
    """Full row including secret_enc — ONLY for internal server use
    (credential injection during scans); never expose it to the API."""
    with _db() as c:
        row = c.execute("SELECT * FROM target_secrets WHERE id=?",
                        (sid,)).fetchone()
    return dict(row) if row else None


def secret_delete(sid):
    with _db() as c:
        c.execute("DELETE FROM target_secrets WHERE id=?", (sid,))
