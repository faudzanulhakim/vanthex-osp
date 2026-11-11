"""
Post-Exploit Lateral Map — pure offline graph over scan findings.
AUTHORIZED TESTING ONLY.

lateral_map(findings, creds=None) builds a small graph of what an
attacker holding the found credentials/secrets could reach laterally:

    { "nodes": [{"id", "kind", "label"}],   # kind: credential|panel|service|host
      "edges": [{"from", "to", "via"}],
      "node_count": int }

Nodes/edges come from the findings' own text only:
  - credential/secret findings (token, api key, password, jwt, private key)
  - exposed admin panels / dashboards (location or title mentions)
  - service URLs in evidence (mysql://, redis://, smtp://, postgres://, amqp)
  - hosts extracted from URLs anywhere in the finding text
A credential links to a panel when they share a host or the panel path is
mentioned in the credential finding; panels and services link to their
host. No network access, never raises on malformed input. Capped at
MAX_NODES = 40 nodes / 80 edges.
"""
import re

MAX_NODES = 40
MAX_EDGES = 80

_CRED_RE = re.compile(
    r"\bapi[ _-]?key\b|\btoken\b|\bcredential|\bpassword\b|\bsecret\b|"
    r"\bjwt\b|private key|bearer\b|basic auth|session token", re.I)

_PANEL_RE = re.compile(
    r"\badmin\b|\bdashboard\b|\bconsole\b|\bmanager\b|\bpanel\b|"
    r"/admin|/manager|/wp-admin", re.I)

_SERVICE_RES = [
    ("mysql", re.compile(r"\bmysql(?:://|[,\s)])", re.I)),
    ("postgres", re.compile(r"\bpostgres(?:ql)?(?:://|\b)", re.I)),
    ("redis", re.compile(r"\bredis(?:://|\b)", re.I)),
    ("smtp", re.compile(r"\bsmtp(?:://|\b)", re.I)),
    ("amqp", re.compile(r"\bamqp(?:://|\b)", re.I)),
    ("mongodb", re.compile(r"\bmongodb(?:://|\b)", re.I)),
]

_URL_RE = re.compile(r"https?://([A-Za-z0-9._-]+)")

_PANEL_PATH_RE = re.compile(
    r"/(?:admin|dashboard|manager|wp-admin|console)[A-Za-z0-9._/-]*", re.I)


def _f(f, key):
    v = f.get(key) if isinstance(f, dict) else None
    return str(v) if v else ""


def _text(f):
    return " ".join(_f(f, k) for k in
                    ("title", "description", "evidence", "location", "param"))


def _slug(s, prefix):
    base = re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")[:40]
    return f"{prefix}-{base}" or prefix


def lateral_map(findings, creds=None):
    """Build the lateral-movement graph from findings text (pure)."""
    nodes, edges = [], []
    nkeys, ekeys = set(), set()

    def add_node(kind, label):
        if len(nodes) >= MAX_NODES:
            return None
        nid = _slug(label, kind)
        if nid in nkeys:
            return nid
        nkeys.add(nid)
        nodes.append({"id": nid, "kind": kind, "label": str(label)[:120]})
        return nid

    def add_edge(frm, to, via):
        if not frm or not to or frm == to or len(edges) >= MAX_EDGES:
            return
        k = (frm, to)
        if k in ekeys:
            return
        ekeys.add(k)
        edges.append({"from": frm, "to": to, "via": str(via)[:120]})

    cred_nodes = []      # (node_id, host, text)
    panel_nodes = []     # (node_id, host, path)

    # optional caller-supplied credentials (dicts with name/host/secret)
    for c in (creds or []):
        if not isinstance(c, dict):
            continue
        name = str(c.get("name") or c.get("username") or "credential")
        host = str(c.get("host") or "")
        nid = add_node("credential", name)
        if nid:
            cred_nodes.append((nid, host, str(c.get("secret") or "")))

    for f in (findings or []):
        if not isinstance(f, dict):
            continue
        text = _text(f)
        title = _f(f, "title") or "finding"
        loc = _f(f, "location")
        hosts = set(_URL_RE.findall(text))
        ev = _f(f, "evidence")

        # credential / secret finding
        if _CRED_RE.search(title + " " + ev):
            nid = add_node("credential", title)
            if nid:
                cred_nodes.append((nid, next(iter(hosts), ""), text))

        # exposed admin panel
        if _PANEL_RE.search(title + " " + loc) and (loc or title):
            label = f"{title}" if title.lower() != "finding" else (loc or "panel")
            nid = add_node("panel", label)
            if nid:
                ppath = (_PANEL_PATH_RE.search(loc)
                         or _PANEL_PATH_RE.search(text))
                panel_nodes.append((nid, next(iter(hosts), ""),
                                    ppath.group(0) if ppath else ""))
                h = next(iter(hosts), "")
                if h:
                    hid = add_node("host", h)
                    add_edge(nid, hid, "panel served by host")

        # service mentioned in evidence
        for svc, pat in _SERVICE_RES:
            if pat.search(text):
                sid = add_node("service", f"{svc} service ({title[:40]})")
                h = next(iter(hosts), "")
                if sid and h:
                    hid = add_node("host", h)
                    add_edge(sid, hid, f"{svc} on host")

        # bare host nodes from URLs in the finding
        for h in list(hosts)[:3]:
            add_node("host", h)

    # credential -> panel edges: shared host or panel path in cred text
    for cid, chost, ctext in cred_nodes:
        for pid, phost, ppath in panel_nodes:
            via = None
            if chost and phost and chost == phost:
                via = f"shared host {chost}"
            elif ppath and ppath.lower() in ctext.lower():
                via = f"panel path {ppath}"
            if via:
                add_edge(cid, pid, via)

    return {"nodes": nodes, "edges": edges,
            "node_count": len(nodes), "edge_count": len(edges)}


def lateral_paths(findings, limit=5, creds=None):
    """Readable chains like 'credential X -> panel Y (host Z)'. Pure."""
    g = lateral_map(findings, creds=creds)
    by_id = {n["id"]: n for n in g["nodes"]}
    out = []
    for e in g["edges"]:
        a, b = by_id.get(e["from"]), by_id.get(e["to"])
        if not a or not b:
            continue
        if a["kind"] == "credential":
            host = ""
            if b["kind"] == "host":
                out.append(f"credential {a['label']} -> host {b['label']}")
            else:
                # find the panel's host edge for the (host Z) suffix
                he = next((x for x in g["edges"]
                           if x["from"] == b["id"]
                           and by_id.get(x["to"], {}).get("kind") == "host"),
                          None)
                host = f" (host {by_id[he['to']]['label']})" if he else ""
                out.append(f"credential {a['label']} -> {b['kind']} "
                           f"{b['label']}{host}")
        if len(out) >= max(1, int(limit)):
            break
    return out[:max(1, int(limit))]
