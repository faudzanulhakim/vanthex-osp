"""
PivotKit v1 — Pivot & Lateral Movement Mapper for VANTHEX (v1.8.0).
AUTHORIZED TESTING ONLY — read-only, bounded.

- build_graph(): pure — builds a pivot graph {node, edges, reachable} from
  artifacts (internal IPs, hostnames, credentials read).
- c_pivot_internal_map(): check — collects internal-network hints leaked
  (netmap endpoints, internal headers, HTML comments, config variables)
  → graph → finding: 'from this foothold, the attacker sees everything'.
"""
import json as _json
import re as _re

from exploitkit import _F

IP_RE = _re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")
PORT_RE = _re.compile(r"\b(10\.\S{3,40}|172\.(?:1[6-9]|2\d|3[01])\.\S{3,40}|192\.168\.\S{3,40}):(443|8080|5432|3306|6379|27017|22|8443|9200)\b")


def build_graph(artifacts):
    """artifacts: list dict {source, hosts:[(ip, role?)], creds:[str], ports:[str]}
    Returns a graph {nodes, edges} — unique nodes, host->host edges via port/cred."""
    nodes, edges = {}, []
    for a in (artifacts or []):
        src = str(a.get("source", "?"))
        for ip, role in (a.get("hosts") or []):
            if ip not in nodes:
                nodes[ip] = {"role": role or "unknown", "discovered_by": []}
            nodes[ip]["discovered_by"].append(src)
        for raw in (a.get("ports") or []):
            m = PORT_RE.search(raw)
            if not m:
                continue
            host, port = m.group(1), m.group(2)
            if host not in nodes:
                nodes[host] = {"role": "service-host", "discovered_by": [src]}
            edges.append({"from": src, "to": host, "port": port})
        for c in (a.get("creds") or [])[:6]:
            edges.append({"from": src, "to": "credential:" + str(c)[:24],
                          "port": ""})
    return {"nodes": nodes, "edges": edges[:40]}


def harvest(ctx):
    """Collect internal-network artifacts from proven surface
    (netmap endpoints, /internal/*, JSON config). Read-only."""
    arts = []
    for ep in ("/internal/netmap", "/internal/hosts"):
        try:
            r = ctx.client.get(ep)
        except Exception:
            continue
        if r.status != 200:
            continue
        body = r.body or ""
        try:
            data = _json.loads(body)
            hosts = [(h.get("ip"), h.get("role")) for h in
                     (data.get("hosts") or []) if h.get("ip")]
            creds = [str(c) for c in (data.get("credentials") or [])][:6]
            arts.append({"source": ep, "hosts": hosts, "ports": [], "creds": creds})
        except Exception:
            hosts = [(m, "") for m in IP_RE.findall(body)][:10]
            ports = [m.group(0) for m in PORT_RE.finditer(body)][:10]
            if hosts or ports:
                arts.append({"source": ep, "hosts": hosts,
                             "ports": ports, "creds": []})
    # internal headers & HTML comments from the main page
    try:
        r = ctx.client.get("/")
        blob = r.body or ""
        hosts = [(m, "") for m in IP_RE.findall(blob)][:6]
        ports = [m.group(0) for m in PORT_RE.finditer(blob)][:6]
        if hosts or ports:
            arts.append({"source": "/ (reflection)", "hosts": hosts,
                         "ports": ports, "creds": []})
    except Exception:
        pass
    return arts


def c_pivot_internal_map(ctx, add):
    """Map the internal network leaked from the public surface: a pivot
    graph (internal hosts + service ports + credentials) = a ready-made
    lateral movement map for an attacker. /safe control returns 403."""
    arts = harvest(ctx)
    if not arts:
        ctx.L("  [pivot] no internal network artifacts — skipped")
        return
    g = build_graph(arts)
    n_hosts = len(g["nodes"])
    if n_hosts == 0:
        return
    rs = ctx.client.get("/safe/internal/netmap")
    if rs.status not in (401, 403):
        ctx.L("  [pivot] /safe control does not block — skip (endpoint may be public by design)")
        return
    sample = ", ".join(list(g["nodes"])[:4])
    ports = sorted({e["port"] for e in g["edges"] if e.get("port")})
    add(_F("CRITICAL",
           f"Internal Network Map Leaked — {n_hosts} hosts (Pivot Map)",
           f"Public surface leaks the internal network topology "
           f"({sample}...) with service ports {', '.join(ports) or 'n/a'} — "
           "an attacker with one foothold immediately gets a MAP of "
           "lateral movement without internal scanning.",
           evidence=f"sources: {[a['source'] for a in arts]}; "
                    f"host: {sample}; port: {ports}",
           cwe="CWE-200", owasp="A01:2021 Broken Access Control", cvss=9.1,
           remed="Netmap/hosts endpoints require auth + allowlist; do not "
                 "reflect internal IPs in public responses; segmentation.",
           confidence="confirmed", location="/internal/netmap",
           param="network-map"))
