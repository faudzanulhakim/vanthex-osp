"""
Attack graph builder — rule-based exploitation chains over scan findings.
AUTHORIZED TESTING ONLY.

Takes a list of finding dicts (the vulnscan2.F() shape, optionally enriched
by threatprior) and builds a directed attack graph:

    { "nodes":   [{"id", "type", "severity", "priority"}],
      "edges":   [{"from", "to", "relation"}],
      "chains":  [{"nodes": [ids...], "titles": [...], "final_impact",
                   "impact_score"}],
      "top_impact": int }

Chain rules (derived from common exploitation patterns):
  - secret / credential leaks (token, api_key, credential, session token)
        -> feed into auth-bypass / OTP-brute / account-takeover findings
  - SSRF -> internal service access
  - injection (SQLi / RCE) -> data access / persistence
  - exposed admin -> account takeover

impact_score (0-100) = terminal impact weight + 10 per hop beyond the
entry node — deeper chains reach a higher final impact, capped at 100.

Stdlib only, offline-safe: pure computation over the findings passed in,
no network access, never raises on malformed input.
"""
import re

MAX_NODES = 40
MAX_EDGES = 60
MAX_CHAINS = 100

SEV_WEIGHTS = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 20, "LOW": 10, "INFO": 5}

# entry-stage finding classifications (checked in order — first match wins)
_STAGE_PATTERNS = [
    ("secret", re.compile(
        r"token|api[_ ]?key|credential|secret|password|private key|session "
        r"token|api key|jwt", re.I)),
    ("injection", re.compile(
        r"sql\s*injection|sql injection|command injection|remote code "
        r"execution|\brce\b|code injection|ssti|template injection", re.I)),
    ("ssrf", re.compile(
        r"\bssrf\b|server-side request|metadata endpoint|internal service "
        r"probe|cloud metadata", re.I)),
    ("admin", re.compile(
        r"admin|dashboard|management console|admin panel|exposed admin",
        re.I)),
    ("auth_bypass", re.compile(
        r"auth|otp|brute|login|jwt|2fa|mfa|takeover|session|password reset",
        re.I)),
]

# terminal impact nodes (assets, not findings)
_TERMINALS = {
    "account_takeover": ("Account takeover", 40),
    "data_access": ("Sensitive data access", 35),
    "persistence": ("Foothold / persistence", 30),
    "internal_service": ("Internal service access", 25),
}

# edges: (from_type, [to_type, relation]) — to_type may be a terminal
_RULES = [
    ("secret", "auth_bypass", "secret_feeds_auth_bypass"),
    ("secret", "account_takeover", "credentials_enable_takeover"),
    ("ssrf", "internal_service", "ssrf_reaches_internal"),
    ("injection", "data_access", "injection_grants_data_access"),
    ("injection", "persistence", "injection_enables_persistence"),
    ("admin", "account_takeover", "admin_leads_to_takeover"),
    ("auth_bypass", "account_takeover", "auth_bypass_to_takeover"),
]


def classify_finding(f):
    """Return the attack-graph stage type for a finding (or None)."""
    text = f"{f.get('title', '')} {f.get('description', '')}"
    for ttype, pat in _STAGE_PATTERNS:
        if pat.search(text):
            return ttype
    return None


def _node_id(i):
    return f"f{i + 1}"


def _term_id(ttype):
    return f"impact:{ttype}"


def _score_for(chain_len, terminal_type):
    base = _TERMINALS[terminal_type][1]
    return min(100, base + 10 * max(0, chain_len - 2))


def _paths_from(adj, start, visited, path, out):
    if len(out) >= MAX_CHAINS:
        return
    for rel, nxt in adj.get(start, ()):  # (relation, node_id)
        if nxt in visited:
            continue
        new_path = path + [nxt]
        if nxt.startswith("impact:"):
            out.append((list(new_path), nxt.split(":", 1)[1]))
        else:
            _paths_from(adj, nxt, visited | {nxt}, new_path, out)
        if len(out) >= MAX_CHAINS:
            return


def build_attack_graph(findings, max_nodes=MAX_NODES, max_edges=MAX_EDGES):
    """Build the attack graph for a findings list (never raises)."""
    graph = {"nodes": [], "edges": [], "chains": [], "top_impact": 0}
    try:
        staged = []  # (node_id, finding, type)
        for i, f in enumerate(findings or []):
            if not isinstance(f, dict):
                continue
            ttype = classify_finding(f)
            if not ttype:
                continue
            staged.append((_node_id(i), f, ttype))
        # keep the first max_nodes finding-nodes (callers pass findings
        # pre-sorted by severity, so this keeps the most severe first);
        # reserve room for the terminal impact nodes so the TOTAL node
        # count stays within max_nodes
        staged = staged[:max(1, max_nodes - len(_TERMINALS))]
        if not staged:
            return graph

        nodes = {nid: {"id": nid, "type": ttype,
                       "severity": f.get("severity", "INFO"),
                       "priority": f.get("priority")}
                 for nid, f, ttype in staged}
        title_of = {nid: str(f.get("title", nid)) for nid, f, _ in staged}
        types = {nid: ttype for nid, _, ttype in staged}

        # adjacency on finding nodes only; terminal edges recorded directly
        adj = {nid: [] for nid in types}
        edges = []
        by_type = {}
        for nid, _, ttype in staged:
            by_type.setdefault(ttype, []).append(nid)

        def add_edge(src, dst, rel):
            edges.append({"from": src, "to": dst, "relation": rel})
            adj.setdefault(src, []).append((rel, dst))

        for ftype, ttype, rel in _RULES:
            for src in by_type.get(ftype, ()):
                if ttype in _TERMINALS:
                    tid = _term_id(ttype)
                    nodes[tid] = {"id": tid, "type": ttype,
                                  "severity": "CRITICAL" if
                                  _TERMINALS[ttype][1] >= 40 else "HIGH",
                                  "priority": None}
                    title_of[tid] = _TERMINALS[ttype][0]
                    add_edge(src, tid, rel)
                else:
                    for dst in by_type.get(ttype, ()):
                        if dst != src:
                            add_edge(src, dst, rel)

        # hard caps (findings nodes already capped; trim edges + terminals)
        if len(edges) > max_edges:
            edges = edges[:max_edges]
        keep = set()
        for e in edges:
            keep.add(e["from"])
            keep.add(e["to"])
        nodes = [nodes[nid] for nid in nodes if nid in keep]
        adj = {n: [x for x in lst if x[1] in keep] for n, lst in adj.items()
               if n in keep}

        # enumerate exploitation chains from every entry node
        incoming = {e["to"] for e in edges}
        chains = []
        for nid in types:
            if nid in keep and nid not in incoming:
                paths = []
                _paths_from(adj, nid, {nid}, [nid], paths)
                for node_ids, ttype in paths:
                    chains.append({
                        "nodes": node_ids,
                        "titles": [title_of[n] for n in node_ids],
                        "final_impact": _TERMINALS[ttype][0],
                        "impact_score": _score_for(len(node_ids), ttype),
                    })
        chains.sort(key=lambda c: -c["impact_score"])
        chains = chains[:MAX_CHAINS]
        graph["nodes"] = nodes
        graph["edges"] = edges
        graph["chains"] = chains
        graph["top_impact"] = chains[0]["impact_score"] if chains else 0
    except Exception:
        pass
    return graph


def top_attack_paths(findings, limit=3):
    """Top-N attack chains for a findings list, highest impact first."""
    g = build_attack_graph(findings)
    return g["chains"][:max(0, int(limit))]


def chain_label(chain):
    """'A -> B -> C (impact 87/100)' for reports."""
    try:
        titles = chain.get("titles") or chain.get("nodes") or []
        return (f"{' -> '.join(str(t) for t in titles)} "
                f"(impact {chain.get('impact_score', 0)}/100)")
    except Exception:
        return ""
