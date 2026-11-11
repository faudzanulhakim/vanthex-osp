"""
DirBrute v1 — adaptive directory/file brute force for VANTHEX.
AUTHORIZED TESTING ONLY.

Wordlist-driven with adaptive filtering (not blind spraying):
- a soft-404 baseline is fingerprinted per scan (unique marker) + body similarity;
- a candidate passes only if the status is not 404, the body differs significantly
  from the baseline, and it is stable across a 2x reproduction;
- a strict request budget (MAX_REQUESTS) and ctx.cancelled() are honored.

c_dir_bruteforce(ctx, add) in c_* style — invoked by the runner via PROFILES.
"""
from netclient import similarity


def _F(sev, title, desc, evidence="", cwe="", owasp="", cvss=0.0, remed="",
       confidence="probable", location="", param="", origin="dirbrute"):
    """Finding factory — identical shape to vulnscan2.F, origin DirBrute."""
    return {"severity": sev, "title": title, "description": desc,
            "evidence": evidence, "cwe": cwe, "owasp": owasp, "cvss": cvss,
            "remediation": remed, "confidence": confidence,
            "location": location, "param": param, "origin": origin}

# ---- hard limits
MAX_REQUESTS = 90          # total requests per check (adaptive, bounded)
MIN_SIM_DIFF = 0.90        # body must differ from the baseline (sim < 0.90)

# common directory wordlist (not a giant one — only high-value candidates)
WORD_DIRS = (
    "admin", "backup", "old", "vault", "dev", "test", "api", "config",
    "db", "internal", "panel", "manager", "private", "secret", "archive",
    "report", "staging", "debug", "console", "install",
)

# common extensions/files for per-directory & per-name fuzzing
DIR_EXTS = (".bak", ".sql", ".zip", ".txt", ".old", ".json")


def _candidates():
    """Path candidate generator: directory names, common files, backup extensions."""
    for d in WORD_DIRS:
        yield f"/{d}/"
        yield f"/{d}/keys.txt"
        yield f"/{d}/config.json"
        yield f"/{d}.bak"
        yield f"/{d}.sql"
        yield f"/{d}.php.bak"
        yield f"/{d}.zip"


def c_dir_bruteforce(ctx, add):
    """Directory/file brute force with adaptive filtering: per-scan soft-404
    baseline, body similarity, 2x reproduction. Finds hidden paths that are
    not linked anywhere (backups, archives, old panels)."""
    # fingerprint the soft-404 baseline (unique per-scan marker, cannot exist)
    rb = ctx.client.get(f"/vhx-noexist-{ctx.marker}-{ctx.num_a}")
    bl_body = rb.body or ""
    # WordSmith (v1.2.3): contextual wordlist merged at the FRONT of the
    # candidate list. Default ON when no explicit wordlist is supplied via
    # opts; opt-out with opts['context_wordlist']=False.
    use_ctx = ctx.opts.get("context_wordlist")
    if use_ctx is None:
        use_ctx = not bool(ctx.opts.get("wordlist"))
    tried = 0
    hits = []
    cands = []
    if use_ctx:
        try:
            from wordsmith import contextual_wordlist
            wl = contextual_wordlist(
                ctx.target, list(getattr(ctx, "technologies", []) or []))
            # only fetchable path entries go in front of the probe order;
            # keep the merged slice bounded so the engine's own candidates
            # below still get request budget.
            ctx_paths = [e for e in wl if e.startswith("/")][:60]
            cands.extend(ctx_paths)
            ctx.L(f"[wordsmith] {len(ctx_paths)} contextual entries")
        except Exception:
            pass
    cands.extend(_candidates())
    for cand in cands:
        if ctx.cancelled() or tried >= MAX_REQUESTS:
            break
        tried += 1
        r = ctx.client.get(cand)
        if r.status != 200 and r.status != 403:
            continue
        body = r.body or ""
        # adaptive: the body must differ from the soft-404 baseline
        if similarity(body, bl_body) >= MIN_SIM_DIFF:
            continue
        # 2x reproduction + consistent
        r2 = ctx.client.get(cand)
        if r2.status == r.status and similarity(r2.body or "", body) >= MIN_SIM_DIFF:
            hits.append((cand, r.status, body))
    for path, status, body in hits:
        sev = "MEDIUM" if status == 200 else "LOW"
        # raise severity if the body appears to contain sensitive content
        low = body.lower()
        if any(t in low for t in ("password", "api_key", "secret", "index of")):
            sev = "HIGH"
        add(_F(sev,
               f"Hidden Path Found (dir brute): {path}",
               "Unlinked path found via filtered brute force (soft-404 "
               "baseline + similarity) — content stable and different "
               "from generic 404 pages.",
               evidence=f"HTTP {status}, body {len(body)}B, stable 2x, "
                         f"differs from baseline",
               cwe="CWE-538", owasp="A05:2021 Security Misconfiguration",
               cvss=5.3 if sev != "HIGH" else 7.5,
               remed="Remove/archive old content from the docroot; block listing "
                     "and backup files on the web server.",
               confidence="confirmed", location=path))
