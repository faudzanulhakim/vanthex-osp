"""
HarKit v1 — HAR traffic replay & diff for VANTHEX. Read-only.

Import a HAR (browser/devtools capture), replay requests under TWO session
identities (cookie A vs cookie B), then differential: an endpoint that
returns private data for both identities indicates weak (horizontal)
authz. Pure module: accepts a har dict + client stub — unit-testable,
no networking of its own (replay via the provided client).

Usage (operator):
    python3 - <<'EOF'
    import json, harkit, netclient
    har = json.load(open("capture.har"))
    c = netclient.Client("http://target.local")
    rows = harkit.replay_and_diff(har, c, "session=AAA", "session=BBB")
    print(harkit.report(rows))
    EOF
"""


def _entries(har):
    for e in (har or {}).get("log", {}).get("entries", []):
        req = e.get("request", {})
        yield (str(req.get("method", "GET")).upper(),
               str(req.get("url", "")),
               req.get("cookies") or [])


def _relative(url, base_host=None):
    """Absolute HAR URL -> relative path (netclient needs relative paths)."""
    from urllib.parse import urlsplit
    sp = urlsplit(url)
    path = sp.path or "/"
    if sp.query:
        path += "?" + sp.query
    return path


def replay_and_diff(har, client, cookie_a, cookie_b, max_entries=40,
                    min_body=20):
    """Replay each HAR entry twice (identity A vs B), diff the bodies.

    Returns list of rows:
      {url, status_a, status_b, len_a, len_b, verdict}
    verdict:
      - "same-private" : both 200 + identical & long-enough bodies
                         (indicates weak authz — same data for different identities)
      - "differential" : A 200, B 401/403 (ACL working — healthy)
      - "both-denied" / "error"
    Read-only: only GET/HEAD entries are replayed (POST is not repeated)."""
    rows = []
    n = 0
    for method, url, _ck in _entries(har):
        if n >= max_entries:
            break
        if method not in ("GET", "HEAD"):
            continue
        path = _relative(url)
        try:
            ra = client.get(path, headers={"Cookie": cookie_a})
            rb = client.get(path, headers={"Cookie": cookie_b})
        except Exception:
            rows.append({"url": url, "verdict": "error", "status_a": 0,
                         "status_b": 0, "len_a": 0, "len_b": 0})
            n += 1
            continue
        la, lb = len(ra.body or ""), len(rb.body or "")
        ok_a, ok_b = ra.status == 200, rb.status == 200
        denied_b = rb.status in (401, 403)
        if ok_a and ok_b and la >= min_body and la == lb \
                and (ra.body or "") == (rb.body or ""):
            verdict = "same-private"
        elif ok_a and denied_b:
            verdict = "differential"
        elif not ok_a and not ok_b:
            verdict = "both-denied"
        else:
            verdict = "mixed"
        rows.append({"url": url, "verdict": verdict,
                     "status_a": ra.status, "status_b": rb.status,
                     "len_a": la, "len_b": lb})
        n += 1
    return rows


def report(rows):
    """Text summary for the operator."""
    if not rows:
        return "Empty HAR / no GET entries to replay."
    out = ["Replay HAR: {} entry — authz differential".format(len(rows))]
    for r in rows:
        mark = "!!" if r["verdict"] == "same-private" else "  "
        out.append(f"{mark} [{r['verdict']:<13}] {r['url'][:80]} "
                   f"(A:{r['status_a']}/{r['len_a']}B B:{r['status_b']}/{r['len_b']}B)")
    n_leak = sum(1 for r in rows if r["verdict"] == "same-private")
    out.append(f"Weak authz indications (same-private): {n_leak}")
    return "\n".join(out)
