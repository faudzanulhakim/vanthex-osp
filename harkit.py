"""
HarKit v1 — replay & diff traffic HAR untuk VANTHEX. Read-only.

Impor HAR (hasil capture browser/devtools), replay request dengan DUA
identitas sesi (cookie A vs cookie B), lalu diferensial: endpoint yang
sama-sama mengembalikan data pribadi untuk kedua identitas = indikasi
authz lemah (horizontal). Modul murni: menerima har dict + client stub —
unit-testable, tanpa network sendiri (replay via client yang diberikan).

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
    """URL absolut HAR -> path relatif (netclient butuh path relatif)."""
    from urllib.parse import urlsplit
    sp = urlsplit(url)
    path = sp.path or "/"
    if sp.query:
        path += "?" + sp.query
    return path


def replay_and_diff(har, client, cookie_a, cookie_b, max_entries=40,
                    min_body=20):
    """Replay tiap entry HAR dua kali (identitas A vs B), diferensial body.

    Returns list of rows:
      {url, status_a, status_b, len_a, len_b, verdict}
    verdict:
      - "same-private" : keduanya 200 + body identik & cukup panjang
                         (indikasi authz lemah — data sama utk identitas beda)
      - "differential" : A 200, B 401/403 (ACL bekerja — sehat)
      - "both-denied" / "error"
    Read-only: hanya GET/HEAD yang di-replay (POST tidak diulang)."""
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
    """Ringkasan teks untuk operator."""
    if not rows:
        return "HAR kosong / tidak ada entry GET yang bisa di-replay."
    out = ["Replay HAR: {} entry — authz differential".format(len(rows))]
    for r in rows:
        mark = "!!" if r["verdict"] == "same-private" else "  "
        out.append(f"{mark} [{r['verdict']:<13}] {r['url'][:80]} "
                   f"(A:{r['status_a']}/{r['len_a']}B B:{r['status_b']}/{r['len_b']}B)")
    n_leak = sum(1 for r in rows if r["verdict"] == "same-private")
    out.append(f"Indikasi authz lemah (same-private): {n_leak}")
    return "\n".join(out)
