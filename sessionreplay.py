"""Session Replay — HAR import + authenticated replay (v1.2.3).

AUTHORIZED TESTING ONLY. This module replays HTTP traffic the operator
has LEGITIMATELY captured (HAR export from their own browser session)
against targets they are authorized to test, to surface broken access
control (IDOR / missing authorization checks) and unintended state
changes. It is not an exfiltration tool: everything runs through
netclient.Client with timeouts, honors ctx cancellation, and stores
nothing on disk.

Three layers:

  parse_har(data)      HAR 1.2 JSON (dict or bytes) -> list of request
                       dicts {method, url, headers, body, cookies}.
                       Tolerant: malformed entries are skipped, never
                       raised.

  replay_chain(client, requests, mutations, max_steps)
                       Replays the chain in order with a fresh-or-supplied
                       client, optionally applying identity mutations
                       (cookie swap, Authorization swap, {{placeholder}}
                       templates). Per step: status, response length and
                       diff-flags. A step is flagged "interesting" when:
                       - replaying with a MODIFIED identity (swapped
                         cookie/token) still returns a 2xx (potential
                         IDOR / authorization gap), or
                       - a mutated GET returns content-length differing
                         >30% from the capture (state leak / change).

  analyze_capture(har) End-to-end: parse + replay + findings built with
                       the same dict shape as vulnscan2.F.

Wire contract for the actions layer (importHar / replayCapture): the
handlers receive the {"headers","body"}-style args envelope used by every
sibling handler in actions.py and run behind the /actions session+admin
gate in app2.py — no extra auth surface is created here.
"""
import base64
import json
import re
import threading
import time

from netclient import Client

# --------------------------------------------------------------- captures ---
# In-memory capture store (task spec: "store capture in memory dict keyed
# by id"). Process-local by design — HAR files contain live session
# cookies and must never be persisted.
_CAPTURES = {}
_REPLAYS = {}
_STORE_LOCK = threading.Lock()
_NEXT_ID = [1]


def _store_capture(name, har):
    with _STORE_LOCK:
        cid = "sr-%04d" % _NEXT_ID[0]
        _NEXT_ID[0] += 1
        _CAPTURES[cid] = {"id": cid, "name": name, "har": har,
                          "ts": time.time()}
    return cid


# ---------------------------------------------------------------- parsing ---

_HOP_BY_HOP = {"host", "content-length", "connection", "transfer-encoding",
               "accept-encoding", "keep-alive", "upgrade"}


def _parse_cookies_header(value):
    """'a=1; b=2' -> {'a': '1', 'b': '2'} (tolerant of junk segments)."""
    out = {}
    for part in (value or "").split(";"):
        if "=" in part:
            k, _, v = part.strip().partition("=")
            if k:
                out[k] = v
    return out


def parse_har(data):
    """Parse a HAR 1.2 document into a flat list of request dicts.

    Accepts a pre-parsed dict or raw bytes/str JSON. Malformed entries
    (non-dict, missing request, missing url) are skipped silently — a
    real-world HAR export is never trusted to be well-formed.
    """
    if isinstance(data, (bytes, bytearray)):
        try:
            data = data.decode("utf-8", "replace")
        except Exception:
            data = ""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            return []
    if not isinstance(data, dict):
        return []
    log = data.get("log")
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        return []
    reqs = []
    for ent in entries:
        try:
            if not isinstance(ent, dict):
                continue
            req = ent.get("request")
            if not isinstance(req, dict):
                continue
            url = req.get("url")
            if not isinstance(url, str) or not url:
                continue
            method = str(req.get("method") or "GET").upper()
            headers = {}
            for h in req.get("headers") or []:
                if isinstance(h, dict) and h.get("name"):
                    headers[str(h["name"]).lower()] = str(h.get("value") or "")
            # Cookies: HAR cookie array first, Cookie header overrides.
            cookies = {}
            for c in req.get("cookies") or []:
                if isinstance(c, dict) and c.get("name"):
                    cookies[str(c["name"])] = str(c.get("value") or "")
            cookies.update(_parse_cookies_header(headers.get("cookie")))
            body = None
            pd = req.get("postData")
            if isinstance(pd, dict) and isinstance(pd.get("text"), str):
                body = pd["text"]
            reqs.append({"method": method, "url": url, "headers": headers,
                         "body": body, "cookies": cookies})
        except Exception:
            continue
    return reqs


# ----------------------------------------------------------------- replay ---

_PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}")


def _apply_placeholders(text, placeholders):
    if not text or not placeholders:
        return text
    return _PLACEHOLDER_RE.sub(
        lambda m: str(placeholders.get(m.group(1), m.group(0))), text)


def _mutation_for(mutations, index):
    """Resolve the mutation dict for step `index` (global + per_step)."""
    if not isinstance(mutations, dict):
        return {}
    mut = {k: v for k, v in mutations.items()
           if k in ("cookie", "headers", "placeholders", "authorization")}
    per = mutations.get("per_step")
    if isinstance(per, list) and 0 <= index < len(per) \
            and isinstance(per[index], dict):
        mut.update(per[index])
    return mut


def _origin_of(url):
    p = url.split("//", 1)
    if len(p) != 2:
        return "", url
    rest = p[1]
    slash = rest.find("/")
    if slash < 0:
        return "http://" + rest, "/"
    return "http://" + rest[:slash], rest[slash:]


def replay_chain(ctx_or_client, requests, mutations=None, max_steps=50):
    """Replay parsed HAR requests in order; return per-step result dicts.

    ctx_or_client: None (fresh client per origin), a netclient.Client,
    or a ctx object exposing `.client` (used like sibling modules do).
    Each step dict: {index, method, url, status, length, elapsed, error,
    modified_identity, interesting, reason}.
    """
    client = None
    if ctx_or_client is not None:
        client = getattr(ctx_or_client, "client", ctx_or_client)
    _clients = {}
    steps = []
    for i, req in enumerate(requests[:max(0, max_steps)]):
        step = {"index": i, "method": req.get("method", "GET"),
                "url": req.get("url", ""), "status": 0, "length": 0,
                "elapsed": 0.0, "error": "", "modified_identity": False,
                "interesting": False, "reason": ""}
        try:
            mut = _mutation_for(mutations, i)
            ph = mut.get("placeholders") if isinstance(
                mut.get("placeholders"), dict) else {}
            url = _apply_placeholders(req["url"], ph)
            origin, path = _origin_of(url)
            hdrs = {k: v for k, v in (req.get("headers") or {}).items()
                    if k not in _HOP_BY_HOP}
            for k, v in (mut.get("headers") or {}).items():
                hdrs[str(k).lower()] = str(v)
            if mut.get("cookie"):
                hdrs["cookie"] = str(mut["cookie"])
            if mut.get("authorization"):
                hdrs["authorization"] = str(mut["authorization"])
            modified = ("cookie" in hdrs and hdrs["cookie"]
                        != (req.get("headers") or {}).get("cookie")) or \
                       ("authorization" in hdrs and hdrs["authorization"]
                        != (req.get("headers") or {}).get("authorization"))
            step["modified_identity"] = bool(modified)
            body = req.get("body")
            if body is not None:
                body = _apply_placeholders(body, ph)
            cli = client
            if cli is None:
                cli = _clients.get(origin)
                if cli is None:
                    cli = Client(origin, timeout=6.0)
                    _clients[origin] = cli
            t0 = time.time()
            resp = cli.request(step["method"], path,
                               data=body if step["method"] != "GET" else None,
                               headers=hdrs, timeout=6.0)
            step["elapsed"] = round(time.time() - t0, 3)
            step["status"] = int(getattr(resp, "status", 0) or 0)
            step["length"] = len(getattr(resp, "body", "") or "")
            step["error"] = str(getattr(resp, "error", "") or "")[:200]
            if modified and 200 <= step["status"] < 300:
                step["interesting"] = True
                step["reason"] = "modified-identity-2xx"
            if modified and step["method"] == "GET" and step["status"]:
                # Capture's true response length comes from the HAR
                # response (analyze_capture attaches _capture_length).
                _capture_len = req.get("_capture_length")
                if isinstance(_capture_len, int) and _capture_len > 0:
                    diff = abs(step["length"] - _capture_len) / _capture_len
                    if diff > 0.30:
                        step["interesting"] = True
                        step["reason"] = (
                            "get-content-diff-%d%%" % round(diff * 100))
        except Exception as exc:  # noqa: BLE001 — never abort a chain mid-way
            step["error"] = str(exc)[:200]
        steps.append(step)
    return steps


# --------------------------------------------------------------- findings ---

def F(sev, title, desc, evidence="", cwe="", owasp="", cvss=0.0, remed="",
      confidence="probable", location="", param="", origin="active"):
    """Same dict shape as vulnscan2.F (kept local so this module stays
    standalone like its sibling engines)."""
    return {"severity": sev, "title": title, "description": desc,
            "evidence": evidence, "cwe": cwe, "owasp": owasp, "cvss": cvss,
            "remediation": remed, "confidence": confidence,
            "location": location, "param": param, "origin": origin}


_IDOR_TITLE = "Replayed Request Bypassed Authorization (IDOR Suspect)"
_STATE_TITLE = "Session Replay Revealed State Change"


def analyze_capture(har, mutations=None, max_steps=50):
    """Parse + replay a HAR capture and build findings for suspicious steps.

    One finding per interesting step: a 2xx under a swapped cookie/token
    becomes the IDOR-suspect finding; a mutated GET whose response length
    drifted >30% from the capture becomes the state-change finding.
    """
    requests = parse_har(har)
    # Attach capture response lengths (content-length of the recorded
    # response, when the HAR export preserved it) for the GET-diff flag.
    try:
        entries = har.get("log", {}).get("entries", []) \
            if isinstance(har, dict) else []
        for req, ent in zip(requests, entries):
            resp = ent.get("response") or {}
            headers = {str(h.get("name", "")).lower(): str(h.get("value", ""))
                       for h in resp.get("headers") or [] if isinstance(h, dict)}
            cl = headers.get("content-length")
            body = resp.get("content") or {}
            text = body.get("text") if isinstance(body, dict) else None
            if cl and cl.isdigit():
                req["_capture_length"] = int(cl)
            elif isinstance(text, str):
                req["_capture_length"] = len(text)
    except Exception:
        pass
    steps = replay_chain(None, requests, mutations=mutations,
                         max_steps=max_steps)
    findings = []
    for st in steps:
        if not st["interesting"]:
            continue
        line = "%s %s" % (st["method"], st["url"])
        if st["reason"] == "modified-identity-2xx":
            findings.append(F(
                "HIGH", _IDOR_TITLE,
                "Replaying a captured request with a MODIFIED identity "
                "(swapped session cookie or Authorization token) still "
                "returned an HTTP 200. The server appears to authorize "
                "the action on something other than the presented "
                "credential — a classic broken-authorization / IDOR "
                "pattern. Verify manually that the returned data truly "
                "belongs to the attacker-controlled identity.",
                evidence="%s -> status %d, %d bytes (replayed with swapped "
                         "identity)" % (line, st["status"], st["length"]),
                cwe="CWE-639", owasp="A01:2021", cvss=8.2,
                remed="Enforce object-level authorization on every "
                      "request: derive the actor identity server-side "
                      "from the authenticated session (never from a "
                      "client-supplied id), check ownership before "
                      "returning data, and return 403 on mismatch. "
                      "Add automated authz regression tests for each "
                      "sensitive endpoint.",
                location=st["url"]))
        else:
            findings.append(F(
                "HIGH", _STATE_TITLE,
                "Replaying a captured GET request with a modified "
                "identity returned content whose size differs by more "
                "than 30%% from the original capture. The endpoint leaks "
                "identity- or state-dependent data to a different "
                "session, indicating a missing authorization check or "
                "an unintended state transition on replay.",
                evidence="%s -> status %d, %d bytes replayed vs %d bytes "
                         "captured (%s length diff)"
                         % (line, st["status"], st["length"],
                            st.get("_capture_length", 0), st["reason"]),
                cwe="CWE-285", owasp="A01:2021", cvss=7.5,
                remed="Audit the endpoint's authorization logic: the "
                      "response must depend only on the authenticated "
                      "principal and explicitly authorized objects. "
                      "Gate state-mutating GET handlers behind POST "
                      "with CSRF protection and re-verify ownership on "
                      "every replayed request.",
                location=st["url"]))
    return {"steps": steps, "findings": findings}


# ----------------------------------------------------------------- actions --
# Handlers follow the sibling actions.py pattern: (args, port) -> result
# dict, running behind app2.py's /actions session + admin gate. `port` is
# unused here (everything is local replay), but the signature keeps the
# dispatch contract uniform.

def _a_import_har(args: dict, port: int) -> dict:
    name = str(args.get("name") or "capture")[:100]
    raw = args.get("data")
    b64 = False
    if raw is None:
        raw = args.get("dataBase64")
        b64 = True
    if raw is None:
        raise ValueError("provide 'data' (raw HAR JSON) or 'dataBase64'")
    if b64:
        try:
            raw = base64.b64decode(str(raw), validate=False)
        except Exception as exc:  # noqa: BLE001
            raise ValueError("invalid base64 HAR data: %s" % exc)
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    try:
        har = json.loads(raw) if isinstance(raw, str) else raw
    except Exception as exc:  # noqa: BLE001
        raise ValueError("HAR JSON parse failed: %s" % exc)
    requests = parse_har(har)
    if not requests:
        raise ValueError("no parsable HAR entries found (expected "
                         "log.entries[].request)")
    cid = _store_capture(name, har)
    return {"id": cid, "name": name, "entries": len(requests)}


def _a_replay_capture(args: dict, port: int) -> dict:
    cid = str(args.get("id") or "")
    with _STORE_LOCK:
        cap = _CAPTURES.get(cid)
    if cap is None:
        raise ValueError("unknown capture id %r" % cid)
    mutations = args.get("mutations")
    if not isinstance(mutations, dict):
        mutations = None
    result = analyze_capture(cap["har"], mutations=mutations)
    summary = {"steps": len(result["steps"]),
               "interesting": sum(1 for s in result["steps"]
                                  if s["interesting"]),
               "statuses": {str(s["status"]): 1 for s in result["steps"]}}
    with _STORE_LOCK:
        _REPLAYS[cid] = {"ts": time.time(),
                         "findings": result["findings"],
                         "steps": result["steps"]}
    return {"id": cid, "summary": summary,
            "findings": result["findings"], "steps": result["steps"]}
