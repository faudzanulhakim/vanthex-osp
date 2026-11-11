"""
csminer.py — Client-Side Zero-Day Miner (runtime data-flow tracking) for
VANTHEX. AUTHORIZED TESTING ONLY — static analysis plus copy-paste console
probes for a human tester; this module never executes browser code itself.

Core is a pure-python instrumented-JS analyzer (no Playwright required):
JSFlowTracer parses HTML/JS text and emits dataflow records
  {source, sink, var_chain, file, line, taint}
for source->sink pairs:

  sources: location.hash, location.search, document.referrer,
           postMessage event.data, window.name
  sinks:   innerHTML, document.write, eval, setTimeout(string),
           src attribute assignment, fetch(url)

Taint is broken by an intervening sanitizer call on the path
(escape*/encodeURI*/encodeURIComponent/DOMPurify/sanitizeHtml/trustedTypes/
TrustedHTML mentions). This is heuristic static analysis — findings are
always "candidate" with verification "static-analysis"; runtime_probe_plan()
turns tainted flows into concrete browser-console probe snippets for a
human tester instead of executing anything.

Optional live-mode check c_cs_mine(ctx, add) follows the scan-check
signature of zerodayheur.c_zeroday_heur — operator-gated (PTK_CSMINE=1),
static tracer only, capped at 5 findings, English text.
sink_stats(dataflows) feeds the attack-surface map with sink usage counts.
"""
import os as _os
import re as _re

def _F():
    # lazy import: vulnscan2 loads this module, so a top-level import
    # would be circular
    from vulnscan2 import F
    return F

MAX_FINDINGS = 5

# ------------------------------------------------------------ sources
SOURCES = (
    "location.hash", "location.search", "document.referrer",
    "event.data", "window.name",
)

# ------------------------------------------------------------ sinks
SINKS = (
    "innerHTML", "document.write", "eval",
    "setTimeout", "fetch",
)

# attribute-style sink:  el.src = <expr>
_SRC_ASSIGN = _re.compile(
    r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.src\s*=")
# srcdoc also dangerous via attribute assignment
_SRCDOC_ASSIGN = _re.compile(
    r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.srcdoc\s*=")

_SANITIZERS = _re.compile(
    r"(?i)(escape|encodeURI|encodeURIComponent|DOMPurify|sanitize"
    r"|trustedTypes|TrustedHTML|TrustedTypes|textContent\s*=)")

_SOURCE_TOKENS = {
    "location.hash": "location.hash",
    "location.search": "location.search",
    "document.referrer": "document.referrer",
    "postMessage event.data": "event.data",
    "window.name": "window.name",
}

_SCRIPT_RE = _re.compile(r"<script\b[^>]*>(.*?)</script>",
                         _re.DOTALL | _re.IGNORECASE)
_ASSIGN_RE = _re.compile(
    r"^\s*(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*(.+?);?\s*$")
_METHOD_SINK_RE = {
    "eval": _re.compile(r"(?<![\w.$])eval\s*\("),
    "setTimeout": _re.compile(r"(?<![\w.$])setTimeout\s*\(\s*['\"`]?"),
    "fetch": _re.compile(r"(?<![\w.$])fetch\s*\("),
    "document.write": _re.compile(r"document\.write(?:ln)?\s*\("),
    "innerHTML": _re.compile(r"\.innerHTML\s*="),
    "outerHTML": _re.compile(r"\.outerHTML\s*="),
}


def _extract_scripts(html_text, filename="inline"):
    """Yield (js_text, start_line, label) for each <script> block; plain
    JS text (no tags) is treated as one whole script at line 1."""
    if "<" not in html_text or not _SCRIPT_RE.search(html_text):
        yield html_text, 1, filename
        return
    for m in _SCRIPT_RE.finditer(html_text):
        start = html_text[:m.start(1)].count("\n") + 1
        yield m.group(1), start, f"{filename}#script[{start}]"


def _find_sink(line):
    """Return sink name if the line writes to a sink, else None."""
    if ".innerHTML" in line and _re.search(r"\.innerHTML\s*=", line):
        return "innerHTML"
    if ".outerHTML" in line and _re.search(r"\.outerHTML\s*=", line):
        return "outerHTML"
    if _re.search(r"document\.write(?:ln)?\s*\(", line):
        return "document.write"
    if _re.search(r"(?<![\w.$])eval\s*\(", line):
        return "eval"
    if _re.search(r"(?<![\w.$])setTimeout\s*\(\s*['\"`]", line):
        return "setTimeout"      # string-arg form only
    if _re.search(r"(?<![\w.$])setTimeout\s*\(\s*[A-Za-z_$][\w$]*", line):
        return "setTimeout"      # identifier holding code
    if _re.search(r"(?<![\w.$])fetch\s*\(", line):
        return "fetch"
    if _SRC_ASSIGN.search(line):
        return "src"
    if _SRCDOC_ASSIGN.search(line):
        return "srcdoc"
    return None


def _find_source(line):
    """Return source label if the line reads a taint source, else None."""
    for label, tok in _SOURCE_TOKENS.items():
        if tok in line:
            return label
    return None


def _sanitize_in(line):
    return bool(_SANITIZERS.search(line))


class JSFlowTracer:
    """Static instrumented-JS analyzer: HTML/JS text in, dataflow records
    out. Pure python — no browser, no third-party deps."""

    def trace(self, html_text, filename="inline"):
        """Trace one page/script. Returns a list of dataflow records
        {source, sink, var_chain, file, line, taint}."""
        records = []
        for js, start_line, label in _extract_scripts(html_text or "",
                                                      filename):
            records.extend(self._trace_script(js, start_line, label))
        return records

    def _trace_script(self, js, start_line, label):
        records = []
        tainted = {}      # var -> source label (braces tracked lightly)
        origin = {}       # var -> original source, kept even after sanitize
        depth = 0
        brace_stack = []  # snapshot of tainted-set sizes per open brace
        for i, raw in enumerate(js.splitlines()):
            line = raw
            ln = start_line + i
            # sink on this line?
            sink = _find_sink(line)
            if sink:
                chain = None if _sanitize_in(line) else \
                    self._var_chain(line, tainted)
                if chain:
                    records.append({
                        "source": chain["source"], "sink": sink,
                        "var_chain": chain["chain"], "file": label,
                        "line": ln, "taint": True})
                else:
                    # sink reached but chain broken (sanitizer or clean
                    # value) — recorded as an untainted dataflow
                    records.append({
                        "source": self._chain_source(line, origin) or
                                  self._chain_source(line, tainted) or "",
                        "sink": sink, "var_chain": [], "file": label,
                        "line": ln, "taint": False})
            # assignment tracking (taint propagation)
            m = _ASSIGN_RE.match(line)
            if m:
                var, rhs = m.group(1), m.group(2)
                src = _find_source(rhs)
                if src:
                    tainted = dict(tainted)
                    tainted[var] = src
                    origin[var] = src
                elif _sanitize_in(rhs) or _find_source(rhs) is None:
                    if var in tainted:
                        tainted = dict(tainted)
                        if _sanitize_in(rhs):
                            del tainted[var]
                        # plain reassignment from unknown kills taint
                        elif not _find_sink(rhs):
                            del tainted[var]
            # minimal brace tracking: snapshot taint at block entry
            opens = line.count("{")
            closes = line.count("}")
            if opens > closes:
                brace_stack.append(dict(tainted))
            if closes > opens and brace_stack:
                # block closed: restore a snapshot conservatively
                tainted = brace_stack.pop() if brace_stack else {}
        return records

    def _var_chain(self, line, tainted):
        """Match sink arguments against tainted vars; returns
        {source, chain} or None. Also catches direct source-in-sink."""
        best = None
        for var, src in tainted.items():
            if _re.search(r"(?<![\w.$])" + _re.escape(var) +
                          r"(?![\w$])", line):
                chain = [src, var]
                best = {"source": src, "chain": chain}
                break
        if best is None:
            # direct flow: source expression written straight to the sink
            src = _find_source(line)
            if src:
                best = {"source": src, "chain": [src]}
        return best

    def _chain_source(self, line, tainted):
        for var, src in tainted.items():
            if _re.search(r"(?<![\w.$])" + _re.escape(var) + r"(?![\w$])",
                          line):
                return src
        return _find_source(line)


# ------------------------------------------------------------ probe plan
def runtime_probe_plan(dataflows):
    """For tainted flows produce concrete browser-console probe snippets
    (copy-paste JS for a human tester). Nothing is executed here — the
    output is a list of dicts {source, sink, file, line, snippet, note}."""
    plans = []
    payload = "csminer-probe"
    for df in dataflows:
        if not df.get("taint"):
            continue
        src = df.get("source") or ""
        sink = df.get("sink") or ""
        loc = df.get("file") or "inline"
        ln = df.get("line") or 0
        if src == "location.hash":
            inject = (f"location.hash = encodeURIComponent('#{payload}'); "
                      f"/* then reload the page */")
        elif src == "location.search":
            inject = (f"history.replaceState(null,'',"
                      f"'?q={payload}'); /* then reload the page */")
        elif src == "document.referrer":
            inject = (f"/* navigate from a page whose Referer header is "
                      f"'{payload}' (e.g. via a link with referrer set) */")
        elif src == "postMessage event.data":
            inject = (f"window.postMessage('{payload}', '*'); "
                      f"/* triggers the message listener */")
        elif src == "window.name":
            inject = (f"window.name = '{payload}'; "
                      f"/* then trigger the code that reads window.name */")
        else:
            inject = f"/* set {src} to '{payload}' */"
        snippet = (
            f"// VANTHEX csminer probe — {sink} at {loc}:{ln}\n"
            f"{inject}\n"
            f"// watch: open DevTools, set a breakpoint at {loc} line {ln} "
            f"(or 'debugger;' via Sources) and check whether '{payload}' "
            f"reaches the {sink} sink"
        )
        plans.append({
            "source": src, "sink": sink, "file": loc, "line": ln,
            "snippet": snippet,
            "note": f"Manual verification for {src} -> {sink} "
                    f"({loc}:{ln}); paste the snippet in the browser "
                    f"console and confirm the sink receives the marker."})
    return plans


# ------------------------------------------------------------ sink stats
def sink_stats(dataflows):
    """Sink usage counts for the attack-surface map:
    {sink: {'total': n, 'tainted': n}} plus a 'sources' breakdown."""
    stats = {}
    for df in dataflows or []:
        sink = df.get("sink") or "unknown"
        e = stats.setdefault(sink, {"total": 0, "tainted": 0})
        e["total"] += 1
        if df.get("taint"):
            e["tainted"] += 1
    return stats


# ------------------------------------------------------------ check hook
def c_cs_mine(ctx, add):
    """Operator-gated check (PTK_CSMINE=1): client-side data-flow mining
    over already-collected page bodies (static tracer only — no browser
    needed). Findings are candidate/static-analysis, capped at 5."""
    if not (_os.environ.get("PTK_CSMINE") == "1"
            or _os.environ.get("VANTHEX_CSMINE") == "1"):
        ctx.L("  [csminer] operator gate PTK_CSMINE not set — skipped")
        return
    pages = []
    getter = getattr(ctx, "page_bodies", None)
    if callable(getter):
        try:
            pages = getter() or []
        except Exception:
            pages = []
    if not pages:
        ctx.L("  [csminer] no collected page bodies available — skipped")
        return
    tracer = JSFlowTracer()
    total = 0
    for url, body in pages:
        if ctx.cancelled() or total >= MAX_FINDINGS:
            break
        if not body:
            continue
        try:
            flows = [d for d in tracer.trace(body, url) if d["taint"]]
        except Exception as exc:
            ctx.L(f"  [csminer] {url} trace failed: {exc}")
            continue
        for df in flows:
            if total >= MAX_FINDINGS:
                break
            chain = " -> ".join(df["var_chain"]) if df["var_chain"] \
                else df["source"]
            add(_F()(
                "MEDIUM",
                "Client-Side Data Flow: Tainted Source Reaches Sink "
                "Without Sanitizer",
                f"Static client-side analysis of the page at {df['file']} "
                f"found a value read from {df['source']} flowing into the "
                f"sink {df['sink']} with no intervening sanitizer call "
                f"(escape/encodeURI/DOMPurify/trusted-types). If the flow "
                f"is reachable at runtime, attacker-controlled input can "
                f"execute script in the victim's browser (DOM XSS). "
                f"Verification requires a manual browser-console probe — "
                f"see runtime_probe_plan().",
                evidence=f"var_chain: {chain}; source={df['source']}; "
                         f"sink={df['sink']}; location={df['file']}:"
                         f"{df['line']}",
                cwe="CWE-79", owasp="A03:2021 Injection", cvss=6.1,
                location=f"{df['file']}:{df['line']}",
                param=df["source"],
                remed="Route the value through a sanitizer (DOMPurify or "
                      "Trusted Types) or use textContent instead of "
                      "innerHTML; never pass user-controlled strings to "
                      "eval/setTimeout as code.",
                confidence="candidate", origin="csminer",
                verification="static-analysis",
                verification_note="Static instrumented-JS analysis only; "
                                  "the taint chain was not executed. Use "
                                  "runtime_probe_plan() for a manual "
                                  "console probe."))
            total += 1
    ctx.L(f"  [csminer] done: {total} client-side dataflow finding(s)")


if __name__ == "__main__":
    print("csminer: static client-side taint tracer wired "
          f"(check cap {MAX_FINDINGS} findings)")
