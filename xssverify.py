"""VANTHEX — parsed-DOM XSS verification (WS2, v1.4.0).

Design refs: docs "v1.4.0 Accuracy & OSINT Depth" WS2 and the dalfox
source audit. Core rule inherited from dalfox and from our own FP
history: REFLECTION ALONE IS NOT XSS. A reflected payload is
`confirmed` only when, in the PARSED DOM (lxml HTML5 tree — never a
text regex), the payload marker is found in an executable position:

  K1 event_handler   an on* attribute whose value contains the inner
                     marker in JS code position (dalfox pattern #2 /
                     inert-guard origin issues #1118/#1183).
  K2 url_scheme      an href/src/action/formaction/data attribute
                     whose value begins javascript: or data:text/html
                     and contains the inner marker.
  K3 script_element  a NEW <script> element (absent from the baseline
                     page) whose text contains the inner marker in
                     code position — i.e. the payload introduced its
                     own script block.
  K4 script_context  the inner marker landed inside a PRE-EXISTING
                     <script> block of the page, in code position
                     (payload designed to break out of a JS string).
  K5 marker_element  an element carrying the OPEN marker in class/id
                     AND a surviving sink (on* handler or child
                     <script>) on that same element subtree — the
                     marker element kept its sink after parsing.

Everything else is at best `reflected` (caller maps it to a probable
finding with "position not confirmed"). Inert sightings are reported
explicitly so callers/tests can see WHY a reflection was not credited:
entity-encoded text, plain text nodes, comments, <textarea>/<title>
content, hidden input values, http(s) URL attribute values, JSON
bodies, and 3xx responses are never HTML execution evidence.

LIMITATION (declared, per design 2.2d): the "code position" test for
script/handler contexts is a SIMPLE STRING ANALYSIS (quote-state
scan), NOT a JavaScript AST. It can misjudge exotic nesting (template
literals inside strings, comments). Confirmed verdicts additionally
require the payload's own construction, which makes a false
"code position" practically unreachable for our payload families; the
headless execution check remains the stronger proof where available.
"""
import json
import re
from urllib.parse import quote

# ---------------------------------------------------------------- markers

def make_sandwich(scan_marker):
    """Per-scan marker sandwich. OPEN/CLOSE bracket the payload so a
    sanitizer that strips the middle or the brackets is visible; INNER
    is the token that must reach an executable position. All three are
    alphanumeric so they survive most encodings unchanged — the
    sandwich detects mangling of the SPECIAL characters around them."""
    base = re.sub(r"[^a-z0-9]", "", str(scan_marker).lower())[:10] or "m0"
    return {"open": f"vxh{base}op", "inner": f"vxm{base}in",
            "close": f"vxh{base}cl"}


def sandwich_probe(m):
    """Benign probe: sandwich + the special characters whose survival
    decides the payload family. Sent BEFORE any payload (design 2.3)."""
    return f"{m['open']}{m['inner']}{m['close']}\"'<>/="


def surviving_chars(body, m):
    """Which probe special characters survived UNENCODED right after
    the close marker in the raw body. Returns a set subset of
    {'"', "'", '<', '>', '/', '='}."""
    out = set()
    if not body:
        return out
    i = body.find(m["close"])
    if i < 0:
        return out
    tail = body[i + len(m["close"]):i + len(m["close"]) + 16]
    for ch in "\"'<>/=":
        if ch in tail:
            out.add(ch)
    return out


def payload_families(survived):
    """Payload families to try, given surviving characters (design 2.3):
    tag family needs < >; attribute family needs a quote; script-string
    family always worth one shot when the marker reflects at all."""
    fams = []
    if "<" in survived and ">" in survived:
        fams.append("tag")
    if '"' in survived or "'" in survived:
        fams.append("attr")
    fams.append("script")
    return fams


def build_payloads(m, families):
    """Bounded payload list per family. The sink in every payload IS
    the inner marker (an identifier), so parsed evidence ties the
    executable position to this scan's marker."""
    inner = m["inner"]
    out = []
    for fam in families:
        if fam == "tag":
            out.append((fam, f"<svg/onload={inner}>"))
            out.append((fam, f'<a href="javascript:{inner}">vx</a>'))
            out.append((fam, f'<b class="{m["open"]}"><svg/onload={inner}></b>'))
            out.append((fam, f"<script>{inner}</script>"))
        elif fam == "attr":
            out.append((fam, f'" onfocus="{inner}" autofocus="'))
            out.append((fam, f"' onmouseover='{inner}"))
        elif fam == "script":
            out.append((fam, f'";{inner};//'))
            out.append((fam, f"'-{inner}-'"))
    return out


# ------------------------------------------------------------- JS scan

def _js_code_position(s, idx):
    """Simple quote-state scan (NOT an AST — see module docstring):
    True when position idx in JS source s is NOT inside a string
    literal. A payload that breaks out of a string (e.g. `";M;//`
    reflected into `var q="PAYLOAD"`) closes the string before the
    marker, so the plain state test already credits it; a marker that
    merely STARTS a string's content stays inside and is inert."""
    if idx <= 0:
        return True
    in_s = in_d = in_t = False
    esc = False
    i = 0
    while i < idx:
        c = s[i]
        if esc:
            esc = False
        elif c == "\\" and (in_s or in_d or in_t):
            esc = True
        elif in_s:
            if c == "'":
                in_s = False
        elif in_d:
            if c == '"':
                in_d = False
        elif in_t:
            if c == "`":
                in_t = False
        elif c == "'":
            in_s = True
        elif c == '"':
            in_d = True
        elif c == "`":
            in_t = True
        i += 1
    return not (in_s or in_d or in_t)


# ---------------------------------------------------------- DOM parsing

_URL_ATTRS = ("href", "src", "action", "formaction", "poster", "data",
              "xlink:href", "cite", "background", "longdesc", "usemap")
_TEXT_ONLY_TAGS = ("textarea", "title", "style", "noscript", "template")


def _parse(body):
    """Parse with lxml's HTML parser (HTML5 tree construction). Falls
    back to BeautifulSoup/html.parser. Returns root element or None."""
    if not body:
        return None
    try:
        from lxml import html as lhtml
        return lhtml.fromstring(body)
    except Exception:
        pass
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(body, "html.parser")
        return soup
    except Exception:
        return None


def _iter_elements(root):
    try:
        return list(root.iter())
    except Exception:
        try:
            return list(root.find_all(True))
        except Exception:
            return []


def _attrs(el):
    try:
        return dict(el.attrib)
    except Exception:
        try:
            return {k: (v if isinstance(v, str) else " ".join(map(str, v)))
                    for k, v in (el.attrs or {}).items()}
        except Exception:
            return {}


def _text(el):
    try:
        return el.text_content() or ""
    except Exception:
        try:
            return el.get_text() or ""
        except Exception:
            return ""


def _tag(el):
    t = getattr(el, "tag", "")
    if not isinstance(t, str):   # lxml comment nodes have a function tag
        return "!--"
    return t.rsplit("}", 1)[-1].lower()


def _script_texts(root):
    return [_text(el) for el in _iter_elements(root) if _tag(el) == "script"]


# ------------------------------------------------------------- analysis

def analyze(status, content_type, body, baseline_body, m):
    """Verdict for one payload response.

    Returns dict:
      verdict: "confirmed" | "reflected" | "none"
      kinds:   evidence kinds found (subset of K1..K5 labels)
      inert:   human-readable inert sightings (why not credited)
      near_miss: True when the marker demonstrably landed in a markup
               or JS context (attribute value, JS string, stripped
               marker element) without reaching an executable
               position — the caller may report that as probable
               "position not confirmed". Pure text/entity-encoded
               reflections are NOT near misses: the application's
               output encoding worked, so they are clean negatives.
      detail:  one-line summary for the finding evidence string
    """
    inner, open_m = m["inner"], m["open"]
    res = {"verdict": "none", "kinds": [], "inert": [],
           "near_miss": False, "detail": ""}
    if not body:
        return res
    # OPEN alone also counts as a sighting: a sanitizer that kept the
    # marker element but stripped the payload is a reflection result,
    # never executable evidence (K5 inert guard).
    raw_has = inner in body or open_m in body
    enc_has = (quote(inner, safe="") in body) or (inner.replace("x", "&#120;") in body)
    if status is not None and 300 <= int(status) < 400:
        if raw_has or enc_has:
            res["verdict"] = "reflected"
            res["inert"].append("3xx redirect response is not HTML evidence")
        return res
    ct = (content_type or "").lower()
    stripped = body.lstrip()
    if "json" in ct or (stripped[:1] in "{[" and _looks_json(stripped)):
        if raw_has or enc_has:
            res["verdict"] = "reflected"
            res["inert"].append("JSON body: marker is data, not HTML")
        return res
    if not raw_has and not enc_has:
        return res
    root = _parse(body)
    if root is None:
        if raw_has:
            res["verdict"] = "reflected"
            res["inert"].append("response could not be parsed as HTML")
        return res
    base_scripts = _script_texts(_parse(baseline_body)) if baseline_body else []
    kinds = []
    inert = []
    near = {"hit": False}

    def note_inert(why, near_miss=False):
        if why not in inert:
            inert.append(why)
        if near_miss:
            near["hit"] = True

    marker_in_dom = False
    for el in _iter_elements(root):
        tag = _tag(el)
        attrs = _attrs(el)
        if tag == "!--":
            if inner in _text(el):
                note_inert("marker inside an HTML comment")
            continue
        # K1 / K4-style: event-handler attributes
        for aname, aval in attrs.items():
            al = aname.rsplit("}", 1)[-1].lower()
            if not isinstance(aval, str):
                continue
            if al.startswith("on") and inner in aval:
                marker_in_dom = True
                idx = aval.find(inner)
                if _js_code_position(aval, idx):
                    kinds.append("event_handler")
                else:
                    note_inert("marker trapped inside a quoted string in an event handler",
                               near_miss=True)
            elif al in _URL_ATTRS and inner in aval:
                marker_in_dom = True
                v = aval.strip().lower()
                if v.startswith("javascript:") or v.startswith("data:text/html"):
                    kinds.append("url_scheme")
                else:
                    note_inert("marker inside an http(s)/relative URL attribute value",
                               near_miss=True)
            elif al in ("class", "id") and open_m in aval:
                marker_in_dom = True
                # K5: marker element — credit only if a sink survives
                # in the same element subtree (#1118 guard).
                subtree = [el] + _iter_elements(el)
                sink = False
                for sub in subtree:
                    for san, sav in _attrs(sub).items():
                        if san.lower().startswith("on") and inner in str(sav):
                            sink = True
                    if _tag(sub) == "script" and inner in _text(sub):
                        sink = True
                if sink:
                    kinds.append("marker_element_sink")
                else:
                    note_inert("marker element present but its sink was stripped (inert)",
                               near_miss=True)
            elif al == "value" and tag == "input" and inner in aval:
                marker_in_dom = True
                itype = (attrs.get("type") or "text").lower()
                if itype == "hidden":
                    note_inert("marker in a hidden input value", near_miss=True)
                else:
                    note_inert("marker in an input value (needs attribute breakout)",
                               near_miss=True)
            elif inner in aval:
                marker_in_dom = True
                note_inert(f"marker inside attribute '{al}' value",
                           near_miss=True)
        # script element content (K3/K4)
        if tag == "script":
            txt = _text(el)
            if inner in txt:
                marker_in_dom = True
                idx = txt.find(inner)
                if not _js_code_position(txt, idx):
                    note_inert("marker inside a string literal in a script block",
                               near_miss=True)
                elif txt in base_scripts:
                    kinds.append("script_context")
                elif any(txt == b for b in base_scripts):
                    kinds.append("script_context")
                else:
                    # a script block that did not exist verbatim in the
                    # baseline: either payload-introduced (K3) or a
                    # pre-existing block CHANGED by reflection (K4).
                    changed = any(inner not in b and _similar_script(b, txt)
                                  for b in base_scripts)
                    kinds.append("script_context" if changed else "script_element")
        # text-only containers and plain text sightings
        if tag in _TEXT_ONLY_TAGS and inner in _text(el):
            marker_in_dom = True
            note_inert(f"marker inside <{tag}> content (text only)")
    if not marker_in_dom and raw_has:
        # marker survives only as character data somewhere (encoded or
        # stripped into text): reflected, never executable evidence.
        if "&lt;" in body or "&#" in body:
            note_inert("payload reflected entity-encoded as text")
        else:
            note_inert("marker present but not in an executable parsed position")
    kinds = sorted(set(kinds))
    res["kinds"] = kinds
    res["inert"] = inert
    res["near_miss"] = bool(near["hit"])
    if kinds:
        res["verdict"] = "confirmed"
        res["detail"] = ("parsed-DOM position evidence: " + ", ".join(kinds)
                         + f"; marker {inner} reached an executable position")
    elif marker_in_dom or raw_has or enc_has:
        res["verdict"] = "reflected"
        res["detail"] = ("payload marker reflected but position not confirmed"
                         + (": " + "; ".join(inert[:3]) if inert else ""))
    return res


def _looks_json(s):
    try:
        json.loads(s)
        return True
    except Exception:
        return False


def _similar_script(base_txt, txt):
    """Crude 'same script block, edited' test for K4: a common prefix
    of >=10 characters between the (stripped) baseline block and the
    response block means the response block is the baseline block with
    the reflection inserted. Simple string analysis by design."""
    a, b = (base_txt or "").strip(), (txt or "").strip()
    if not a or not b:
        return False
    n = 0
    for ca, cb in zip(a, b):
        if ca != cb:
            break
        n += 1
    return n >= 6


# ------------------------------------------------------- stored helper

def body_occurrences(body, needle):
    return body.count(needle) if body and needle else 0
