"""DOCX pentest report generator — stdlib only (zipfile + hand-built OOXML).

v3.5.1 — format laporan formal standar internasional, selaras penuh dengan
keluaran HTML: halaman sampul resmi, Document Control + riwayat versi, daftar
isi (field Word), Executive Summary + matriks risiko, Scope & Methodology +
profil teknologi, Findings Summary, Detailed Findings bernomor 4.N (atribut,
evidence & PoC sebagai blok monospace ber-shading, langkah reproduksi,
dampak, remediasi, referensi), Remediation Roadmap, Appendix A–C (metodologi
risiko, metadata, format submisi HackerOne). Header klasifikasi & footer
nomor halaman (PAGE/NUMPAGES) di semua halaman.
"""
import html as H
import json
import os
import time
import zipfile

import report_common as RC
import report_i18n as RI

COMPANY = os.environ.get("PTK_COMPANY", "PTK Security Assessment")
VERSION = "1.2.1"
NAVY = "16365C"
ZEBRA = "F4F6F9"
SEV_COLOR = {"CRITICAL": "9B2226", "HIGH": "C05621", "MEDIUM": "975A16",
             "LOW": "4A5568", "INFO": "2B6CB0", "CLEAN": "276749"}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "CLEAN": 5}
CONF_LABEL = {"confirmed": "Confirmed", "probable": "Probable", "candidate": "Candidate"}
STATUS_LABEL = {"open": "Open", "confirmed": "Confirmed",
                "false_positive": "False Positive", "fixed": "Fixed"}


def _r(text, size=22, bold=False, color=None, font=None, italic=False):
    esc = H.escape(str(text))
    rpr = f'<w:rPr><w:sz w:val="{size}"/>'
    if font:
        rpr += f'<w:rFonts w:ascii="{font}" w:hAnsi="{font}"/>'
    if bold:
        rpr += "<w:b/>"
    if italic:
        rpr += "<w:i/>"
    if color:
        rpr += f'<w:color w:val="{color}"/>'
    rpr += "</w:rPr>"
    return f'<w:r>{rpr}<w:t xml:space="preserve">{esc}</w:t></w:r>'


def _p(runs, style=None, spacing_after=120, align=None, spacing_before=0):
    ppr = "<w:pPr>"
    if style:
        ppr += f'<w:pStyle w:val="{style}"/>'
    if align:
        ppr += f'<w:jc w:val="{align}"/>'
    ppr += f'<w:spacing w:after="{spacing_after}" w:before="{spacing_before}"/></w:pPr>'
    return f"<w:p>{ppr}{''.join(runs)}</w:p>"


def _pagebreak():
    return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'


def _cell(runs, w=None, shade=None):
    pr = f'<w:tcPr><w:tcW w:w="{w}" w:type="dxa"/>' if w else "<w:tcPr>"
    if shade:
        pr += f'<w:shd w:val="clear" w:fill="{shade}"/>'
    pr += "</w:tcPr>"
    content = "".join(runs)
    if not content.lstrip().startswith("<w:p"):
        content = "<w:p>" + content + "</w:p>"
    return f"<w:tc>{pr}{content}</w:tc>"


def _table(widths, rows, band=False):
    tbl = ['<w:tbl><w:tblPr><w:tblW w:w="9000" w:type="dxa"/><w:tblBorders>'
           + "".join(f'<w:{e} w:val="single" w:sz="4" w:color="B9C2CF"/>'
                     for e in ["top", "left", "bottom", "right", "insideH", "insideV"])
           + "</w:tblBorders></w:tblPr><w:tblGrid>"
           + "".join(f'<w:gridCol w:w="{w}"/>' for w in widths) + "</w:tblGrid>"]
    for ri, (cells, header) in enumerate(rows):
        tr = "<w:tr>"
        for (txt, w, color, bold) in cells:
            shade = NAVY if header else (ZEBRA if band and ri % 2 == 0 and ri > 0 else None)
            tr += _cell([_r(txt, 18, bold=bold or header,
                            color="FFFFFF" if header else color)],
                        w=w, shade=shade)
        tbl.append(tr + "</w:tr>")
    tbl.append("</w:tbl>")
    return "".join(tbl)


def _codeblock(text, width=9000):
    """Blok monospace ber-shading untuk Evidence / PoC (1x1 table)."""
    lines = str(text).splitlines() or [""]
    paras = "".join(_p([_r(ln, 17, color="1F2A37", font="Consolas")], spacing_after=0)
                    for ln in lines)
    borders = "".join(f'<w:{e} w:val="single" w:sz="4" w:color="B9C2CF"/>'
                      for e in ["top", "left", "bottom", "right"])
    return (f'<w:tbl><w:tblPr><w:tblW w:w="{width}" w:type="dxa"/>'
            f"<w:tblBorders>{borders}</w:tblBorders></w:tblPr>"
            f'<w:tblGrid><w:gridCol w:w="{width}"/></w:tblGrid>'
            f'<w:tr><w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/>'
            f'<w:shd w:val="clear" w:fill="{ZEBRA}"/></w:tcPr>{paras}</w:tc></w:tr></w:tbl>')


def C(txt, w, color=None, bold=False):
    return (str(txt), w, color, bold)


def generate_docx(scan, findings, path, lang="en"):
    lang = RI.norm_lang(lang)

    def T(key, **kw):
        return RI.t(lang, key, **kw)

    def _conf(code):
        code = code if code in ("confirmed", "probable", "candidate") else "probable"
        return RI.conf_label(lang, code)

    def _status(code):
        code = code if code in ("open", "confirmed", "false_positive", "fixed") else "open"
        return RI.status_label(lang, code)
    risk = scan.get("overall_risk", "-")
    findings = sorted(findings, key=lambda f: (SEV_ORDER.get(f["severity"], 9),
                                               -float(f.get("cvss") or 0)))
    started = time.localtime(scan.get("started_at") or time.time())
    report_id = f"RPT-{time.strftime('%Y%m%d', started)}-{str(scan.get('id', '000000'))[:6].upper()}"
    fingerprint = RC.data_fingerprint(scan)
    date_str = RI.format_date(lang, started)
    dt_str = time.strftime("%Y-%m-%d %H:%M", started)
    meta = {}
    try:
        meta = json.loads(scan.get("result") or "{}")
    except Exception:
        meta = {}
    risk_score = meta.get("risk_score")
    target = scan.get("target", "")
    stype = scan.get("scan_type", "vulnscan")
    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    atype = (T("atype_mobile") if stype == "mobile" else T("atype_web"))
    body = []

    # ---------------- COVER ----------------
    body.append(_p([_r("CONFIDENTIAL — TLP:AMBER", 20, True, "9B2226")],
                   align="center", spacing_after=60))
    body.append(_p([_r("━" * 46, 16, color=NAVY)], align="center", spacing_after=500))
    body.append(_p([_r(COMPANY.upper(), 20, color="5B6B7F")], align="center", spacing_after=420))
    body.append(_p([_r(T("cover_title").upper(), 44, True, NAVY)], align="center", spacing_after=80))
    body.append(_p([_r(T("cover_subtitle"), 21,
                       color="33475B")], align="center", spacing_after=500))
    cw = [2600, 6400]
    cover_rows = [([C(T("lbl_target"), cw[0], None, True), C(target, cw[1])], False),
                  ([C(T("lbl_report_id"), cw[0], None, True), C(report_id, cw[1])], False),
                  ([C(T("lbl_assessment_date"), cw[0], None, True), C(date_str, cw[1])], False),
                  ([C(T("lbl_overall_risk"), cw[0], None, True),
                    C(RI.sev_label(lang, risk) + (("  " + T("risk_score_part", score=risk_score)) if risk_score is not None else ""),
                      cw[1], SEV_COLOR.get(risk), True)], False),
                  ([C(T("lbl_doc_version"), cw[0], None, True), C(T("doc_version_val"), cw[1])], False),
                  ([C(T("lbl_classification"), cw[0], None, True), C("CONFIDENTIAL — TLP:AMBER", cw[1])], False)]
    body.append(_table(cw, cover_rows))
    body.append(_p([_r("", 10)], spacing_after=700))
    body.append(_p([_r("━" * 46, 16, color=NAVY)], align="center", spacing_after=60))
    body.append(_p([_r("CONFIDENTIAL — TLP:AMBER", 20, True, "9B2226")], align="center"))
    body.append(_pagebreak())

    # ---------------- DOCUMENT CONTROL ----------------
    body.append(_p([_r(T("h_doc_control"), 28, True, NAVY)], style="Heading1"))
    dc = [([C(T("lbl_field"), 2400), C(T("lbl_detail"), 6600)], True),
          ([C(T("lbl_report_id"), 2400), C(f"{report_id} · {T('lbl_scan_id')}: {scan.get('id', '-')}", 6600)], False),
          ([C(T("lbl_source_hash"), 2400), C(fingerprint, 6600)], False),
          ([C(T("lbl_prepared_by"), 2400), C(T("prepared_by_val", version=VERSION), 6600)], False),
          ([C(T("lbl_target"), 2400), C(target, 6600)], False),
          ([C(T("lbl_assessment_type"), 2400), C(f"{atype} — {T('profile_word')}: {scan.get('profile', '-')}", 6600)], False),
          ([C(T("lbl_datetime"), 2400), C(dt_str, 6600)], False),
          ([C(T("lbl_classification"), 2400), C(T("classification_val"), 6600)], False),
          ([C(T("lbl_distribution"), 2400), C(T("distribution_val"), 6600)], False),
          ([C(T("lbl_verification_status"), 2400), C(T("verification_status_val"), 6600)], False)]
    body.append(_table([2400, 6600], dc, band=True))
    body.append(_p([_r(T("h_version_history"), 23, True, NAVY)], spacing_before=200, spacing_after=60))
    vh = [([C(T("col_version"), 1500), C(T("lbl_date"), 2000), C(T("lbl_description"), 5500)], True),
          ([C("1.0", 1500), C(date_str, 2000),
            C(T("version_history_val"), 5500)], False)]
    body.append(_table([1500, 2000, 5500], vh))
    body.append(_p([_r(T("h_contents"), 23, True, NAVY)], spacing_before=200, spacing_after=40))
    body.append('<w:p><w:pPr><w:spacing w:after="60"/></w:pPr>'
                '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
                '<w:r><w:instrText xml:space="preserve"> TOC \\o "1-2" \\h \\z \\u </w:instrText></w:r>'
                '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
                '<w:r><w:t>' + " · ".join(
                    T(k) for k in ("h_doc_control", "sec1", "sec2", "sec3", "sec4",
                                   "sec5", "appA", "appB", "appC_short")
                ).replace("&", "&amp;") + " — " + T("toc_update_hint") + '</w:t></w:r>'
                '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>')

    # ---------------- 1. EXECUTIVE SUMMARY ----------------
    body.append(_p([_r(T("sec1"), 28, True, NAVY)], style="Heading1"))
    n = len(findings)
    sev_txt = ", ".join(f"{RI.sev_label(lang, k)} {v}" for k, v in by_sev.items() if v)
    body.append(_p([_r(
        T("exec_para_docx", target=target, profile=scan.get("profile", "-"), n=n,
          sev_part=f" ({sev_txt or T('none_word')})", risk=RI.sev_label(lang, risk),
          score_part=(T("score_part", score=f"{risk_score}/100") if risk_score is not None else "")), 22)]))
    for w in (meta.get("warnings") or []):
        body.append(_p([_r(T("scan_warning_prefix") + str(w), 21, True, "975A16")], spacing_after=60))
    body.append(_p([_r(T("h_risk_matrix"), 23, True, NAVY)], spacing_before=160, spacing_after=60))
    MW = [2000, 1300, 1300, 4400]
    mrows = [([C(T("col_severity"), MW[0]), C(T("col_count"), MW[1]), C(T("col_share"), MW[2]),
               C(T("col_required_response"), MW[3])], True)]
    for s, resp in [("CRITICAL", T("resp_critical")),
                    ("HIGH", T("resp_high")),
                    ("MEDIUM", T("resp_medium")),
                    ("LOW", T("resp_low")),
                    ("INFO", T("resp_info"))]:
        cnt = by_sev.get(s, 0)
        mrows.append(([C(RI.sev_label(lang, s), MW[0], SEV_COLOR.get(s), True), C(str(cnt), MW[1]),
                       C(f"{round(100 * cnt / max(1, n))}%", MW[2]), C(resp, MW[3])], False))
    body.append(_table(MW, mrows, band=True))
    if findings:
        body.append(_p([_r(T("h_highest_priority"), 23, True, NAVY)],
                       spacing_before=160, spacing_after=40))
        for f in findings[:5]:
            body.append(_p([_r(f"— [{RI.sev_label(lang, f['severity'])}] {f['title']} (CVSS {f.get('cvss', 0)})", 20)],
                           spacing_after=30))

    # ---------------- 2. SCOPE & METHODOLOGY ----------------
    body.append(_p([_r(T("sec2"), 28, True, NAVY)], style="Heading1"))
    scope_rows = [([C(T("col_item"), 2400), C(T("lbl_detail"), 6600)], True),
                  ([C(T("lbl_target"), 2400), C(target, 6600)], False),
                  ([C(T("lbl_assessment_type"), 2400), C(atype, 6600)], False),
                  ([C(T("lbl_profile_checks"), 2400), C(T("profile_checks_val", profile=scan.get("profile", "-"), run=meta.get("checks_run", "?"), total=meta.get("checks_total", "?")), 6600)], False),
                  ([C(T("lbl_duration"), 2400), C(T("duration_val", seconds=meta.get("duration_s", "?")), 6600)], False),
                  ([C(T("lbl_start_time"), 2400), C(dt_str, 6600)], False)]
    body.append(_table([2400, 6600], scope_rows, band=True))
    body.append(_p([_r("", 10)], spacing_after=80))
    body.append(_p([_r(T("methodology_para"), 22)]))
    body.append(_p([_r(T("confidence_model_label") + " ", 22, True),
                    _r(T("confidence_model_para"), 22)]))
    body.append(_p([_r(T("limitations_label") + " ", 22, True),
                    _r(T("limitations_para"), 22)]))
    techs = meta.get("tech_profile") or meta.get("technologies") or []
    if techs:
        body.append(_p([_r(T("sec2_1"), 23, True, NAVY)],
                       style="Heading2", spacing_before=160))
        body.append(_p([_r(T("tech_intro_docx"), 22)]))
        TW = [1900, 1300, 900, 1100, 1500, 2300]
        trows = [([C(T("col_technology"), TW[0]), C(T("col_category"), TW[1]), C(T("col_version"), TW[2]),
                   C(T("col_confidence"), TW[3]), C(T("col_cve_candidates"), TW[4]),
                   C(T("col_detection_evidence"), TW[5])], True)]
        for t in techs:
            trows.append(([C(t.get("name", ""), TW[0]), C(t.get("category", ""), TW[1]),
                           C(t.get("version", "") or "-", TW[2]),
                           C(t.get("confidence", ""), TW[3]),
                           C(", ".join(c.get("id", "") for c in
                                      (t.get("cves") or [])) or "-", TW[4]),
                           C(t.get("evidence", ""), TW[5])], False))
        body.append(_table(TW, trows, band=True))
        body.append(_p([_r("", 10)], spacing_after=80))

    # ---------------- 3. FINDINGS SUMMARY ----------------
    body.append(_p([_r(T("sec3"), 28, True, NAVY)], style="Heading1"))
    W = [700, 1000, 4100, 700, 1200, 1300]
    rows = [([C(T("col_id"), W[0]), C(T("col_severity"), W[1]), C(T("col_finding"), W[2]),
              C(T("col_cvss"), W[3]), C(T("col_confidence"), W[4]), C(T("col_status"), W[5])], True)]
    for i, f in enumerate(findings, 1):
        rows.append(([C(f"F-{i:03d}", W[0]),
                      C(RI.sev_label(lang, f["severity"]), W[1], SEV_COLOR.get(f["severity"]), True),
                      C(f["title"], W[2]),
                      C(f.get("cvss", 0), W[3]),
                      C(_conf(f.get("confidence") or "probable"), W[4]),
                      C(_status(f.get("status") or "open"), W[5])], False))
    body.append(_table(W, rows, band=True) if findings else _p([_r(T("no_findings"), 22)]))
    body.append(_p([_r("", 10)], spacing_after=120))

    # ---------------- 4. DETAILED FINDINGS ----------------
    body.append(_p([_r(T("sec4"), 28, True, NAVY)], style="Heading1"))
    AW = [2000, 7000]
    for i, f in enumerate(findings, 1):
        conf = _conf(f.get("confidence") or "probable")
        status = _status(f.get("status") or "open")
        body.append(_p([_r(f"4.{i} F-{i:03d} — {f['title']}", 23, True, NAVY)],
                       style="Heading2", spacing_before=180, spacing_after=60))
        attrs = [([C(T("lbl_attribute"), AW[0]), C(T("lbl_value"), AW[1])], True),
                 ([C(T("lbl_severity"), AW[0]), C(f"{RI.sev_label(lang, f['severity'])} " + T("cvss_score_part", cvss=f.get("cvss", 0)),
                                           AW[1], SEV_COLOR.get(f["severity"]), True)], False),
                 ([C(T("lbl_cvss_vector"), AW[0]), C(RC.cvss_vector(f) + " " + T("cvss_vector_note"), AW[1])], False),
                 ([C(T("lbl_weakness"), AW[0]), C(f"{f.get('cwe') or '-'} | {f.get('owasp') or '-'}", AW[1])], False),
                 ([C(T("lbl_conf_status"), AW[0]), C(f"{conf} / {status}", AW[1])], False),
                 ([C(T("lbl_origin"), AW[0]), C(str(f.get('origin', 'active')).capitalize() + T("origin_suffix"), AW[1])], False)]
        if f.get("location"):
            attrs.append(([C(T("lbl_location"), AW[0]),
                          C(f["location"] + (f" ?{f['param']}" if f.get("param") else ""), AW[1])], False))
        if f.get("assignee"):
            attrs.append(([C(T("lbl_assigned_to"), AW[0]), C(str(f["assignee"]), AW[1])], False))
        if f.get("due_date"):
            attrs.append(([C(T("lbl_remediation_due"), AW[0]), C(str(f["due_date"]), AW[1])], False))
        body.append(_table(AW, attrs))
        body.append(_p([_r("", 10)], spacing_after=60))
        body.append(_p([_r(T("h_description"), 21, True, NAVY)], spacing_after=30))
        body.append(_p([_r(f["description"], 21)], spacing_after=80))
        if f.get("evidence"):
            body.append(_p([_r(T("h_evidence"), 21, True, NAVY)], spacing_after=30))
            body.append(_codeblock(str(f["evidence"])[:900]))
            body.append(_p([_r("", 10)], spacing_after=80))
        body.append(_p([_r(T("h_impact"), 21, True, NAVY)], spacing_after=30))
        body.append(_p([_r(RC.impact_for(f, lang), 21)], spacing_after=80))
        body.append(_p([_r(T("h_steps"), 21, True, NAVY)], spacing_after=30))
        for si, step in enumerate(RC.steps_for(f, target, lang), 1):
            body.append(_p([_r(f"{si}. {step}", 20)], spacing_after=30))
        poc = RC.poc_for(f, target)
        if poc:
            body.append(_p([_r(T("h_poc"), 21, True, NAVY)],
                           spacing_before=60, spacing_after=30))
            body.append(_codeblock(poc))
            body.append(_p([_r("", 10)], spacing_after=80))
        body.append(_p([_r(T("h_remediation"), 21, True, NAVY)], spacing_after=30))
        body.append(_p([_r(f.get("remediation") or T("remediation_default"), 21)],
                       spacing_after=80))
        body.append(_p([_r(T("h_references"), 21, True, NAVY)], spacing_after=30))
        for ref in RC.refs_for(f, lang):
            body.append(_p([_r(f"— {ref}", 19, color="33475B")], spacing_after=20))
        body.append(_p([_r("", 10)], spacing_after=160))

    # ---------------- 5. REMEDIATION ROADMAP ----------------
    body.append(_p([_r(T("sec5"), 28, True, NAVY)], style="Heading1"))
    prio = [(T("prio1_label"), ["CRITICAL"], T("prio1_guide")),
            (T("prio2_label"), ["HIGH"], T("prio2_guide")),
            (T("prio3_label"), ["MEDIUM"], T("prio3_guide")),
            (T("prio4_label"), ["LOW", "INFO"], T("prio4_guide"))]
    RW = [2600, 1200, 5200]
    rrows = [([C(T("col_priority"), RW[0]), C(T("col_findings"), RW[1]), C(T("col_guidance"), RW[2])], True)]
    for label, sevs, guide in prio:
        cnt = sum(1 for f in findings if f["severity"] in sevs)
        rrows.append(([C(label, RW[0]), C(str(cnt), RW[1]), C(guide, RW[2])], False))
    body.append(_table(RW, rrows, band=True))
    body.append(_p([_r(T("roadmap_note"), 20, color="5B6B7F")]))

    # ---------------- APPENDIX A ----------------
    body.append(_p([_r(T("appA"), 28, True, NAVY)], style="Heading1"))
    BW = [1800, 1800, 5400]
    brows = [([C(T("col_severity"), BW[0]), C(T("col_cvss_range"), BW[1]), C(T("col_meaning"), BW[2])], True),
             ([C(RI.sev_label(lang, "CRITICAL"), BW[0], "9B2226", True), C("9.0 – 10.0", BW[1]), C(T("meaning_critical"), BW[2])], False),
             ([C(RI.sev_label(lang, "HIGH"), BW[0], "C05621", True), C("7.0 – 8.9", BW[1]), C(T("meaning_high"), BW[2])], False),
             ([C(RI.sev_label(lang, "MEDIUM"), BW[0], "975A16", True), C("4.0 – 6.9", BW[1]), C(T("meaning_medium"), BW[2])], False),
             ([C(RI.sev_label(lang, "LOW"), BW[0], "4A5568", True), C("0.1 – 3.9", BW[1]), C(T("meaning_low"), BW[2])], False),
             ([C(RI.sev_label(lang, "INFO"), BW[0], "2B6CB0", True), C("0.0", BW[1]), C(T("meaning_info"), BW[2])], False)]
    body.append(_table(BW, brows, band=True))
    body.append(_p([_r(T("appA_note_docx"), 20, color="5B6B7F")]))

    # ---------------- APPENDIX B ----------------
    body.append(_p([_r(T("appB"), 28, True, NAVY)], style="Heading1"))
    brow = [([C(T("lbl_field"), 2400), C(T("lbl_detail"), 6600)], True),
            ([C(T("lbl_engine"), 2400), C(T("engine_val", version=VERSION), 6600)], False),
            ([C(T("lbl_scan_id"), 2400), C(str(scan.get("id", "-")), 6600)], False),
            ([C(T("lbl_report_id"), 2400), C(report_id, 6600)], False),
            ([C(T("lbl_profile"), 2400), C(str(scan.get("profile", "-")), 6600)], False),
            ([C(T("lbl_checks"), 2400), C(f"{meta.get('checks_run', '?')} / {meta.get('checks_total', '?')}", 6600)], False),
            ([C(T("lbl_duration"), 2400), C(T("duration_val", seconds=meta.get("duration_s", "?")), 6600)], False)]
    body.append(_table([2400, 6600], brow, band=True))
    for e in (meta.get("errors") or [])[:10]:
        body.append(_p([_r(T("check_error_prefix") + str(e), 18, color="8A94A6")], spacing_after=30))

    # ---------------- APPENDIX C ----------------
    body.append(_p([_r(T("appC"), 28, True, NAVY)], style="Heading1"))
    body.append(_p([_r(T("appC_intro"), 20, color="5B6B7F")]))
    for i, f in enumerate(findings, 1):
        conf = _conf(f.get("confidence") or "probable")
        body.append(_p([_r(f"C.{i} {T('submission_word')} F-{i:03d}", 22, True, NAVY)],
                       style="Heading2", spacing_before=140, spacing_after=40))
        for label, val in [(T("lbl_title"), f["title"]), (T("lbl_asset"), target),
                           (T("lbl_weakness"), f"{f.get('cwe') or '-'} · {f.get('owasp') or '-'}"),
                           (T("lbl_severity"), f"{RI.sev_label(lang, f['severity'])} — CVSS {f.get('cvss', 0)} · {RC.cvss_vector(f)} · {T('lbl_confidence_word')}: {conf}"),
                           (T("lbl_summary"), f["description"])]:
            body.append(_p([_r(f"{label}: ", 20, True), _r(val, 20)], spacing_after=20))
        steps_txt = " ".join(f"({si}) {s}" for si, s in
                             enumerate(RC.steps_for(f, target, lang), 1))
        body.append(_p([_r(T("h_steps") + ": ", 20, True), _r(steps_txt, 20)], spacing_after=20))
        if f.get("evidence"):
            body.append(_p([_r(T("lbl_supporting") + ": ", 20, True),
                            _r(str(f["evidence"])[:400], 19, color="33475B")], spacing_after=20))
        body.append(_p([_r(T("h_impact") + ": ", 20, True), _r(RC.impact_for(f, lang), 20)], spacing_after=120))

    body.append(_p([_r(T("disclaimer"), 19, color="5B6B7F")], spacing_before=200))
    body.append(_p([_r(T("end_of_report"), 19, True, NAVY)], align="center", spacing_before=120))
    body.append(_p([_r("CONFIDENTIAL — TLP:AMBER", 17, True, "9B2226")], align="center", spacing_after=0))

    sect = ('<w:sectPr>'
            '<w:headerReference w:type="default" r:id="rId3"/>'
            '<w:footerReference w:type="default" r:id="rId4"/>'
            '<w:pgSz w:w="11906" w:h="16838"/>'
            '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" '
            'w:header="720" w:footer="720"/></w:sectPr>')
    document = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                "<w:body>" + "".join(body) + sect + "</w:body></w:document>")
    styles = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
              '<w:docDefaults><w:rPrDefault><w:rPr>'
              '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/>'
              '</w:rPr></w:rPrDefault></w:docDefaults>'
              '<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/>'
              '<w:pPr><w:outlineLvl w:val="0"/><w:spacing w:before="300" w:after="140"/>'
              '<w:pBdr><w:bottom w:val="single" w:sz="12" w:color="16365C"/></w:pBdr></w:pPr>'
              '<w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="16365C"/></w:rPr></w:style>'
              '<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/>'
              '<w:pPr><w:outlineLvl w:val="1"/><w:spacing w:before="200" w:after="80"/></w:pPr>'
              '<w:rPr><w:b/><w:sz w:val="23"/><w:color w:val="16365C"/></w:rPr></w:style>'
              '</w:styles>')
    ct = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
<Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>
<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>
</Types>'''
    rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>'''
    doc_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/>
<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>
</Relationships>'''
    settings = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>'''
    hdr = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           '<w:p><w:pPr><w:jc w:val="center"/>'
           '<w:pBdr><w:bottom w:val="single" w:sz="4" w:color="B9C2CF"/></w:pBdr></w:pPr>'
           f'<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="5B6B7F"/></w:rPr>'
           f'<w:t>{T("cover_title")} · {H.escape(report_id)} · </w:t></w:r>'
           '<w:r><w:rPr><w:b/><w:sz w:val="16"/><w:color w:val="9B2226"/></w:rPr>'
           '<w:t>CONFIDENTIAL — TLP:AMBER</w:t></w:r></w:p></w:hdr>')
    ftr = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           '<w:p><w:pPr><w:jc w:val="center"/>'
           '<w:pBdr><w:top w:val="single" w:sz="4" w:color="B9C2CF"/></w:pBdr></w:pPr>'
           '<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="5B6B7F"/></w:rPr>'
           f'<w:t>CONFIDENTIAL — TLP:AMBER · {T("page_word")} </w:t></w:r>'
           '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
           '<w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r>'
           '<w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>1</w:t></w:r>'
           '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
           f'<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="5B6B7F"/></w:rPr><w:t> {T("of_word")} </w:t></w:r>'
           '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
           '<w:r><w:instrText xml:space="preserve"> NUMPAGES </w:instrText></w:r>'
           '<w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>1</w:t></w:r>'
           '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
           '</w:p></w:ftr>')
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/document.xml", document)
        z.writestr("word/_rels/document.xml.rels", doc_rels)
        z.writestr("word/styles.xml", styles)
        z.writestr("word/settings.xml", settings)
        z.writestr("word/header1.xml", hdr)
        z.writestr("word/footer1.xml", ftr)
    return path
