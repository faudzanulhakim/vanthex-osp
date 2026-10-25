"""HTML report generator — format laporan pentest formal standar internasional
(v3.5.1). Struktur & gaya mengikuti praktik laporan firma keamanan
profesional: halaman sampul resmi, Document Control, daftar isi, executive
summary, scope & methodology, tabel ringkasan temuan, detail temuan bernomor
(4.1, 4.2, ...), remediation roadmap, dan lampiran metodologi/metadata/format
submisi. Siap cetak A4 (@page: header/footer berjalan, nomor halaman), tanpa
elemen dekoratif non-formal. Konten selaras penuh dengan keluaran DOCX.
"""
import html as H
import json
import os
import time

import report_common as RC
import report_i18n as RI

COMPANY = os.environ.get("PTK_COMPANY", "PTK Security Assessment")
VERSION = "1.2.1"

SEV_COLOR = {"CRITICAL": "#9B2226", "HIGH": "#C05621", "MEDIUM": "#975A16",
             "LOW": "#4A5568", "INFO": "#2B6CB0", "CLEAN": "#276749"}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "CLEAN": 5}
CONF_LABEL = {"confirmed": "Confirmed", "probable": "Probable",
              "candidate": "Candidate"}
STATUS_LABEL = {"open": "Open", "confirmed": "Confirmed",
                "false_positive": "False Positive", "fixed": "Fixed"}

CSS = """
@page { size: A4; margin: 20mm 17mm 18mm 17mm;
  @top-left { content: "%%TITLE%%"; font: 8pt Arial; color: #8A94A6; }
  @top-right { content: "CONFIDENTIAL — TLP:AMBER"; font: 8pt Arial; color: #9B2226; }
  @bottom-left { content: "CONFIDENTIAL — TLP:AMBER"; font: 8pt Arial; color: #8A94A6; }
  @bottom-right { content: "%%PAGE%% " counter(page) " %%OF%% " counter(pages); font: 8pt Arial; color: #8A94A6; } }
@page :first { @top-left { content: none } @top-right { content: none }
  @bottom-left { content: none } @bottom-right { content: none } }
* { box-sizing: border-box }
body { font-family: Arial, "Helvetica Neue", sans-serif; font-size: 10.5pt; line-height: 1.5;
  color: #1F2A37; margin: 0; background: #E9EDF2; }
.sheet { max-width: 820px; margin: 24px auto; background: #fff; padding: 56px 60px 64px;
  box-shadow: 0 1px 6px rgba(20,40,70,.18); }
@media print { body { background: #fff } .sheet { box-shadow: none; margin: 0; max-width: none; padding: 0 } }
h1, h2, h3, h4 { font-family: "Helvetica Neue", Arial, sans-serif; color: #16365C; margin: 0 }
h2.sec { font-size: 15pt; border-bottom: 2.2px solid #16365C; padding-bottom: 5px;
  margin: 30px 0 12px; page-break-after: avoid; }
h3.sub { font-size: 12pt; margin: 20px 0 8px; page-break-after: avoid; }
h4.lbl { font-size: 10.5pt; margin: 13px 0 4px; color: #16365C; page-break-after: avoid; }
p { margin: 0 0 9px; text-align: justify }
.small { font-size: 9pt; color: #5B6B7F }
table { width: 100%; border-collapse: collapse; margin: 8px 0 14px; font-size: 9.6pt }
th { background: #16365C; color: #fff; text-align: left; padding: 6px 8px; font-size: 9.2pt;
  letter-spacing: .02em }
td { padding: 5.5px 8px; border-bottom: .6pt solid #D8DEE7; vertical-align: top }
tr:nth-child(even) td { background: #F4F6F9 }
table.kv td:first-child { width: 190px; font-weight: bold; color: #33475B; background: #EDF1F6 }
code, pre { font-family: Consolas, "Courier New", monospace }
pre { background: #F4F6F9; border: .6pt solid #D8DEE7; border-left: 3px solid #16365C;
  padding: 8px 10px; font-size: 8.8pt; white-space: pre-wrap; word-break: break-word; margin: 4px 0 10px }
ol, ul { margin: 4px 0 10px; padding-left: 20px } li { margin-bottom: 3px; text-align: justify }
.sev { font-weight: bold; font-size: 9pt; letter-spacing: .04em }
.finding { border-top: 1.4px solid #16365C; padding-top: 10px; margin-top: 20px }
.finding table.kv { margin-top: 6px }
.classif { color: #9B2226; font-weight: bold; letter-spacing: .14em; font-size: 9.5pt; text-align: center }
.cover { text-align: center; padding: 90px 0 0; page-break-after: always }
.cover .rule { border-top: 2.6px solid #16365C; margin: 14px 0 }
.cover h1 { font-size: 27pt; line-height: 1.25; margin: 26px 0 6px }
.cover .subtitle { font-size: 12.5pt; color: #33475B; margin-bottom: 44px }
.cover table { max-width: 520px; margin: 26px auto; text-align: left }
.cover .foot { margin-top: 110px }
.toc { list-style: none; padding: 0; margin: 6px 0 0; font-size: 10.5pt }
.toc li { padding: 3.5px 0; border-bottom: .5pt dotted #B9C2CF }
.toc a { color: #16365C; text-decoration: none }
.toc .lvl2 { padding-left: 22px; font-size: 9.8pt }
.sig { margin-top: 34px; font-size: 9pt; color: #5B6B7F; border-top: .6pt solid #D8DEE7; padding-top: 10px }
details.h1 { border: .6pt solid #D8DEE7; margin: 8px 0; padding: 8px 12px }
details.h1 summary { font-weight: bold; color: #16365C; cursor: pointer }
"""


def _sev(s, label=None):
    return f'<span class="sev" style="color:{SEV_COLOR.get(s, "#333")}">{H.escape(label if label is not None else s)}</span>'


def render_report(scan, findings, lang="en"):
    lang = RI.norm_lang(lang)

    def T(key, **kw):
        return RI.t(lang, key, **kw)

    def _conf(code):
        code = code if code in ("confirmed", "probable", "candidate") else "probable"
        return RI.conf_label(lang, code)

    def _status(code):
        return (RI.status_label(lang, code) if code in
                ("open", "confirmed", "false_positive", "fixed") else str(code))

    css = (CSS.replace("%%TITLE%%", T("cover_title"))
              .replace("%%PAGE%%", T("page_word")).replace("%%OF%%", T("of_word")))
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

    # ---------- Findings Summary + Detail + Appendix C ----------
    sum_rows, detail, h1_blocks, toc_findings = "", "", "", ""
    for i, f in enumerate(findings, 1):
        conf = _conf(f.get("confidence") or "probable")
        status = _status(f.get("status") or "open")
        vec = RC.cvss_vector(f)
        loc = f.get("location") or ""
        prm = f.get("param") or ""
        fid = f"F-{i:03d}"
        sum_rows += f"""<tr><td><b>{fid}</b></td><td>{_sev(f['severity'], RI.sev_label(lang, f['severity']))}</td>
          <td>{H.escape(f['title'])}</td><td>{f.get('cvss', 0)}</td>
          <td>{conf}</td><td>{H.escape(str(status))}</td></tr>"""
        steps = "".join(f"<li>{H.escape(s)}</li>" for s in RC.steps_for(f, target, lang))
        poc = RC.poc_for(f, target)
        poc_html = (f'<h4 class="lbl">{T("h_poc")}</h4><pre>{H.escape(poc)}</pre>'
                    if poc else "")
        refs = "".join(f"<li>{H.escape(r)}</li>" for r in RC.refs_for(f, lang))
        detail += f"""
        <div class="finding" id="f{i}">
          <h3 class="sub">4.{i} {fid} — {H.escape(f['title'])}</h3>
          <table class="kv">
            <tr><td>{T("lbl_severity")}</td><td>{_sev(f['severity'], RI.sev_label(lang, f['severity']))} &nbsp;{T("cvss_score_part", cvss=f.get('cvss', 0))}</td></tr>
            <tr><td>{T("lbl_cvss_vector")}</td><td><code>{H.escape(vec)}</code> <span class="small">{T("cvss_vector_note")}</span></td></tr>
            <tr><td>{T("lbl_weakness")}</td><td>{H.escape(f.get('cwe') or '-')} &nbsp;|&nbsp; {H.escape(f.get('owasp') or '-')}</td></tr>
            <tr><td>{T("lbl_conf_status")}</td><td>{conf} / {H.escape(str(status))}</td></tr>
            <tr><td>{T("lbl_origin")}</td><td>{H.escape(str(f.get('origin', 'active')).capitalize())}{T("origin_suffix")}</td></tr>
            {f'<tr><td>{T("lbl_location")}</td><td><code>{H.escape(loc + (" ?" + prm if prm else ""))}</code></td></tr>' if loc else ''}
            {f'<tr><td>{T("lbl_assigned_to")}</td><td>{H.escape(str(f["assignee"]))}</td></tr>' if f.get('assignee') else ''}
            {f'<tr><td>{T("lbl_remediation_due")}</td><td>{H.escape(str(f["due_date"]))}</td></tr>' if f.get('due_date') else ''}
          </table>
          <h4 class="lbl">{T("h_description")}</h4><p>{H.escape(f.get('description') or '')}</p>
          {f'<h4 class="lbl">{T("h_evidence")}</h4><pre>{H.escape(str(f["evidence"])[:900])}</pre>' if f.get('evidence') else ''}
          <h4 class="lbl">{T("h_steps")}</h4><ol>{steps}</ol>
          {poc_html}
          <h4 class="lbl">{T("h_impact")}</h4><p>{H.escape(RC.impact_for(f, lang))}</p>
          <h4 class="lbl">{T("h_remediation")}</h4><p>{H.escape(f.get('remediation') or T('remediation_default'))}</p>
          <h4 class="lbl">{T("h_references")}</h4><ul>{refs}</ul>
        </div>"""
        steps_txt = " ".join(f"({si}) {s}" for si, s in enumerate(RC.steps_for(f, target, lang), 1))
        h1_blocks += f"""
        <details class="h1"><summary>{fid} — {H.escape(f['title'])}</summary>
          <p><b>{T("lbl_title")}:</b> {H.escape(f['title'])}<br>
          <b>{T("lbl_asset")}:</b> {H.escape(target)}<br>
          <b>{T("lbl_weakness")}:</b> {H.escape(f.get('cwe') or '-')} · {H.escape(f.get('owasp') or '-')}<br>
          <b>{T("lbl_severity")}:</b> {H.escape(RI.sev_label(lang, f['severity']))} — CVSS {f.get('cvss', 0)} · {H.escape(vec)} · {T("lbl_confidence_word")}: {conf}<br>
          <b>{T("lbl_summary")}:</b> {H.escape(f.get('description') or '')}<br>
          <b>{T("h_steps")}:</b> {H.escape(steps_txt)}<br>
          {f'<b>{T("lbl_supporting")}:</b> {H.escape(str(f["evidence"])[:400])}<br>' if f.get('evidence') else ''}
          <b>{T("h_impact")}:</b> {H.escape(RC.impact_for(f, lang))}</p>
        </details>"""
        toc_findings += f'<li class="lvl2"><a href="#f{i}">4.{i} {fid} — {H.escape(f["title"])}</a></li>'

    matrix = "".join(
        f'<tr><td>{_sev(s, RI.sev_label(lang, s))}</td><td style="text-align:center">{by_sev.get(s, 0)}</td>'
        f'<td style="text-align:center">{round(100 * by_sev.get(s, 0) / max(1, len(findings)))}%</td>'
        f'<td>{desc}</td></tr>'
        for s, desc in [("CRITICAL", T("resp_critical")),
                        ("HIGH", T("resp_high")),
                        ("MEDIUM", T("resp_medium")),
                        ("LOW", T("resp_low")),
                        ("INFO", T("resp_info"))])
    top5 = "".join(f'<li>[{H.escape(RI.sev_label(lang, x["severity"]))}] {H.escape(x["title"])} (CVSS {x.get("cvss", 0)})</li>'
                   for x in findings[:5])
    prio = [(T("prio1_label"), ["CRITICAL"], T("prio1_guide")),
            (T("prio2_label"), ["HIGH"], T("prio2_guide")),
            (T("prio3_label"), ["MEDIUM"], T("prio3_guide")),
            (T("prio4_label"), ["LOW", "INFO"], T("prio4_guide"))]
    roadmap = "".join(
        f'<tr><td><b>{lbl}</b></td><td style="text-align:center">{sum(1 for f in findings if f["severity"] in sevs)}</td><td>{guide}</td></tr>'
        for lbl, sevs, guide in prio)
    warnings = "".join(f'<p><b>{T("scan_warning_prefix").strip()}</b> {H.escape(str(w))}</p>'
                       for w in (meta.get("warnings") or []))
    techs = meta.get("tech_profile") or meta.get("technologies") or []
    tech_html = ""
    if techs:
        rows_t = "".join(
            f'<tr><td><b>{H.escape(str(t.get("name", "")))}</b></td>'
            f'<td>{H.escape(str(t.get("category", "")))}</td>'
            f'<td>{H.escape(str(t.get("version") or "-"))}</td>'
            f'<td>{H.escape(str(t.get("confidence", "")))}</td>'
            f'<td>{H.escape(", ".join(c.get("id", "") for c in (t.get("cves") or [])) or "-")}</td>'
            f'<td>{H.escape(str(t.get("evidence", "")))}</td></tr>' for t in techs)
        tech_html = (f'<h3 class="sub">{T("sec2_1").replace("&", "&amp;")}</h3>'
                     f'<p>{T("tech_intro_html")}</p>'
                     f'<table><tr><th>{T("col_technology")}</th><th>{T("col_category")}</th><th>{T("col_version")}</th>'
                     f'<th>{T("col_confidence")}</th><th>{T("col_cve_candidates")}</th>'
                     f'<th>{T("col_detection_evidence")}</th></tr>{rows_t}</table>')

    exec_para = T("exec_para_html",
                  target=f"<b>{H.escape(target)}</b>",
                  profile=f"<b>{H.escape(str(scan.get('profile', '-')))}</b>",
                  nfindings=f"<b>{len(findings)} {T('findings_word')}</b>",
                  risk=f'<b style="color:{SEV_COLOR.get(risk, "#333")}">{H.escape(RI.sev_label(lang, str(risk)))}</b>',
                  score_part=(T("score_part_html", score=f"<b>{risk_score}/100</b>")
                              if risk_score is not None else ""))

    return f"""<!DOCTYPE html><html lang="{lang}"><head><meta charset="utf-8">
<title>{T("cover_title")} {report_id} — {H.escape(target)}</title>
<style>{css}</style></head><body><div class="sheet">

<div class="cover">
  <div class="classif">CONFIDENTIAL — TLP:AMBER</div>
  <div class="rule"></div>
  <div class="small" style="letter-spacing:.22em">{H.escape(COMPANY.upper())}</div>
  <h1>{T("cover_title")}</h1>
  <div class="subtitle">{T("cover_subtitle")}</div>
  <table class="kv">
    <tr><td>{T("lbl_target")}</td><td><b>{H.escape(target)}</b></td></tr>
    <tr><td>{T("lbl_report_id")}</td><td>{report_id}</td></tr>
    <tr><td>{T("lbl_assessment_date")}</td><td>{date_str}</td></tr>
    <tr><td>{T("lbl_overall_risk")}</td><td><b style="color:{SEV_COLOR.get(risk, '#333')}">{H.escape(RI.sev_label(lang, str(risk)))}</b>{f' &nbsp;{T("risk_score_part", score=risk_score)}' if risk_score is not None else ''}</td></tr>
    <tr><td>{T("lbl_doc_version")}</td><td>{T("doc_version_val")}</td></tr>
    <tr><td>{T("lbl_classification")}</td><td>CONFIDENTIAL — TLP:AMBER</td></tr>
  </table>
  <div class="foot"><div class="rule"></div>
  <div class="classif">CONFIDENTIAL — TLP:AMBER</div></div>
</div>

<h2 class="sec">{T("h_doc_control")}</h2>
<table class="kv">
  <tr><td>{T("lbl_report_id")}</td><td>{report_id} &nbsp;·&nbsp; {T("lbl_scan_id")}: {H.escape(str(scan.get('id', '-')))}</td></tr>
  <tr><td>{T("lbl_source_hash")}</td><td style="word-break:break-all">{fingerprint}</td></tr>
  <tr><td>{T("lbl_prepared_by")}</td><td>{T("prepared_by_val", version=VERSION)}</td></tr>
  <tr><td>{T("lbl_target")}</td><td>{H.escape(target)}</td></tr>
  <tr><td>{T("lbl_assessment_type")}</td><td>{T('atype_mobile') if stype == 'mobile' else T('atype_web')} — {T("profile_word")}: {H.escape(str(scan.get('profile', '-')))}</td></tr>
  <tr><td>{T("lbl_datetime")}</td><td>{dt_str}</td></tr>
  <tr><td>{T("lbl_classification")}</td><td>{T("classification_val")}</td></tr>
  <tr><td>{T("lbl_distribution")}</td><td>{T("distribution_val")}</td></tr>
</table>
<h3 class="sub">{T("h_version_history")}</h3>
<table><tr><th style="width:90px">{T("col_version")}</th><th style="width:130px">{T("lbl_date")}</th><th>{T("lbl_description")}</th></tr>
<tr><td>1.0</td><td>{date_str}</td><td>{T("version_history_val")}</td></tr></table>

<h2 class="sec">{T("h_contents")}</h2>
<ol class="toc">
  <li><a href="#s1">{T("sec1")}</a></li>
  <li><a href="#s2">{T("sec2").replace("&", "&amp;")}</a></li>
  <li><a href="#s3">{T("sec3")}</a></li>
  <li><a href="#s4">{T("sec4")}</a></li>
  {toc_findings}
  <li><a href="#s5">{T("sec5")}</a></li>
  <li><a href="#sa">{T("appA")}</a></li>
  <li><a href="#sb">{T("appB")}</a></li>
  <li><a href="#sc">{T("appC")}</a></li>
</ol>

<h2 class="sec" id="s1">{T("sec1")}</h2>
<p>{exec_para}</p>
{warnings}
<h3 class="sub">{T("h_risk_matrix")}</h3>
<table><tr><th>{T("col_severity")}</th><th style="text-align:center;width:90px">{T("col_count")}</th><th style="text-align:center;width:90px">{T("col_share")}</th><th>{T("col_required_response")}</th></tr>
{matrix}</table>
<h3 class="sub">{T("h_highest_priority")}</h3>
<ul>{top5 or '<li>—</li>'}</ul>

<h2 class="sec" id="s2">{T("sec2").replace("&", "&amp;")}</h2>
<table class="kv">
  <tr><td>{T("lbl_target")}</td><td>{H.escape(target)}</td></tr>
  <tr><td>{T("lbl_assessment_type")}</td><td>{T('atype_mobile') if stype == 'mobile' else T('atype_web')}</td></tr>
  <tr><td>{T("lbl_profile_checks")}</td><td>{T("profile_checks_val", profile=H.escape(str(scan.get('profile', '-'))), run=meta.get('checks_run', '?'), total=meta.get('checks_total', '?'))}</td></tr>
  <tr><td>{T("lbl_duration")}</td><td>{T("duration_val", seconds=meta.get('duration_s', '?'))}</td></tr>
  <tr><td>{T("lbl_start_time")}</td><td>{dt_str}</td></tr>
</table>
<p>{T("methodology_para")}</p>
<p><b>{T("confidence_model_label")}</b> {T("confidence_model_para")}</p>
<p><b>{T("limitations_label")}</b> {T("limitations_para")}</p>
{tech_html}

<h2 class="sec" id="s3">{T("sec3")}</h2>
<table><tr><th style="width:60px">{T("col_id")}</th><th style="width:90px">{T("col_severity")}</th><th>{T("col_finding")}</th>
<th style="width:60px">{T("col_cvss")}</th><th style="width:110px">{T("col_confidence")}</th><th style="width:110px">{T("col_status")}</th></tr>
{sum_rows or f'<tr><td colspan="6">{T("no_findings")}</td></tr>'}</table>

<h2 class="sec" id="s4">{T("sec4")}</h2>
{detail or f'<p>{T("no_findings")}</p>'}

<h2 class="sec" id="s5">{T("sec5")}</h2>
<table><tr><th>{T("col_priority")}</th><th style="text-align:center;width:90px">{T("col_findings")}</th><th>{T("col_guidance")}</th></tr>
{roadmap}</table>
<p>{T("roadmap_note")}</p>

<h2 class="sec" id="sa">{T("appA")}</h2>
<p>{T("appA_note_html")}</p>

<h2 class="sec" id="sb">{T("appB")}</h2>
<table class="kv">
  <tr><td>{T("lbl_engine")}</td><td>{T("engine_val", version=VERSION)}</td></tr>
  <tr><td>{T("lbl_scan_id")}</td><td>{H.escape(str(scan.get('id', '-')))}</td></tr>
  <tr><td>{T("lbl_report_id")}</td><td>{report_id}</td></tr>
  <tr><td>{T("lbl_profile")}</td><td>{H.escape(str(scan.get('profile', '-')))}</td></tr>
  <tr><td>{T("lbl_checks")}</td><td>{meta.get('checks_run', '?')} / {meta.get('checks_total', '?')}</td></tr>
  <tr><td>{T("lbl_duration")}</td><td>{T("duration_val", seconds=meta.get('duration_s', '?'))}</td></tr>
</table>

<h2 class="sec" id="sc">{T("appC")}</h2>
<p>{T("appC_intro")}</p>
{h1_blocks or '<p>—</p>'}

<div class="sig">{T("disclaimer")}<br><br>{T("end_of_report")}<br>
<span class="classif" style="font-size:8.5pt">CONFIDENTIAL — TLP:AMBER</span></div>

</div></body></html>"""
