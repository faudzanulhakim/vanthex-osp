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

COMPANY = os.environ.get("PTK_COMPANY", "PTK Security Assessment")
VERSION = "1.0.0"

SEV_COLOR = {"CRITICAL": "#9B2226", "HIGH": "#C05621", "MEDIUM": "#975A16",
             "LOW": "#4A5568", "INFO": "#2B6CB0", "CLEAN": "#276749"}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "CLEAN": 5}
CONF_LABEL = {"confirmed": "Confirmed", "probable": "Probable",
              "candidate": "Candidate"}
STATUS_LABEL = {"open": "Open", "confirmed": "Confirmed",
                "false_positive": "False Positive", "fixed": "Fixed"}

CSS = """
@page { size: A4; margin: 20mm 17mm 18mm 17mm;
  @top-left { content: "Penetration Test Report"; font: 8pt Arial; color: #8A94A6; }
  @top-right { content: "CONFIDENTIAL — TLP:AMBER"; font: 8pt Arial; color: #9B2226; }
  @bottom-left { content: "CONFIDENTIAL — TLP:AMBER"; font: 8pt Arial; color: #8A94A6; }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); font: 8pt Arial; color: #8A94A6; } }
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


def _sev(s):
    return f'<span class="sev" style="color:{SEV_COLOR.get(s, "#333")}">{H.escape(s)}</span>'


def render_report(scan, findings):
    risk = scan.get("overall_risk", "-")
    findings = sorted(findings, key=lambda f: (SEV_ORDER.get(f["severity"], 9),
                                               -float(f.get("cvss") or 0)))
    started = time.localtime(scan.get("started_at") or time.time())
    report_id = f"RPT-{time.strftime('%Y%m%d', started)}-{str(scan.get('id', '000000'))[:6].upper()}"
    fingerprint = RC.data_fingerprint(scan)
    date_str = time.strftime("%d %B %Y", started)
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
        conf = CONF_LABEL.get(f.get("confidence") or "probable", "Probable")
        status = STATUS_LABEL.get(f.get("status") or "open", f.get("status") or "Open")
        vec = RC.cvss_vector(f)
        loc = f.get("location") or ""
        prm = f.get("param") or ""
        fid = f"F-{i:03d}"
        sum_rows += f"""<tr><td><b>{fid}</b></td><td>{_sev(f['severity'])}</td>
          <td>{H.escape(f['title'])}</td><td>{f.get('cvss', 0)}</td>
          <td>{conf}</td><td>{H.escape(str(status))}</td></tr>"""
        steps = "".join(f"<li>{H.escape(s)}</li>" for s in RC.steps_for(f, target))
        poc = RC.poc_for(f, target)
        poc_html = (f'<h4 class="lbl">Proof of Concept</h4><pre>{H.escape(poc)}</pre>'
                    if poc else "")
        refs = "".join(f"<li>{H.escape(r)}</li>" for r in RC.refs_for(f))
        detail += f"""
        <div class="finding" id="f{i}">
          <h3 class="sub">4.{i} {fid} — {H.escape(f['title'])}</h3>
          <table class="kv">
            <tr><td>Severity</td><td>{_sev(f['severity'])} &nbsp;(CVSS v3.1 score: {f.get('cvss', 0)})</td></tr>
            <tr><td>CVSS Vector</td><td><code>{H.escape(vec)}</code> <span class="small">(representative for the weakness class — to be validated against the target environment prior to external submission)</span></td></tr>
            <tr><td>Weakness</td><td>{H.escape(f.get('cwe') or '-')} &nbsp;|&nbsp; {H.escape(f.get('owasp') or '-')}</td></tr>
            <tr><td>Confidence / Status</td><td>{conf} / {H.escape(str(status))}</td></tr>
            <tr><td>Origin</td><td>{H.escape(str(f.get('origin', 'active')).capitalize())} — how this finding was obtained (footprint)</td></tr>
            {f'<tr><td>Location</td><td><code>{H.escape(loc + (" ?" + prm if prm else ""))}</code></td></tr>' if loc else ''}
            {f'<tr><td>Assigned to</td><td>{H.escape(str(f["assignee"]))}</td></tr>' if f.get('assignee') else ''}
            {f'<tr><td>Remediation due</td><td>{H.escape(str(f["due_date"]))}</td></tr>' if f.get('due_date') else ''}
          </table>
          <h4 class="lbl">Description</h4><p>{H.escape(f.get('description') or '')}</p>
          {f'<h4 class="lbl">Evidence</h4><pre>{H.escape(str(f["evidence"])[:900])}</pre>' if f.get('evidence') else ''}
          <h4 class="lbl">Steps to Reproduce</h4><ol>{steps}</ol>
          {poc_html}
          <h4 class="lbl">Impact</h4><p>{H.escape(RC.impact_for(f))}</p>
          <h4 class="lbl">Remediation</h4><p>{H.escape(f.get('remediation') or 'Apply hardening in accordance with OWASP ASVS.')}</p>
          <h4 class="lbl">References</h4><ul>{refs}</ul>
        </div>"""
        steps_txt = " ".join(f"({si}) {s}" for si, s in enumerate(RC.steps_for(f, target), 1))
        h1_blocks += f"""
        <details class="h1"><summary>{fid} — {H.escape(f['title'])}</summary>
          <p><b>Title:</b> {H.escape(f['title'])}<br>
          <b>Asset:</b> {H.escape(target)}<br>
          <b>Weakness:</b> {H.escape(f.get('cwe') or '-')} · {H.escape(f.get('owasp') or '-')}<br>
          <b>Severity:</b> {H.escape(f['severity'])} — CVSS {f.get('cvss', 0)} · {H.escape(vec)} · Confidence: {conf}<br>
          <b>Summary:</b> {H.escape(f.get('description') or '')}<br>
          <b>Steps to Reproduce:</b> {H.escape(steps_txt)}<br>
          {f'<b>Supporting Material (Evidence):</b> {H.escape(str(f["evidence"])[:400])}<br>' if f.get('evidence') else ''}
          <b>Impact:</b> {H.escape(RC.impact_for(f))}</p>
        </details>"""
        toc_findings += f'<li class="lvl2"><a href="#f{i}">4.{i} {fid} — {H.escape(f["title"])}</a></li>'

    matrix = "".join(
        f'<tr><td>{_sev(s)}</td><td style="text-align:center">{by_sev.get(s, 0)}</td>'
        f'<td style="text-align:center">{round(100 * by_sev.get(s, 0) / max(1, len(findings)))}%</td>'
        f'<td>{desc}</td></tr>'
        for s, desc in [("CRITICAL", "Immediate remediation required"),
                        ("HIGH", "Remediate within 30 days"),
                        ("MEDIUM", "Remediate within 90 days"),
                        ("LOW", "Address in the regular hardening cycle"),
                        ("INFO", "Informational; no direct risk")])
    top5 = "".join(f'<li>[{H.escape(x["severity"])}] {H.escape(x["title"])} (CVSS {x.get("cvss", 0)})</li>'
                   for x in findings[:5])
    prio = [("P1 — Immediate (≤ 7 days)", ["CRITICAL"], "Remediate before release or public exposure; validate by retest."),
            ("P2 — High (≤ 30 days)", ["HIGH"], "Schedule within the current sprint."),
            ("P3 — Medium (≤ 90 days)", ["MEDIUM"], "Include in the security backlog."),
            ("P4 — Low (roadmap)", ["LOW", "INFO"], "Periodic hardening and monitoring.")]
    roadmap = "".join(
        f'<tr><td><b>{lbl}</b></td><td style="text-align:center">{sum(1 for f in findings if f["severity"] in sevs)}</td><td>{guide}</td></tr>'
        for lbl, sevs, guide in prio)
    warnings = "".join(f'<p><b>Scan warning:</b> {H.escape(str(w))}</p>'
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
        tech_html = ('<h3 class="sub">2.1 Technology &amp; Integration Profile</h3>'
                     '<p>The following third-party components and services were identified from '
                     'the target\'s response artifacts (headers, cookies, HTML, scripts); '
                     'each entry is accompanied by its detection evidence.</p>'
                     '<table><tr><th>Technology</th><th>Category</th><th>Version</th>'
                     '<th>Confidence</th><th>CVE candidates</th>'
                     f'<th>Detection evidence</th></tr>{rows_t}</table>')

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Penetration Test Report {report_id} — {H.escape(target)}</title>
<style>{CSS}</style></head><body><div class="sheet">

<div class="cover">
  <div class="classif">CONFIDENTIAL — TLP:AMBER</div>
  <div class="rule"></div>
  <div class="small" style="letter-spacing:.22em">{H.escape(COMPANY.upper())}</div>
  <h1>Penetration Test Report</h1>
  <div class="subtitle">Automated Security Assessment</div>
  <table class="kv">
    <tr><td>Target</td><td><b>{H.escape(target)}</b></td></tr>
    <tr><td>Report ID</td><td>{report_id}</td></tr>
    <tr><td>Assessment date</td><td>{date_str}</td></tr>
    <tr><td>Overall risk</td><td><b style="color:{SEV_COLOR.get(risk, '#333')}">{H.escape(str(risk))}</b>{f' &nbsp;(Risk Score {risk_score}/100)' if risk_score is not None else ''}</td></tr>
    <tr><td>Document version</td><td>1.0 — Final</td></tr>
    <tr><td>Classification</td><td>CONFIDENTIAL — TLP:AMBER</td></tr>
  </table>
  <div class="foot"><div class="rule"></div>
  <div class="classif">CONFIDENTIAL — TLP:AMBER</div></div>
</div>

<h2 class="sec">Document Control</h2>
<table class="kv">
  <tr><td>Report ID</td><td>{report_id} &nbsp;·&nbsp; Scan ID: {H.escape(str(scan.get('id', '-')))}</td></tr>
  <tr><td>Source Data SHA-256</td><td style="word-break:break-all">{fingerprint}</td></tr>
  <tr><td>Prepared by</td><td>VANTHEX Offensive Security Platform v{VERSION} (self-built assessment engine)</td></tr>
  <tr><td>Target</td><td>{H.escape(target)}</td></tr>
  <tr><td>Assessment type</td><td>{'Mobile application static analysis (Android APK)' if stype == 'mobile' else 'Black-box automated web application penetration test'} — profile: {H.escape(str(scan.get('profile', '-')))}</td></tr>
  <tr><td>Date / time</td><td>{dt_str}</td></tr>
  <tr><td>Classification</td><td>CONFIDENTIAL — TLP:AMBER. Distribution is limited to the system owner and the remediation team.</td></tr>
  <tr><td>Distribution</td><td>System owner, remediation team, and risk management stakeholders. Forwarding to third parties requires written authorisation.</td></tr>
</table>
<h3 class="sub">Version History</h3>
<table><tr><th style="width:90px">Version</th><th style="width:130px">Date</th><th>Description</th></tr>
<tr><td>1.0</td><td>{date_str}</td><td>Final report of the automated assessment. Subsequent changes are issued via retest as version 1.1 or later.</td></tr></table>

<h2 class="sec">Contents</h2>
<ol class="toc">
  <li><a href="#s1">1. Executive Summary</a></li>
  <li><a href="#s2">2. Scope &amp; Methodology</a></li>
  <li><a href="#s3">3. Findings Summary</a></li>
  <li><a href="#s4">4. Detailed Findings</a></li>
  {toc_findings}
  <li><a href="#s5">5. Remediation Roadmap</a></li>
  <li><a href="#sa">Appendix A. Risk Rating Methodology</a></li>
  <li><a href="#sb">Appendix B. Assessment Metadata</a></li>
  <li><a href="#sc">Appendix C. Platform Submission Format (HackerOne/Bugcrowd-ready)</a></li>
</ol>

<h2 class="sec" id="s1">1. Executive Summary</h2>
<p>An automated security assessment was performed against <b>{H.escape(target)}</b> using the
<b>{H.escape(str(scan.get('profile', '-')))}</b> profile. The assessment identified <b>{len(findings)} findings</b>
with an overall risk of <b style="color:{SEV_COLOR.get(risk, '#333')}">{H.escape(str(risk))}</b>{f' and a risk score of <b>{risk_score}/100</b>' if risk_score is not None else ''}.
Findings with <b>Confirmed</b> confidence have passed automated verification (content signatures,
comparative payload pairs, and/or a reproduction pass). <b>Probable</b> and <b>Candidate</b> findings are
indications that must be manually confirmed by the tester before being declared final vulnerabilities.
All testing was performed only on systems with official authorization.</p>
{warnings}
<h3 class="sub">Risk Matrix</h3>
<table><tr><th>Severity</th><th style="text-align:center;width:90px">Count</th><th style="text-align:center;width:90px">Share</th><th>Required response</th></tr>
{matrix}</table>
<h3 class="sub">Highest Priority Findings</h3>
<ul>{top5 or '<li>—</li>'}</ul>

<h2 class="sec" id="s2">2. Scope &amp; Methodology</h2>
<table class="kv">
  <tr><td>Target</td><td>{H.escape(target)}</td></tr>
  <tr><td>Assessment type</td><td>{'Mobile application static analysis (Android APK)' if stype == 'mobile' else 'Black-box automated web application penetration test'}</td></tr>
  <tr><td>Profile / checks</td><td>{H.escape(str(scan.get('profile', '-')))} — {meta.get('checks_run', '?')} of {meta.get('checks_total', '?')} checks executed</td></tr>
  <tr><td>Duration</td><td>{meta.get('duration_s', '?')} seconds</td></tr>
  <tr><td>Start time</td><td>{dt_str}</td></tr>
</table>
<p>The methodology follows the OWASP Web Security Testing Guide (WSTG), the OWASP Application
Security Verification Standard (ASVS), and the Penetration Testing Execution Standard (PTES). Risk
ratings use CVSS v3.1; every finding is mapped to a CWE and an OWASP Top 10 2021 / API Security
Top 10 category.</p>
<p><b>Confidence model.</b> Confirmed: proven by automated verification (signatures, baselines,
payload pairs, re-reproduction). Probable: a strong indication based on response behavior. Candidate:
a suspicion based on version or pattern — not proof of exploitation.</p>
<p><b>Limitations.</b> Automated testing does not cover deep business logic, multi-account
flows, or vulnerabilities that require an out-of-band listener (blind). A negative result reads as
"not confirmed within the coverage of the checks performed", not a guarantee that the system is
clean. Checks based on direct socket connections (port/TLS) may be limited on networks with
proxy-only egress.</p>
{tech_html}

<h2 class="sec" id="s3">3. Findings Summary</h2>
<table><tr><th style="width:60px">ID</th><th style="width:90px">Severity</th><th>Finding</th>
<th style="width:60px">CVSS</th><th style="width:110px">Confidence</th><th style="width:110px">Status</th></tr>
{sum_rows or '<tr><td colspan="6">No findings.</td></tr>'}</table>

<h2 class="sec" id="s4">4. Detailed Findings</h2>
{detail or '<p>No findings.</p>'}

<h2 class="sec" id="s5">5. Remediation Roadmap</h2>
<table><tr><th>Priority</th><th style="text-align:center;width:90px">Findings</th><th>Guidance</th></tr>
{roadmap}</table>
<p>After remediation, perform a retest (the Rescan feature on the dashboard) and update the
finding statuses to Fixed via the Findings menu.</p>

<h2 class="sec" id="sa">Appendix A. Risk Rating Methodology</h2>
<p>Severity is derived from the per-finding CVSS v3.1 score: CRITICAL 9.0-10.0, HIGH 7.0-8.9,
MEDIUM 4.0-6.9, LOW 0.1-3.9, INFO 0.0. The scan Risk Score (0-100) is a weighted aggregate of
severity x confidence across all findings and serves as a posture indicator, not a substitute
for per-finding assessment. The CVSS vector shown in each finding's detail is representative
of its weakness class and must be validated against the target environment.</p>

<h2 class="sec" id="sb">Appendix B. Assessment Metadata</h2>
<table class="kv">
  <tr><td>Engine</td><td>VANTHEX Offensive Security Platform v{VERSION}</td></tr>
  <tr><td>Scan ID</td><td>{H.escape(str(scan.get('id', '-')))}</td></tr>
  <tr><td>Report ID</td><td>{report_id}</td></tr>
  <tr><td>Profile</td><td>{H.escape(str(scan.get('profile', '-')))}</td></tr>
  <tr><td>Checks</td><td>{meta.get('checks_run', '?')} / {meta.get('checks_total', '?')}</td></tr>
  <tr><td>Duration</td><td>{meta.get('duration_s', '?')} seconds</td></tr>
</table>

<h2 class="sec" id="sc">Appendix C. Platform Submission Format (HackerOne/Bugcrowd-ready)</h2>
<p>The per-finding blocks below follow the bug bounty platform report structure (Title, Asset,
Weakness, Severity, Summary, Steps to Reproduce, Supporting Material, Impact) and can be copied
directly into a submission form after manual verification.</p>
{h1_blocks or '<p>—</p>'}

<div class="sig">Disclaimer — This report was generated by automated scanning. Findings with
Probable/Candidate confidence require manual verification by a competent tester before being
declared final vulnerabilities to third parties. Testing was performed only on systems with
official authorization.<br><br>— End of Report —<br>
<span class="classif" style="font-size:8.5pt">CONFIDENTIAL — TLP:AMBER</span></div>

</div></body></html>"""
