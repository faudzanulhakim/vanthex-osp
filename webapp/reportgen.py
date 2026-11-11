"""
ReportGen v1 — Campaign Report Generator for VANTHEX (v1.8.0).
AUTHORIZED TESTING ONLY.

Campaign-style .docx report (different from the formal-assessment
docx_report.py): executive summary, phase TIMELINE, chain-of-exploits
(step & approval), most dangerous findings, and prioritized
recommendations. Stdlib + python-docx.
"""
import datetime as _dt
import os as _os

try:
    import docx as _docx
    from docx.shared import Pt as _Pt, RGBColor as _RGB
except ImportError:
    _docx = None

SEV_COLOR = {"CRITICAL": "9B2226", "HIGH": "C05621", "MEDIUM": "975A16",
             "LOW": "4A5568", "INFO": "2B6CB0"}


def _h(doc, text, lvl=1):
    h = doc.add_heading(text, level=lvl)
    return h


def build_campaign_report(path, meta, timeline, chains, findings, recs=None):
    """meta {target, date, operator}; timeline [{phase, t, desc}];
    chains [{name, steps:[{action, approved}], outcome}];
    findings list dict standard VANTHEX; recs list str."""
    if _docx is None:
        raise RuntimeError("python-docx not available")
    doc = _docx.Document()
    doc.add_heading("VANTHEX Campaign Report", 0)
    p = doc.add_paragraph()
    p.add_run(f"Target: {meta.get('target', '?')}\n").bold = True
    p.add_run(f"Date: {meta.get('date', _dt.date.today().isoformat())}  •  "
              f"Operator: {meta.get('operator', 'VANTHEX')}  •  "
              "AUTHORIZED TESTING ONLY")
    # Executive summary
    _h(doc, "1. Executive Summary", 1)
    sev = {}
    for f in findings:
        sev[f.get("severity", "?")] = sev.get(f.get("severity", "?"), 0) + 1
    conf_cr = sum(1 for f in findings if f.get("severity") == "CRITICAL"
                  and f.get("confidence") == "confirmed")
    doc.add_paragraph(
        f"Total of {len(findings)} findings: " +
        ", ".join(f"{k}={v}" for k, v in sorted(sev.items())) +
        f". {conf_cr} critical credentials/access CONFIRMED. "
        "The exploit chain proved able to move from the public surface "
        "to internal access (see the chain chapter).")
    # Timeline
    _h(doc, "2. Campaign Timeline", 1)
    for t in timeline:
        doc.add_paragraph(f"[{t.get('t', '')}] {t.get('phase', '?')}: "
                          f"{t.get('desc', '')}", style="List Bullet")
    # Chains
    _h(doc, "3. Chain of Exploits", 1)
    for c in chains or []:
        _h(doc, f"Chain: {c.get('name', '?')}", 2)
        for s in c.get("steps", []):
            doc.add_paragraph(f"→ {s.get('action', '?')} "
                              f"[{'APPROVED' if s.get('approved') else 'DENIED'}]",
                              style="List Bullet")
        doc.add_paragraph(f"Outcome: {c.get('outcome', '-')}")
    # Findings
    _h(doc, "4. Key Findings", 1)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for f in sorted(findings, key=lambda x: order.get(x.get("severity"), 9)):
        pp = doc.add_paragraph()
        run = pp.add_run(f"[{f.get('severity', '?')}] {f.get('title', '?')}")
        run.bold = True
        run.font.color.rgb = _RGB.from_string(
            SEV_COLOR.get(f.get("severity", ""), "000000"))
        doc.add_paragraph(f"Location: {f.get('location', '?')} • "
                          f"Confidence: {f.get('confidence', '?')} • "
                          f"CVSS: {f.get('cvss', '?')}", style="List Bullet")
        doc.add_paragraph(str(f.get("description", ""))[:400])
    # Recommendations
    _h(doc, "5. Prioritized Recommendations", 1)
    for i, r in enumerate(recs or [], 1):
        doc.add_paragraph(f"{i}. {r}")
    doc.save(path)
    return path
