"""
report.py — HTML dashboard report generator for Ghost Profiler.

Self-contained single-file HTML (inline CSS, no external deps) with
posture grade, risk meters, device cards, and AI analysis.
"""

import datetime
import html as html_mod

RISK_COLORS = {
    "LOW": "#22c55e", "MEDIUM": "#eab308", "HIGH": "#f97316", "CRITICAL": "#ef4444",
}


def _esc(s):
    return html_mod.escape(str(s))


def device_card_html(p: dict) -> str:
    color = RISK_COLORS.get(p["risk_level"], "#888")
    filled = p["risk_score"] // 10
    meter = "█" * filled + "░" * (10 - filled)
    services = "<br>".join(_esc(s) for s in p.get("services", []))
    notes = ""
    if p.get("risk_notes"):
        notes = "<ul>" + "".join(f"<li>{_esc(n)}</li>" for n in p["risk_notes"]) + "</ul>"
    ai = ""
    if p.get("ai_analysis"):
        src = _esc(p.get("ai_source", "AI"))
        ai = f"<div class='ai'><b>GHOST-1:</b> {_esc(p['ai_analysis'])}<br><i>— {src}</i></div>"
    return f"""
    <div class="card" style="border-left:5px solid {color}">
      <div class="card-head">
        <span class="codename">{_esc(p['codename'])}</span>
        <span class="risk" style="color:{color}">{p['risk_level']} {p['risk_score']}/100</span>
      </div>
      <div class="meter">{meter}</div>
      <table>
        <tr><td>IP</td><td>{_esc(p['ip'])}</td></tr>
        <tr><td>Host</td><td>{_esc(p['hostname'])}</td></tr>
        <tr><td>MAC</td><td>{_esc(p['mac'])} {_esc(p.get('vendor','') if p.get('vendor') != '—' else '')}</td></tr>
        <tr><td>MAC type</td><td>{_esc(p.get('mac_type') or '—')}</td></tr>
        <tr><td>OS</td><td>{_esc(p['os'])}</td></tr>
        <tr><td>Type</td><td>{_esc(p['device_type'])}</td></tr>
        <tr><td>Ports</td><td>{_esc(', '.join(map(str, p['open_ports'])) or '—')}</td></tr>
        <tr><td>Services</td><td>{services}</td></tr>
      </table>
      {notes}
      {ai}
    </div>"""


def generate_html(profiles: list, cidr: str, model: str, grade: str, grade_note: str,
                  summary: str = None) -> str:
    cards = "".join(device_card_html(p) for p in
                    sorted(profiles, key=lambda x: -x["risk_score"]))
    grade_color = {"A": "#22c55e", "B": "#84cc16", "C": "#eab308",
                   "D": "#f97316", "F": "#ef4444"}.get(grade, "#888")
    summary_block = ""
    if summary:
        summary_block = f"<div class='summary'><b>EXECUTIVE SUMMARY</b><br>{_esc(summary)}</div>"
    generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Ghost Profiler Report — {_esc(cidr)}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ background:#0a0e14; color:#d7dce3; font-family:'JetBrains Mono','Fira Code',monospace;
         margin:0; padding:32px; }}
  h1 {{ color:#e879f9; letter-spacing:3px; margin:0 0 4px; }}
  .sub {{ color:#566; font-size:13px; margin-bottom:24px; }}
  .topbar {{ display:flex; gap:24px; align-items:center; background:#10161f;
            border:1px solid #1e2a3a; border-radius:10px; padding:18px 24px; margin-bottom:24px; }}
  .grade {{ font-size:52px; font-weight:800; color:{grade_color};
           border:3px solid {grade_color}; border-radius:12px; padding:4px 22px; }}
  .grade-note {{ color:#9ab; font-size:14px; }}
  .stat {{ font-size:13px; color:#8aa; }}
  .stat b {{ color:#e879f9; font-size:22px; display:block; }}
  .summary {{ background:#131a26; border:1px solid #3b1f4d; border-radius:10px;
             padding:16px 20px; margin-bottom:24px; color:#e0c8f5; font-size:14px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(420px,1fr)); gap:18px; }}
  .card {{ background:#10161f; border:1px solid #1e2a3a; border-radius:10px; padding:16px 18px; }}
  .card-head {{ display:flex; justify-content:space-between; align-items:baseline; margin-bottom:6px; }}
  .codename {{ font-weight:800; font-size:16px; color:#fff; letter-spacing:1px; }}
  .risk {{ font-weight:700; font-size:13px; }}
  .meter {{ color:#22d3ee; font-size:13px; margin-bottom:10px; }}
  table {{ width:100%; border-collapse:collapse; font-size:12.5px; }}
  td {{ padding:2.5px 6px; vertical-align:top; }}
  td:first-child {{ color:#22d3ee; text-align:right; width:90px; font-weight:600; }}
  ul {{ margin:8px 0 0; padding-left:18px; font-size:12.5px; color:#fbbf24; }}
  .ai {{ margin-top:10px; background:#141024; border:1px solid #3b1f4d; border-radius:8px;
        padding:10px 12px; font-size:12.5px; color:#d8b4fe; }}
  .foot {{ margin-top:28px; color:#456; font-size:11.5px; }}
</style>
</head>
<body>
  <h1>👻 GHOST PROFILER</h1>
  <div class="sub">ctOS network report — {_esc(cidr)} — generated {generated} — model: {_esc(model)}</div>
  <div class="topbar">
    <div class="grade">{grade}</div>
    <div class="grade-note">{_esc(grade_note)}<br><br>
      <span class="stat-inline">{len(profiles)} devices ·
      {sum(1 for p in profiles if p['risk_level'] in ('HIGH','CRITICAL'))} high/critical ·
      {sum(len(p['open_ports']) for p in profiles)} open ports total</span></div>
    <div style="flex:1"></div>
    <div class="stat"><b>{len(profiles)}</b>devices</div>
    <div class="stat"><b>{sum(len(p['open_ports']) for p in profiles)}</b>open ports</div>
    <div class="stat"><b>{sum(1 for p in profiles if p['risk_level'] in ('HIGH','CRITICAL'))}</b>high/critical</div>
  </div>
  {summary_block}
  <div class="grid">{cards}</div>
  <div class="foot">Generated by Ghost Profiler · authorized networks only · profiles devices, not people</div>
</body>
</html>"""
