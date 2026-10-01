"""Self-contained, escaped HTML report and local dashboard."""

from collections import Counter
from html import escape
import json

from .model import validate_audit
from .policy import coverage

STYLE = """
:root{color-scheme:light;--ink:#162338;--muted:#53647a;--line:#dbe4ed;--paper:#fff;--bg:#f0f4f8;--blue:#2464cc}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 system-ui,sans-serif}
main{max-width:1180px;margin:auto;padding:40px 28px}header{background:#13253e;color:white;padding:40px;border-radius:20px}
.brand{color:#86c5ff;letter-spacing:.16em;font-weight:750;font-size:12px}h1{font-size:36px;line-height:1.2;margin:12px 0}
h2{font-size:23px;margin:32px 0 14px}h3{margin:0 0 12px;font-size:18px}.subtitle{color:#c5d3e4;max-width:750px}
.meta{display:flex;flex-wrap:wrap;gap:10px 24px;margin-top:24px;font-size:13px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-top:22px}
.card,.panel{background:white;border:1px solid var(--line);border-radius:14px;padding:22px}.metric{font-size:30px;font-weight:750;line-height:1.2}.muted{color:var(--muted)}
.badge{font-size:11px;font-weight:750;letter-spacing:.04em;padding:5px 9px;border-radius:6px;white-space:nowrap;background:#e8edf3;color:#46566c}
.PASS{background:#d9f4e5;color:#12603b}.FAIL{background:#ffe2e0;color:#9c2828}.UNKNOWN,.ERROR{background:#fff0cf;color:#785305}
.severity{font-size:12px;text-transform:uppercase;color:var(--muted)}table{border-collapse:collapse;width:100%;background:white}th,td{padding:16px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);background:#f8fafc}
.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:14px}details{margin-top:10px}summary{cursor:pointer;color:var(--blue)}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;background:#f4f7fa;padding:16px;border-radius:8px}
.control{font-size:11px;color:var(--muted)}.toolbar{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}input,select,button{font:inherit;border:1px solid var(--line);border-radius:8px;padding:10px;background:white;color:var(--ink)}input{flex:1;min-width:180px}
button{cursor:pointer}.risk{border-left:4px solid #e59b37;margin:12px 0}.note{padding:16px 20px;background:#e4edf8;border-radius:10px}footer{font-size:12px;color:var(--muted);margin:32px 0}.bar{height:8px;background:#e4edf8;border-radius:4px;margin-top:12px}.bar span{display:block;height:100%;background:var(--blue);border-radius:4px}
a{color:var(--blue)}header a{color:#86c5ff}@media(max-width:600px){main{padding:18px 12px}header{padding:24px}h1{font-size:28px}th,td{padding:12px}.cards{grid-template-columns:repeat(2,1fr)}}@media print{body{background:white}main{max-width:none;padding:0}.toolbar{display:none}header{border-radius:0;print-color-adjust:exact}.panel,.card,tr{break-inside:avoid}details{display:block}}
"""

SCRIPT = """
const search=document.getElementById('search'), state=document.getElementById('state');
function filter(){for(const row of document.querySelectorAll('tbody tr')){row.hidden=!(row.textContent.toLowerCase().includes(search.value.toLowerCase())&&(!state.value||row.dataset.state===state.value));}}
search.addEventListener('input',filter);state.addEventListener('change',filter);
document.getElementById('print').addEventListener('click',()=>window.print());
"""


def e(value):
    return escape(str(value), quote=True)


def page(title, body, interactive=False):
    script = f"<script>{SCRIPT}</script>" if interactive else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; connect-src 'none'">
<title>{e(title)}</title><style>{STYLE}</style></head><body><main>{body}</main>{script}</body></html>"""


def render(audit):
    validate_audit(audit)
    counts = coverage(audit["findings"])
    evidence = {o["id"]: o for o in audit["observations"]}
    cards = "".join(
        f'<div class="card"><div class="muted">{label}</div><div class="metric">{value}</div></div>'
        for label, value in [
            ("Controls assessed", f"{counts['assessed']}/{counts['applicable']}"),
            ("Failed", counts["FAIL"]),
            ("Passed", counts["PASS"]),
            ("Unknown / errors", counts["UNKNOWN"] + counts["ERROR"]),
        ]
    )
    rows = []
    for finding in sorted(
        audit["findings"],
        key=lambda f: (
            {"FAIL": 0, "ERROR": 1, "UNKNOWN": 2, "PASS": 3, "NOT_APPLICABLE": 4}[f["status"]],
            f["id"],
        ),
    ):
        raw = [evidence[i] for i in finding["evidence_ids"] if i in evidence]
        exception = finding.get("exception")
        exception_html = (
            (
                f"<p><strong>{'Expired exception' if exception['expired'] else 'Recorded exception'}:</strong> "
                f"{e(exception['reason'])} · {e(exception['expires_at'])}</p>"
            )
            if exception
            else ""
        )
        links = " ".join(
            f'<a href="{e(url)}" rel="noreferrer">Reference</a>'
            for url in finding.get("references", [])
            if url.startswith("https://")
        )
        rows.append(f'''<tr data-state="{e(finding["status"])}"><td><div class="control">{e(finding["id"])} · rule {e(finding["rule_version"])}</div>
<strong>{e(finding["title"])}</strong><div class="severity">{e(finding["severity"])}</div></td>
<td><span class="badge {e(finding["status"])}">{e(finding["status"])}</span></td>
<td>{e(finding["details"])}{exception_html}<details><summary>Evidence &amp; recommended action</summary>
<p>{e(finding["remediation"])}</p>{links}<pre>{e(json.dumps(raw, indent=2, ensure_ascii=False))}</pre></details></td></tr>''')
    risks = "".join(
        f'<article class="panel risk"><h3>{e(r["title"])}</h3><div class="severity">{e(r["severity"])}</div>'
        f"<ul>{''.join('<li>' + e(f) + '</li>' for f in r['factors'])}</ul>"
        f'<p class="muted">{e(r["limitations"])}</p></article>'
        for r in audit.get("risks", [])
    )
    body = f"""<header><div class="brand">OFINFIX / RSAT</div><h1>Endpoint security assessment</h1>
<p class="subtitle">Evidence you can inspect. Findings you can act on. A record you can compare.</p>
<div class="meta"><span>{e(audit["platform"])} · {e(audit["os_release"])} · {e(audit["architecture"])}</span>
<span>Asset {e(audit["asset_id"])}</span><span>{e(audit["started_at"])}</span></div></header>
<section class="cards">{cards}</section><div class="panel" style="margin-top:14px"><strong>{counts["assessed_percent"]}% of applicable controls assessed</strong>
<div class="bar"><span style="width:{counts["assessed_percent"]}%"></span></div><p class="muted">Coverage describes this rule pack. It is not an overall security score.</p></div>
<h2>Assessment scope</h2><p class="note">{e(audit["scope"])}. Unknown results identify missing evidence and require follow-up.</p>
<h2>Prioritized review</h2>{risks or '<div class="panel muted">No supported risk scenario was identified from the collected evidence. Review control failures and unknowns below.</div>'}
<h2>Control findings</h2><div class="toolbar"><input id="search" type="search" aria-label="Search findings" placeholder="Search controls or evidence">
<select id="state" aria-label="Filter status"><option value="">All statuses</option>{"".join(f"<option>{s}</option>" for s in ["FAIL", "PASS", "UNKNOWN", "ERROR", "NOT_APPLICABLE"])}</select>
<button id="print">Print / save PDF</button></div><div class="tablewrap"><table><thead><tr><th>Control</th><th>Status</th><th>Assessment</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>
<footer>RSAT {e(audit["collector_version"])} · Audit {e(audit["audit_id"])} · Finished {e(audit["finished_at"])}<br>
This point-in-time assessment does not certify compliance or establish that an endpoint is uncompromised. Evidence may contain sensitive system information.</footer>"""
    return page("RSAT · Endpoint security assessment", body, True)


def dashboard(audits):
    for audit in audits:
        validate_audit(audit)
    latest = {}
    for audit in sorted(audits, key=lambda a: a["started_at"]):
        latest[audit["asset_id"]] = audit
    total = Counter(f["status"] for audit in latest.values() for f in audit["findings"])
    rows = "".join(
        f"<tr><td>{e(a['asset_id'])}</td><td>{e(a['platform'])} {e(a['os_release'])}</td>"
        f"<td>{e(a['started_at'])}</td><td>{coverage(a['findings'])['FAIL']}</td>"
        f"<td>{coverage(a['findings'])['assessed_percent']}%</td></tr>"
        for a in latest.values()
    )
    body = f"""<header><div class="brand">OFINFIX / RSAT WORKSPACE</div><h1>Engagement overview</h1>
<p class="subtitle">A local view of imported endpoint audits. Latest audit per asset.</p></header>
<section class="cards"><div class="card"><div class="muted">Assets</div><div class="metric">{len(latest)}</div></div>
<div class="card"><div class="muted">Imported audits</div><div class="metric">{len(audits)}</div></div>
<div class="card"><div class="muted">Failed controls</div><div class="metric">{total["FAIL"]}</div></div></section>
<h2>Latest endpoint assessments</h2><div class="tablewrap"><table><thead><tr><th>Asset</th><th>Platform</th><th>Collected</th><th>Failures</th><th>Coverage</th></tr></thead><tbody>{rows}</tbody></table></div>
<footer>Imported data stays local. Verify bundle signatures separately before trusting imported evidence.</footer>"""
    return page("RSAT · Engagement overview", body)
