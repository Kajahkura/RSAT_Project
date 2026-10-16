import {Audit, Finding} from './evidence';
import {Decision, decisionLabels} from './decisions';
import {publicControls} from './control-catalog';

function escapeHtml(value:string):string {
  return value.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
}
function csvCell(value:string):string {
  const safe=/^[\s\u0000-\u001f]*[=+\-@]/.test(value) || /^[\t\r\n]/.test(value) ? "'" + value : value;
  return '"' + safe.replace(/"/g,'""') + '"';
}
function selectedFindings(audit:Audit,selected:Set<string>):Finding[] {
  const findings=audit.findings.filter(f=>selected.has(f.id));
  if(!findings.length) throw Error('Select at least one finding to export.');
  return findings;
}
export function findingsJson(audit:Audit,selected:Set<string>,decisions:Decision[],verification:string):string {
  const findings=selectedFindings(audit,selected);
  return JSON.stringify({schema:'rsat.findings-export/1',audit_id:audit.audit_id,asset_id:audit.asset_id,scope:audit.scope,collected_at:audit.started_at,
    source_verification:verification,export_verification:'This selected export is unsigned. It does not preserve the original bundle signature.',
    findings:findings.map(f=>({...f,remediation_decision:decisions.find(d=>d.controlId===f.id) ?? null}))},null,2);
}
export function findingsCsv(audit:Audit,selected:Set<string>,decisions:Decision[]):string {
  const header=['control_id','title','outcome','severity','details','remediation','rule_version','decision','owner','note','due_date'];
  const rows=selectedFindings(audit,selected).map(f=>{
    const decision=decisions.find(d=>d.controlId===f.id);
    return [f.id,f.title,f.status,f.severity,f.details,f.remediation,f.rule_version,decision ? decisionLabels[decision.state] : 'Unreviewed',decision?.owner ?? '',decision?.note ?? '',decision?.dueDate ?? ''];
  });
  return '\ufeff' + [header,...rows].map(row=>row.map(csvCell).join(',')).join('\r\n') + '\r\n';
}
export function redactedReport(audit:Audit,selected:Set<string>,decisions:Decision[]):string {
  const findings=selectedFindings(audit,selected);
  const rows=findings.map((f,index)=>{
    const reference=Object.hasOwn(publicControls,f.id) ? publicControls[f.id] : undefined;
    const decision=decisions.find(d=>d.controlId===f.id);
    return '<tr><td><strong>' + escapeHtml(reference?.title ?? 'Custom control') + '</strong><br><small>' + escapeHtml(reference ? f.id : 'CUSTOM-' + (index+1)) + '</small></td><td>' + escapeHtml(f.status) + '</td><td>' + escapeHtml(f.severity) + '</td><td>' + escapeHtml(decision ? decisionLabels[decision.state] : 'Unreviewed') + '</td></tr>';
  }).join('');
  const failed=findings.filter(f=>f.status==='FAIL').length;
  const gaps=findings.filter(f=>['UNKNOWN','ERROR'].includes(f.status)).length;
  return '<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'"><title>RSAT · Redacted assessment excerpt</title><style>' +
    'body{font:14px/1.6 system-ui,sans-serif;color:#18283c;margin:0;background:#f6f7f9}main{max-width:1000px;margin:auto;padding:32px}header{background:#142335;color:white;padding:28px;border-radius:12px}header p{color:#d7b572}h1{margin:8px 0}section{background:white;padding:24px;border:1px solid #dfe5eb;border-radius:10px;margin-top:20px}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:14px 10px;border-bottom:1px solid #e1e7ed;vertical-align:top}small{color:#657387}.stats{display:flex;gap:25px;flex-wrap:wrap}footer{margin-top:24px;color:#657387;font-size:12px}@media print{body{background:white}main{padding:0}header{border:1px solid #18283c}tr{break-inside:avoid}}@media(max-width:600px){main{padding:15px}section{padding:14px}table{font-size:11px}th,td{padding:8px 4px}}' +
    '</style></head><body><main><header><p>RSAT / CLIENT REPORT</p><h1>Redacted assessment excerpt</h1><p>Device 1 · Selected recorded control outcomes</p></header><section><div class="stats"><strong>' + findings.length + ' selected controls</strong><span>' + failed + ' failed</span><span>' + gaps + ' evidence gaps</span></div><p>This excerpt contains only selected results. It does not describe full assessment coverage or establish endpoint health or compliance.</p></section><section><table><thead><tr><th>Public control reference</th><th>Recorded outcome</th><th>Severity</th><th>Remediation decision</th></tr></thead><tbody>' + rows + '</tbody></table></section><section><h2>Redaction and interpretation</h2><p>Device identifiers, names, timestamps, raw observations, imported prose, rule versions, and free-text decision fields are omitted. Control names use public RSAT reference labels; custom identifiers are replaced with report-local labels.</p><p>Decisions are user-recorded plans. They do not change audit outcomes or prove a successful fix. Reassess the device to verify improvement. This report is unsigned and does not carry the source bundle signature.</p><p>Use your browser’s Print function to save a PDF. Review the selected results before sharing; control outcomes themselves may be sensitive.</p></section><footer>RSAT · MIT licensed · No external scripts, fonts or network resources.</footer></main></body></html>';
}
export function downloadFile(contents:string,type:string,filename:string):void {
  const url=URL.createObjectURL(new Blob([contents],{type}));
  const anchor=document.createElement('a');
  anchor.href=url;anchor.download=filename;document.body.append(anchor);anchor.click();anchor.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
