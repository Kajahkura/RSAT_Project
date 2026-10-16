import React,{useState} from 'react';
import {Audit, Finding} from './evidence';
import {Decision, decisionLabels} from './decisions';
import {downloadFile,findingsCsv,findingsJson,redactedReport} from './reporting';

type Props={audit:Audit;filtered:Finding[];search:string;setSearch:(value:string)=>void;status:string;setStatus:(value:string)=>void;decisions:Decision[];trust:string;onInspect:(finding:Finding)=>void;onMessage:(message:string)=>void};
export function FindingsPanel(props:Props) {
  const [checked,setChecked]=useState<Set<string>>(new Set());
  function toggle(id:string) {setChecked(previous=>{const next=new Set(previous);if(next.has(id))next.delete(id);else next.add(id);return next;});}
  function exportSelected(kind:'json'|'csv'|'report') {
    try {
      const text=kind==='json' ? findingsJson(props.audit,checked,props.decisions,props.trust) : kind==='csv' ? findingsCsv(props.audit,checked,props.decisions) : redactedReport(props.audit,checked,props.decisions);
      const extension=kind==='report' ? 'html' : kind;
      const mime=kind==='json' ? 'application/json' : kind==='csv' ? 'text/csv;charset=utf-8' : 'text/html;charset=utf-8';
      downloadFile(text,mime,'rsat-'+(kind==='report' ? 'redacted-report' : 'selected-findings')+'.'+extension);
      props.onMessage(kind==='report' ? 'Redacted report downloaded locally. Open it and use Print to save a PDF.' : 'Selected findings exported locally. This file contains finding text and any decision notes; review it before sharing.');
    } catch(e) {props.onMessage((e as Error).message);}
  }
  const allVisible=props.filtered.length>0 && props.filtered.every(f=>checked.has(f.id));
  return <section className="panel"><div className="filters"><input aria-label="Search findings" placeholder="Search control, title or severity…" value={props.search} onChange={e=>props.setSearch(e.target.value)}/><select aria-label="Filter outcome" value={props.status} onChange={e=>props.setStatus(e.target.value)}><option value="">All outcomes</option>{['FAIL','UNKNOWN','ERROR','PASS','NOT_APPLICABLE'].map(x=><option key={x}>{x}</option>)}</select><span>{props.filtered.length} controls</span></div><div className="export-tools"><div><strong>{checked.size} selected findings</strong><p className="fine">Selections survive filtering. JSON/CSV contain selected text and notes. The redacted client report omits identifying metadata and all imported prose.</p></div><div className="action-row"><button className="button subtle" disabled={!checked.size} onClick={()=>exportSelected('json')}>Export selected JSON</button><button className="button subtle" disabled={!checked.size} onClick={()=>exportSelected('csv')}>Export selected CSV</button><button className="button primary" disabled={!checked.size} onClick={()=>exportSelected('report')}>Create redacted report</button>{checked.size>0 && <button className="text-button" onClick={()=>setChecked(new Set())}>Clear selection</button>}</div></div><div className="table-wrap"><table><thead><tr><th><input type="checkbox" aria-label="Select visible findings" checked={allVisible} onChange={()=>setChecked(previous=>{const next=new Set(previous);for(const f of props.filtered){if(allVisible)next.delete(f.id);else next.add(f.id);}return next;})}/></th><th>Control</th><th>Outcome</th><th>Severity</th><th>Decision</th></tr></thead><tbody>{props.filtered.map(f=>{const decision=props.decisions.find(d=>d.controlId===f.id);return <tr key={f.id}><td><input type="checkbox" aria-label={'Select '+f.id} checked={checked.has(f.id)} onChange={()=>toggle(f.id)}/></td><td><button className="control-button" onClick={()=>props.onInspect(f)}><strong>{f.title}</strong><small>{f.id} · rule {f.rule_version}</small></button></td><td><span className={'badge '+f.status.toLowerCase()}>{f.status.replace('_',' ')}</span></td><td>{f.severity}</td><td>{decision ? decisionLabels[decision.state] : 'Unreviewed'}</td></tr>;})}</tbody></table></div>{!props.filtered.length && <p className="empty">No controls match these filters.</p>}</section>;
}
