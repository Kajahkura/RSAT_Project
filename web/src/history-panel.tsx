import React,{useEffect,useRef,useState} from 'react';
import {Audit,metrics} from './evidence';
import {Decision,Snapshot} from './decisions';
import {Saved,clearHistory,loadSnapshot,saveHistory} from './vault';
import {Comparison,changeLabels,compareAudits,deviceKey,freshness} from './reassessment';

type Summary={row:Saved;key:string;label:string;asset:string;platform:string;started:string;finished:string|null;decisionCount:number};
type Props={audit:Audit;decisions:Decision[];deviceLabel:string;setDeviceLabel:(value:string)=>void;dirty:boolean;busy:boolean;setBusy:(value:boolean)=>void;history:Saved[];setHistory:(value:Saved[])=>void;onSaved:()=>void;onOpen:(snapshot:Snapshot)=>Promise<void>;onMessage:(message:string)=>void};
export function HistoryPanel(props:Props) {
  const [password,setPassword]=useState('');
  const [retention,setRetention]=useState(10);
  const [summaries,setSummaries]=useState<Summary[]>([]);
  const [comparison,setComparison]=useState<Comparison|null>(null);
  const [windowHours,setWindowHours]=useState(24);
  const [progress,setProgress]=useState('');
  const operation=useRef(0);
  useEffect(()=>()=>{operation.current++;props.setBusy(false);},[props.setBusy]);
  function summarize(row:Saved,snapshot:Snapshot):Summary {return {row,key:deviceKey(snapshot.audit),label:snapshot.deviceLabel,asset:snapshot.audit.asset_id,platform:snapshot.audit.platform,started:snapshot.audit.started_at,finished:snapshot.audit.finished_at,decisionCount:snapshot.decisions.length};}
  async function save() {
    props.setBusy(true);const token=++operation.current;
    try {const rows=await saveHistory(props.audit,password,retention,{decisions:props.decisions,deviceLabel:props.deviceLabel});props.setHistory(rows);if(token!==operation.current)return;props.onSaved();setSummaries(previous=>previous.filter(s=>rows.some(r=>r.id===s.row.id)));props.onMessage('Encrypted snapshot saved on this browser, including device label and remediation decisions.');}
    catch(e){if(token===operation.current)props.onMessage((e as Error).message);}finally{if(token===operation.current){setPassword('');props.setBusy(false);}}
  }
  async function unlock(row:Saved,compare=false) {
    props.setBusy(true);const token=++operation.current;
    try {
      const snapshot=await loadSnapshot(row,password);
      if(token!==operation.current)return;
      if(compare){setComparison(compareAudits(snapshot.audit,props.audit));setSummaries(previous=>[...previous.filter(s=>s.row.id!==row.id),summarize(row,snapshot)]);props.onMessage('Compared the same device. Policy, scope and evidence changes remain distinct.');}
      else await props.onOpen(snapshot);
    } catch(e){if(token===operation.current)props.onMessage((e as Error).message);}
    finally{if(token===operation.current){setPassword('');props.setBusy(false);}}
  }
  async function unlockGroups() {
    if(props.history.length>100){props.onMessage('Device grouping supports up to 100 retained snapshots. Review retention before grouping.');return;}
    props.setBusy(true);const token=++operation.current;const unlocked:Summary[]=[];let locked=0;
    try {
      for(let index=0;index<props.history.length;index++){
        if(token!==operation.current)return;
        setProgress('Unlocking '+(index+1)+' of '+props.history.length+' snapshots…');
        try {const snapshot=await loadSnapshot(props.history[index],password);if(token!==operation.current)return;unlocked.push(summarize(props.history[index],snapshot));}catch{locked++;}
      }
      if(token===operation.current){setSummaries(unlocked);props.onMessage(unlocked.length ? 'Grouped '+unlocked.length+' snapshots by device. '+locked+' remain locked or unreadable.' : 'Unable to unlock any snapshots. Check the passphrase and snapshot integrity.');}
    } finally {if(token===operation.current){setPassword('');setProgress('');props.setBusy(false);}}
  }
  async function clear() {
    try {await clearHistory();props.setHistory([]);setSummaries([]);setComparison(null);setPassword('');props.onMessage('All local encrypted snapshots deleted.');}
    catch(e){props.onMessage((e as Error).message);}
  }
  const groups=new Map<string,Summary[]>();
  for(const summary of summaries){const group=groups.get(summary.key) ?? [];group.push(summary);groups.set(summary.key,group);}
  return <section className="panel history-panel"><p className="eyebrow">ENCRYPTED ON THIS BROWSER</p><h2>Keep a record of improvement</h2><p>Audits, device labels and remediation notes are encrypted together. Device groups appear only after unlocking and remain in memory. Passphrases are never stored; losing one means losing access.</p><label htmlFor="device-label">Device label for this assessment</label><input id="device-label" disabled={props.busy} value={props.deviceLabel} maxLength={120} autoComplete="off" placeholder="An optional label, kept inside encrypted history" onChange={e=>props.setDeviceLabel(e.target.value)}/><p className="fine">Groups use recorded device identity, platform and host/guest environment. Labels do not merge unrelated devices. Use the same engagement salt for repeat collection.</p><label htmlFor="password">History passphrase (at least 12 characters)</label><input id="password" disabled={props.busy} type="password" autoComplete="off" maxLength={1000} value={password} onChange={e=>setPassword(e.target.value)}/><p className="fine">The passphrase clears after each operation. Re-enter it to open or compare a retained assessment.</p><div className="history-actions"><label>Keep last <input aria-label="Retention count" disabled={props.busy} type="number" min={1} max={100} value={retention} onChange={e=>setRetention(Number(e.target.value))}/> snapshots</label><button className="button primary" disabled={props.busy} onClick={save}>Save encrypted snapshot</button><button className="button subtle" disabled={props.busy || !props.history.length} onClick={unlockGroups}>Unlock device groups</button><button className="button danger" disabled={props.busy || !props.history.length} onClick={clear}>Delete local history</button></div><p className="fine">{props.dirty ? 'Unsaved labels or decisions remain in memory until you save an encrypted snapshot.' : props.decisions.length+' remediation decisions are attached to the current assessment.'} Signer trust must be checked again against the original bundle after restoration.</p>{progress && <div className="unlock-progress"><span>{progress}</span><button className="text-button" onClick={()=>{operation.current++;setProgress('');setPassword('');props.setBusy(false);}}>Cancel unlocking</button></div>}{groups.size>0 && <div className="device-groups"><div className="section-header"><div><h3>{groups.size} device groups</h3><button className="text-button" disabled={props.busy} onClick={()=>{setSummaries([]);setComparison(null);setPassword('');}}>Hide unlocked groups</button></div><label>Freshness review window<select aria-label="Freshness review window" value={windowHours} onChange={e=>setWindowHours(Number(e.target.value))}><option value={24}>24 hours</option><option value={168}>7 days</option><option value={720}>30 days</option></select></label></div>{Array.from(groups.entries()).map(([key,group])=>{const sorted=[...group].sort((a,b)=>Date.parse(b.started)-Date.parse(a.started));const newest=sorted[0];const age=freshness({...props.audit,started_at:newest.started,finished_at:newest.finished},Date.now(),windowHours);return <section className="device-group" key={key}><div className="section-header"><div><h3>{newest.label || newest.platform+' device'}</h3><p className="fine">{newest.asset.slice(0,16)}… · {group.length} assessments · {newest.platform}</p></div><span className={'badge '+age.kind}>{age.label}</span></div><p className="fine">{age.detail}</p>{sorted.map(s=><div className="history-row" key={s.row.id}><span><strong>{new Date(s.started).toLocaleString()}</strong><small>{s.decisionCount} recorded decisions{deviceKey(props.audit)===s.key ? ' · Current device' : ''}</small></span><button className="text-button" disabled={props.busy} onClick={()=>unlock(s.row)}>Unlock</button><button className="text-button" disabled={props.busy || deviceKey(props.audit)!==s.key || Date.parse(s.started)>Date.parse(props.audit.started_at)} onClick={()=>unlock(s.row,true)}>Compare to current</button></div>)}</section>;})}</div>}{props.history.filter(row=>!summaries.some(s=>s.row.id===row.id)).map(row=><div className="history-row" key={row.id}><span><strong>Encrypted snapshot</strong><small>Saved {new Date(row.created).toLocaleString()} · device identity locked</small></span><button className="text-button" disabled={props.busy} onClick={()=>unlock(row)}>Unlock</button><button className="text-button" disabled={props.busy} onClick={()=>unlock(row,true)}>Compare to current</button></div>)}{!props.history.length && <p className="empty">No retained snapshots. Imports remain in memory until you explicitly save them.</p>}{comparison && <ComparisonView comparison={comparison}/>}</section>;
}
export function ComparisonView({comparison}:{comparison:Comparison}) {
  const counts={regression:0,improvement:0,policy_changed:0,evidence_gap:0};
  for(const change of comparison.changes)if(change.kind in counts)counts[change.kind as keyof typeof counts]++;
  return <section className="comparison"><p className="eyebrow">REASSESSMENT / SAME RECORDED DEVICE</p><h3>{comparison.changes.length} recorded changes</h3><p className="fine">Baseline: {new Date(comparison.baselineTime).toLocaleString()} · Current: {new Date(comparison.currentTime).toLocaleString()}</p><div className="comparison-counts"><span>{counts.regression} regressions</span><span>{counts.improvement} improvements</span><span>{counts.policy_changed} policy changes</span><span>{counts.evidence_gap} evidence gaps</span></div>{comparison.policyChanged && <p>Policy identity or version changed. Changed outcomes cannot be attributed to security settings alone.</p>}{comparison.scopeChanged && <p>Assessment scope changed. Outcomes are listed as scope changes, not verified improvements or regressions.</p>}{comparison.collectorChanged && <p className="fine">Collector version changed. Review measurement compatibility before interpreting an outcome change.</p>}<div className="table-wrap"><table><thead><tr><th>Control</th><th>Before</th><th>After</th><th>Interpretation</th></tr></thead><tbody>{comparison.changes.map(c=><tr key={c.id}><td>{c.id}<small className="change-title">{c.title}</small></td><td>{c.before ?? 'Not present'}</td><td>{c.after ?? 'Not present'}</td><td><span className={'change-badge '+c.kind}>{changeLabels[c.kind]}</span></td></tr>)}</tbody></table></div>{!comparison.changes.length && <p>No recorded control outcomes or policy versions changed.</p>}<p className="fine">New or removed controls and unavailable evidence are not proof of a fix. These comparisons use recorded outcomes and declared versions; reassessment does not establish causation or endpoint compromise.</p></section>;
}
