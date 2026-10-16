import {Audit, Finding, Outcome, canonical, record} from './evidence';

export type ChangeKind = 'regression' | 'improvement' | 'evidence_gap' | 'coverage_changed' | 'outcome_changed' | 'policy_changed' | 'scope_changed' | 'added' | 'removed';
export type Change = {id:string; title:string; before:Outcome|null; after:Outcome|null; kind:ChangeKind; ruleChanged:boolean};
export type Comparison = {changes:Change[]; policyChanged:boolean; scopeChanged:boolean; collectorChanged:boolean; baselineTime:string; currentTime:string};
export const changeLabels:Record<ChangeKind,string> = {
  regression:'Regression', improvement:'Improvement', evidence_gap:'Evidence gap', coverage_changed:'Coverage changed',
  outcome_changed:'Outcome changed', policy_changed:'Policy changed', scope_changed:'Scope changed', added:'New control', removed:'Removed control',
};

function environmentKind(audit:Audit):string {
  return record(audit.environment) && typeof audit.environment.kind === 'string' ? audit.environment.kind : 'unspecified';
}
export function deviceKey(audit:Audit):string {
  return canonical({asset:audit.asset_id, identityScope:audit.asset_id_scope ?? 'unspecified', platform:audit.platform, environment:environmentKind(audit)});
}
function policyIdentity(audit:Audit):string {
  return record(audit.policy) ? canonical({id:audit.policy.id ?? null, version:audit.policy.version ?? null}) : 'unspecified';
}
function classify(before:Finding, after:Finding):ChangeKind {
  if(before.status === 'PASS' && after.status === 'FAIL') return 'regression';
  if(before.status === 'FAIL' && after.status === 'PASS') return 'improvement';
  if(['PASS','FAIL'].includes(before.status) && ['UNKNOWN','ERROR'].includes(after.status)) return 'evidence_gap';
  if(['UNKNOWN','ERROR','NOT_APPLICABLE'].includes(before.status) || after.status === 'NOT_APPLICABLE') return 'coverage_changed';
  return 'outcome_changed';
}
export function compareAudits(before:Audit, after:Audit):Comparison {
  if(deviceKey(before) !== deviceKey(after)) throw Error('Choose audits of the same device, identity scope and host or guest environment.');
  if(Date.parse(before.started_at) > Date.parse(after.started_at)) throw Error('The baseline is newer than the current audit. Open the newest audit before comparing.');
  if(before.audit_id === after.audit_id && canonical(before) !== canonical(after)) throw Error('These audits reuse an audit identifier with different contents. Generate a new assessment.');
  const policyChanged = policyIdentity(before) !== policyIdentity(after);
  const scopeChanged = before.scope !== after.scope;
  const old = new Map(before.findings.map(f => [f.id,f]));
  const current = new Map(after.findings.map(f => [f.id,f]));
  const changes:Change[] = [];
  for(const f of after.findings) {
    const previous = old.get(f.id);
    if(!previous) { changes.push({id:f.id,title:f.title,before:null,after:f.status,kind:'added',ruleChanged:false}); continue; }
    const ruleChanged = previous.rule_version !== f.rule_version || previous.severity !== f.severity;
    if(previous.status === f.status && !ruleChanged && !policyChanged && !scopeChanged) continue;
    const kind:ChangeKind = scopeChanged ? 'scope_changed' : (ruleChanged || policyChanged) ? 'policy_changed' : classify(previous,f);
    changes.push({id:f.id,title:f.title,before:previous.status,after:f.status,kind,ruleChanged});
  }
  for(const f of before.findings) if(!current.has(f.id)) changes.push({id:f.id,title:f.title,before:f.status,after:null,kind:'removed',ruleChanged:false});
  return {changes,policyChanged,scopeChanged,collectorChanged:before.collector_version !== after.collector_version,baselineTime:before.started_at,currentTime:after.started_at};
}

export function freshness(audit:Audit, now:number, windowHours=24):{label:string;detail:string;kind:string} {
  const timestamps=audit.observations.filter(o=>o.collected_at!==undefined).map(o=>o.collected_at!);
  return freshnessFromTimes(audit.started_at,audit.finished_at,timestamps,audit.observations.length-timestamps.length,now,windowHours);
}
export function freshnessFromTimes(started:string,completed:string|null,times:string[],missing:number,now:number,windowHours=24):{label:string;detail:string;kind:string} {
  if(completed === null) return {label:'Incomplete assessment',detail:'This audit has no completion timestamp.',kind:'unknown'};
  const finished = Date.parse(completed);
  if(finished < Date.parse(started)) return {label:'Inconsistent timestamps',detail:'Completion precedes the start of collection.',kind:'unknown'};
  if(finished>now+300000)return {label:'Future timestamp',detail:'Check the collector and browser clocks before relying on freshness.',kind:'unknown'};
  const timestamps=times.map(time=>Date.parse(time));
  if(timestamps.some(time=>time>now+300000))return {label:'Future evidence timestamp',detail:'Check observation and collector clocks before relying on freshness.',kind:'unknown'};
  const oldest=Math.min(finished,...timestamps);
  const age = now - oldest;
  if(age < -300000) return {label:'Future timestamp',detail:'Check the collector and browser clocks before relying on freshness.',kind:'unknown'};
  const hours = Math.max(0,age / 3600000);
  const ageLabel = hours < 1 ? 'less than an hour ago' : hours < 48 ? Math.floor(hours) + ' hours ago' : Math.floor(hours / 24) + ' days ago';
  const basis=timestamps.length ? 'Oldest recorded evidence: ' : 'Assessment completed: ';
  return {label:hours <= windowHours ? 'Within review window' : 'Reassessment due',detail:basis + ageLabel + '. Review window: ' + windowHours + ' hours. ' + (missing ? missing+' observations have no individual timestamp. ' : '') + 'This is evidence age, not continuous monitoring.',kind:hours <= windowHours ? 'pass' : 'unknown'};
}
