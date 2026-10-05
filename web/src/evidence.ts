export const outcomes = ['PASS','FAIL','UNKNOWN','ERROR','NOT_APPLICABLE'] as const;
export type Outcome = typeof outcomes[number];
export type Finding = {id:string; title:string; status:Outcome; severity:string; evidence_ids:string[]; details:string; remediation:string; rule_version:string};
export type Observation = {id:string; state:string; value:unknown; collected_at?:string; reason?:string; source?:string};
export type Risk = {id:string;title:string;severity:string;evidence_ids:string[];factors:string[];limitations:string};
export type Audit = {schema_version:string;audit_id:string;asset_id:string;platform:string;collector_version:string;os_release:string;architecture:string;scope:string;started_at:string;finished_at:string|null;observations:Observation[];findings:Finding[];risks:Risk[];vulnerabilities:{id:string;name:string}[];policy?:{id:string;version:string};environment?:{kind:string};[key:string]:unknown};
export function record(value:unknown):value is Record<string,unknown> {return !!value && typeof value==='object'&&!Array.isArray(value);}
const text = (value:unknown):value is string => typeof value==='string'&&value.length<=200000;
const strings = (value:unknown):value is string[] => Array.isArray(value)&&value.length<=10000&&value.every(text);
export function validateAudit(value:unknown):Audit {
  if(!record(value)||value.schema_version!=='2.0') throw Error('Choose a supported RSAT 2.0 audit.');
  for(const field of ['audit_id','asset_id','platform','collector_version','os_release','architecture','scope','started_at']) if(!text(value[field])||!value[field])throw Error('Invalid audit field: '+field);
  if(!Number.isFinite(Date.parse(value.started_at as string)))throw Error('Invalid audit timestamp.');
  if(value.finished_at!==null&&(!text(value.finished_at)||!Number.isFinite(Date.parse(value.finished_at))))throw Error('Invalid finished timestamp.');
  for(const field of ['observations','findings','risks','vulnerabilities'])if(!Array.isArray(value[field])||(value[field] as unknown[]).length>50000)throw Error('Invalid audit list: '+field);
  if((value.findings as unknown[]).length>1000||(value.observations as unknown[]).length>10000)throw Error('Audit exceeds workspace limits.');
  const ids=new Set<string>();
  for(const o of value.observations as unknown[]){if(!record(o)||!text(o.id)||!o.id||ids.has(o.id)||!['OK','UNKNOWN','ERROR','NOT_APPLICABLE'].includes(String(o.state)))throw Error('Invalid or duplicate observation.');ids.add(o.id);}
  ids.clear();
  for(const f of value.findings as unknown[]){if(!record(f)||!text(f.id)||!f.id||ids.has(f.id)||!outcomes.includes(f.status as Outcome)||!strings(f.evidence_ids)||!['info','low','medium','high','critical'].includes(String(f.severity)))throw Error('Invalid or duplicate finding.');for(const k of ['title','details','remediation','rule_version'])if(!text(f[k]))throw Error('Invalid finding field: '+k);ids.add(f.id);}
  for(const r of value.risks as unknown[]){if(!record(r)||!strings(r.evidence_ids)||!strings(r.factors))throw Error('Invalid risk evidence.');for(const k of ['id','title','severity','limitations'])if(!text(r[k]))throw Error('Invalid risk field.');}
  for(const v of value.vulnerabilities as unknown[])if(!record(v)||!text(v.id)||!text(v.name))throw Error('Invalid vulnerability.');
  return value as Audit;
}
export function canonical(value:unknown):string {
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  if(record(value))return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
  return JSON.stringify(value);
}
export function metrics(audit:Audit){const applicable=audit.findings.filter(f=>f.status!=='NOT_APPLICABLE');const assessed=applicable.filter(f=>f.status==='PASS'||f.status==='FAIL').length;return {applicable:applicable.length,assessed,coverage:applicable.length?Math.round(100*assessed/applicable.length):0,failed:applicable.filter(f=>f.status==='FAIL').length,gaps:applicable.filter(f=>f.status==='UNKNOWN'||f.status==='ERROR').length,passed:applicable.filter(f=>f.status==='PASS').length};}
export function retrieve(audit:Audit,question:string):Finding[]{const terms=question.toLowerCase().split(/\W+/).filter(x=>x.length>3);const candidates=audit.findings.filter(f=>f.status!=='NOT_APPLICABLE');const scored=candidates.map(f=>({f,score:terms.reduce((n,t)=>n+Number((f.title+' '+f.id+' '+f.details).toLowerCase().includes(t)),0)})).filter(x=>x.score>0);return scored.sort((a,b)=>b.score-a.score).slice(0,5).map(x=>x.f);}
export function drift(before:Audit,after:Audit){if(before.asset_id!==after.asset_id)throw Error('Choose audits of the same asset.');return after.findings.flatMap(f=>{const old=before.findings.find(x=>x.id===f.id);return old&&old.status!==f.status?[{id:f.id,before:old.status,after:f.status,ruleChanged:old.rule_version!==f.rule_version}]:[];});}
