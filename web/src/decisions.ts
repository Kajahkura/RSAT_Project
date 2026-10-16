import {Audit, canonical, record} from './evidence';

export const decisionStates = ['planned','in_progress','ready_for_recheck','accepted_risk'] as const;
export type DecisionState = typeof decisionStates[number];
export const decisionLabels:Record<DecisionState,string> = {planned:'Planned',in_progress:'In progress',ready_for_recheck:'Ready for recheck',accepted_risk:'Accepted risk'};
export type Decision = {controlId:string;state:DecisionState;owner:string;note:string;dueDate:string;updatedAt:string;auditHash:string;ruleVersion:string};
export type Snapshot = {audit:Audit;decisions:Decision[];deviceLabel:string};
export async function auditHash(audit:Audit):Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256',new TextEncoder().encode(canonical(audit)));
  return Array.from(new Uint8Array(bytes),n=>n.toString(16).padStart(2,'0')).join('');
}
export function validateDecisions(value:unknown, audit:Audit, hash:string):Decision[] {
  if(!Array.isArray(value) || value.length > audit.findings.length) throw Error('Invalid remediation records.');
  const ids = new Set<string>();
  for(const d of value) {
    if(!record(d) || typeof d.controlId !== 'string' || ids.has(d.controlId) || !decisionStates.includes(d.state as DecisionState)) throw Error('Invalid remediation record.');
    const finding = audit.findings.find(f=>f.id===d.controlId);
    if(!finding || d.auditHash !== hash || d.ruleVersion !== finding.rule_version) throw Error('Remediation records do not belong to this audit and rule version.');
    for(const [field,limit] of [['owner',120],['note',2000],['dueDate',10],['updatedAt',50]] as const) {
      if(typeof d[field] !== 'string' || d[field].length > limit) throw Error('Invalid remediation field: ' + field);
    }
    const due=d.dueDate as string;
    const parsed=Date.parse(due);
    if(!Number.isFinite(Date.parse(d.updatedAt as string)) || (due !== '' && (!/^\d{4}-\d{2}-\d{2}$/.test(due) || !Number.isFinite(parsed) || new Date(parsed).toISOString().slice(0,10)!==due))) throw Error('Invalid remediation date.');
    ids.add(d.controlId);
  }
  return value as Decision[];
}
