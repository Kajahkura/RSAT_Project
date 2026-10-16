import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, createHash} from 'node:crypto';
import example from '../public/demo-audit.json';
import {Audit, validateAudit, canonical} from '../src/evidence';
import {compareAudits, deviceKey, freshness} from '../src/reassessment';
import {auditHash, Decision, validateDecisions} from '../src/decisions';
import {findingsJson, findingsCsv, redactedReport} from '../src/reporting';
import {publicControls} from '../src/control-catalog';
import {publicKeyFingerprint} from '../src/onboarding';

function fixture():Audit {return validateAudit(structuredClone(example));}
function next(before:Audit):Audit {
  return {...structuredClone(before), audit_id:'second-assessment', started_at:'2026-10-02T10:00:00Z', finished_at:'2026-10-02T10:00:20Z'};
}
async function decision(audit:Audit):Promise<Decision> {
  return {controlId:audit.findings[0].id, state:'ready_for_recheck', owner:'PRIVATE-OWNER', note:'PRIVATE-NOTE', dueDate:'2026-12-01', updatedAt:'2026-10-16T12:00:00Z', auditHash:await auditHash(audit), ruleVersion:audit.findings[0].rule_version};
}

test('same-device reassessment separates recorded regressions, improvements and gaps',()=>{
  const before=fixture(), after=next(before);
  after.findings[0].status='PASS';
  after.findings[1].status='FAIL';
  after.findings[2].status='UNKNOWN';
  const changes=compareAudits(before,after).changes;
  assert.deepEqual(changes.map(c=>c.kind),['improvement','regression','evidence_gap']);
  assert.equal(compareAudits(before,before).changes.length,0);
});

test('policy and scope changes cannot claim a verified fix',()=>{
  const before=fixture(), after=next(before);
  after.findings[0].status='PASS';
  after.findings[0].rule_version='changed';
  assert.equal(compareAudits(before,after).changes[0].kind,'policy_changed');
  after.findings[0].rule_version=before.findings[0].rule_version;
  after.policy={id:'different-policy',version:'3'};
  assert.ok(compareAudits(before,after).changes.every(c=>c.kind==='policy_changed'));
  after.scope='Changed scope';
  assert.ok(compareAudits(before,after).changes.every(c=>c.kind==='scope_changed'));
});

test('comparison rejects different identities, contexts, reversed time and reused IDs',()=>{
  const before=fixture();
  for(const patch of [{asset_id:'another-device'},{asset_id_scope:'another-engagement'},{platform:'Linux'},{environment:{kind:'wsl'}}]) {
    assert.throws(()=>compareAudits(before,{...next(before),...patch}),/same device/);
    assert.notEqual(deviceKey(before),deviceKey({...before,...patch}));
  }
  assert.throws(()=>compareAudits(next(before),before),/newer/);
  const after=next(before);after.audit_id=before.audit_id;
  assert.throws(()=>compareAudits(before,after),/identifier/);
});

test('coverage, added and removed controls remain separate from fixes',()=>{
  const before=fixture(), after=next(before);
  after.findings[0].status='NOT_APPLICABLE';
  after.findings.pop();
  after.findings.push({...before.findings[0],id:'CUSTOM-CONTROL'});
  assert.deepEqual(compareAudits(before,after).changes.map(c=>c.kind),['coverage_changed','added','removed']);
  after.collector_version='new-collector';
  assert.equal(compareAudits(before,after).collectorChanged,true);
});

test('freshness handles review windows, incomplete, future and inconsistent evidence',()=>{
  const audit=fixture(), now=Date.parse('2026-10-02T12:00:00Z');
  assert.equal(freshness(audit,now).label,'Reassessment due');
  assert.equal(freshness(audit,now,168).label,'Within review window');
  assert.equal(freshness({...audit,finished_at:null},now).label,'Incomplete assessment');
  assert.equal(freshness({...audit,finished_at:'2026-10-03T00:00:00Z'},now).label,'Future timestamp');
  assert.equal(freshness({...audit,finished_at:'2025-01-01T00:00:00Z'},now).label,'Inconsistent timestamps');
});

test('a recent audit cannot hide stale or future observation timestamps',()=>{
  const audit=next(fixture()),now=Date.parse('2026-10-02T12:00:00Z');
  audit.observations[0].collected_at='2026-09-01T00:00:00Z';
  assert.equal(freshness(audit,now).label,'Reassessment due');
  assert.match(freshness(audit,now).detail,/Oldest recorded evidence/);
  audit.observations[0].collected_at='2026-12-01T00:00:00Z';
  assert.equal(freshness(audit,now).label,'Future evidence timestamp');
});

test('remediation decisions are strictly audit/rule-bound and never alter outcomes',async()=>{
  const audit=fixture(), hash=await auditHash(audit), d=await decision(audit), original=canonical(audit);
  assert.equal(validateDecisions([d],audit,hash)[0].state,'ready_for_recheck');
  assert.equal(canonical(audit),original);
  for(const patch of [{state:'resolved'},{auditHash:'wrong'},{ruleVersion:'wrong'},{dueDate:'2026-02-31'},{note:'x'.repeat(2001)}]) {
    assert.throws(()=>validateDecisions([{...d,...patch}],audit,hash));
  }
  assert.throws(()=>validateDecisions([d,d],audit,hash));
  assert.throws(()=>validateDecisions([d],next(audit),'new-hash'));
});

test('selected exports preserve selection and disclose unsigned provenance',async()=>{
  const audit=fixture(), d=await decision(audit), selected=new Set([d.controlId]);
  const json=JSON.parse(findingsJson(audit,selected,[d],'Verified signature'));
  assert.equal(json.findings.length,1);
  assert.equal(json.findings[0].remediation_decision.note,'PRIVATE-NOTE');
  assert.match(json.export_verification,/unsigned/);
  assert.equal(json.source_verification,'Verified signature');
  for(const fn of [()=>findingsJson(audit,new Set(),[],''),()=>findingsCsv(audit,new Set(),[]),()=>redactedReport(audit,new Set(),[])])assert.throws(fn,/Select/);
});

test('CSV guards formulas, tabs, quotes and line breaks in finding and decision fields',async()=>{
  const audit=fixture(), d=await decision(audit);
  audit.findings[0].title='=HYPERLINK("https://example.invalid")';
  audit.findings[0].details='\tformula';
  d.owner='  @SUM(1+1)';d.note='line1\n"line2"';
  const csv=findingsCsv(audit,new Set([d.controlId]),[d]);
  assert.ok(csv.startsWith('\ufeff'));
  assert.ok(csv.includes('"\'=HYPERLINK(""https://example.invalid"")"'));
  assert.ok(csv.includes('"\'\tformula"'));
  assert.ok(csv.includes('"\'  @SUM(1+1)"'));
  assert.ok(csv.includes('"line1\n""line2"""'));
});

test('redacted reports exclude identifiers, imported prose and free-text decisions',async()=>{
  const audit=fixture(), d=await decision(audit);
  audit.asset_id='PRIVATE-ASSET';audit.hostname='PRIVATE-HOST';audit.scope='PRIVATE-SCOPE';
  for(const f of audit.findings){f.title='PRIVATE-TITLE';f.details='PRIVATE-DETAILS';f.remediation='PRIVATE-REMEDIATION';f.rule_version='PRIVATE-RULE';}
  audit.findings.push({...audit.findings[0],id:'PRIVATE-CUSTOM-ID'});
  const report=redactedReport(audit,new Set(audit.findings.map(f=>f.id)),[d]);
  assert.ok(!report.includes('PRIVATE-'));
  assert.ok(!report.includes(audit.started_at));
  assert.ok(report.includes(publicControls[audit.findings[0].id].title));
  assert.ok(report.includes('CUSTOM-'));
  assert.ok(report.includes('Ready for recheck'));
  assert.match(report,/unsigned/);
  assert.doesNotMatch(report,/<script|https?:\/\/|<iframe|<img/i);
});

test('prototype-named custom controls cannot access inherited catalog entries',()=>{
  const audit=fixture();audit.findings=[{...audit.findings[0],id:'__proto__'}];
  assert.match(redactedReport(audit,new Set(['__proto__']),[]),/Custom control/);
});

test('trusted signing-key fingerprints hash public Ed25519 DER bytes',async()=>{
  const {publicKey,privateKey}=generateKeyPairSync('ed25519');
  const pem=publicKey.export({type:'spki',format:'pem'}).toString();
  const der=publicKey.export({type:'spki',format:'der'});
  assert.equal(await publicKeyFingerprint(pem),createHash('sha256').update(der).digest('hex'));
  await assert.rejects(publicKeyFingerprint(privateKey.export({type:'pkcs8',format:'pem'}).toString()),/public PEM/);
  await assert.rejects(publicKeyFingerprint('invalid'));
});

test('optional identity metadata cannot silently downgrade comparison validation',()=>{
  for(const patch of [{policy:'invalid'},{environment:{kind:12}},{asset_id_scope:{name:'invalid'}}])assert.throws(()=>validateAudit({...fixture(),...patch}));
});
