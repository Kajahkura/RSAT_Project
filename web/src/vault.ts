import {Audit, record, validateAudit} from './evidence';
import {Decision, Snapshot, auditHash, validateDecisions} from './decisions';

export type Saved = {id:string;created:number};
type EncryptedEntry = Saved & {salt:number[];iv:number[];ciphertext:ArrayBuffer};
const format = 'rsat.workspace.snapshot/1';
const maxBytes = 25000000;

async function db():Promise<IDBDatabase> {
  return new Promise((resolve,reject)=>{
    const request=indexedDB.open('rsat-encrypted-history',1);
    request.onupgradeneeded=()=>request.result.createObjectStore('snapshots',{keyPath:'id'});
    request.onsuccess=()=>resolve(request.result);
    request.onerror=()=>reject(Error('Local history unavailable. Check browser storage permissions or use a regular browsing window.'));
  });
}
async function transaction<T>(mode:IDBTransactionMode,action:(store:IDBObjectStore)=>IDBRequest<T>):Promise<T> {
  const database=await db();
  try {
    return await new Promise<T>((resolve,reject)=>{
      const tx=database.transaction('snapshots',mode);
      const request=action(tx.objectStore('snapshots'));
      let result:T;
      request.onsuccess=()=>{result=request.result;};
      tx.oncomplete=()=>resolve(result);
      tx.onabort=()=>reject(Error('Local history transaction failed. Browser storage may be full.'));
      tx.onerror=()=>reject(Error('Local history write failed. Check storage permissions and available space.'));
    });
  } finally {database.close();}
}
async function key(password:string,salt:Uint8Array):Promise<CryptoKey> {
  if(password.length<12 || password.length>1000) throw Error('Use a passphrase of 12–1000 characters.');
  const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt:salt as BufferSource,iterations:600000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
export async function listHistory():Promise<Saved[]> {
  const database=await db();
  try {
    return await new Promise((resolve,reject)=>{
      const tx=database.transaction('snapshots','readonly');
      const rows:Saved[]=[];
      const request=tx.objectStore('snapshots').openCursor();
      request.onsuccess=()=>{
        const cursor=request.result;
        if(!cursor) return;
        const row=cursor.value;
        if(!record(row) || typeof row.id!=='string' || typeof row.created!=='number' || !Number.isFinite(row.created) || rows.length>=1000) {tx.abort();return;}
        rows.push({id:row.id,created:row.created});
        cursor.continue();
      };
      tx.oncomplete=()=>resolve(rows.sort((a,b)=>b.created-a.created));
      tx.onabort=()=>reject(Error('Local history contains unsupported records. Export retained evidence before clearing browser storage.'));
      tx.onerror=()=>reject(Error('Unable to read local history.'));
    });
  } finally {database.close();}
}
export async function saveHistory(audit:Audit,password:string,keep:number,state:{decisions?:Decision[];deviceLabel?:string}={}):Promise<Saved[]> {
  if(!Number.isInteger(keep)||keep<1||keep>100) throw Error('Retention must be 1–100 snapshots.');
  validateAudit(audit);
  const deviceLabel=state.deviceLabel ?? '';
  if(typeof deviceLabel!=='string' || deviceLabel.length>120) throw Error('Device labels must be at most 120 characters.');
  const decisions=validateDecisions(state.decisions ?? [],audit,await auditHash(audit));
  const plaintext=new TextEncoder().encode(JSON.stringify({format,audit,decisions,deviceLabel}));
  if(plaintext.byteLength>maxBytes) throw Error('This snapshot exceeds the 25 MB history limit. Export selected findings or use the native evidence archive.');
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const id=crypto.randomUUID();
  const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:new TextEncoder().encode(id)},await key(password,salt),plaintext);
  await transaction('readwrite',store=>store.put({id,created:Date.now(),salt:[...salt],iv:[...iv],ciphertext}));
  const rows=await listHistory();
  for(const row of rows.slice(keep)) await transaction('readwrite',store=>store.delete(row.id));
  return listHistory();
}
export async function loadSnapshot(row:Saved,password:string):Promise<Snapshot> {
  try {
    const stored=await transaction<EncryptedEntry|undefined>('readonly',store=>store.get(row.id));
    if(!stored || !(stored.ciphertext instanceof ArrayBuffer) || stored.ciphertext.byteLength>maxBytes+16 || stored.salt.length!==16 || stored.iv.length!==12) throw Error('Unsupported encrypted entry.');
    const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(stored.iv),additionalData:new TextEncoder().encode(row.id)},await key(password,new Uint8Array(stored.salt)),stored.ciphertext);
    const value:unknown=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plaintext));
    if(record(value) && value.format===format) {
      const audit=validateAudit(value.audit);
      if(typeof value.deviceLabel!=='string' || value.deviceLabel.length>120) throw Error('Invalid device label.');
      return {audit,decisions:validateDecisions(value.decisions,audit,await auditHash(audit)),deviceLabel:value.deviceLabel};
    }
    return {audit:validateAudit(value),decisions:[],deviceLabel:''};
  } catch {throw Error('Unable to unlock this snapshot. Check the passphrase, browser storage and snapshot integrity.');}
}
export async function loadHistory(row:Saved,password:string):Promise<Audit> {return (await loadSnapshot(row,password)).audit;}
export async function clearHistory():Promise<void> {await transaction('readwrite',store=>store.clear());}
