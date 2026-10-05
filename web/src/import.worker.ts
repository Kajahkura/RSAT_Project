import { unzipSync } from 'fflate';
import { validateAudit,record } from './evidence';
const encoder=new TextEncoder();
const hex=(bytes:ArrayBuffer)=>Array.from(new Uint8Array(bytes),x=>x.toString(16).padStart(2,'0')).join('');
async function digest(data:Uint8Array){return hex(await crypto.subtle.digest('SHA-256',data as BufferSource));}
function pem(pinned:string){if(!pinned.includes('-----BEGIN PUBLIC KEY-----')||pinned.length>2000)throw Error('Choose an Ed25519 public PEM key.');const raw=atob(pinned.replace(/-----[A-Z ]+-----/g,'').replace(/\s/g,''));return Uint8Array.from(raw,c=>c.charCodeAt(0));}
self.onmessage=async(event:MessageEvent<{bytes:ArrayBuffer;zip:boolean;pinned:string}>)=>{
 try{
  const {bytes,zip,pinned}=event.data;
  if(bytes.byteLength>20000000)throw Error('File exceeds the 20 MB import limit.');
  let raw=new Uint8Array(bytes);let trust='Unverified JSON import';
  if(zip){
   let total=0,count=0;const names=new Set<string>();
   const entries=unzipSync(raw,{filter:file=>{total+=file.originalSize;count++;if(count>100||total>50000000||!Number.isSafeInteger(file.originalSize)||file.originalSize<0||names.has(file.name)||/[\\/]/.test(file.name)||file.name.startsWith('.'))throw Error('Unsafe evidence bundle.');names.add(file.name);return true;}});
   if(!entries['manifest.json']||!entries['audit.json'])throw Error('Bundle needs manifest.json and audit.json.');
   const manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(entries['manifest.json']));
   if(!record(manifest)||manifest.schema_version!=='1.0'||manifest.hash_algorithm!=='sha256'||!record(manifest.files))throw Error('Unsupported bundle manifest.');
   const allowed=new Set([...Object.keys(manifest.files),'manifest.json','manifest.sig','signer.pub.pem']);
   if(Object.keys(entries).some(k=>!allowed.has(k))||!Object.keys(manifest.files).length||!('audit.json' in manifest.files))throw Error('Unmanifested audit or bundle files.');
   for(const [name,hash]of Object.entries(manifest.files)){if(!entries[name]||typeof hash!=='string'||await digest(entries[name])!==hash)throw Error('Bundle integrity check failed.');}
   trust='Bundle integrity checked · signer untrusted';
   if(pinned.trim()){
    if(!entries['manifest.sig'])throw Error('Pinned signature requested, but bundle is unsigned.');
    const key=await crypto.subtle.importKey('spki',pem(pinned) as BufferSource,{name:'Ed25519'},false,['verify']);
    if(!await crypto.subtle.verify('Ed25519',key,entries['manifest.sig'] as BufferSource,entries['manifest.json'] as BufferSource))throw Error('Pinned signer verification failed.');
    trust='Verified signature · independently pinned key';
   }
   raw=entries['audit.json'];
  }else if(pinned.trim())throw Error('Signature verification requires a signed .rsat.zip bundle.');
  const audit=validateAudit(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw)));
  self.postMessage({ok:true,audit,trust,fileSha256:await digest(new Uint8Array(bytes))});
 }catch(error){self.postMessage({ok:false,error:error instanceof Error?error.message:'Invalid import.'});}
};
