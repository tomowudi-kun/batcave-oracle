/* STAGED extension of the existing change gate. Public-key evidence only.
 * The authenticated HTTP wrapper supplies ctx; requests never supply trust.
 * Custody attestations must be independently installed by the registrar.
 * No attestation writer, deployer, command dispatcher or executable grants here.
 */
import {PIN,SCHEMA,OWNER_DOMAIN,canonicalReleaseText,verifyReleaseEvidence} from './verify_release_approval_v1.mjs';
export const ENROLL_DOMAIN='batcave.oracle.independent_nanny.enrollment.owner.v1\n';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HEX=/^[a-f0-9]{64}$/;
const LAB_KEY='4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b';
const LAB_RAW_HASH='61dde7b2e70af2d47746b75f401d87d57e41e123aeba185cc8ca6b7e1b05b664';
const LAB_RAW_KEY='PkCiAsi_f6Cv2UkYCYZbE3z8L5pgUi339QB-yLVvKCo';
const FLAGS=Object.freeze({deployment_authorized:false,execution_authorized:false,grant_issued:false});
const te=new TextEncoder();
export function stableJson(x){
 if(Array.isArray(x))return '['+x.map(stableJson).join(',')+']';
 if(x&&typeof x==='object')return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+stableJson(x[k])).join(',')+'}';
 return JSON.stringify(x);
}
export async function hashText(s){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',te.encode(s))),b=>b.toString(16).padStart(2,'0')).join('');}
async function hashRaw(b){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',b)),x=>x.toString(16).padStart(2,'0')).join('');}
function must(v,reason){if(!v)throw Error(reason);}
function exact(x,fields){return x&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).sort().join('|')===fields.split('|').sort().join('|');}
function iso(v){return typeof v==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString()===v;}
function b64(s,n){must(typeof s==='string'&&new RegExp('^[A-Za-z0-9_-]{'+n+'}$').test(s),'BAD_BASE64URL');const a=Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));must(btoa(String.fromCharCode(...a)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')===s,'NONCANONICAL_BASE64URL');return a;}
function fresh(row,now){return row&&row.consumed_at===null&&iso(row.expires_at)&&Date.parse(row.expires_at)>now&&Date.parse(row.issued_at)<=now+30000&&Date.parse(row.issued_at)>=now-600000;}
async function checkPublic(raw,fp){must(HEX.test(fp),'BAD_KEY_HASH');const bytes=b64(raw,43);must(bytes.length===32&&await hashRaw(bytes)===fp,'KEY_HASH_MISMATCH');await crypto.subtle.importKey('raw',bytes,{name:'Ed25519'},false,['verify']);return bytes;}
export async function verifyPublicSignature(key,message,signature){
 const bytes=await checkPublic(key.public_key_b64url,key.public_key_sha256);
 const sig=b64(signature,86);must(sig.length===64,'BAD_SIGNATURE_LENGTH');
 const k=await crypto.subtle.importKey('raw',bytes,{name:'Ed25519'},false,['verify']);
 must(await crypto.subtle.verify('Ed25519',k,sig,te.encode(message)),'SIGNATURE_INVALID');
}
async function ownerKey(repo,id){
 const row=await repo.getOwner(id);must(row&&row.owner_user_id===id&&row.revoked_at===null,'OWNER_KEY_REQUIRED');
 await checkPublic(row.public_key_b64url,row.public_key_sha256);
 return {...row,role:'owner',registered:true,valid_until:null};
}
async function intent(repo,now){
 const i=await repo.getIntent(PIN.intent_key),s=i?.requested_scope;
 must(i?.state==='held'&&i.content_sha256===PIN.intent_sha256&&Date.parse(i.valid_until)>now,'PINNED_INTENT_NOT_CURRENT');
 must(s?.scope===PIN.scope&&s.fixture===PIN.fixture&&s.target_device===PIN.target_device&&s.target_operation===PIN.operation&&s.owner_gate_portal_release_zip_sha256===PIN.owner_gate_zip_sha256&&s.oracle_model_worker_release_zip_sha256===PIN.worker_zip_sha256&&s.no_general_shell===true&&s.no_production_permissions===true,'PINNED_INTENT_SCOPE_MISMATCH');
 return i;
}
async function candidate(record,owner){
 must(exact(record,'schema|role|registered|independently_attested|production_release_authorized|host_identity|public_key_b64url|public_key_sha256|created_at'),'BAD_CANDIDATE_SHAPE');
 must(record.schema==='batcave.nanny.release.public_key.v1'&&record.role==='independent_release_reviewer_CANDIDATE'&&record.registered===false&&record.independently_attested===false&&record.production_release_authorized===false&&iso(record.created_at),'BAD_CANDIDATE_SCOPE');
 const h=record.host_identity;
 must(exact(h,'host|os|user')&&typeof h.host==='string'&&h.host.toUpperCase()==='CORTANA'&&h.os==='win32'&&typeof h.user==='string'&&h.user.trim().length>0&&!/^(system|local service|network service)$/i.test(h.user),'PROTECTED_CORTANA_IDENTITY_REQUIRED');
 await checkPublic(record.public_key_b64url,record.public_key_sha256);
 must(record.public_key_sha256!==owner.public_key_sha256&&record.public_key_sha256!==LAB_KEY&&record.public_key_sha256!==LAB_RAW_HASH&&record.public_key_b64url!==LAB_RAW_KEY,'REVIEWER_KEY_NOT_INDEPENDENT');
 return {record_sha256:await hashText(stableJson(record)),host_identity_sha256:await hashText(stableJson(h))};
}
function custodyValid(a,owner,fp,hostHash,now){
 return a&&UUID.test(a.id)&&a.owner_user_id===owner&&a.public_key_sha256===fp&&a.host_identity_sha256===hostHash&&a.independently_attested===true&&a.release_policy_version==='strict_nanny.release.v1'&&a.private_key_custodian==='Cortana separate protected reviewer'&&HEX.test(a.evidence_sha256)&&a.revoked_at===null&&iso(a.valid_until)&&Date.parse(a.valid_until)>now;
}
export function canonicalEnrollmentText(p){
 must(exact(p,'schema|owner_user_id|candidate_sha256|reviewer_key_sha256|host_identity_sha256|attestation_id|nonce|issued_at|expires_at'),'BAD_ENROLLMENT_PAYLOAD');
 return stableJson(p);
}
async function registered(repo,id,fp,now){
 const k=await repo.getReviewer(id,fp);
 must(k?.role==='independent_release_reviewer'&&k.owner_user_id===id&&k.registered===true&&k.revoked_at===null&&iso(k.valid_until)&&Date.parse(k.valid_until)>now,'INDEPENDENT_REVIEWER_NOT_ENROLLED');
 const a=await repo.getCustody(id,fp);
 must(a?.id===k.attestation_id&&custodyValid(a,id,fp,k.host_identity_sha256,now),'INDEPENDENT_CUSTODY_REQUIRED');
 must(k.independently_attested===true&&k.release_policy_version===a.release_policy_version&&k.private_key_custodian===a.private_key_custodian,'REGISTRATION_ATTESTATION_MISMATCH');
 await checkPublic(k.public_key_b64url,k.public_key_sha256);return k;
}
async function newChallenge(repo,args){
 const r=await repo.issueChallenge(args);
 must(UUID.test(r?.id)&&r.nonce===args.nonce&&r.payload_sha256===args.payload_sha256&&r.owner_user_id===args.owner_user_id,'CHALLENGE_NOT_RECORDED');
 return r;
}
export async function handleReleaseGate(body,ctx,repo,now=Date.now()){
 try{
  must(ctx?.owner_authenticated===true&&UUID.test(ctx.owner_user_id),'OWNER_AUTH_REQUIRED');
  must(body&&typeof body==='object'&&!Array.isArray(body)&&typeof body.action==='string','BAD_REQUEST');
  const id=ctx.owner_user_id,owner=await ownerKey(repo,id);
  const i=await intent(repo,now);
  if(body.action==='oracle_release_enrollment_challenge_v1'){
   must(exact(body,'action|candidate'),'BAD_REQUEST');
   const c=await candidate(body.candidate,owner),fp=body.candidate.public_key_sha256;
   const a=await repo.getCustody(id,fp);
   must(custodyValid(a,id,fp,c.host_identity_sha256,now),'INDEPENDENT_CUSTODY_REQUIRED');
   const issued_at=new Date(now).toISOString(),expires_at=new Date(Math.min(now+5*60000,Date.parse(i.valid_until),Date.parse(a.valid_until))).toISOString();
   const nonce=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');
   const payload={schema:'batcave.oracle.release.enrollment.v1',owner_user_id:id,candidate_sha256:c.record_sha256,reviewer_key_sha256:fp,host_identity_sha256:c.host_identity_sha256,attestation_id:a.id,nonce,issued_at,expires_at};
   const ch=await newChallenge(repo,{kind:'enrollment',owner_user_id:id,owner_key_sha256:owner.public_key_sha256,reviewer_key_sha256:fp,attestation_id:a.id,nonce,issued_at,expires_at,payload,payload_sha256:await hashText(stableJson(payload)),candidate:body.candidate});
   return {status:200,body:{...FLAGS,challenge_id:ch.id,payload,signing_message:ENROLL_DOMAIN+canonicalEnrollmentText(payload)}};
  }
  if(body.action==='oracle_release_enroll_reviewer_v1'){
   must(exact(body,'action|challenge_id|owner_signature_b64url')&&UUID.test(body.challenge_id),'BAD_REQUEST');
   const ch=await repo.getChallenge(id,body.challenge_id);
   must(ch?.kind==='enrollment'&&fresh(ch,now)&&ch.owner_key_sha256===owner.public_key_sha256,'CHALLENGE_NOT_FRESH');
   const c=await candidate(ch.candidate,owner),p=ch.payload;
   must(await hashText(stableJson(p))===ch.payload_sha256&&p.candidate_sha256===c.record_sha256&&p.nonce===ch.nonce&&p.owner_user_id===id&&p.reviewer_key_sha256===ch.candidate.public_key_sha256&&p.host_identity_sha256===c.host_identity_sha256&&p.attestation_id===ch.attestation_id,'CHALLENGE_BINDING_MISMATCH');
   const a=await repo.getCustody(id,p.reviewer_key_sha256);
   must(a?.id===p.attestation_id&&custodyValid(a,id,p.reviewer_key_sha256,c.host_identity_sha256,now),'INDEPENDENT_CUSTODY_REQUIRED');
   await verifyPublicSignature(owner,ENROLL_DOMAIN+canonicalEnrollmentText(p),body.owner_signature_b64url);
   const r=await repo.enrollVerified({challenge:ch,owner_signature_b64url:body.owner_signature_b64url});
   must(r?.inserted===true,'REPLAY_REVOKED_OR_STALE_ENROLLMENT');
   return {status:200,body:{...FLAGS,reviewer_registered:true,reviewer_public_key_sha256:p.reviewer_key_sha256}};
  }
  if(body.action==='oracle_release_challenge_v1'){
   must(exact(body,'action|reviewer_public_key_sha256')&&HEX.test(body.reviewer_public_key_sha256),'BAD_REQUEST');
   const k=await registered(repo,id,body.reviewer_public_key_sha256,now);
   must(k.public_key_sha256!==owner.public_key_sha256&&k.public_key_sha256!==LAB_KEY&&k.public_key_sha256!==LAB_RAW_HASH&&k.public_key_b64url!==LAB_RAW_KEY,'REVIEWER_KEY_NOT_INDEPENDENT');
   const issued_at=new Date(now).toISOString(),expires_at=new Date(Math.min(now+10*60000,Date.parse(i.valid_until),Date.parse(k.valid_until))).toISOString();
   const nonce=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');
   const payload={...PIN,schema:SCHEMA,owner_user_id:id,nonce,issued_at,expires_at};
   const ch=await newChallenge(repo,{kind:'release',owner_user_id:id,owner_key_sha256:owner.public_key_sha256,reviewer_key_sha256:k.public_key_sha256,attestation_id:k.attestation_id,nonce,issued_at,expires_at,payload,payload_sha256:await hashText(stableJson(payload)),candidate:null});
   return {status:200,body:{...FLAGS,challenge_id:ch.id,payload,signing_message:OWNER_DOMAIN+canonicalReleaseText(payload)}};
  }
  if(body.action==='oracle_release_record_evidence_v1'){
   must(exact(body,'action|challenge_id|owner_signature_b64url|nanny_signature_b64url')&&UUID.test(body.challenge_id),'BAD_REQUEST');
   const ch=await repo.getChallenge(id,body.challenge_id);
   must(ch?.kind==='release'&&fresh(ch,now)&&ch.owner_key_sha256===owner.public_key_sha256,'CHALLENGE_NOT_FRESH');
   must(await hashText(stableJson(ch.payload))===ch.payload_sha256&&ch.payload.nonce===ch.nonce&&ch.payload.owner_user_id===id,'CHALLENGE_BINDING_MISMATCH');
   const k=await registered(repo,id,ch.reviewer_key_sha256,now);
   const verdict=await verifyReleaseEvidence({payload:ch.payload,owner_signature_b64url:body.owner_signature_b64url,nanny_signature_b64url:body.nanny_signature_b64url,authenticated_owner_id:id,trusted_owner_key:owner,trusted_nanny_key:k,nonce_issued_by_gate:true,nonce_consumed:false,now});
   const r=await repo.recordEvidence({challenge:ch,owner_signature_b64url:body.owner_signature_b64url,nanny_signature_b64url:body.nanny_signature_b64url,verdict});
   must(r?.inserted===true,'REPLAY_REVOKED_OR_STALE_EVIDENCE');
   return {status:200,body:{...FLAGS,evidence_recorded:true,evidence_id:r.evidence_id,cryptographic_evidence_valid:true}};
  }
  throw Error('UNSUPPORTED_ACTION');
 }catch(e){
  const reason=/^[A-Z][A-Z0-9_]{2,100}$/.test(e?.message||'')?e.message:'RELEASE_GATE_UNAVAILABLE';
  return {status:reason==='OWNER_AUTH_REQUIRED'?401:reason==='RELEASE_GATE_UNAVAILABLE'?503:403,body:{...FLAGS,error:reason}};
 }
}
