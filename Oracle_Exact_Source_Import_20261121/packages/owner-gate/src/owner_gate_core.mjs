/* Strictly scoped owner-authenticated operations for the EXISTING Batcave gate.
 * Caller must authenticate confirmed owner email BEFORE invoking any operation.
 * Repository writes must be implemented by private, service-role-only atomic RPCs.
 * Never authorizes production release, broad shell, or arbitrary prompts.
 */
import {verifyOwnerEnrollmentV2,DOMAIN,REVIEWER_KEY,FIXTURE_TOKEN,RELEASE_SHA} from './verify_owner_enrollment_v2.mjs';
import {verifyOracleLabReview} from './verify_lab_grant.mjs';
import {readLabJobStatus} from './lab_job_status.mjs';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HEX32=/^[a-f0-9]{32}$/;
function deny(error,status=403){return {status,body:{error,lab_only:true,execution_authorized:false,deployment_authorized:false}};}
function mustOwner(ctx){return typeof ctx?.owner_user_id==='string'&&UUID.test(ctx.owner_user_id)&&ctx.owner_authenticated===true;}
function keyset(x,s){return x&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).sort().join('|')===s;}
function seededNonce(){return Array.from(crypto.getRandomValues(new Uint8Array(16)),x=>x.toString(16).padStart(2,'0')).join('');}
function fpRecord(r){
 return r&&Object.keys(r).sort().join('|')==='cloud_enrolled|host|production_release_authorized|public_key_pem|public_key_sha256|reviewer_sid|role|schema'&&r.role==='lab_reviewer_only'&&r.reviewer_sid==='S-1-5-19'&&r.public_key_sha256===REVIEWER_KEY&&r.cloud_enrolled===false&&r.production_release_authorized===false;
}
export async function handleOracleLabOwnerRequest(body,ctx,repo,now=Date.now(),verifyReview=verifyOracleLabReview){
 if(!mustOwner(ctx))return deny('OWNER_AUTH_REQUIRED',401);
 if(!body||typeof body!=='object'||Array.isArray(body)||typeof body.action!=='string')return deny('BAD_BODY',422);
 if(body.action==='oracle_lab_job_status_v1')return readLabJobStatus(body,ctx,repo,now);
 if(body.action==='oracle_lab_enroll_challenge_v2'){
  if(!keyset(body,'action'))return deny('BAD_BODY',422);
  const ownerKey=await repo.getOwnerKey(ctx.owner_user_id);
  if(!ownerKey||ownerKey.revoked_at!==null)return deny('OWNER_KEY_REQUIRED');
  const nonce=seededNonce(),expires_at=new Date(now+5*60000).toISOString();
  const challenge=await repo.issueEnrollmentChallenge({owner_user_id:ctx.owner_user_id,nonce,expires_at});
  if(!challenge||challenge.owner_user_id!==ctx.owner_user_id||challenge.nonce!==nonce||new Date(challenge.expires_at).toISOString()!==expires_at) return deny('CHALLENGE_FAILED',503);
  const request={schema:DOMAIN,owner_user_id:ctx.owner_user_id,host:'CORTANA',reviewer_sid:'S-1-5-19',reviewer_key_sha256:REVIEWER_KEY,role:'lab_reviewer_only',fixture_token:FIXTURE_TOKEN,release_archive_sha256:RELEASE_SHA,nonce,expires_at};
  return {status:200,body:{schema:'batcave.oracle.lab.enroll.challenge.v2',request,signing_message:[DOMAIN,ctx.owner_user_id,'CORTANA','S-1-5-19',REVIEWER_KEY,'lab_reviewer_only',FIXTURE_TOKEN,RELEASE_SHA,nonce,expires_at].join('\n'),challenge_id:challenge.challenge_id,execution_authorized:false,deployment_authorized:false}};
 }
 if(body.action==='oracle_lab_enroll_reviewer_v2'){
  if(!keyset(body,'action|challenge_id|public_record|request|signature_b64url')||!UUID.test(body.challenge_id))return deny('BAD_BODY',422);
  if(!fpRecord(body.public_record))return deny('BAD_REVIEWER_RECORD',403);
  const ownerKey=await repo.getOwnerKey(ctx.owner_user_id);
  const challenge=await repo.getChallenge(body.challenge_id,ctx.owner_user_id);
  try{await verifyOwnerEnrollmentV2({request:body.request,signature_b64url:body.signature_b64url,ownerKey,authenticatedOwnerId:ctx.owner_user_id,challenge,now});}catch{return deny('OWNER_SIGNATURE_OR_SCOPE_DENIED');}
  if(typeof body.public_record.public_key_pem!=='string')return deny('MISSING_PUBLIC_KEY',422);
  // Host-side public SPKI must match known good Cortana public key, not merely claimant hash.
  try{
   const b64=body.public_record.public_key_pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g,'');
   const spki=Uint8Array.from(atob(b64),c=>c.charCodeAt(0));
   const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',spki)),b=>b.toString(16).padStart(2,'0')).join('');
   if(hash!==REVIEWER_KEY)throw Error('hash');
   const pub=await crypto.subtle.importKey('spki',spki,{name:'Ed25519'},false,['verify']);
   if(pub.type!=='public')throw Error('key');
  }catch{return deny('PUBLIC_KEY_PIN_MISMATCH');}
  const receipt=await repo.enrollVerifiedReviewer({challenge_id:body.challenge_id,owner_user_id:ctx.owner_user_id,request:body.request,signature_b64url:body.signature_b64url,public_record:body.public_record,expected_release_sha256:RELEASE_SHA});
  if(!receipt?.inserted){
   // Authentication, owner signature, and public SPKI were already verified above.
   // Surface only a fixed reason and sanitized SQLSTATE; never disclose credentials.
   const permitted=['invalid_record','challenge_unmatched','db_error'];
   const reason=permitted.includes(receipt?.reason)?receipt.reason:'unclassified';
   const sqlstate=/^[A-Z0-9]{5}$/.test(String(receipt?.sqlstate||''))?receipt.sqlstate:'unknown';
   // Return only an allowlisted failed field name, never field values or user identifiers.
   const allowedChecks=['owner_null','challenge_null','nonce_invalid','signature_invalid','record_type_invalid','role_invalid','host_invalid','sid_invalid','key_invalid','prod_invalid','cloud_invalid'];
   const failedField=reason==='invalid_record' && receipt?.checks && allowedChecks.find(k=>receipt.checks[k]===true);
   const suffix=reason==='db_error'?'_'+sqlstate:(failedField?'_'+failedField.toUpperCase():'');
   return deny('LAB_ENROLLMENT_'+reason.toUpperCase()+suffix,409);
  }
  return {status:200,body:{enrollment_recorded:true,reviewer_key_sha256:REVIEWER_KEY,lab_only:true,execution_authorized:false,deployment_authorized:false}};
 }
 if(body.action==='oracle_lab_record_review_v2'){
  if(!keyset(body,'action|job_id|raw_request_json|signed_receipt')||!UUID.test(body.job_id)||typeof body.raw_request_json!=='string')return deny('BAD_BODY',422);
  const key=await repo.getEnrolledReviewer(REVIEWER_KEY);
  if(!key||key.revoked_at!==null||key.release_archive_sha256!==RELEASE_SHA||key.owner_user_id!==ctx.owner_user_id)return deny('LAB_KEY_NOT_ENROLLED');
  const job=await repo.getModelJob(body.job_id);
  if(!job||job.status!=='pending'||job.attempt_count!==0||Date.parse(job.expires_at)<=now||job.device_name!=='Oracle')return deny('NO_PENDING_MODEL_JOB');
  if(!job.payload||Object.keys(job.payload).sort().join('|')!=='artifact_sha256|fixture|nonce|operation|schema')return deny('EXTRA_OR_MISSING_CLOUD_FIELDS');
  let checked;
  try{
   checked=await verifyReview({requestJson:body.raw_request_json,receipt:body.signed_receipt,
    publicRecord:key.public_record,
    trust:{role:key.role,enrollment_verified:true,revoked_at:null,public_key_sha256:REVIEWER_KEY},
    job:{id:job.id,nonce:job.payload.nonce,schema:job.payload.schema,action:job.action,operation:job.payload.operation,fixture:job.payload.fixture,artifact_sha256:job.payload.artifact_sha256},now});
  }catch{return deny('LAB_REVIEW_SIGNATURE_OR_JOB_DENIED');}
  if(!checked.review_valid||checked.production_deployment_authorized!==false)return deny('LAB_REVIEW_DENIED');
  if(Date.parse(body.signed_receipt.payload.reviewed_at)>Date.parse(job.expires_at))return deny('REVIEW_AFTER_JOB_EXPIRY');
  // A grant cannot outlive the exact window Cortana reviewed. The cloud task expires
  // no later than the reviewer request; otherwise it would extend reviewer consent.
  if(!checked.expires_at||Date.parse(checked.expires_at)<Date.parse(job.expires_at))return deny('REVIEW_SCOPE_TOO_SHORT');
  if(Date.parse(body.signed_receipt.payload.reviewed_at)<Date.parse(job.created_at))return deny('REVIEW_BEFORE_JOB_CREATED');
  // No direct table writes here: repository executes one private RPC with atomic pending-job check.
  const accepted=await repo.insertVerifiedGrant({job_id:job.id,nonce:job.payload.nonce,
   owner_user_id:ctx.owner_user_id,reviewer_key_sha256:REVIEWER_KEY,release_archive_sha256:RELEASE_SHA,
   request_sha256:body.signed_receipt.payload.request_sha256,raw_request_json:body.raw_request_json,
   signed_receipt:body.signed_receipt,expires_at:job.expires_at});
  if(!accepted?.inserted)return deny('DUPLICATE_OR_STALE_GRANT',409);
  return {status:200,body:{lab_review_recorded:true,job_id:job.id,grant_state:'pending_one_time_lease',execution_authorized:false,deployment_authorized:false}};
 }
 return deny('UNSUPPORTED_ACTION',400);
}
