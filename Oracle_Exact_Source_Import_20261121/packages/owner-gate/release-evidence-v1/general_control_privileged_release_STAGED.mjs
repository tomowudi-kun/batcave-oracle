/* STAGED, NOT DEPLOYED. GENUINELY SEPARATE privileged release-review
 * signature, distinct from owner consent and reviewer evidence admission.
 * This module NEVER issues execution permission, a lease or a deployment.
 * The privately attested reviewer must explicitly sign the exact currently
 * HELD intent, source, policy, owner/reviewer receipts and rollback scope.
 * Existing lab reviewer enrollment is NOT accepted. No auto-attestation.
 */
import {createHash,createPublicKey,randomBytes,verify} from 'node:crypto';
import {validateGeneralControlOwnerRequestV1} from '../src/general_control_owner_request_v1.mjs';
export const RELEASE_SCHEMA='batcave.general_control.privileged_release_review.v1';
export const RELEASE_DOMAIN='BATCAVE_GENERAL_CONTROL_PRIVILEGED_RELEASE_V1\n';
const ACTION_PREPARE='general_control_privileged_release_prepare_v1';
const ACTION_RECORD='general_control_privileged_release_record_v1';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const H32=/^[0-9a-f]{32}$/,H40=/^[0-9a-f]{40}$/,H64=/^[0-9a-f]{64}$/,H128=/^[0-9a-f]{128}$/;
const PREFIX='302a300506032b6570032100';
const FIELDS=['schema','owner_user_id','request_id','reviewer_identity_id',
 'reviewer_key_hex','intent_key','intent_sha256','request_sha256',
 'owner_signature_sha256','reviewer_signature_sha256','source_commit',
 'policy_digest','device','capability','target_origin','target_session_id',
 'command_digest','rollback_ref','nonce','issued_at','expires_at',
 'execution_authorized','deployment_authorized'];
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
const digest=x=>createHash('sha256').update(x).digest('hex');
const denied=(reason)=>Object.freeze({status:'DENY',reason,
 execution_authorized:false,deployment_authorized:false,grant_issued:false});
function iso(x){return typeof x==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x)&&Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;}
export function releaseSigningTextSTAGED(p){
 if(!exact(p,FIELDS)||p.schema!==RELEASE_SCHEMA||p.execution_authorized!==false||
  p.deployment_authorized!==false||!UUID.test(p.owner_user_id)||
  !UUID.test(p.request_id)||!UUID.test(p.reviewer_identity_id)||
  p.owner_user_id===p.reviewer_identity_id||!H64.test(p.reviewer_key_hex)||
  !H64.test(p.intent_sha256)||!H64.test(p.request_sha256)||
  !H64.test(p.owner_signature_sha256)||!H64.test(p.reviewer_signature_sha256)||
  !H40.test(p.source_commit)||!H64.test(p.policy_digest)||
  !H64.test(p.command_digest)||!H32.test(p.nonce)||!iso(p.issued_at)||
  !iso(p.expires_at)||typeof p.intent_key!=='string'||p.intent_key.length>180||
  !p.intent_key.startsWith('batcave.general_control.')||
  !['Oracle','Cortana'].includes(p.device)||
  !['host.read','host.write_reversible','browser.observe','browser.click','browser.type'].includes(p.capability)||
  typeof p.target_session_id!=='string'||p.target_session_id.length<8||
  typeof p.rollback_ref!=='string'||p.rollback_ref.length>100)
  throw Error('INVALID_EXACT_PRIVILEGED_RELEASE_PAYLOAD');
 return RELEASE_DOMAIN+JSON.stringify(Object.fromEntries(FIELDS.map(k=>[k,p[k]])));
}
function validReviewer(session,reg,now){
 return session?.reviewer_authenticated===true&&
  session.protected_reviewer_session_verified===true&&
  session.independent_identity_verified===true&&UUID.test(session.reviewer_identity_id)||
  false;
}
function trustedReviewer(session,reg,now){
 return validReviewer(session,reg,now)&&reg?.identity_id===session.reviewer_identity_id&&
  reg.independently_attested===true&&reg.production_release_authorized===true&&
  reg.key_scope==='general_control_privileged_reviewer_v1'&&
  reg.key_state==='active'&&reg.revoked_at===null&&
  H64.test(reg.key_hex)&&H64.test(reg.host_identity_sha256)&&
  reg.host_identity_sha256===session.host_identity_sha256&&
  iso(reg.valid_until)&&Date.parse(reg.valid_until)>now;
}
const binding=r=>Object.fromEntries(['owner_user_id','device','target_origin',
 'target_session_id','command_digest','source_commit','policy_digest'].map(k=>[k,r[k]]));
async function inspection(requestId,session,services,now){
 if(!UUID.test(requestId))throw Error('INVALID_REVIEW_REQUEST');
 const [evidence,reg,intent,policy]=await Promise.all([
  services.getCompleteSignedEvidence(requestId),
  services.getReviewerRegistration(session.reviewer_identity_id),
  services.getHeldReleaseIntent(requestId),
  services.getCurrentPolicy(requestId)
 ]);
 if(!trustedReviewer(session,reg,now))throw Error('INDEPENDENT_ATTESTATION_REQUIRED');
 const req=evidence?.request;
 if(!req||req.request_id!==requestId||req.owner_user_id===reg.identity_id||
  evidence.owner_signature_state!=='owner_signature_recorded_only'||
  evidence.reviewer_signature_state!=='reviewer_signature_recorded_only'||
  !H128.test(evidence.owner_signature_hex)||!H128.test(evidence.reviewer_signature_hex))
  throw Error('TWO_DURABLE_SIGNATURE_RECEIPTS_REQUIRED');
 if(!policy||policy.current!==true||policy.capability_allowed!==true||
  policy.source_commit!==req.source_commit||policy.digest!==req.policy_digest||
  policy.device!==req.device||policy.capability!==req.capability||
  policy.target_session_id!==req.target_session_id||
  policy.target_origin!==req.target_origin)
  throw Error('FRESH_POLICY_AND_TARGET_REQUIRED');
 const result=validateGeneralControlOwnerRequestV1(req,binding(req),now);
 if(!H40.test(req.source_commit)||!H64.test(req.policy_digest)||
  intent?.intent_key!=='batcave.general_control.pr3.owner_release_request.20261122'||
  intent.state!=='held'||!H64.test(intent.content_sha256)||
  intent.requested_scope?.source_commit!==req.source_commit||
  intent.requested_scope?.policy_digest!==req.policy_digest||
  intent.requested_scope?.device!==req.device||
  intent.requested_scope?.capability!==req.capability||
  intent.requested_scope?.target_session_id!==req.target_session_id||
  intent.requested_scope?.target_origin!==req.target_origin||
  intent.requested_scope?.command_digest!==req.command_digest||
  !iso(intent.valid_until)||Date.parse(intent.valid_until)<=now)
  throw Error('EXACT_CURRENT_HELD_INTENT_REQUIRED');
 return {request:req,reg,intent,ownerSignatureHash:digest(Buffer.from(evidence.owner_signature_hex,'hex')),
  reviewerSignatureHash:digest(Buffer.from(evidence.reviewer_signature_hex,'hex')),
  requestHash:digest(result.signing_message)};
}
export async function handlePrivilegedReleaseReviewSTAGED(body,session,services,now=Date.now()){
 if(!validReviewer(session)||!Number.isSafeInteger(now))
  return denied('PROTECTED_INDEPENDENT_REVIEWER_REQUIRED');
 if(!services||['getCompleteSignedEvidence','getReviewerRegistration','getHeldReleaseIntent',
   'getCurrentPolicy'].some(k=>typeof services[k]!=='function')||
  !services.repository||
  ['reserve','getPrepared','recordSignature'].some(k=>typeof services.repository[k]!=='function'))
  return denied('PRIVATE_TRUST_RESOLVERS_REQUIRED');
 if(body?.action===ACTION_PREPARE){
  if(!exact(body,['action','request_id'])||!UUID.test(body.request_id))
   return denied('INVALID_PREPARE');
  try{
   const x=await inspection(body.request_id,session,services,now);
   const r=x.request;
   const p={schema:RELEASE_SCHEMA,owner_user_id:r.owner_user_id,
    request_id:r.request_id,reviewer_identity_id:x.reg.identity_id,
    reviewer_key_hex:x.reg.key_hex,intent_key:x.intent.intent_key,
    intent_sha256:x.intent.content_sha256,request_sha256:x.requestHash,
    owner_signature_sha256:x.ownerSignatureHash,
    reviewer_signature_sha256:x.reviewerSignatureHash,
    source_commit:r.source_commit,policy_digest:r.policy_digest,
    device:r.device,capability:r.capability,target_origin:r.target_origin,
    target_session_id:r.target_session_id,command_digest:r.command_digest,
    rollback_ref:r.rollback_ref,nonce:randomBytes(16).toString('hex'),
    issued_at:new Date(now).toISOString(),expires_at:new Date(now+180000).toISOString(),
    execution_authorized:false,deployment_authorized:false};
   const msg=releaseSigningTextSTAGED(p);
   const stored=await services.repository.reserve(p,digest(msg));
   if(stored?.reserved!==true||stored.request_id!==r.request_id||
    stored.nonce!==p.nonce||stored.status!=='unused')
    return denied('PRIVATE_CHALLENGE_NOT_RESERVED');
   return Object.freeze({status:'AWAIT_EXPLICIT_INDEPENDENT_REVIEWER_SIGNATURE',
    challenge:p,signing_text:msg,execution_authorized:false,deployment_authorized:false,
    grant_issued:false});
  }catch{return denied('NOT_ELIGIBLE_FOR_PRIVILEGED_RELEASE');}
 }
 if(body?.action===ACTION_RECORD){
  if(!exact(body,['action','request_id','nonce','signature_hex'])||
   !UUID.test(body.request_id)||!H32.test(body.nonce)||!H128.test(body.signature_hex))
   return denied('INVALID_EVIDENCE');
  try{
   const stored=await services.repository.getPrepared(body.request_id,body.nonce);
   if(stored?.status!=='unused'||!stored.payload)throw Error('NO_FRESH_CHALLENGE');
   const p=stored.payload;
   const msg=releaseSigningTextSTAGED(p);
   if(stored.signing_sha256!==digest(msg)||
    p.request_id!==body.request_id||p.nonce!==body.nonce||
    Date.parse(p.issued_at)>now+30000||Date.parse(p.issued_at)<now-300000||
    Date.parse(p.expires_at)<=now||
    Date.parse(p.expires_at)-Date.parse(p.issued_at)>180000)
    throw Error('STALE_OR_REWRITTEN_CHALLENGE');
   const x=await inspection(p.request_id,session,services,now);
   if(p.reviewer_identity_id!==session.reviewer_identity_id||
    p.reviewer_key_hex!==x.reg.key_hex||p.owner_user_id!==x.request.owner_user_id||
    p.source_commit!==x.request.source_commit||
    p.policy_digest!==x.request.policy_digest||
    p.intent_sha256!==x.intent.content_sha256||
    p.request_sha256!==x.requestHash||
    p.owner_signature_sha256!==x.ownerSignatureHash||
    p.reviewer_signature_sha256!==x.reviewerSignatureHash)
    throw Error('REVIEW_TARGET_CHANGED');
   const pub=createPublicKey({key:Buffer.from(PREFIX+x.reg.key_hex,'hex'),format:'der',type:'spki'});
   if(!verify(null,Buffer.from(msg),pub,Buffer.from(body.signature_hex,'hex')))
    throw Error('INVALID_PRIVILEGED_SIGNATURE');
   const receipt=await services.repository.recordSignature({
    request_id:p.request_id,nonce:p.nonce,reviewer_identity_id:p.reviewer_identity_id,
    reviewer_key_hex:p.reviewer_key_hex,source_commit:p.source_commit,
    policy_digest:p.policy_digest,intent_sha256:p.intent_sha256,
    request_sha256:p.request_sha256,signature_hex:body.signature_hex,
    signing_sha256:stored.signing_sha256
   });
   if(receipt?.recorded!==true||receipt.request_id!==p.request_id||
    receipt.status!=='privileged_release_signature_recorded_only')
    throw Error('NO_DURABLE_SIGNATURE_RECEIPT');
   return Object.freeze({status:'PRIVILEGED_RELEASE_SIGNATURE_RECORDED_ONLY',
    request_id:p.request_id,privileged_signature_recorded:true,
    deployment_authorized:false,execution_authorized:false,grant_issued:false});
  }catch{return denied('PRIVILEGED_RELEASE_SIGNATURE_NOT_RECORDED');}
 }
 return denied('UNSUPPORTED_REVIEW_ACTION');
}
