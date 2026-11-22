/* Public signed review transport; final recording still requires owner JWT.
 * No signer enrollment, grant writer, dispatcher or release-hold mutation. */
import {FIRST_BASIS,FIRST_VERSION,firstStable,firstHash,firstISO} from '../release-evidence-v1/first_reviewer_protocol.mjs';
import {verifyReleaseEvidence,PIN} from '../release-evidence-v1/verify_release_approval_v1.mjs';
const FLAGS=Object.freeze({deployment_authorized:false,execution_authorized:false,grant_issued:false});
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const KEYS='deployment_authorized|execution_authorized|expires_at|intent_key|local_file_hashes|nonce|reviewed_at|reviewer_host_identity|reviewer_public_key_sha256|schema|signature_b64url|status';
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join('|')===keys;
const must=(v,s)=>{if(!v)throw Error(s);};
export async function validateReleaseReview(review,ctx,now=Date.now()){
 must(exact(review,KEYS)&&review.schema==='batcave.nanny.local.review.evidence.v1'&&review.status==='NOT_ENROLLED_BY_THIS_COMMAND'&&review.deployment_authorized===false&&review.execution_authorized===false,'REVIEW_BAD_SHAPE');
 const {root:r,challenge:c,owner:o,intent:i}=ctx||{},p=r?.policy;
 must(r&&c&&o&&i&&r.registered_at!==null&&r.revoked_at===null&&r.owner_declined_at===null,'REVIEW_CONTEXT_CLOSED');
 must(c.kind==='release'&&c.consumed_at===null&&c.withdrawn_at===null&&typeof c.pending_owner_signature_b64url==='string'&&(!r.last_owner_declined_at||Date.parse(c.issued_at)>Date.parse(r.last_owner_declined_at)),'REVIEW_CHALLENGE_NOT_CURRENT');
 must(c.payload_sha256===await firstHash(firstStable(c.payload))&&c.policy_sha256===r.policy_sha256&&c.owner_user_id===p.owner_user_id&&c.owner_key_sha256===p.owner_key_sha256&&c.reviewer_key_sha256===p.reviewer_key_sha256&&o.owner_user_id===p.owner_user_id&&o.public_key_sha256===p.owner_key_sha256,'REVIEW_BINDING');
 must(i.state==='held'&&i.content_sha256===p.release_intent_sha256&&Date.parse(i.valid_until)>now,'REVIEW_HELD_INTENT_REQUIRED');
 must(review.intent_key===PIN.intent_key&&review.nonce===c.payload.nonce&&review.expires_at===c.payload.expires_at&&review.reviewer_public_key_sha256===p.reviewer_key_sha256,'REVIEW_BINDING');
 must(exact(review.local_file_hashes,'gate_sha256|source_commit|worker_sha256')&&review.local_file_hashes.gate_sha256===PIN.owner_gate_zip_sha256&&review.local_file_hashes.worker_sha256===PIN.worker_zip_sha256&&review.local_file_hashes.source_commit===PIN.pr_head_sha,'REVIEW_ARTIFACTS_CHANGED');
 must(exact(review.reviewer_host_identity,'host|os|user')&&await firstHash(firstStable(review.reviewer_host_identity))===p.host_identity_sha256,'REVIEW_HOST_CHANGED');
 must(firstISO(review.reviewed_at)&&Date.parse(review.reviewed_at)>=Date.parse(c.payload.issued_at)&&Date.parse(review.reviewed_at)<Date.parse(c.payload.expires_at)&&Date.parse(review.reviewed_at)<=now+30000,'REVIEW_TIME_INVALID');
 const owner={...o,role:'owner',registered:true,valid_until:null};
 const reviewer={role:'independent_release_reviewer',owner_user_id:p.owner_user_id,registered:true,public_key_sha256:p.reviewer_key_sha256,public_key_b64url:p.reviewer_public_key_b64url,valid_until:p.signer_valid_until,revoked_at:r.revoked_at,independently_attested:false,release_policy_version:FIRST_VERSION,trust_basis:FIRST_BASIS,private_key_custodian:'Cortana separate protected reviewer',owner_bootstrap_record:r};
 await verifyReleaseEvidence({payload:c.payload,owner_signature_b64url:c.pending_owner_signature_b64url,nanny_signature_b64url:review.signature_b64url,authenticated_owner_id:p.owner_user_id,trusted_owner_key:owner,trusted_nanny_key:reviewer,nonce_issued_by_gate:true,nonce_consumed:false,now});
 return firstHash(firstStable(review));
}
export async function submitReleaseReview(body,repo,now=Date.now(),report=()=>{}){
 let stage='request';
 try{
  must(exact(body,'challenge_id|op|review')&&body.op==='submit_release'&&UUID.test(body.challenge_id),'REVIEW_BAD_REQUEST');
  stage='context';const ctx=await repo.context(body.challenge_id);
  stage='signatures';const h=await validateReleaseReview(body.review,ctx,now);
  stage='ledger';const saved=await repo.storeReview(ctx.challenge.id,ctx.challenge.payload_sha256,body.review,h);
  must(saved?.stored===true,'REVIEW_NOT_STORED');
  return {status:200,body:{...FLAGS,review_received:true,challenge_id:ctx.challenge.id}};
 }catch(e){
  const error=/^[A-Z][A-Z0-9_]{2,80}$/.test(e?.message||'')?e.message:'REVIEW_UNAVAILABLE';
  const sqlstate=/^[A-Z0-9]{5}$/.test(e?.code||'')?e.code:undefined;
  try{report({event:'release_review_rejected',stage,error,...(sqlstate?{sqlstate}:{})});}catch{}
  return {status:error==='REVIEW_UNAVAILABLE'?503:403,body:{...FLAGS,error}};
 }
}
