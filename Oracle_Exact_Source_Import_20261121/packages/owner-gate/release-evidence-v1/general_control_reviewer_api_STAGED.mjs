/* STAGED, NOT DEPLOYED: authenticated independent reviewer evidence route.
 * This route is NOT served from the owner phone origin. The caller must first
 * prove possession of a separate protected reviewer identity via independently
 * verified server middleware. Same-account user JWT is NEVER enough.
 * Trusted registration/policy/target are resolved entirely on the server.
 * Recording reviewer evidence is NOT a signed general-control release,
 * an active key registration, a task lease or permission to deploy.
 */
import {reviewGeneralControlEvidenceSTAGED as verifyAndRecord}
 from './general_control_reviewer_admission_STAGED.mjs';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const H64=/^[a-f0-9]{64}$/;
const H128=/^[a-f0-9]{128}$/;
const ACTION='general_control_independent_reviewer_record_v1';
const deny=(code,status=403)=>Object.freeze({status,body:{
 error:'GENERAL_CONTROL_REVIEWER_'+code,
 execution_authorized:false,deployment_authorized:false,grant_issued:false
}});
const exact=(x,k)=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 Object.keys(x).length===k.length&&k.every(name=>Object.hasOwn(x,name));
const needs=['getReviewerRegistration','getCurrentPolicy','getTrustedBinding'];
export async function handleIndependentGeneralControlReviewerSTAGED(
 body,session,services,now=Date.now()){
 if(!session||session.reviewer_authenticated!==true||
    session.protected_reviewer_session_verified!==true||
    session.independent_identity_verified!==true||
    typeof session.reviewer_identity_id!=='string'||
    !UUID.test(session.reviewer_identity_id)||
    !H64.test(session.host_identity_sha256)||
    !Number.isSafeInteger(now))
   return deny('PROTECTED_REVIEWER_AUTH_REQUIRED',401);
 if(!exact(body,['action','request_id','signature_hex'])||
    body.action!==ACTION ||!UUID.test(body.request_id)||
    !H128.test(body.signature_hex))
   return deny('INVALID_EXACT_EVIDENCE',422);
 if(!services||needs.some(n=>typeof services[n]!=='function')||
    !services.repository || typeof services.repository.getPreparedReview!=='function'||
    typeof services.repository.appendReviewerEvidence!=='function')
   return deny('PRIVATE_TRUST_SERVICES_REQUIRED',503);
 try {
  const pending=await services.repository.getPreparedReview(body.request_id);
  if(!pending||pending.owner_evidence_state!=='owner_signature_recorded_only'||
     pending.nonce_state!=='consumed_owner_evidence'||
     pending.reviewer_evidence_state!=='unused')
   return deny('NO_ELIGIBLE_OWNER_RECEIPT',409);
  const ownerId=pending.request?.owner_user_id;
  if(!UUID.test(ownerId)||ownerId===session.reviewer_identity_id)
   return deny('INDEPENDENT_IDENTITY_REQUIRED',403);
  const reg=await services.getReviewerRegistration(session.reviewer_identity_id);
  if(!reg||reg.identity_id!==session.reviewer_identity_id||
     reg.independently_attested!==true||reg.production_release_authorized!==true||
     reg.key_state!=='active'||reg.key_scope!=='general_control_privileged_reviewer_v1'||
     reg.revoked_at!==null ||!H64.test(reg.key_hex)||
     reg.host_identity_sha256!==session.host_identity_sha256||
     !Number.isFinite(Date.parse(reg.valid_until))||Date.parse(reg.valid_until)<=now)
   return deny('QUALIFIED_REVIEWER_NOT_REGISTERED');
  const policy=await services.getCurrentPolicy(body.request_id);
  const binding=await services.getTrustedBinding(body.request_id);
  if(!policy||policy.current!==true ||policy.capability_allowed!==true||
     policy.digest!==pending.request.policy_digest||
     policy.source_commit!==pending.request.source_commit)
   return deny('CURRENT_POLICY_REQUIRED',409);
  const result=await verifyAndRecord({
    request_id:body.request_id,signature_hex:body.signature_hex,
  },{
    reviewer_authenticated:true,reviewer_identity_id:session.reviewer_identity_id,
    owner_identity_id:ownerId,
    reviewer_registration:{
      identity_id:reg.identity_id,independently_attested:reg.independently_attested,
      key_state:reg.key_state,key_scope:reg.key_scope,key_hex:reg.key_hex,
    },
    trusted_binding:binding,current_policy:policy,
  },services.repository,now);
  if(result?.status!=='REVIEWER_EVIDENCE_RECORDED_ONLY'||
     result.request_id!==body.request_id ||
     result.execution_authorized!==false||result.deployment_authorized!==false)
   return deny('REVIEWER_EVIDENCE_NOT_ACCEPTED',409);
  return Object.freeze({status:200,body:{
    schema:'batcave.general_control.reviewer_evidence_receipt.v1',
    request_id:body.request_id,state:'reviewer_signature_recorded_only',
    qualified_reviewer_evidence_recorded:true,
    privileged_release_signature_recorded:false,
    execution_authorized:false,deployment_authorized:false,grant_issued:false,
  }});
 } catch {return deny('REVIEWER_RECORD_NOT_CONFIRMED',409);}
}
