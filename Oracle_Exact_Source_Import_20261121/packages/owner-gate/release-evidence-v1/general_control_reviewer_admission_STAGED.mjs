/* STAGED: independent reviewer evidence admission, NOT a release gate.
 * All context callbacks must be backed by authenticated server records.
 * No grant, key enrollment, deployment, or command dispatch is possible here.
 */
import {createPublicKey,verify} from 'node:crypto';
import {validateGeneralControlOwnerRequestV1} from '../src/general_control_owner_request_v1.mjs';
const HEX64=/^[0-9a-f]{64}$/,HEX128=/^[0-9a-f]{128}$/;
const PREFIX='302a300506032b6570032100';
const DOMAIN='BATCAVE_NANNY_GENERAL_CONTROL_V1\n';
const exact=(x,k)=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
  Object.keys(x).length===k.length&&k.every(y=>Object.hasOwn(x,y));
const deny=(reason)=>Object.freeze({status:'DENY',reason,execution_authorized:false,deployment_authorized:false});
export async function reviewGeneralControlEvidenceSTAGED(input,context,repository,now=Date.now()){
  if(!exact(input,['request_id','signature_hex']))return deny('BAD_EVIDENCE_SHAPE');
  if(!exact(context,['reviewer_authenticated','reviewer_identity_id','owner_identity_id','reviewer_registration','trusted_binding','current_policy'])||
    context.reviewer_authenticated!==true)return deny('REVIEWER_AUTH_REQUIRED');
  if(!repository||typeof repository.getPreparedReview!=='function'||
    typeof repository.appendReviewerEvidence!=='function')return deny('PRIVATE_REPOSITORY_REQUIRED');
  const reg=context.reviewer_registration;
  if(!reg||reg.independently_attested!==true||reg.key_state!=='active'||
    reg.key_scope!=='general_control_privileged_reviewer_v1'||
    reg.identity_id!==context.reviewer_identity_id||
    reg.identity_id===context.owner_identity_id||
    !HEX64.test(reg.key_hex)||!HEX128.test(input.signature_hex))return deny('INDEPENDENT_REVIEWER_REQUIRED');
  try{
    const saved=await repository.getPreparedReview(input.request_id);
    if(!saved||saved.owner_evidence_state!=='owner_signature_recorded_only'||
      saved.reviewer_evidence_state!=='unused'||saved.request?.request_id!==input.request_id||
      saved.nonce_state!=='consumed_owner_evidence')return deny('NO_REVIEWABLE_OWNER_EVIDENCE');
    const req=saved.request,policy=context.current_policy;
    if(!policy||policy.current!==true||policy.capability_allowed!==true||
      policy.digest!==req.policy_digest||policy.source_commit!==req.source_commit)return deny('POLICY_CHANGED');
    const candidate=validateGeneralControlOwnerRequestV1(req,context.trusted_binding,now);
    const pub=createPublicKey({key:Buffer.from(PREFIX+reg.key_hex,'hex'),format:'der',type:'spki'});
    if(!verify(null,Buffer.from(DOMAIN+candidate.signing_message),pub,Buffer.from(input.signature_hex,'hex')))
      return deny('INVALID_REVIEWER_SIGNATURE');
    // Repository must atomically check all request/policy/identity/nonce values
    // and append once, with a unique reviewer-evidence receipt.
    const receipt=await repository.appendReviewerEvidence({
      request_id:req.request_id,nonce:req.nonce,owner_user_id:req.owner_user_id,
      policy_digest:req.policy_digest,source_commit:req.source_commit,
      reviewer_identity_id:reg.identity_id,reviewer_key_hex:reg.key_hex,
      signature_hex:input.signature_hex,
    });
    if(!receipt||receipt.inserted!==true||receipt.request_id!==req.request_id||
      receipt.state!=='reviewer_signature_recorded_only')return deny('REVIEWER_EVIDENCE_NOT_CONFIRMED');
    return Object.freeze({status:'REVIEWER_EVIDENCE_RECORDED_ONLY',
      request_id:req.request_id,execution_authorized:false,deployment_authorized:false});
  }catch{return deny('REVIEWER_EVIDENCE_NOT_CONFIRMED');}
}
