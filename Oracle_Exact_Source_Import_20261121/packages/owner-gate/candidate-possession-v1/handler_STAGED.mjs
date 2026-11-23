/* STAGED SOURCE ONLY: owner-scoped, nonauthorizing challenge envelope.
 * NOT a deploy grant, key registry, custody attestation, or release signer.
 * Session is supplied ONLY by trusted server auth, never JSON from the caller.
 */
import {issuePossessionChallengeSTAGED,recordPossessionProofSTAGED}
 from '../src/general_control_reviewer_possession_STAGED.mjs';
export const OWNER_ID='ff189123-b5c3-4ee0-9267-06d4f20fb44f';
export const DRAFT_ID='50920aad-09e6-4895-aea1-a29410edd435';
const no=(reason)=>Object.freeze({status:'DENY',reason,registered:false,
 independently_attested:false,production_release_authorized:false,
 execution_authorized:false,deployment_authorized:false,grant_issued:false});
const exact=(o,keys)=>o&&typeof o==='object'&&!Array.isArray(o)&&
 Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
export async function handleCandidatePossessionOnlySTAGED(body,owner,services,now=Date.now()){
 if(owner?.authenticated_owner!==true||owner?.owner_user_id!==OWNER_ID)
  return no('OWNER_SESSION_REQUIRED');
 if(!services?.repository||typeof services.getPrivateCandidate!=='function')
  return no('PRIVATE_DATABASE_REQUIRED');
 if(exact(body,['op','draft_id'])&&body.op==='issue'&&body.draft_id===DRAFT_ID){
  const result=await issuePossessionChallengeSTAGED(
   {draft_id:DRAFT_ID},owner,services,now);
  return Object.freeze({registered:false,independently_attested:false,
   production_release_authorized:false,execution_authorized:false,
   deployment_authorized:false,grant_issued:false,...result});
 }
 if(exact(body,['op','proof'])&&body.op==='record'){
  const p=body.proof;
  if(!p||typeof p!=='object'||Array.isArray(p)||
   typeof p.request_id!=='string'||typeof p.nonce!=='string')
    return no('INVALID_PROOF');
  try {
   // Strong owner binding: user may not submit a proof for an unrelated draft.
   const stored=await services.repository.getPrepared(p.request_id,p.nonce);
   if(stored?.payload?.draft_id!==DRAFT_ID||
      stored?.payload?.owner_user_id!==OWNER_ID)
    return no('WRONG_OR_UNISSUED_CHALLENGE');
   const result=await recordPossessionProofSTAGED(p,services,now);
   return Object.freeze({registered:false,independently_attested:false,
    production_release_authorized:false,execution_authorized:false,
    deployment_authorized:false,grant_issued:false,...result});
  }catch{return no('PROOF_UNAVAILABLE');}
 }
 return no('UNSUPPORTED_OR_UNSCOPED_ACTION');
}
