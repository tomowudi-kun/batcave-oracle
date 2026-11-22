/* Public evidence transport only; the existing authenticated enrollment gate stays separate. */
import {verifyFirstPair,firstStable,firstHash} from '../release-evidence-v1/first_reviewer_protocol.mjs';
export const FLAGS=Object.freeze({reviewer_registered:false,independently_attested:false,deployment_authorized:false,execution_authorized:false,grant_issued:false});
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const proofKeys='challenge_id|deployment_authorized|execution_authorized|grant_issued|independently_attested|nonce|policy_sha256|proof_signature_b64url|reviewer_public_key_sha256|schema';
const exact=(x,k)=>x&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).sort().join('|')===k;
const must=(x,e)=>{if(!x)throw Error(e);};
export function activeContext(ctx,now){
 must(ctx?.root&&ctx.challenge&&ctx.owner&&ctx.intent,'PROOF_CONTEXT_REQUIRED');
 const {root:r,challenge:c,owner:o,intent:i}=ctx,p=r.policy;
 must(r.registered_at===null&&r.revoked_at===null&&r.owner_declined_at===null&&ctx.existing_reviewers===0,'PROOF_CONTEXT_CLOSED');
 must(c.kind==='first_key'&&c.consumed_at===null&&c.withdrawn_at===null&&typeof c.pending_owner_signature_b64url==='string'&&Date.parse(c.expires_at)>now,'PROOF_CHALLENGE_NOT_CURRENT');
 must(o.revoked_at===null&&o.owner_user_id===p.owner_user_id&&o.public_key_sha256===p.owner_key_sha256&&c.owner_user_id===o.owner_user_id&&c.owner_key_sha256===o.public_key_sha256&&c.reviewer_key_sha256===p.reviewer_key_sha256&&c.policy_sha256===r.policy_sha256,'PROOF_KEY_BINDING');
 must(i.state==='held'&&i.content_sha256===p.release_intent_sha256&&Date.parse(i.valid_until)>now,'PROOF_HELD_INTENT_REQUIRED');
 return ctx;
}
function proofEnvelope(proof){
 must(exact(proof,proofKeys)&&proof.schema==='batcave.nanny.first_key.possession.v1'&&UUID.test(proof.challenge_id),'PROOF_BAD_SHAPE');
 for(const k of ['independently_attested','deployment_authorized','execution_authorized','grant_issued'])must(proof[k]===false,'PROOF_AUTHORITY_DENIED');
}
async function proofIdentity(proof,ctx){
 must(ctx?.root&&ctx.challenge&&ctx.owner,'PROOF_CONTEXT_REQUIRED');
 const {root,challenge:c}=ctx;
 must(c.kind==='first_key'&&c.payload_sha256===await firstHash(firstStable(c.payload)),'PROOF_CHALLENGE_BINDING');
 must(proof.challenge_id===c.id&&proof.nonce===c.payload.nonce&&proof.policy_sha256===root.policy_sha256&&proof.reviewer_public_key_sha256===root.policy.reviewer_key_sha256,'PROOF_BINDING');
}
export async function validatePublicProof(proof,ctx,now=Date.now()){
 proofEnvelope(proof);activeContext(ctx,now);await proofIdentity(proof,ctx);
 const {root,challenge:c,owner}=ctx;
 await verifyFirstPair({payload:c.payload,record:root,owner,owner_signature_b64url:c.pending_owner_signature_b64url,proof_signature_b64url:proof.proof_signature_b64url,now});
 return await firstHash(firstStable(proof));
}
function failure(e,report=()=>{},operation='',stage=''){
 const name=/^[A-Z][A-Z0-9_]{2,80}$/.test(e?.message||'')?e.message:'PROOF_UNAVAILABLE';
 const sqlstate=/^[A-Z0-9]{5}$/.test(e?.code||'')?e.code:undefined;
 try{report({event:'public_proof_rejected',operation,stage,error:name,...(sqlstate?{sqlstate}:{})});}catch{}
 return {status:name==='UNAUTHORIZED'?401:name==='PROOF_UNAVAILABLE'?503:403,body:{...FLAGS,error:name}};
}
export async function submitPublicProof(body,repo,now=Date.now(),report){
 let stage='request';
 try{
  must(exact(body,'op|proof')&&body.op==='submit'&&UUID.test(body.proof?.challenge_id),'PROOF_BAD_REQUEST');
  stage='context';const ctx=await repo.context(body.proof.challenge_id);
  stage='signatures';const hash=await validatePublicProof(body.proof,ctx,now);
  // The private ledger rechecks revocation, No, expiry and scope under row locks.
  stage='ledger';
  const stored=await repo.store(ctx.challenge.id,ctx.challenge.payload_sha256,body.proof,hash);
  must(stored?.stored===true,'PROOF_NOT_STORED');
  return {status:200,body:{...FLAGS,proof_received:true,challenge_id:ctx.challenge.id}};
 }catch(e){return failure(e,report,'submit',stage);}
}
// Read-only artifact diagnosis. The reference time comes only from the saved,
// signed challenge. This never stores evidence or makes expired consent current.
export async function inspectPublicProof(body,repo,report){
 let stage='request';
 try{
  must(exact(body,'op|proof')&&body.op==='inspect','PROOF_BAD_REQUEST');proofEnvelope(body.proof);
  stage='context';const ctx=await repo.context(body.proof.challenge_id);
  await proofIdentity(body.proof,ctx);const {root,challenge:c,owner}=ctx;
  stage='historical_signatures';
  const reference=Date.parse(c.payload.issued_at)+1;
  must(Number.isFinite(reference),'PROOF_CHALLENGE_BINDING');
  await verifyFirstPair({payload:c.payload,record:root,owner,owner_signature_b64url:c.pending_owner_signature_b64url,proof_signature_b64url:body.proof.proof_signature_b64url,now:reference});
  return {status:200,body:{...FLAGS,diagnostic_only:true,historical_signatures_match:true,proof_received:false}};
 }catch(e){return failure(e,report,'inspect',stage);}
}
export async function ownerProofStatus(body,owner,repo,now=Date.now(),report){
 try{
  must(owner?.authenticated===true&&UUID.test(owner.id),'UNAUTHORIZED');
  must(exact(body,'challenge_id|op')&&body.op==='status'&&UUID.test(body.challenge_id),'PROOF_BAD_REQUEST');
  const ctx=await repo.context(body.challenge_id);
  must(ctx?.owner?.owner_user_id===owner.id,'UNAUTHORIZED');
  activeContext(ctx,now);
  const proof=await repo.proof(body.challenge_id);
  if(proof)await validatePublicProof(proof,ctx,now);
  return {status:200,body:{...FLAGS,proof:proof||null,challenge_id:body.challenge_id}};
 }catch(e){return failure(e,report,'status','owner_status');}
}
