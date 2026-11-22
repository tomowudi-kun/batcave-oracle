/* Synthetic test keys and in-memory ledger only. Never imported by production. */
import {generateKeyPairSync,sign,createHash,randomUUID} from 'node:crypto';
import {firstStable,FIRST_BASIS,FIRST_VERSION,FIRST_OWNER_DOMAIN,FIRST_PROOF_DOMAIN} from './first_reviewer_protocol.mjs';
import {PIN,SCHEMA,NANNY_DOMAIN,canonicalReleaseText} from './verify_release_approval_v1.mjs';
import {handleReleaseGate} from './release_gate_core.mjs';
export const NOW=Date.parse('2026-11-22T05:00:00.000Z');
export const iso=t=>new Date(t).toISOString(),digest=x=>createHash('sha256').update(typeof x==='string'?x:firstStable(x)).digest('hex');
const pair=()=>{const p=generateKeyPairSync('ed25519'),raw=p.publicKey.export({format:'der',type:'spki'}).subarray(-32);return {...p,public_key_b64url:raw.toString('base64url'),public_key_sha256:createHash('sha256').update(raw).digest('hex')};};
export const sig=(k,s)=>sign(null,Buffer.from(s),k.privateKey).toString('base64url');
export async function fixture(){
 const ownerKey=pair(),reviewerKey=pair(),id=randomUUID(),challenges=new Map();
 const owner={owner_user_id:id,public_key_b64url:ownerKey.public_key_b64url,public_key_sha256:ownerKey.public_key_sha256,revoked_at:null,role:'owner',registered:true,valid_until:null};
 const host={host:'Cortana',os:'win32',user:'SyntheticReviewer'};
 const policy={schema:'batcave.oracle.owner_first_reviewer.policy.v1',scope:'first_reviewer_enrollment_only',trust_basis:FIRST_BASIS,owner_user_id:id,owner_key_sha256:owner.public_key_sha256,reviewer_key_sha256:reviewerKey.public_key_sha256,reviewer_public_key_b64url:reviewerKey.public_key_b64url,candidate_sha256:'a'.repeat(64),host_identity_sha256:digest(host),custody_evidence_sha256:'b'.repeat(64),reviewer_sid:'S-1-5-21-101-202-303-1001',release_intent_key:PIN.intent_key,release_intent_sha256:PIN.intent_sha256,signer_valid_until:iso(NOW+86400000)};
 const root={policy,policy_sha256:digest(policy),registered_at:iso(NOW-30000),revoked_at:null,owner_declined_at:null,last_owner_declined_at:null};
 const firstPayload=Object.fromEntries(['scope','trust_basis','owner_user_id','owner_key_sha256','reviewer_key_sha256','candidate_sha256','host_identity_sha256','reviewer_sid','custody_evidence_sha256','signer_valid_until'].map(k=>[k,policy[k]]));
 Object.assign(firstPayload,{schema:'batcave.oracle.first_reviewer.enrollment.v1',policy_sha256:root.policy_sha256,nonce:'f'.repeat(32),issued_at:iso(NOW-60000),expires_at:iso(NOW+540000)});
 const registration={id:randomUUID(),kind:'first_key',owner_user_id:id,owner_key_sha256:owner.public_key_sha256,reviewer_key_sha256:reviewerKey.public_key_sha256,policy_sha256:root.policy_sha256,payload:firstPayload,payload_sha256:digest(firstPayload),nonce:firstPayload.nonce,issued_at:firstPayload.issued_at,expires_at:firstPayload.expires_at,consumed_at:root.registered_at,recorded_at:root.registered_at,owner_signature_b64url:sig(ownerKey,FIRST_OWNER_DOMAIN+firstStable(firstPayload)),reviewer_signature_b64url:sig(reviewerKey,FIRST_PROOF_DOMAIN+firstStable(firstPayload))};
 Object.assign(root,{registration_challenge_id:registration.id,registration_challenge:registration});
 const state={root,owner,intent:{state:'held',content_sha256:PIN.intent_sha256,valid_until:iso(NOW+86400000),requested_scope:{scope:PIN.scope,fixture:PIN.fixture,target_device:PIN.target_device,target_operation:PIN.operation,owner_gate_portal_release_zip_sha256:PIN.owner_gate_zip_sha256,oracle_model_worker_release_zip_sha256:PIN.worker_zip_sha256,no_general_shell:true,no_production_permissions:true}},reviews:new Map(),writes:0,evidence:0};
 const reviewer=()=>({role:'independent_release_reviewer',owner_user_id:id,registered:true,independently_attested:false,release_policy_version:FIRST_VERSION,trust_basis:FIRST_BASIS,public_key_b64url:reviewerKey.public_key_b64url,public_key_sha256:reviewerKey.public_key_sha256,valid_until:policy.signer_valid_until,revoked_at:root.revoked_at,private_key_custodian:'Cortana separate protected reviewer',owner_bootstrap_record:structuredClone(root)});
 const current=c=>c&&!c.consumed_at&&!c.withdrawn_at&&!root.owner_declined_at&&!root.revoked_at&&(!root.last_owner_declined_at||Date.parse(c.issued_at)>Date.parse(root.last_owner_declined_at));
 const repo={
  getOwner:async()=>structuredClone(owner),getIntent:async()=>structuredClone(state.intent),getFirstPolicy:async()=>structuredClone(root),getReviewer:async()=>reviewer(),
  issueChallenge:async a=>{const c={...a,id:randomUUID(),consumed_at:null,recorded_at:null,withdrawn_at:null,pending_owner_signature_b64url:null};challenges.set(c.id,c);return structuredClone(c);},
  getChallenge:async(o,c)=>structuredClone(challenges.get(c)),getFirstChallenge:async(o,c)=>structuredClone(challenges.get(c)),
  getLatestFirstRelease:async()=>structuredClone([...challenges.values()].at(-1)),
  saveReleaseEndorsementVerified:async a=>{const c=challenges.get(a.challenge.id);if(!c||c.withdrawn_at||(root.last_owner_declined_at&&Date.parse(c.issued_at)<=Date.parse(root.last_owner_declined_at)))return {saved:false};c.pending_owner_signature_b64url=a.owner_signature_b64url;root.owner_declined_at=null;return {saved:true};},
  declineRelease:async()=>{root.owner_declined_at=iso(NOW);root.last_owner_declined_at=iso(NOW);for(const c of challenges.values())if(!c.consumed_at)c.withdrawn_at=iso(NOW);return {declined:true};},
  getReleaseReview:async(o,c)=>structuredClone(state.reviews.get(c)||null),
  recordEvidence:async a=>{const c=challenges.get(a.challenge.id);if(!current(c))return {inserted:false};c.consumed_at=iso(NOW+1);c.recorded_at=c.consumed_at;c.owner_signature_b64url=a.owner_signature_b64url;c.reviewer_signature_b64url=a.nanny_signature_b64url;state.evidence++;return {inserted:true,evidence_id:c.id};},
  context:async c=>({root:structuredClone(root),owner:structuredClone(owner),intent:structuredClone(state.intent),challenge:structuredClone(challenges.get(c))}),
  storeReview:async(c,h,r,rh)=>{state.writes++;const ch=challenges.get(c);if(!current(ch)||ch.payload_sha256!==h)return {stored:false};const old=state.reviews.get(c);if(old&&digest(old)!==rh)return {stored:false};state.reviews.set(c,structuredClone(r));return {stored:true};}
 };
 const call=(b,t=NOW,ctx={owner_authenticated:true,owner_user_id:id})=>handleReleaseGate(b,ctx,repo,t);
 async function endorsed(){const r=await call({action:'oracle_release_challenge_v1',reviewer_public_key_sha256:reviewerKey.public_key_sha256});if(r.status!==200)throw Error(JSON.stringify(r));const ch=r.body;const owner_signature_b64url=sig(ownerKey,ch.signing_message);const saved=await call({action:'oracle_release_endorse_v1',challenge_id:ch.challenge_id,owner_signature_b64url});if(saved.status!==200)throw Error(JSON.stringify(saved));return {schema:'batcave.oracle.gate.release.challenge.v1',issuer:'batcave-control',challenge_id:ch.challenge_id,payload:ch.payload,owner_signature_b64url};}
 const review=e=>({schema:'batcave.nanny.local.review.evidence.v1',status:'NOT_ENROLLED_BY_THIS_COMMAND',intent_key:PIN.intent_key,nonce:e.payload.nonce,expires_at:e.payload.expires_at,reviewer_public_key_sha256:reviewerKey.public_key_sha256,signature_b64url:sig(reviewerKey,NANNY_DOMAIN+canonicalReleaseText(e.payload)),reviewer_host_identity:host,local_file_hashes:{gate_sha256:PIN.owner_gate_zip_sha256,worker_sha256:PIN.worker_zip_sha256,source_commit:PIN.pr_head_sha},reviewed_at:iso(NOW),deployment_authorized:false,execution_authorized:false});
 return {state,root,owner,ownerKey,reviewerKey,id,repo,call,challenges,endorsed,review,now:NOW};
}
