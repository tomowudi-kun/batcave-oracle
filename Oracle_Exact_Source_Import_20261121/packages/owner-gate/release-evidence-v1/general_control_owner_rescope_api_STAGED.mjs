/* STAGED / NOT DEPLOYED: owner root -> general-control scope endorsement.
 * Root and source/policy context MUST come from independently authenticated,
 * private server records, not browser parameters. The current legacy owner
 * key signs only a pending scope endorsement; nothing is activated here.
 */
import {
 RESCOPE_SCHEMA, RESCOPE_SIGNATURE_SCHEMA,
 validateOwnerRescopeChallengeSTAGED,recordOwnerRescopePendingSTAGED,
} from './general_control_owner_rescope_STAGED.mjs';
const ORIGINAL_ORIGIN='https://batcave-linux-approval.vercel.app';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA=/^[0-9a-f]{64}$/;
const COMMIT=/^[0-9a-f]{40}$/;
const HEX32=/^[0-9a-f]{32}$/;
const ACTIONS={
 prepare:'general_control_root_rescope_prepare_v1',
 endorse:'general_control_root_rescope_endorse_v1',
 decline:'general_control_root_rescope_decline_v1',
};
const exact=(x,keys)=>!!x&&typeof x==='object'&&!Array.isArray(x)&&
 Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const deny=(code,status=403)=>({status,body:{error:'RESCOPE_'+code,
 execution_authorized:false,deployment_authorized:false}});
const h=b=>Array.from(b,c=>c.toString(16).padStart(2,'0')).join('');
async function hashHex(b){return h(new Uint8Array(await crypto.subtle.digest('SHA-256',b)));}
function decode(s){
 if(typeof s!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(s))throw Error('INVALID_ROOT');
 const bytes=Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='),c=>c.charCodeAt(0));
 if(bytes.length!==32)throw Error('INVALID_ROOT');return bytes;
}
function ownerOK(ctx){
 return ctx?.owner_authenticated===true&&ctx.origin===ORIGINAL_ORIGIN&&
   typeof ctx.owner_user_id==='string'&&UUID.test(ctx.owner_user_id);
}
function required(repo,methods){
 return methods.every(name=>typeof repo?.[name]==='function');
}
export async function handleGeneralControlRootRescopeSTAGED(body,ctx,repo,now=Date.now()){
 if(!ownerOK(ctx))return deny('AUTHENTICATED_OWNER_OR_ORIGIN_REQUIRED',401);
 if(!body||typeof body!=='object'||Array.isArray(body)||
   typeof body.action!=='string'||!Number.isSafeInteger(now))return deny('BAD_REQUEST',422);
 const owner=ctx.owner_user_id;
 if(!required(repo,['getRoot','getTrustedScopePolicy']))return deny('PRIVATE_RESOLVERS_REQUIRED',503);
 const action=body.action;
 if(action===ACTIONS.prepare){
  if(!exact(body,['action']))return deny('BAD_PREPARE',422);
  if(!required(repo,['reserve']))return deny('PRIVATE_RESERVATION_REQUIRED',503);
  try{
   const [root,policy]=await Promise.all([repo.getRoot(owner),repo.getTrustedScopePolicy(owner)]);
   if(root?.owner_user_id!==owner||root.revoked_at!==null||
     !SHA.test(root.public_key_sha256)||!COMMIT.test(policy?.source_commit)||
     !SHA.test(policy?.policy_digest)||policy?.current!==true)
    return deny('TRUSTED_OWNER_AND_POLICY_REQUIRED',403);
   const pub=decode(root.public_key_b64url);
   if(await hashHex(pub)!==root.public_key_sha256)return deny('OWNER_ROOT_MISMATCH');
   const challenge={
    schema:RESCOPE_SCHEMA,owner_user_id:owner,
    challenge_id:crypto.randomUUID(),nonce:h(crypto.getRandomValues(new Uint8Array(16))),
    root_key_sha256:root.public_key_sha256,scope_public_key_hex:h(pub),
    source_commit:policy.source_commit,policy_digest:policy.policy_digest,
    issued_at:new Date(now).toISOString(),expires_at:new Date(now+180000).toISOString(),
    execution_authorized:false,deployment_authorized:false,
   };
   await validateOwnerRescopeChallengeSTAGED(challenge,{
    owner_user_id:owner,authenticated:true,origin:ORIGINAL_ORIGIN,root,
    source_commit:policy.source_commit,policy_digest:policy.policy_digest,
   },now);
   const result=await repo.reserve(challenge);
   if(result?.reserved!==true||result.challenge_id!==challenge.challenge_id||
      result.nonce!==challenge.nonce||result.state!=='unused')
    return deny('ONE_TIME_CHALLENGE_NOT_RESERVED',409);
   return {status:200,body:{schema:'batcave.general_control.owner_rescope_prepared.v1',
    challenge,root:{owner_user_id:root.owner_user_id,
      public_key_sha256:root.public_key_sha256,public_key_b64url:root.public_key_b64url,
      revoked_at:null},
    policy:{source_commit:policy.source_commit,policy_digest:policy.policy_digest},
    state:'AWAIT_EXPLICIT_OWNER_CLICK',execution_authorized:false,
    deployment_authorized:false}};
  }catch{return deny('PREPARE_FAILED',409);}
 }
 if(action===ACTIONS.endorse){
  if(!exact(body,['action','evidence'])||
    !exact(body.evidence,['schema','owner_user_id','challenge_id','nonce','signature_hex',
     'execution_authorized','deployment_authorized'])||
    body.evidence.schema!==RESCOPE_SIGNATURE_SCHEMA||
    body.evidence.owner_user_id!==owner||
    body.evidence.execution_authorized!==false||
    body.evidence.deployment_authorized!==false)
    return deny('BAD_OWNER_ENDORSEMENT',422);
  if(!required(repo,['getPrepared','recordPending']))return deny('PRIVATE_EVIDENCE_REPOSITORY_REQUIRED',503);
  try{
   const [root,policy]=await Promise.all([repo.getRoot(owner),repo.getTrustedScopePolicy(owner)]);
   if(policy?.current!==true||!COMMIT.test(policy.source_commit)||!SHA.test(policy.policy_digest))
    return deny('TRUSTED_SCOPE_NOT_CURRENT',403);
   const result=await recordOwnerRescopePendingSTAGED(body.evidence,{
    owner_user_id:owner,authenticated:true,origin:ORIGINAL_ORIGIN,root,
    source_commit:policy.source_commit,policy_digest:policy.policy_digest,
   },repo,now);
   if(result.status!=='OWNER_SCOPE_ENDORSED_PENDING_INDEPENDENT')return deny('ENDORSEMENT_NOT_RECORDED',409);
   return {status:200,body:{
    schema:'batcave.general_control.owner_rescope_pending_receipt.v1',
    challenge_id:result.challenge_id,owner_user_id:owner,
    state:'pending_independent_review',owner_signature_recorded:true,
    independent_signature_recorded:false,execution_authorized:false,
    deployment_authorized:false,grant_issued:false,
   }};
  }catch{return deny('ENDORSEMENT_NOT_CONFIRMED',409);}
 }
 if(action===ACTIONS.decline){
  if(!exact(body,['action','challenge_id','nonce'])||
    !UUID.test(body.challenge_id)||!HEX32.test(body.nonce))
    return deny('BAD_DECLINE',422);
  if(!required(repo,['getPrepared','decline']))return deny('PRIVATE_DECLINE_REPOSITORY_REQUIRED',503);
  try{
   const saved=await repo.getPrepared(owner,body.challenge_id);
   if(saved?.state!=='unused'||saved.challenge?.owner_user_id!==owner||
      saved.challenge.challenge_id!==body.challenge_id||
      saved.challenge.nonce!==body.nonce)return deny('STALE_OR_UNKNOWN',409);
   const declined=await repo.decline({owner_user_id:owner,
    challenge_id:body.challenge_id,nonce:body.nonce});
   if(declined?.declined!==true||declined.challenge_id!==body.challenge_id)
    return deny('DECLINE_NOT_RECORDED',409);
   return {status:200,body:{
    schema:'batcave.general_control.owner_rescope_declined.v1',
    challenge_id:body.challenge_id,owner_user_id:owner,state:'declined',
    execution_authorized:false,deployment_authorized:false,grant_issued:false,
   }};
  }catch{return deny('DECLINE_NOT_CONFIRMED',409);}
 }
 return deny('UNSUPPORTED_ACTION',400);
}
