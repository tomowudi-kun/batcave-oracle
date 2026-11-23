import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {handlePrivilegedReleaseReviewSTAGED as handle,RELEASE_DOMAIN,
 releaseSigningTextSTAGED} from './general_control_privileged_release_STAGED.mjs';
const now=Date.parse('2026-11-23T02:27:00.000Z');
const owner='123e4567-e89b-42d3-a456-426614174000';
const reviewer='123e4567-e89b-42d3-a456-426614174009';
const pair=generateKeyPairSync('ed25519');
const keyHex=pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');
const request={schema:'batcave.general_control.owner_request.v1',
 owner_user_id:owner,request_id:'123e4567-e89b-42d3-a456-426614174001',
 device:'Oracle',capability:'host.read',target_origin:null,
 target_session_id:'oracle-session-1',command_digest:'a'.repeat(64),
 source_commit:'b'.repeat(40),policy_digest:'c'.repeat(64),
 nonce:'d'.repeat(32),issued_at:'2026-11-23T02:26:00.000Z',
 expires_at:'2026-11-23T02:30:00.000Z',rollback_ref:'none'};
const intent={intent_key:'batcave.general_control.pr3.owner_release_request.20261122',
 state:'held',content_sha256:'e'.repeat(64),
 valid_until:'2026-11-29T17:01:31.870Z',
 requested_scope:Object.fromEntries(
  ['source_commit','policy_digest','device','capability','target_session_id',
  'target_origin','command_digest'].map(k=>[k,request[k]]))};
const reg={identity_id:reviewer,independently_attested:true,
 production_release_authorized:true,key_scope:'general_control_privileged_reviewer_v1',
 key_state:'active',revoked_at:null,key_hex:keyHex,
 host_identity_sha256:'f'.repeat(64),
 valid_until:'2026-12-01T00:00:00.000Z'};
const session={reviewer_authenticated:true,
 protected_reviewer_session_verified:true,independent_identity_verified:true,
 reviewer_identity_id:reviewer,host_identity_sha256:reg.host_identity_sha256};
const policy={current:true,capability_allowed:true,digest:request.policy_digest,
 source_commit:request.source_commit,device:request.device,
 capability:request.capability,target_origin:request.target_origin,
 target_session_id:request.target_session_id};
function fixture(){
 const state={prepared:null,recorded:0,registration:{...reg},intent:{...intent},
 policy:{...policy},
 evidence:{request,owner_signature_state:'owner_signature_recorded_only',
 reviewer_signature_state:'reviewer_signature_recorded_only',
 owner_signature_hex:'1'.repeat(128),reviewer_signature_hex:'2'.repeat(128)}};
 const repository={
  reserve:async(p,hash)=>{if(state.prepared)return {reserved:false};
   state.prepared={payload:p,signing_sha256:hash,status:'unused'};
   return {reserved:true,request_id:p.request_id,nonce:p.nonce,status:'unused'};},
  getPrepared:async(id,nonce)=>state.prepared?.payload.request_id===id&&
   state.prepared.payload.nonce===nonce?state.prepared:null,
  recordSignature:async row=>{
   if(state.prepared?.status!=='unused'||row.nonce!==state.prepared.payload.nonce)
     return {recorded:false};
   state.prepared.status='recorded';state.recorded++;
   return {recorded:true,request_id:row.request_id,
    status:'privileged_release_signature_recorded_only'};},
 };
 const services={repository,
  getCompleteSignedEvidence:async()=>state.evidence,
  getReviewerRegistration:async()=>state.registration,
  getHeldReleaseIntent:async()=>state.intent,
  getCurrentPolicy:async()=>state.policy};
 return {state,services};
}
const prepare={action:'general_control_privileged_release_prepare_v1',
 request_id:request.request_id};
async function challenge(f){
 const x=await handle(prepare,session,f.services,now);
 assert.equal(x.status,'AWAIT_EXPLICIT_INDEPENDENT_REVIEWER_SIGNATURE',JSON.stringify(x));
 return x;
}
const reviewerSign=x=>sign(null,Buffer.from(x.signing_text),pair.privateKey).toString('hex');
const finish=(x,sig=reviewerSign(x))=>({
 action:'general_control_privileged_release_record_v1',
 request_id:request.request_id,nonce:x.challenge.nonce,signature_hex:sig});
test('separate reviewer signature challenge binds exact current held intent and prior receipts',async()=>{
 const f=fixture(),x=await challenge(f);
 assert.equal(x.challenge.source_commit,request.source_commit);
 assert.equal(x.challenge.intent_sha256,intent.content_sha256);
 assert.equal(x.challenge.owner_signature_sha256.length,64);
 assert.equal(x.challenge.reviewer_signature_sha256.length,64);
 assert.equal(x.challenge.request_sha256.length,64);
 assert.equal(x.signing_text.startsWith(RELEASE_DOMAIN),true);
 assert.equal(x.signing_text,releaseSigningTextSTAGED(x.challenge));
 assert.equal(x.execution_authorized,false);
 assert.equal(x.deployment_authorized,false);
 assert.equal(x.grant_issued,false);
 assert.equal(f.state.recorded,0);
});
test('qualified third signature records only non-authorizing release-review receipt',async()=>{
 const f=fixture(),x=await challenge(f);
 const result=await handle(finish(x),session,f.services,now);
 assert.equal(result.status,'PRIVILEGED_RELEASE_SIGNATURE_RECORDED_ONLY',JSON.stringify(result));
 assert.equal(result.privileged_signature_recorded,true);
 assert.equal(result.execution_authorized,false);
 assert.equal(result.deployment_authorized,false);
 assert.equal(result.grant_issued,false);
 assert.equal(f.state.recorded,1);
 assert.equal((await handle(finish(x),session,f.services,now)).status,'DENY');
 assert.equal(f.state.recorded,1);
});
test('old fixed reviewer, revoked key or absent separate protected identity cannot prepare',async()=>{
 for(const change of [{key_scope:'first_reviewer_enrollment_only'},
  {independently_attested:false},
  {production_release_authorized:false},
  {revoked_at:'2026-11-21T00:00:00.000Z'},
  {key_state:'pending'},
  {host_identity_sha256:'0'.repeat(64)},
  {identity_id:owner},
  {valid_until:'2026-11-22T00:00:00.000Z'}]){
  const f=fixture();f.state.registration={...reg,...change};
  assert.equal((await handle(prepare,session,f.services,now)).status,'DENY');
 }
 for(const s of [{...session,reviewer_authenticated:false},
  {...session,protected_reviewer_session_verified:false},
  {...session,independent_identity_verified:false}]){
  assert.equal((await handle(prepare,s,fixture().services,now)).status,'DENY');
 }
});
test('old release intent pinned to different source fails before challenge',async()=>{
 for(const change of [{state:'released'},
  {requested_scope:{...intent.requested_scope,source_commit:'0'.repeat(40)}},
  {requested_scope:{...intent.requested_scope,command_digest:'0'.repeat(64)}},
  {valid_until:'2026-11-22T00:00:00.000Z'},
  {content_sha256:'invalid'}]){
  const f=fixture();f.state.intent={...intent,...change};
  assert.equal((await handle(prepare,session,f.services,now)).status,'DENY');
  assert.equal(f.state.prepared,null);
 }
});
test('owner or reviewer signature missing and changed source/session/policy all reject',async()=>{
 for(const change of [{owner_signature_state:'not_signed'},
   {reviewer_signature_hex:'bad'},
   {reviewer_signature_state:'pending'}]){
  const f=fixture();f.state.evidence={...f.state.evidence,...change};
  assert.equal((await handle(prepare,session,f.services,now)).status,'DENY');
 }
 for(const change of [{current:false},{digest:'f'.repeat(64)},
  {target_session_id:'different-session'}]){
  const f=fixture();f.state.policy={...policy,...change};
  assert.equal((await handle(prepare,session,f.services,now)).status,'DENY');
 }
});
test('forged signature, changed reviewer key and stale policy before record fail closed',async()=>{
 const f=fixture(),x=await challenge(f);
 assert.equal((await handle(finish(x,'0'.repeat(128)),session,f.services,now)).status,'DENY');
 f.state.registration={...reg,key_hex:'0'.repeat(64)};
 assert.equal((await handle(finish(x),session,f.services,now)).status,'DENY');
 f.state.registration={...reg};f.state.policy={...policy,source_commit:'a'.repeat(40)};
 assert.equal((await handle(finish(x),session,f.services,now)).status,'DENY');
 assert.equal(f.state.recorded,0);
});
test('expiry, client authority flags, changed nonce and missing repository fail closed',async()=>{
 const f=fixture(),x=await challenge(f);
 assert.equal((await handle(finish(x),session,f.services,now+5*60000)).status,'DENY');
 assert.equal((await handle({...finish(x),grant:true},session,f.services,now)).status,'DENY');
 assert.equal((await handle({...finish(x),nonce:'f'.repeat(32)},session,f.services,now)).status,'DENY');
 f.services.repository.recordSignature=null;
 assert.equal((await handle(finish(x),session,f.services,now)).status,'DENY');
});
test('reusing previous owner/reviewer evidence signature is not a third release signature',async()=>{
 const f=fixture(),x=await challenge(f);
 assert.equal((await handle(finish(x,f.state.evidence.reviewer_signature_hex),session,f.services,now)).status,'DENY');
 assert.equal((await handle(finish(x,f.state.evidence.owner_signature_hex),session,f.services,now)).status,'DENY');
});
