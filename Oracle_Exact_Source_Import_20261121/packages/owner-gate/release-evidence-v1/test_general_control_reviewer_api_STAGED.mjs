import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign as edSign} from 'node:crypto';
import {validateGeneralControlOwnerRequestV1 as validate}
 from '../src/general_control_owner_request_v1.mjs';
import {handleIndependentGeneralControlReviewerSTAGED as handle}
 from './general_control_reviewer_api_STAGED.mjs';
const now=Date.parse('2026-11-23T01:44:00.000Z');
const owner='123e4567-e89b-42d3-a456-426614174000';
const reviewer='123e4567-e89b-42d3-a456-426614174009';
const host='e'.repeat(64);
const pair=generateKeyPairSync('ed25519');
const pub=pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');
const request={
 schema:'batcave.general_control.owner_request.v1',owner_user_id:owner,
 request_id:'123e4567-e89b-42d3-a456-426614174001',
 device:'Oracle',capability:'host.read',target_origin:null,
 target_session_id:'oracle-session-1',command_digest:'a'.repeat(64),
 source_commit:'b'.repeat(40),policy_digest:'c'.repeat(64),
 nonce:'d'.repeat(32),
 issued_at:'2026-11-23T01:43:00.000Z',
 expires_at:'2026-11-23T01:46:00.000Z',
 rollback_ref:'none'
};
const binding=Object.fromEntries(['owner_user_id','device','target_origin',
 'target_session_id','command_digest','source_commit','policy_digest']
 .map(x=>[x,request[x]]));
const message=validate(request,binding,now).signing_message;
const signature=edSign(null,Buffer.from('BATCAVE_NANNY_GENERAL_CONTROL_V1\n'+message),
 pair.privateKey).toString('hex');
const session={reviewer_authenticated:true,protected_reviewer_session_verified:true,
 independent_identity_verified:true,reviewer_identity_id:reviewer,host_identity_sha256:host};
const registration={identity_id:reviewer,key_hex:pub,independently_attested:true,
 production_release_authorized:true,key_state:'active',
 key_scope:'general_control_privileged_reviewer_v1',
 host_identity_sha256:host,revoked_at:null,valid_until:'2026-12-01T00:00:00.000Z'};
const policy={current:true,capability_allowed:true,digest:request.policy_digest,
 source_commit:request.source_commit};
const body={action:'general_control_independent_reviewer_record_v1',
 request_id:request.request_id,signature_hex:signature};
function fixture(){
 const state={written:0,receipt:null,registration:{...registration},policy:{...policy},
 binding:{...binding},prepared:{request,owner_evidence_state:'owner_signature_recorded_only',
 nonce_state:'consumed_owner_evidence',reviewer_evidence_state:'unused'}};
 const repository={
  getPreparedReview:async()=>state.prepared,
  appendReviewerEvidence:async row=>{
   if(state.receipt||row.request_id!==request.request_id)return {inserted:false};
   state.receipt=row;state.written++;
   return {inserted:true,request_id:row.request_id,state:'reviewer_signature_recorded_only'};
  },
 };
 const services={repository,getReviewerRegistration:async()=>state.registration,
  getCurrentPolicy:async()=>state.policy,getTrustedBinding:async()=>state.binding};
 return {state,services};
}
test('qualified independently attested reviewer records exact signature, never releases',async()=>{
 const f=fixture(),out=await handle(body,session,f.services,now);
 assert.equal(out.status,200,JSON.stringify(out));
 assert.equal(out.body.state,'reviewer_signature_recorded_only');
 assert.equal(out.body.privileged_release_signature_recorded,false);
 assert.equal(out.body.execution_authorized,false);
 assert.equal(out.body.deployment_authorized,false);
 assert.equal(f.state.written,1);
 assert.equal(f.state.receipt.reviewer_identity_id,reviewer);
 assert.equal(f.state.receipt.reviewer_key_hex,pub);
 assert.equal((await handle(body,session,f.services,now)).status,409);
});
test('owner login alone or unverified protected session never enters reviewer path',async()=>{
 const f=fixture();
 for(const s of [{...session,reviewer_authenticated:false},
  {...session,protected_reviewer_session_verified:false},
  {...session,independent_identity_verified:false},
  {...session,reviewer_identity_id:owner},
  {...session,host_identity_sha256:'not-a-hash'}]){
  assert.notEqual((await handle(body,s,f.services,now)).status,200);
 }
 assert.equal(f.state.written,0);
});
test('lab-only key, expired, revoked, or non-independent registration cannot sign',async()=>{
 for(const changed of [
  {key_scope:'lab_reviewer_only'},
  {production_release_authorized:false},
  {independently_attested:false},
  {key_state:'pending'},
  {revoked_at:'2026-11-22T00:00:00.000Z'},
  {host_identity_sha256:'f'.repeat(64)},
  {identity_id:owner},
  {valid_until:'2026-11-22T00:00:00.000Z'},
 ]) {
  const f=fixture();f.state.registration={...registration,...changed};
  const r=await handle(body,session,f.services,now);
  assert.notEqual(r.status,200,JSON.stringify({changed,r}));
  assert.equal(f.state.written,0);
 }
});
test('forged Ed25519 signature and extra action fields are rejected',async()=>{
 const f=fixture();
 assert.notEqual((await handle({...body,signature_hex:'0'.repeat(128)},session,f.services,now)).status,200);
 assert.equal((await handle({...body,grant:true},session,f.services,now)).status,422);
 assert.equal((await handle({...body,action:'general_control_release_v1'},session,f.services,now)).status,422);
 assert.equal(f.state.written,0);
});
test('changed server policy or browser/host session prevents durable evidence',async()=>{
 const f=fixture();
 f.state.policy={...policy,digest:'f'.repeat(64)};
 assert.equal((await handle(body,session,f.services,now)).status,409);
 f.state.policy={...policy};f.state.binding={...binding,target_session_id:'new-session-9'};
 assert.notEqual((await handle(body,session,f.services,now)).status,200);
 assert.equal(f.state.written,0);
});
test('missing owner evidence, duplicate reviewer, or different owner identity refuses',async()=>{
 for(const prepared of [
  {...fixture().state.prepared,owner_evidence_state:'missing'},
  {...fixture().state.prepared,nonce_state:'unused'},
  {...fixture().state.prepared,reviewer_evidence_state:'reviewer_signature_recorded_only'},
  {...fixture().state.prepared,request:{...request,owner_user_id:reviewer}}
 ]) {
  const f=fixture();f.state.prepared=prepared;
  assert.notEqual((await handle(body,session,f.services,now)).status,200);
  assert.equal(f.state.written,0);
 }
});
test('repository and trust failures deny without false success',async()=>{
 const f=fixture();f.services.repository.appendReviewerEvidence=async()=>{throw Error('DB offline')};
 assert.notEqual((await handle(body,session,f.services,now)).status,200);
 f.services.getReviewerRegistration=null;
 assert.equal((await handle(body,session,f.services,now)).status,503);
 assert.equal(f.state.written,0);
});
test('challenge expiration prevents delayed reviewer signature',async()=>{
 const f=fixture();
 assert.notEqual((await handle(body,session,f.services,now+5*60000)).status,200);
 assert.equal(f.state.written,0);
});
