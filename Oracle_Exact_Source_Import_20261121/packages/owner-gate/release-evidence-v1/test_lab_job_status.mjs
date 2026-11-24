import test from 'node:test';
import assert from 'node:assert/strict';
import {readLabJobStatus} from '../src/lab_job_status.mjs';
import {REVIEWER_KEY,FIXTURE_TOKEN,RELEASE_SHA} from '../src/verify_owner_enrollment_v2.mjs';
import {parseTrialReference,parseTrialRequest,buildLabRequestCommand,labStatusMessage,mountLabTrialHandoff} from './lab_trial_handoff.mjs';
const now=Date.parse('2026-11-22T14:00:00Z');
const owner='123e4567-e89b-42d3-a456-426614174000', id='123e4567-e89b-42d3-a456-426614174001',nonce='a'.repeat(32);
const ctx={owner_user_id:owner,owner_authenticated:true};
const body={action:'oracle_lab_job_status_v1',job_id:id,nonce};
const ref={schema:'batcave.nanny.lab.request.v1',request_id:id,device:'Oracle',operation:'oracle_model_fixture_v1',scope:'disposable_lab_only',artifact_sha256:FIXTURE_TOKEN,nonce,created_at:'2026-11-22T06:42:30Z',expires_at:'2026-11-22T06:52:30Z'};
function fixture(){return {id,owner_user_id:owner,grant_nonce:nonce,device_name:'Oracle',action:'oracle_model_generate_v1',payload:{schema:'batcave.oracle.job.v1',nonce,operation:'model_generate_and_verify_v1',fixture:'fixed_clamp_score_v1',artifact_sha256:FIXTURE_TOKEN},grant_artifact_sha256:FIXTURE_TOKEN,reviewer_key_sha256:REVIEWER_KEY,release_archive_sha256:RELEASE_SHA,scope:'disposable_lab_only',status:'succeeded',attempt_count:1,consumed_at:'2026-11-22T06:50:28Z',completed_at:'2026-11-22T06:50:44Z',expires_at:ref.expires_at,receipt_matches:true,receipt_outcome:'succeeded',result:{schema:'batcave.linux.receipt.v1',job_id:id,operation:'model_generate_and_verify_v1',target:'BatcaveUbuntu',outcome:'success',receipt_hmac_sha256:'private internal receipt evidence',result:{tests_passed:true,tests_run:8,model:'qwen2.5-coder:1.5b',artifact_sha256:'e'.repeat(64),artifact_bytes:111}}};}
function repo(j=fixture()){return {getModelJobStatus:async(job,who)=>{assert.equal(job,id);assert.equal(who,owner);return j;},insertVerifiedGrant:()=>{throw Error('Status must never write a grant');}};}
const status=async j=>(await readLabJobStatus(body,ctx,repo(j),now)).body;

test('historical expired request displays verified success without renewed consent',async()=>{
 const s=await status(fixture());assert.equal(s.state,'succeeded');assert.equal(s.completion_verified,true);
 assert.equal(labStatusMessage(s,ref),'Oracle completed this trial. All eight tests passed; the matching result receipt is recorded.');
 const raw=JSON.stringify(ref);assert.deepEqual(parseTrialReference(raw,now),ref);
 assert.throws(()=>parseTrialRequest(raw,now),/expired/);assert.throws(()=>buildLabRequestCommand(raw,now),/expired/);
 assert.doesNotMatch(JSON.stringify(s),/private internal|receipt_hmac|public_key|signed_receipt|payload/);
});
test('authentication is required before the repository is read',async()=>{
 const r={getModelJobStatus:()=>{throw Error('Unauthorized repository read');}};
 for(const c of [null,{...ctx,owner_authenticated:false},{...ctx,owner_user_id:'invalid'}])assert.equal((await readLabJobStatus(body,c,r,now)).status,401);
});
test('extra fields and malformed identifiers are refused',async()=>{
 for(const b of [{...body,command:'shell'},{...body,job_id:'invalid'},{...body,nonce:'bad'},{}])assert.equal((await readLabJobStatus(b,ctx,repo(),now)).status,422);
});
test('missing grant, wrong owner, nonce, device or fixed scope reveal no task',async()=>{
 assert.equal((await readLabJobStatus(body,ctx,repo(null),now)).status,404);
 for(const patch of [{owner_user_id:'other'},{grant_nonce:'b'.repeat(32)},{device_name:'Cortana'},{scope:'computer_control'},{reviewer_key_sha256:'b'.repeat(64)},{release_archive_sha256:'b'.repeat(64)},{grant_artifact_sha256:'b'.repeat(64)}])assert.equal((await readLabJobStatus(body,ctx,repo({...fixture(),...patch}),now)).status,404);
 const j=fixture();j.payload.nonce='b'.repeat(32);assert.equal((await readLabJobStatus(body,ctx,repo(j),now)).status,404);
});
test('a succeeded command alone is not verified completion',async()=>{
 for(const patch of [{receipt_matches:false},{receipt_outcome:'started'},{consumed_at:null},{attempt_count:2},{completed_at:null}]){
  const s=await status({...fixture(),...patch});assert.equal(s.state,'needs_attention');assert.equal(s.completion_verified,false);
 }
});
test('malformed or mismatched completion evidence stays unverified',async()=>{
 for(const patch of [{schema:'wrong'},{job_id:'other'},{operation:'shell'},{target:'other'},{outcome:'failure'}]){
  const j=fixture();Object.assign(j.result,patch);assert.equal((await status(j)).state,'needs_attention');
 }
 for(const patch of [{tests_passed:false},{tests_run:7},{model:'other'},{artifact_sha256:'bad'},{artifact_bytes:0}]){
  const j=fixture();Object.assign(j.result.result,patch);assert.equal((await status(j)).state,'needs_attention');
 }
});
test('pending, running, expired and ambiguous execution are distinguished',async()=>{
 const base=fixture();base.result=null;base.receipt_matches=false;base.receipt_outcome=null;
 assert.equal((await status({...base,status:'pending',attempt_count:0,expires_at:'2026-11-22T14:05:00Z'})).state,'queued');
 assert.equal((await status({...base,status:'leased',expires_at:'2026-11-22T14:05:00Z'})).state,'running');
 assert.equal((await status({...base,status:'pending'})).state,'expired');
 assert.equal((await status({...base,status:'leased'})).state,'needs_attention');
 assert.equal((await status({...base,status:'pending',expires_at:'bad'})).state,'needs_attention');
});
test('failure requires its own matching terminal receipt',async()=>{
 assert.equal((await status({...fixture(),status:'failed',receipt_outcome:'failed'})).state,'failed');
 assert.equal((await status({...fixture(),status:'failed',receipt_matches:false})).state,'needs_attention');
});
test('UI refuses wrong task, nonce and authority and does not equate queued with done',async()=>{
 const s=await status(fixture());
 for(const patch of [{job_id:'other'},{nonce:'b'.repeat(32)},{read_only:false},{execution_authorized:true},{deployment_authorized:true}])assert.throws(()=>labStatusMessage({...s,...patch},ref),/not verified/);
 assert.match(labStatusMessage({...s,state:'queued',completion_verified:false},ref),/not started/);
 assert.match(labStatusMessage({...s,state:'running',completion_verified:false},ref),/running/);
 assert.match(labStatusMessage({...s,completion_verified:false},ref),/Needs attention/);
});
test('mounted historical page reads saved status, disables replay and stops polling on success',async()=>{
 const original={document:globalThis.document,location:globalThis.location,window:globalThis.window,setInterval:globalThis.setInterval,clearInterval:globalThis.clearInterval};
 const nodes=new Map(['copy','note','file','receipt','send','refresh','result'].map(k=>['[data-'+k+']',{disabled:false,textContent:'',value:''}]));
 const root={isConnected:true,querySelector:s=>nodes.get(s)};let reads=0,cleared=0;
 try{
  globalThis.document={createElement:()=>root,visibilityState:'visible'};
  globalThis.location={search:'?model_trial_v1='+Buffer.from(JSON.stringify(ref)).toString('base64url')};
  globalThis.window={addEventListener:()=>{}};globalThis.setInterval=()=>123;globalThis.clearInterval=id=>{assert.equal(id,123);cleared++;};
  mountLabTrialHandoff({parent:{prepend:r=>assert.equal(r,root)},getOwnerId:()=>owner,api:async b=>{reads++;assert.deepEqual(b,body);return (await readLabJobStatus(b,ctx,repo(),now)).body;}});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(reads,1);assert.equal(nodes.get('[data-copy]').disabled,true);assert.equal(nodes.get('[data-send]').disabled,true);
  assert.match(nodes.get('[data-result]').textContent,/All eight tests passed/);assert.equal(cleared,1);
 }finally{for(const[k,v]of Object.entries(original)){if(v===undefined)delete globalThis[k];else globalThis[k]=v;}}
});
