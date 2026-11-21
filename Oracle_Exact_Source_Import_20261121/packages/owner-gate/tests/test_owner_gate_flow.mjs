import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname,join} from 'node:path';
import {handleOracleLabOwnerRequest} from '../src/owner_gate_core.mjs';
import {canonicalEnrollmentMessage,RELEASE_SHA,FIXTURE_TOKEN} from '../src/verify_owner_enrollment_v2.mjs';
const data=JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)),'cortana_public_record.json'),'utf8'));
const ownerId='123e4567-e89b-42d3-a456-426614174000';
const now=Date.parse('2026-11-21T03:00:00.000Z');
const pair=generateKeyPairSync('ed25519');
const rawPub=pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64url');
const ownerKey={owner_user_id:ownerId,public_key_b64url:rawPub,revoked_at:null};
const jobId=randomUUID(),nonce='a'.repeat(32);
function sampleJob(){return {id:jobId,device_name:'Oracle',action:'oracle_model_generate_v1',status:'pending',attempt_count:0,
 created_at:new Date(now-1000).toISOString(),expires_at:new Date(now+4*60000).toISOString(),
 payload:{schema:'batcave.oracle.job.v1',nonce,operation:'model_generate_and_verify_v1',fixture:'fixed_clamp_score_v1',artifact_sha256:FIXTURE_TOKEN}};}
function repo(){
 const state={challenge:null,enrolled:false,job:sampleJob(),inserted:false,calls:[],grant:null};
 return {state,
  async getOwnerKey(){return ownerKey},
  async issueEnrollmentChallenge(x){state.challenge={...x,challenge_id:randomUUID(),consumed_at:null};return {...state.challenge,expires_at:state.challenge.expires_at.replace('Z','+00:00')}},
  async getChallenge(){return state.challenge},
  async enrollVerifiedReviewer(x){state.calls.push('enroll');if(state.enrolled)return {inserted:false};state.enrolled=true;state.challenge.consumed_at=new Date(now).toISOString();return {inserted:true}},
  async getEnrolledReviewer(){return state.enrolled?{owner_user_id:ownerId,public_record:data,role:'lab_reviewer_only',release_archive_sha256:RELEASE_SHA,revoked_at:null}:null},
  async getModelJob(){return state.job},
  async insertVerifiedGrant(x){state.calls.push('grant');if(state.inserted)return {inserted:false};state.inserted=true;state.grant=x;return {inserted:true}}
 };
}
const ctx={owner_user_id:ownerId,owner_authenticated:true};
async function challenge(r){return handleOracleLabOwnerRequest({action:'oracle_lab_enroll_challenge_v2'},ctx,r,now);}
async function validEnrollment(r){
 const c=await challenge(r);
 const signature_b64url=sign(null,Buffer.from(c.body.signing_message),pair.privateKey).toString('base64url');
 return {action:'oracle_lab_enroll_reviewer_v2',challenge_id:c.body.challenge_id,request:c.body.request,public_record:data,signature_b64url};
}
const mockCheck=async()=>({review_valid:true,production_deployment_authorized:false,expires_at:new Date(now+5*60000).toISOString()});
function fakeReceipt(){return {payload:{reviewed_at:new Date(now+100).toISOString(),request_sha256:'b'.repeat(64)}}}
function dummyRequest(){return '{}';}
test('rejects unauthenticated owner without repo operations',async()=>{
 let n=0;const r={getOwnerKey:()=>{n++;}};
 const out=await handleOracleLabOwnerRequest({action:'oracle_lab_enroll_challenge_v2'},{owner_user_id:ownerId,owner_authenticated:false},r,now);
 assert.equal(out.status,401);assert.equal(n,0);
});
test('rejects unknown action, extra fields and production intent',async()=>{
 const r=repo();for(const body of [{action:'deploy_production'}, {action:'oracle_lab_enroll_challenge_v2',prod:true},{action:'oracle_lab_grant_shell',command:'whoami'}]){
 const out=await handleOracleLabOwnerRequest(body,ctx,r,now);assert.ok(out.status>=400);assert.equal(out.body.deployment_authorized,false);}
 assert.equal(r.state.challenge,null);
});
test('issues owner-only challenge signed over *both* fixture token and current release archive',async()=>{
 const r=repo(),c=await challenge(r);assert.equal(c.status,200);
 assert.match(c.body.signing_message,new RegExp(RELEASE_SHA));assert.match(c.body.signing_message,new RegExp(FIXTURE_TOKEN));
 assert.equal(c.body.request.release_archive_sha256,RELEASE_SHA);assert.equal(c.body.request.host,'CORTANA');
 assert.equal(c.body.deployment_authorized,false);
});
test('valid owner Ed25519 signature enrolls only pinned lab key',async()=>{
 const r=repo(),input=await validEnrollment(r);
 const out=await handleOracleLabOwnerRequest(input,ctx,r,now);
 assert.equal(out.status,200);assert.equal(out.body.enrollment_recorded,true);
 assert.equal(out.body.deployment_authorized,false);assert.deepEqual(r.state.calls,['enroll']);
});
test('old v0.3 archive hash cannot replace release archive SHA',async()=>{
 const r=repo(),input=await validEnrollment(r);input.request.release_archive_sha256=FIXTURE_TOKEN;
 const out=await handleOracleLabOwnerRequest(input,ctx,r,now);
 assert.equal(out.status,403);assert.equal(r.state.enrolled,false);
});
test('wrong owner signature is rejected before write',async()=>{
 const r=repo(),input=await validEnrollment(r);input.signature_b64url='0'.repeat(86);
 const out=await handleOracleLabOwnerRequest(input,ctx,r,now);
 assert.equal(out.status,403);assert.equal(r.state.calls.length,0);
});
test('altered public key bytes rejected despite claimed pinned fingerprint',async()=>{
 const r=repo(),input=await validEnrollment(r);input.public_record={...data,public_key_pem:data.public_key_pem.replace('MCow','MCox')};
 const out=await handleOracleLabOwnerRequest(input,ctx,r,now);
 assert.equal(out.status,403);assert.equal(r.state.calls.length,0);
});
test('expired owner challenge fails closed',async()=>{
 const r=repo(),input=await validEnrollment(r);
 const out=await handleOracleLabOwnerRequest(input,ctx,r,now+11*60000);
 assert.equal(out.status,403);assert.equal(r.state.calls.length,0);
});
test('reused enrollment challenge rejected',async()=>{
 const r=repo(),input=await validEnrollment(r);
 assert.equal((await handleOracleLabOwnerRequest(input,ctx,r,now)).status,200);
 assert.equal((await handleOracleLabOwnerRequest(input,ctx,r,now)).status,403);
 assert.equal(r.state.calls.length,1);
});
test('lab grant rejects before enrollment',async()=>{
 const r=repo(),out=await handleOracleLabOwnerRequest({action:'oracle_lab_record_review_v2',job_id:jobId,raw_request_json:dummyRequest(),signed_receipt:fakeReceipt()},ctx,r,now,mockCheck);
 assert.equal(out.status,403);assert.equal(r.state.calls.length,0);
});
test('lab grant rejects failed signature before DB write',async()=>{
 const r=repo();r.state.enrolled=true;
 const badVerify=async()=>{throw Error('BAD_SIGNATURE')};
 const out=await handleOracleLabOwnerRequest({action:'oracle_lab_record_review_v2',job_id:jobId,raw_request_json:dummyRequest(),signed_receipt:fakeReceipt()},ctx,r,now,badVerify);
 assert.equal(out.status,403);assert.equal(r.state.calls.length,0);
});
test('lab grant refuses leased job, wrong device or expiry',async()=>{
 const r=repo();r.state.enrolled=true;
 const request={action:'oracle_lab_record_review_v2',job_id:jobId,raw_request_json:dummyRequest(),signed_receipt:fakeReceipt()};
 for(const patch of [{status:'leased'},{device_name:'Cortana'},{expires_at:new Date(now-1).toISOString()},{attempt_count:1}]){
   r.state.job={...sampleJob(),...patch};
   const out=await handleOracleLabOwnerRequest(request,ctx,r,now,mockCheck);assert.equal(out.status,403);}
 assert.equal(r.state.calls.length,0);
});
test('one verified review recorded as lab-only; same grant replay rejected',async()=>{
 const r=repo();r.state.enrolled=true;
 const request={action:'oracle_lab_record_review_v2',job_id:jobId,raw_request_json:dummyRequest(),signed_receipt:fakeReceipt()};
 const first=await handleOracleLabOwnerRequest(request,ctx,r,now,mockCheck);
 assert.equal(first.status,200);assert.equal(first.body.execution_authorized,false);assert.equal(first.body.deployment_authorized,false);
 assert.equal(r.state.grant.release_archive_sha256,RELEASE_SHA);assert.equal(r.state.grant.nonce,nonce);
 const second=await handleOracleLabOwnerRequest(request,ctx,r,now,mockCheck);assert.equal(second.status,409);
});
test('review before job creation is rejected',async()=>{
 const r=repo();r.state.enrolled=true;r.state.job.created_at=new Date(now+5000).toISOString();
 const out=await handleOracleLabOwnerRequest({action:'oracle_lab_record_review_v2',job_id:jobId,raw_request_json:dummyRequest(),signed_receipt:fakeReceipt()},ctx,r,now,mockCheck);
 assert.equal(out.status,403);assert.equal(r.state.calls.length,0);
});
test('server refuses reviewer trying to confer production authority',async()=>{
 const r=repo();r.state.enrolled=true;
 const out=await handleOracleLabOwnerRequest({action:'oracle_lab_record_review_v2',job_id:jobId,raw_request_json:dummyRequest(),signed_receipt:fakeReceipt()},ctx,r,now,async()=>({review_valid:true,production_deployment_authorized:true}));
 assert.equal(out.status,403);assert.equal(r.state.calls.length,0);
});

test('cannot extend grant past the reviewer-approved expiry',async()=>{
 const r=repo();r.state.enrolled=true;
 const out=await handleOracleLabOwnerRequest({action:'oracle_lab_record_review_v2',job_id:jobId,raw_request_json:dummyRequest(),signed_receipt:fakeReceipt()},ctx,r,now,
   async()=>({review_valid:true,production_deployment_authorized:false,expires_at:new Date(now+1000).toISOString()}));
 assert.equal(out.status,403);assert.equal(out.body.error,'REVIEW_SCOPE_TOO_SHORT');assert.equal(r.state.calls.length,0);
});

test('extra cloud command fields are rejected before grant is written',async()=>{
 const r=repo();r.state.enrolled=true;r.state.job.payload.extra_command='powershell';
 const out=await handleOracleLabOwnerRequest({action:'oracle_lab_record_review_v2',job_id:jobId,raw_request_json:dummyRequest(),signed_receipt:fakeReceipt()},ctx,r,now,mockCheck);
 assert.equal(out.status,403);assert.equal(out.body.error,'EXTRA_OR_MISSING_CLOUD_FIELDS');assert.equal(r.state.calls.length,0);
});
