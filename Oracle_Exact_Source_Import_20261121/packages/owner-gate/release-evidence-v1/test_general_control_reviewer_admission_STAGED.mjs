import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {reviewGeneralControlEvidenceSTAGED as review} from './general_control_reviewer_admission_STAGED.mjs';
const now=Date.parse('2026-11-22T21:35:00.000Z');
const id='123e4567-e89b-42d3-a456-426614174000';
const request={schema:'batcave.general_control.owner_request.v1',owner_user_id:id,
 request_id:'123e4567-e89b-42d3-a456-426614174001',device:'Oracle',capability:'host.read',
 target_origin:null,target_session_id:'oracle-session-1',command_digest:'a'.repeat(64),
 source_commit:'b'.repeat(40),policy_digest:'c'.repeat(64),nonce:'d'.repeat(32),
 issued_at:'2026-11-22T21:34:00.000Z',expires_at:'2026-11-22T21:37:00.000Z',rollback_ref:'none'};
const binding={owner_user_id:id,device:request.device,target_origin:null,
 target_session_id:request.target_session_id,command_digest:request.command_digest,
 source_commit:request.source_commit,policy_digest:request.policy_digest};
const keys=generateKeyPairSync('ed25519');
const pub=keys.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');
const msg=request.schema+'\n'+JSON.stringify(request);
const signature=sign(null,Buffer.from('BATCAVE_NANNY_GENERAL_CONTROL_V1\n'+msg),keys.privateKey).toString('hex');
const evidence={request_id:request.request_id,signature_hex:signature};
const context={reviewer_authenticated:true,reviewer_identity_id:'reviewer-2',
 owner_identity_id:'owner-1',reviewer_registration:{identity_id:'reviewer-2',
 independently_attested:true,key_state:'active',key_scope:'general_control_privileged_reviewer_v1',key_hex:pub},
 trusted_binding:binding,current_policy:{current:true,capability_allowed:true,
 digest:request.policy_digest,source_commit:request.source_commit}};
const repo=(saved={},receipt={})=>({getPreparedReview:async()=>({
 request,owner_evidence_state:'owner_signature_recorded_only',
 reviewer_evidence_state:'unused',nonce_state:'consumed_owner_evidence',...saved}),
 appendReviewerEvidence:async()=>({inserted:true,request_id:request.request_id,
 state:'reviewer_signature_recorded_only',...receipt})});
test('valid independent signature only records evidence, never releases',async()=>{
 const out=await review(evidence,context,repo(),now);
 assert.equal(out.status,'REVIEWER_EVIDENCE_RECORDED_ONLY');
 assert.equal(out.execution_authorized,false);assert.equal(out.deployment_authorized,false);
});
test('missing authenticated reviewer and lab-only scope denied',async()=>{
 assert.equal((await review(evidence,{...context,reviewer_authenticated:false},repo(),now)).status,'DENY');
 const c={...context,reviewer_registration:{...context.reviewer_registration,key_scope:'lab_reviewer_only'}};
 assert.equal((await review(evidence,c,repo(),now)).status,'DENY');
});
test('owner as reviewer and non-independent registration denied',async()=>{
 for(const change of [{reviewer_identity_id:'owner-1'},{
 reviewer_registration:{...context.reviewer_registration,independently_attested:false}}])
 assert.equal((await review(evidence,{...context,...change},repo(),now)).status,'DENY');
});
test('invalid signature and extra evidence fields denied',async()=>{
 assert.equal((await review({...evidence,signature_hex:'0'.repeat(128)},context,repo(),now)).status,'DENY');
 assert.equal((await review({...evidence,approved:true},context,repo(),now)).status,'DENY');
});
test('missing owner receipt, consumed reviewer evidence, or wrong nonce state denied',async()=>{
 for(const change of [{owner_evidence_state:'unused'},{reviewer_evidence_state:'recorded'},
 {nonce_state:'unused'}])assert.equal((await review(evidence,context,repo(change),now)).status,'DENY');
});
test('policy/session changes and expiry denied',async()=>{
 assert.equal((await review(evidence,{...context,current_policy:{...context.current_policy,digest:'f'.repeat(64)}},repo(),now)).status,'DENY');
 assert.equal((await review(evidence,{...context,trusted_binding:{...binding,target_session_id:'changed-session-2'}},repo(),now)).status,'DENY');
 assert.equal((await review(evidence,context,repo(),now+300000)).status,'DENY');
});
test('failed durable append never claims approval',async()=>{
 assert.equal((await review(evidence,context,repo({}, {inserted:false}),now)).status,'DENY');
 assert.equal((await review(evidence,context,{...repo(),appendReviewerEvidence:async()=>{throw Error('DB down')}},now)).status,'DENY');
});
test('no private repository denied',async()=>{
 assert.equal((await review(evidence,context,{},now)).status,'DENY');
});
