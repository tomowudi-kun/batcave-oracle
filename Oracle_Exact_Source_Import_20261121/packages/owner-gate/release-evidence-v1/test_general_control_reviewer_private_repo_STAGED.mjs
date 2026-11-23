import test from 'node:test';
import assert from 'node:assert/strict';
import {makeGeneralControlReviewerPrivateRepoSTAGED as make} from './general_control_reviewer_private_repo_STAGED.mjs';
const owner='123e4567-e89b-42d3-a456-426614174000';
const reviewer='123e4567-e89b-42d3-a456-426614174009';
const e={request_id:'123e4567-e89b-42d3-a456-426614174001',owner_user_id:owner,
 nonce:'a'.repeat(32),policy_digest:'b'.repeat(64),source_commit:'c'.repeat(40),
 reviewer_identity_id:reviewer,reviewer_key_hex:'d'.repeat(64),signature_hex:'e'.repeat(128)};
const mock=(recorded=true)=>{const calls=[];const sql=(parts,...values)=>{calls.push({parts,values});return Promise.resolve([{recorded}]);};return {sql,calls};};
test('parameterized private invoker stores exactly the eight typed values, never authorizes',async()=>{
 const m=mock(),r=make(m.sql,{getTrustedPreparedReview:async()=>({trusted:true})});
 assert.deepEqual(await r.getPreparedReview(e.request_id),{trusted:true});
 const out=await r.appendReviewerEvidence(e);
 assert.deepEqual(out,{inserted:true,request_id:e.request_id,state:'reviewer_signature_recorded_only'});
 assert.equal(m.calls.length,1);
 assert.deepEqual(m.calls[0].values,[e.request_id,e.owner_user_id,e.nonce,e.policy_digest,e.source_commit,e.reviewer_identity_id,e.reviewer_key_hex,e.signature_hex]);
 assert.match(m.calls[0].parts.join('?'),/general_control_append_reviewer_evidence_staged_v1/);
 assert.equal('execution_authorized' in out,false);
});
test('rejected database admission is not success',async()=>{
 const m=mock(false),r=make(m.sql,{getTrustedPreparedReview:async()=>null});
 assert.deepEqual(await r.appendReviewerEvidence(e),{inserted:false});
});
test('missing private connection or trusted resolver fails closed',()=>{
 assert.throws(()=>make(()=>{}),/PRIVATE_CONNECTION/);
 assert.throws(()=>make(null,{getTrustedPreparedReview:async()=>{}}),/PRIVATE_CONNECTION/);
});
test('injection, duplicate identity, malformed signature, and extra fields rejected before query',async()=>{
 const m=mock(),r=make(m.sql,{getTrustedPreparedReview:async()=>null});
 for(const patch of [{request_id:"' OR TRUE --"},{reviewer_identity_id:owner},
   {policy_digest:'invalid'},{signature_hex:'0'.repeat(127)},{extra:'grant'}])
   await assert.rejects(()=>r.appendReviewerEvidence({...e,...patch}),/INVALID_PRIVATE/);
 assert.equal(m.calls.length,0);
});
test('read side rejects invalid ID before resolver',async()=>{
 let called=false;const m=mock(),r=make(m.sql,{getTrustedPreparedReview:async()=>{called=true;}});
 await assert.rejects(()=>r.getPreparedReview('bad'),/INVALID_PRIVATE/);
 assert.equal(called,false);
});
test('database exception propagates; no invented receipt',async()=>{
 const r=make(()=>Promise.reject(Error('database unavailable')),{getTrustedPreparedReview:async()=>null});
 await assert.rejects(()=>r.appendReviewerEvidence(e),/database unavailable/);
});
