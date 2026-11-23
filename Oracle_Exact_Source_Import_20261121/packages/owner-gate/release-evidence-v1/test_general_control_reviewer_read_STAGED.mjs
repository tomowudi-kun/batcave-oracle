import test from 'node:test';
import assert from 'node:assert/strict';
import {makeGeneralControlReviewerReadSTAGED as make} from './general_control_reviewer_read_STAGED.mjs';
const id='123e4567-e89b-42d3-a456-426614174001';
const request={request_id:id,owner_user_id:'123e4567-e89b-42d3-a456-426614174000'};
function mock(row){
 const calls=[];
 const sql=async(parts,...values)=>{calls.push({query:parts.join('?'),values});return row?[row]:[]};
 return {sql,calls};
}
test('trusted private join maps durable consumed owner receipt into reviewable state',async()=>{
 const m=mock({request,nonce_state:'consumed',
  owner_evidence_state:'owner_signature_recorded_only',
  reviewer_evidence_state:null});
 const result=await make(m.sql)(id);
 assert.equal(result.owner_evidence_state,'owner_signature_recorded_only');
 assert.equal(result.nonce_state,'consumed_owner_evidence');
 assert.equal(result.reviewer_evidence_state,'unused');
 assert.deepEqual(m.calls[0].values,[id]);
 assert.match(m.calls[0].query,/JOIN batcave.general_control_owner_evidence_staged_v1/);
 assert.match(m.calls[0].query,/LEFT JOIN batcave.general_control_reviewer_evidence_staged_v1/);
});
test('missing, unused, missing owner signature or duplicate reviewer never imply ready',async()=>{
 for(const row of [null,
  {request,nonce_state:'unused',owner_evidence_state:'owner_signature_recorded_only'},
  {request,nonce_state:'consumed',owner_evidence_state:'missing'}]){
  assert.equal(await make(mock(row).sql)(id),null);
 }
 const x=await make(mock({request,nonce_state:'consumed',
  owner_evidence_state:'owner_signature_recorded_only',
  reviewer_evidence_state:'reviewer_signature_recorded_only'}).sql)(id);
 assert.equal(x.reviewer_evidence_state,'reviewer_signature_recorded_only');
});
test('invalid ids never reach SQL',async()=>{
 const m=mock(null),read=make(m.sql);
 await assert.rejects(read("bad' OR TRUE --"),/INVALID_REVIEW_REQUEST_ID/);
 assert.equal(m.calls.length,0);
});
test('missing private SQL client fails closed',()=>{
 assert.throws(()=>make(null),/PRIVATE_POSTGRES_REQUIRED/);
});
