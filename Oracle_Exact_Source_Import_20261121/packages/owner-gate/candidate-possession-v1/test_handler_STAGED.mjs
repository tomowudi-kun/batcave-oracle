import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {handleCandidatePossessionOnlySTAGED as handle,OWNER_ID,DRAFT_ID}
 from './handler_STAGED.mjs';
import {possessionMessage} from '../src/general_control_reviewer_possession_STAGED.mjs';
const now=Date.parse('2026-11-23T21:29:00.000Z');
const keys=generateKeyPairSync('ed25519');
const raw=keys.publicKey.export({type:'spki',format:'der'}).subarray(-32);
const fpr=createHash('sha256').update(raw).digest('hex');
const pub=raw.toString('base64url');
const owner={authenticated_owner:true,owner_user_id:OWNER_ID};
const candidate={id:DRAFT_ID,owner_user_id:OWNER_ID,
 kind:'general_control_public_reviewer_candidate_v1',host:'Cortana',
 account:'CORTANA\\StrictNannyRelease',
 sid:'S-1-5-21-349890097-2052580754-4142396749-1004',
 public_key_sha256_raw:fpr,public_key_b64url_raw:pub,registered:false,
 independently_attested:false,production_release_authorized:false,
 execution_authorized:false};
function fixture(){
 const state={prepared:null,recorded:0};
 const repo={
  reserve:async(payload,signing_sha256)=>{
   if(state.prepared)return {reserved:false};
   state.prepared={payload,signing_sha256,state:'unused'};
   return {reserved:true,request_id:payload.request_id,nonce:payload.nonce};
  },
  getPrepared:async(id,nonce)=>
   state.prepared?.payload.request_id===id&&state.prepared.payload.nonce===nonce?
    state.prepared:null,
  recordProof:async(p)=>{
   if(state.prepared?.state!=='unused'||state.prepared.payload.request_id!==p.request_id||
      state.prepared.payload.nonce!==p.nonce)return {recorded:false};
   state.prepared.state='candidate_possession_recorded_only';
   state.recorded++;
   return {recorded:true,request_id:p.request_id,state:'candidate_possession_recorded_only'};
  }
 };
 return {state,services:{repository:repo,getPrivateCandidate:async()=>candidate}};
}
const signProof=challenge=>({schema:'batcave.general_control.reviewer_possession_proof.v1',
 request_id:challenge.request_id,nonce:challenge.nonce,
 signature_hex:sign(null,Buffer.from(possessionMessage(challenge,now)),keys.privateKey).toString('hex')});
function noAuthority(res){
 for(const field of ['registered','independently_attested','production_release_authorized',
 'execution_authorized','deployment_authorized','grant_issued'])assert.equal(res[field],false);
}
test('only trusted owner + exact draft may issue a server reserved challenge',async()=>{
 const f=fixture();
 for(const session of [null,{authenticated_owner:false,owner_user_id:OWNER_ID},
  {authenticated_owner:true,owner_user_id:DRAFT_ID}]){
  const r=await handle({op:'issue',draft_id:DRAFT_ID},session,f.services,now);
  assert.equal(r.status,'DENY');noAuthority(r);
 }
 for(const payload of [{op:'issue',draft_id:OWNER_ID},
  {op:'issue',draft_id:DRAFT_ID,execution_authorized:true},
  {op:'release',draft_id:DRAFT_ID}]){
  const r=await handle(payload,owner,f.services,now);
  assert.equal(r.status,'DENY');noAuthority(r);
 }
 assert.equal(f.state.prepared,null);
 const r=await handle({op:'issue',draft_id:DRAFT_ID},owner,f.services,now);
 assert.equal(r.status,'AWAIT_EXPLICIT_KEY_POSSESSION_PROOF');
 assert.equal(r.challenge.owner_user_id,OWNER_ID);
 assert.equal(r.challenge.draft_id,DRAFT_ID);
 noAuthority(r);
});
test('candidate public signature records only one proof and cannot authorize release',async()=>{
 const f=fixture();
 const issued=await handle({op:'issue',draft_id:DRAFT_ID},owner,f.services,now);
 assert.equal(issued.status,'AWAIT_EXPLICIT_KEY_POSSESSION_PROOF');
 const p=signProof(issued.challenge);
 const forged=await handle({op:'record',proof:{...p,signature_hex:'0'.repeat(128)}},
  owner,f.services,now);
 assert.equal(forged.status,'DENY');noAuthority(forged);assert.equal(f.state.recorded,0);
 const recorded=await handle({op:'record',proof:p},owner,f.services,now);
 assert.equal(recorded.status,'CANDIDATE_POSSESSION_RECORDED_ONLY');
 assert.equal(recorded.proof_of_possession_verified,true);noAuthority(recorded);
 assert.equal(f.state.recorded,1);
 const replay=await handle({op:'record',proof:p},owner,f.services,now);
 assert.equal(replay.status,'DENY');noAuthority(replay);assert.equal(f.state.recorded,1);
});
test('owner cannot record unrelated or expired challenges; no session denies',async()=>{
 const f=fixture();
 const issued=await handle({op:'issue',draft_id:DRAFT_ID},owner,f.services,now);
 const p=signProof(issued.challenge);
 assert.equal((await handle({op:'record',proof:p},null,f.services,now)).status,'DENY');
 assert.equal((await handle({op:'record',proof:p,release:true},owner,f.services,now)).status,'DENY');
 assert.equal((await handle({op:'record',proof:p},owner,f.services,now+301000)).status,'DENY');
 f.state.prepared.payload.owner_user_id=DRAFT_ID;
 assert.equal((await handle({op:'record',proof:p},owner,f.services,now)).status,'DENY');
 assert.equal(f.state.recorded,0);
});
