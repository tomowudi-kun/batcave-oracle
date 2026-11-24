import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {issuePossessionChallengeSTAGED as issue,recordPossessionProofSTAGED as record,
 possessionMessage,POP_SCHEMA,POP_DOMAIN} from '../src/general_control_reviewer_possession_STAGED.mjs';
const now=Date.parse('2026-11-23T21:29:00.000Z');
const draft='50920aad-09e6-4895-aea1-a29410edd435',owner='ff189123-b5c3-4ee0-9267-06d4f20fb44f';
const key=generateKeyPairSync('ed25519');
const raw=key.publicKey.export({type:'spki',format:'der'}).subarray(-32);
const fingerprint=createHash('sha256').update(raw).digest('hex');
const candidate={id:draft,owner_user_id:owner,kind:'general_control_public_reviewer_candidate_v1',
 registered:false,independently_attested:false,production_release_authorized:false,
 execution_authorized:false,host:'Cortana',account:'CORTANA\\StrictNannyRelease',
 sid:'S-1-5-21-349890097-2052580754-4142396749-1004',
 public_key_sha256_raw:fingerprint,public_key_b64url_raw:raw.toString('base64url')};
const session={authenticated_owner:true,owner_user_id:owner};
function fixture(){
 const state={candidate:{...candidate},prepared:null,records:0};
 const services={getPrivateCandidate:async()=>state.candidate,
  repository:{
   reserve:async(payload,signing_sha256)=>{if(state.prepared)return {reserved:false};
    state.prepared={payload,signing_sha256,state:'unused'};
    return {reserved:true,request_id:payload.request_id,nonce:payload.nonce};
   },
   getPrepared:async(request_id,nonce)=>state.prepared?.payload.request_id===request_id&&
     state.prepared?.payload.nonce===nonce?state.prepared:null,
   recordProof:async r=>{if(state.prepared?.state!=='unused'||
    state.prepared.payload.request_id!==r.request_id||
    state.prepared.payload.nonce!==r.nonce)return {recorded:false};
    state.prepared.state='recorded';state.records++;
    return {recorded:true,request_id:r.request_id,state:'candidate_possession_recorded_only'};
   }
  }};
 return {state,services};
}
async function prepare(f){
 const x=await issue({draft_id:draft},session,f.services,now);
 assert.equal(x.status,'AWAIT_EXPLICIT_KEY_POSSESSION_PROOF',JSON.stringify(x));
 return x.challenge;
}
const proof=challenge=>({schema:'batcave.general_control.reviewer_possession_proof.v1',
 request_id:challenge.request_id,nonce:challenge.nonce,
 signature_hex:sign(null,Buffer.from(possessionMessage(challenge,now)),key.privateKey).toString('hex')});
test('challenge reserves server-only nonce for exact candidate; no authority',async()=>{
 const f=fixture(),c=await prepare(f);
 assert.equal(c.schema,POP_SCHEMA);assert.equal(c.candidate_key_sha256,fingerprint);
 assert.equal(c.purpose,'candidate_key_possession_only');
 assert.equal(possessionMessage(c,now).startsWith(POP_DOMAIN),true);
 assert.equal(c.execution_authorized,false);assert.equal(c.deployment_authorized,false);
 assert.equal(c.grant_issued,false);assert.equal(f.state.records,0);
});
test('one-use real Ed25519 proof records possession only, no attestation/grant',async()=>{
 const f=fixture(),c=await prepare(f),p=proof(c);
 const x=await record(p,f.services,now);
 assert.equal(x.status,'CANDIDATE_POSSESSION_RECORDED_ONLY',JSON.stringify(x));
 assert.equal(x.proof_of_possession_verified,true);
 for(const k of ['independently_attested','registered','production_release_authorized',
 'execution_authorized','deployment_authorized','grant_issued'])assert.equal(x[k],false);
 assert.equal(f.state.records,1);
 assert.equal((await record(p,f.services,now)).status,'DENY');
 assert.equal(f.state.records,1);
});
test('no owner session or candidate authority claim prevents prepare',async()=>{
 for(const s of [{authenticated_owner:false,owner_user_id:owner},
  {authenticated_owner:true,owner_user_id:draft},null]){
  assert.equal((await issue({draft_id:draft},s,fixture().services,now)).status,'DENY');
 }
 for(const mutation of [{registered:true},{independently_attested:true},
  {account:'CORTANA\\StrictNannyReviewer'},{public_key_sha256_raw:'0'.repeat(64)},
  {owner_user_id:draft}]){
  const f=fixture();f.state.candidate={...candidate,...mutation};
  assert.equal((await issue({draft_id:draft},session,f.services,now)).status,'DENY');
 }
});
test('forgery, wrong signature, changed nonce and extra fields deny',async()=>{
 const f=fixture(),c=await prepare(f),p=proof(c);
 assert.equal((await record({...p,signature_hex:'0'.repeat(128)},f.services,now)).status,'DENY');
 assert.equal((await record({...p,nonce:'f'.repeat(32)},f.services,now)).status,'DENY');
 assert.equal((await record({...p,authorization:true},f.services,now)).status,'DENY');
 assert.equal(f.state.records,0);
});
test('proof expires and changed candidate cannot be used',async()=>{
 const f=fixture(),c=await prepare(f),p=proof(c);
 assert.equal((await record(p,f.services,now+301000)).status,'DENY');
 f.state.candidate={...candidate,account:'CORTANA\\StrictNannyReviewer'};
 assert.equal((await record(p,f.services,now)).status,'DENY');
 assert.equal(f.state.records,0);
});
test('challenge with fake authority, changed identity, or malformed key rejects local signing',async()=>{
 const f=fixture(),c=await prepare(f);
 for(const x of [{execution_authorized:true},{sid:'wrong'},
  {candidate_key_sha256:'a'.repeat(64)},{expires_at:'2026-11-23T21:20:00.000Z'},
  {extra:'malicious'}]){
  assert.throws(()=>possessionMessage({...c,...x},now));
 }
});
test('unsigned proof and no reserved server challenge deny',async()=>{
 const f=fixture();
 const p={schema:'batcave.general_control.reviewer_possession_proof.v1',
  request_id:'c1b7634c-eb00-4aee-8fd5-f33bc8c96b9f',nonce:'a'.repeat(32),
  signature_hex:'0'.repeat(128)};
 assert.equal((await record(p,f.services,now)).status,'DENY');
});
