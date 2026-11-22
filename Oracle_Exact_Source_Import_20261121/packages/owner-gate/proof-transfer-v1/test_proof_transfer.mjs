import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash,randomUUID} from 'node:crypto';
import {submitPublicProof,inspectPublicProof,ownerProofStatus} from './proof_transfer_core.mjs';
import {FIRST_PROOF_DOMAIN,FIRST_OWNER_DOMAIN,firstStable} from '../release-evidence-v1/first_reviewer_protocol.mjs';
const now=Date.parse('2026-11-21T23:00:00.000Z'),iso=n=>new Date(n).toISOString(),hash=x=>createHash('sha256').update(x).digest('hex');
function pair(){const p=generateKeyPairSync('ed25519'),raw=p.publicKey.export({type:'spki',format:'der'}).subarray(-32);return{...p,public_key_b64url:raw.toString('base64url'),public_key_sha256:hash(raw)};}
function fixture(){
 const o=pair(),r=pair(),owner={owner_user_id:randomUUID(),public_key_b64url:o.public_key_b64url,public_key_sha256:o.public_key_sha256,revoked_at:null};
 const policy={schema:'batcave.oracle.owner_first_reviewer.policy.v1',scope:'first_reviewer_enrollment_only',trust_basis:'owner_signed_first_reviewer_bootstrap',owner_user_id:owner.owner_user_id,owner_key_sha256:o.public_key_sha256,reviewer_key_sha256:r.public_key_sha256,reviewer_public_key_b64url:r.public_key_b64url,candidate_sha256:'c'.repeat(64),host_identity_sha256:'d'.repeat(64),custody_evidence_sha256:'e'.repeat(64),reviewer_sid:'S-1-5-21-101-202-303-1001',release_intent_key:'batcave.oracle.lab_v031.release_request.20261121',release_intent_sha256:'ff41a4a74e25fd31bf9a466d1566100ba9e98cc5d8769fd01fe12c9c653c4e80',signer_valid_until:iso(now+86400000)};
 const root={policy,policy_sha256:hash(firstStable(policy)),registered_at:null,revoked_at:null,owner_declined_at:null};
 const payload=Object.fromEntries(['scope','trust_basis','owner_user_id','owner_key_sha256','reviewer_key_sha256','candidate_sha256','host_identity_sha256','reviewer_sid','custody_evidence_sha256','signer_valid_until'].map(k=>[k,policy[k]]));
 Object.assign(payload,{schema:'batcave.oracle.first_reviewer.enrollment.v1',policy_sha256:root.policy_sha256,nonce:'f'.repeat(32),issued_at:iso(now-1000),expires_at:iso(now+599000)});
 const challenge={id:randomUUID(),kind:'first_key',owner_user_id:owner.owner_user_id,owner_key_sha256:o.public_key_sha256,reviewer_key_sha256:r.public_key_sha256,policy_sha256:root.policy_sha256,payload,payload_sha256:hash(firstStable(payload)),expires_at:payload.expires_at,consumed_at:null,withdrawn_at:null,pending_owner_signature_b64url:sign(null,Buffer.from(FIRST_OWNER_DOMAIN+firstStable(payload)),o.privateKey).toString('base64url')};
 const ctx={owner,root,challenge,existing_reviewers:0,intent:{state:'held',content_sha256:policy.release_intent_sha256,valid_until:iso(now+86400000)}};
 const proof={schema:'batcave.nanny.first_key.possession.v1',challenge_id:challenge.id,nonce:payload.nonce,policy_sha256:root.policy_sha256,reviewer_public_key_sha256:r.public_key_sha256,proof_signature_b64url:sign(null,Buffer.from(FIRST_PROOF_DOMAIN+firstStable(payload)),r.privateKey).toString('base64url'),independently_attested:false,deployment_authorized:false,execution_authorized:false,grant_issued:false};
 let stored=null,writes=0;
 const repo={context:async id=>id===challenge.id?structuredClone(ctx):null,store:async(id,h,p,ph)=>{writes++;if(!stored)stored=structuredClone(p);return{stored:ph===hash(firstStable(stored))&&firstStable(p)===firstStable(stored)};},proof:async()=>stored};
 return{ctx,proof,repo,writes:()=>writes,stored:()=>stored,ownerContext:{authenticated:true,id:owner.owner_user_id},submit:()=>submitPublicProof({op:'submit',proof},repo,now),status:()=>ownerProofStatus({op:'status',challenge_id:challenge.id},{authenticated:true,id:owner.owner_user_id},repo,now)};
}
test('genuine owner and candidate signatures transport public proof without enrollment or release',async()=>{const f=fixture(),r=await f.submit();assert.equal(r.status,200,JSON.stringify(r));assert.equal(r.body.proof_received,true);for(const k of ['reviewer_registered','independently_attested','deployment_authorized','execution_authorized','grant_issued'])assert.equal(r.body[k],false);assert.equal(f.ctx.root.registered_at,null);assert.equal(f.ctx.intent.state,'held');assert.deepEqual((await f.status()).body.proof,f.proof);});
test('missing or forged candidate signatures never reach the ledger',async()=>{for(const sig of [null,'A'.repeat(86)]){const f=fixture();f.proof.proof_signature_b64url=sig;assert.equal((await f.submit()).status,403);assert.equal(f.writes(),0);}});
test('saved owner endorsement is independently reverified; a candidate cannot self-approve',async()=>{const f=fixture();f.ctx.challenge.pending_owner_signature_b64url=f.proof.proof_signature_b64url;assert.equal((await f.submit()).body.error,'FIRST_SIGNATURE_INVALID');assert.equal(f.writes(),0);});
test('expired signatures cannot become current through a transport receipt',async()=>{const f=fixture();const r=await submitPublicProof({op:'submit',proof:f.proof},f.repo,now+600001);assert.equal(r.status,403);assert.equal(f.writes(),0);});
test('No, revocation, owner rotation, consumed challenges and released intents close transport',async()=>{for(const change of [f=>f.ctx.root.owner_declined_at=iso(now),f=>f.ctx.root.revoked_at=iso(now),f=>f.ctx.owner.public_key_sha256='a'.repeat(64),f=>f.ctx.challenge.withdrawn_at=iso(now),f=>f.ctx.challenge.consumed_at=iso(now),f=>f.ctx.intent.state='released',f=>f.ctx.intent.valid_until=iso(now-1)]){const f=fixture();change(f);assert.equal((await f.submit()).status,403);assert.equal(f.writes(),0);}});
test('registration or another privileged reviewer prevents a new bootstrap deposit',async()=>{for(const change of [f=>f.ctx.root.registered_at=iso(now),f=>f.ctx.existing_reviewers=1]){const f=fixture();change(f);assert.equal((await f.submit()).status,403);}});
test('proof identity and exact public-envelope fields cannot be substituted',async()=>{for(const change of [f=>f.proof.challenge_id=randomUUID(),f=>f.proof.nonce='a'.repeat(32),f=>f.proof.policy_sha256='a'.repeat(64),f=>f.proof.reviewer_public_key_sha256='b'.repeat(64),f=>f.proof.extra='no',f=>f.proof.execution_authorized=true]){const f=fixture();change(f);assert.equal((await f.submit()).status,403);assert.equal(f.writes(),0);}});
test('submission cannot return private policy, owner session or authentication credentials',async()=>{const f=fixture(),r=await f.submit();assert.deepEqual(Object.keys(r.body).sort(),['challenge_id','deployment_authorized','execution_authorized','grant_issued','independently_attested','proof_received','reviewer_registered']);});
test('owner status requires actual owner authentication and rejects another account',async()=>{const f=fixture();await f.submit();for(const owner of [{authenticated:false,id:f.ctx.owner.owner_user_id},{authenticated:true,id:randomUUID()}]){const r=await ownerProofStatus({op:'status',challenge_id:f.ctx.challenge.id},owner,f.repo,now);assert.equal(r.status,401);assert.equal(r.body.proof,undefined);}});
test('same public proof can be submitted idempotently; it does not consume the nonce',async()=>{const f=fixture();assert.equal((await f.submit()).status,200);assert.equal((await f.submit()).status,200);assert.equal(f.ctx.challenge.consumed_at,null);assert.deepEqual(f.stored(),f.proof);});
test('a ledger rejection after validation fails closed',async()=>{const f=fixture();f.repo.store=async()=>({stored:false});assert.equal((await f.submit()).body.error,'PROOF_NOT_STORED');});
test('tampered stored proof is not returned to the owner page',async()=>{const f=fixture();await f.submit();f.repo.proof=async()=>({...f.proof,proof_signature_b64url:'A'.repeat(86)});assert.equal((await f.status()).body.error,'FIRST_SIGNATURE_INVALID');});

test('expired public artifact can be diagnosed without storing, consuming or renewing consent',async()=>{
 const f=fixture();f.ctx.challenge.expires_at=iso(now-1);
 const before=structuredClone(f.ctx),r=await inspectPublicProof({op:'inspect',proof:f.proof},f.repo);
 assert.equal(r.status,200);assert.equal(r.body.diagnostic_only,true);assert.equal(r.body.historical_signatures_match,true);assert.equal(r.body.proof_received,false);
 for(const k of ['reviewer_registered','independently_attested','deployment_authorized','execution_authorized','grant_issued'])assert.equal(r.body[k],false);
 assert.equal(f.writes(),0);assert.deepEqual(f.ctx,before);assert.equal((await f.submit()).status,403);
});
test('historical diagnosis never overrides No, registration or nonce consumption',async()=>{
 for(const change of [f=>f.ctx.root.owner_declined_at=iso(now),f=>f.ctx.root.registered_at=iso(now),f=>f.ctx.challenge.consumed_at=iso(now),f=>f.ctx.challenge.withdrawn_at=iso(now)]){
  const f=fixture();change(f);const before=structuredClone(f.ctx),r=await inspectPublicProof({op:'inspect',proof:f.proof},f.repo);
  assert.equal(r.status,200);assert.equal(r.body.proof_received,false);assert.equal(f.writes(),0);assert.deepEqual(f.ctx,before);assert.equal((await f.submit()).status,403);
 }
});
test('historical inspection rejects forged and substituted artifacts without writing',async()=>{
 for(const change of [f=>f.proof.proof_signature_b64url='A'.repeat(86),f=>f.proof.nonce='a'.repeat(32),f=>f.ctx.challenge.payload.nonce='a'.repeat(32),f=>f.proof.execution_authorized=true,f=>f.proof.extra='private',f=>f.ctx.root.revoked_at=iso(now)]){
  const f=fixture();change(f);assert.equal((await inspectPublicProof({op:'inspect',proof:f.proof},f.repo)).status,403);assert.equal(f.writes(),0);
 }
});
test('rejection logs identify stage and SQLSTATE without exposing exception text or evidence',async()=>{
 const f=fixture(),events=[];f.repo.store=async()=>{throw Object.assign(Error('sensitive SQL and parameters must never be logged'),{code:'42501'});};
 const r=await submitPublicProof({op:'submit',proof:f.proof},f.repo,now,e=>events.push(e));
 assert.equal(r.status,503);assert.equal(r.body.error,'PROOF_UNAVAILABLE');assert.deepEqual(events,[{event:'public_proof_rejected',operation:'submit',stage:'ledger',error:'PROOF_UNAVAILABLE',sqlstate:'42501'}]);
 assert.equal(JSON.stringify(events).includes(f.proof.proof_signature_b64url),false);
});
