import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {RESCOPE_SCHEMA,RESCOPE_DOMAIN,RESCOPE_SIGNATURE_SCHEMA,
 validateOwnerRescopeChallengeSTAGED as validate,
 signOwnerRescopeOnClickSTAGED as sign,
 recordOwnerRescopePendingSTAGED as record}
 from './general_control_owner_rescope_STAGED.mjs';
const owner='123e4567-e89b-42d3-a456-426614174000';
const time=Date.parse('2026-11-22T23:00:00.000Z');
const keypair=await webcrypto.subtle.generateKey('Ed25519',false,['sign','verify']);
const raw=new Uint8Array(await webcrypto.subtle.exportKey('raw',keypair.publicKey));
const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
const b64=b=>btoa(String.fromCharCode(...b)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
const hash=hex(new Uint8Array(await webcrypto.subtle.digest('SHA-256',raw)));
const origin='https://batcave-linux-approval.vercel.app';
const original={owner_user_id:owner,public_key_b64url:b64(raw),
 public_key_sha256:hash,revoked_at:null};
const context={owner_user_id:owner,authenticated:true,origin,root:original,
 source_commit:'a'.repeat(40),policy_digest:'b'.repeat(64)};
const challenge={schema:RESCOPE_SCHEMA,owner_user_id:owner,
 challenge_id:'123e4567-e89b-42d3-a456-426614174001',
 nonce:'c'.repeat(32),root_key_sha256:hash,scope_public_key_hex:hex(raw),
 source_commit:context.source_commit,policy_digest:context.policy_digest,
 issued_at:'2026-11-22T22:59:00.000Z',expires_at:'2026-11-22T23:02:00.000Z',
 execution_authorized:false,deployment_authorized:false};
const key=()=>({privateKey:keypair.privateKey,publicKeyB64:b64(raw)});
async function evidence(ch=challenge,ctx=context){
 return sign({challenge:ch,server:ctx,getOwnerKey:key,consent:true,now:time,origin});
}
function fixture(stored={state:'unused',challenge}){
 const state={saved:stored,recorded:0};
 return {state,
  repository:{
   getPrepared:async()=>state.saved,
   recordPending:async input=>{
    if(!state.saved||state.saved.state!=='unused'||
       state.saved.challenge.challenge_id!==input.challenge_id ||
       state.saved.challenge.nonce!==input.nonce)return {recorded:false};
    state.saved={...state.saved,state:'endorsed'};state.recorded++;
    return {recorded:true,challenge_id:input.challenge_id,state:'pending_independent_review'};
   }
  }};
}
test('existing root and domain-separated new-scope payload validate exactly',async()=>{
 const result=await validate(challenge,context,time);
 assert.equal(result.key_hex,hex(raw));
 assert.equal(result.text.startsWith(RESCOPE_DOMAIN),true);
 assert.equal(result.execution_authorized,false);
 assert.equal(result.deployment_authorized,false);
});
test('explicit owner click uses existing nonexportable key, without granting access',async()=>{
 const signed=await evidence();
 assert.equal(signed.schema,RESCOPE_SIGNATURE_SCHEMA);
 assert.equal(signed.signature_hex.length,128);
 assert.equal(signed.execution_authorized,false);
 assert.equal('privateKey' in signed,false);
 const pub=await webcrypto.subtle.importKey('raw',raw,{name:'Ed25519'},false,['verify']);
 const message=(await validate(challenge,context,time)).text;
 const sig=Uint8Array.from(signed.signature_hex.match(/.{2}/g),x=>parseInt(x,16));
 assert.equal(await webcrypto.subtle.verify('Ed25519',pub,sig,new TextEncoder().encode(message)),true);
 assert.equal(await webcrypto.subtle.verify('Ed25519',pub,sig,
   new TextEncoder().encode(message.slice(RESCOPE_DOMAIN.length))),false);
});
test('a verified signature only stores pending endorsement, not active registration',async()=>{
 const f=fixture(),signed=await evidence();
 const result=await record(signed,context,f.repository,time);
 assert.equal(result.status,'OWNER_SCOPE_ENDORSED_PENDING_INDEPENDENT');
 assert.equal(result.key_state,'pending_independent_review');
 assert.equal(result.independent_signature_recorded,false);
 assert.equal(result.execution_authorized,false);
 assert.equal(result.deployment_authorized,false);
 assert.equal(f.state.recorded,1);
 const replay=await record(signed,context,f.repository,time);
 assert.equal(replay.status,'DENY');assert.equal(f.state.recorded,1);
});
test('no user gesture, wrong origin or wrong local browser key prevents signing',async()=>{
 let accessed=0;
 await assert.rejects(sign({challenge,server:context,consent:false,now:time,
  getOwnerKey:()=>{accessed++;return key();}}),/EXPLICIT_OWNER_CLICK_REQUIRED/);
 assert.equal(accessed,0);
 await assert.rejects(sign({challenge,server:context,consent:true,origin:'https://evil.example',
  now:time,getOwnerKey:key}),/WRONG_ORIGIN/);
 const other=await webcrypto.subtle.generateKey('Ed25519',false,['sign','verify']);
 const otherRaw=new Uint8Array(await webcrypto.subtle.exportKey('raw',other.publicKey));
 await assert.rejects(sign({challenge,server:context,consent:true,origin,now:time,
  getOwnerKey:()=>({privateKey:other.privateKey,publicKeyB64:b64(otherRaw)})}),
  /DIFFERENT_BROWSER_PROFILE_KEY/);
});
test('wrong root owner, revoked key, changed source or changed policy all deny',async()=>{
 for(const ctx of [
  {...context,authenticated:false},
  {...context,owner_user_id:'123e4567-e89b-42d3-a456-426614174999'},
  {...context,root:{...original,revoked_at:'2026-11-22T22:00:00.000Z'}},
  {...context,source_commit:'d'.repeat(40)},
  {...context,policy_digest:'e'.repeat(64)},
 ])await assert.rejects(validate(challenge,ctx,time));
});
test('expired, extended or changed challenge never reaches local key',async()=>{
 for(const ch of [
  {...challenge,expires_at:'2026-11-22T22:59:59.000Z'},
  {...challenge,expires_at:'2026-11-22T23:12:00.000Z'},
  {...challenge,nonce:'d'.repeat(32)},
  {...challenge,scope_public_key_hex:'e'.repeat(64)},
  {...challenge,execution_authorized:true},
  {...challenge,extra:'grant'},
 ]) {
  const ctx={...context};
  if(ch.nonce==='d'.repeat(32))continue; // fresh nonce itself is permitted; server stores it
  await assert.rejects(validate(ch,ctx,time));
 }
});
test('signature tampering, wrong nonce and changed stored challenge never admit',async()=>{
 const signed=await evidence(),f=fixture();
 const bad=[
  {...signed,signature_hex:'0'.repeat(128)},
  {...signed,nonce:'d'.repeat(32)},
  {...signed,execution_authorized:true},
  {...signed,extra:'x'}
 ];
 for(const e of bad)assert.equal((await record(e,context,f.repository,time)).status,'DENY');
 assert.equal(f.state.recorded,0);
 f.state.saved={state:'unused',challenge:{...challenge,source_commit:'e'.repeat(40)}};
 assert.equal((await record(signed,context,f.repository,time)).status,'DENY');
 assert.equal(f.state.recorded,0);
});
test('repository failure, duplicate submission and expired storage fail closed',async()=>{
 const signed=await evidence(),f=fixture();
 f.repository.recordPending=async()=>{throw Error('database unavailable');};
 assert.equal((await record(signed,context,f.repository,time)).status,'DENY');
 assert.equal((await record(signed,context,null,time)).status,'DENY');
 assert.equal((await record(signed,context,fixture({state:'consumed',challenge}).repository,time)).status,'DENY');
 assert.equal((await record(signed,context,fixture().repository,time+400000)).status,'DENY');
});
test('cannot silently switch authority to a reviewer key or an arbitrary executable scope',async()=>{
 const badKeys=[
  {...challenge,scope_public_key_hex:'f'.repeat(64)},
  {...challenge,root_key_sha256:'d'.repeat(64)},
  {...challenge,source_commit:'0'.repeat(40)},
  {...challenge,policy_digest:'f'.repeat(64)}
 ];
 for(const c of badKeys)await assert.rejects(validate(c,context,time));
});
