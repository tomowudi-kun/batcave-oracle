import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {handleGeneralControlOwnerApiV1 as handle} from './general_control_owner_api_STAGED.mjs';
import {signGeneralControlOwnerChallengeV1 as sign} from './general_control_owner_signing_v1.mjs';

const now=Date.parse('2026-11-22T21:05:00.000Z');
const ownerId='123e4567-e89b-42d3-a456-426614174000';
const origin='https://batcave-linux-approval.vercel.app';
const ctx={owner_user_id:ownerId,owner_authenticated:true,origin};
const key=await webcrypto.subtle.generateKey('Ed25519',false,['sign','verify']);
const pub=new Uint8Array(await webcrypto.subtle.exportKey('raw',key.publicKey));
const hex=a=>Array.from(a,b=>b.toString(16).padStart(2,'0')).join('');
const b64url=a=>btoa(String.fromCharCode(...a)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
const local={privateKey:key.privateKey,publicKeyB64:b64url(pub)};
const scope={device:'Cortana',capability:'browser.observe',target_origin:'https://example.org',
 target_session_id:'browser-session-1',command_digest:'a'.repeat(64),
 source_commit:'b'.repeat(40),policy_digest:'c'.repeat(64),rollback_ref:'none'};
const reg={owner_user_id:ownerId,key_scope:'general_control_owner_v1',key_state:'active',
 key_hex:hex(pub),revoked_at:null};
const actionPrepare={action:'general_control_prepare_owner_v1'};
const actionRecord=evidence=>({action:'general_control_record_owner_v1',evidence});
const actionDecline=ch=>({action:'general_control_decline_owner_v1',owner_user_id:ownerId,
 request_id:ch.request.request_id,nonce:ch.request.nonce});
function fixture(patch={}) {
 const state={reserved:null,nonceState:'unused',signed:0,declined:0,calls:0};
 const repo={
  getPendingScope:async()=>scope,
  getScopeRegistration:async()=>reg,
  reservePreparedChallenge:async row=>{
    state.reserved=row;state.nonceState='unused';
    return {inserted:true,request_id:row.request_id,nonce:row.nonce,
      request_sha256:row.request_sha256,nonce_state:'unused'};
  },
  getPreparedChallenge:async(owner,requestId)=>{
    if(!state.reserved || owner!==ownerId || state.reserved.request_id!==requestId)return null;
    return {...state.reserved,nonce_state:state.nonceState};
  },
  getCurrentScope:async()=>scope,
  recordSignedOwnerEvidence:async row=>{
    state.calls++;
    if(!state.reserved || state.nonceState!=='unused'||
       row.request_id!==state.reserved.request_id ||
       row.nonce!==state.reserved.nonce ||
       row.request_sha256!==state.reserved.request_sha256 ||
       row.policy_sha256!==scope.policy_digest)return {recorded:false};
    state.nonceState='consumed';state.signed++;
    return {recorded:true,request_id:row.request_id,nonce:row.nonce,
      state:'owner_signature_recorded_only'};
  },
  declinePreparedChallenge:async row=>{
    if(!state.reserved || state.nonceState!=='unused'||
       row.request_id!==state.reserved.request_id ||
       row.nonce!==state.reserved.nonce ||
       row.request_sha256!==state.reserved.request_sha256)return {declined:false};
    state.nonceState='declined';state.declined++;
    return {declined:true,request_id:row.request_id,nonce:row.nonce,state:'declined'};
  },
  ...patch,
 };
 return {repo,state};
}
async function prepared(f=fixture(),t=now) {
 const result=await handle(actionPrepare,ctx,f.repo,t);
 assert.equal(result.status,200,JSON.stringify(result));
 return {f,ch:result.body};
}
async function evidence(ch,t=now) {
 return await sign({challenge:ch,ownerUserId:ownerId,getOwnerKey:async()=>local,
   consent:true,now:t,origin});
}
test('fails closed before authenticated owner and original origin; no persistence',async()=>{
 const f=fixture();
 for(const identity of [{...ctx,owner_authenticated:false},{...ctx,origin:'https://evil.org'},
   {...ctx,owner_user_id:'123e4567-e89b-42d3-a456-426614174999'}]){
   const out=await handle(actionPrepare,identity,f.repo,now);
   assert.equal(out.status,401);assert.equal(out.body.execution_authorized,false);
 }
 assert.equal(f.state.reserved,null);
});
test('server-only pending scope yields exact three-minute one-use challenge',async()=>{
 const {f,ch}=await prepared();
 assert.equal(ch.request.owner_user_id,ownerId);
 assert.equal(ch.request.capability,scope.capability);
 assert.equal(ch.request.target_origin,scope.target_origin);
 assert.equal(ch.nonce_state,'unused');
 assert.equal(ch.execution_authorized,false);
 assert.equal(ch.deployment_authorized,false);
 assert.equal(ch.request.expires_at,new Date(now+180000).toISOString());
 assert.equal(f.state.reserved.request_sha256.length,64);
 assert.equal(ch.scope_registration.key_scope,'general_control_owner_v1');
});
test('real nonexportable owner Ed25519 signature is verified and stored once, never grants',async()=>{
 const {f,ch}=await prepared();
 const signed=await evidence(ch);
 const out=await handle(actionRecord(signed),ctx,f.repo,now);
 assert.equal(out.status,200,JSON.stringify(out));
 assert.equal(out.body.state,'owner_signature_recorded_only');
 assert.equal(out.body.execution_authorized,false);
 assert.equal(out.body.deployment_authorized,false);
 assert.equal(f.state.signed,1);
 assert.equal((await handle(actionRecord(signed),ctx,f.repo,now)).status,409);
 assert.equal(f.state.signed,1);
});
test('explicit No atomically declines once and cannot later sign',async()=>{
 const {f,ch}=await prepared();
 const out=await handle(actionDecline(ch),ctx,f.repo,now);
 assert.equal(out.status,200,JSON.stringify(out));
 assert.equal(out.body.state,'declined');
 assert.equal(f.state.declined,1);
 const signed=await evidence(ch);
 assert.equal((await handle(actionRecord(signed),ctx,f.repo,now)).status,409);
 assert.equal((await handle(actionDecline(ch),ctx,f.repo,now)).status,409);
});
test('unsigned, mismatched, tampered or untrusted owner evidence never reaches writer',async()=>{
 const {f,ch}=await prepared();
 const good=await evidence(ch);
 for(const changed of [
  {...good,signature_hex:'0'.repeat(128)},
  {...good,nonce:'e'.repeat(32)},
  {...good,owner_user_id:'other'},
  {...good,execution_authorized:true},
  {...good,extra:'inject'},
 ]) {
  const r=await handle(actionRecord(changed),ctx,f.repo,now);
  assert.notEqual(r.status,200);
 }
 assert.equal(f.state.calls,1); // only a well-shaped but cryptographically invalid signature reached verification, not write
 assert.equal(f.state.signed,0);
});
test('changed trusted policy, session, revoked scoped key or expiry stops the write',async()=>{
 const {f,ch}=await prepared();
 const signed=await evidence(ch);
 f.repo.getCurrentScope=async()=>({...scope,target_session_id:'new-session-99'});
 assert.equal((await handle(actionRecord(signed),ctx,f.repo,now)).status,409);
 f.repo.getCurrentScope=async()=>scope;
 f.repo.getScopeRegistration=async()=>({...reg,key_state:'revoked'});
 assert.equal((await handle(actionRecord(signed),ctx,f.repo,now)).status,403);
 f.repo.getScopeRegistration=async()=>reg;
 assert.equal((await handle(actionRecord(signed),ctx,f.repo,now+181000)).status,409);
 assert.equal(f.state.signed,0);
});
test('cannot prepare using lab-only reviewer key, arbitrary shell or malicious scope',async()=>{
 const lab=fixture({getScopeRegistration:async()=>({...reg,key_scope:'lab_reviewer_only'})});
 assert.notEqual((await handle(actionPrepare,ctx,lab.repo,now)).status,200);
 const shell=fixture({getPendingScope:async()=>({...scope,capability:'host.shell'})});
 assert.notEqual((await handle(actionPrepare,ctx,shell.repo,now)).status,200);
 const injected=fixture({getPendingScope:async()=>({...scope,owner_user_id:'other'})});
 assert.notEqual((await handle(actionPrepare,ctx,injected.repo,now)).status,200);
});
test('ambiguous/forged repository success and missing atomic backend never claim approval',async()=>{
 const {f,ch}=await prepared();
 const signed=await evidence(ch);
 f.repo.recordSignedOwnerEvidence=async()=>({recorded:true,request_id:ch.request.request_id,
   nonce:ch.request.nonce,state:'GRANTED'});
 assert.notEqual((await handle(actionRecord(signed),ctx,f.repo,now)).status,200);
 f.repo.recordSignedOwnerEvidence=null;
 assert.equal((await handle(actionRecord(signed),ctx,f.repo,now)).status,503);
 assert.equal(f.state.signed,0);
});
test('race on the same nonce permits exactly one owner receipt',async()=>{
 const {f,ch}=await prepared();
 const signed=await evidence(ch);
 const [a,b]=await Promise.all([handle(actionRecord(signed),ctx,f.repo,now),
   handle(actionRecord(signed),ctx,f.repo,now)]);
 assert.deepEqual([a.status,b.status].sort(),[200,409]);
 assert.equal(f.state.signed,1);
});
test('does not trust request content, unknown action, or unsigned direct grant',async()=>{
 const f=fixture();
 for(const invalid of [
  {action:'general_control_prepare_owner_v1',device:'Oracle'},
  {action:'general_control_issue_grant_v1'},
  {action:'general_control_record_owner_v1'},
  {action:'general_control_decline_owner_v1',owner_user_id:'other',
    request_id:'123e4567-e89b-42d3-a456-426614174001',nonce:'c'.repeat(32)},
 ]) {
  const r=await handle(invalid,ctx,f.repo,now);
  assert.notEqual(r.status,200);
 }
});
