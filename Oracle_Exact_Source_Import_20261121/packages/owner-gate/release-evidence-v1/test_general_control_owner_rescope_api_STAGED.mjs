import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {handleGeneralControlRootRescopeSTAGED as handle}
 from './general_control_owner_rescope_api_STAGED.mjs';
import {signOwnerRescopeOnClickSTAGED as sign}
 from './general_control_owner_rescope_STAGED.mjs';
const now=Date.parse('2026-11-22T23:02:00.000Z');
const owner='123e4567-e89b-42d3-a456-426614174000';
const origin='https://batcave-linux-approval.vercel.app';
const ctx={owner_authenticated:true,owner_user_id:owner,origin};
const pair=await webcrypto.subtle.generateKey('Ed25519',false,['sign','verify']);
const raw=new Uint8Array(await webcrypto.subtle.exportKey('raw',pair.publicKey));
const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
const b64=b=>btoa(String.fromCharCode(...b)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
const hash=hex(new Uint8Array(await webcrypto.subtle.digest('SHA-256',raw)));
const root={owner_user_id:owner,public_key_sha256:hash,public_key_b64url:b64(raw),revoked_at:null};
const scoped={source_commit:'a'.repeat(40),policy_digest:'b'.repeat(64),current:true};
function fixture(){
 const s={prepared:null,state:'unused',endorsed:0,declined:0,policy:{...scoped},root:{...root}};
 const repo={
  getRoot:async id=>id===owner?s.root:null,
  getTrustedScopePolicy:async id=>id===owner?s.policy:null,
  reserve:async c=>{
    s.prepared=c;s.state='unused';
    return {reserved:true,challenge_id:c.challenge_id,nonce:c.nonce,state:'unused'};
  },
  getPrepared:async(id,cid)=>id===owner&&s.prepared?.challenge_id===cid?
    {challenge:s.prepared,state:s.state}:null,
  recordPending:async row=>{
    if(s.state!=='unused'||s.prepared?.challenge_id!==row.challenge_id ||
       s.prepared.nonce!==row.nonce)return {recorded:false};
    s.state='endorsed';s.endorsed++;
    return {recorded:true,challenge_id:row.challenge_id,
     state:'pending_independent_review'};
  },
  decline:async input=>{
    if(s.state!=='unused'||input.challenge_id!==s.prepared?.challenge_id||
       input.nonce!==s.prepared?.nonce)return {declined:false};
    s.state='declined';s.declined++;
    return {declined:true,challenge_id:input.challenge_id};
  }
 };
 return {repo,s};
}
const prepare={action:'general_control_root_rescope_prepare_v1'};
const endorse=evidence=>({action:'general_control_root_rescope_endorse_v1',evidence});
const decline=ch=>({action:'general_control_root_rescope_decline_v1',
 challenge_id:ch.challenge_id,nonce:ch.nonce});
async function start(f){
 const response=await handle(prepare,ctx,f.repo,now);
 assert.equal(response.status,200,JSON.stringify(response));
 return response.body;
}
async function signPrepared(response){
 const rootRecord=response.root,policy=response.policy;
 return sign({challenge:response.challenge,
  server:{owner_user_id:owner,authenticated:true,origin,root:rootRecord,...policy},
  getOwnerKey:()=>({privateKey:pair.privateKey,publicKeyB64:b64(raw)}),
  now,origin,consent:true});
}
test('authenticated owner prepare issues real scoped one-use root challenge, never grant',async()=>{
 const f=fixture(),r=await start(f);
 assert.equal(r.state,'AWAIT_EXPLICIT_OWNER_CLICK');
 assert.equal(r.challenge.owner_user_id,owner);
 assert.equal(r.challenge.root_key_sha256,hash);
 assert.equal(r.challenge.scope_public_key_hex,hex(raw));
 assert.equal(r.challenge.source_commit,scoped.source_commit);
 assert.equal(r.execution_authorized,false);
 assert.equal(r.deployment_authorized,false);
 assert.equal(f.s.endorsed,0);
});
test('existing key owner click admits only pending scope, not active permission',async()=>{
 const f=fixture(),prepared=await start(f);
 const evidence=await signPrepared(prepared);
 const response=await handle(endorse(evidence),ctx,f.repo,now);
 assert.equal(response.status,200,JSON.stringify(response));
 assert.equal(response.body.state,'pending_independent_review');
 assert.equal(response.body.independent_signature_recorded,false);
 assert.equal(response.body.execution_authorized,false);
 assert.equal(response.body.deployment_authorized,false);
 assert.equal(response.body.grant_issued,false);
 assert.equal(f.s.endorsed,1);
 assert.equal((await handle(endorse(evidence),ctx,f.repo,now)).status,409);
});
test('explicit owner No declines and cannot be endorsed afterward',async()=>{
 const f=fixture(),prepared=await start(f);
 const evidence=await signPrepared(prepared);
 const d=await handle(decline(prepared.challenge),ctx,f.repo,now);
 assert.equal(d.status,200);
 assert.equal(d.body.state,'declined');
 assert.equal(f.s.declined,1);
 assert.equal((await handle(endorse(evidence),ctx,f.repo,now)).status,409);
});
test('unauthenticated, wrong origin, wrong owner or supplied scope rejected',async()=>{
 const f=fixture();
 for(const alternative of [{...ctx,owner_authenticated:false},
   {...ctx,origin:'https://evil.example'},
   {...ctx,owner_user_id:'not-a-uuid'}]){
   const r=await handle(prepare,alternative,f.repo,now);
   assert.equal(r.status,401);
 }
 assert.equal((await handle({...prepare,scope:'host.shell'},ctx,f.repo,now)).status,422);
 assert.equal((await handle({action:'general_control_activate_key_v1'},ctx,f.repo,now)).status,400);
 assert.equal(f.s.prepared,null);
});
test('root revoke, wrong root fingerprint and missing current policy fail before reservation',async()=>{
 const f=fixture();
 f.s.root={...root,revoked_at:'2026-11-22T22:00:00.000Z'};
 assert.notEqual((await handle(prepare,ctx,f.repo,now)).status,200);
 f.s.root={...root,public_key_sha256:'0'.repeat(64)};
 assert.notEqual((await handle(prepare,ctx,f.repo,now)).status,200);
 f.s.root={...root};f.s.policy={...scoped,current:false};
 assert.notEqual((await handle(prepare,ctx,f.repo,now)).status,200);
 assert.equal(f.s.prepared,null);
});
test('policy/source changes, missing storage or replay all fail closed',async()=>{
 const f=fixture(),p=await start(f),evidence=await signPrepared(p);
 f.s.policy={...scoped,source_commit:'f'.repeat(40)};
 assert.equal((await handle(endorse(evidence),ctx,f.repo,now)).status,409);
 f.s.policy={...scoped,policy_digest:'e'.repeat(64)};
 assert.equal((await handle(endorse(evidence),ctx,f.repo,now)).status,409);
 f.s.policy={...scoped};
 f.repo.recordPending=null;
 assert.equal((await handle(endorse(evidence),ctx,f.repo,now)).status,503);
 assert.equal(f.s.endorsed,0);
});
test('forged evidence, grant flags, invalid signature or wrong nonce never admit',async()=>{
 const f=fixture(),p=await start(f),evidence=await signPrepared(p);
 for(const changed of [
  {...evidence,signature_hex:'0'.repeat(128)},
  {...evidence,nonce:'f'.repeat(32)},
  {...evidence,execution_authorized:true},
  {...evidence,extra:'grant'},
 ]){
  const r=await handle(endorse(changed),ctx,f.repo,now);
  assert.notEqual(r.status,200);
 }
 assert.equal(f.s.endorsed,0);
});
test('private repository failures and expired signature deny without writing',async()=>{
 const f=fixture(),p=await start(f),evidence=await signPrepared(p);
 f.repo.getPrepared=async()=>{throw Error('offline');};
 assert.equal((await handle(endorse(evidence),ctx,f.repo,now)).status,409);
 f.repo.getPrepared=async()=>({state:'unused',challenge:p.challenge});
 assert.equal((await handle(endorse(evidence),ctx,f.repo,now+400000)).status,409);
 assert.equal(f.s.endorsed,0);
});
