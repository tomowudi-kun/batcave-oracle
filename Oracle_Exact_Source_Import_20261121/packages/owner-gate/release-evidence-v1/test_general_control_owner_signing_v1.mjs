import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto,createPublicKey,verify as nodeVerify} from 'node:crypto';
import {GENERAL_CONTROL_REQUEST_SCHEMA as REQUEST_SCHEMA,
  validateGeneralControlOwnerRequestV1 as validate} from '../src/general_control_owner_request_v1.mjs';
import {GENERAL_CONTROL_OWNER_CHALLENGE_SCHEMA as CHALLENGE_SCHEMA,
  GENERAL_CONTROL_OWNER_SIGNING_DOMAIN as DOMAIN,
  inspectGeneralControlOwnerChallengeV1 as inspect,
  signGeneralControlOwnerChallengeV1 as sign} from './general_control_owner_signing_v1.mjs';

const now=Date.parse('2026-11-22T20:50:00.000Z');
const userId='123e4567-e89b-42d3-a456-426614174000';
const key=await webcrypto.subtle.generateKey({name:'Ed25519'},false,['sign','verify']);
const pub=new Uint8Array(await webcrypto.subtle.exportKey('raw',key.publicKey));
const toHex=a=>Array.from(a,b=>b.toString(16).padStart(2,'0')).join('');
const toB64=a=>btoa(String.fromCharCode(...a)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
const saved={privateKey:key.privateKey,publicKeyB64:toB64(pub)};
const request={schema:REQUEST_SCHEMA,owner_user_id:userId,request_id:'123e4567-e89b-42d3-a456-426614174001',
  device:'Cortana',capability:'browser.observe',target_origin:'https://example.org',
  target_session_id:'browser-session-1',command_digest:'a'.repeat(64),source_commit:'b'.repeat(40),
  policy_digest:'c'.repeat(64),nonce:'d'.repeat(32),issued_at:'2026-11-22T20:49:00.000Z',
  expires_at:'2026-11-22T20:52:00.000Z',rollback_ref:'none'};
const trusted_binding=Object.fromEntries(['owner_user_id','device','target_origin','target_session_id',
  'command_digest','source_commit','policy_digest'].map(k=>[k,request[k]]));
const challenge={schema:CHALLENGE_SCHEMA,request,trusted_binding,
  scope_registration:{owner_user_id:userId,key_scope:'general_control_owner_v1',key_state:'active',
    key_hex:toHex(pub),revoked_at:null},
  signing_message:validate(request,trusted_binding,now).signing_message,nonce_state:'unused',
  execution_authorized:false,deployment_authorized:false};
const clone=(patch={})=>({...challenge,...patch});
const opts=(ch=challenge)=>({challenge:ch,ownerUserId:userId,getOwnerKey:async()=>saved,
  consent:true,now,origin:'https://batcave-linux-approval.vercel.app'});
test('read-only preview displays exact device/capability/browser scope and never authorizes',()=>{
  const p=inspect(challenge,userId,now);
  assert.equal(p.device,'Cortana');assert.equal(p.target_origin,'https://example.org');
  assert.equal(p.capability,'browser.observe');assert.equal(p.execution_authorized,false);
  assert.equal('signature_hex' in p,false);
});
test('explicit click signs domain-separated canonical bytes using nonexportable Ed25519',async()=>{
  const out=await sign(opts());
  assert.equal(out.execution_authorized,false);
  assert.equal(out.deployment_authorized,false);
  assert.equal(out.signature_hex.length,128);
  const spki=Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(pub)]);
  const pk=createPublicKey({key:spki,format:'der',type:'spki'});
  assert.equal(nodeVerify(null,Buffer.from(DOMAIN+challenge.signing_message),pk,
    Buffer.from(out.signature_hex,'hex')),true);
  assert.equal(nodeVerify(null,Buffer.from(challenge.signing_message),pk,
    Buffer.from(out.signature_hex,'hex')),false);
});
test('no explicit click, no key access or signature',async()=>{
  let called=0;
  await assert.rejects(sign({...opts(),consent:false,getOwnerKey:async()=>{called++;return saved;}}),/OWNER_CLICK_REQUIRED/);
  assert.equal(called,0);
});
test('wrong owner origin, stale nonce and expired challenge all refuse',async()=>{
  await assert.rejects(sign({...opts(),origin:'https://evil.example'}),/WRONG_OWNER_ORIGIN/);
  await assert.rejects(sign(opts(clone({nonce_state:'consumed'}))),/NONCE_NOT_AVAILABLE/);
  await assert.rejects(sign({...opts(),now:now+5*60000}),/INVALID_SCOPE_OR_WINDOW/);
});
test('scope registration must be active, new scope, same owner and not revoked',async()=>{
  for(const patch of [
    {key_scope:'fixed_trial_owner_v1'}, {key_state:'disabled'}, {owner_user_id:'other'},
    {revoked_at:'2026-11-21T00:00:00.000Z'},
  ])await assert.rejects(sign(opts(clone({scope_registration:{...challenge.scope_registration,...patch}}))),
    /GENERAL_SCOPE_KEY_NOT_REGISTERED/);
});
test('nonmatching local public key, extractable key, or missing signer refuses',async()=>{
  await assert.rejects(sign({...opts(),getOwnerKey:async()=>({...saved,publicKeyB64:toB64(new Uint8Array(32))})}),
    /SCOPE_REGISTERED_PUBLIC_KEY_MISMATCH/);
  const fake={type:'private',extractable:true,algorithm:{name:'Ed25519'},usages:['sign']};
  await assert.rejects(sign({...opts(),getOwnerKey:async()=>({...saved,privateKey:fake})}),
    /NONEXPORTABLE_KEY_REQUIRED/);
  await assert.rejects(sign({...opts(),getOwnerKey:null}),/LOCAL_KEY_PROVIDER_REQUIRED/);
});
test('modified command, wrong session/device binding, or changed signing text refuses',async()=>{
  await assert.rejects(sign(opts(clone({request:{...request,command_digest:'e'.repeat(64)}}))),/INVALID_SCOPE_OR_WINDOW/);
  await assert.rejects(sign(opts(clone({request:{...request,target_session_id:'other-session-99'}}))),/INVALID_SCOPE_OR_WINDOW/);
  await assert.rejects(sign(opts(clone({trusted_binding:{...trusted_binding,device:'Oracle'}}))),/INVALID_SCOPE_OR_WINDOW/);
  await assert.rejects(sign(opts(clone({signing_message:challenge.signing_message+'x'}))),/SIGNING_BYTES_MISMATCH/);
});
test('cannot slip in grant flags, extra fields, or arbitrary privileged capability',async()=>{
  await assert.rejects(sign(opts(clone({execution_authorized:true}))),/INVALID_CHALLENGE_SHAPE/);
  await assert.rejects(sign(opts(clone({extra:'grant'}))),/INVALID_CHALLENGE_SHAPE/);
  await assert.rejects(sign(opts(clone({request:{...request,capability:'host.shell'}}))),/INVALID_SCOPE_OR_WINDOW/);
});
