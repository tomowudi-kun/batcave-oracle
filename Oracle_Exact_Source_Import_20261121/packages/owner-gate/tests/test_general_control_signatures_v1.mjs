import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {checkGeneralControlSignaturesV1 as check} from '../src/general_control_signatures_v1.mjs';
import {GENERAL_CONTROL_REQUEST_SCHEMA as SCHEMA,validateGeneralControlOwnerRequestV1 as validate}
  from '../src/general_control_owner_request_v1.mjs';
const now=Date.parse('2026-11-22T19:05:00.000Z');
const keys=()=>{const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  return {privateKey,hex:publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex')};};
const owner=keys(),nanny=keys(),lab=keys();
const req={schema:SCHEMA,owner_user_id:'123e4567-e89b-42d3-a456-426614174000',
  request_id:'123e4567-e89b-42d3-a456-426614174001',device:'Cortana',capability:'browser.observe',
  target_origin:'https://example.org',target_session_id:'browser-session-1',command_digest:'a'.repeat(64),
  source_commit:'b'.repeat(40),policy_digest:'c'.repeat(64),nonce:'d'.repeat(32),
  issued_at:'2026-11-22T19:04:00.000Z',expires_at:'2026-11-22T19:07:00.000Z',rollback_ref:'none'};
const binding=Object.fromEntries(['owner_user_id','device','target_origin','target_session_id',
  'command_digest','source_commit','policy_digest'].map(k=>[k,req[k]]));
const context={
  binding,
  owner:{authenticated:true,owner_user_id:req.owner_user_id,key_scope:'general_control_owner_v1',
    key_state:'active',identity_id:'owner-1',key_hex:owner.hex},
  reviewer:{independently_attested:true,key_scope:'general_control_privileged_reviewer_v1',
    key_state:'active',identity_id:'nanny-1',key_hex:nanny.hex},
  ledger:{nonce_state:'unused',request_id:req.request_id,nonce:req.nonce},
  policy:{current:true,digest:req.policy_digest,source_commit:req.source_commit,capability_allowed:true},
};
const signature=(key,prefix,message)=>sign(null,Buffer.from(prefix+message),key.privateKey).toString('hex');
const msg=validate(req,binding,now).signing_message;
const signatures={owner:signature(owner,'BATCAVE_OWNER_GENERAL_CONTROL_V1\n',msg),
  reviewer:signature(nanny,'BATCAVE_NANNY_GENERAL_CONTROL_V1\n',msg)};
const run=(r=req,c=context,s=signatures,t=now)=>check(r,c,s,t);
const denies=(r,c,s,t)=>assert.equal(run(r,c,s,t).status,'DENY');
test('two independently scoped Ed25519 signatures verify but never grant execution',()=>{
  const r=run();assert.equal(r.status,'SIGNATURES_VALID_ONLY');assert.equal(r.execution_authorized,false);
  assert.equal(r.deployment_authorized,false);assert.equal('grant' in r,false);
});
test('owner absent, unscoped, unauthenticated or wrong identity denies',()=>{
  denies(req,{...context,owner:{...context.owner,authenticated:false}},signatures);
  denies(req,{...context,owner:{...context.owner,key_scope:'fixed_trial'}},signatures);
  denies(req,{...context,owner:{...context.owner,owner_user_id:'other'}},signatures);
});
test('independent Nanny missing, lab key or same owner identity denies',()=>{
  denies(req,{...context,reviewer:{...context.reviewer,independently_attested:false}},signatures);
  denies(req,{...context,reviewer:{...context.reviewer,key_scope:'lab_reviewer_only',key_hex:lab.hex}},signatures);
  denies(req,{...context,reviewer:{...context.reviewer,identity_id:'owner-1'}},signatures);
  denies(req,{...context,reviewer:{...context.reviewer,key_hex:owner.hex}},signatures);
});
test('tampered signatures and role swaps deny',()=>{
  denies(req,context,{...signatures,owner:signatures.reviewer});
  denies(req,context,{...signatures,reviewer:signatures.owner});
  denies(req,context,{...signatures,owner:'0'.repeat(128)});
  denies(req,context,{...signatures,reviewer:'not-hex'});
  denies(req,context,{owner:signatures.owner});
});
test('signed data changed, including target session or digest, denies',()=>{
  denies({...req,target_session_id:'other-session-99'},context,signatures);
  denies({...req,command_digest:'e'.repeat(64)},context,signatures);
  denies({...req,nonce:'e'.repeat(32)},context,signatures);
});
test('server binding, current policy and source pin required',()=>{
  denies(req,{...context,binding:{...binding,target_session_id:'other-session-99'}},signatures);
  denies(req,{...context,policy:{...context.policy,current:false}},signatures);
  denies(req,{...context,policy:{...context.policy,capability_allowed:false}},signatures);
  denies(req,{...context,policy:{...context.policy,source_commit:'e'.repeat(40)}},signatures);
});
test('used nonce, wrong request or expired request deny',()=>{
  denies(req,{...context,ledger:{...context.ledger,nonce_state:'used'}},signatures);
  denies(req,{...context,ledger:{...context.ledger,request_id:'other'}},signatures);
  denies(req,context,signatures,Date.parse('2026-11-22T19:08:00.000Z'));
});
test('caller cannot provide fake reviewer key in signature envelope',()=>{
  denies(req,context,{...signatures,reviewer_key_hex:lab.hex});
  denies(req,{},signatures);
  denies(req,context,null);
});
