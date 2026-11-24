import test from 'node:test';
import assert from 'node:assert/strict';
import {validateGeneralControlOwnerRequestV1 as validate, GENERAL_CONTROL_REQUEST_SCHEMA as SCHEMA}
  from '../src/general_control_owner_request_v1.mjs';
const now = Date.parse('2026-11-22T19:05:00.000Z');
const id = '123e4567-e89b-42d3-a456-426614174000';
const request = Object.freeze({
  schema:SCHEMA,owner_user_id:id,request_id:'123e4567-e89b-42d3-a456-426614174001',
  device:'Cortana',capability:'browser.observe',target_origin:'https://example.org',
  target_session_id:'browser-session-1',command_digest:'a'.repeat(64),
  source_commit:'b'.repeat(40),policy_digest:'c'.repeat(64),nonce:'d'.repeat(32),
  issued_at:'2026-11-22T19:04:00.000Z',expires_at:'2026-11-22T19:07:00.000Z',rollback_ref:'none',
});
const trusted = Object.freeze({owner_user_id:request.owner_user_id,device:request.device,
  target_origin:request.target_origin,target_session_id:request.target_session_id,
  command_digest:request.command_digest,source_commit:request.source_commit,
  policy_digest:request.policy_digest});
const go=(patch={},bind=trusted,clock=now)=>validate({...request,...patch},bind,clock);
const denied=(patch,bind=trusted,clock=now)=>assert.throws(()=>go(patch,bind,clock),/^Error: GENERAL_CONTROL_REQUEST_/);

test('canonical signing bytes are deterministic despite input property order and never authorize',()=>{
  const a=go(); const b=validate(Object.fromEntries(Object.entries(request).reverse()),trusted,now);
  assert.equal(a.signing_message,b.signing_message);
  assert.deepEqual(a.signing_bytes,b.signing_bytes);
  assert.equal(a.execution_authorized,false);assert.equal(a.deployment_authorized,false);
  assert.equal(a.signature_verified,false);
  assert.match(a.signing_message,/^batcave\.general_control\.owner_request\.v1\n\{/);
});
test('extra/missing/prototype-polluting fields and missing trusted context denied',()=>{
  denied({unreviewed_command:'powershell'});
  const missing={...request};delete missing.policy_digest;
  assert.throws(()=>validate(missing,trusted,now),/BAD_REQUEST_SHAPE/);
  assert.throws(()=>validate(request,request,now),/TRUSTED_BINDING_REQUIRED/);
  assert.throws(()=>validate(request,{},now),/TRUSTED_BINDING_REQUIRED/);
  const polluted=JSON.parse(JSON.stringify(request).replace('"schema"','"__proto__":{},"schema"'));
  assert.throws(()=>validate(polluted,trusted,now),/BAD_REQUEST_SHAPE/);
});
test('unsupported device and capabilities (shell, credential access, admin) denied',()=>{
  for(const p of [{device:'Linux'},{device:'*'},{capability:'shell'},{capability:'host.admin'},
    {capability:'browser.cookies'},{capability:'browser.upload_unreviewed'}]) denied(p);
});
test('browser origin must be exact HTTPS origin; host uses null origin',()=>{
  for(const x of ['http://example.org','https://example.org/path','https://user:pw@example.org',
    'https://example.org?x=1','https://*.example.org','https://example.org/','javascript:alert(1)']) denied({target_origin:x});
  const host={...request,capability:'host.read',target_origin:null};
  const b={...trusted,target_origin:null};
  assert.equal(validate(host,b,now).execution_authorized,false);
  assert.throws(()=>validate({...host,target_origin:'https://example.org'},b,now),/INVALID_TARGET_ORIGIN/);
});
test('session, owner, policy, command, source hash and nonces must match exact trusted binding',()=>{
  for(const key of ['owner_user_id','device','target_origin','target_session_id','command_digest','source_commit','policy_digest']){
    const replacement=key==='target_origin'?'https://example.com':key==='owner_user_id'?'123e4567-e89b-42d3-a456-426614174002':key==='device'?'Oracle':key==='target_session_id'?'other-session-99':key==='source_commit'?'e'.repeat(40):'e'.repeat(64);
    assert.throws(()=>validate({...request,[key]:replacement},trusted,now),/GENERAL_CONTROL_REQUEST_/);
  }
  for(const p of [{target_session_id:'*'},{target_session_id:''},{nonce:'not-a-nonce'},
    {request_id:'bad'},{policy_digest:'A'.repeat(64)},{source_commit:'b'.repeat(39)}]) denied(p);
});
test('mutation capabilities require a bounded rollback reference',()=>{
  for(const capability of ['host.write_reversible','browser.click','browser.type']){
    denied({capability});
    const host=capability.startsWith('host.');
    const p={...request,capability,target_origin:host?null:request.target_origin,rollback_ref:'rollback:'+'f'.repeat(64)};
    const b={...trusted,target_origin:host?null:trusted.target_origin};
    assert.equal(validate(p,b,now).execution_authorized,false);
  }
  denied({rollback_ref:'rollback:'+'f'.repeat(64)});
});
test('request freshness, replay window bounds and UTC format enforced',()=>{
  denied({expires_at:'2026-11-22T19:04:59.000Z'});
  denied({issued_at:'2026-11-22T19:05:31.000Z'});
  denied({issued_at:'2026-11-22T18:59:59.000Z'});
  denied({expires_at:'2026-11-22T19:10:00.000Z'});
  denied({issued_at:'2026-11-22T19:04:00Z'});
  denied({issued_at:'2026-02-30T19:04:00.000Z'});
  denied({},trusted,NaN);
});
test('validator is not signer, replay ledger or independent approval',()=>{
  const a=go();
  assert.deepEqual(Object.keys(a).sort(),['deployment_authorized','execution_authorized','signature_verified','signing_bytes','signing_message']);
  assert.equal('grant' in a,false);assert.equal('lease' in a,false);
});
