import test from 'node:test';
import assert from 'node:assert/strict';
import {createGeneralControlPasteFallbackV1 as make,parseGeneralControlPasteFallbackV1 as parse} from '../src/general_control_paste_fallback_v1.mjs';
const now=Date.parse('2026-11-22T19:05:00.000Z');
const r={schema:'batcave.general_control.owner_request.v1',owner_user_id:'123e4567-e89b-42d3-a456-426614174000',request_id:'123e4567-e89b-42d3-a456-426614174001',device:'Cortana',capability:'browser.observe',target_origin:'https://example.org',target_session_id:'browser-session-1',command_digest:'a'.repeat(64),source_commit:'b'.repeat(40),policy_digest:'c'.repeat(64),nonce:'d'.repeat(32),issued_at:'2026-11-22T19:04:00.000Z',expires_at:'2026-11-22T19:07:00.000Z',rollback_ref:'none'};
const trusted=Object.fromEntries(['owner_user_id','device','target_origin','target_session_id','command_digest','source_commit','policy_digest'].map(k=>[k,r[k]]));
test('fallback roundtrips to same canonical signing message and remains non-authorizing',()=>{
 const x=make(r,trusted,now); const y=parse(x.paste,trusted,now);
 assert.deepEqual(y.request,r);assert.equal(x.execution_authorized,false);assert.equal(y.execution_authorized,false);
 assert.equal(y.signature_verified,false);assert.match(x.instruction,/Do not run it in a terminal/);
});
test('fallback canonical despite reordered source object',()=>assert.equal(make(r,trusted,now).paste,make(Object.fromEntries(Object.entries(r).reverse()),trusted,now).paste));
test('changed device, session, origin, command, source, policy cannot cross trusted binding',()=>{
 for(const k of ['device','target_session_id','target_origin','command_digest','source_commit','policy_digest']){
  const changed={...r,[k]:k==='device'?'Oracle':k==='target_origin'?'https://elsewhere.org':k==='target_session_id'?'other-session-1':k==='source_commit'?'e'.repeat(40):'e'.repeat(64)};
  assert.throws(()=>make(changed,trusted,now));
  const text='BATCAVE_GENERAL_CONTROL_REQUEST_V1 '+Buffer.from(JSON.stringify(changed)).toString('base64url');
  assert.throws(()=>parse(text,trusted,now));
 }
});
test('rejects malformed, appended, noncanonical, and oversized paste text',()=>{
 const x=make(r,trusted,now).paste;
 for(const s of ['',x+';',x+' ',x+'\nrm -rf /','echo '+x,'BATCAVE_GENERAL_CONTROL_REQUEST_V1 @@','BATCAVE_GENERAL_CONTROL_REQUEST_V1 '+'a'.repeat(4096)]) assert.throws(()=>parse(s,trusted,now));
});
test('rejects extra fields and invalid JSON',()=>{
 const bad={...r,exec:'whoami'};
 for(const body of [JSON.stringify(bad),'{oops',JSON.stringify([r])]){
  assert.throws(()=>parse('BATCAVE_GENERAL_CONTROL_REQUEST_V1 '+Buffer.from(body).toString('base64url'),trusted,now));
 }
});
test('expired fallback cannot be replayed even if originally valid',()=>{
 const x=make(r,trusted,now);assert.throws(()=>parse(x.paste,trusted,Date.parse('2026-11-22T19:07:01.000Z')));
});
test('fallback never contains a runnable shell command or bypasses signature approval',()=>{
 const x=make(r,trusted,now);assert.ok(x.paste.startsWith('BATCAVE_GENERAL_CONTROL_REQUEST_V1 '));
 assert.equal('grant' in x,false);assert.equal('shell' in x,false);assert.equal('approved' in parse(x.paste,trusted,now),false);
});
