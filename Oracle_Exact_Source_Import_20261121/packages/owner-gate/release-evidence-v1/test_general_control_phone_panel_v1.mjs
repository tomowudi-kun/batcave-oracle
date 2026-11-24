import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto,createPublicKey,verify} from 'node:crypto';
import {mountGeneralControlPhonePanelV1 as mount} from './general_control_phone_panel_v1.mjs';
import {GENERAL_CONTROL_OWNER_CHALLENGE_SCHEMA as CHALLENGE_SCHEMA,
  GENERAL_CONTROL_OWNER_SIGNING_DOMAIN as DOMAIN} from './general_control_owner_signing_v1.mjs';
import {GENERAL_CONTROL_REQUEST_SCHEMA as REQUEST_SCHEMA,
  validateGeneralControlOwnerRequestV1 as validate} from '../src/general_control_owner_request_v1.mjs';

const origin='https://batcave-linux-approval.vercel.app';
const now=Date.parse('2026-11-22T20:55:00.000Z');
const userId='123e4567-e89b-42d3-a456-426614174000';
const key=await webcrypto.subtle.generateKey({name:'Ed25519'},false,['sign','verify']);
const pub=new Uint8Array(await webcrypto.subtle.exportKey('raw',key.publicKey));
const hex=a=>Array.from(a,b=>b.toString(16).padStart(2,'0')).join('');
const b64url=a=>btoa(String.fromCharCode(...a)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
const request={schema:REQUEST_SCHEMA,owner_user_id:userId,
  request_id:'123e4567-e89b-42d3-a456-426614174001',device:'Cortana',
  capability:'browser.observe',target_origin:'https://example.org',
  target_session_id:'browser-session-1',command_digest:'a'.repeat(64),
  source_commit:'b'.repeat(40),policy_digest:'c'.repeat(64),nonce:'d'.repeat(32),
  issued_at:'2026-11-22T20:54:00.000Z',expires_at:'2026-11-22T20:57:00.000Z',
  rollback_ref:'none'};
const binding=Object.fromEntries(
  ['owner_user_id','device','target_origin','target_session_id','command_digest',
    'source_commit','policy_digest'].map(k=>[k,request[k]]));
const challenge={schema:CHALLENGE_SCHEMA,request, trusted_binding:binding,
  scope_registration:{owner_user_id:userId,key_scope:'general_control_owner_v1',
    key_state:'active',key_hex:hex(pub),revoked_at:null},
  signing_message:validate(request,binding,now).signing_message,
  nonce_state:'unused',execution_authorized:false,deployment_authorized:false};
const saved={privateKey:key.privateKey,publicKeyB64:b64url(pub)};
class FakeElement {
  constructor(tag){this.tag=tag;this.children=[];this.disabled=false;this.textContent='';this.onclick=null;}
  append(...children){this.children.push(...children);}
}
const makeDocument=()=>({createElement(tag){return new FakeElement(tag);}});
const ownerReceipt={
  schema:'batcave.general_control.owner_evidence_receipt.v1',
  owner_user_id:userId,request_id:request.request_id,nonce:request.nonce,
  state:'owner_signature_recorded_only',execution_authorized:false,deployment_authorized:false,
};
const declinedReceipt={...ownerReceipt,schema:'batcave.general_control.owner_decline_receipt.v1',
  state:'declined'};
function fixture(patch={}){
  const root=new FakeElement('div');
  const calls={prepare:0,record:0,decline:0,key:0};
  const options={
    root,doc:makeDocument(),origin,
    getOwnerId:()=>userId,
    getOwnerKey:async()=>{calls.key++;return saved;},
    prepareChallenge:async()=>{calls.prepare++;return challenge;},
    recordOwnerEvidence:async()=>{calls.record++;return ownerReceipt;},
    declineChallenge:async()=>{calls.decline++;return declinedReceipt;},
    now:()=>now,
    ...patch,
  };
  return {root,calls,options,ui:mount(options)};
}
test('initial panel is inert and cannot sign without reviewing server scope',async()=>{
  const f=fixture();
  assert.equal(f.ui.phase,'NOT_READY');
  assert.equal(f.ui.yes.disabled,true);
  assert.equal(f.ui.no.disabled,true);
  await f.ui.yes.onclick();
  assert.equal(f.calls.key,0);
  assert.equal(f.calls.record,0);
});
test('valid server challenge makes explicit Yes/No available and shows every important field',async()=>{
  const f=fixture();
  await f.ui.review.onclick();
  assert.equal(f.ui.phase,'READY');
  assert.equal(f.ui.yes.disabled,false);
  assert.equal(f.ui.no.disabled,false);
  for(const fragment of ['Cortana','browser.observe','https://example.org',
    request.command_digest,request.policy_digest,request.rollback_ref,
    request.target_session_id,request.expires_at]){
    assert.ok(f.ui.details.textContent.includes(fragment),fragment);
  }
  assert.equal(f.calls.key,0);
});
test('explicit Yes signs exact scope and records owner evidence, never a grant',async()=>{
  const pk=createPublicKey({key:Buffer.concat([
    Buffer.from('302a300506032b6570032100','hex'),Buffer.from(pub)]),
    format:'der',type:'spki'});
  let submitted;
  const f=fixture({recordOwnerEvidence:async envelope=>{
    submitted=envelope;
    assert.equal(envelope.execution_authorized,false);
    assert.equal(envelope.deployment_authorized,false);
    assert.equal(verify(null,Buffer.from(DOMAIN+challenge.signing_message),pk,
      Buffer.from(envelope.signature_hex,'hex')),true);
    return ownerReceipt;
  }});
  await f.ui.review.onclick();
  await f.ui.yes.onclick();
  assert.equal(submitted.request_id,request.request_id);
  assert.equal(f.ui.phase,'AWAIT_INDEPENDENT_REVIEW');
  assert.ok(f.ui.status.textContent.includes('HELD'));
  assert.equal(f.ui.yes.disabled,true);
  assert.equal('privateKey' in submitted,false);
});
test('No sends decline and signs nothing',async()=>{
  const f=fixture();
  await f.ui.review.onclick();
  await f.ui.no.onclick();
  assert.equal(f.ui.phase,'DECLINED');
  assert.equal(f.calls.decline,1);
  assert.equal(f.calls.key,0);
  assert.equal(f.calls.record,0);
});
test('wrong original owner origin or missing authenticated server routes fail at mount',()=>{
  assert.throws(()=>fixture({origin:'https://example.org'}),/WRONG_ORIGIN/);
  assert.throws(()=>fixture({recordOwnerEvidence:null}),/RECORD_EVIDENCE_REQUIRED/);
  assert.throws(()=>fixture({declineChallenge:null}),/DECLINE_CHALLENGE_REQUIRED/);
});
test('invalid, expired or mismatched challenge cannot enable Yes',async()=>{
  for(const patch of [
    {nonce_state:'consumed'},
    {scope_registration:{...challenge.scope_registration,key_scope:'fixed_trial'}},
    {signing_message:challenge.signing_message+'tampered'},
    {request:{...request,device:'Oracle'}},
  ]){
    const f=fixture({prepareChallenge:async()=>({...challenge,...patch})});
    await f.ui.review.onclick();
    assert.equal(f.ui.yes.disabled,true);
    assert.equal(f.ui.phase,'NOT_READY');
    assert.equal(f.calls.key,0);
  }
  const expired=fixture({now:()=>now+4*60000});
  await expired.ui.review.onclick();
  assert.equal(expired.ui.yes.disabled,true);
});
test('wrong or forged server receipt never claims acceptance; no automatic re-sign',async()=>{
  const f=fixture({recordOwnerEvidence:async()=>({...ownerReceipt,execution_authorized:true})});
  await f.ui.review.onclick();
  await f.ui.yes.onclick();
  assert.equal(f.ui.phase,'VERIFY_BEFORE_RETRY');
  assert.equal(f.ui.yes.disabled,true);
  assert.equal(f.calls.key,1);
  await f.ui.yes.onclick();
  assert.equal(f.calls.key,1);
});
test('server errors and decline errors remain fail-closed',async()=>{
  const failLoad=fixture({prepareChallenge:async()=>{throw Error('network');}});
  await failLoad.ui.review.onclick();
  assert.equal(failLoad.ui.phase,'NOT_READY');
  assert.equal(failLoad.ui.yes.disabled,true);
  const failDecline=fixture({declineChallenge:async()=>({...declinedReceipt,state:'unknown'})});
  await failDecline.ui.review.onclick();
  await failDecline.ui.no.onclick();
  assert.equal(failDecline.ui.phase,'VERIFY_BEFORE_RETRY');
  assert.equal(failDecline.calls.key,0);
});
