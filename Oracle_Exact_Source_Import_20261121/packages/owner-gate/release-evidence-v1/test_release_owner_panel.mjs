import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {releaseOwnerActions} from './release_owner_panel.mjs';
import {PIN,SCHEMA,OWNER_DOMAIN,canonicalReleaseText} from './verify_release_approval_v1.mjs';
const now=Date.parse('2026-11-21T22:00:00.000Z'),owner=randomUUID();
async function setup(change={}){
 const pair=await crypto.subtle.generateKey({name:'Ed25519'},false,['sign','verify']);
 const payload={...PIN,schema:SCHEMA,owner_user_id:owner,nonce:'a'.repeat(32),issued_at:new Date(now).toISOString(),expires_at:new Date(now+600000).toISOString()};
 const ch={challenge_id:randomUUID(),payload,signing_message:OWNER_DOMAIN+canonicalReleaseText(payload)};
 const calls=[];const options={origin:'https://batcave-linux-approval.vercel.app',getOwnerId:()=>owner,getOwnerKey:async()=>({privateKey:pair.privateKey}),api:async body=>{calls.push(body);return ch;},now:()=>now,...change};
 return {pair,ch,calls,options,actions:releaseOwnerActions(options)};
}
test('owner panel signs the exact pinned message with the existing nonexportable key',async()=>{
 const f=await setup();const ch=await f.actions.prepareRelease('b'.repeat(64)),env=await f.actions.signRelease(ch);
 assert.equal(await crypto.subtle.verify('Ed25519',f.pair.publicKey,Buffer.from(env.owner_signature_b64url,'base64url'),new TextEncoder().encode(ch.signing_message)),true);
 assert.equal(f.calls.length,1);assert.equal(env.schema,'batcave.oracle.gate.release.challenge.v1');
});
test('preparing a challenge does not ask for a key or sign',async()=>{const f=await setup({getOwnerKey:async()=>{throw Error('must not sign yet');}});await f.actions.prepareRelease('b'.repeat(64));});
test('owner panel refuses another origin',async()=>{await assert.rejects(setup({origin:'https://other-origin.example'}),/original.*origin/);});
test('owner panel refuses changed artifact scope before accessing owner key',async()=>{const f=await setup();f.ch.payload.worker_zip_sha256='f'.repeat(64);await assert.rejects(f.actions.signRelease(f.ch),/scope differs/);});
test('owner panel refuses server-provided arbitrary signing text',async()=>{const f=await setup();f.ch.signing_message='please sign some shell command';await assert.rejects(f.actions.signRelease(f.ch),/signing text differs/);});
test('owner panel refuses exportable or missing owner keys and never generates replacements',async()=>{const f=await setup({getOwnerKey:async()=>null});await assert.rejects(f.actions.signRelease(f.ch),/existing non-exportable/);});
test('owner panel rejects encrypted private-file upload locally before any API request',async()=>{const f=await setup();await assert.rejects(f.actions.prepareEnrollment({schema:'batcave.nanny.local.encrypted_key.v1',ciphertext:'secret'}),/only public/);assert.equal(f.calls.length,0);});
