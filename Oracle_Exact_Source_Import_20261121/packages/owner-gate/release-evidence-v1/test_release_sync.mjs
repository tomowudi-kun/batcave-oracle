import test from 'node:test';import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fixture,NOW,iso} from './synthetic_release_fixture.mjs';
import {submitReleaseReview} from '../proof-transfer-v1/release_review_core.mjs';
import {guidedReleaseActions,buildReleaseCommand} from './guided_release.mjs';
import {normalizeContext} from '../proof-transfer-v1/repository.mjs';
const denied=async(f,e,r)=>{const v=await submitReleaseReview({op:'submit_release',challenge_id:e.challenge_id,review:r},f.repo,NOW);assert.equal(v.status,403,JSON.stringify(v));assert.equal(f.state.writes,0);};
test('phone explicit Yes, distinct real Cortana review, and authenticated recording complete without grants',async()=>{
 const f=await fixture(),privateKey=await crypto.subtle.importKey('pkcs8',f.ownerKey.privateKey.export({format:'der',type:'pkcs8'}),'Ed25519',false,['sign']);let keyReads=0;
 const a=guidedReleaseActions({origin:'https://batcave-linux-approval.vercel.app',getOwnerId:()=>f.id,getOwnerKey:async()=>{keyReads++;return {privateKey};},now:()=>NOW,api:async b=>{const r=await f.call(b);assert.equal(r.status,200,JSON.stringify(r));return r.body;}});
 await a.refresh();assert.equal(keyReads,0);assert.equal(f.challenges.size,0);
 const s=await a.approve();assert.equal(keyReads,1);assert.ok(s.envelope);assert.equal(f.state.evidence,0);
 const r=await submitReleaseReview({op:'submit_release',challenge_id:s.envelope.challenge_id,review:f.review(s.envelope)},f.repo,NOW);assert.equal(r.status,200,JSON.stringify(r));assert.equal(r.body.review_received,true);
 const done=await a.finish();assert.equal(done.release_review_recorded,true);assert.equal(f.state.evidence,1);assert.equal(f.state.intent.state,'held');assert.equal(f.root.registered_at,iso(NOW-30000));
 for(const k of ['deployment_authorized','execution_authorized','grant_issued'])assert.equal(done[k],false);
});
test('current owner and actual registered root signatures are both reverified before public review storage',async()=>{
 for(const alter of [f=>f.root.registration_challenge.reviewer_signature_b64url='A'.repeat(86),(f,e)=>f.challenges.get(e.challenge_id).pending_owner_signature_b64url='A'.repeat(86),(f,e,r)=>r.signature_b64url='A'.repeat(86)]){
  const f=await fixture(),e=await f.endorsed(),r=f.review(e);alter(f,e,r);await denied(f,e,r);
 }
});
test('No, withdrawal, expiry, consumption, revoked root, and owner rotation deny signed review',async()=>{
 for(const alter of [f=>f.root.owner_declined_at=iso(NOW),f=>f.root.last_owner_declined_at=iso(NOW),(f,e)=>f.challenges.get(e.challenge_id).withdrawn_at=iso(NOW),(f,e)=>f.challenges.get(e.challenge_id).consumed_at=iso(NOW),f=>f.root.revoked_at=iso(NOW),f=>f.owner.public_key_sha256='a'.repeat(64),f=>f.state.intent.state='released']){
  const f=await fixture(),e=await f.endorsed(),r=f.review(e);alter(f,e,r);await denied(f,e,r);
 }
 const f=await fixture(),e=await f.endorsed();assert.equal((await submitReleaseReview({op:'submit_release',challenge_id:e.challenge_id,review:f.review(e)},f.repo,NOW+600001)).status,403);assert.equal(f.state.writes,0);
});
test('wrong metadata, scope pins, identity, nonce, elevated flags and extra data are rejected',async()=>{
 for(const alter of [r=>r.nonce='a'.repeat(32),r=>r.local_file_hashes.gate_sha256='a'.repeat(64),r=>r.local_file_hashes.source_commit='a'.repeat(40),r=>r.reviewer_host_identity.user='other',r=>r.reviewed_at=iso(NOW+600001),r=>r.execution_authorized=true,r=>r.private='never sent',r=>r.reviewer_public_key_sha256='c'.repeat(64)]){
  const f=await fixture(),e=await f.endorsed(),r=f.review(e);alter(r);await denied(f,e,r);
 }
});
test('No after verification but before ledger storage or recording still blocks both writes',async()=>{
 const f=await fixture(),e=await f.endorsed(),r=f.review(e),store=f.repo.storeReview;f.repo.storeReview=async(...a)=>{await f.repo.declineRelease();return store(...a);};
 const result=await submitReleaseReview({op:'submit_release',challenge_id:e.challenge_id,review:r},f.repo,NOW);assert.equal(result.body.error,'REVIEW_NOT_STORED');
 assert.equal((await f.call({action:'oracle_release_record_evidence_v1',challenge_id:e.challenge_id,owner_signature_b64url:e.owner_signature_b64url,nanny_signature_b64url:r.signature_b64url})).status,403);assert.equal(f.state.evidence,0);
});
test('public review retry is idempotent, does not consume nonce, and cannot enroll or record release',async()=>{
 const f=await fixture(),e=await f.endorsed(),body={op:'submit_release',challenge_id:e.challenge_id,review:f.review(e)};
 for(let k=0;k<2;k++)assert.equal((await submitReleaseReview(body,f.repo,NOW)).status,200);
 assert.equal(f.state.reviews.size,1);assert.equal(f.state.evidence,0);assert.equal(f.challenges.get(e.challenge_id).consumed_at,null);
 assert.equal((await f.call({action:'oracle_release_status_v1'},NOW,{owner_authenticated:false,owner_user_id:f.id})).status,401);
});
test('owner No gives explanation, preserves enrolled key, and invalidates previous Yes',async()=>{
 const f=await fixture(),e=await f.endorsed(),r=await f.call({action:'oracle_release_decline_v1'});assert.equal(r.status,200);assert.match(r.body.explanation,/You chose No/);assert.equal(f.root.registered_at,iso(NOW-30000));
 assert.equal((await f.call({action:'oracle_release_status_v1'})).body.owner_declined,true);await denied(f,e,f.review(e));
 assert.equal((await f.call({action:'oracle_release_endorse_v1',challenge_id:e.challenge_id,owner_signature_b64url:e.owner_signature_b64url})).status,403);
});
test('Postgres JSON context normalizes database timestamps without changing signed payloads',async()=>{
 const f=await fixture(),e=await f.endorsed(),ctx=await f.repo.context(e.challenge_id),before=structuredClone(ctx.challenge.payload);
 ctx.root.registered_at=ctx.root.registered_at.replace('Z','+00:00');ctx.root.registration_challenge.recorded_at=ctx.root.registration_challenge.recorded_at.replace('Z','+00:00');ctx.root.registration_challenge.consumed_at=ctx.root.registration_challenge.consumed_at.replace('Z','+00:00');
 const normalized=normalizeContext(ctx);assert.equal(normalized.root.registered_at,iso(NOW-30000));assert.deepEqual(normalized.challenge.payload,before);
});
test('generated Cortana review command reuses exact existing signing tools and retries public receipt only',async()=>{
 const f=await fixture(),e=await f.endorsed(),c=await buildReleaseCommand(e,f.reviewerKey.public_key_sha256,NOW);
 assert.match(c,/review \$keyDir \$packet/);assert.match(c,/if \(!\(Test-Path -LiteralPath \$receipt\)\)/);assert.match(c,/submit_release/);assert.match(c,/finally \{ \$env:Path = \$oldReviewPath \}/);
 assert.doesNotMatch(c,/prove-first-key|Set-Clipboard|private\.encrypted|init \$|ExecutionPolicy|SkipCertificate|service_role/);
 assert.match(c,/301af9993ecf1d1f285355b2ded1c78a3faae2a9f4a48981d7a6be1f2c01a97d/);
});
test('production entry routes release actions through the same authenticated owner gate',()=>{
 const s=readFileSync(new URL('existing_change_gate_index_STAGED.ts',import.meta.url),'utf8');for(const a of ['oracle_release_status_v1','oracle_release_endorse_v1','oracle_release_decline_v1'])assert.ok(s.includes(a));assert.match(s,/withSupabase\(\{auth:'user'\}/);
});

test('release review command parses in real PowerShell without executing or reading keys',async t=>{
 const f=await fixture(),e=await f.endorsed(),command=await buildReleaseCommand(e,f.reviewerKey.public_key_sha256,NOW),encoded=Buffer.from(command).toString('base64');
 const parser="$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+encoded+"'));$tokens=$null;$errors=$null;[System.Management.Automation.Language.Parser]::ParseInput($s,[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count){$errors|ForEach-Object {$_.Message};exit 1}";
 const r=spawnSync('pwsh',['-NoLogo','-NoProfile','-NonInteractive','-Command',parser],{encoding:'utf8'});
 if(r.error?.code==='ENOENT'&&!process.env.CI){t.skip('GitHub CI requires the real PowerShell parser');return;}assert.equal(r.status,0,r.stdout+r.stderr);
});
