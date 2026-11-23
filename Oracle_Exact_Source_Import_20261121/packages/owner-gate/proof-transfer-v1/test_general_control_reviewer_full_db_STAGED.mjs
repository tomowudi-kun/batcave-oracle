/* Disposable PostgreSQL, synthetic keys: owner-click -> atomic owner receipt
 * -> separately authenticated reviewer Ed25519 -> atomic reviewer receipt.
 * There is NEVER a release, delegation or executable device grant.
 */
import test,{before,after,beforeEach} from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto,generateKeyPairSync,sign as edSign} from 'node:crypto';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {readFileSync} from 'node:fs';
import postgres from 'postgres';
import {createGeneralControlPrivateRepositorySTAGED as ownerRepository}
 from '../release-evidence-v1/general_control_private_repository_STAGED.mjs';
import {handleGeneralControlOwnerApiV1 as handleOwner}
 from '../release-evidence-v1/general_control_owner_api_STAGED.mjs';
import {signGeneralControlOwnerChallengeV1 as ownerSign}
 from '../release-evidence-v1/general_control_owner_signing_v1.mjs';
import {makeGeneralControlReviewerReadSTAGED as reviewerRead}
 from '../release-evidence-v1/general_control_reviewer_read_STAGED.mjs';
import {makeGeneralControlReviewerPrivateRepoSTAGED as reviewerRepository}
 from '../release-evidence-v1/general_control_reviewer_private_repo_STAGED.mjs';
import {handleIndependentGeneralControlReviewerSTAGED as handleReviewer}
 from '../release-evidence-v1/general_control_reviewer_api_STAGED.mjs';

const url=process.env.BATCAVE_TEST_DATABASE_URL;
if(typeof url!=='string')throw Error('TEST_DB_REQUIRED');
const u=new URL(url);
if(!['localhost','127.0.0.1','::1'].includes(u.hostname)||
   u.pathname!=='/release_gate_test')throw Error('REFUSE_NONDISPOSABLE_DATABASE');
const sql=postgres(url,{prepare:false,max:8});
const dirnameHere=dirname(fileURLToPath(import.meta.url));
const sibling=resolve(dirnameHere,'../release-evidence-v1');
const owner='123e4567-e89b-42d3-a456-426614174000';
const reviewer='123e4567-e89b-42d3-a456-426614174009';
const origin='https://batcave-linux-approval.vercel.app';
const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
const b64=b=>btoa(String.fromCharCode(...b)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
const ownerKeys=await webcrypto.subtle.generateKey('Ed25519',false,['sign','verify']);
const ownerPublic=new Uint8Array(await webcrypto.subtle.exportKey('raw',ownerKeys.publicKey));
const reviewerKeys=generateKeyPairSync('ed25519');
const reviewerHex=reviewerKeys.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');
const hostHash='e'.repeat(64);
const trustedScope={device:'Oracle',capability:'host.read',target_origin:null,
 target_session_id:'oracle-session-1',command_digest:'a'.repeat(64),
 source_commit:'b'.repeat(40),policy_digest:'c'.repeat(64),rollback_ref:'none'};
const ctx={owner_user_id:owner,owner_authenticated:true,origin};
const reviewerSession={reviewer_authenticated:true,protected_reviewer_session_verified:true,
 independent_identity_verified:true,reviewer_identity_id:reviewer,host_identity_sha256:hostHash};
const ownerReg={owner_user_id:owner,key_scope:'general_control_owner_v1',
 key_state:'active',key_hex:hex(ownerPublic),revoked_at:null};
const reg={identity_id:reviewer,key_hex:reviewerHex,independently_attested:true,
 production_release_authorized:true,key_state:'active',
 key_scope:'general_control_privileged_reviewer_v1',
 host_identity_sha256:hostHash,revoked_at:null,
 valid_until:new Date(Date.now()+24*3600*1000).toISOString()};
const ownerRepo=ownerRepository(sql,{
 getTrustedPendingScope:async()=>({...trustedScope}),
 getTrustedCurrentScope:async()=>({...trustedScope}),
 getRegisteredOwnerKey:async()=>({...ownerReg}),
});
const state={policy:{current:true,capability_allowed:true,digest:trustedScope.policy_digest,
 source_commit:trustedScope.source_commit},reviewer:{...reg}};
const reviewerRepo=reviewerRepository(sql,{getTrustedPreparedReview:reviewerRead(sql)});
const services={
 repository:reviewerRepo,
 getReviewerRegistration:async()=>state.reviewer,
 getCurrentPolicy:async()=>state.policy,
 getTrustedBinding:async()=>({
   owner_user_id:owner,device:trustedScope.device,target_origin:trustedScope.target_origin,
   target_session_id:trustedScope.target_session_id,command_digest:trustedScope.command_digest,
   source_commit:trustedScope.source_commit,policy_digest:trustedScope.policy_digest,
 }),
};
const ownerAction={action:'general_control_prepare_owner_v1'};
async function ownerStart(){
 const now=Date.now();
 const prepared=await handleOwner(ownerAction,ctx,ownerRepo,now);
 assert.equal(prepared.status,200,JSON.stringify(prepared));
 return prepared.body;
}
async function ownerYes(prepared){
 const evidence=await ownerSign({challenge:prepared,ownerUserId:owner,
  getOwnerKey:async()=>({privateKey:ownerKeys.privateKey,publicKeyB64:b64(ownerPublic)}),
  consent:true,now:Date.now(),origin});
 const result=await handleOwner({action:'general_control_record_owner_v1',evidence},
  ctx,ownerRepo,Date.now());
 assert.equal(result.status,200,JSON.stringify(result));
 return evidence;
}
function reviewerEvidence(prepared){
 const message='BATCAVE_NANNY_GENERAL_CONTROL_V1\n'+prepared.signing_message;
 return {action:'general_control_independent_reviewer_record_v1',
  request_id:prepared.request.request_id,
  signature_hex:edSign(null,Buffer.from(message),reviewerKeys.privateKey).toString('hex')};
}
before(async()=>{
 for(const name of ['general_control_nonce_ledger_STAGED.sql',
  'general_control_owner_evidence_atomic_STAGED.sql',
  'general_control_challenge_repository_STAGED.sql',
  'general_control_reviewer_evidence_atomic_STAGED.sql']){
  await sql.unsafe(readFileSync(resolve(sibling,name),'utf8'));
 }
});
beforeEach(async()=>{
 await sql.unsafe('TRUNCATE batcave.general_control_reviewer_evidence_staged_v1, batcave.general_control_owner_evidence_staged_v1, batcave.general_control_prepared_challenges_staged_v1, batcave.general_control_nonce_ledger_v1 CASCADE');
 state.policy={current:true,capability_allowed:true,digest:trustedScope.policy_digest,
  source_commit:trustedScope.source_commit};
 state.reviewer={...reg};
});
after(async()=>{await sql.end({timeout:2});});
test('actual owner and independent reviewer signatures produce two durable receipts, zero grants',async()=>{
 const prepared=await ownerStart();
 await ownerYes(prepared);
 const body=reviewerEvidence(prepared);
 const result=await handleReviewer(body,reviewerSession,services,Date.now());
 assert.equal(result.status,200,JSON.stringify(result));
 assert.equal(result.body.state,'reviewer_signature_recorded_only');
 assert.equal(result.body.privileged_release_signature_recorded,false);
 assert.equal(result.body.execution_authorized,false);
 assert.equal(result.body.deployment_authorized,false);
 const rows=await sql`SELECT r.state, r.reviewer_identity_id,
  r.execution_authorized,r.deployment_authorized,o.state AS owner_state
  FROM batcave.general_control_reviewer_evidence_staged_v1 r
  JOIN batcave.general_control_owner_evidence_staged_v1 o
   ON o.request_id=r.request_id`;
 assert.equal(rows.length,1);
 assert.equal(rows[0].owner_state,'owner_signature_recorded_only');
 assert.equal(rows[0].state,'reviewer_signature_recorded_only');
 assert.equal(rows[0].reviewer_identity_id,reviewer);
 assert.equal(rows[0].execution_authorized,false);
 assert.equal(rows[0].deployment_authorized,false);
 assert.equal((await handleReviewer(body,reviewerSession,services,Date.now())).status,409);
});
test('reviewer cannot sign absent durable owner receipt',async()=>{
 const prepared=await ownerStart();
 const response=await handleReviewer(reviewerEvidence(prepared),reviewerSession,services,Date.now());
 assert.equal(response.status,409);
 const rows=await sql`SELECT count(*)::int AS count
   FROM batcave.general_control_reviewer_evidence_staged_v1`;
 assert.equal(rows[0].count,0);
});
test('changed active policy, revoked identity and invalid signature all refuse',async()=>{
 const prepared=await ownerStart();await ownerYes(prepared);
 const good=reviewerEvidence(prepared);
 state.policy={...state.policy,digest:'f'.repeat(64)};
 assert.equal((await handleReviewer(good,reviewerSession,services,Date.now())).status,409);
 state.policy={current:true,capability_allowed:true,digest:trustedScope.policy_digest,
  source_commit:trustedScope.source_commit};
 state.reviewer={...reg,revoked_at:new Date().toISOString()};
 assert.equal((await handleReviewer(good,reviewerSession,services,Date.now())).status,403);
 state.reviewer={...reg};
 assert.equal((await handleReviewer({...good,signature_hex:'0'.repeat(128)},
  reviewerSession,services,Date.now())).status,409);
 const count=await sql`SELECT count(*)::int AS count
   FROM batcave.general_control_reviewer_evidence_staged_v1`;
 assert.equal(count[0].count,0);
});
test('race between duplicate independent signatures stores exactly one review',async()=>{
 const prepared=await ownerStart();await ownerYes(prepared);
 const request=reviewerEvidence(prepared);
 const [a,b]=await Promise.all([handleReviewer(request,reviewerSession,services,Date.now()),
  handleReviewer(request,reviewerSession,services,Date.now())]);
 assert.deepEqual([a.status,b.status].sort(),[200,409]);
 const count=await sql`SELECT count(*)::int AS count
   FROM batcave.general_control_reviewer_evidence_staged_v1`;
 assert.equal(count[0].count,1);
});
test('owner account and lab-only reviewer cannot write reviewer evidence',async()=>{
 const prepared=await ownerStart();await ownerYes(prepared);
 const e=reviewerEvidence(prepared);
 assert.equal((await handleReviewer(e,{...reviewerSession,
  protected_reviewer_session_verified:false},services,Date.now())).status,401);
 state.reviewer={...reg,key_scope:'lab_reviewer_only'};
 assert.equal((await handleReviewer(e,reviewerSession,services,Date.now())).status,403);
 const count=await sql`SELECT count(*)::int AS count
   FROM batcave.general_control_reviewer_evidence_staged_v1`;
 assert.equal(count[0].count,0);
});
