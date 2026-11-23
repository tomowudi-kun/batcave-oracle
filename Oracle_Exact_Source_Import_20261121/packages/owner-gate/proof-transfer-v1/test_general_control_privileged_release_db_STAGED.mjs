/* Disposable PostgreSQL only. Synthetic complete owner + reviewer receipts,
 * followed by a genuinely distinct Ed25519 privileged release review receipt.
 * This cannot enroll a reviewer, release a deployment or issue a command.
 */
import test,{before,after,beforeEach} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash,randomUUID} from 'node:crypto';
import postgres from 'postgres';
import {readFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {makePrivilegedReleasePrivateRepoSTAGED as makeRepo}
 from '../release-evidence-v1/general_control_privileged_release_private_repo_STAGED.mjs';
import {handlePrivilegedReleaseReviewSTAGED as handle}
 from '../release-evidence-v1/general_control_privileged_release_STAGED.mjs';
import {validateGeneralControlOwnerRequestV1 as validate}
 from '../src/general_control_owner_request_v1.mjs';
const url=process.env.BATCAVE_TEST_DATABASE_URL;
if(!url)throw Error('TEST_DATABASE_REQUIRED');
const u=new URL(url);
if(!['localhost','127.0.0.1','::1'].includes(u.hostname)||
 u.pathname!=='/release_gate_test')throw Error('REFUSE_LIVE_DATABASE');
const sql=postgres(url,{max:8,prepare:false});
const root=resolve(dirname(fileURLToPath(import.meta.url)),'../release-evidence-v1');
const owner='123e4567-e89b-42d3-a456-426614174000';
const reviewer='123e4567-e89b-42d3-a456-426614174009';
const keys=generateKeyPairSync('ed25519');
const pub=keys.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');
const host='f'.repeat(64),commit='b'.repeat(40),digest='c'.repeat(64);
const intentKey='batcave.general_control.pr3.owner_release_request.20261122';
const intentHash='e'.repeat(64);
const hexhash=s=>createHash('sha256').update(s).digest('hex');
const session={reviewer_authenticated:true,protected_reviewer_session_verified:true,
 independent_identity_verified:true,reviewer_identity_id:reviewer,host_identity_sha256:host};
const reg={identity_id:reviewer,key_hex:pub,host_identity_sha256:host,
 independently_attested:true,production_release_authorized:true,
 key_scope:'general_control_privileged_reviewer_v1',key_state:'active',
 revoked_at:null,valid_until:new Date(Date.now()+3600000).toISOString()};
const repo=makeRepo(sql);
const state={policy:null,trusted:null,reg:{...reg}};
const services={repository:repo,
 getReviewerRegistration:async()=>state.reg,
 getCurrentPolicy:async()=>state.policy,
 getTrustedBinding:async()=>state.trusted,
 getHeldReleaseIntent:async()=>{
  const rows=await sql`SELECT intent_key,state,content_sha256,valid_until,requested_scope
   FROM batcave.change_gate_intents WHERE intent_key=${intentKey}`;
  if(!rows[0])return null;
  return {...rows[0],valid_until:new Date(rows[0].valid_until).toISOString()};
 },
 getCompleteSignedEvidence:async requestId=>{
  const rows=await sql`SELECT p.request_json AS request,
   o.state AS owner_signature_state,o.signature_hex AS owner_signature_hex,
   r.state AS reviewer_signature_state,r.signature_hex AS reviewer_signature_hex
   FROM batcave.general_control_prepared_challenges_staged_v1 p
   JOIN batcave.general_control_owner_evidence_staged_v1 o
    ON o.request_id=p.request_id
   JOIN batcave.general_control_reviewer_evidence_staged_v1 r
    ON r.request_id=p.request_id
   WHERE p.request_id=${requestId}::uuid LIMIT 1`;
  return rows[0]??null;
 }
};
const bind=r=>Object.fromEntries(['owner_user_id','device','target_origin',
 'target_session_id','command_digest','source_commit','policy_digest'].map(k=>[k,r[k]]));
const create=async()=>{
 const now=Date.now(),id=randomUUID(),nonce='a'.repeat(32);
 const req={schema:'batcave.general_control.owner_request.v1',
  owner_user_id:owner,request_id:id,device:'Oracle',capability:'host.read',
  target_origin:null,target_session_id:'oracle-session-1',
  command_digest:'1'.repeat(64),source_commit:commit,policy_digest:digest,
  nonce,issued_at:new Date(now-1000).toISOString(),
  expires_at:new Date(now+180000).toISOString(),rollback_ref:'none'};
 const trusted=bind(req),sha=hexhash(validate(req,trusted,now).signing_message);
 state.trusted=trusted;
 state.policy={current:true,capability_allowed:true,digest,
  source_commit:commit,device:req.device,capability:req.capability,
  target_origin:req.target_origin,target_session_id:req.target_session_id};
 state.reg={...reg};
 const scope={source_commit:commit,policy_digest:digest,device:req.device,
  capability:req.capability,target_session_id:req.target_session_id,
  target_origin:req.target_origin,command_digest:req.command_digest};
 await sql`INSERT INTO batcave.general_control_nonce_ledger_v1
  (request_id,owner_user_id,nonce,request_sha256,policy_sha256,expires_at,state,consumed_at)
  VALUES(${id}::uuid,${owner}::uuid,${nonce},${sha},
   ${digest},${req.expires_at}::timestamptz,'consumed',clock_timestamp())`;
 await sql`INSERT INTO batcave.general_control_prepared_challenges_staged_v1
  (request_id,owner_user_id,nonce,request_sha256,policy_sha256,expires_at,
   request_json,scope_json)
  VALUES(${id}::uuid,${owner}::uuid,${nonce},${sha},
   ${digest},${req.expires_at}::timestamptz,${sql.json(req)}::jsonb,
   ${sql.json(scope)}::jsonb)`;
 await sql`INSERT INTO batcave.general_control_owner_evidence_staged_v1
  (request_id,owner_user_id,nonce,request_sha256,policy_sha256,signature_hex)
  VALUES(${id}::uuid,${owner}::uuid,${nonce},${sha},
   ${digest},${'2'.repeat(128)})`;
 await sql`INSERT INTO batcave.general_control_reviewer_evidence_staged_v1
  (request_id,owner_user_id,nonce,policy_sha256,source_commit,
   reviewer_identity_id,reviewer_key_hex,signature_hex)
  VALUES(${id}::uuid,${owner}::uuid,${nonce},${digest},
   ${commit},${reviewer}::uuid,${pub},${'3'.repeat(128)})`;
 await sql`INSERT INTO batcave.change_gate_intents
  (intent_key,state,content_sha256,valid_until,requested_scope)
  VALUES(${intentKey},'held',${intentHash},
   (clock_timestamp()+interval '1 day'),${sql.json(scope)}::jsonb)
  ON CONFLICT (intent_key) DO UPDATE SET state='held',content_sha256=${intentHash},
    valid_until=clock_timestamp()+interval '1 day',
    requested_scope=EXCLUDED.requested_scope`;
 return req;
};
async function challenge(req){
 const r=await handle({action:'general_control_privileged_release_prepare_v1',
 request_id:req.request_id},session,services,Date.now());
 assert.equal(r.status,'AWAIT_EXPLICIT_INDEPENDENT_REVIEWER_SIGNATURE',JSON.stringify(r));
 return r;
}
const signReview=c=>sign(null,Buffer.from(c.signing_text),keys.privateKey).toString('hex');
const record=c=>({action:'general_control_privileged_release_record_v1',
 request_id:c.challenge.request_id,nonce:c.challenge.nonce,
 signature_hex:signReview(c)});
before(async()=>{
 // Disposable PostgreSQL has no production change-gate intent by design.
 // Create the minimal fixture explicitly; never use this against production.
 await sql.unsafe('CREATE SCHEMA IF NOT EXISTS batcave');
 await sql.unsafe(`CREATE TABLE IF NOT EXISTS batcave.change_gate_intents (
  intent_key text PRIMARY KEY,state text,content_sha256 text,
  valid_until timestamptz,requested_scope jsonb)`);
 for(const name of ['general_control_nonce_ledger_STAGED.sql',
  'general_control_owner_evidence_atomic_STAGED.sql',
  'general_control_challenge_repository_STAGED.sql',
  'general_control_reviewer_evidence_atomic_STAGED.sql',
  'general_control_privileged_release_ledger_STAGED.sql']){
  await sql.unsafe(readFileSync(resolve(root,name),'utf8'));
 }
 await sql.unsafe('ALTER TABLE batcave.change_gate_intents ADD COLUMN IF NOT EXISTS requested_scope jsonb');
});
beforeEach(async()=>{
 await sql.unsafe('TRUNCATE batcave.general_control_privileged_release_review_staged_v1,batcave.general_control_reviewer_evidence_staged_v1,batcave.general_control_owner_evidence_staged_v1,batcave.general_control_prepared_challenges_staged_v1,batcave.general_control_nonce_ledger_v1 CASCADE');
 await sql`DELETE FROM batcave.change_gate_intents WHERE intent_key=${intentKey}`;
});
after(async()=>{await sql.end({timeout:2});});
test('real signed privileged review is durable and non-authorizing; replay rejected',async()=>{
 const req=await create(),c=await challenge(req);
 const result=await handle(record(c),session,services,Date.now());
 assert.equal(result.status,'PRIVILEGED_RELEASE_SIGNATURE_RECORDED_ONLY',JSON.stringify(result));
 const rows=await sql`SELECT state,signature_hex,execution_authorized,
  deployment_authorized,grant_issued
  FROM batcave.general_control_privileged_release_review_staged_v1`;
 assert.equal(rows.length,1);
 assert.equal(rows[0].state,'recorded');
 assert.equal(rows[0].signature_hex,signReview(c));
 for(const key of ['execution_authorized','deployment_authorized','grant_issued'])
  assert.equal(rows[0][key],false);
 assert.equal((await handle(record(c),session,services,Date.now())).status,'DENY');
});
test('identical concurrent privileged signatures have exactly one acceptance',async()=>{
 const req=await create(),c=await challenge(req);
 const [a,b]=await Promise.all([
  handle(record(c),session,services,Date.now()),
  handle(record(c),session,services,Date.now()),
 ]);
 assert.deepEqual([a.status,b.status].sort(),['DENY','PRIVILEGED_RELEASE_SIGNATURE_RECORDED_ONLY']);
 const count=await sql`SELECT count(*)::int AS n
  FROM batcave.general_control_privileged_release_review_staged_v1
  WHERE state='recorded'`;
 assert.equal(count[0].n,1);
});
test('held-intent source switch after prepare prevents signed release',async()=>{
 const req=await create(),c=await challenge(req);
 await sql`UPDATE batcave.change_gate_intents SET
  requested_scope=jsonb_set(requested_scope,'{source_commit}',to_jsonb(${'f'.repeat(40)}::text))
  WHERE intent_key=${intentKey}`;
 assert.equal((await handle(record(c),session,services,Date.now())).status,'DENY');
 const result=await sql`SELECT state
  FROM batcave.general_control_privileged_release_review_staged_v1`;
 assert.equal(result[0].state,'unused');
});
test('forged signature and non-independent reviewer cannot write',async()=>{
 const req=await create(),c=await challenge(req);
 const e=record(c);
 e.signature_hex='0'.repeat(128);
 assert.equal((await handle(e,session,services,Date.now())).status,'DENY');
 state.reg={...reg,independently_attested:false};
 assert.equal((await handle(record(c),session,services,Date.now())).status,'DENY');
});
test('public roles have no access to held private privileged review receipt',async()=>{
 const perms=await sql`SELECT
  has_table_privilege('anon','batcave.general_control_privileged_release_review_staged_v1','SELECT') AS a,
  has_table_privilege('authenticated','batcave.general_control_privileged_release_review_staged_v1','UPDATE') AS b,
  has_function_privilege('authenticated',
   'batcave.general_control_record_privileged_release_staged_v1(uuid,text,uuid,text,text,text,text,text,text,text)','EXECUTE') AS c`;
 assert.deepEqual(Object.values(perms[0]),[false,false,false]);
});
