/* Disposable localhost Postgres only: synthetic Ed25519 reviewer candidate
 * possession proof with real private SQL nonce and one-use receipt. NOT live.
 */
import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import postgres from 'postgres';
import {issuePossessionChallengeSTAGED as issue,recordPossessionProofSTAGED as record,
 possessionMessage} from '../src/general_control_reviewer_possession_STAGED.mjs';
import {makeCandidatePossessionPrivateRepoSTAGED as makeRepo}
 from '../release-evidence-v1/general_control_candidate_possession_private_repo_STAGED.mjs';
const u=process.env.BATCAVE_TEST_DATABASE_URL;
if(!u)throw Error('TEST_DB_REQUIRED');
const url=new URL(u);
if(!['localhost','127.0.0.1','::1'].includes(url.hostname)||
 url.pathname!=='/release_gate_test')throw Error('REFUSE_PRODUCTION_DB');
const sql=postgres(u,{prepare:false,max:6});
const ledger=resolve(dirname(fileURLToPath(import.meta.url)),
 '../release-evidence-v1/general_control_candidate_possession_ledger_STAGED.sql');
const {repository,getPrivateCandidate}=makeRepo(sql),services={repository,getPrivateCandidate};
const sha=b=>createHash('sha256').update(b).digest('hex');
before(async()=>{
 await sql.unsafe('CREATE SCHEMA IF NOT EXISTS batcave');
 await sql.unsafe(`DO $pl$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN CREATE ROLE anon;END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN CREATE ROLE authenticated;END IF;
 END $pl$`);
 await sql.unsafe(`CREATE TABLE IF NOT EXISTS batcave.oracle_instruction_drafts_v1(
 id uuid PRIMARY KEY,owner_user_id uuid NOT NULL,source text NOT NULL,
 source_message text NOT NULL DEFAULT 'synthetic',
 interpreted_intent jsonb NOT NULL,
 risk_level text NOT NULL DEFAULT 'high',
 state text NOT NULL DEFAULT 'draft',
 requires_independent_review boolean NOT NULL DEFAULT true,
 execution_authorized boolean NOT NULL DEFAULT false,
 dispatched_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz
 )`);
 await sql.unsafe(readFileSync(ledger,'utf8'));
});
after(async()=>{await sql.end({timeout:2});});
async function setup(){
 const pair=generateKeyPairSync('ed25519');
 const raw=pair.publicKey.export({type:'spki',format:'der'}).subarray(-32);
 const draft=randomUUID(),owner=randomUUID();
 const keyhash=sha(raw),keyb64=raw.toString('base64url');
 const intent={kind:'general_control_public_reviewer_candidate_v1',
  registered:false,independently_attested:false,production_release_authorized:false,
  execution_authorized:false,device:'Cortana',account:'CORTANA\\StrictNannyRelease',
  sid_from_owner_screenshot:'S-1-5-21-349890097-2052580754-4142396749-1004',
  public_key_sha256_raw:keyhash,public_key_b64url_raw:keyb64};
 await sql`INSERT INTO batcave.oracle_instruction_drafts_v1
  (id,owner_user_id,source,source_message,interpreted_intent,risk_level,state,
   requires_independent_review,execution_authorized,dispatched_at,expires_at)
  VALUES(${draft}::uuid,${owner}::uuid,'chatgpt_owner_instruction','synthetic possession only',
   ${sql.json(intent)}::jsonb,'high','draft',true,false,NULL,
   (clock_timestamp()+interval '1 day'))`;
 const observed=await getPrivateCandidate(draft,owner);
 assert.deepEqual(observed,{id:draft,owner_user_id:owner,kind:intent.kind,
 registered:false,independently_attested:false,production_release_authorized:false,
 execution_authorized:false,host:intent.device,account:intent.account,
 sid:intent.sid_from_owner_screenshot,public_key_sha256_raw:intent.public_key_sha256_raw,
 public_key_b64url_raw:intent.public_key_b64url_raw},'Private PostgreSQL draft normalization changed');
 const session={authenticated_owner:true,owner_user_id:owner};
 const out=await issue({draft_id:draft},session,services);
 assert.equal(out.status,'AWAIT_EXPLICIT_KEY_POSSESSION_PROOF',JSON.stringify(out));
 const challenge=out.challenge;
 const proof={schema:'batcave.general_control.reviewer_possession_proof.v1',
  request_id:challenge.request_id,nonce:challenge.nonce,
  signature_hex:sign(null,Buffer.from(possessionMessage(challenge)),pair.privateKey).toString('hex')};
 return {draft,owner,challenge,proof};
}
test('genuine synthetic Ed25519 candidate proof records only once, never activates reviewer',async()=>{
 const x=await setup();
 const accepted=await record(x.proof,services);
 assert.equal(accepted.status,'CANDIDATE_POSSESSION_RECORDED_ONLY',JSON.stringify(accepted));
 const rows=await sql`SELECT state,signature_hex,independently_attested,registered,
  production_release_authorized,execution_authorized,deployment_authorized,grant_issued
  FROM batcave.general_control_reviewer_possession_staged_v1
  WHERE request_id=${x.challenge.request_id}::uuid`;
 assert.equal(rows.length,1);assert.equal(rows[0].state,'candidate_possession_recorded_only');
 assert.equal(rows[0].signature_hex,x.proof.signature_hex);
 for(const k of ['independently_attested','registered','production_release_authorized',
  'execution_authorized','deployment_authorized','grant_issued'])assert.equal(rows[0][k],false);
 assert.equal((await record(x.proof,services)).status,'DENY');
});
test('concurrent same valid signature is accepted only once',async()=>{
 const x=await setup();
 const results=await Promise.all([record(x.proof,services),record(x.proof,services)]);
 assert.deepEqual(results.map(z=>z.status).sort(),['CANDIDATE_POSSESSION_RECORDED_ONLY','DENY']);
});
test('synthetic changed fingerprint after challenge denies despite correct original signature',async()=>{
 const x=await setup();
 await sql`UPDATE batcave.oracle_instruction_drafts_v1
 SET interpreted_intent=jsonb_set(interpreted_intent,'{public_key_sha256_raw}',to_jsonb(${'b'.repeat(64)}::text))
 WHERE id=${x.draft}::uuid`;
 assert.equal((await record(x.proof,services)).status,'DENY');
 const rows=await sql`SELECT state FROM batcave.general_control_reviewer_possession_staged_v1
 WHERE request_id=${x.challenge.request_id}::uuid`;
 assert.equal(rows[0].state,'unused');
});
test('changed owner candidate state after challenge rejects signature',async()=>{
 const x=await setup();
 await sql`UPDATE batcave.oracle_instruction_drafts_v1 SET state='held'
 WHERE id=${x.draft}::uuid`;
 assert.equal((await record(x.proof,services)).status,'DENY');
});
test('public roles have no direct access to private possession receipts',async()=>{
 const r=await sql`SELECT
  has_table_privilege('anon','batcave.general_control_reviewer_possession_staged_v1','SELECT') AS a,
  has_table_privilege('authenticated','batcave.general_control_reviewer_possession_staged_v1','UPDATE') AS b,
  has_function_privilege('anon',
    'batcave.general_control_record_candidate_possession_staged_v1(uuid,uuid,uuid,text,text,text,text)','EXECUTE') AS c`;
 assert.deepEqual(Object.values(r[0]),[false,false,false]);
});
