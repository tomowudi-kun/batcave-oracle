/* End-to-end scope-owner-signing acceptance on disposable PostgreSQL only.
 * No live host, source release, reviewer promotion or grant is involved.
 */
import test,{before,after,beforeEach} from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import postgres from 'postgres';
import {makeGeneralControlRootRescopePrivateRepoSTAGED as makeRepo}
 from '../release-evidence-v1/general_control_rescope_private_repo_STAGED.mjs';
import {handleGeneralControlRootRescopeSTAGED as handle}
 from '../release-evidence-v1/general_control_owner_rescope_api_STAGED.mjs';
import {signOwnerRescopeOnClickSTAGED as sign}
 from '../release-evidence-v1/general_control_owner_rescope_STAGED.mjs';
const url=process.env.BATCAVE_TEST_DATABASE_URL;
if(typeof url!=='string')throw Error('TEST_DATABASE_REQUIRED');
const u=new URL(url);
if(!['localhost','127.0.0.1','::1'].includes(u.hostname)||
 u.pathname!=='/release_gate_test')throw Error('REFUSE_LIVE_DATABASE');
const sql=postgres(url,{prepare:false,max:8});
const folder=resolve(dirname(fileURLToPath(import.meta.url)),'../release-evidence-v1');
const owner='123e4567-e89b-42d3-a456-426614174000';
const origin='https://batcave-linux-approval.vercel.app';
const ctx={owner_user_id:owner,owner_authenticated:true,origin};
const keypair=await webcrypto.subtle.generateKey('Ed25519',false,['sign','verify']);
const raw=new Uint8Array(await webcrypto.subtle.exportKey('raw',keypair.publicKey));
const hex=a=>Array.from(a,b=>b.toString(16).padStart(2,'0')).join('');
const b64=a=>btoa(String.fromCharCode(...a)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
const keyHash=hex(new Uint8Array(await webcrypto.subtle.digest('SHA-256',raw)));
const root={owner_user_id:owner,public_key_sha256:keyHash,
 public_key_b64url:b64(raw),revoked_at:null};
const scope={current:true,source_commit:'a'.repeat(40),policy_digest:'b'.repeat(64)};
const start={action:'general_control_root_rescope_prepare_v1'};
const endorse=evidence=>({action:'general_control_root_rescope_endorse_v1',evidence});
const decline=ch=>({action:'general_control_root_rescope_decline_v1',
 challenge_id:ch.challenge_id,nonce:ch.nonce});
function fixture(){
 const state={root:{...root},scope:{...scope}};
 const repo=makeRepo(sql,{
  getTrustedExistingRoot:async id=>id===owner?state.root:null,
  getTrustedSourcePolicy:async id=>id===owner?state.scope:null,
 });
 return {state,repo};
}
async function prepare(f){
 const now=Date.now();
 const result=await handle(start,ctx,f.repo,now);
 assert.equal(result.status,200,JSON.stringify(result));
 return result.body;
}
async function evidence(prepared){
 return sign({
  challenge:prepared.challenge,
  server:{owner_user_id:owner,authenticated:true,origin,
   root:prepared.root,...prepared.policy},
  getOwnerKey:()=>({privateKey:keypair.privateKey,publicKeyB64:b64(raw)}),
  now:Date.now(),origin,consent:true,
 });
}
before(async()=>{
 await sql.unsafe(readFileSync(resolve(folder,'general_control_owner_rescope_ledger_STAGED.sql'),'utf8'));
});
beforeEach(async()=>{
 await sql.unsafe('TRUNCATE batcave.general_control_owner_scope_pending_staged_v1,batcave.general_control_owner_rescope_challenges_staged_v1 CASCADE');
});
after(async()=>{await sql.end({timeout:2});});
test('real database reservation persists only a prepared owner challenge',async()=>{
 const f=fixture(),p=await prepare(f);
 const rows=await sql`SELECT state,root_key_sha256,scope_public_key_hex
  FROM batcave.general_control_owner_rescope_challenges_staged_v1`;
 assert.equal(rows.length,1);assert.equal(rows[0].state,'unused');
 assert.equal(rows[0].root_key_sha256,keyHash);
 assert.equal(rows[0].scope_public_key_hex,hex(raw));
 assert.equal(p.execution_authorized,false);
 const pending=await sql`SELECT count(*)::int AS count
  FROM batcave.general_control_owner_scope_pending_staged_v1`;
 assert.equal(pending[0].count,0);
});
test('real Ed25519 owner Yes yields one durable pending record, not an active key',async()=>{
 const f=fixture(),p=await prepare(f),signed=await evidence(p);
 const r=await handle(endorse(signed),ctx,f.repo,Date.now());
 assert.equal(r.status,200,JSON.stringify(r));
 assert.equal(r.body.state,'pending_independent_review');
 assert.equal(r.body.execution_authorized,false);
 assert.equal(r.body.deployment_authorized,false);
 const rows=await sql`SELECT state,signature_hex,execution_authorized,
  deployment_authorized FROM batcave.general_control_owner_scope_pending_staged_v1`;
 assert.equal(rows.length,1);assert.equal(rows[0].state,'pending_independent_review');
 assert.equal(rows[0].signature_hex,signed.signature_hex);
 assert.equal(rows[0].execution_authorized,false);
 assert.equal(rows[0].deployment_authorized,false);
 assert.equal((await handle(endorse(signed),ctx,f.repo,Date.now())).status,409);
});
test('actual database No records decline and rejects later Yes',async()=>{
 const f=fixture(),p=await prepare(f),signed=await evidence(p);
 assert.equal((await handle(decline(p.challenge),ctx,f.repo,Date.now())).status,200);
 assert.equal((await handle(endorse(signed),ctx,f.repo,Date.now())).status,409);
 const row=await sql`SELECT state
  FROM batcave.general_control_owner_rescope_challenges_staged_v1`;
 assert.equal(row[0].state,'declined');
});
test('concurrent identical owner signatures have only one DB winner',async()=>{
 const f=fixture(),p=await prepare(f),signed=await evidence(p);
 const results=await Promise.all([
  handle(endorse(signed),ctx,f.repo,Date.now()),
  handle(endorse(signed),ctx,f.repo,Date.now()),
 ]);
 assert.deepEqual(results.map(x=>x.status).sort(),[200,409]);
 const row=await sql`SELECT count(*)::int AS count
  FROM batcave.general_control_owner_scope_pending_staged_v1`;
 assert.equal(row[0].count,1);
});
test('changed live source, invalid signature and revoked old root cannot create a pending key',async()=>{
 const f=fixture(),p=await prepare(f),signed=await evidence(p);
 f.state.scope={...scope,source_commit:'f'.repeat(40)};
 assert.equal((await handle(endorse(signed),ctx,f.repo,Date.now())).status,409);
 f.state.scope={...scope};
 assert.equal((await handle(endorse({...signed,signature_hex:'0'.repeat(128)}),ctx,f.repo,Date.now())).status,409);
 f.state.root={...root,revoked_at:'2026-11-22T22:00:00.000Z'};
 assert.equal((await handle(endorse(signed),ctx,f.repo,Date.now())).status,409);
 const rows=await sql`SELECT count(*)::int AS count
  FROM batcave.general_control_owner_scope_pending_staged_v1`;
 assert.equal(rows[0].count,0);
});
test('wrong authenticated owner and SQL-like IDs fail before touching a private row',async()=>{
 const f=fixture(),p=await prepare(f);
 const bad=await handle(endorse(await evidence(p)),
  {...ctx,owner_authenticated:false},f.repo,Date.now());
 assert.equal(bad.status,401);
 await assert.rejects(()=>f.repo.getPrepared(owner,"' OR true --"),/BAD_SERVER_OWNER_OR_CHALLENGE/);
});
test('anon and authenticated roles cannot inspect or mutate rescope ledger',async()=>{
 const rights=await sql`SELECT
  has_table_privilege('anon','batcave.general_control_owner_scope_pending_staged_v1','SELECT') AS a,
  has_table_privilege('authenticated','batcave.general_control_owner_scope_pending_staged_v1','SELECT') AS b,
  has_function_privilege('anon',
   'batcave.general_control_record_root_rescope_staged_v1(uuid,uuid,text,text,text,text,text,text)','EXECUTE') AS c,
  has_function_privilege('authenticated',
   'batcave.general_control_record_root_rescope_staged_v1(uuid,uuid,text,text,text,text,text,text)','EXECUTE') AS d`;
 assert.deepEqual(Object.values(rights[0]),[false,false,false,false]);
});
