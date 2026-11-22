/* Disposable database acceptance of the STAGED private owner repository.
 * Must run only against localhost/release_gate_test. Uses postgres@3.4.5,
 * synthetic Ed25519 keys and server-owned fixture scopes. Never production.
 */
import {test,before,after,beforeEach} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname,resolve} from 'node:path';
import {webcrypto} from 'node:crypto';
import postgres from 'postgres';
import {createGeneralControlPrivateRepositorySTAGED as makeRepo}
 from '../release-evidence-v1/general_control_private_repository_STAGED.mjs';
import {handleGeneralControlOwnerApiV1 as handle}
 from '../release-evidence-v1/general_control_owner_api_STAGED.mjs';
import {signGeneralControlOwnerChallengeV1 as sign}
 from '../release-evidence-v1/general_control_owner_signing_v1.mjs';

const databaseUrl=process.env.BATCAVE_TEST_DATABASE_URL;
if(typeof databaseUrl!=='string')throw Error('TEST_DATABASE_URL_REQUIRED');
const u=new URL(databaseUrl);
if(!['localhost','127.0.0.1','::1'].includes(u.hostname)||
   u.pathname!=='/release_gate_test')throw Error('REFUSE_NONDISPOSABLE_DATABASE');
const sql=postgres(databaseUrl,{prepare:false,max:8});
const dirnameHere=dirname(fileURLToPath(import.meta.url));
const sibling=resolve(dirnameHere,'../release-evidence-v1');
const OWNER='123e4567-e89b-42d3-a456-426614174000';
const ctx={owner_user_id:OWNER,owner_authenticated:true,
  origin:'https://batcave-linux-approval.vercel.app'};
const now=Date.now();
const keypair=await webcrypto.subtle.generateKey('Ed25519',false,['sign','verify']);
const raw=new Uint8Array(await webcrypto.subtle.exportKey('raw',keypair.publicKey));
const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
const b64=bytes=>btoa(String.fromCharCode(...bytes)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
const local={privateKey:keypair.privateKey,publicKeyB64:b64(raw)};
const key={owner_user_id:OWNER,key_scope:'general_control_owner_v1',
 key_state:'active',key_hex:hex(raw),revoked_at:null};
const scope={device:'Cortana',capability:'browser.observe',target_origin:'https://example.org',
 target_session_id:'browser-session-1',command_digest:'a'.repeat(64),source_commit:'b'.repeat(40),
 policy_digest:'c'.repeat(64),rollback_ref:'none'};
const prepare={action:'general_control_prepare_owner_v1'};
const record=evidence=>({action:'general_control_record_owner_v1',evidence});
const decline=challenge=>({action:'general_control_decline_owner_v1',
 owner_user_id:OWNER,request_id:challenge.request.request_id,nonce:challenge.request.nonce});
async function doSign(ch){return sign({challenge:ch,ownerUserId:OWNER,getOwnerKey:async()=>local,
 consent:true,now,origin:ctx.origin});}
function fixture(){
 let current={...scope};
 let registered={...key};
 const repository=makeRepo(sql,{
  getTrustedPendingScope:async owner=>owner===OWNER?{...scope}:null,
  getTrustedCurrentScope:async owner=>owner===OWNER?{...current}:null,
  getRegisteredOwnerKey:async owner=>owner===OWNER?{...registered}:null,
 });
 return {repository,setScope:x=>{current=x;},setKey:x=>{registered=x;}};
}
async function start(f){
 const prepared=await handle(prepare,ctx,f.repository,now);
 assert.equal(prepared.status,200,JSON.stringify(prepared));
 return prepared.body;
}
before(async()=>{
 for(const name of ['general_control_nonce_ledger_STAGED.sql',
  'general_control_owner_evidence_atomic_STAGED.sql',
  'general_control_challenge_repository_STAGED.sql']){
   await sql.unsafe(readFileSync(resolve(sibling,name),'utf8'));
 }
});
beforeEach(async()=>{
 await sql.unsafe('TRUNCATE batcave.general_control_owner_evidence_staged_v1, batcave.general_control_prepared_challenges_staged_v1, batcave.general_control_nonce_ledger_v1 CASCADE');
});
after(async()=>{await sql.end({timeout:2});});
test('parameterized reservation stores a real one-use challenge and exact owner binding',async()=>{
 const f=fixture(),ch=await start(f);
 const rows=await sql`SELECT n.state,n.request_sha256,
  p.request_json,p.scope_json FROM batcave.general_control_nonce_ledger_v1 n
  JOIN batcave.general_control_prepared_challenges_staged_v1 p
    ON p.request_id=n.request_id`;
 assert.equal(rows.length,1);
 assert.equal(rows[0].state,'unused');
 assert.equal(rows[0].request_json.request_id,ch.request.request_id);
 assert.equal(rows[0].scope_json.target_session_id,scope.target_session_id);
 assert.equal(rows[0].request_sha256.length,64);
 assert.equal(ch.execution_authorized,false);
});
test('authentic synthetic signature records durable evidence exactly once, no grant',async()=>{
 const f=fixture(),ch=await start(f),evidence=await doSign(ch);
 const result=await handle(record(evidence),ctx,f.repository,now);
 assert.equal(result.status,200,JSON.stringify(result));
 assert.equal(result.body.execution_authorized,false);
 assert.equal(result.body.deployment_authorized,false);
 const stored=await sql`SELECT signature_hex,state FROM
   batcave.general_control_owner_evidence_staged_v1`;
 assert.equal(stored.length,1);
 assert.equal(stored[0].signature_hex,evidence.signature_hex);
 assert.equal(stored[0].state,'owner_signature_recorded_only');
 assert.equal((await handle(record(evidence),ctx,f.repository,now)).status,409);
 const nonce=await sql`SELECT state FROM batcave.general_control_nonce_ledger_v1`;
 assert.equal(nonce[0].state,'consumed');
});
test('No atomically declines and permanently blocks the same signed request',async()=>{
 const f=fixture(),ch=await start(f),evidence=await doSign(ch);
 assert.equal((await handle(decline(ch),ctx,f.repository,now)).status,200);
 assert.equal((await handle(record(evidence),ctx,f.repository,now)).status,409);
 const rows=await sql`SELECT state FROM batcave.general_control_nonce_ledger_v1`;
 assert.equal(rows[0].state,'declined');
 const count=await sql`SELECT count(*)::int AS count FROM
  batcave.general_control_owner_evidence_staged_v1`;
 assert.equal(count[0].count,0);
});
test('simultaneous Yes requests produce only one durable receipt',async()=>{
 const f=fixture(),ch=await start(f),evidence=await doSign(ch);
 const results=await Promise.all([
   handle(record(evidence),ctx,f.repository,now),
   handle(record(evidence),ctx,f.repository,now),
 ]);
 assert.deepEqual(results.map(x=>x.status).sort(),[200,409]);
 const count=await sql`SELECT count(*)::int AS count FROM
  batcave.general_control_owner_evidence_staged_v1`;
 assert.equal(count[0].count,1);
});
test('only one currently active owner challenge may exist; after No, a new one is possible',async()=>{
 const f=fixture(),a=await start(f);
 const again=await handle(prepare,ctx,f.repository,now);
 assert.equal(again.status,409);
 assert.equal((await handle(decline(a),ctx,f.repository,now)).status,200);
 const afterDecline=await handle(prepare,ctx,f.repository,now);
 assert.equal(afterDecline.status,200);
 assert.notEqual(afterDecline.body.request.request_id,a.request.request_id);
});
test('tampered signature or changed server policy/session cannot reach atomic persistence',async()=>{
 const f=fixture(),ch=await start(f),evidence=await doSign(ch);
 assert.equal((await handle(record({...evidence,signature_hex:'0'.repeat(128)}),ctx,f.repository,now)).status,403);
 f.setScope({...scope,target_session_id:'other-session-99'});
 assert.equal((await handle(record(evidence),ctx,f.repository,now)).status,409);
 f.setScope({...scope});
 f.setKey({...key,key_scope:'lab_reviewer_only'});
 assert.equal((await handle(record(evidence),ctx,f.repository,now)).status,403);
 const state=await sql`SELECT state FROM batcave.general_control_nonce_ledger_v1`;
 assert.equal(state[0].state,'unused');
});
test('cross-owner access and SQL-like identifiers cannot read or approve a request',async()=>{
 const f=fixture(),ch=await start(f);
 assert.equal(await f.repository.getPreparedChallenge(
  '123e4567-e89b-42d3-a456-426614174999',ch.request.request_id),null);
 await assert.rejects(()=>f.repository.getPreparedChallenge(OWNER,"' OR 1=1 --"),
  /INVALID_SERVER_OWNER_OR_REQUEST_ID/);
 const result=await handle(record(await doSign(ch)),{...ctx,owner_authenticated:false},f.repository,now);
 assert.equal(result.status,401);
});
test('anon and authenticated roles cannot call reserved functions or read staged tables',async()=>{
 const rights=await sql`SELECT
   has_table_privilege('anon','batcave.general_control_prepared_challenges_staged_v1','SELECT') AS anon_table,
   has_table_privilege('authenticated','batcave.general_control_prepared_challenges_staged_v1','SELECT') AS auth_table,
   has_function_privilege('anon',
    'batcave.general_control_reserve_prepared_staged_v1(uuid,uuid,text,text,text,timestamptz,jsonb,jsonb)','EXECUTE') AS anon_rpc,
   has_function_privilege('authenticated',
    'batcave.general_control_reserve_prepared_staged_v1(uuid,uuid,text,text,text,timestamptz,jsonb,jsonb)','EXECUTE') AS auth_rpc`;
 assert.deepEqual(rights[0],{anon_table:false,auth_table:false,anon_rpc:false,auth_rpc:false});
});
