import test from 'node:test';
import assert from 'node:assert/strict';
import {inspectGeneralControlLivePreflightSTAGED as inspect}
 from './general_control_live_preflight_STAGED.mjs';
const owner='123e4567-e89b-42d3-a456-426614174000';
const sha='a'.repeat(40);
function fixture(patch={}){
 const values={
  intent:{state:'held',owner_auth_state:'unconfigured',nanny_review_state:'pending',
   valid_until:'2099-11-29T17:01:31.000Z',
   requested_scope:{source_commit:'b'.repeat(40),deployment_authorized:false}},
  rule:{gate_mode:'shadow',strict_nanny_required:true,batcave_identity_required:true,
   signed_scope_required:true},
  root:1,reviewer:0,
  devices:[{device_name:'Cortana',state:'active'},{device_name:'Oracle',state:'active'}],
  ...patch};
 const touched=[];
 async function sql(strings,...args){
  const query=strings.join('$');
  touched.push({query,args});
  if(query.includes('FROM batcave.change_gate_intents'))return values.intent?[values.intent]:[];
  if(query.includes('FROM batcave.change_gate_rules'))return values.rule?[values.rule]:[];
  if(query.includes('FROM batcave.linux_owner_keys_v1'))return [{active:values.root}];
  if(query.includes('FROM batcave.oracle_release_keys_v1'))return [{qualified:values.reviewer}];
  if(query.includes('FROM batcave.devices'))return values.devices;
  throw Error('UNKNOWN_QUERY');
 }
 return {sql,touched};
}
test('real-current-shaped HELD records with active devices cannot authorize',async()=>{
 const f=fixture(),r=await inspect(f.sql,owner,sha);
 for(const reason of ['RELEASE_NOT_SIGNED','OWNER_RELEASE_SIGNATURE_MISSING',
  'INDEPENDENT_RELEASE_SIGNATURE_MISSING','EXACT_SOURCE_PIN_MISMATCH',
  'RELEASE_DEPLOYMENT_NOT_AUTHORIZED','PROJECT_RELEASE_GATE_NOT_ENFORCED',
  'QUALIFIED_INDEPENDENT_SIGNER_MISSING'])
  assert.ok(r.blockers.includes(reason),reason);
 assert.deepEqual(r.device_registry,[
  {device:'Oracle',registered_active:true},{device:'Cortana',registered_active:true}]);
 assert.equal(r.existing_root_key_present,true);
 assert.equal(r.registered_general_control_key_confirmed,false);
 assert.equal(r.signed_in_browser_session_confirmed,false);
 assert.equal(r.execution_authorized,false);
 assert.equal(r.deployment_authorized,false);
 assert.equal(r.grant_issued,false);
 assert.equal(f.touched.length,5);
 assert.ok(f.touched.some(x=>x.args.includes(owner)));
});
test('missing owner/intent, policy, signer and devices all fail closed',async()=>{
 const f=fixture({intent:null,rule:null,root:0,reviewer:0,devices:[]});
 const r=await inspect(f.sql,owner,sha);
 for(const reason of ['RELEASE_INTENT_MISSING','PROJECT_RELEASE_GATE_NOT_ENFORCED',
  'EXISTING_OWNER_KEY_UNAVAILABLE','QUALIFIED_INDEPENDENT_SIGNER_MISSING',
  'ORACLE_NOT_REGISTERED_ACTIVE','CORTANA_NOT_REGISTERED_ACTIVE'])
  assert.ok(r.blockers.includes(reason),reason);
 assert.equal(r.execution_authorized,false);
});
test('even forged complete source flags are NOT proof of individual consent',async()=>{
 const f=fixture({
  intent:{state:'released',owner_auth_state:'signed',nanny_review_state:'signed',
   valid_until:'2099-11-29T17:01:31.000Z',
   requested_scope:{source_commit:sha,deployment_authorized:true}},
  rule:{gate_mode:'enforce',strict_nanny_required:true,batcave_identity_required:true,
   signed_scope_required:true},root:1,reviewer:1
 });
 const r=await inspect(f.sql,owner,sha);
 assert.deepEqual(r.blockers,[]);
 assert.equal(r.state,'SOURCE_FACTS_ONLY');
 assert.equal(r.owner_signature_verified,false);
 assert.equal(r.independent_signature_verified,false);
 assert.equal(r.registered_general_control_key_confirmed,false);
 assert.equal(r.execution_authorized,false);
 assert.equal(r.deployment_authorized,false);
});
test('malformed identity and source hashes cannot query the private DB',async()=>{
 const f=fixture();
 await assert.rejects(inspect(f.sql,'other',sha),/TRUSTED_OWNER_AND_SOURCE_REQUIRED/);
 await assert.rejects(inspect(f.sql,owner,'not-40-hex'),/TRUSTED_OWNER_AND_SOURCE_REQUIRED/);
 assert.equal(f.touched.length,0);
});
test('no server query helper fails before touching live state',async()=>{
 await assert.rejects(inspect(null,owner,sha),/TRUSTED_OWNER_AND_SOURCE_REQUIRED/);
});
