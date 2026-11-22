"""Actual private receipt ledger; synthetic localhost release_gate_test ONLY.
Signature authentication is covered separately with real synthetic Node key pairs.
"""
import concurrent.futures
import json
import os
import subprocess
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'release-evidence-v1'))
import test_first_ledger as first
import test_release_ledger as ledger
query,literal,OWNER=ledger.query,ledger.literal,ledger.OWNER
class ProofLedgerTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  first.FirstLedgerTests.setUpClass()
  query(Path(__file__).with_name('schema_STAGED.sql').read_text())
 def setUp(self):
  self.f=first.FirstLedgerTests();self.f.setUp();self.c=self.f.challenge();assert self.f.save_endorsement(self.c)['saved']
  nonce=query(f"SELECT nonce FROM batcave.oracle_first_challenges_v1 WHERE id='{self.c[0]}';")
  self.proof=dict(schema='batcave.nanny.first_key.possession.v1',challenge_id=self.c[0],nonce=nonce,policy_sha256=self.f.policy_hash,reviewer_public_key_sha256='b'*64,proof_signature_b64url='B'*86,independently_attested=False,deployment_authorized=False,execution_authorized=False,grant_issued=False)
 def store(self,proof=None,payload_hash=None):
  return json.loads(query(f"SELECT batcave.oracle_first_store_public_proof_v1('{self.c[0]}',{literal(payload_hash or self.c[1])},{literal(json.dumps(proof or self.proof))}::jsonb,repeat('a',64));"))
 def test_deposit_is_public_evidence_only_no_root_challenge_or_release_change(self):
  self.assertTrue(self.store()['stored'])
  self.assertEqual(query('SELECT count(*) FROM batcave.oracle_first_public_proofs_v1;'),'1')
  self.assertEqual(query('SELECT count(*) FROM batcave.oracle_first_challenges_v1 WHERE consumed_at IS NOT NULL;'),'0')
  self.assertEqual(query('SELECT registered_at IS NULL FROM batcave.oracle_first_reviewer_v1;'),'t')
  self.assertEqual(query('SELECT state FROM batcave.change_gate_intents;'),'held')
  self.assertEqual(query('SELECT count(*) FROM batcave.oracle_first_public_proofs_v1 WHERE independently_attested OR deployment_authorized OR execution_authorized OR grant_issued;'),'0')
 def test_actual_postgres_js_driver_keeps_proof_as_json_object(self):
  script="""
import postgres from 'postgres';
import {readFileSync} from 'node:fs';
import {proofRepository} from './repository.mjs';
const f=JSON.parse(readFileSync(0,'utf8'));
const sql=postgres(process.env.BATCAVE_TEST_DATABASE_URL,{prepare:false,max:1});
try{
 const [legacy]=await sql`SELECT batcave.oracle_first_store_public_proof_v1(${f.id}::uuid,${f.payload_hash},${JSON.stringify(f.proof)}::jsonb,${f.proof_hash}) AS receipt`;
 const repo=proofRepository(sql),checks=await repo.readiness(),fixed=await repo.store(f.id,f.payload_hash,f.proof,f.proof_hash),saved=await repo.proof(f.id);
 console.log(JSON.stringify({legacy:legacy.receipt,fixed,checks,saved}));
}finally{await sql.end();}
"""
  fixture=dict(id=self.c[0],payload_hash=self.c[1],proof_hash='a'*64,proof=self.proof)
  result=subprocess.run(['node','--input-type=module','-e',script],input=json.dumps(fixture),capture_output=True,text=True,cwd=Path(__file__).resolve().parent,env=os.environ,timeout=25)
  self.assertEqual(result.returncode,0,result.stderr)
  receipt=json.loads(result.stdout)
  self.assertFalse(receipt['legacy']['stored'])
  self.assertTrue(receipt['fixed']['stored'])
  self.assertTrue(all(receipt['checks'].values()))
  self.assertEqual(receipt['saved'],self.proof)
  self.assertEqual(query('SELECT registered_at IS NULL FROM batcave.oracle_first_reviewer_v1;'),'t')
  self.assertEqual(query('SELECT count(*) FROM batcave.oracle_first_challenges_v1 WHERE consumed_at IS NOT NULL;'),'0')
 def test_replay_is_idempotent_and_concurrent_receipts_have_one_row(self):
  with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:r=list(pool.map(lambda _:self.store(),range(4)))
  self.assertTrue(all(v['stored'] for v in r));self.assertEqual(query('SELECT count(*) FROM batcave.oracle_first_public_proofs_v1;'),'1')
  self.assertFalse(self.store(dict(self.proof,proof_signature_b64url='C'*86))['stored'])
 def test_no_and_revocation_block_new_deposit(self):
  self.f.decline();self.assertFalse(self.store()['stored'])
  self.setUp();query('UPDATE batcave.oracle_first_reviewer_v1 SET revoked_at=now();');self.assertFalse(self.store()['stored'])
 def test_owner_rotation_and_released_or_expired_intent_block_deposit(self):
  for statement in ["UPDATE batcave.linux_owner_keys_v1 SET public_key_sha256=repeat('f',64);","UPDATE batcave.change_gate_intents SET state='released';","UPDATE batcave.change_gate_intents SET valid_until=now()-interval '1 second';"]:
   self.setUp();query(statement);self.assertFalse(self.store()['stored'])
 def test_nonce_policy_payload_and_authority_fields_cannot_be_substituted(self):
  self.assertFalse(self.store(payload_hash='f'*64)['stored'])
  for values in [dict(nonce='f'*32),dict(policy_sha256='f'*64),dict(reviewer_public_key_sha256='f'*64),dict(grant_issued=True),dict(independently_attested=True)]:
   self.assertFalse(self.store(dict(self.proof,**values))['stored'])
 def test_clients_cannot_read_insert_or_invoke_receipt_storage(self):
  for role in ['anon','authenticated']:
   for statement in ['SELECT * FROM batcave.oracle_first_public_proofs_v1',"SELECT batcave.oracle_first_store_public_proof_v1(NULL,NULL,NULL,NULL)"]:
    self.assertIn('permission denied',query(f'SET ROLE {role};{statement};',ok=False))
 def test_receipt_is_append_only_and_no_after_deposit_still_stops_enrollment(self):
  self.assertTrue(self.store()['stored'])
  self.assertIn('append-only',query('DELETE FROM batcave.oracle_first_public_proofs_v1;',ok=False))
  self.assertIn('append-only',query("UPDATE batcave.oracle_first_public_proofs_v1 SET proof_sha256=repeat('b',64);",ok=False))
  self.f.decline();self.assertFalse(self.f.finish(self.c)['inserted'])
 def test_expired_or_consumed_challenge_cannot_create_a_new_receipt(self):
  self.assertTrue(self.f.finish(self.c)['inserted']);self.assertFalse(self.store()['stored'])
  self.setUp();expired=self.f.challenge(expired=True);self.c=expired;self.assertFalse(self.store()['stored'])
if __name__=='__main__':unittest.main(verbosity=2)
