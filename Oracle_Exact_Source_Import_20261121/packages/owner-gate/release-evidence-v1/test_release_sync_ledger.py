"""Real PostgreSQL evidence/No races. Isolated localhost synthetic database only.
Actual signature verification runs in test_release_sync.mjs before this boundary.
"""
import concurrent.futures
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import unittest
import test_first_ledger as first
from test_release_ledger import query,literal,OWNER,js_iso

class ReleaseSyncLedgerTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  first.FirstLedgerTests.setUpClass()
  query(Path(__file__).with_name('release_sync_STAGED.sql').read_text())
 def setUp(self):
  self.f=first.FirstLedgerTests();self.f.setUp();assert self.f.finish(self.f.challenge())['inserted']
  self.c=self.f.challenge('release');assert self.endorse()['saved']
  payload=json.loads(query(f"SELECT payload FROM batcave.oracle_first_challenges_v1 WHERE id='{self.c[0]}';"))
  self.review=dict(schema='batcave.nanny.local.review.evidence.v1',status='NOT_ENROLLED_BY_THIS_COMMAND',intent_key=payload['intent_key'],nonce=payload['nonce'],expires_at=payload['expires_at'],reviewer_public_key_sha256='b'*64,signature_b64url='B'*86,reviewer_host_identity=dict(host='Cortana',os='win32',user='SyntheticReviewer'),local_file_hashes=dict(gate_sha256=payload['owner_gate_zip_sha256'],worker_sha256=payload['worker_zip_sha256'],source_commit=payload['pr_head_sha']),reviewed_at=js_iso(dt.datetime.now(dt.timezone.utc)),deployment_authorized=False,execution_authorized=False)
 def endorse(self,c=None):
  c=c or self.c
  return json.loads(query(f"SELECT batcave.oracle_release_save_endorsement_v1('{OWNER}','{c[0]}','{c[1]}',repeat('A',86));"))
 def decline(self):return json.loads(query(f"SELECT batcave.oracle_release_decline_v1('{OWNER}','{self.f.policy_hash}');"))
 def store(self,review=None):
  return json.loads(query(f"SELECT batcave.oracle_release_store_review_v1('{self.c[0]}','{self.c[1]}',{literal(json.dumps(review or self.review))}::jsonb,repeat('e',64));"))
 def test_receipt_storage_is_evidence_only_and_keeps_registered_singleton(self):
  self.assertTrue(self.store()['stored']);self.assertEqual(query('SELECT count(*) FROM batcave.oracle_release_public_reviews_v1;'),'1')
  self.assertEqual(query('SELECT registered_at IS NOT NULL FROM batcave.oracle_first_reviewer_v1;'),'t')
  self.assertEqual(query(f"SELECT consumed_at IS NULL FROM batcave.oracle_first_challenges_v1 WHERE id='{self.c[0]}';"),'t')
  self.assertEqual(query('SELECT state FROM batcave.change_gate_intents;'),'held')
  self.assertEqual(query('SELECT count(*) FROM batcave.oracle_release_public_reviews_v1 WHERE deployment_authorized OR execution_authorized OR grant_issued;'),'0')
 def test_actual_driver_stores_review_object_not_encoded_json_string(self):
  script="""
import postgres from 'postgres';import {readFileSync} from 'node:fs';import {proofRepository} from './repository.mjs';
const f=JSON.parse(readFileSync(0,'utf8')),sql=postgres(process.env.BATCAVE_TEST_DATABASE_URL,{prepare:false,max:1});
try{const repo=proofRepository(sql),r=await repo.storeReview(f.id,f.hash,f.review,'e'.repeat(64));console.log(JSON.stringify(r));}finally{await sql.end();}
"""
  r=subprocess.run(['node','--input-type=module','-e',script],input=json.dumps(dict(id=self.c[0],hash=self.c[1],review=self.review)),capture_output=True,text=True,cwd=Path(__file__).resolve().parent.parent/'proof-transfer-v1',env=os.environ,timeout=25)
  self.assertEqual(r.returncode,0,r.stderr);self.assertTrue(json.loads(r.stdout)['stored'])
 def test_concurrent_identical_public_deposits_are_one_immutable_row(self):
  with concurrent.futures.ThreadPoolExecutor(max_workers=3) as p:r=list(p.map(lambda _:self.store(),range(3)))
  self.assertTrue(all(v['stored'] for v in r));self.assertEqual(query('SELECT count(*) FROM batcave.oracle_release_public_reviews_v1;'),'1')
  self.assertFalse(self.store(dict(self.review,signature_b64url='C'*86))['stored'])
  self.assertIn('append-only',query('DELETE FROM batcave.oracle_release_public_reviews_v1;',ok=False))
 def test_no_after_receipt_stops_final_recording_and_does_not_unregister(self):
  self.assertTrue(self.store()['stored']);self.assertTrue(self.decline()['declined']);self.assertFalse(self.f.finish(self.c)['inserted']);self.assertFalse(self.store()['stored']);self.assertFalse(self.endorse()['saved'])
  self.assertEqual(query('SELECT registered_at IS NOT NULL FROM batcave.oracle_first_reviewer_v1;'),'t')
  fresh=self.f.challenge('release',issued_now=True);self.assertTrue(self.endorse(fresh)['saved']);self.assertFalse(self.f.finish(self.c)['inserted'])
 def test_stale_revoked_owner_and_expired_challenges_cannot_store(self):
  for sql in ["UPDATE batcave.oracle_first_reviewer_v1 SET revoked_at=now();","UPDATE batcave.linux_owner_keys_v1 SET public_key_sha256=repeat('f',64);","UPDATE batcave.change_gate_intents SET valid_until=now()-interval '1 second';"]:
   self.setUp();query(sql);self.assertFalse(self.store()['stored'])
  self.setUp();expired=self.f.challenge('release',expired=True);self.assertFalse(self.endorse(expired)['saved'])
 def test_changed_scope_nonce_and_flags_cannot_be_deposited(self):
  for values in [dict(nonce='f'*32),dict(reviewer_public_key_sha256='c'*64),dict(execution_authorized=True),dict(local_file_hashes=dict(self.review['local_file_hashes'],source_commit='a'*40))]:self.assertFalse(self.store(dict(self.review,**values))['stored'])
 def test_no_and_finish_lock_race_has_one_consistent_order_and_cannot_replay(self):
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as p:
   a=p.submit(self.f.finish,self.c);b=p.submit(self.decline);finish=a.result();decline=b.result()
  self.assertTrue(decline['declined']);self.assertFalse(self.f.finish(self.c)['inserted']);self.assertFalse(self.store()['stored'])
  self.assertEqual(query('SELECT count(*) FROM batcave.oracle_first_challenges_v1 WHERE deployment_authorized OR execution_authorized OR grant_issued;'),'0')
 def test_untrusted_roles_cannot_store_endorse_or_decline(self):
  for role in ['anon','authenticated']:
   for call in ['SELECT * FROM batcave.oracle_release_public_reviews_v1','SELECT batcave.oracle_release_store_review_v1(NULL,NULL,NULL,NULL)','SELECT batcave.oracle_release_save_endorsement_v1(NULL,NULL,NULL,NULL)','SELECT batcave.oracle_release_decline_v1(NULL,NULL)']:
    self.assertIn('permission denied',query(f'SET ROLE {role};{call};',ok=False))
if __name__=='__main__':unittest.main(verbosity=2)
