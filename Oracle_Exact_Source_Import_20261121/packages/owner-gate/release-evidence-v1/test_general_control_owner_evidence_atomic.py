"""Staged atomic owner evidence receipt tests; disposable PostgreSQL only."""
import concurrent.futures
import unittest
import uuid
from pathlib import Path
from test_release_ledger import query
OWNER='123e4567-e89b-42d3-a456-426614174000'
class OwnerEvidenceAtomicity(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  here=Path(__file__).parent
  query((here/'general_control_nonce_ledger_STAGED.sql').read_text())
  query((here/'general_control_owner_evidence_atomic_STAGED.sql').read_text())
 def setUp(self):
  query('TRUNCATE batcave.general_control_owner_evidence_staged_v1, batcave.general_control_nonce_ledger_v1 CASCADE;')
  self.request=str(uuid.uuid4());self.nonce=uuid.uuid4().hex
  query(f"""INSERT INTO batcave.general_control_nonce_ledger_v1
    (request_id,owner_user_id,nonce,request_sha256,policy_sha256,expires_at)
    VALUES('{self.request}','{OWNER}','{self.nonce}','{'a'*64}','{'b'*64}',
    clock_timestamp()+interval '2 minutes');""")
 def record(self,owner=OWNER,nonce=None,sha='a'*64,policy='b'*64,sig='c'*128):
  return query(f"""SELECT batcave.general_control_record_owner_evidence_staged_v1(
   '{self.request}','{owner}','{nonce or self.nonce}','{sha}','{policy}','{sig}');""")=='t'
 def test_single_record_atomic_and_replay_denied(self):
  self.assertTrue(self.record());self.assertFalse(self.record())
  self.assertEqual(query('SELECT count(*) FROM batcave.general_control_owner_evidence_staged_v1;'),'1')
  self.assertEqual(query('SELECT state FROM batcave.general_control_nonce_ledger_v1;'),'consumed')
 def test_wrong_binding_and_invalid_signature_do_not_consume(self):
  self.assertFalse(self.record(owner=str(uuid.uuid4())))
  self.assertFalse(self.record(nonce='d'*32))
  self.assertFalse(self.record(sha='f'*64))
  self.assertFalse(self.record(policy='f'*64))
  self.assertFalse(self.record(sig='bad'))
  self.assertEqual(query('SELECT state FROM batcave.general_control_nonce_ledger_v1;'),'unused')
  self.assertEqual(query('SELECT count(*) FROM batcave.general_control_owner_evidence_staged_v1;'),'0')
 def test_decline_or_expiry_prevents_owner_receipt(self):
  self.assertEqual(query(f"SELECT batcave.general_control_decline_nonce_staged_v1('{self.request}','{OWNER}','{self.nonce}');"),'t')
  self.assertFalse(self.record())
  self.assertEqual(query('SELECT count(*) FROM batcave.general_control_owner_evidence_staged_v1;'),'0')
 def test_racing_signatures_have_one_durable_winner(self):
  with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
   results=list(pool.map(lambda _:self.record(),range(4)))
  self.assertEqual(results.count(True),1)
  self.assertEqual(results.count(False),3)
  self.assertEqual(query('SELECT count(*) FROM batcave.general_control_owner_evidence_staged_v1;'),'1')
 def test_insert_failure_rolls_back_nonce_consumption(self):
  # Force an evidence constraint error after the nonce UPDATE, in same transaction.
  query(f"""CREATE OR REPLACE FUNCTION pg_temp.block_owner_evidence() RETURNS trigger
    LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic evidence insert failure'; END$$;
    CREATE TRIGGER synthetic_block BEFORE INSERT ON batcave.general_control_owner_evidence_staged_v1
    FOR EACH ROW EXECUTE FUNCTION pg_temp.block_owner_evidence();""")
  error=query(f"""SELECT batcave.general_control_record_owner_evidence_staged_v1(
   '{self.request}','{OWNER}','{self.nonce}','{'a'*64}','{'b'*64}','{'c'*128}');""",ok=False)
  self.assertIn('synthetic evidence insert failure',error)
  self.assertEqual(query('SELECT state FROM batcave.general_control_nonce_ledger_v1;'),'unused')
  self.assertEqual(query('SELECT count(*) FROM batcave.general_control_owner_evidence_staged_v1;'),'0')
  query('DROP TRIGGER synthetic_block ON batcave.general_control_owner_evidence_staged_v1;')
 def test_client_roles_have_no_evidence_access(self):
  for role in ['anon','authenticated']:
   for statement in ['SELECT * FROM batcave.general_control_owner_evidence_staged_v1',
    f"SELECT batcave.general_control_record_owner_evidence_staged_v1('{self.request}','{OWNER}','{self.nonce}','{'a'*64}','{'b'*64}','{'c'*128}')"]:
    self.assertIn('permission denied',query(f'SET ROLE {role};{statement};',ok=False))
if __name__=='__main__':unittest.main(verbosity=2)
