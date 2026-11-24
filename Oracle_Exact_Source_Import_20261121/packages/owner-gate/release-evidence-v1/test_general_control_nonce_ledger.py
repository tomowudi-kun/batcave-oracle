"""Isolated disposable PostgreSQL nonce atomicity tests. No production grant."""
import concurrent.futures
import unittest
import uuid
from pathlib import Path
from test_release_ledger import query, literal
OWNER='123e4567-e89b-42d3-a456-426614174000'
class NonceLedger(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  # query() refuses non-localhost/non-release_gate_test URLs.
  query(Path(__file__).with_name('general_control_nonce_ledger_STAGED.sql').read_text())
 def setUp(self):
  query('TRUNCATE batcave.general_control_nonce_ledger_v1;')
  self.id=str(uuid.uuid4())
  self.nonce=uuid.uuid4().hex
  self.sha='a'*64
  self.policy='b'*64
  query(f"""INSERT INTO batcave.general_control_nonce_ledger_v1
    (request_id,owner_user_id,nonce,request_sha256,policy_sha256,expires_at)
    VALUES('{self.id}','{OWNER}','{self.nonce}','{self.sha}','{self.policy}',clock_timestamp()+interval '2 minutes');""")
 def consume(self,sha=None,policy=None,owner=OWNER,nonce=None,ident=None):
  return query(f"SELECT batcave.general_control_consume_nonce_staged_v1('{ident or self.id}','{owner}','{nonce or self.nonce}','{sha or self.sha}','{policy or self.policy}');")=='t'
 def decline(self):
  return query(f"SELECT batcave.general_control_decline_nonce_staged_v1('{self.id}','{OWNER}','{self.nonce}');")=='t'
 def test_single_consume_then_replay_denied(self):
  self.assertTrue(self.consume());self.assertFalse(self.consume())
  self.assertEqual(query('SELECT state FROM batcave.general_control_nonce_ledger_v1;'),'consumed')
  self.assertEqual(query('SELECT count(*) FROM batcave.general_control_nonce_ledger_v1 WHERE consumed_at IS NOT NULL;'),'1')
 def test_wrong_owner_nonce_digest_policy_and_request_denied(self):
  for params in [dict(owner=str(uuid.uuid4())),dict(nonce='f'*32),dict(sha='f'*64),
                 dict(policy='f'*64),dict(ident=str(uuid.uuid4()))]:
   self.assertFalse(self.consume(**params))
  self.assertEqual(query('SELECT state FROM batcave.general_control_nonce_ledger_v1;'),'unused')
 def test_expired_nonce_denied(self):
  query("UPDATE batcave.general_control_nonce_ledger_v1 SET expires_at=clock_timestamp()-interval '1 second';")
  self.assertFalse(self.consume());self.assertFalse(self.decline())
 def test_decline_prevents_consume(self):
  self.assertTrue(self.decline());self.assertFalse(self.consume());self.assertFalse(self.decline())
  self.assertEqual(query('SELECT state FROM batcave.general_control_nonce_ledger_v1;'),'declined')
 def test_consumed_cannot_be_declined(self):
  self.assertTrue(self.consume());self.assertFalse(self.decline())
 def test_concurrent_consume_has_exactly_one_winner(self):
  with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
   answers=list(pool.map(lambda _:self.consume(),range(4)))
  self.assertEqual(answers.count(True),1)
  self.assertEqual(answers.count(False),3)
 def test_duplicate_owner_nonce_and_request_rejected(self):
  x=str(uuid.uuid4())
  bad=query(f"""INSERT INTO batcave.general_control_nonce_ledger_v1
    (request_id,owner_user_id,nonce,request_sha256,policy_sha256,expires_at)
    VALUES('{x}','{OWNER}','{self.nonce}','{self.sha}','{self.policy}',clock_timestamp()+interval '2 minutes');""",ok=False)
  self.assertIn('duplicate key',bad)
 def test_untrusted_roles_have_no_table_or_function_access(self):
  for role in ['anon','authenticated']:
   for command in ['SELECT * FROM batcave.general_control_nonce_ledger_v1',
    f"SELECT batcave.general_control_consume_nonce_staged_v1('{self.id}','{OWNER}','{self.nonce}','{self.sha}','{self.policy}')"]:
    err=query(f'SET ROLE {role};{command};',ok=False)
    self.assertIn('permission denied',err)
if __name__=='__main__':unittest.main(verbosity=2)
