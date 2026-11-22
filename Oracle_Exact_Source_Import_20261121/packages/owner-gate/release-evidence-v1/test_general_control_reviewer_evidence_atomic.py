"""Disposable local PostgreSQL: reviewer evidence atomicity, never production."""
import concurrent.futures
import unittest
import uuid
from pathlib import Path
from test_release_ledger import query

OWNER='123e4567-e89b-42d3-a456-426614174000'
REVIEWER='123e4567-e89b-42d3-a456-426614174009'
POLICY='a'*64
REQ='b'*64
SOURCE='c'*40
KEY='d'*64
SIG='e'*128

class ReviewerEvidence(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  for name in ['general_control_nonce_ledger_STAGED.sql',
   'general_control_owner_evidence_atomic_STAGED.sql',
   'general_control_reviewer_evidence_atomic_STAGED.sql']:
   query(Path(__file__).with_name(name).read_text())
 def setUp(self):
  query('TRUNCATE batcave.general_control_reviewer_evidence_staged_v1,'
   'batcave.general_control_owner_evidence_staged_v1,'
   'batcave.general_control_nonce_ledger_v1 CASCADE;')
  self.request=str(uuid.uuid4())
  self.nonce=uuid.uuid4().hex
  query(f"""INSERT INTO batcave.general_control_nonce_ledger_v1
    (request_id,owner_user_id,nonce,request_sha256,policy_sha256,expires_at)
    VALUES('{self.request}','{OWNER}','{self.nonce}','{REQ}','{POLICY}',
      clock_timestamp()+interval '2 minutes');""")
 def owner(self):
  return query(f"""SELECT batcave.general_control_record_owner_evidence_staged_v1(
    '{self.request}','{OWNER}','{self.nonce}','{REQ}','{POLICY}','{SIG}');""")=='t'
 def reviewer(self,request=None,owner=OWNER,nonce=None,policy=POLICY,source=SOURCE,
   reviewer=REVIEWER,key=KEY,sig=SIG):
  return query(f"""SELECT batcave.general_control_append_reviewer_evidence_staged_v1(
    '{request or self.request}','{owner}','{nonce or self.nonce}','{policy}',
    '{source}','{reviewer}','{key}','{sig}');""")=='t'
 def test_requires_durable_owner_evidence(self):
  self.assertFalse(self.reviewer())
  self.assertTrue(self.owner())
  self.assertTrue(self.reviewer())
  self.assertEqual(query('SELECT count(*) FROM batcave.general_control_reviewer_evidence_staged_v1;'),'1')
 def test_duplicate_and_concurrent_are_one_use(self):
  self.assertTrue(self.owner())
  with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
   result=list(pool.map(lambda _:self.reviewer(),range(4)))
  self.assertEqual(result.count(True),1)
  self.assertEqual(result.count(False),3)
  self.assertEqual(query('SELECT count(*) FROM batcave.general_control_reviewer_evidence_staged_v1;'),'1')
 def test_mismatched_owner_nonce_policy_and_signature_rejected(self):
  self.assertTrue(self.owner())
  for opts in [dict(owner=str(uuid.uuid4())),dict(nonce='f'*32),
    dict(policy='f'*64),dict(reviewer=OWNER),dict(key='invalid'),dict(sig='invalid'),
    dict(source='invalid'),dict(request=str(uuid.uuid4()))]:
   self.assertFalse(self.reviewer(**opts))
  self.assertEqual(query('SELECT count(*) FROM batcave.general_control_reviewer_evidence_staged_v1;'),'0')
 def test_no_authorization_or_grants(self):
  self.assertTrue(self.owner());self.assertTrue(self.reviewer())
  self.assertEqual(query('SELECT (execution_authorized OR deployment_authorized)::text FROM batcave.general_control_reviewer_evidence_staged_v1;'),'false')
  self.assertEqual(query("SELECT has_table_privilege('authenticated','batcave.general_control_reviewer_evidence_staged_v1','SELECT')::text;"),'false')
  self.assertEqual(query("SELECT has_function_privilege('authenticated','batcave.general_control_append_reviewer_evidence_staged_v1(uuid,uuid,text,text,text,uuid,text,text)','EXECUTE')::text;"),'false')
 def test_declined_nonce_cannot_be_reviewed(self):
  query(f"""UPDATE batcave.general_control_nonce_ledger_v1 SET state='declined'
   WHERE request_id='{self.request}';""")
  self.assertFalse(self.reviewer())
 def test_receipt_insert_failure_does_not_change_owner_record(self):
  self.assertTrue(self.owner())
  self.assertFalse(self.reviewer(sig='bad'))
  self.assertEqual(query('SELECT state FROM batcave.general_control_owner_evidence_staged_v1;'),'owner_signature_recorded_only')

if __name__=='__main__': unittest.main()
