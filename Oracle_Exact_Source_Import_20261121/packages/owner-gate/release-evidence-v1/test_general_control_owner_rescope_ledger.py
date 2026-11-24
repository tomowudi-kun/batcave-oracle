"""Disposable PostgreSQL ONLY: owner root rescope pending, never grant."""
import concurrent.futures
import json
import unittest
import uuid
from pathlib import Path
from test_release_ledger import query, literal

OWNER='123e4567-e89b-42d3-a456-426614174000'
ROOT='a'*64
KEY='b'*64
SOURCE='c'*40
POLICY='d'*64
SIG='f'*128

class RootScopePending(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  # query() strictly refuses any non-localhost/non-release_gate_test DB.
  query(Path(__file__).with_name('general_control_owner_rescope_ledger_STAGED.sql').read_text())
 def setUp(self):
  query('TRUNCATE batcave.general_control_owner_scope_pending_staged_v1,batcave.general_control_owner_rescope_challenges_staged_v1 CASCADE;')
  self.id=str(uuid.uuid4())
  self.nonce=uuid.uuid4().hex
  self.insert(self.id,self.nonce)
 def insert(self,request,nonce,owner=OWNER):
  payload=dict(schema='batcave.general_control.owner_rescope_challenge.v1',
   owner_user_id=owner,challenge_id=request,nonce=nonce,
   root_key_sha256=ROOT,scope_public_key_hex=KEY,source_commit=SOURCE,policy_digest=POLICY,
   issued_at='2026-11-22T22:59:00.000Z',
   expires_at='2026-11-22T23:02:00.000Z',
   execution_authorized=False,deployment_authorized=False)
  # Store fresh wall-clock timestamps, not static 2026 test fixture times.
  issued=query("SELECT to_char(date_trunc('milliseconds',clock_timestamp()),'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"');")
  expiry=query("SELECT to_char(date_trunc('milliseconds',clock_timestamp()+interval '2 minutes'),'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"');")
  payload['issued_at']=issued
  payload['expires_at']=expiry
  query(f"""INSERT INTO batcave.general_control_owner_rescope_challenges_staged_v1
    (challenge_id,owner_user_id,nonce,root_key_sha256,scope_public_key_hex,
     source_commit,policy_digest,issued_at,expires_at,payload)
    VALUES('{request}','{owner}','{nonce}','{ROOT}','{KEY}','{SOURCE}',
     '{POLICY}',{literal(issued)}::timestamptz,{literal(expiry)}::timestamptz,
     {literal(json.dumps(payload))}::jsonb);""")
 def endorse(self,owner=OWNER,ident=None,nonce=None,root=ROOT,key=KEY,source=SOURCE,policy=POLICY,sig=SIG):
  return query(f"""SELECT batcave.general_control_record_root_rescope_staged_v1(
   '{owner}','{ident or self.id}','{nonce or self.nonce}','{root}',
   '{key}','{source}','{policy}','{sig}');""")=='t'
 def test_one_use_pending_record_and_no_active_permission(self):
  self.assertTrue(self.endorse());self.assertFalse(self.endorse())
  self.assertEqual(query("SELECT state FROM batcave.general_control_owner_rescope_challenges_staged_v1;"),'endorsed')
  self.assertEqual(query("SELECT state FROM batcave.general_control_owner_scope_pending_staged_v1;"),'pending_independent_review')
  self.assertEqual(query("SELECT (execution_authorized OR deployment_authorized)::text FROM batcave.general_control_owner_scope_pending_staged_v1;"),'false')
 def test_mismatches_and_bad_signature_do_not_consume(self):
  for opts in [dict(owner=str(uuid.uuid4())),dict(ident=str(uuid.uuid4())),
   dict(nonce='f'*32),dict(root='f'*64),dict(key='f'*64),
   dict(source='f'*40),dict(policy='f'*64),dict(sig='bad')]:
   self.assertFalse(self.endorse(**opts))
  self.assertEqual(query("SELECT state FROM batcave.general_control_owner_rescope_challenges_staged_v1;"),'unused')
 def test_expired_cannot_admit(self):
  query("""WITH t AS (
     SELECT date_trunc('milliseconds',clock_timestamp()-interval '10 minutes') AS issued,
            date_trunc('milliseconds',clock_timestamp()-interval '8 minutes') AS expires)
    UPDATE batcave.general_control_owner_rescope_challenges_staged_v1 c
    SET issued_at=t.issued,expires_at=t.expires,
        payload=jsonb_set(jsonb_set(c.payload,'{issued_at}',
           to_jsonb(to_char(t.issued,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))),
           '{expires_at}',to_jsonb(to_char(t.expires,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')))
    FROM t;""")
  self.assertFalse(self.endorse())
 def test_concurrent_submissions_exactly_one(self):
  with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
   outcomes=list(pool.map(lambda _:self.endorse(),range(4)))
  self.assertEqual(outcomes.count(True),1)
  self.assertEqual(outcomes.count(False),3)
  self.assertEqual(query("SELECT count(*) FROM batcave.general_control_owner_scope_pending_staged_v1;"),'1')
 def test_second_pending_scope_cannot_override_first(self):
  self.assertTrue(self.endorse())
  second=str(uuid.uuid4());nonce=uuid.uuid4().hex;self.insert(second,nonce)
  error=query(f"""SELECT batcave.general_control_record_root_rescope_staged_v1(
   '{OWNER}','{second}','{nonce}','{ROOT}','{KEY}','{SOURCE}','{POLICY}','{SIG}');""",ok=False)
  self.assertIn('duplicate key',error)
  self.assertEqual(query(f"SELECT state FROM batcave.general_control_owner_rescope_challenges_staged_v1 WHERE challenge_id='{second}';"),'unused')
 def test_evidence_insert_failure_rolls_back_nonce(self):
  query("""CREATE OR REPLACE FUNCTION batcave.block_rescope_test() RETURNS trigger
   LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic re-scope evidence failure'; END$$;
   CREATE TRIGGER synthetic_block_rescope BEFORE INSERT ON batcave.general_control_owner_scope_pending_staged_v1
   FOR EACH ROW EXECUTE FUNCTION batcave.block_rescope_test();""")
  error=query(f"""SELECT batcave.general_control_record_root_rescope_staged_v1(
   '{OWNER}','{self.id}','{self.nonce}','{ROOT}','{KEY}','{SOURCE}','{POLICY}','{SIG}');""",ok=False)
  self.assertIn('synthetic re-scope evidence failure',error)
  self.assertEqual(query("SELECT state FROM batcave.general_control_owner_rescope_challenges_staged_v1;"),'unused')
  query("DROP TRIGGER synthetic_block_rescope ON batcave.general_control_owner_scope_pending_staged_v1; DROP FUNCTION batcave.block_rescope_test();")
 def test_untrusted_roles_cannot_read_or_call_private_ledger(self):
  for role in ['anon','authenticated']:
   for statement in [
    "SELECT * FROM batcave.general_control_owner_scope_pending_staged_v1",
    f"SELECT batcave.general_control_record_root_rescope_staged_v1('{OWNER}','{self.id}','{self.nonce}','{ROOT}','{KEY}','{SOURCE}','{POLICY}','{SIG}')"]:
    err=query(f"SET ROLE {role};{statement};",ok=False)
    self.assertIn('permission denied',err)

if __name__=='__main__':unittest.main(verbosity=2)
