"""Full existing SQL grant -> v0.3.1 lease -> receipt boundary, localhost ONLY.

These records/signatures are synthetic SQL fixtures. The authenticated Edge
verifiers, including genuine synthetic owner signatures, are tested separately.
This suite never claims SQL independently verifies an Ed25519 signature.
"""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
import uuid
from test_release_ledger import query, literal, OWNER

HERE=Path(__file__).resolve().parent
PACKAGES=HERE.parent.parent
TOKEN='a'*64
DEVICE='123e4567-e89b-42d3-a456-426614174099'
KEY='4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b'
FIXTURE='4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f'

class LabGrantLeaseTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  # The imported helper refuses any host/database except localhost/release_gate_test.
  # This suite is last in the isolated CI database; no live schema is reachable.
  query("""
DROP SCHEMA batcave CASCADE; CREATE SCHEMA batcave;
CREATE SCHEMA IF NOT EXISTS extensions;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN CREATE ROLE service_role; END IF; END $$;
CREATE TABLE batcave.devices(id uuid PRIMARY KEY,device_name text,state text,last_seen_at timestamptz);
CREATE TABLE public.batcave_device_credentials(device_id uuid,token_hash text,revoked_at timestamptz);
CREATE TABLE batcave.commands(id uuid PRIMARY KEY,device_id uuid,action text,status text,payload jsonb,created_at timestamptz DEFAULT now(),expires_at timestamptz,attempt_count int DEFAULT 0,lease_until timestamptz,completed_at timestamptz,result jsonb);
CREATE TABLE batcave.command_events(command_id uuid,event_type text,details jsonb);
CREATE TABLE batcave.device_receipts(command_id uuid PRIMARY KEY,device_id uuid,outcome text,finished_at timestamptz,result jsonb);
""")
  query((HERE.parent/'sql/lab_only_enrollment_additive_STAGED.sql').read_text())
  query((PACKAGES/'oracle-worker/cloud/oracle_bridge_rpc_v03.sql').read_text())
  query("REVOKE ALL ON FUNCTION public.batcave_oracle_bridge_v1(text,text,uuid,text,jsonb) FROM PUBLIC,anon,authenticated; GRANT EXECUTE ON FUNCTION public.batcave_oracle_bridge_v1(text,text,uuid,text,jsonb) TO service_role;")
 def setUp(self):
  query(f"""
TRUNCATE batcave.oracle_lab_review_grants_v1,batcave.oracle_lab_reviewer_keys_v1,batcave.oracle_lab_enroll_challenges_v2,batcave.commands,batcave.command_events,batcave.device_receipts,batcave.devices,public.batcave_device_credentials;
INSERT INTO batcave.devices VALUES('{DEVICE}','Oracle','active',NULL);
INSERT INTO public.batcave_device_credentials VALUES('{DEVICE}','{TOKEN}',NULL);
""")
  self.job=self.new_job()
 def new_job(self,operation='model_generate_and_verify_v1'):
  ident=str(uuid.uuid4());nonce=uuid.uuid4().hex
  action={'runtime_inventory':'oracle_runtime_inventory_v1','disposable_project_build_v1':'oracle_disposable_build_v1','model_generate_and_verify_v1':'oracle_model_generate_v1'}[operation]
  payload=dict(schema='batcave.oracle.job.v1',nonce=nonce,operation=operation)
  if operation=='model_generate_and_verify_v1':payload.update(fixture='fixed_clamp_score_v1',artifact_sha256=FIXTURE)
  query(f"INSERT INTO batcave.commands(id,device_id,action,status,payload,expires_at) VALUES('{ident}','{DEVICE}',{literal(action)},'pending',{literal(json.dumps(payload))}::jsonb,now()+interval '4 minutes');")
  expiry=query(f"SELECT expires_at FROM batcave.commands WHERE id='{ident}';")
  return dict(id=ident,nonce=nonce,payload=payload,expires_at=expiry)
 def enroll(self):
  ident=str(uuid.uuid4());nonce=uuid.uuid4().hex
  expiry=query(f"INSERT INTO batcave.oracle_lab_enroll_challenges_v2(challenge_id,owner_user_id,nonce,expires_at) VALUES('{ident}','{OWNER}','{nonce}',now()+interval '5 minutes') RETURNING expires_at;")
  public=dict(schema='batcave.nanny.lab.public_key.v1',host='CORTANA',reviewer_sid='S-1-5-19',role='lab_reviewer_only',public_key_sha256=KEY,public_key_pem='synthetic SQL fixture only'.ljust(110,'x'),cloud_enrolled=False,production_release_authorized=False)
  result=json.loads(query(f"SELECT public.batcave_oracle_lab_enroll_verified_v2('{OWNER}','{ident}','{nonce}',{literal(expiry)}::timestamptz,{literal(json.dumps(public))}::jsonb,{literal('A'*86)});"))
  self.assertTrue(result['inserted'])
 def grant_input(self,job=None):
  job=job or self.job
  raw=json.dumps(dict(request_id=job['id'],nonce=job['nonce'],operation='model_generate_and_verify_v1',scope='disposable_lab_only',fixture='fixed_clamp_score_v1',artifact_sha256=FIXTURE,expires_at=job['expires_at']),sort_keys=True,separators=(',',':'))
  sha=hashlib.sha256(raw.encode()).hexdigest()
  receipt=dict(payload=dict(decision='LAB_ALLOW',request_id=job['id'],request_sha256=sha,execution_authorized=False,deployment_authorized=False,production_release_authorized=False),signature_b64url='B'*86)
  return dict(owner_user_id=OWNER,job_id=job['id'],nonce=job['nonce'],request_sha256=sha,raw_request_json=raw,signed_receipt=receipt,expires_at=job['expires_at'])
 def grant(self,job=None):
  x=self.grant_input(job)
  return json.loads(query(f"SELECT public.batcave_oracle_lab_record_verified_v2('{OWNER}','{x['job_id']}','{x['nonce']}','{x['request_sha256']}',{literal(x['raw_request_json'])},{literal(json.dumps(x['signed_receipt']))}::jsonb,{literal(x['expires_at'])}::timestamptz);"))
 def rpc(self,op='poll_model',job=None,result=None,token=TOKEN):
  ident='NULL' if job is None else literal(job['id'])+'::uuid'
  nonce='NULL' if job is None else literal(job['nonce'])
  result='NULL' if result is None else literal(json.dumps(result))+'::jsonb'
  return json.loads(query(f"SELECT public.batcave_oracle_bridge_v1({literal(token)},{literal(op)},{ident},{nonce},{result});"))
 def test_without_enrollment_or_grant_model_cannot_lease(self):
  self.assertFalse(self.rpc()['pending']);self.assertFalse(self.grant()['inserted'])
  self.enroll();self.assertFalse(self.rpc()['pending'])
  self.assertEqual(query('SELECT attempt_count FROM batcave.commands;'),'0')
 def test_actual_driver_repository_stores_object_then_real_rpc_leases_once(self):
  self.enroll();x=self.grant_input()
  script="""
import postgres from 'postgres';import {readFileSync} from 'node:fs';
import {labRepository} from '../release-evidence-v1/lab_repository.mjs';
const x=JSON.parse(readFileSync(0,'utf8')),sql=postgres(process.env.BATCAVE_TEST_DATABASE_URL,{prepare:false,max:1});
try{
 const [old]=await sql`SELECT public.batcave_oracle_lab_record_verified_v2(${x.owner_user_id}::uuid,${x.job_id}::uuid,${x.nonce},${x.request_sha256},${x.raw_request_json},${JSON.stringify(x.signed_receipt)}::jsonb,${x.expires_at}::timestamptz) AS receipt`;
 const fixed=await labRepository(sql).insertVerifiedGrant(x);
 console.log(JSON.stringify({old:old.receipt,fixed}));
}finally{await sql.end();}
"""
  result=subprocess.run(['node','--input-type=module','-e',script],input=json.dumps(x),capture_output=True,text=True,cwd=HERE.parent/'proof-transfer-v1',env=os.environ,timeout=25)
  self.assertEqual(result.returncode,0,result.stderr);receipt=json.loads(result.stdout)
  self.assertFalse(receipt['old']['inserted']);self.assertTrue(receipt['fixed']['inserted'])
  self.assertTrue(self.rpc()['pending']);self.assertFalse(self.rpc()['pending'])
  self.assertEqual(query('SELECT attempt_count FROM batcave.commands;'),'1')
  self.assertEqual(query('SELECT count(*) FROM batcave.oracle_lab_review_grants_v1 WHERE consumed_at IS NOT NULL;'),'1')
 def test_concurrent_poll_has_one_winner_and_no_model_re_lease(self):
  self.enroll();self.assertTrue(self.grant()['inserted'])
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:self.rpc(),range(2)))
  self.assertEqual(sum(r.get('pending') is True for r in results),1)
  query("UPDATE batcave.commands SET lease_until=now()-interval '1 second';")
  self.assertFalse(self.rpc()['pending'])
  self.assertEqual(query('SELECT attempt_count FROM batcave.commands;'),'1')
 def test_old_inventory_and_build_work_without_model_grants(self):
  self.new_job('runtime_inventory');self.new_job('disposable_project_build_v1')
  self.assertEqual(self.rpc('poll')['job']['operation'],'runtime_inventory')
  self.assertEqual(self.rpc('poll_build')['job']['operation'],'disposable_project_build_v1')
  self.assertFalse(self.rpc()['pending'])
 def test_revoked_key_and_expired_grant_do_not_lease(self):
  self.enroll();self.assertTrue(self.grant()['inserted'])
  query("UPDATE batcave.oracle_lab_reviewer_keys_v1 SET revoked_at=now();")
  self.assertFalse(self.rpc()['pending'])
  query("UPDATE batcave.oracle_lab_reviewer_keys_v1 SET revoked_at=NULL;UPDATE batcave.oracle_lab_review_grants_v1 SET expires_at=now()-interval '1 second',enrolled_review_verified_at=now()-interval '5 minutes';")
  self.assertFalse(self.rpc()['pending'])
 def test_stale_job_nonce_and_changed_artifact_do_not_receive_grants(self):
  self.enroll();query("UPDATE batcave.commands SET payload=jsonb_set(payload,'{nonce}',to_jsonb(repeat('f',32)));")
  self.assertFalse(self.grant()['inserted'])
  query(f"UPDATE batcave.commands SET payload=jsonb_set(payload,'{{nonce}}',to_jsonb('{self.job['nonce']}'::text)),attempt_count=1;")
  self.assertFalse(self.grant()['inserted'])
  query("UPDATE batcave.commands SET attempt_count=0,payload=jsonb_set(payload,'{artifact_sha256}',to_jsonb(repeat('f',64)));")
  self.assertFalse(self.grant()['inserted'])
 def test_receipt_requires_consumed_grant_and_records_one_result(self):
  self.enroll();self.assertTrue(self.grant()['inserted'])
  result=dict(schema='batcave.linux.receipt.v1',job_id=self.job['id'],operation='model_generate_and_verify_v1',target='BatcaveUbuntu',outcome='success',completed_at='2026-11-21T23:00:00Z',receipt_hmac_sha256='c'*64,result=dict(tests_passed=True,tests_run=8,workspace='lab-projects/'+self.job['id'],artifact='src/model_generated.py',model='qwen2.5-coder:1.5b',artifact_sha256='d'*64,artifact_bytes=100,local_run_id=str(uuid.uuid4())))
  self.assertFalse(self.rpc('receipt',self.job,result)['ok'])
  self.assertTrue(self.rpc()['pending'])
  bad=json.loads(json.dumps(result));bad['result']['tests_run']=7
  self.assertFalse(self.rpc('receipt',self.job,bad)['ok'])
  self.assertEqual(self.rpc('receipt',self.job,result)['receipt'],'recorded')
  self.assertEqual(self.rpc('receipt',self.job,result)['receipt'],'already_recorded')
  self.assertEqual(query('SELECT count(*) FROM batcave.device_receipts;'),'1')
  self.assertEqual(query("SELECT count(*) FROM batcave.command_events WHERE event_type='oracle_model_lease';"),'1')
  self.assertEqual(query("SELECT count(*) FROM batcave.command_events WHERE event_type='oracle_model_receipt';"),'1')
 def test_wrong_device_credentials_and_client_writer_permissions_deny(self):
  self.assertEqual(self.rpc(token='f'*64)['http_status'],401)
  for role in ['anon','authenticated']:
   self.assertIn('permission denied',query(f"SET ROLE {role}; SELECT public.batcave_oracle_lab_record_verified_v2(NULL,NULL,NULL,NULL,NULL,NULL,NULL);",ok=False))
   self.assertIn('permission denied',query(f"SET ROLE {role}; SELECT public.batcave_oracle_bridge_v1('{TOKEN}','poll_model',NULL,NULL,NULL);",ok=False))

if __name__=='__main__':unittest.main(verbosity=2)
