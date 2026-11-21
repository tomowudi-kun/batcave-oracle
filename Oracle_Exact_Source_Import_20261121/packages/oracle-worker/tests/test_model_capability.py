import datetime as dt
import hashlib
import pathlib
import sys
import tempfile
import unittest
import uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1] / 'patch'))
import model_capability as c

NOW=dt.datetime(2026,11,21,tzinfo=dt.timezone.utc)

def job():
 return {'id':str(uuid.uuid4()), 'nonce':'b'*32,'operation':c.OPERATION,'expires_at':(NOW+dt.timedelta(minutes=3)).isoformat()}

class Agent:
 def __init__(self):self.calls=0
 def run_once(self,model,url,root):
  self.calls+=1
  d=pathlib.Path(root)/'runs'/str(uuid.uuid4());d.mkdir(parents=True)
  f=d/'model_generated.py';s=b'def clamp_score(score):\n if score < 0: return 0\n if score > 10: return 10\n return score\n';f.write_bytes(s)
  return {'status':'LAB_PASS','tests_run':8,'tests_passed':True,'artifact':str(f),'artifact_sha256':hashlib.sha256(s).hexdigest(),'run_id':d.name}

class Tests(unittest.TestCase):
 def test_success_and_no_duplicate_inference(self):
  j=job();a=Agent()
  with tempfile.TemporaryDirectory() as p:
   r=c.run_typed_job(j,a,p,now=NOW);self.assertTrue(r['tests_passed']);self.assertEqual(r['tests_run'],8)
   again=c.run_typed_job(j,a,p,now=NOW);self.assertEqual(r,again);self.assertEqual(a.calls,1)
 def test_agent_hash_mismatch_blocked(self):
  with tempfile.TemporaryDirectory() as p:
   f=pathlib.Path(p)/'agent.py';f.write_text('print(123)')
   with self.assertRaisesRegex(c.TaskBlocked,'source hash'):c.load_reviewed_agent(f)
 def test_agent_symlink_blocked(self):
  with tempfile.TemporaryDirectory() as p:
   base=pathlib.Path(p);(base/'x.py').write_text('pass');(base/'agent.py').symlink_to(base/'x.py')
   with self.assertRaisesRegex(c.TaskBlocked,'symlinked'):c.load_reviewed_agent(base/'agent.py')
 def test_operation_rejected(self):
  j=job();j['operation']='run_shell'
  with self.assertRaises(c.TaskBlocked):c.parse_job(j,NOW)
 def test_extra_params_rejected(self):
  j=job();j['prompt']='do arbitrary work'
  with self.assertRaises(c.TaskBlocked):c.parse_job(j,NOW)
 def test_expired_rejected(self):
  j=job();j['expires_at']=(NOW-dt.timedelta(seconds=1)).isoformat()
  with self.assertRaises(c.TaskBlocked):c.parse_job(j,NOW)
 def test_bad_nonce_rejected(self):
  j=job();j['nonce']='not-a-nonce'
  with self.assertRaises(c.TaskBlocked):c.parse_job(j,NOW)
 def test_ambiguous_claim_fenced(self):
  j=job()
  with tempfile.TemporaryDirectory() as p:
   (pathlib.Path(p)/'model-job-claims'/j['id']).mkdir(parents=True)
   with self.assertRaisesRegex(c.TaskBlocked,'UNCERTAIN'):c.run_typed_job(j,Agent(),p,now=NOW)
 def test_prior_other_nonce_rejected(self):
  j=job();a=Agent()
  with tempfile.TemporaryDirectory() as p:
   c.run_typed_job(j,a,p,now=NOW)
   j['nonce']='a'*32
   with self.assertRaisesRegex(c.TaskBlocked,'another request'):c.run_typed_job(j,a,p,now=NOW)
 def test_id_rejected(self):
  j=job();j['id']='../../outside'
  with self.assertRaises(c.TaskBlocked):c.parse_job(j,NOW)
 def test_bad_model_outcome_no_retry(self):
  class Bad:
   def run_once(self,*_):return {'status':'FAILED'}
  j=job()
  with tempfile.TemporaryDirectory() as p:
   with self.assertRaisesRegex(c.TaskBlocked,'tests failed'):c.run_typed_job(j,Bad(),p,now=NOW)
   with self.assertRaisesRegex(c.TaskBlocked,'UNCERTAIN'):c.run_typed_job(j,Agent(),p,now=NOW)

if __name__=='__main__':unittest.main()
