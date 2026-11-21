import datetime as dt
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'patch'))
import batcave_linux_worker as w
import oracle_cloud_bridge as b
import model_capability as m

KEY=b'e'*40
NOW=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

def local_job(operation, identifier=None):
    j={'schema':w.SCHEMA,'job_id':identifier or str(uuid.uuid4()),'target':'BatcaveUbuntu',
       'operation':operation,'issued_at':(NOW-dt.timedelta(seconds=2)).isoformat().replace('+00:00','Z'),
       'expires_at':(NOW+dt.timedelta(minutes=9)).isoformat().replace('+00:00','Z'),
       'nonce':'a'*32}
    j['signature']=hmac.new(KEY,w.canonical(j),hashlib.sha256).hexdigest()
    return j

def cloud_job(local):
    return {'id':local['job_id'],'nonce':local['nonce'], 'operation':local['operation'],
            'expires_at':local['expires_at']}

class Agent:
    calls=0
    def run_once(self,model,endpoint,output_root):
        self.calls+=1
        d=Path(output_root)/'runs'/str(uuid.uuid4())
        d.mkdir(parents=True)
        f=d/'model_generated.py'
        source=b'def clamp_score(score):\n if score < 0: return 0\n if score > 10: return 10\n return score\n'
        f.write_bytes(source)
        return {'status':'LAB_PASS','run_id':d.name,'artifact':str(f),
                'artifact_sha256':hashlib.sha256(source).hexdigest(),
                'tests_run':8,'tests_passed':True}

class Integration(unittest.TestCase):
    def test_existing_inventory_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp); (d/'receipts').mkdir()
            r=w.execute(local_job('runtime_inventory'),KEY,'BatcaveUbuntu',d/'receipts',now=NOW)
            self.assertEqual(r['operation'],'runtime_inventory')
            self.assertIn('python',r['result'])
            self.assertTrue((d/'receipts'/(r['job_id']+'.receipt.json')).exists())

    def test_existing_disposable_build_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp); (d/'receipts').mkdir()
            r=w.execute(local_job(w.BUILD_OP),KEY,'BatcaveUbuntu',d/'receipts',now=NOW)
            self.assertEqual(r['result']['tests_run'],6)
            self.assertTrue(r['result']['tests_passed'])

    def test_new_worker_model_receipt_signed_and_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); receipt_dir=root/'receipts';receipt_dir.mkdir()
            model_root=root/'model_lab'; model_root.mkdir()
            job=local_job(w.MODEL_OP)
            agent=Agent()
            def fixed(_job,_receipt,now=None):
                return m.run_typed_job(cloud_job(_job),agent,model_root,now=NOW)
            with patch.object(w,'model_disposable_project',side_effect=fixed):
                receipt=w.execute(job,KEY,'BatcaveUbuntu',receipt_dir,now=NOW)
            self.assertEqual(agent.calls,1)
            self.assertEqual(receipt['result']['tests_run'],8)
            self.assertEqual(receipt['result']['model'],'qwen2.5-coder:1.5b')
            self.assertEqual(receipt['result']['artifact'],'src/model_generated.py')
            self.assertEqual(receipt['request_sha256'],w.digest({k:v for k,v in job.items() if k!='signature'}))
            signed={k:v for k,v in receipt.items() if k!='receipt_hmac_sha256'}
            self.assertEqual(receipt['receipt_hmac_sha256'],hmac.new(KEY,w.canonical(signed),hashlib.sha256).hexdigest())
            # Simulate the existing bridge independently checking the signed cloud result.
            with patch.object(b,'RECEIPTS',receipt_dir),patch.object(b.Path,'home',return_value=root):
                fixed_file=root/'.local/share/batcave-oracle-model-lab'/'lab-projects'/job['job_id']/'src/model_generated.py'
                fixed_file.parent.mkdir(parents=True)
                fixed_file.write_bytes((model_root/'lab-projects'/job['job_id']/'src/model_generated.py').read_bytes())
                self.assertEqual(b.verified_receipt(cloud_job(job),KEY)['job_id'],job['job_id'])
                fixed_file.write_text('tampered')
                with self.assertRaisesRegex(ValueError,'missing|mismatch'):
                    b.verified_receipt(cloud_job(job),KEY)

    def test_new_cloud_operation_allowed_existing_unknown_rejected(self):
        model=cloud_job(local_job(w.MODEL_OP))
        self.assertIsInstance(b.validate_cloud_job(model),dt.datetime)
        model['operation']='arbitrary_shell'
        with self.assertRaisesRegex(ValueError,'unauthorized_operation'):b.validate_cloud_job(model)

    def test_local_hmac_tamper_denied(self):
        job=local_job(w.MODEL_OP)
        job['operation']='runtime_inventory'
        with self.assertRaisesRegex(w.Rejected,'signature mismatch'):
            w.authenticate(job,KEY,'BatcaveUbuntu',now=NOW)

    def test_model_capability_fences_duplicate_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            job=cloud_job(local_job(w.MODEL_OP));agent=Agent()
            a=m.run_typed_job(job,agent,tmp,now=NOW)
            bresult=m.run_typed_job(job,agent,tmp,now=NOW)
            self.assertEqual(agent.calls,1)
            self.assertEqual(a,bresult)

    def test_bad_expiry_denied(self):
        job=local_job(w.MODEL_OP);job['expires_at']=(NOW-dt.timedelta(seconds=1)).isoformat().replace('+00:00','Z')
        job['signature']=hmac.new(KEY,w.canonical({k:v for k,v in job.items() if k!='signature'}),hashlib.sha256).hexdigest()
        with self.assertRaisesRegex(w.Rejected,'job not currently valid'):
            w.authenticate(job,KEY,'BatcaveUbuntu',now=NOW)

if __name__=='__main__':unittest.main()
