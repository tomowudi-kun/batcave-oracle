from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
SQL=(ROOT/'cloud/oracle_bridge_rpc_v03.sql').read_text()
EDGE=(ROOT/'cloud/index.ts').read_text()
WORKER=(ROOT/'patch/batcave_linux_worker.py').read_text()
BRIDGE=(ROOT/'patch/oracle_cloud_bridge.py').read_text()

class CloudContract(unittest.TestCase):
 def test_preserves_existing_rpc_security_and_ops(self):
  self.assertIn('CREATE OR REPLACE FUNCTION public.batcave_oracle_bridge_v1',SQL)
  self.assertIn('SECURITY DEFINER\nSET search_path TO',SQL)
  self.assertIn("p_op IN ('poll','poll_build','poll_model')",SQL)
  self.assertIn("action='oracle_runtime_inventory_v1'",SQL)
  self.assertIn("action='oracle_disposable_build_v1'",SQL)
  statement='\n'.join(x for x in SQL.splitlines() if not x.lstrip().startswith('--'))
  self.assertNotRegex(statement,r'\bGRANT\b')
  self.assertNotRegex(statement,r'\bEXECUTE\b')
 def test_model_receipt_strict_metadata(self):
  for needle in ("payload->>'fixture'='fixed_clamp_score_v1'",
                 "'tests_run') IS DISTINCT FROM '8'",
                 "'artifact') IS DISTINCT FROM 'src/model_generated.py'",
                 "'model') IS DISTINCT FROM 'qwen2.5-coder:1.5b'",
                 "'model_generate_and_verify_v1'", "THEN 8 ELSE 3 END"):
   self.assertIn(needle,SQL)
 def test_fixed_model_only_no_user_prompt(self):
  self.assertIn("'model_generate_and_verify_v1'",BRIDGE)
  self.assertIn('MODEL_OP = "model_generate_and_verify_v1"',WORKER)
  self.assertNotIn('job.get("prompt")',WORKER)
  self.assertNotIn("job.get('prompt')",BRIDGE)
 def test_artifact_bounds_regex(self):
  rx=r'^([2-9][0-9]|[1-9][0-9]{2}|1[0-9]{3}|20[0-3][0-9]|204[0-9])$'
  self.assertIn(rx[1:-1],SQL)
  for n in [1,19,20,99,100,999,1000,1999,2000,2039,2040,2049,2050,9999]:
   self.assertEqual(bool(re.fullmatch(rx,str(n))),20<=n<=2049)
 def test_edge_only_allowlisted_commands(self):
  for cmd in ['poll','poll_build','poll_model','capabilities']:
   self.assertIn("m.op==='"+cmd+"'",EDGE)
  self.assertNotIn('arbitrary_shell',EDGE)

if __name__=='__main__': unittest.main()
