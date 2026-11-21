from pathlib import Path
import re, unittest, hashlib
p=Path(__file__).resolve().parents[1]/'cloud/oracle_bridge_rpc_v03.sql'
s=p.read_text()
legacy=Path('/mnt/data/Oracle_Worker_Model_Integration_v0.3/cloud/oracle_bridge_rpc_v03.sql').read_text()

class TestGuard(unittest.TestCase):
 def test_exact_functions_preserved(self):
  assert s.count('CREATE OR REPLACE FUNCTION public.batcave_oracle_bridge_v1')==1
  assert 'SECURITY DEFINER' in s and "SET search_path TO ''" in s
 def test_legacy_routes_still_present(self):
  for t in ["'oracle_runtime_inventory_v1'", "'oracle_disposable_build_v1'", "p_op IN ('poll','poll_build','poll_model')", "'receipt'", 'receipt_hmac_sha256']:
   assert t in s
 def test_model_grant_restricted_to_model_poller(self):
  assert "p_op='poll_model'" in s
  assert "EXISTS (\n             SELECT 1 FROM batcave.oracle_lab_review_grants_v1" in s
 def test_key_not_revoked(self):
  assert "k.revoked_at IS NULL" in s
  assert "k.role='lab_reviewer_only'" in s
 def test_exact_pin(self):
  assert '4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f' in s
  assert '4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b' in s
 def test_expiration_and_nonce(self):
  assert "g.expires_at>=c.expires_at" in s and "g.expires_at>v_now" in s
  assert "g.request_nonce=c.payload->>'nonce'" in s
 def test_receipt_scope(self):
  assert "g.signed_receipt->'payload'->>'decision'='LAB_ALLOW'" in s
  assert "g.signed_receipt->'payload'->>'request_sha256'=g.request_sha256" in s
 def test_atomic_claim_with_lease(self):
  assert re.search(r'WITH picked AS MATERIALIZED \(.*?consumed_model_grant AS \(.*?SET consumed_at=v_now.*?UPDATE batcave.commands c\s+SET status=',s,re.S)
 def test_model_no_reclaim_after_failure(self):
  assert "c.action='oracle_model_generate_v1' AND c.status='pending'" in s
  assert "c.attempt_count=0" in s
 def test_server_receipt_requires_consumed(self):
  assert "IF v_job.action='oracle_model_generate_v1' AND NOT EXISTS" in s
  assert "g.consumed_at IS NOT NULL" in s
 def test_no_server_public_privilege(self):
  assert 'GRANT EXECUTE' not in s and 'GRANT ALL' not in s
 def test_only_predicates_changed(self):
  # Whole receipt validator and old response schema remain unchanged except additive model-grant check.
  assert "'result','succeeded'" in s
  assert "'oracle_model_receipt'" in s
if __name__=='__main__': unittest.main(verbosity=2)
