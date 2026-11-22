"""Real PostgreSQL first-root locking tests; synthetic localhost ONLY.
Crypto verified with real synthetic keys in Node before this persistence boundary.
"""
import concurrent.futures
import datetime as dt
import hashlib
import json
from pathlib import Path
import unittest
import uuid
from test_release_ledger import query, literal, js_iso, LedgerTests, OWNER, INTENT, INTENT_SHA

def stable(x): return json.dumps(x,sort_keys=True,separators=(',',':'))
def digest(x): return hashlib.sha256(x.encode()).hexdigest()

class FirstLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        query('DROP SCHEMA IF EXISTS batcave CASCADE;')
        LedgerTests.setUpClass()
        query(Path(__file__).with_name('first_reviewer_schema_STAGED.sql').read_text())
        query(Path(__file__).with_name('first_reviewer_sync_STAGED.sql').read_text())

    def setUp(self):
        query(f"""TRUNCATE batcave.oracle_first_challenges_v1,batcave.oracle_first_reviewer_v1,batcave.oracle_release_evidence_v1,batcave.oracle_release_challenges_v1,batcave.oracle_release_keys_v1,batcave.oracle_release_custody_v1,batcave.linux_owner_keys_v1,batcave.change_gate_intents CASCADE;
        INSERT INTO batcave.linux_owner_keys_v1 VALUES('{OWNER}','{'a'*64}',NULL);
        INSERT INTO batcave.change_gate_intents VALUES('{INTENT}','held','{INTENT_SHA}',now()+interval '1 hour');""")
        self.policy=dict(schema='batcave.oracle.owner_first_reviewer.policy.v1',scope='first_reviewer_enrollment_only',trust_basis='owner_signed_first_reviewer_bootstrap',owner_user_id=OWNER,owner_key_sha256='a'*64,reviewer_key_sha256='b'*64,reviewer_public_key_b64url='C'*43,candidate_sha256='d'*64,host_identity_sha256='e'*64,custody_evidence_sha256='f'*64,reviewer_sid='S-1-5-21-101-202-303-1001',release_intent_key=INTENT,release_intent_sha256=INTENT_SHA,signer_valid_until=js_iso(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)))
        text=stable(self.policy);self.policy_hash=digest(text)
        query(f'INSERT INTO batcave.oracle_first_reviewer_v1(policy,canonical_policy,policy_sha256) VALUES({literal(text)}::jsonb,{literal(text)},{literal(self.policy_hash)});')

    def challenge(self,kind='first_key',expired=False,changed_policy=False):
        ident=str(uuid.uuid4());now=dt.datetime.now(dt.timezone.utc)
        issued=now-dt.timedelta(minutes=2) if expired else now-dt.timedelta(seconds=1)
        expires=now-dt.timedelta(seconds=1) if expired else now+dt.timedelta(minutes=4)
        nonce=uuid.uuid4().hex
        if kind=='first_key':
            payload={k:self.policy[k] for k in ['owner_user_id','owner_key_sha256','reviewer_key_sha256','candidate_sha256','host_identity_sha256','reviewer_sid','custody_evidence_sha256','scope','trust_basis','signer_valid_until']}
            payload.update(schema='batcave.oracle.first_reviewer.enrollment.v1',policy_sha256=self.policy_hash)
            if changed_policy: payload['reviewer_sid']='S-1-5-21-999-888-777-1001'
            candidate=dict(public_key_sha256='b'*64,public_key_b64url='C'*43)
        else:
            payload=dict(schema='batcave.oracle.pinned.release.v1',intent_key=INTENT,intent_sha256=INTENT_SHA,owner_user_id=OWNER,owner_gate_zip_sha256='69ab19be8ec2e11e902716da59c2dda8693a3d3c78a16d8bdc1ded25a8d16851',worker_zip_sha256='4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2',pr_head_sha='33b62fae6ccb2224f04cce43443510b71c051297',target_device='Oracle',operation='model_generate_and_verify_v1',fixture='fixed_clamp_score_v1',scope='disposable_lab_only');candidate=None
        payload.update(nonce=nonce,issued_at=js_iso(issued),expires_at=js_iso(expires))
        text=stable(payload);h=digest(text)
        c='NULL' if candidate is None else literal(stable(candidate))+'::jsonb'
        query(f"INSERT INTO batcave.oracle_first_challenges_v1(id,kind,owner_user_id,owner_key_sha256,reviewer_key_sha256,policy_sha256,nonce,issued_at,expires_at,payload,canonical_payload,payload_sha256,candidate) VALUES('{ident}',{literal(kind)},'{OWNER}','{'a'*64}','{'b'*64}',{literal(self.policy_hash)},{literal(nonce)},{literal(payload['issued_at'])},{literal(payload['expires_at'])},{literal(text)}::jsonb,{literal(text)},{literal(h)},{c});")
        return ident,h

    def finish(self,c,missing=False):
        sig='NULL' if missing else literal('B'*86)
        return json.loads(query(f"SELECT batcave.oracle_first_finish_v1('{OWNER}','{c[0]}','{c[1]}',{'NULL' if missing else literal('A'*86)},{sig});"))

    def test_bootstrap_then_release_keeps_truth_and_all_holds(self):
        self.assertTrue(self.finish(self.challenge())['inserted'])
        self.assertTrue(self.finish(self.challenge('release'))['inserted'])
        self.assertEqual(query('SELECT independently_attested OR production_release_authorized FROM batcave.oracle_first_reviewer_v1;'),'f')
        self.assertEqual(query('SELECT count(*) FROM batcave.oracle_first_challenges_v1 WHERE deployment_authorized OR execution_authorized OR grant_issued;'),'0')
        self.assertEqual(query('SELECT count(*) FROM batcave.oracle_release_custody_v1;'),'0')
        self.assertEqual(query(f"SELECT state FROM batcave.change_gate_intents WHERE intent_key='{INTENT}';"),'held')

    def test_two_distinct_concurrent_first_key_challenges_have_exactly_one_winner(self):
        challenges=[self.challenge(),self.challenge()]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(self.finish,challenges))
        self.assertEqual(sum(r['inserted'] for r in results),1)
        self.assertEqual(query('SELECT count(*) FROM batcave.oracle_first_challenges_v1 WHERE consumed_at IS NOT NULL;'),'1')

    def test_release_nonce_replay_has_one_winner(self):
        self.assertTrue(self.finish(self.challenge())['inserted']);c=self.challenge('release')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:self.finish(c),range(2)))
        self.assertEqual(sum(r['inserted'] for r in results),1)

    def test_revoked_root_cannot_be_registered_again_or_reused(self):
        self.assertTrue(self.finish(self.challenge())['inserted']);c=self.challenge()
        query('UPDATE batcave.oracle_first_reviewer_v1 SET revoked_at=clock_timestamp();')
        self.assertFalse(self.finish(c)['inserted'])
        self.assertFalse(self.finish(self.challenge('release'))['inserted'])
        self.assertIn('immutable',query('UPDATE batcave.oracle_first_reviewer_v1 SET registered_at=NULL,registration_challenge_id=NULL;',ok=False))
        self.assertIn('immutable',query('UPDATE batcave.oracle_first_reviewer_v1 SET revoked_at=NULL;',ok=False))

    def test_existing_independently_enrolled_reviewer_blocks_first_bootstrap(self):
        att=str(uuid.uuid4())
        query(f"""INSERT INTO batcave.oracle_release_custody_v1(id,owner_user_id,public_key_sha256,host_identity_sha256,evidence_sha256,independently_attested,release_policy_version,private_key_custodian,valid_until) VALUES('{att}','{OWNER}','{'c'*64}','{'d'*64}','{'e'*64}',true,'strict_nanny.release.v1','Cortana separate protected reviewer',now()+interval '1 hour');
        INSERT INTO batcave.oracle_release_keys_v1(owner_user_id,public_key_sha256,public_key_b64url,host_identity_sha256,attestation_id,role,registered,independently_attested,release_policy_version,private_key_custodian,valid_until) VALUES('{OWNER}','{'c'*64}','{'D'*43}','{'d'*64}','{att}','independent_release_reviewer',true,true,'strict_nanny.release.v1','Cortana separate protected reviewer',now()+interval '1 hour');""")
        self.assertFalse(self.finish(self.challenge())['inserted'])

    def test_expiry_owner_rotation_and_held_intent_rechecked(self):
        c=self.challenge(expired=True);self.assertFalse(self.finish(c)['inserted'])
        c=self.challenge();query(f"UPDATE batcave.linux_owner_keys_v1 SET public_key_sha256='{'f'*64}';")
        self.assertFalse(self.finish(c)['inserted'])
        query(f"UPDATE batcave.linux_owner_keys_v1 SET public_key_sha256='{'a'*64}'; UPDATE batcave.change_gate_intents SET state='released';")
        self.assertFalse(self.finish(c)['inserted'])

    def test_policy_binding_digest_and_missing_pair_denied(self):
        self.assertFalse(self.finish(self.challenge(changed_policy=True))['inserted'])
        self.assertFalse(self.finish(self.challenge(),missing=True)['inserted'])
        self.assertIn('immutable',query("UPDATE batcave.oracle_first_reviewer_v1 SET policy_sha256=repeat('f',64);",ok=False))

    def test_clients_cannot_read_seed_register_or_remove_root(self):
        for role in ['anon','authenticated']:
            for sql in ['SELECT * FROM batcave.oracle_first_reviewer_v1','SELECT * FROM batcave.oracle_first_challenges_v1',"SELECT batcave.oracle_first_finish_v1(NULL,NULL,NULL,NULL,NULL)"]:
                self.assertIn('permission denied',query(f'SET ROLE {role}; {sql};',ok=False))
        self.assertIn('permanent',query('DELETE FROM batcave.oracle_first_reviewer_v1;',ok=False))

    def test_receipts_and_payloads_are_append_only(self):
        c=self.challenge();self.assertTrue(self.finish(c)['inserted'])
        self.assertIn('immutable',query(f"UPDATE batcave.oracle_first_challenges_v1 SET owner_signature_b64url=repeat('C',86) WHERE id='{c[0]}';",ok=False))
        self.assertIn('append-only',query(f"DELETE FROM batcave.oracle_first_challenges_v1 WHERE id='{c[0]}';",ok=False))


    def save_endorsement(self,c,sig='A'*86):
        return json.loads(query(f"SELECT batcave.oracle_first_save_endorsement_v1('{OWNER}','{c[0]}','{c[1]}',{literal(sig)});"))

    def decline(self):
        return json.loads(query(f"SELECT batcave.oracle_first_decline_v1('{OWNER}','{self.policy_hash}');"))

    def test_saved_endorsement_does_not_consume_or_register(self):
        c=self.challenge();self.assertTrue(self.save_endorsement(c)['saved'])
        self.assertEqual(query('SELECT count(*) FROM batcave.oracle_first_challenges_v1 WHERE consumed_at IS NOT NULL;'),'0')
        self.assertEqual(query('SELECT registered_at IS NULL FROM batcave.oracle_first_reviewer_v1;'),'t')
        self.assertFalse(self.save_endorsement(c,'C'*86)['saved'])
        self.assertIn('immutable',query("UPDATE batcave.oracle_first_challenges_v1 SET pending_owner_signature_b64url=NULL;",ok=False))
        self.assertTrue(self.finish(c)['inserted'])

    def test_no_withdraws_all_prior_nonces_and_stops_saved_pairs(self):
        a,b=self.challenge(),self.challenge();self.assertTrue(self.save_endorsement(a)['saved'])
        self.assertTrue(self.decline()['declined'])
        for c in [a,b]:
            self.assertFalse(self.finish(c)['inserted'])
            self.assertFalse(self.save_endorsement(c)['saved'])
        self.assertEqual(query('SELECT count(*) FROM batcave.oracle_first_challenges_v1 WHERE withdrawn_at IS NOT NULL;'),'2')
        self.assertIn('immutable',query('UPDATE batcave.oracle_first_challenges_v1 SET withdrawn_at=NULL;',ok=False))
        self.assertEqual(query(f"SELECT state FROM batcave.change_gate_intents WHERE intent_key='{INTENT}';"),'held')

    def test_new_yes_after_no_only_restores_new_nonce(self):
        old=self.challenge();self.assertTrue(self.decline()['declined'])
        # challenge() intentionally backdates issued_at by one second; make this
        # genuinely new issuance after No rather than adjusting the old row.
        fresh=self.challenge_after_no()
        self.assertTrue(self.save_endorsement(fresh)['saved'])
        self.assertFalse(self.finish(old)['inserted'])
        self.assertTrue(self.finish(fresh)['inserted'])
        self.assertFalse(self.decline()['declined'])

    def challenge_after_no(self):
        c=self.challenge()
        # Preserve immutability: recreate a synthetic fresh row, never edit it.
        # Use a transaction time from after the recorded denial in INSERT.
        raw=query(f"SELECT row_to_json(c) FROM batcave.oracle_first_challenges_v1 c WHERE id='{c[0]}';")
        r=json.loads(raw);payload=r['payload'];issued=dt.datetime.now(dt.timezone.utc)
        payload['issued_at']=js_iso(issued);payload['expires_at']=js_iso(issued+dt.timedelta(minutes=4));payload['nonce']=uuid.uuid4().hex
        text=stable(payload);h=digest(text);ident=str(uuid.uuid4())
        query(f"INSERT INTO batcave.oracle_first_challenges_v1(id,kind,owner_user_id,owner_key_sha256,reviewer_key_sha256,policy_sha256,nonce,issued_at,expires_at,payload,canonical_payload,payload_sha256,candidate) VALUES('{ident}','first_key','{OWNER}','{'a'*64}','{'b'*64}','{self.policy_hash}','{payload['nonce']}',{literal(payload['issued_at'])},{literal(payload['expires_at'])},{literal(text)}::jsonb,{literal(text)},'{h}',{literal(stable(r['candidate']))}::jsonb);")
        return ident,h

    def test_signature_saving_rechecks_expiry_rotation_and_revocation(self):
        self.assertFalse(self.save_endorsement(self.challenge(expired=True))['saved'])
        c=self.challenge();query(f"UPDATE batcave.linux_owner_keys_v1 SET public_key_sha256='{'f'*64}';")
        self.assertFalse(self.save_endorsement(c)['saved'])
        query(f"UPDATE batcave.linux_owner_keys_v1 SET public_key_sha256='{'a'*64}'; UPDATE batcave.oracle_first_reviewer_v1 SET revoked_at=clock_timestamp();")
        self.assertFalse(self.save_endorsement(c)['saved'])
        self.assertFalse(self.decline()['declined'])

    def test_no_cutoff_catches_concurrent_insert_that_was_not_in_locked_snapshot(self):
        self.assertTrue(self.decline()['declined'])
        old=self.challenge()  # Issued one second before No, inserted after it.
        self.assertEqual(query(f"SELECT withdrawn_at IS NULL FROM batcave.oracle_first_challenges_v1 WHERE id='{old[0]}';"),'t')
        self.assertFalse(self.save_endorsement(old)['saved'])
        fresh=self.challenge_after_no();self.assertTrue(self.save_endorsement(fresh)['saved'])
        self.assertFalse(self.finish(old)['inserted'])
        self.assertTrue(self.finish(fresh)['inserted'])

    def test_private_sync_functions_not_callable_by_clients(self):
        for role in ['anon','authenticated']:
            for sql in ['SELECT batcave.oracle_first_save_endorsement_v1(NULL,NULL,NULL,NULL)','SELECT batcave.oracle_first_decline_v1(NULL,NULL)']:
                self.assertIn('permission denied',query(f'SET ROLE {role}; {sql};',ok=False))

    def test_concurrent_no_and_finish_have_one_ordered_result(self):
        c=self.challenge();self.assertTrue(self.save_endorsement(c)['saved'])
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            no=pool.submit(self.decline);finish=pool.submit(self.finish,c)
            n,r=no.result(),finish.result()
        self.assertNotEqual(n['declined'],r['inserted'])
        self.assertEqual(query('SELECT (registered_at IS NOT NULL)::int + (owner_declined_at IS NOT NULL)::int FROM batcave.oracle_first_reviewer_v1;'),'1')

if __name__=='__main__':
    # Do not rerun imported legacy class here; CI runs its suite separately.
    unittest.main(defaultTest='FirstLedgerTests',verbosity=2)
