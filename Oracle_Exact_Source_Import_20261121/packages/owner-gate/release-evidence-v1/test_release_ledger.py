"""Actual PostgreSQL lock/replay tests. Synthetic localhost database ONLY.

Node tests verify real synthetic Ed25519 signatures before this DB boundary.
This suite tests the atomic persistence boundary, not independent key custody.
"""
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
from urllib.parse import urlparse
import uuid

DSN = os.environ.get('BATCAVE_TEST_DATABASE_URL', '')
u = urlparse(DSN)
if u.hostname not in ('localhost', '127.0.0.1') or u.path != '/release_gate_test':
    raise SystemExit('Requires localhost database release_gate_test; never use production.')

OWNER = '123e4567-e89b-42d3-a456-426614174000'
ATTESTATION = '123e4567-e89b-42d3-a456-426614174001'
INTENT = 'batcave.oracle.lab_v031.release_request.20261121'
INTENT_SHA = 'ff41a4a74e25fd31bf9a466d1566100ba9e98cc5d8769fd01fe12c9c653c4e80'

def literal(s):
    return "'" + str(s).replace("'", "''") + "'"

def query(sql, ok=True):
    p = subprocess.run(['psql', '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', DSN], input=sql, text=True, capture_output=True, timeout=20)
    if ok and p.returncode:
        raise AssertionError(p.stderr)
    if not ok:
        assert p.returncode, 'Expected statement rejection'
        return p.stderr
    return p.stdout.strip()

def js_iso(t):
    return t.isoformat(timespec='milliseconds').replace('+00:00', 'Z')

class LedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        query("""
        DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='anon') THEN CREATE ROLE anon; END IF;
        IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN CREATE ROLE authenticated; END IF; END $$;
        CREATE SCHEMA batcave;
        CREATE TABLE batcave.linux_owner_keys_v1(owner_user_id uuid PRIMARY KEY,public_key_sha256 text NOT NULL,revoked_at timestamptz);
        CREATE TABLE batcave.change_gate_intents(intent_key text PRIMARY KEY,state text,content_sha256 text,valid_until timestamptz);
        """)
        query(Path(__file__).with_name('release_evidence_schema_STAGED.sql').read_text())

    def setUp(self):
        query(f"""
        TRUNCATE batcave.oracle_release_evidence_v1,batcave.oracle_release_challenges_v1,batcave.oracle_release_keys_v1,batcave.oracle_release_custody_v1,batcave.linux_owner_keys_v1,batcave.change_gate_intents;
        INSERT INTO batcave.linux_owner_keys_v1 VALUES('{OWNER}','{'a'*64}',NULL);
        INSERT INTO batcave.change_gate_intents VALUES('{INTENT}','held','{INTENT_SHA}',now()+interval '1 hour');
        INSERT INTO batcave.oracle_release_custody_v1(id,owner_user_id,public_key_sha256,host_identity_sha256,evidence_sha256,independently_attested,release_policy_version,private_key_custodian,valid_until)
        VALUES('{ATTESTATION}','{OWNER}','{'b'*64}','{'c'*64}','{'d'*64}',true,'strict_nanny.release.v1','Cortana separate protected reviewer',now()+interval '1 hour');
        """)

    def challenge(self, kind='enrollment', expired=False):
        ident = str(uuid.uuid4())
        now = dt.datetime.now(dt.timezone.utc)
        begin = now-dt.timedelta(seconds=61) if expired else now-dt.timedelta(seconds=1)
        end = now-dt.timedelta(seconds=1) if expired else now+dt.timedelta(minutes=4)
        nonce = uuid.uuid4().hex
        payload = dict(schema='batcave.oracle.release.enrollment.v1',owner_user_id=OWNER,nonce=nonce,issued_at=js_iso(begin),expires_at=js_iso(end),reviewer_key_sha256='b'*64,host_identity_sha256='c'*64,attestation_id=ATTESTATION,candidate_sha256='e'*64)
        candidate = dict(public_key_sha256='b'*64,public_key_b64url='C'*43)
        if kind == 'release':
            payload = dict(schema='batcave.oracle.pinned.release.v1',owner_user_id=OWNER,nonce=nonce,issued_at=js_iso(begin),expires_at=js_iso(end),intent_key=INTENT,intent_sha256=INTENT_SHA,owner_gate_zip_sha256='69ab19be8ec2e11e902716da59c2dda8693a3d3c78a16d8bdc1ded25a8d16851',worker_zip_sha256='4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2',pr_head_sha='33b62fae6ccb2224f04cce43443510b71c051297',target_device='Oracle',operation='model_generate_and_verify_v1',fixture='fixed_clamp_score_v1',scope='disposable_lab_only')
            candidate = None
        canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        h = hashlib.sha256(canonical.encode()).hexdigest()
        candidate_sql = 'NULL' if candidate is None else literal(json.dumps(candidate))+'::jsonb'
        query(f"INSERT INTO batcave.oracle_release_challenges_v1(id,kind,owner_user_id,owner_key_sha256,reviewer_key_sha256,attestation_id,nonce,issued_at,expires_at,payload,canonical_payload,candidate) VALUES('{ident}',{literal(kind)},'{OWNER}','{'a'*64}','{'b'*64}','{ATTESTATION}',{literal(nonce)},{literal(js_iso(begin))},{literal(js_iso(end))},{literal(canonical)}::jsonb,{literal(canonical)},{candidate_sql});")
        return ident, h, kind

    def finish(self, c, bad_hash=False):
        ident, h, kind = c
        if bad_hash:
            h = 'f'*64
        nanny = 'NULL' if kind == 'enrollment' else literal('B'*86)
        return json.loads(query(f"SELECT batcave.oracle_release_finish_v1('{OWNER}','{ident}',{literal(h)},{literal('A'*86)},{nanny});"))

    def enrolled(self):
        self.assertTrue(self.finish(self.challenge())['inserted'])

    def test_enrollment_then_release_records_evidence_only(self):
        self.enrolled()
        self.assertTrue(self.finish(self.challenge('release'))['inserted'])
        self.assertEqual(query('SELECT count(*) FROM batcave.oracle_release_evidence_v1 WHERE deployment_authorized OR execution_authorized OR grant_issued;'), '0')
        self.assertEqual(query(f"SELECT state FROM batcave.change_gate_intents WHERE intent_key='{INTENT}';"), 'held')

    def test_concurrent_release_has_one_winner(self):
        self.enrolled()
        c = self.challenge('release')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.finish(c), range(2)))
        self.assertEqual(sum(r['inserted'] for r in results), 1)
        self.assertEqual(query(f"SELECT count(*) FROM batcave.oracle_release_evidence_v1 WHERE challenge_id='{c[0]}';"), '1')

    def test_duplicate_enrollment_does_not_consume_second_challenge(self):
        self.enrolled()
        c = self.challenge()
        self.assertFalse(self.finish(c)['inserted'])
        self.assertEqual(query(f"SELECT consumed_at IS NULL FROM batcave.oracle_release_challenges_v1 WHERE id='{c[0]}';"), 't')

    def test_changed_payload_hash_cannot_consume_nonce(self):
        c = self.challenge()
        self.assertFalse(self.finish(c, bad_hash=True)['inserted'])
        self.assertTrue(self.finish(c)['inserted'])

    def test_expired_challenge_cannot_enroll(self):
        self.assertFalse(self.finish(self.challenge(expired=True))['inserted'])

    def test_revoked_custody_denies_commit(self):
        c = self.challenge()
        query('UPDATE batcave.oracle_release_custody_v1 SET revoked_at=now();')
        self.assertFalse(self.finish(c)['inserted'])

    def test_rotated_owner_denies_commit(self):
        c = self.challenge()
        query(f"UPDATE batcave.linux_owner_keys_v1 SET public_key_sha256='{'f'*64}';")
        self.assertFalse(self.finish(c)['inserted'])

    def test_revoked_reviewer_denies_release(self):
        self.enrolled()
        c = self.challenge('release')
        query('UPDATE batcave.oracle_release_keys_v1 SET revoked_at=now();')
        self.assertFalse(self.finish(c)['inserted'])

    def test_stale_intent_denies_commit(self):
        c = self.challenge()
        query(f"UPDATE batcave.change_gate_intents SET content_sha256='{'f'*64}';")
        self.assertFalse(self.finish(c)['inserted'])

    def test_evidence_cannot_be_promoted_to_executable_grant(self):
        self.enrolled()
        error = query('UPDATE batcave.oracle_release_evidence_v1 SET execution_authorized=true;', ok=False)
        self.assertIn('check constraint', error)

    def test_public_roles_have_no_ledger_or_registration_access(self):
        self.assertEqual(query("SELECT has_table_privilege('anon','batcave.oracle_release_custody_v1','INSERT') OR has_table_privilege('authenticated','batcave.oracle_release_keys_v1','INSERT') OR has_function_privilege('authenticated','batcave.oracle_release_finish_v1(uuid,uuid,text,text,text)','EXECUTE');"), 'f')

if __name__ == '__main__':
    unittest.main(verbosity=2)
