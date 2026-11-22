"""Actual PostgreSQL recovery regression; synthetic localhost database ONLY.

No production DSN, credentials, device token, host command or grant is accepted.
These tests exercise the persisted SQL boundary, not a physical-host recovery.
"""
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import unittest
from urllib.parse import urlparse
import uuid

DSN = os.environ.get('BATCAVE_TEST_DATABASE_URL', '')
u = urlparse(DSN)
if u.scheme not in ('postgresql', 'postgres') or u.hostname not in ('localhost', '127.0.0.1') or u.path != '/release_gate_test':
    raise SystemExit('Requires synthetic localhost/release_gate_test; production is forbidden.')
HERE = Path(__file__).resolve().parents[1]
BEFORE = (HERE/'sql/before_generic_commands.sql').read_text()
AFTER = (HERE/'sql/reconcile_generic_commands_STAGED.sql').read_text()
DEVICE = '123e4567-e89b-42d3-a456-426614174099'
OTHER = '123e4567-e89b-42d3-a456-426614174098'

def query(sql, ok=True):
    p = subprocess.run(['psql', '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', DSN],
                       input=sql, text=True, capture_output=True, timeout=20)
    if ok and p.returncode:
        raise AssertionError(p.stderr)
    if not ok:
        assert p.returncode, 'Expected database rejection'
        return p.stderr
    return p.stdout.strip()

class CommandRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        query("""
        DROP SCHEMA IF EXISTS batcave CASCADE; CREATE SCHEMA batcave;
        CREATE TABLE batcave.devices(id uuid PRIMARY KEY,state text NOT NULL);
        CREATE TABLE batcave.commands(id uuid PRIMARY KEY,device_id uuid REFERENCES batcave.devices(id),
          action text,payload jsonb,status text,created_at timestamptz DEFAULT now(),expires_at timestamptz,
          lease_until timestamptz,attempt_count integer DEFAULT 0,completed_at timestamptz,result jsonb);
        CREATE TABLE batcave.device_receipts(command_id uuid PRIMARY KEY REFERENCES batcave.commands(id),
          device_id uuid REFERENCES batcave.devices(id),outcome text,recorded_at timestamptz DEFAULT now(),
          finished_at timestamptz,result jsonb);
        CREATE TABLE batcave.command_events(command_id uuid,event_type text,details jsonb);
        """)
        query(BEFORE)
        query("REVOKE ALL ON FUNCTION batcave.start_command(uuid,uuid),batcave.complete_command(uuid,uuid,jsonb,boolean),batcave.claim_next_command(uuid,integer) FROM PUBLIC;")

    def setUp(self):
        query('TRUNCATE batcave.command_events,batcave.device_receipts,batcave.commands,batcave.devices CASCADE;')
        query(BEFORE)
        query(AFTER)
        query(f"INSERT INTO batcave.devices VALUES('{DEVICE}','active'),('{OTHER}','active');")
        self.job = self.new_job()

    def new_job(self, lease='5 minutes', expires='10 minutes', status='leased'):
        ident = str(uuid.uuid4())
        query(f"INSERT INTO batcave.commands(id,device_id,action,payload,status,expires_at,lease_until,attempt_count) VALUES('{ident}','{DEVICE}','synthetic_fixture','{{}}','{status}',now()+interval '{expires}',now()+interval '{lease}',1);")
        return ident

    def start(self, job=None, device=DEVICE):
        return query(f"SELECT batcave.start_command('{job or self.job}','{device}');")

    def finish(self, job=None, device=DEVICE, value='{"artifact_sha256":"synthetic-fixture","tests_passed":true}', success='true'):
        encoded = 'NULL' if value is None else "'"+value.replace("'", "''")+"'::jsonb"
        return query(f"SELECT batcave.complete_command('{job or self.job}','{device}',{encoded},{success});")

    def state(self):
        return json.loads(query(f"SELECT jsonb_build_object('status',c.status,'attempt',c.attempt_count,'result',c.result,'receipt',r.outcome,'receipt_result',r.result,'events',(SELECT count(*) FROM batcave.command_events WHERE command_id=c.id)) FROM batcave.commands c LEFT JOIN batcave.device_receipts r ON r.command_id=c.id WHERE c.id='{self.job}';"))

    def test_actual_original_late_completion_bug_and_fixed_reconciliation(self):
        self.job = self.new_job(lease='2 seconds', expires='1 second')
        self.assertEqual(self.start(), 't')
        query('SELECT pg_sleep(2.1);')
        # Old completion refuses a real, already-started job after its lease.
        old_complete = BEFORE[BEFORE.index('CREATE OR REPLACE FUNCTION batcave.complete_command'):]
        # Snapshot order is not relied on: use only this function's definition.
        old_complete = old_complete.split('$function$;', 1)[0]+'$function$;'
        query(old_complete)
        self.assertEqual(self.finish(), 'f')
        self.assertEqual(query(f"SELECT count(*) FROM batcave.claim_next_command('{DEVICE}',60);"), '0')
        query(BEFORE)
        query(AFTER)
        self.assertEqual(self.finish(), 't')
        s = self.state()
        self.assertEqual((s['status'], s['receipt'], s['attempt'], s['events']), ('succeeded','succeeded',1,1))
        self.assertEqual(s['result'], s['receipt_result'])

    def test_started_identity_is_recorded_once(self):
        self.assertEqual(self.start(), 't')
        self.assertEqual(self.start(), 'f')
        s = self.state()
        self.assertEqual(s['receipt_result']['schema'], 'batcave.command.start.v1')
        self.assertEqual(s['receipt_result']['attempt'], 1)
        self.assertEqual(self.finish(), 't')

    def test_expired_or_missing_lease_cannot_start(self):
        query(f"UPDATE batcave.commands SET lease_until=now()-interval '1 second' WHERE id='{self.job}';")
        self.assertEqual(self.start(), 'f')
        query(f"UPDATE batcave.commands SET lease_until=NULL WHERE id='{self.job}';")
        self.assertEqual(self.start(), 'f')

    def test_no_start_means_no_completion(self):
        self.assertEqual(self.finish(), 'f')
        self.assertEqual(self.state()['events'], 0)

    def test_job_expiry_prevents_start_even_inside_lease(self):
        query(f"UPDATE batcave.commands SET expires_at=now()-interval '1 second' WHERE id='{self.job}';")
        self.assertEqual(self.start(), 'f')

    def test_wrong_device_cannot_start_or_finish(self):
        self.assertEqual(self.start(device=OTHER), 'f')
        self.assertEqual(self.start(), 't')
        self.assertEqual(self.finish(device=OTHER), 'f')
        self.assertEqual(self.state()['receipt'], 'started')

    def test_legacy_live_lease_keeps_compatibility(self):
        query(f"INSERT INTO batcave.device_receipts(command_id,device_id,outcome) VALUES('{self.job}','{DEVICE}','started');")
        self.assertEqual(self.finish(), 't')
        self.assertEqual(self.state()['receipt'], 'succeeded')

    def test_legacy_expired_start_remains_explicitly_unresolved(self):
        query(f"INSERT INTO batcave.device_receipts(command_id,device_id,outcome) VALUES('{self.job}','{DEVICE}','started'); UPDATE batcave.commands SET lease_until=now()-interval '1 second' WHERE id='{self.job}';")
        self.assertEqual(self.finish(), 'f')
        self.assertEqual(self.state()['status'], 'leased')
        self.assertEqual(query(f"SELECT count(*) FROM batcave.claim_next_command('{DEVICE}',60);"), '0')

    def test_changed_attempt_or_lease_cannot_reuse_start(self):
        self.assertEqual(self.start(), 't')
        query(f"UPDATE batcave.commands SET attempt_count=2 WHERE id='{self.job}';")
        self.assertEqual(self.finish(), 'f')
        query(f"UPDATE batcave.commands SET attempt_count=1,lease_until=lease_until+interval '1 second' WHERE id='{self.job}';")
        self.assertEqual(self.finish(), 'f')

    def test_identical_result_is_idempotent_and_conflict_rejected(self):
        self.assertEqual(self.start(), 't')
        self.assertEqual(self.finish(), 't')
        self.assertEqual(self.finish(), 't')
        self.assertEqual(self.finish(value='{"different":true}'), 'f')
        self.assertEqual(self.finish(success='false'), 'f')
        self.assertEqual(self.state()['events'], 1)

    def test_concurrent_starts_have_one_winner(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.start(), range(2)))
        self.assertEqual(sorted(results), ['f','t'])

    def test_concurrent_identical_completions_have_one_terminal_event(self):
        self.assertEqual(self.start(), 't')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.finish(), range(2)))
        self.assertEqual(results, ['t','t'])
        self.assertEqual(self.state()['events'], 1)

    def test_concurrent_conflicting_completions_only_one_wins(self):
        # Two competing terminal outcomes must never both be acknowledged.
        self.assertEqual(self.start(), 't')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.finish, value='{"winner":"A"}', success='true')
            second = pool.submit(self.finish, value='{"winner":"B"}', success='false')
            results = [first.result(), second.result()]
        self.assertEqual(sorted(results), ['f', 't'])
        s = self.state()
        self.assertEqual(s['events'], 1)
        self.assertEqual(s['result'], s['receipt_result'])
        self.assertIn(s['result']['winner'], ('A', 'B'))
        self.assertEqual(s['status'], 'succeeded' if s['result']['winner'] == 'A' else 'failed')
        self.assertEqual(self.finish(value='{"winner":"A"}', success='true'),
                         't' if s['result']['winner'] == 'A' else 'f')
        self.assertEqual(self.finish(value='{"winner":"B"}', success='false'),
                         't' if s['result']['winner'] == 'B' else 'f')
        self.assertEqual(self.state()['events'], 1)

    def test_failed_result_is_also_idempotent(self):
        self.assertEqual(self.start(), 't')
        self.assertEqual(self.finish(success='false'), 't')
        self.assertEqual(self.finish(success='false'), 't')
        self.assertEqual((self.state()['status'],self.state()['receipt'],self.state()['events']), ('failed','failed',1))

    def test_inconsistent_terminal_record_is_not_acknowledged(self):
        self.assertEqual(self.start(), 't')
        self.assertEqual(self.finish(), 't')
        query(f"UPDATE batcave.device_receipts SET result=NULL WHERE command_id='{self.job}';")
        self.assertEqual(self.finish(), 'f')

    def test_invalid_result_and_null_verdict_are_rejected(self):
        self.assertEqual(self.start(), 't')
        for value in [None, 'null', '[]', '"text"']:
            self.assertEqual(self.finish(value=value), 'f')
        self.assertEqual(self.finish(success='NULL'), 'f')
        self.assertEqual(self.state()['receipt'], 'started')

    def test_unknown_or_corrupt_receipt_is_not_overwritten(self):
        self.assertEqual(self.start(), 't')
        query(f"UPDATE batcave.device_receipts SET outcome='unknown' WHERE command_id='{self.job}';")
        self.assertEqual(self.finish(), 'f')
        self.assertEqual(self.state()['receipt'], 'unknown')

    def test_event_error_rolls_back_both_terminal_records(self):
        self.assertEqual(self.start(), 't')
        query("CREATE FUNCTION batcave.reject_test_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic event failure'; END $$; CREATE TRIGGER reject_test_event BEFORE INSERT ON batcave.command_events FOR EACH ROW EXECUTE FUNCTION batcave.reject_test_event();")
        try:
            query(f"SELECT batcave.complete_command('{self.job}','{DEVICE}','{{}}'::jsonb,true);", ok=False)
            self.assertEqual((self.state()['status'],self.state()['receipt'],self.state()['events']), ('leased','started',0))
        finally:
            query('DROP TRIGGER reject_test_event ON batcave.command_events; DROP FUNCTION batcave.reject_test_event();')

    def test_invoker_and_private_execute_permissions_remain(self):
        self.assertEqual(query("SELECT bool_and(NOT p.prosecdef AND p.proacl::text='{postgres=X/postgres}') FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='batcave' AND p.proname IN ('claim_next_command','start_command','complete_command');"), 't')

if __name__ == '__main__':
    unittest.main(verbosity=2)
