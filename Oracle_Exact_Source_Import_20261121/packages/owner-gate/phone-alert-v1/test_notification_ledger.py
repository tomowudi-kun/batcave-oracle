"""Actual PostgreSQL queue, auth and webhook isolation. Synthetic localhost only.
Uses the existing release ledger fixtures; Vault and pg_net are local test stubs.
No production connections, signing keys, subscriptions or outbound requests.
"""
import concurrent.futures
import json
from pathlib import Path
import sys
import unittest
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'release-evidence-v1'))
import test_first_ledger as first
import test_release_ledger as ledger
query,literal,OWNER=ledger.query,ledger.literal,ledger.OWNER

class NotificationLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        first.FirstLedgerTests.setUpClass()
        query("""
        DROP SCHEMA IF EXISTS vault CASCADE; DROP SCHEMA IF EXISTS net CASCADE;
        CREATE SCHEMA vault; CREATE SCHEMA net;
        CREATE TABLE vault.secrets(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),decrypted_secret text NOT NULL);
        CREATE VIEW vault.decrypted_secrets AS SELECT * FROM vault.secrets;
        CREATE FUNCTION vault.create_secret(new_secret text,new_name text DEFAULT NULL,new_description text DEFAULT '') RETURNS uuid LANGUAGE sql AS $$ INSERT INTO vault.secrets(decrypted_secret) VALUES(new_secret) RETURNING id $$;
        CREATE TABLE net.request_log(id bigint GENERATED ALWAYS AS IDENTITY,url text,body jsonb,headers jsonb,timeout_milliseconds integer);
        CREATE FUNCTION net.http_post(url text,body jsonb DEFAULT '{}'::jsonb,params jsonb DEFAULT '{}'::jsonb,headers jsonb DEFAULT '{}'::jsonb,timeout_milliseconds integer DEFAULT 1000) RETURNS bigint LANGUAGE sql AS $$ INSERT INTO net.request_log(url,body,headers,timeout_milliseconds) VALUES(url,body,headers,timeout_milliseconds) RETURNING id $$;
        """)
        sql=Path(__file__).with_name('schema_STAGED.sql').read_text().replace('CREATE EXTENSION IF NOT EXISTS pg_net WITH SCHEMA extensions;','-- pg_net is a local stub; no network in this test.')
        query(sql)
        query("""INSERT INTO batcave.owner_phone_config_v1(slot,public_key,secret_id,dispatch_hash) SELECT 1,repeat('P',87),vault.create_secret('{"privateKey":"synthetic-only","dispatchToken":"synthetic-notification-only"}'),repeat('f',64);""")

    def setUp(self):
        self.fixtures=first.FirstLedgerTests();self.fixtures.setUp()
        query('TRUNCATE net.request_log;')
        self.sub=str(uuid.uuid4())
        query(f"INSERT INTO batcave.owner_phone_subscriptions_v1(id,owner_user_id,endpoint_sha256,endpoint,p256dh,auth) VALUES('{self.sub}','{OWNER}',repeat('d',64),'https://fcm.googleapis.com/fcm/send/synthetic-test',repeat('P',87),repeat('A',22));")

    def queue(self,kind='review',owner=OWNER,sub=None):
        return json.loads(query(f"SELECT batcave.queue_owner_phone_alert_v1('{owner}',{literal(kind)},{'NULL' if sub is None else literal(sub)+'::uuid'});"))

    def test_queue_delivers_only_to_fixed_notification_function_with_no_authority(self):
        ids=self.queue();self.assertEqual(len(ids),1)
        row=json.loads(query("SELECT jsonb_build_object('url',url,'op',body->>'op','keys',jsonb_object_length(body),'dispatch_header',headers?'x-batcave-notification-dispatch','timeout',timeout_milliseconds) FROM net.request_log;".replace("jsonb_object_length(body)","(SELECT count(*) FROM jsonb_object_keys(body))")))
        self.assertEqual(row,dict(url='https://wizflveeptzeajsdybzs.supabase.co/functions/v1/batcave-phone-alert-v1',op='dispatch',keys=2,dispatch_header=True,timeout=15000))
        self.assertEqual(query('SELECT count(*) FROM batcave.owner_phone_notifications_v1 WHERE deployment_authorized OR execution_authorized;'),'0')
        self.assertEqual(query('SELECT registered_at IS NULL FROM batcave.oracle_first_reviewer_v1;'),'t')
        self.assertEqual(query('SELECT state FROM batcave.change_gate_intents;'),'held')

    def test_simultaneous_review_queues_create_one_delivery(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(lambda _:self.queue(),range(4)))
        self.assertEqual(sum(map(len,results)),1)
        self.assertEqual(query('SELECT count(*) FROM net.request_log;'),'1')

    def test_no_revocation_rotation_and_released_intent_suppress_review(self):
        self.assertTrue(self.fixtures.decline()['declined']);self.assertEqual(self.queue(),[])
        self.setUp();query("UPDATE batcave.linux_owner_keys_v1 SET revoked_at=now();");self.assertEqual(self.queue(),[])
        self.setUp();query("UPDATE batcave.linux_owner_keys_v1 SET public_key_sha256=repeat('e',64);");self.assertEqual(self.queue(),[])
        self.setUp();query("UPDATE batcave.change_gate_intents SET state='released';");self.assertEqual(self.queue(),[])
        self.setUp();query("UPDATE batcave.change_gate_intents SET valid_until=now()-interval '1 second';");self.assertEqual(self.queue(),[])
        self.assertEqual(query('SELECT count(*) FROM net.request_log;'),'0')

    def test_saved_fresh_owner_yes_is_not_requested_again(self):
        self.assertTrue(self.fixtures.save_endorsement(self.fixtures.challenge())['saved'])
        self.assertEqual(self.queue(),[])
        self.assertEqual(query('SELECT count(*) FROM net.request_log;'),'0')

    def test_subscription_owner_and_endpoint_constraints_reject_cross_owner(self):
        other=str(uuid.uuid4())
        query(f"INSERT INTO batcave.linux_owner_keys_v1 VALUES('{other}',repeat('b',64),NULL);")
        self.assertEqual(self.queue(owner=other),[])
        error=query(f"INSERT INTO batcave.owner_phone_notifications_v1(subscription_id,owner_user_id,kind,request_key) VALUES('{self.sub}','{other}','test',repeat('c',64));",ok=False)
        self.assertIn('foreign key',error)
        self.assertIn('check constraint',query("UPDATE batcave.owner_phone_subscriptions_v1 SET endpoint='http://127.0.0.1/private';",ok=False))

    def test_disabled_phones_and_test_cooldown(self):
        self.assertEqual(len(self.queue('test')),1);self.assertEqual(self.queue('test'),[])
        query('UPDATE batcave.owner_phone_subscriptions_v1 SET disabled_at=now();')
        self.assertEqual(self.queue(),[])

    def test_clients_cannot_read_queue_secrets_or_dispatch(self):
        for role in ['anon','authenticated']:
            for statement in ['SELECT * FROM batcave.owner_phone_subscriptions_v1','SELECT * FROM batcave.owner_phone_notifications_v1','SELECT * FROM batcave.owner_phone_config_v1',f"SELECT batcave.queue_owner_phone_alert_v1('{OWNER}','test',NULL)","SELECT * FROM net.request_log","SELECT * FROM vault.decrypted_secrets"]:
                self.assertIn('permission denied',query(f'SET ROLE {role};{statement};',ok=False))

    def test_claim_is_atomic_and_expired_delivery_cannot_be_claimed(self):
        ident=self.queue()[0]
        def claim(_):return query(f"UPDATE batcave.owner_phone_notifications_v1 SET send_state='sending' WHERE id='{ident}' AND send_state='queued' AND expires_at>clock_timestamp() RETURNING id;")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(claim,range(4)))
        self.assertEqual(sum(bool(r) for r in results),1)
        query(f"UPDATE batcave.owner_phone_notifications_v1 SET created_at=now()-interval '11 minutes',expires_at=now()-interval '1 minute',send_state='queued' WHERE id='{ident}';")
        self.assertEqual(claim(0),'')

if __name__=='__main__':unittest.main(verbosity=2)
