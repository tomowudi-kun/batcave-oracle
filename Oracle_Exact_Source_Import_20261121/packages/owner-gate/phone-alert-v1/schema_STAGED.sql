-- Notification-only tables. No access to command/release mutators.
BEGIN;
CREATE EXTENSION IF NOT EXISTS pg_net WITH SCHEMA extensions;
REVOKE ALL ON SCHEMA net FROM PUBLIC,anon,authenticated;
CREATE TABLE batcave.owner_phone_config_v1(
 slot smallint PRIMARY KEY CHECK(slot=1), public_key text NOT NULL CHECK(public_key ~ '^[A-Za-z0-9_-]{87}$'),
 secret_id uuid NOT NULL, dispatch_hash text NOT NULL CHECK(dispatch_hash ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE batcave.owner_phone_subscriptions_v1(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),owner_user_id uuid NOT NULL REFERENCES batcave.linux_owner_keys_v1(owner_user_id),
 endpoint_sha256 text NOT NULL UNIQUE CHECK(endpoint_sha256 ~ '^[a-f0-9]{64}$'),endpoint text NOT NULL CHECK(length(endpoint)<4096 AND endpoint ~ '^https://fcm[.]googleapis[.]com/(fcm/send|wp)/[A-Za-z0-9_:-]+$'),
 p256dh text NOT NULL CHECK(p256dh ~ '^[A-Za-z0-9_-]{87}$'),auth text NOT NULL CHECK(auth ~ '^[A-Za-z0-9_-]{22}$'),
 created_at timestamptz NOT NULL DEFAULT now(),disabled_at timestamptz,UNIQUE(id,owner_user_id)
);
CREATE TABLE batcave.owner_phone_notifications_v1(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),subscription_id uuid NOT NULL REFERENCES batcave.owner_phone_subscriptions_v1(id),owner_user_id uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN ('review','test')),request_key text NOT NULL CHECK(request_key ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT now(),expires_at timestamptz NOT NULL DEFAULT now()+interval '10 minutes',
 send_state text NOT NULL DEFAULT 'queued' CHECK(send_state IN ('queued','sending','sent','failed','gone','cancelled','uncertain')),
 receipt_hash text CHECK(receipt_hash ~ '^[a-f0-9]{64}$'),sent_at timestamptz,shown_at timestamptz,opened_at timestamptz,
 deployment_authorized boolean NOT NULL DEFAULT false CHECK(NOT deployment_authorized),execution_authorized boolean NOT NULL DEFAULT false CHECK(NOT execution_authorized),
 FOREIGN KEY(subscription_id,owner_user_id) REFERENCES batcave.owner_phone_subscriptions_v1(id,owner_user_id),
 UNIQUE(subscription_id,kind,request_key), CHECK(expires_at>created_at AND expires_at<=created_at+interval '10 minutes')
);
CREATE INDEX owner_phone_delivery_status ON batcave.owner_phone_notifications_v1(owner_user_id,subscription_id,created_at DESC);
CREATE FUNCTION batcave.owner_phone_dispatch_v1() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
DECLARE cfg batcave.owner_phone_config_v1%ROWTYPE; private jsonb;
BEGIN
 SELECT * INTO cfg FROM batcave.owner_phone_config_v1 WHERE slot=1;
 IF NOT FOUND THEN RAISE EXCEPTION 'phone notification config missing'; END IF;
 SELECT decrypted_secret::jsonb INTO private FROM vault.decrypted_secrets WHERE id=cfg.secret_id;
 IF private->>'dispatchToken' IS NULL THEN RAISE EXCEPTION 'phone notification secret missing'; END IF;
 PERFORM net.http_post(url:='https://wizflveeptzeajsdybzs.supabase.co/functions/v1/batcave-phone-alert-v1',
 headers:=jsonb_build_object('Content-Type','application/json','x-batcave-notification-dispatch',private->>'dispatchToken'),
 body:=jsonb_build_object('op','dispatch','notification_id',NEW.id),timeout_milliseconds:=15000);
 RETURN NEW;
END; $$;
CREATE TRIGGER owner_phone_dispatch AFTER INSERT ON batcave.owner_phone_notifications_v1 FOR EACH ROW EXECUTE FUNCTION batcave.owner_phone_dispatch_v1();
CREATE FUNCTION batcave.queue_owner_phone_alert_v1(p_owner uuid,p_kind text DEFAULT 'review',p_subscription uuid DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
DECLARE root batcave.oracle_first_reviewer_v1%ROWTYPE; sub record; request text; ident uuid; ids jsonb:='[]'::jsonb; at timestamptz:=clock_timestamp();until timestamptz;
BEGIN
 IF p_kind NOT IN ('test','review') OR NOT EXISTS(SELECT 1 FROM batcave.linux_owner_keys_v1 WHERE owner_user_id=p_owner AND revoked_at IS NULL) THEN RETURN ids; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_owner::text,20261122));
 IF p_kind='review' THEN
  SELECT * INTO root FROM batcave.oracle_first_reviewer_v1 WHERE slot=1;
  IF NOT FOUND OR root.registered_at IS NOT NULL OR root.revoked_at IS NOT NULL OR root.owner_declined_at IS NOT NULL OR root.policy->>'owner_user_id'<>p_owner::text OR NOT EXISTS(SELECT 1 FROM batcave.linux_owner_keys_v1 WHERE owner_user_id=p_owner AND public_key_sha256=root.policy->>'owner_key_sha256' AND revoked_at IS NULL) OR (root.policy->>'signer_valid_until')::timestamptz<=at OR NOT EXISTS(SELECT 1 FROM batcave.change_gate_intents WHERE intent_key=root.policy->>'release_intent_key' AND content_sha256=root.policy->>'release_intent_sha256' AND state='held' AND valid_until>at) THEN RETURN ids; END IF;
  IF EXISTS(SELECT 1 FROM batcave.oracle_first_challenges_v1 WHERE kind='first_key' AND owner_user_id=p_owner AND policy_sha256=root.policy_sha256 AND pending_owner_signature_b64url IS NOT NULL AND consumed_at IS NULL AND expires_at>at) THEN RETURN ids; END IF;
  request:=root.policy_sha256;until:=LEAST(at+interval '10 minutes',(root.policy->>'signer_valid_until')::timestamptz);
 ELSE request:=encode(sha256(convert_to(gen_random_uuid()::text,'UTF8')),'hex');until:=at+interval '10 minutes'; END IF;
 FOR sub IN SELECT id FROM batcave.owner_phone_subscriptions_v1 WHERE owner_user_id=p_owner AND disabled_at IS NULL AND (p_subscription IS NULL OR id=p_subscription) LOOP
  IF p_kind='test' AND EXISTS(SELECT 1 FROM batcave.owner_phone_notifications_v1 WHERE subscription_id=sub.id AND created_at>at-interval '30 seconds') THEN CONTINUE; END IF;
  INSERT INTO batcave.owner_phone_notifications_v1(subscription_id,owner_user_id,kind,request_key,created_at,expires_at) VALUES(sub.id,p_owner,p_kind,request,at,until) ON CONFLICT DO NOTHING RETURNING id INTO ident;
  IF ident IS NOT NULL THEN ids:=ids||jsonb_build_array(ident); END IF;
 END LOOP;
 RETURN ids;
END; $$;
ALTER TABLE batcave.owner_phone_config_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE batcave.owner_phone_subscriptions_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE batcave.owner_phone_notifications_v1 ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON batcave.owner_phone_config_v1,batcave.owner_phone_subscriptions_v1,batcave.owner_phone_notifications_v1 FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION batcave.owner_phone_dispatch_v1(),batcave.queue_owner_phone_alert_v1(uuid,text,uuid) FROM PUBLIC,anon,authenticated;
COMMENT ON TABLE batcave.owner_phone_notifications_v1 IS 'Notification delivery only. Shown/opened receipts never approve, sign, review, dispatch commands or release Oracle.';
COMMIT;
