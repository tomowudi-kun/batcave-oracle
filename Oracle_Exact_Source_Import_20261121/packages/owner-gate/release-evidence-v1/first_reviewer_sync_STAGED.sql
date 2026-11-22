-- Same confirmed-owner gate, public signed evidence only. No new trust/grants.
BEGIN;
ALTER TABLE batcave.oracle_first_challenges_v1 ADD COLUMN withdrawn_at timestamptz, ADD COLUMN pending_owner_signature_b64url text CHECK(pending_owner_signature_b64url ~ '^[A-Za-z0-9_-]{86}$');
ALTER TABLE batcave.oracle_first_reviewer_v1 ADD COLUMN owner_declined_at timestamptz, ADD COLUMN last_owner_declined_at timestamptz;
CREATE OR REPLACE FUNCTION batcave.oracle_first_challenge_immutable_v1() RETURNS trigger LANGUAGE plpgsql SET search_path='' AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'first-key receipt is append-only'; END IF;
 IF (to_jsonb(NEW)-ARRAY['consumed_at','recorded_at','owner_signature_b64url','reviewer_signature_b64url','pending_owner_signature_b64url','withdrawn_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['consumed_at','recorded_at','owner_signature_b64url','reviewer_signature_b64url','pending_owner_signature_b64url','withdrawn_at']) OR OLD.consumed_at IS NOT NULL OR (OLD.withdrawn_at IS NOT NULL AND NEW.withdrawn_at IS DISTINCT FROM OLD.withdrawn_at) OR (OLD.pending_owner_signature_b64url IS NOT NULL AND NEW.pending_owner_signature_b64url IS DISTINCT FROM OLD.pending_owner_signature_b64url) THEN RAISE EXCEPTION 'first-key challenge is immutable'; END IF;
 RETURN NEW;
END; $$;
-- Private persistence boundary, called AFTER genuine owner signature verification.
-- Saving one signature never registers/promotes a key or consumes the nonce.
CREATE FUNCTION batcave.oracle_first_save_endorsement_v1(p_owner uuid,p_challenge uuid,p_hash text,p_signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
DECLARE c batcave.oracle_first_challenges_v1%ROWTYPE; r batcave.oracle_first_reviewer_v1%ROWTYPE; o record; i record; v_now timestamptz;
BEGIN
 SELECT * INTO c FROM batcave.oracle_first_challenges_v1 WHERE id=p_challenge AND owner_user_id=p_owner FOR UPDATE;
 IF NOT FOUND OR c.kind<>'first_key' OR c.withdrawn_at IS NOT NULL OR c.consumed_at IS NOT NULL OR c.payload_sha256 IS DISTINCT FROM p_hash OR (c.pending_owner_signature_b64url IS NOT NULL AND c.pending_owner_signature_b64url IS DISTINCT FROM p_signature) THEN RETURN jsonb_build_object('saved',false); END IF;
 SELECT * INTO r FROM batcave.oracle_first_reviewer_v1 WHERE slot=1 FOR UPDATE;
 IF NOT FOUND OR r.registered_at IS NOT NULL OR r.revoked_at IS NOT NULL OR r.policy_sha256<>c.policy_sha256 OR r.policy->>'owner_user_id'<>p_owner::text OR r.policy->>'owner_key_sha256'<>c.owner_key_sha256 OR r.policy->>'reviewer_key_sha256'<>c.reviewer_key_sha256 THEN RETURN jsonb_build_object('saved',false); END IF;
 SELECT public_key_sha256,revoked_at INTO o FROM batcave.linux_owner_keys_v1 WHERE owner_user_id=p_owner FOR SHARE;
 IF NOT FOUND OR o.revoked_at IS NOT NULL OR o.public_key_sha256 IS DISTINCT FROM c.owner_key_sha256 THEN RETURN jsonb_build_object('saved',false); END IF;
 SELECT state,content_sha256,valid_until INTO i FROM batcave.change_gate_intents WHERE intent_key=r.policy->>'release_intent_key' FOR SHARE;
 IF NOT FOUND OR i.state<>'held' OR i.content_sha256 IS DISTINCT FROM (r.policy->>'release_intent_sha256') THEN RETURN jsonb_build_object('saved',false); END IF;
 v_now:=clock_timestamp();
 IF (r.last_owner_declined_at IS NOT NULL AND c.issued_at<=r.last_owner_declined_at) OR c.expires_at<=v_now OR c.issued_at>v_now+interval '30 seconds' OR c.issued_at<v_now-interval '10 minutes' OR i.valid_until<=v_now OR (r.policy->>'signer_valid_until')::timestamptz<=v_now OR p_signature IS NULL OR p_signature !~ '^[A-Za-z0-9_-]{86}$' THEN RETURN jsonb_build_object('saved',false); END IF;
 IF c.pending_owner_signature_b64url IS NULL THEN UPDATE batcave.oracle_first_challenges_v1 SET pending_owner_signature_b64url=p_signature WHERE id=c.id; END IF;
 IF r.owner_declined_at IS NOT NULL THEN UPDATE batcave.oracle_first_reviewer_v1 SET owner_declined_at=NULL WHERE slot=1; END IF;
 RETURN jsonb_build_object('saved',true,'reviewer_registered',false,'independently_attested',false,'deployment_authorized',false,'execution_authorized',false,'grant_issued',false);
END; $$;
REVOKE ALL ON FUNCTION batcave.oracle_first_save_endorsement_v1(uuid,uuid,text,text) FROM PUBLIC,anon,authenticated;
COMMENT ON COLUMN batcave.oracle_first_challenges_v1.pending_owner_signature_b64url IS 'Genuine public owner endorsement, immutable once stored. Still needs actual candidate proof and original atomic registration. Same owner-authenticated gate only.';
-- No can withdraw unused enrollment challenges. It never removes an enrolled key.
-- Lock captured challenge(s) before root, matching save/finish. Never lock
-- newly inserted rows after root; the permanent timestamp cutoff rejects those
-- older nonces even after a later Yes. No clock/expiry extension is performed.
CREATE FUNCTION batcave.oracle_first_decline_v1(p_owner uuid,p_policy_hash text)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
DECLARE r batcave.oracle_first_reviewer_v1%ROWTYPE; o record; v_now timestamptz; v_ids uuid[];
BEGIN
 SELECT array_agg(locked.id) INTO v_ids FROM (SELECT id FROM batcave.oracle_first_challenges_v1 WHERE kind='first_key' AND owner_user_id=p_owner AND policy_sha256=p_policy_hash AND consumed_at IS NULL ORDER BY id FOR UPDATE) locked;
 SELECT * INTO r FROM batcave.oracle_first_reviewer_v1 WHERE slot=1 FOR UPDATE;
 IF NOT FOUND OR r.registered_at IS NOT NULL OR r.revoked_at IS NOT NULL OR r.policy_sha256 IS DISTINCT FROM p_policy_hash OR r.policy->>'owner_user_id' IS DISTINCT FROM p_owner::text THEN RETURN jsonb_build_object('declined',false); END IF;
 SELECT public_key_sha256,revoked_at INTO o FROM batcave.linux_owner_keys_v1 WHERE owner_user_id=p_owner FOR SHARE;
 IF NOT FOUND OR o.revoked_at IS NOT NULL OR o.public_key_sha256 IS DISTINCT FROM (r.policy->>'owner_key_sha256') THEN RETURN jsonb_build_object('declined',false); END IF;
 v_now:=clock_timestamp();
 UPDATE batcave.oracle_first_challenges_v1 SET withdrawn_at=v_now WHERE id=ANY(v_ids) AND consumed_at IS NULL AND withdrawn_at IS NULL;
 UPDATE batcave.oracle_first_reviewer_v1 SET owner_declined_at=v_now,last_owner_declined_at=v_now WHERE slot=1;
 RETURN jsonb_build_object('declined',true,'reviewer_registered',false,'deployment_authorized',false,'execution_authorized',false,'grant_issued',false);
END; $$;
REVOKE ALL ON FUNCTION batcave.oracle_first_decline_v1(uuid,text) FROM PUBLIC,anon,authenticated;
CREATE OR REPLACE FUNCTION batcave.oracle_first_finish_v1(p_owner uuid,p_challenge uuid,p_hash text,p_owner_sig text,p_reviewer_sig text)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
DECLARE c batcave.oracle_first_challenges_v1%ROWTYPE; r batcave.oracle_first_reviewer_v1%ROWTYPE; o record; i record; v_now timestamptz; f text;
BEGIN
 SELECT * INTO c FROM batcave.oracle_first_challenges_v1 WHERE id=p_challenge AND owner_user_id=p_owner FOR UPDATE;
 IF NOT FOUND OR c.withdrawn_at IS NOT NULL OR c.consumed_at IS NOT NULL OR c.payload_sha256 IS DISTINCT FROM p_hash THEN RETURN jsonb_build_object('inserted',false); END IF;
 SELECT * INTO r FROM batcave.oracle_first_reviewer_v1 WHERE slot=1 FOR UPDATE;
 IF NOT FOUND OR r.revoked_at IS NOT NULL OR r.policy_sha256<>c.policy_sha256 OR r.policy->>'owner_user_id'<>p_owner::text OR r.policy->>'owner_key_sha256'<>c.owner_key_sha256 OR r.policy->>'reviewer_key_sha256'<>c.reviewer_key_sha256 THEN RETURN jsonb_build_object('inserted',false); END IF;
 SELECT owner_user_id,public_key_sha256,revoked_at INTO o FROM batcave.linux_owner_keys_v1 WHERE owner_user_id=p_owner FOR SHARE;
 IF NOT FOUND OR o.revoked_at IS NOT NULL OR o.public_key_sha256 IS DISTINCT FROM c.owner_key_sha256 THEN RETURN jsonb_build_object('inserted',false); END IF;
 SELECT state,content_sha256,valid_until INTO i FROM batcave.change_gate_intents WHERE intent_key=r.policy->>'release_intent_key' FOR SHARE;
 IF NOT FOUND OR i.state<>'held' OR i.content_sha256 IS DISTINCT FROM (r.policy->>'release_intent_sha256') THEN RETURN jsonb_build_object('inserted',false); END IF;
 IF p_owner_sig IS NULL OR p_reviewer_sig IS NULL OR p_owner_sig !~ '^[A-Za-z0-9_-]{86}$' OR p_reviewer_sig !~ '^[A-Za-z0-9_-]{86}$' THEN RETURN jsonb_build_object('inserted',false); END IF;
 IF c.kind='first_key' THEN
  IF r.owner_declined_at IS NOT NULL OR (r.last_owner_declined_at IS NOT NULL AND c.issued_at<=r.last_owner_declined_at) OR (c.pending_owner_signature_b64url IS NOT NULL AND c.pending_owner_signature_b64url IS DISTINCT FROM p_owner_sig) THEN RETURN jsonb_build_object('inserted',false); END IF;
  -- Serialize with ordinary reviewer insertions and every other first-key attempt.
  LOCK TABLE batcave.oracle_release_keys_v1 IN SHARE ROW EXCLUSIVE MODE;
  IF r.registered_at IS NOT NULL OR EXISTS(SELECT 1 FROM batcave.oracle_release_keys_v1) THEN RETURN jsonb_build_object('inserted',false); END IF;
  FOREACH f IN ARRAY ARRAY['owner_user_id','owner_key_sha256','reviewer_key_sha256','candidate_sha256','host_identity_sha256','reviewer_sid','custody_evidence_sha256','scope','trust_basis','signer_valid_until'] LOOP
   IF c.payload->>f IS DISTINCT FROM (r.policy->>f) THEN RETURN jsonb_build_object('inserted',false); END IF;
  END LOOP;
  IF c.payload->>'policy_sha256' IS DISTINCT FROM r.policy_sha256 OR c.candidate->>'public_key_sha256' IS DISTINCT FROM (r.policy->>'reviewer_key_sha256') OR c.candidate->>'public_key_b64url' IS DISTINCT FROM (r.policy->>'reviewer_public_key_b64url') THEN RETURN jsonb_build_object('inserted',false); END IF;
 ELSE
  IF r.registered_at IS NULL THEN RETURN jsonb_build_object('inserted',false); END IF;
 END IF;
 v_now:=clock_timestamp();
 IF c.expires_at<=v_now OR c.issued_at>v_now+interval '30 seconds' OR c.issued_at<v_now-interval '10 minutes' OR i.valid_until<=v_now OR (r.policy->>'signer_valid_until')::timestamptz<=v_now THEN RETURN jsonb_build_object('inserted',false); END IF;
 UPDATE batcave.oracle_first_challenges_v1 SET consumed_at=v_now,recorded_at=v_now,owner_signature_b64url=p_owner_sig,reviewer_signature_b64url=p_reviewer_sig WHERE id=c.id;
 IF c.kind='first_key' THEN UPDATE batcave.oracle_first_reviewer_v1 SET registered_at=v_now,registration_challenge_id=c.id WHERE slot=1; END IF;
 RETURN jsonb_build_object('inserted',true,'evidence_id',c.id);
END; $$;
COMMIT;
