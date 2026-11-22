BEGIN;
CREATE TABLE batcave.oracle_first_public_proofs_v1(
 challenge_id uuid PRIMARY KEY REFERENCES batcave.oracle_first_challenges_v1(id),
 owner_user_id uuid NOT NULL REFERENCES batcave.linux_owner_keys_v1(owner_user_id),
 proof jsonb NOT NULL CHECK(jsonb_typeof(proof)='object' AND length(proof::text)<5000),
 proof_sha256 text NOT NULL CHECK(proof_sha256 ~ '^[a-f0-9]{64}$'),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 independently_attested boolean NOT NULL DEFAULT false CHECK(NOT independently_attested),
 deployment_authorized boolean NOT NULL DEFAULT false CHECK(NOT deployment_authorized),
 execution_authorized boolean NOT NULL DEFAULT false CHECK(NOT execution_authorized),
 grant_issued boolean NOT NULL DEFAULT false CHECK(NOT grant_issued)
);
CREATE FUNCTION batcave.oracle_first_public_proof_immutable_v1() RETURNS trigger LANGUAGE plpgsql SET search_path='' AS $$ BEGIN RAISE EXCEPTION 'public proof receipt is append-only'; END $$;
CREATE TRIGGER oracle_first_public_proof_immutable BEFORE UPDATE OR DELETE ON batcave.oracle_first_public_proofs_v1 FOR EACH ROW EXECUTE FUNCTION batcave.oracle_first_public_proof_immutable_v1();
CREATE FUNCTION batcave.oracle_first_store_public_proof_v1(p_challenge uuid,p_payload_sha text,p_proof jsonb,p_proof_sha text) RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
DECLARE r batcave.oracle_first_reviewer_v1%ROWTYPE;c batcave.oracle_first_challenges_v1%ROWTYPE;o batcave.linux_owner_keys_v1%ROWTYPE;old jsonb;t timestamptz:=clock_timestamp();
BEGIN
 SELECT * INTO r FROM batcave.oracle_first_reviewer_v1 WHERE slot=1 FOR UPDATE;
 IF NOT FOUND OR r.registered_at IS NOT NULL OR r.revoked_at IS NOT NULL OR r.owner_declined_at IS NOT NULL OR (r.policy->>'signer_valid_until')::timestamptz<=t THEN RETURN jsonb_build_object('stored',false); END IF;
 SELECT * INTO c FROM batcave.oracle_first_challenges_v1 WHERE id=p_challenge FOR UPDATE;
 IF NOT FOUND OR c.kind<>'first_key' OR c.consumed_at IS NOT NULL OR c.withdrawn_at IS NOT NULL OR c.pending_owner_signature_b64url IS NULL OR c.expires_at<=t OR c.payload_sha256<>p_payload_sha OR c.policy_sha256<>r.policy_sha256 OR c.owner_user_id::text<>r.policy->>'owner_user_id' THEN RETURN jsonb_build_object('stored',false); END IF;
 SELECT * INTO o FROM batcave.linux_owner_keys_v1 WHERE owner_user_id=c.owner_user_id FOR SHARE;
 IF NOT FOUND OR o.revoked_at IS NOT NULL OR o.public_key_sha256<>r.policy->>'owner_key_sha256' OR c.owner_key_sha256<>o.public_key_sha256 OR c.reviewer_key_sha256<>r.policy->>'reviewer_key_sha256' THEN RETURN jsonb_build_object('stored',false); END IF;
 PERFORM 1 FROM batcave.change_gate_intents WHERE intent_key=r.policy->>'release_intent_key' AND state='held' AND content_sha256=r.policy->>'release_intent_sha256' AND valid_until>t FOR SHARE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM batcave.oracle_release_keys_v1 WHERE registered AND revoked_at IS NULL) THEN RETURN jsonb_build_object('stored',false); END IF;
 IF p_proof->>'schema' IS DISTINCT FROM 'batcave.nanny.first_key.possession.v1' OR p_proof->>'challenge_id' IS DISTINCT FROM c.id::text OR p_proof->>'nonce' IS DISTINCT FROM c.nonce OR p_proof->>'policy_sha256' IS DISTINCT FROM r.policy_sha256 OR p_proof->>'reviewer_public_key_sha256' IS DISTINCT FROM r.policy->>'reviewer_key_sha256' OR p_proof->'independently_attested' IS DISTINCT FROM 'false'::jsonb OR p_proof->'deployment_authorized' IS DISTINCT FROM 'false'::jsonb OR p_proof->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR p_proof->'grant_issued' IS DISTINCT FROM 'false'::jsonb THEN RETURN jsonb_build_object('stored',false); END IF;
 IF c.expires_at<=clock_timestamp() THEN RETURN jsonb_build_object('stored',false); END IF;
 INSERT INTO batcave.oracle_first_public_proofs_v1(challenge_id,owner_user_id,proof,proof_sha256) VALUES(c.id,c.owner_user_id,p_proof,p_proof_sha) ON CONFLICT DO NOTHING;
 SELECT proof INTO old FROM batcave.oracle_first_public_proofs_v1 WHERE challenge_id=c.id;
 RETURN jsonb_build_object('stored',old=p_proof);
END $$;
ALTER TABLE batcave.oracle_first_public_proofs_v1 ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON batcave.oracle_first_public_proofs_v1 FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION batcave.oracle_first_store_public_proof_v1(uuid,text,jsonb,text),batcave.oracle_first_public_proof_immutable_v1() FROM PUBLIC,anon,authenticated;
COMMENT ON TABLE batcave.oracle_first_public_proofs_v1 IS 'Verified public proof transport only; cannot enroll, attest custody, sign release, issue grants or execute commands.';
COMMIT;
