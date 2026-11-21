-- STAGED ONLY: first-key policy approved; no live migration/deployment approval.
-- Apply after release_evidence_schema_STAGED.sql. NO live policy or identity seed.
BEGIN;
CREATE TABLE batcave.oracle_first_reviewer_v1 (
 slot smallint PRIMARY KEY DEFAULT 1 CHECK(slot=1),
 policy jsonb NOT NULL CHECK(jsonb_typeof(policy)='object'),
 canonical_policy text NOT NULL CHECK(length(canonical_policy)<=6000 AND canonical_policy::jsonb=policy),
 policy_sha256 text NOT NULL UNIQUE CHECK(policy_sha256=encode(sha256(convert_to(canonical_policy,'UTF8')),'hex')),
 registered_at timestamptz,
 registration_challenge_id uuid UNIQUE,
 revoked_at timestamptz,
 independently_attested boolean NOT NULL DEFAULT false CHECK(NOT independently_attested),
 production_release_authorized boolean NOT NULL DEFAULT false CHECK(NOT production_release_authorized),
 CHECK((registered_at IS NULL)=(registration_challenge_id IS NULL)),
 CHECK(policy @> '{"schema":"batcave.oracle.owner_first_reviewer.policy.v1","scope":"first_reviewer_enrollment_only","trust_basis":"owner_signed_first_reviewer_bootstrap","release_intent_key":"batcave.oracle.lab_v031.release_request.20261121","release_intent_sha256":"ff41a4a74e25fd31bf9a466d1566100ba9e98cc5d8769fd01fe12c9c653c4e80"}'::jsonb),
 CHECK(((policy->>'reviewer_key_sha256') ~ '^[a-f0-9]{64}$' AND (policy->>'owner_key_sha256') ~ '^[a-f0-9]{64}$' AND (policy->>'reviewer_public_key_b64url') ~ '^[A-Za-z0-9_-]{43}$' AND policy->>'reviewer_key_sha256'<>policy->>'owner_key_sha256' AND policy->>'reviewer_key_sha256' NOT IN ('4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b','61dde7b2e70af2d47746b75f401d87d57e41e123aeba185cc8ca6b7e1b05b664') AND policy->>'reviewer_public_key_b64url'<>'PkCiAsi_f6Cv2UkYCYZbE3z8L5pgUi339QB-yLVvKCo') IS TRUE)
);
CREATE TABLE batcave.oracle_first_challenges_v1 (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 kind text NOT NULL CHECK(kind IN ('first_key','release')),
 owner_user_id uuid NOT NULL,
 owner_key_sha256 text NOT NULL CHECK(owner_key_sha256 ~ '^[a-f0-9]{64}$'),
 reviewer_key_sha256 text NOT NULL CHECK(reviewer_key_sha256 ~ '^[a-f0-9]{64}$'),
 policy_sha256 text NOT NULL REFERENCES batcave.oracle_first_reviewer_v1(policy_sha256),
 nonce text NOT NULL UNIQUE CHECK(nonce ~ '^[a-f0-9]{32}$'),
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '10 minutes'),
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),
 canonical_payload text NOT NULL CHECK(length(canonical_payload)<=6000 AND canonical_payload::jsonb=payload),
 payload_sha256 text NOT NULL CHECK(payload_sha256=encode(sha256(convert_to(canonical_payload,'UTF8')),'hex')),
 candidate jsonb,
 consumed_at timestamptz,
 recorded_at timestamptz,
 owner_signature_b64url text CHECK(owner_signature_b64url ~ '^[A-Za-z0-9_-]{86}$'),
 reviewer_signature_b64url text CHECK(reviewer_signature_b64url ~ '^[A-Za-z0-9_-]{86}$'),
 deployment_authorized boolean NOT NULL DEFAULT false CHECK(NOT deployment_authorized),
 execution_authorized boolean NOT NULL DEFAULT false CHECK(NOT execution_authorized),
 grant_issued boolean NOT NULL DEFAULT false CHECK(NOT grant_issued),
 CHECK((kind='first_key' AND candidate IS NOT NULL AND jsonb_typeof(candidate)='object') OR (kind='release' AND candidate IS NULL)),
 CHECK(((payload->>'nonce')=nonce AND (payload->>'owner_user_id')::uuid=owner_user_id AND (payload->>'issued_at')::timestamptz=issued_at AND (payload->>'expires_at')::timestamptz=expires_at) IS TRUE),
 CHECK((consumed_at IS NULL AND recorded_at IS NULL AND owner_signature_b64url IS NULL AND reviewer_signature_b64url IS NULL) OR (consumed_at IS NOT NULL AND consumed_at=recorded_at AND owner_signature_b64url IS NOT NULL AND reviewer_signature_b64url IS NOT NULL)),
 CHECK(kind<>'first_key' OR payload @> '{"schema":"batcave.oracle.first_reviewer.enrollment.v1","scope":"first_reviewer_enrollment_only","trust_basis":"owner_signed_first_reviewer_bootstrap"}'::jsonb),
 CHECK(kind<>'release' OR payload @> '{"schema":"batcave.oracle.pinned.release.v1","intent_key":"batcave.oracle.lab_v031.release_request.20261121","intent_sha256":"ff41a4a74e25fd31bf9a466d1566100ba9e98cc5d8769fd01fe12c9c653c4e80","owner_gate_zip_sha256":"69ab19be8ec2e11e902716da59c2dda8693a3d3c78a16d8bdc1ded25a8d16851","worker_zip_sha256":"4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2","pr_head_sha":"33b62fae6ccb2224f04cce43443510b71c051297","target_device":"Oracle","operation":"model_generate_and_verify_v1","fixture":"fixed_clamp_score_v1","scope":"disposable_lab_only"}'::jsonb)
);
ALTER TABLE batcave.oracle_first_reviewer_v1 ADD FOREIGN KEY(registration_challenge_id) REFERENCES batcave.oracle_first_challenges_v1(id);
-- A consumed root slot can never be reset/replaced, even after revocation.
CREATE FUNCTION batcave.oracle_first_policy_immutable_v1() RETURNS trigger LANGUAGE plpgsql SET search_path='' AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'first-key policy is permanent; revoke instead'; END IF;
 IF NEW.policy IS DISTINCT FROM OLD.policy OR NEW.canonical_policy IS DISTINCT FROM OLD.canonical_policy OR NEW.policy_sha256 IS DISTINCT FROM OLD.policy_sha256 OR NEW.slot<>OLD.slot OR (OLD.registered_at IS NOT NULL AND (NEW.registered_at IS DISTINCT FROM OLD.registered_at OR NEW.registration_challenge_id IS DISTINCT FROM OLD.registration_challenge_id)) OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN RAISE EXCEPTION 'first-key policy and consumed slot are immutable'; END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER first_policy_immutable BEFORE UPDATE OR DELETE ON batcave.oracle_first_reviewer_v1 FOR EACH ROW EXECUTE FUNCTION batcave.oracle_first_policy_immutable_v1();
-- Challenge content and recorded signature pairs are append-only.
CREATE FUNCTION batcave.oracle_first_challenge_immutable_v1() RETURNS trigger LANGUAGE plpgsql SET search_path='' AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'first-key receipt is append-only'; END IF;
 IF (to_jsonb(NEW)-ARRAY['consumed_at','recorded_at','owner_signature_b64url','reviewer_signature_b64url']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['consumed_at','recorded_at','owner_signature_b64url','reviewer_signature_b64url']) OR OLD.consumed_at IS NOT NULL THEN RAISE EXCEPTION 'first-key challenge is immutable'; END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER first_challenge_immutable BEFORE UPDATE OR DELETE ON batcave.oracle_first_challenges_v1 FOR EACH ROW EXECUTE FUNCTION batcave.oracle_first_challenge_immutable_v1();
-- Private DB function: signatures MUST have been cryptographically verified by
-- the existing owner-authenticated gate before calling. Not exposed to clients.
CREATE FUNCTION batcave.oracle_first_finish_v1(p_owner uuid,p_challenge uuid,p_hash text,p_owner_sig text,p_reviewer_sig text)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
DECLARE c batcave.oracle_first_challenges_v1%ROWTYPE; r batcave.oracle_first_reviewer_v1%ROWTYPE; o record; i record; v_now timestamptz; f text;
BEGIN
 SELECT * INTO c FROM batcave.oracle_first_challenges_v1 WHERE id=p_challenge AND owner_user_id=p_owner FOR UPDATE;
 IF NOT FOUND OR c.consumed_at IS NOT NULL OR c.payload_sha256 IS DISTINCT FROM p_hash THEN RETURN jsonb_build_object('inserted',false); END IF;
 SELECT * INTO r FROM batcave.oracle_first_reviewer_v1 WHERE slot=1 FOR UPDATE;
 IF NOT FOUND OR r.revoked_at IS NOT NULL OR r.policy_sha256<>c.policy_sha256 OR r.policy->>'owner_user_id'<>p_owner::text OR r.policy->>'owner_key_sha256'<>c.owner_key_sha256 OR r.policy->>'reviewer_key_sha256'<>c.reviewer_key_sha256 THEN RETURN jsonb_build_object('inserted',false); END IF;
 SELECT owner_user_id,public_key_sha256,revoked_at INTO o FROM batcave.linux_owner_keys_v1 WHERE owner_user_id=p_owner FOR SHARE;
 IF NOT FOUND OR o.revoked_at IS NOT NULL OR o.public_key_sha256 IS DISTINCT FROM c.owner_key_sha256 THEN RETURN jsonb_build_object('inserted',false); END IF;
 SELECT state,content_sha256,valid_until INTO i FROM batcave.change_gate_intents WHERE intent_key=r.policy->>'release_intent_key' FOR SHARE;
 IF NOT FOUND OR i.state<>'held' OR i.content_sha256 IS DISTINCT FROM (r.policy->>'release_intent_sha256') THEN RETURN jsonb_build_object('inserted',false); END IF;
 IF p_owner_sig IS NULL OR p_reviewer_sig IS NULL OR p_owner_sig !~ '^[A-Za-z0-9_-]{86}$' OR p_reviewer_sig !~ '^[A-Za-z0-9_-]{86}$' THEN RETURN jsonb_build_object('inserted',false); END IF;
 IF c.kind='first_key' THEN
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
ALTER TABLE batcave.oracle_first_reviewer_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE batcave.oracle_first_challenges_v1 ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON batcave.oracle_first_reviewer_v1,batcave.oracle_first_challenges_v1 FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION batcave.oracle_first_finish_v1(uuid,uuid,text,text,text),batcave.oracle_first_policy_immutable_v1(),batcave.oracle_first_challenge_immutable_v1() FROM PUBLIC,anon,authenticated;
COMMENT ON TABLE batcave.oracle_first_reviewer_v1 IS 'Private exact first-key policy, never public source. Registration requires real existing owner signature and candidate possession. NOT independent custody attestation. No seed included.';
COMMIT;
