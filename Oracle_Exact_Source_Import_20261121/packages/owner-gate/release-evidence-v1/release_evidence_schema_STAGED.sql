-- STAGED ONLY. Extend existing private gate; never apply without independent review.
-- No executable grants, workers, policies, existing intent updates or public API.
BEGIN;
CREATE TABLE batcave.oracle_release_custody_v1 (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 owner_user_id uuid NOT NULL,
 public_key_sha256 text NOT NULL CHECK(public_key_sha256 ~ '^[a-f0-9]{64}$'),
 host_identity_sha256 text NOT NULL CHECK(host_identity_sha256 ~ '^[a-f0-9]{64}$'),
 evidence_sha256 text NOT NULL CHECK(evidence_sha256 ~ '^[a-f0-9]{64}$'),
 independently_attested boolean NOT NULL CHECK(independently_attested),
 release_policy_version text NOT NULL CHECK(release_policy_version='strict_nanny.release.v1'),
 private_key_custodian text NOT NULL CHECK(private_key_custodian='Cortana separate protected reviewer'),
 attested_at timestamptz NOT NULL DEFAULT now(),
 valid_until timestamptz NOT NULL CHECK(valid_until>attested_at),
 revoked_at timestamptz,
 UNIQUE(owner_user_id,public_key_sha256)
);
COMMENT ON TABLE batcave.oracle_release_custody_v1 IS 'Independent registrar only. No owner/browser/model endpoint may insert attestations. A row is not created by this migration.';
CREATE TABLE batcave.oracle_release_keys_v1 (
 owner_user_id uuid NOT NULL,
 public_key_sha256 text NOT NULL CHECK(public_key_sha256 ~ '^[a-f0-9]{64}$'),
 public_key_b64url text NOT NULL CHECK(public_key_b64url ~ '^[A-Za-z0-9_-]{43}$'),
 host_identity_sha256 text NOT NULL,
 attestation_id uuid NOT NULL REFERENCES batcave.oracle_release_custody_v1(id),
 role text NOT NULL CHECK(role='independent_release_reviewer'),
 registered boolean NOT NULL CHECK(registered),
 independently_attested boolean NOT NULL CHECK(independently_attested),
 release_policy_version text NOT NULL CHECK(release_policy_version='strict_nanny.release.v1'),
 private_key_custodian text NOT NULL CHECK(private_key_custodian='Cortana separate protected reviewer'),
 valid_until timestamptz NOT NULL,
 revoked_at timestamptz,
 production_release_authorized boolean NOT NULL DEFAULT false CHECK(NOT production_release_authorized),
 registered_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(owner_user_id,public_key_sha256)
);
CREATE TABLE batcave.oracle_release_challenges_v1 (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 kind text NOT NULL CHECK(kind IN ('enrollment','release')),
 owner_user_id uuid NOT NULL,
 owner_key_sha256 text NOT NULL CHECK(owner_key_sha256 ~ '^[a-f0-9]{64}$'),
 reviewer_key_sha256 text NOT NULL CHECK(reviewer_key_sha256 ~ '^[a-f0-9]{64}$'),
 attestation_id uuid NOT NULL REFERENCES batcave.oracle_release_custody_v1(id),
 nonce text NOT NULL UNIQUE CHECK(nonce ~ '^[a-f0-9]{32}$'),
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '10 minutes'),
 consumed_at timestamptz,
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),
 canonical_payload text NOT NULL CHECK(length(canonical_payload)<=5000 AND canonical_payload::jsonb=payload),
 payload_sha256 text GENERATED ALWAYS AS (encode(sha256(convert_to(canonical_payload,'UTF8')),'hex')) STORED,
 candidate jsonb,
 CHECK((kind='enrollment' AND candidate IS NOT NULL AND jsonb_typeof(candidate)='object') OR (kind='release' AND candidate IS NULL)),
 CHECK(((payload->>'nonce')=nonce AND (payload->>'owner_user_id')::uuid=owner_user_id AND (payload->>'issued_at')::timestamptz=issued_at AND (payload->>'expires_at')::timestamptz=expires_at) IS TRUE),
 CHECK(kind<>'release' OR payload @> '{"schema":"batcave.oracle.pinned.release.v1","intent_key":"batcave.oracle.lab_v031.release_request.20261121","intent_sha256":"ff41a4a74e25fd31bf9a466d1566100ba9e98cc5d8769fd01fe12c9c653c4e80","owner_gate_zip_sha256":"69ab19be8ec2e11e902716da59c2dda8693a3d3c78a16d8bdc1ded25a8d16851","worker_zip_sha256":"4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2","pr_head_sha":"33b62fae6ccb2224f04cce43443510b71c051297","target_device":"Oracle","operation":"model_generate_and_verify_v1","fixture":"fixed_clamp_score_v1","scope":"disposable_lab_only"}'::jsonb)
);
CREATE TABLE batcave.oracle_release_evidence_v1 (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 challenge_id uuid NOT NULL UNIQUE REFERENCES batcave.oracle_release_challenges_v1(id),
 owner_user_id uuid NOT NULL,
 owner_signature_b64url text NOT NULL CHECK(owner_signature_b64url ~ '^[A-Za-z0-9_-]{86}$'),
 nanny_signature_b64url text,
 recorded_at timestamptz NOT NULL DEFAULT now(),
 deployment_authorized boolean NOT NULL DEFAULT false CHECK(NOT deployment_authorized),
 execution_authorized boolean NOT NULL DEFAULT false CHECK(NOT execution_authorized),
 grant_issued boolean NOT NULL DEFAULT false CHECK(NOT grant_issued),
 CHECK(nanny_signature_b64url IS NULL OR nanny_signature_b64url ~ '^[A-Za-z0-9_-]{86}$')
);
-- Called only AFTER the authenticated gate verifies signatures. Lock and recheck
-- current trust/intent in the same transaction as registration or evidence + consume.
CREATE FUNCTION batcave.oracle_release_finish_v1(p_owner uuid,p_challenge uuid,p_hash text,p_owner_sig text,p_nanny_sig text DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
DECLARE c batcave.oracle_release_challenges_v1%ROWTYPE;
 a batcave.oracle_release_custody_v1%ROWTYPE;
 k batcave.oracle_release_keys_v1%ROWTYPE;
 o record; i record; evidence_id uuid; inserted_count integer; v_now timestamptz;
BEGIN
 SELECT * INTO c FROM batcave.oracle_release_challenges_v1 WHERE id=p_challenge AND owner_user_id=p_owner FOR UPDATE;
 IF NOT FOUND OR c.consumed_at IS NOT NULL OR c.payload_sha256 IS DISTINCT FROM p_hash THEN RETURN jsonb_build_object('inserted',false); END IF;
 SELECT owner_user_id,public_key_sha256,revoked_at INTO o FROM batcave.linux_owner_keys_v1 WHERE owner_user_id=p_owner FOR SHARE;
 IF NOT FOUND OR o.revoked_at IS NOT NULL OR o.public_key_sha256 IS DISTINCT FROM c.owner_key_sha256 THEN RETURN jsonb_build_object('inserted',false); END IF;
 SELECT state,content_sha256,valid_until INTO i FROM batcave.change_gate_intents WHERE intent_key='batcave.oracle.lab_v031.release_request.20261121' FOR SHARE;
 IF NOT FOUND OR i.state<>'held' OR i.content_sha256<>'ff41a4a74e25fd31bf9a466d1566100ba9e98cc5d8769fd01fe12c9c653c4e80' THEN RETURN jsonb_build_object('inserted',false); END IF;
 SELECT * INTO a FROM batcave.oracle_release_custody_v1 WHERE id=c.attestation_id AND owner_user_id=p_owner AND public_key_sha256=c.reviewer_key_sha256 FOR SHARE;
 IF NOT FOUND OR a.revoked_at IS NOT NULL OR NOT a.independently_attested OR a.public_key_sha256=c.owner_key_sha256 OR a.public_key_sha256='4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b' THEN RETURN jsonb_build_object('inserted',false); END IF;
 IF p_owner_sig IS NULL OR p_owner_sig !~ '^[A-Za-z0-9_-]{86}$' THEN RETURN jsonb_build_object('inserted',false); END IF;
 IF c.kind='release' THEN
  SELECT * INTO k FROM batcave.oracle_release_keys_v1 WHERE owner_user_id=p_owner AND public_key_sha256=c.reviewer_key_sha256 FOR SHARE;
  IF NOT FOUND OR k.revoked_at IS NOT NULL OR k.attestation_id<>a.id OR k.host_identity_sha256<>a.host_identity_sha256 OR p_nanny_sig IS NULL OR p_nanny_sig !~ '^[A-Za-z0-9_-]{86}$' THEN RETURN jsonb_build_object('inserted',false); END IF;
 END IF;
 -- Use a new wall clock after any lock waits; transaction start time may be stale.
 v_now:=clock_timestamp();
 IF c.expires_at<=v_now OR c.issued_at>v_now+interval '30 seconds' OR c.issued_at<v_now-interval '10 minutes' OR i.valid_until<=v_now OR a.valid_until<=v_now OR (c.kind='release' AND k.valid_until<=v_now) THEN RETURN jsonb_build_object('inserted',false); END IF;
 IF c.kind='enrollment' THEN
  IF p_nanny_sig IS NOT NULL OR c.payload->>'reviewer_key_sha256'<>a.public_key_sha256 OR c.payload->>'host_identity_sha256'<>a.host_identity_sha256 OR c.payload->>'attestation_id'<>a.id::text OR c.candidate->>'public_key_sha256'<>a.public_key_sha256 THEN RETURN jsonb_build_object('inserted',false); END IF;
  INSERT INTO batcave.oracle_release_keys_v1(owner_user_id,public_key_sha256,public_key_b64url,host_identity_sha256,attestation_id,role,registered,independently_attested,release_policy_version,private_key_custodian,valid_until)
  VALUES(p_owner,a.public_key_sha256,c.candidate->>'public_key_b64url',a.host_identity_sha256,a.id,'independent_release_reviewer',true,true,a.release_policy_version,a.private_key_custodian,a.valid_until)
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_count=ROW_COUNT;
  IF inserted_count<>1 THEN RETURN jsonb_build_object('inserted',false); END IF;
 END IF;
 INSERT INTO batcave.oracle_release_evidence_v1(challenge_id,owner_user_id,owner_signature_b64url,nanny_signature_b64url)
 VALUES(c.id,p_owner,p_owner_sig,p_nanny_sig) RETURNING id INTO evidence_id;
 UPDATE batcave.oracle_release_challenges_v1 SET consumed_at=v_now WHERE id=c.id;
 RETURN jsonb_build_object('inserted',true,'evidence_id',evidence_id);
END;
$$;
ALTER TABLE batcave.oracle_release_custody_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE batcave.oracle_release_keys_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE batcave.oracle_release_challenges_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE batcave.oracle_release_evidence_v1 ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON batcave.oracle_release_custody_v1,batcave.oracle_release_keys_v1,batcave.oracle_release_challenges_v1,batcave.oracle_release_evidence_v1 FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION batcave.oracle_release_finish_v1(uuid,uuid,text,text,text) FROM PUBLIC,anon,authenticated;
-- Existing gate uses a private DB connection. No Data API exposure is added.
-- No grants to a client or service token, no custody seed and no policy promotion.
COMMIT;
