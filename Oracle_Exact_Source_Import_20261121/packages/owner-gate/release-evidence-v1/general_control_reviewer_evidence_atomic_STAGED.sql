-- STAGED / NOT DEPLOYED. Private atomic reviewer evidence admission only.
-- Apply AFTER general_control_nonce_ledger_STAGED.sql and
-- general_control_owner_evidence_atomic_STAGED.sql in disposable tests.
-- The server MUST verify authenticated independent reviewer, registered
-- independently attested active production key, Ed25519 signature over exact
-- canonical request, owner receipt, fresh policy/session BEFORE this function.
-- Database checks durable equality (including the immutable source pin) and concurrency, NOT cryptographic truth.
CREATE TABLE IF NOT EXISTS batcave.general_control_reviewer_evidence_staged_v1 (
 request_id uuid PRIMARY KEY REFERENCES batcave.general_control_owner_evidence_staged_v1(request_id),
 owner_user_id uuid NOT NULL,
 nonce text NOT NULL CHECK(nonce ~ '^[a-f0-9]{32}$'),
 policy_sha256 text NOT NULL CHECK(policy_sha256 ~ '^[a-f0-9]{64}$'),
 source_commit text NOT NULL CHECK(source_commit ~ '^[a-f0-9]{40}$'),
 reviewer_identity_id uuid NOT NULL,
 reviewer_key_hex text NOT NULL CHECK(reviewer_key_hex ~ '^[a-f0-9]{64}$'),
 signature_hex text NOT NULL CHECK(signature_hex ~ '^[a-f0-9]{128}$'),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 state text NOT NULL DEFAULT 'reviewer_signature_recorded_only'
   CHECK(state='reviewer_signature_recorded_only'),
 execution_authorized boolean NOT NULL DEFAULT false CHECK(execution_authorized=false),
 deployment_authorized boolean NOT NULL DEFAULT false CHECK(deployment_authorized=false),
 CHECK(reviewer_identity_id<>owner_user_id),
 UNIQUE(owner_user_id,nonce)
);
REVOKE ALL ON batcave.general_control_reviewer_evidence_staged_v1 FROM PUBLIC,anon,authenticated;
CREATE OR REPLACE FUNCTION batcave.general_control_append_reviewer_evidence_staged_v1(
 p_request_id uuid,p_owner_user_id uuid,p_nonce text,p_policy_sha256 text,
 p_source_commit text,p_reviewer_identity_id uuid,p_reviewer_key_hex text,p_signature_hex text
) RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE matched integer;
BEGIN
 IF p_reviewer_identity_id IS NULL OR p_reviewer_identity_id=p_owner_user_id
   OR p_reviewer_key_hex IS NULL OR p_reviewer_key_hex !~ '^[a-f0-9]{64}$'
   OR p_signature_hex IS NULL OR p_signature_hex !~ '^[a-f0-9]{128}$'
   OR p_source_commit IS NULL OR p_source_commit !~ '^[a-f0-9]{40}$'
 THEN RETURN false; END IF;
 -- Locks the original consumed nonce row until commit. A duplicate reviewer
 -- cannot race through this check and write two receipts.
 PERFORM 1 FROM batcave.general_control_nonce_ledger_v1 n
 JOIN batcave.general_control_owner_evidence_staged_v1 o
   ON o.request_id=n.request_id AND o.owner_user_id=n.owner_user_id
   AND o.nonce=n.nonce AND o.policy_sha256=n.policy_sha256
 JOIN batcave.general_control_prepared_challenges_staged_v1 p
   ON p.request_id=n.request_id AND p.owner_user_id=n.owner_user_id
   AND p.nonce=n.nonce AND p.request_sha256=n.request_sha256
   AND p.policy_sha256=n.policy_sha256
 WHERE n.request_id=p_request_id AND n.owner_user_id=p_owner_user_id
   AND n.nonce=p_nonce AND n.policy_sha256=p_policy_sha256
   AND p.request_json->>'source_commit'=p_source_commit
   AND p.request_json->>'policy_digest'=p_policy_sha256
   AND n.state='consumed' AND o.state='owner_signature_recorded_only'
 FOR UPDATE OF n;
 GET DIAGNOSTICS matched=ROW_COUNT;
 IF matched<>1 THEN RETURN false; END IF;
 INSERT INTO batcave.general_control_reviewer_evidence_staged_v1(
   request_id,owner_user_id,nonce,policy_sha256,source_commit,
   reviewer_identity_id,reviewer_key_hex,signature_hex
 ) VALUES(p_request_id,p_owner_user_id,p_nonce,p_policy_sha256,p_source_commit,
   p_reviewer_identity_id,p_reviewer_key_hex,p_signature_hex)
 ON CONFLICT (request_id) DO NOTHING;
 GET DIAGNOSTICS matched=ROW_COUNT;
 RETURN matched=1;
END $$;
REVOKE ALL ON FUNCTION batcave.general_control_append_reviewer_evidence_staged_v1(
 uuid,uuid,text,text,text,uuid,text,text) FROM PUBLIC,anon,authenticated;
-- No grant to service_role/device/client; no release, lease or execution.
