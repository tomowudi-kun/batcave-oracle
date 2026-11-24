-- STAGED / NOT DEPLOYED: independent privileged source/scope release
-- SIGNATURE RECEIPT ONLY. Requires prior owner + reviewer evidence migrations.
-- Absolutely no authority/grants/leases/command dispatch is present here.
-- Server MUST authenticate independently attested qualified reviewer and
-- cryptographically verify the purpose-separated Ed25519 signature first.
-- SECURITY INVOKER function never asserts cryptographic truth on its own.
CREATE TABLE IF NOT EXISTS batcave.general_control_privileged_release_review_staged_v1 (
 request_id uuid PRIMARY KEY REFERENCES batcave.general_control_reviewer_evidence_staged_v1(request_id),
 owner_user_id uuid NOT NULL,
 nonce text NOT NULL UNIQUE CHECK(nonce ~ '^[a-f0-9]{32}$'),
 reviewer_identity_id uuid NOT NULL,
 reviewer_key_hex text NOT NULL CHECK(reviewer_key_hex ~ '^[a-f0-9]{64}$'),
 source_commit text NOT NULL CHECK(source_commit ~ '^[a-f0-9]{40}$'),
 policy_sha256 text NOT NULL CHECK(policy_sha256 ~ '^[a-f0-9]{64}$'),
 intent_key text NOT NULL CHECK(intent_key='batcave.general_control.pr3.owner_release_request.v1.' || source_commit),
 intent_sha256 text NOT NULL CHECK(intent_sha256 ~ '^[a-f0-9]{64}$'),
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 signing_sha256 text NOT NULL CHECK(signing_sha256 ~ '^[a-f0-9]{64}$'),
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 state text NOT NULL DEFAULT 'unused' CHECK(state IN ('unused','recorded')),
 signature_hex text CHECK(signature_hex ~ '^[a-f0-9]{128}$'),
 recorded_at timestamptz,
 execution_authorized boolean NOT NULL DEFAULT false CHECK(execution_authorized=false),
 deployment_authorized boolean NOT NULL DEFAULT false CHECK(deployment_authorized=false),
 grant_issued boolean NOT NULL DEFAULT false CHECK(grant_issued=false),
 CHECK(owner_user_id<>reviewer_identity_id),
 CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '3 minutes'),
 CHECK((state='recorded')=(signature_hex IS NOT NULL AND recorded_at IS NOT NULL)),
 CHECK((payload->>'schema')='batcave.general_control.privileged_release_review.v1'),
 CHECK((payload->>'request_id')=request_id::text),
 CHECK((payload->>'owner_user_id')=owner_user_id::text),
 CHECK((payload->>'reviewer_identity_id')=reviewer_identity_id::text),
 CHECK((payload->>'nonce')=nonce),
 CHECK((payload->>'reviewer_key_hex')=reviewer_key_hex),
 CHECK((payload->>'source_commit')=source_commit),
 CHECK((payload->>'policy_digest')=policy_sha256),
 CHECK((payload->>'intent_key')=intent_key),
 CHECK((payload->>'intent_sha256')=intent_sha256),
 CHECK((payload->>'request_sha256')=request_sha256),
 CHECK((payload->>'issued_at')::timestamptz=issued_at),
 CHECK((payload->>'expires_at')::timestamptz=expires_at),
 CHECK((payload->>'execution_authorized')='false'),
 CHECK((payload->>'deployment_authorized')='false')
);
ALTER TABLE batcave.general_control_privileged_release_review_staged_v1 ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON batcave.general_control_privileged_release_review_staged_v1 FROM PUBLIC,anon,authenticated;
CREATE OR REPLACE FUNCTION batcave.general_control_record_privileged_release_staged_v1(
 p_request_id uuid,p_nonce text,p_reviewer_identity_id uuid,p_reviewer_key_hex text,
 p_source_commit text,p_policy_digest text,p_intent_sha256 text,
 p_request_sha256 text,p_signing_sha256 text,p_signature_hex text
) RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
 IF p_signature_hex IS NULL OR p_signature_hex !~ '^[a-f0-9]{128}$'
    OR p_nonce IS NULL OR p_nonce !~ '^[a-f0-9]{32}$'
    OR p_signing_sha256 IS NULL OR p_signing_sha256 !~ '^[a-f0-9]{64}$'
 THEN RETURN false; END IF;
 UPDATE batcave.general_control_privileged_release_review_staged_v1 s
 SET state='recorded',signature_hex=p_signature_hex,recorded_at=clock_timestamp()
 WHERE s.request_id=p_request_id AND s.nonce=p_nonce
   AND s.reviewer_identity_id=p_reviewer_identity_id AND s.reviewer_key_hex=p_reviewer_key_hex
   AND s.source_commit=p_source_commit AND s.policy_sha256=p_policy_digest
   AND s.intent_sha256=p_intent_sha256 AND s.request_sha256=p_request_sha256
   AND s.signing_sha256=p_signing_sha256 AND s.state='unused'
   AND s.expires_at>clock_timestamp()
   AND EXISTS (
     SELECT 1 FROM batcave.general_control_reviewer_evidence_staged_v1 r
     JOIN batcave.general_control_owner_evidence_staged_v1 o
       ON o.request_id=r.request_id AND o.owner_user_id=r.owner_user_id
       AND o.nonce=r.nonce AND o.policy_sha256=r.policy_sha256
     JOIN batcave.general_control_prepared_challenges_staged_v1 p
       ON p.request_id=r.request_id AND p.owner_user_id=r.owner_user_id
       AND p.nonce=r.nonce AND p.policy_sha256=r.policy_sha256
     JOIN batcave.change_gate_intents i ON i.intent_key=s.intent_key
     WHERE r.request_id=s.request_id AND r.owner_user_id=s.owner_user_id
       AND r.reviewer_identity_id=s.reviewer_identity_id
       AND r.reviewer_key_hex=s.reviewer_key_hex
       AND r.source_commit=s.source_commit AND r.policy_sha256=s.policy_sha256
       AND r.state='reviewer_signature_recorded_only'
       AND o.state='owner_signature_recorded_only'
       AND p.request_sha256=s.request_sha256
       AND p.request_json->>'source_commit'=s.source_commit
       AND p.request_json->>'policy_digest'=s.policy_sha256
       AND i.state='held' AND i.content_sha256=s.intent_sha256
       AND i.valid_until>clock_timestamp()
       AND i.requested_scope->>'source_commit'=s.source_commit
       AND i.requested_scope->>'policy_digest'=s.policy_sha256
       AND i.requested_scope->>'device'=p.request_json->>'device'
       AND i.requested_scope->>'capability'=p.request_json->>'capability'
       AND i.requested_scope->>'target_session_id'=p.request_json->>'target_session_id'
   );
 GET DIAGNOSTICS changed=ROW_COUNT;
 RETURN changed=1;
END $$;
REVOKE ALL ON FUNCTION batcave.general_control_record_privileged_release_staged_v1(
 uuid,text,uuid,text,text,text,text,text,text,text) FROM PUBLIC,anon,authenticated;
-- No GRANT to service_role or a device. Do not modify existing release intent,
-- signer enrollment, change-gate mode, or any task executor as part of staging.
