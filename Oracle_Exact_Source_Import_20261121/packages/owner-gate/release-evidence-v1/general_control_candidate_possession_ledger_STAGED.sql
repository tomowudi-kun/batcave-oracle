-- STAGED ONLY: private, non-authorizing reviewer candidate PoP ledger.
-- Signature MUST be verified by protected server handler before calling
-- the atomic recording function. NO reviewer key registration/attestation.
CREATE TABLE IF NOT EXISTS batcave.general_control_reviewer_possession_staged_v1 (
 request_id uuid PRIMARY KEY,
 draft_id uuid NOT NULL REFERENCES batcave.oracle_instruction_drafts_v1(id),
 owner_user_id uuid NOT NULL,
 candidate_key_sha256 text NOT NULL CHECK(candidate_key_sha256~'^[a-f0-9]{64}$'),
 candidate_public_b64url text NOT NULL CHECK(candidate_public_b64url~'^[A-Za-z0-9_-]{43}$'),
 nonce text NOT NULL UNIQUE CHECK(nonce~'^[a-f0-9]{32}$'),
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),
 signing_sha256 text NOT NULL CHECK(signing_sha256~'^[a-f0-9]{64}$'),
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 state text NOT NULL DEFAULT 'unused'
   CHECK(state IN ('unused','candidate_possession_recorded_only')),
 signature_hex text CHECK(signature_hex~'^[a-f0-9]{128}$'),
 recorded_at timestamptz,
 independently_attested boolean NOT NULL DEFAULT false CHECK(NOT independently_attested),
 registered boolean NOT NULL DEFAULT false CHECK(NOT registered),
 production_release_authorized boolean NOT NULL DEFAULT false CHECK(NOT production_release_authorized),
 execution_authorized boolean NOT NULL DEFAULT false CHECK(NOT execution_authorized),
 deployment_authorized boolean NOT NULL DEFAULT false CHECK(NOT deployment_authorized),
 grant_issued boolean NOT NULL DEFAULT false CHECK(NOT grant_issued),
 CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '5 minutes'),
 CHECK((state='candidate_possession_recorded_only')=(signature_hex IS NOT NULL AND recorded_at IS NOT NULL)),
 CHECK((payload->>'schema')='batcave.general_control.reviewer_possession_challenge.v1'),
 CHECK((payload->>'purpose')='candidate_key_possession_only'),
 CHECK((payload->>'request_id')=request_id::text),
 CHECK((payload->>'draft_id')=draft_id::text),
 CHECK((payload->>'owner_user_id')=owner_user_id::text),
 CHECK((payload->>'candidate_key_sha256')=candidate_key_sha256),
 CHECK((payload->>'candidate_public_b64url')=candidate_public_b64url),
 CHECK((payload->>'nonce')=nonce),
 CHECK((payload->>'issued_at')::timestamptz=issued_at),
 CHECK((payload->>'expires_at')::timestamptz=expires_at),
 CHECK((payload->>'execution_authorized')='false'),
 CHECK((payload->>'deployment_authorized')='false'),
 CHECK((payload->>'grant_issued')='false')
);
ALTER TABLE batcave.general_control_reviewer_possession_staged_v1 ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON batcave.general_control_reviewer_possession_staged_v1 FROM PUBLIC,anon,authenticated;
-- SECURITY INVOKER: requires a PRIVATE database session with direct table permission.
-- Function alone cannot prove signature; server MUST Ed25519-verify first.
CREATE OR REPLACE FUNCTION batcave.general_control_record_candidate_possession_staged_v1(
 p_request_id uuid,p_draft_id uuid,p_owner_user_id uuid,p_nonce text,
 p_candidate_key_sha256 text,p_signing_sha256 text,p_signature_hex text
) RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
 IF p_nonce IS NULL OR p_nonce!~'^[a-f0-9]{32}$' OR
    p_candidate_key_sha256 IS NULL OR p_candidate_key_sha256!~'^[a-f0-9]{64}$' OR
    p_signing_sha256 IS NULL OR p_signing_sha256!~'^[a-f0-9]{64}$' OR
    p_signature_hex IS NULL OR p_signature_hex!~'^[a-f0-9]{128}$'
 THEN RETURN false; END IF;
 UPDATE batcave.general_control_reviewer_possession_staged_v1 p
 SET state='candidate_possession_recorded_only',
     signature_hex=p_signature_hex,recorded_at=clock_timestamp()
 WHERE p.request_id=p_request_id AND p.draft_id=p_draft_id
   AND p.owner_user_id=p_owner_user_id AND p.nonce=p_nonce
   AND p.candidate_key_sha256=p_candidate_key_sha256
   AND p.signing_sha256=p_signing_sha256 AND p.state='unused'
   AND p.expires_at>clock_timestamp() AND p.issued_at<=clock_timestamp()+interval '30 seconds'
   AND EXISTS (
    SELECT 1 FROM batcave.oracle_instruction_drafts_v1 d
    WHERE d.id=p.draft_id AND d.owner_user_id=p.owner_user_id
      AND d.state='draft' AND d.execution_authorized=false
      AND d.interpreted_intent->>'kind'='general_control_public_reviewer_candidate_v1'
      AND d.interpreted_intent->>'public_key_sha256_raw'=p.candidate_key_sha256
      AND d.interpreted_intent->>'public_key_b64url_raw'=p.candidate_public_b64url
      AND d.interpreted_intent->>'registered'='false'
      AND d.interpreted_intent->>'independently_attested'='false'
   );
 GET DIAGNOSTICS changed=ROW_COUNT;
 RETURN changed=1;
END $$;
REVOKE ALL ON FUNCTION batcave.general_control_record_candidate_possession_staged_v1(
 uuid,uuid,uuid,text,text,text,text) FROM PUBLIC,anon,authenticated;
-- Do NOT expose this table/function through REST, a device credential,
-- or a same-user owner UI that could impersonate an independent reviewer.
-- No key enrollment, privilege grant, production release or command execution.
