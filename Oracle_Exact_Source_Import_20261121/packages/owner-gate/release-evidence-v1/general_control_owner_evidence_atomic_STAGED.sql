-- STAGED / NOT DEPLOYED. Adds atomic owner-evidence persistence to the
-- existing general_control_nonce_ledger_STAGED.sql; NO grant or dispatch.
-- The calling authenticated server MUST verify the exact owner Ed25519
-- signature, current scope, registered key, and fresh policy before calling.
-- This function does NOT verify cryptographic signatures or grant authority.
CREATE TABLE IF NOT EXISTS batcave.general_control_owner_evidence_staged_v1 (
  request_id uuid PRIMARY KEY REFERENCES batcave.general_control_nonce_ledger_v1(request_id),
  owner_user_id uuid NOT NULL,
  nonce text NOT NULL CHECK(nonce ~ '^[a-f0-9]{32}$'),
  request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
  policy_sha256 text NOT NULL CHECK(policy_sha256 ~ '^[a-f0-9]{64}$'),
  signature_hex text NOT NULL CHECK(signature_hex ~ '^[a-f0-9]{128}$'),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  state text NOT NULL DEFAULT 'owner_signature_recorded_only'
    CHECK(state='owner_signature_recorded_only'),
  UNIQUE(owner_user_id,nonce)
);
REVOKE ALL ON batcave.general_control_owner_evidence_staged_v1 FROM PUBLIC;
CREATE OR REPLACE FUNCTION batcave.general_control_record_owner_evidence_staged_v1(
  p_request_id uuid, p_owner_user_id uuid, p_nonce text,
  p_request_sha256 text, p_policy_sha256 text, p_signature_hex text
) RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
  -- The update and insert are in the SAME PostgreSQL transaction.
  -- If insert fails, the UPDATE is rolled back; no consumed-without-receipt.
  IF p_signature_hex IS NULL OR p_signature_hex !~ '^[a-f0-9]{128}$' THEN
    RETURN false;
  END IF;
  UPDATE batcave.general_control_nonce_ledger_v1
  SET state='consumed',consumed_at=clock_timestamp()
  WHERE request_id=p_request_id AND owner_user_id=p_owner_user_id
    AND nonce=p_nonce AND request_sha256=p_request_sha256
    AND policy_sha256=p_policy_sha256 AND state='unused'
    AND expires_at>clock_timestamp();
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed<>1 THEN RETURN false; END IF;
  INSERT INTO batcave.general_control_owner_evidence_staged_v1
    (request_id,owner_user_id,nonce,request_sha256,policy_sha256,signature_hex)
  VALUES(p_request_id,p_owner_user_id,p_nonce,p_request_sha256,p_policy_sha256,p_signature_hex);
  RETURN true;
END $$;
REVOKE ALL ON FUNCTION batcave.general_control_record_owner_evidence_staged_v1(
  uuid,uuid,text,text,text,text) FROM PUBLIC;
-- Intentionally NO GRANT to anon/authenticated/service_role/device.
-- Never call this from a client or before authenticated signature validation.
