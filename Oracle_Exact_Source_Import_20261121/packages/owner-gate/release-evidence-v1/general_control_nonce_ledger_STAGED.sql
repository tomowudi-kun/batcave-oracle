-- STAGED ONLY: isolated nonce reservation / consumption boundary.
-- No GRANT, deployment, job dispatch, or signature verification.
-- Caller MUST first verify authenticated owner and both real role-separated
-- Ed25519 signatures against the exact canonical request and current policy.
-- This SQL does not establish that verification and MUST NOT be exposed as RPC.
CREATE SCHEMA IF NOT EXISTS batcave;
CREATE TABLE IF NOT EXISTS batcave.general_control_nonce_ledger_v1 (
  request_id uuid PRIMARY KEY,
  owner_user_id uuid NOT NULL,
  nonce text NOT NULL CHECK(nonce ~ '^[a-f0-9]{32}$'),
  request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
  policy_sha256 text NOT NULL CHECK(policy_sha256 ~ '^[a-f0-9]{64}$'),
  expires_at timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'unused' CHECK(state IN ('unused','consumed','declined')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  consumed_at timestamptz,
  UNIQUE(owner_user_id,nonce),
  CHECK ((state='consumed')=(consumed_at IS NOT NULL))
);
REVOKE ALL ON batcave.general_control_nonce_ledger_v1 FROM PUBLIC;
-- The only transition permitted after creation is unused -> consumed/declined.
-- A successful consume returns a one-time receipt, not an execution grant.
CREATE OR REPLACE FUNCTION batcave.general_control_consume_nonce_staged_v1(
  p_request_id uuid,p_owner_user_id uuid,p_nonce text,
  p_request_sha256 text,p_policy_sha256 text
) RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE updated integer;
BEGIN
  UPDATE batcave.general_control_nonce_ledger_v1
  SET state='consumed',consumed_at=clock_timestamp()
  WHERE request_id=p_request_id AND owner_user_id=p_owner_user_id
    AND nonce=p_nonce AND request_sha256=p_request_sha256
    AND policy_sha256=p_policy_sha256 AND state='unused'
    AND expires_at>clock_timestamp();
  GET DIAGNOSTICS updated=ROW_COUNT;
  RETURN updated=1;
END $$;
CREATE OR REPLACE FUNCTION batcave.general_control_decline_nonce_staged_v1(
  p_request_id uuid,p_owner_user_id uuid,p_nonce text
) RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE updated integer;
BEGIN
  UPDATE batcave.general_control_nonce_ledger_v1 SET state='declined'
  WHERE request_id=p_request_id AND owner_user_id=p_owner_user_id
    AND nonce=p_nonce AND state='unused' AND expires_at>clock_timestamp();
  GET DIAGNOSTICS updated=ROW_COUNT;
  RETURN updated=1;
END $$;
REVOKE ALL ON FUNCTION batcave.general_control_consume_nonce_staged_v1(uuid,uuid,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION batcave.general_control_decline_nonce_staged_v1(uuid,uuid,text) FROM PUBLIC;
-- Do not GRANT EXECUTE to anon, authenticated, service_role, or a device.
-- No production SQL application is authorized by this staged file.
