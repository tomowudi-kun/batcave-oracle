-- STAGED / DO NOT APPLY TO PRODUCTION.
-- Depends on general_control_nonce_ledger_STAGED.sql. This creates a private,
-- immutable prepared-request record and atomic nonce reservation for the
-- authenticated server-side owner Yes/No protocol. It never verifies signatures,
-- enrolls keys, issues grants, leases jobs, dispatches commands or changes gates.
CREATE TABLE IF NOT EXISTS batcave.general_control_prepared_challenges_staged_v1 (
 request_id uuid PRIMARY KEY REFERENCES batcave.general_control_nonce_ledger_v1(request_id),
 owner_user_id uuid NOT NULL,
 nonce text NOT NULL CHECK(nonce ~ '^[a-f0-9]{32}$'),
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 policy_sha256 text NOT NULL CHECK(policy_sha256 ~ '^[a-f0-9]{64}$'),
 expires_at timestamptz NOT NULL,
 request_json jsonb NOT NULL CHECK(jsonb_typeof(request_json)='object'),
 scope_json jsonb NOT NULL CHECK(jsonb_typeof(scope_json)='object'),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(owner_user_id,nonce),
 CHECK (request_json->>'owner_user_id'=owner_user_id::text),
 CHECK (request_json->>'request_id'=request_id::text),
 CHECK (request_json->>'nonce'=nonce),
 CHECK (request_json->>'policy_digest'=policy_sha256),
 CHECK ((request_json->>'expires_at')::timestamptz=expires_at),
 CHECK (request_json->>'schema'='batcave.general_control.owner_request.v1')
);
REVOKE ALL ON batcave.general_control_prepared_challenges_staged_v1 FROM PUBLIC, anon, authenticated;
-- Prevent ordinary concurrent sessions for the SAME owner from preparing
-- multiple active challenges. Serializes only on the owner ID, never on
-- a requester-controlled policy name. Expired unused records are historical
-- and do not prevent future challenges.
CREATE OR REPLACE FUNCTION batcave.general_control_reserve_prepared_staged_v1(
 p_owner_user_id uuid, p_request_id uuid, p_nonce text,
 p_request_sha256 text, p_policy_sha256 text, p_expires_at timestamptz,
 p_request_json jsonb, p_scope_json jsonb
) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF p_request_json IS NULL OR jsonb_typeof(p_request_json)<>'object'
    OR p_scope_json IS NULL OR jsonb_typeof(p_scope_json)<>'object'
    OR p_nonce IS NULL OR p_nonce !~ '^[a-f0-9]{32}$'
    OR p_request_sha256 IS NULL OR p_request_sha256 !~ '^[a-f0-9]{64}$'
    OR p_policy_sha256 IS NULL OR p_policy_sha256 !~ '^[a-f0-9]{64}$'
    OR p_request_json->>'schema'<>'batcave.general_control.owner_request.v1'
    OR p_request_json->>'owner_user_id' IS DISTINCT FROM p_owner_user_id::text
    OR p_request_json->>'request_id' IS DISTINCT FROM p_request_id::text
    OR p_request_json->>'nonce' IS DISTINCT FROM p_nonce
    OR p_request_json->>'policy_digest' IS DISTINCT FROM p_policy_sha256
    OR (p_request_json->>'expires_at')::timestamptz IS DISTINCT FROM p_expires_at
    OR p_expires_at<=clock_timestamp()
    OR p_expires_at>clock_timestamp()+interval '5 minutes'
 THEN
  RETURN jsonb_build_object('inserted',false);
 END IF;
 PERFORM pg_catalog.pg_advisory_xact_lock(
   pg_catalog.hashtextextended(p_owner_user_id::text, 90511));
 IF EXISTS (
   SELECT 1 FROM batcave.general_control_nonce_ledger_v1
   WHERE owner_user_id=p_owner_user_id AND state='unused'
     AND expires_at>clock_timestamp()
 ) THEN
   RETURN jsonb_build_object('inserted',false);
 END IF;
 INSERT INTO batcave.general_control_nonce_ledger_v1(
   request_id,owner_user_id,nonce,request_sha256,policy_sha256,expires_at)
 VALUES(p_request_id,p_owner_user_id,p_nonce,p_request_sha256,p_policy_sha256,p_expires_at);
 INSERT INTO batcave.general_control_prepared_challenges_staged_v1(
   request_id,owner_user_id,nonce,request_sha256,policy_sha256,expires_at,request_json,scope_json)
 VALUES(p_request_id,p_owner_user_id,p_nonce,p_request_sha256,p_policy_sha256,
   p_expires_at,p_request_json,p_scope_json);
 RETURN jsonb_build_object(
   'inserted',true,'request_id',p_request_id,'nonce',p_nonce,
   'request_sha256',p_request_sha256,'nonce_state','unused');
END $$;
REVOKE ALL ON FUNCTION batcave.general_control_reserve_prepared_staged_v1(
 uuid,uuid,text,text,text,timestamptz,jsonb,jsonb)
 FROM PUBLIC,anon,authenticated;
-- This function is private and invoker-only. It must never be exposed as RPC
-- or called before the authenticated owner/policy scope validator has run.
