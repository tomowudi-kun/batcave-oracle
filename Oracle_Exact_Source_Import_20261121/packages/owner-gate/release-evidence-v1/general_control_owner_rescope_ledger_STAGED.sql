-- STAGED / NOT DEPLOYED. Owner-root re-scope is separate from grants.
-- Backend MUST verify registered owner root, the explicit domain-separated
-- Ed25519 signature, current source/policy, and authenticated original origin
-- BEFORE calling the private atomic record function.
-- This SQL does NOT verify cryptography, activate a key, issue a grant or
-- change the existing fixed lab enrollment, releases or change-gate rules.
CREATE TABLE IF NOT EXISTS batcave.general_control_owner_rescope_challenges_staged_v1 (
 challenge_id uuid PRIMARY KEY,
 owner_user_id uuid NOT NULL,
 nonce text NOT NULL CHECK(nonce ~ '^[a-f0-9]{32}$'),
 root_key_sha256 text NOT NULL CHECK(root_key_sha256 ~ '^[a-f0-9]{64}$'),
 scope_public_key_hex text NOT NULL CHECK(scope_public_key_hex ~ '^[a-f0-9]{64}$'),
 source_commit text NOT NULL CHECK(source_commit ~ '^[a-f0-9]{40}$'),
 policy_digest text NOT NULL CHECK(policy_digest ~ '^[a-f0-9]{64}$'),
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),
 state text NOT NULL DEFAULT 'unused' CHECK(state IN ('unused','endorsed','declined')),
 recorded_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(owner_user_id,nonce),
 CHECK ((state='endorsed')=(recorded_at IS NOT NULL)),
 CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'),
 CHECK (payload->>'schema'='batcave.general_control.owner_rescope_challenge.v1'),
 CHECK (payload->>'owner_user_id'=owner_user_id::text),
 CHECK (payload->>'challenge_id'=challenge_id::text),
 CHECK (payload->>'nonce'=nonce),
 CHECK (payload->>'root_key_sha256'=root_key_sha256),
 CHECK (payload->>'scope_public_key_hex'=scope_public_key_hex),
 CHECK (payload->>'source_commit'=source_commit),
 CHECK (payload->>'policy_digest'=policy_digest),
 CHECK ((payload->>'expires_at')::timestamptz=expires_at),
 CHECK ((payload->>'issued_at')::timestamptz=issued_at),
 CHECK (payload->>'execution_authorized'='false'),
 CHECK (payload->>'deployment_authorized'='false')
);
CREATE TABLE IF NOT EXISTS batcave.general_control_owner_scope_pending_staged_v1 (
 owner_user_id uuid PRIMARY KEY,
 challenge_id uuid UNIQUE NOT NULL REFERENCES
   batcave.general_control_owner_rescope_challenges_staged_v1(challenge_id),
 root_key_sha256 text NOT NULL CHECK(root_key_sha256 ~ '^[a-f0-9]{64}$'),
 key_hex text NOT NULL CHECK(key_hex ~ '^[a-f0-9]{64}$'),
 source_commit text NOT NULL CHECK(source_commit ~ '^[a-f0-9]{40}$'),
 policy_digest text NOT NULL CHECK(policy_digest ~ '^[a-f0-9]{64}$'),
 signature_hex text NOT NULL CHECK(signature_hex ~ '^[a-f0-9]{128}$'),
 state text NOT NULL DEFAULT 'pending_independent_review'
    CHECK (state='pending_independent_review'),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 execution_authorized boolean NOT NULL DEFAULT false CHECK (execution_authorized=false),
 deployment_authorized boolean NOT NULL DEFAULT false CHECK (deployment_authorized=false)
);
REVOKE ALL ON batcave.general_control_owner_rescope_challenges_staged_v1
 FROM PUBLIC,anon,authenticated;
REVOKE ALL ON batcave.general_control_owner_scope_pending_staged_v1
 FROM PUBLIC,anon,authenticated;
CREATE OR REPLACE FUNCTION batcave.general_control_record_root_rescope_staged_v1(
 p_owner uuid,p_challenge uuid,p_nonce text,p_root_sha text,
 p_key_hex text,p_source_commit text,p_policy_digest text,p_signature text
) RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
 IF p_signature IS NULL OR p_signature !~ '^[a-f0-9]{128}$'
 THEN RETURN false; END IF;
 UPDATE batcave.general_control_owner_rescope_challenges_staged_v1
 SET state='endorsed',recorded_at=clock_timestamp()
 WHERE owner_user_id=p_owner AND challenge_id=p_challenge
   AND nonce=p_nonce AND root_key_sha256=p_root_sha
   AND scope_public_key_hex=p_key_hex AND source_commit=p_source_commit
   AND policy_digest=p_policy_digest AND state='unused'
   AND expires_at>clock_timestamp();
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>1 THEN RETURN false; END IF;
 -- The INSERT and UPDATE are atomic: on duplicate, integrity violation or
 -- transaction error the nonce consumption is rolled back automatically.
 INSERT INTO batcave.general_control_owner_scope_pending_staged_v1(
  owner_user_id,challenge_id,root_key_sha256,key_hex,source_commit,
  policy_digest,signature_hex
 ) VALUES(p_owner,p_challenge,p_root_sha,p_key_hex,p_source_commit,
  p_policy_digest,p_signature);
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION batcave.general_control_record_root_rescope_staged_v1(
 uuid,uuid,text,text,text,text,text,text) FROM PUBLIC,anon,authenticated;
-- No function grants to service_role or devices. No active-key table.
-- Never deploy a general-control runtime on this pending evidence alone.
