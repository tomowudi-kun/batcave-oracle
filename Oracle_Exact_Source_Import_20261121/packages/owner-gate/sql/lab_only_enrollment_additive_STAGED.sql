-- DRAFT/STAGED ONLY. Additive lab-specific tables and service-role-only atomic writers.
-- Never deploy without existing independent gate review. Does not change existing shadow gate rules.
-- Ed25519 MUST be verified by authenticated owner Edge before these service-role-only RPCs.
BEGIN;
CREATE TABLE batcave.oracle_lab_enroll_challenges_v2 (
 challenge_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 owner_user_id uuid NOT NULL,
 nonce text NOT NULL UNIQUE CHECK (nonce ~ '^[a-f0-9]{32}$'),
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 UNIQUE(owner_user_id,challenge_id),
 CHECK (expires_at>created_at AND expires_at<=created_at+interval '10 minutes')
);
CREATE TABLE batcave.oracle_lab_reviewer_keys_v1 (
 public_key_sha256 text PRIMARY KEY CHECK (public_key_sha256='4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b'),
 public_key_pem text NOT NULL CHECK (char_length(public_key_pem) BETWEEN 100 AND 512),
 public_record jsonb NOT NULL CHECK (jsonb_typeof(public_record)='object'),
 reviewer_sid text NOT NULL DEFAULT 'S-1-5-19' CHECK (reviewer_sid='S-1-5-19'),
 role text NOT NULL DEFAULT 'lab_reviewer_only' CHECK (role='lab_reviewer_only'),
 owner_user_id uuid NOT NULL,
 release_archive_sha256 text NOT NULL CHECK (release_archive_sha256='4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2'),
 fixture_token text NOT NULL CHECK (fixture_token='4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f'),
 challenge_id uuid NOT NULL UNIQUE REFERENCES batcave.oracle_lab_enroll_challenges_v2(challenge_id),
 enrollment_verified_at timestamptz NOT NULL DEFAULT now(),
 enrollment_owner_signature_b64url text NOT NULL CHECK (enrollment_owner_signature_b64url ~ '^[A-Za-z0-9_-]{86}$'),
 enrollment_owner_signature_sha256 text NOT NULL CHECK (enrollment_owner_signature_sha256 ~ '^[a-f0-9]{64}$'),
 revoked_at timestamptz,
 production_release_authorized boolean NOT NULL DEFAULT false CHECK (production_release_authorized=false)
);
CREATE TABLE batcave.oracle_lab_review_grants_v1 (
 job_id uuid PRIMARY KEY REFERENCES batcave.commands(id),
 reviewer_key_sha256 text NOT NULL REFERENCES batcave.oracle_lab_reviewer_keys_v1(public_key_sha256),
 owner_user_id uuid NOT NULL,
 release_archive_sha256 text NOT NULL CHECK (release_archive_sha256='4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2'),
 request_nonce text NOT NULL UNIQUE CHECK (request_nonce ~ '^[a-f0-9]{32}$'),
 request_sha256 text NOT NULL UNIQUE CHECK (request_sha256 ~ '^[a-f0-9]{64}$'),
 raw_request_json text NOT NULL CHECK (char_length(raw_request_json) BETWEEN 100 AND 2048),
 signed_receipt jsonb NOT NULL CHECK (jsonb_typeof(signed_receipt)='object'),
 artifact_sha256 text NOT NULL DEFAULT '4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f'
   CHECK (artifact_sha256='4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f'),
 operation text NOT NULL DEFAULT 'model_generate_and_verify_v1' CHECK (operation='model_generate_and_verify_v1'),
 scope text NOT NULL DEFAULT 'disposable_lab_only' CHECK (scope='disposable_lab_only'),
 fixture text NOT NULL DEFAULT 'fixed_clamp_score_v1' CHECK (fixture='fixed_clamp_score_v1'),
 enrolled_review_verified_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 production_release_authorized boolean NOT NULL DEFAULT false CHECK (production_release_authorized=false),
 CHECK (expires_at>enrolled_review_verified_at AND expires_at<=enrolled_review_verified_at+interval '10 minutes')
);
ALTER TABLE batcave.oracle_lab_enroll_challenges_v2 ENABLE ROW LEVEL SECURITY;
ALTER TABLE batcave.oracle_lab_reviewer_keys_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE batcave.oracle_lab_review_grants_v1 ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON batcave.oracle_lab_enroll_challenges_v2 FROM PUBLIC,anon,authenticated;
REVOKE ALL ON batcave.oracle_lab_reviewer_keys_v1 FROM PUBLIC,anon,authenticated;
REVOKE ALL ON batcave.oracle_lab_review_grants_v1 FROM PUBLIC,anon,authenticated;
GRANT SELECT, INSERT ON batcave.oracle_lab_enroll_challenges_v2 TO service_role;
GRANT SELECT ON batcave.oracle_lab_reviewer_keys_v1 TO service_role;
GRANT SELECT ON batcave.oracle_lab_review_grants_v1 TO service_role;
-- Atomic owner-key enrollment. Security INVOKER, public callable only to service_role.
CREATE OR REPLACE FUNCTION public.batcave_oracle_lab_enroll_verified_v2(
 p_owner_user_id uuid,p_challenge_id uuid,p_nonce text,p_expires_at timestamptz,
 p_public_record jsonb,p_owner_signature_b64url text
) RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $function$
DECLARE v_row record; v_inserted text;
BEGIN
 IF p_owner_user_id IS NULL OR p_challenge_id IS NULL OR p_nonce !~ '^[a-f0-9]{32}$'
 OR p_owner_signature_b64url !~ '^[A-Za-z0-9_-]{86}$'
 OR pg_catalog.jsonb_typeof(p_public_record)<>'object'
 OR (p_public_record->>'role') IS DISTINCT FROM 'lab_reviewer_only'
 OR (p_public_record->>'host') IS DISTINCT FROM 'CORTANA'
 OR (p_public_record->>'reviewer_sid') IS DISTINCT FROM 'S-1-5-19'
 OR (p_public_record->>'public_key_sha256') IS DISTINCT FROM '4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b'
 OR (p_public_record->>'production_release_authorized') IS DISTINCT FROM 'false'
 OR (p_public_record->>'cloud_enrolled') IS DISTINCT FROM 'false' THEN
  RETURN pg_catalog.jsonb_build_object('inserted',false);
 END IF;
 UPDATE batcave.oracle_lab_enroll_challenges_v2
 SET consumed_at=pg_catalog.now()
 WHERE challenge_id=p_challenge_id AND owner_user_id=p_owner_user_id
 AND nonce=p_nonce AND expires_at=p_expires_at AND consumed_at IS NULL AND expires_at>pg_catalog.now()
 RETURNING challenge_id INTO v_row;
 IF NOT FOUND THEN RETURN pg_catalog.jsonb_build_object('inserted',false); END IF;
 INSERT INTO batcave.oracle_lab_reviewer_keys_v1(
 public_key_sha256,public_key_pem,public_record,owner_user_id,release_archive_sha256,
 fixture_token,challenge_id,enrollment_owner_signature_b64url,enrollment_owner_signature_sha256)
 VALUES ('4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b',
 p_public_record->>'public_key_pem',p_public_record,p_owner_user_id,
 '4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2',
 '4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f',
 p_challenge_id,p_owner_signature_b64url,
 encode(extensions.digest(pg_catalog.convert_to(p_owner_signature_b64url,'UTF8'),'sha256'),'hex'))
 ON CONFLICT DO NOTHING RETURNING public_key_sha256 INTO v_inserted;
 IF NOT FOUND THEN RAISE EXCEPTION 'duplicate_enrollment'; END IF;
 RETURN pg_catalog.jsonb_build_object('inserted',true,'lab_only',true,'deployment_authorized',false);
EXCEPTION WHEN OTHERS THEN
 RETURN pg_catalog.jsonb_build_object('inserted',false);
END
$function$;
-- One-time server-verified review grant, still NOT authorization for production releases.
CREATE OR REPLACE FUNCTION public.batcave_oracle_lab_record_verified_v2(
 p_owner_user_id uuid,p_job_id uuid,p_nonce text,p_request_sha256 text,
 p_raw_request_json text,p_signed_receipt jsonb,p_expires_at timestamptz
) RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $function$
DECLARE v_job record; v_key record; v_inserted uuid;
BEGIN
 IF p_owner_user_id IS NULL OR p_job_id IS NULL OR p_nonce !~ '^[a-f0-9]{32}$'
 OR p_request_sha256 !~ '^[a-f0-9]{64}$'
 OR pg_catalog.char_length(p_raw_request_json) NOT BETWEEN 100 AND 2048
 OR encode(extensions.digest(pg_catalog.convert_to(p_raw_request_json,'UTF8'),'sha256'),'hex') IS DISTINCT FROM p_request_sha256
 OR pg_catalog.jsonb_typeof(p_signed_receipt)<>'object'
 OR (p_signed_receipt->'payload'->>'decision') IS DISTINCT FROM 'LAB_ALLOW'
 OR (p_signed_receipt->'payload'->>'request_id') IS DISTINCT FROM p_job_id::text
 OR (p_signed_receipt->'payload'->>'request_sha256') IS DISTINCT FROM p_request_sha256
 OR (p_signed_receipt->'payload'->>'execution_authorized') IS DISTINCT FROM 'false'
 OR (p_signed_receipt->'payload'->>'deployment_authorized') IS DISTINCT FROM 'false'
 OR (p_signed_receipt->'payload'->>'production_release_authorized') IS DISTINCT FROM 'false'
 THEN RETURN pg_catalog.jsonb_build_object('inserted',false); END IF;
 SELECT c.id,c.status,c.attempt_count,c.payload,c.expires_at,d.device_name INTO v_job
 FROM batcave.commands c JOIN batcave.devices d ON d.id=c.device_id
 WHERE c.id=p_job_id FOR UPDATE OF c;
 IF NOT FOUND THEN RETURN pg_catalog.jsonb_build_object('inserted',false); END IF;
 IF v_job.device_name IS DISTINCT FROM 'Oracle' OR v_job.status<>'pending' OR v_job.attempt_count<>0
 OR v_job.expires_at<=pg_catalog.now() OR v_job.expires_at IS DISTINCT FROM p_expires_at
 OR (v_job.payload->>'schema') IS DISTINCT FROM 'batcave.oracle.job.v1'
 OR (v_job.payload->>'operation') IS DISTINCT FROM 'model_generate_and_verify_v1'
 OR (v_job.payload->>'fixture') IS DISTINCT FROM 'fixed_clamp_score_v1'
 OR (v_job.payload->>'artifact_sha256') IS DISTINCT FROM '4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f'
 OR v_job.payload->>'nonce' IS DISTINCT FROM p_nonce
 OR v_job.payload IS DISTINCT FROM pg_catalog.jsonb_build_object(
  'schema','batcave.oracle.job.v1','nonce',p_nonce,
  'operation','model_generate_and_verify_v1','fixture','fixed_clamp_score_v1',
  'artifact_sha256','4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f')
 THEN RETURN pg_catalog.jsonb_build_object('inserted',false); END IF;
 SELECT * INTO v_key FROM batcave.oracle_lab_reviewer_keys_v1
 WHERE public_key_sha256='4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b'
 AND owner_user_id=p_owner_user_id AND revoked_at IS NULL AND role='lab_reviewer_only'
 AND production_release_authorized=false;
 IF NOT FOUND THEN RETURN pg_catalog.jsonb_build_object('inserted',false); END IF;
 INSERT INTO batcave.oracle_lab_review_grants_v1(
 job_id,reviewer_key_sha256,owner_user_id,release_archive_sha256,request_nonce,request_sha256,
 raw_request_json,signed_receipt,expires_at)
 VALUES(p_job_id,v_key.public_key_sha256,p_owner_user_id,v_key.release_archive_sha256,p_nonce,
 p_request_sha256,p_raw_request_json,p_signed_receipt,p_expires_at)
 ON CONFLICT DO NOTHING RETURNING job_id INTO v_inserted;
 IF NOT FOUND THEN RETURN pg_catalog.jsonb_build_object('inserted',false); END IF;
 RETURN pg_catalog.jsonb_build_object('inserted',true,'lab_only',true,'deployment_authorized',false);
EXCEPTION WHEN OTHERS THEN
 RETURN pg_catalog.jsonb_build_object('inserted',false);
END
$function$;
REVOKE EXECUTE ON FUNCTION public.batcave_oracle_lab_enroll_verified_v2(uuid,uuid,text,timestamptz,jsonb,text) FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.batcave_oracle_lab_record_verified_v2(uuid,uuid,text,text,text,jsonb,timestamptz) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.batcave_oracle_lab_enroll_verified_v2(uuid,uuid,text,timestamptz,jsonb,text) TO service_role;
GRANT EXECUTE ON FUNCTION public.batcave_oracle_lab_record_verified_v2(uuid,uuid,text,text,text,jsonb,timestamptz) TO service_role;
-- These functions also need least-privilege table access for SECURITY INVOKER service_role.
GRANT SELECT, UPDATE ON batcave.oracle_lab_enroll_challenges_v2 TO service_role;
GRANT INSERT ON batcave.oracle_lab_reviewer_keys_v1 TO service_role;
GRANT INSERT ON batcave.oracle_lab_review_grants_v1 TO service_role;
COMMIT;
