-- STAGED ONLY: change the EXISTING, Oracle-only private RPC after independent review.
-- Rollback: restore preceding pg_get_functiondef backup (required BEFORE applying).
-- Existing name/signature/SECURITY DEFINER/search_path/grants remain unchanged.
-- Access restricted to existing service_role by current deployment; verify grants on staging and after release.
CREATE OR REPLACE FUNCTION public.batcave_oracle_bridge_v1(
    p_token_hash text, p_op text, p_command_id uuid DEFAULT NULL::uuid,
    p_nonce text DEFAULT NULL::text, p_result jsonb DEFAULT NULL::jsonb
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO ''
AS $function$
DECLARE
 v_device uuid;
 v_job record;
 v_now timestamptz := pg_catalog.now();
BEGIN
 IF p_token_hash IS NULL OR p_token_hash !~ '^[a-f0-9]{64}$' THEN
   RETURN pg_catalog.jsonb_build_object('ok',false,'http_status',401);
 END IF;
 SELECT d.id INTO v_device
 FROM public.batcave_device_credentials cred
 JOIN batcave.devices d ON cred.device_id=d.id
 WHERE cred.token_hash=p_token_hash
   AND cred.revoked_at IS NULL
   AND d.state='active' AND d.device_name='Oracle'
 LIMIT 1;
 IF v_device IS NULL THEN
   RETURN pg_catalog.jsonb_build_object('ok',false,'http_status',401);
 END IF;
 UPDATE batcave.devices SET last_seen_at=v_now WHERE id=v_device;
 IF p_op='capabilities' THEN
   RETURN pg_catalog.jsonb_build_object('ok',true,'scope','oracle_runtime_inventory_v1','capabilities',pg_catalog.jsonb_build_array('runtime_inventory','disposable_project_build_v1','model_generate_and_verify_v1'));
 ELSIF p_op='status' THEN
   RETURN pg_catalog.jsonb_build_object('ok',true,'scope','oracle_runtime_inventory_v1','device','Oracle','ready',true);
 ELSIF p_op IN ('poll','poll_build','poll_model') THEN
   -- Model jobs are allowed ONLY after a separately verified Cortana lab grant.
   -- A model grant is single-use. On ambiguous/failed execution it requires
   -- a NEW independently signed review; the model job is never automatically re-leased.
   WITH picked AS MATERIALIZED (
     SELECT c.id
     FROM batcave.commands c
     WHERE c.device_id=v_device
       AND c.payload->>'schema'='batcave.oracle.job.v1'
       AND c.payload->>'nonce' ~ '^[a-f0-9]{32}$'
       AND c.expires_at>v_now
       AND (
         (c.action='oracle_runtime_inventory_v1'
           AND c.payload->>'operation'='runtime_inventory')
         OR (p_op IN ('poll_build','poll_model')
           AND c.action='oracle_disposable_build_v1'
           AND c.payload->>'operation'='disposable_project_build_v1')
         OR (p_op='poll_model'
           AND c.action='oracle_model_generate_v1'
           AND c.payload->>'operation'='model_generate_and_verify_v1'
           AND c.payload->>'fixture'='fixed_clamp_score_v1'
           AND c.payload->>'artifact_sha256'='4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f'
           AND EXISTS (
             SELECT 1 FROM batcave.oracle_lab_review_grants_v1 g
             JOIN batcave.oracle_lab_reviewer_keys_v1 k
               ON k.public_key_sha256=g.reviewer_key_sha256
             WHERE g.job_id=c.id
               AND g.request_nonce=c.payload->>'nonce'
               AND g.reviewer_key_sha256='4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b'
               AND k.revoked_at IS NULL
               AND k.role='lab_reviewer_only'
               AND g.operation='model_generate_and_verify_v1'
               AND g.scope='disposable_lab_only'
               AND g.fixture='fixed_clamp_score_v1'
               AND g.artifact_sha256=c.payload->>'artifact_sha256'
               AND g.expires_at>=c.expires_at
               AND g.expires_at>v_now
               AND g.consumed_at IS NULL
               AND g.signed_receipt->'payload'->>'decision'='LAB_ALLOW'
               AND g.signed_receipt->'payload'->>'request_id'=c.id::text
               AND g.signed_receipt->'payload'->>'request_sha256'=g.request_sha256
               AND g.signed_receipt->'payload'->>'execution_authorized'='false'
               AND g.signed_receipt->'payload'->>'deployment_authorized'='false'
               AND g.production_release_authorized=false
           ))
       )
       AND (
         (c.action<>'oracle_model_generate_v1' AND (
            c.status='pending' OR
            (c.status='leased' AND c.lease_until<v_now AND c.attempt_count<3)
         ))
         OR (c.action='oracle_model_generate_v1' AND c.status='pending'
             AND c.attempt_count=0)
       )
     ORDER BY c.created_at ASC LIMIT 1 FOR UPDATE OF c SKIP LOCKED
   ),
   consumed_model_grant AS (
     UPDATE batcave.oracle_lab_review_grants_v1 g
     SET consumed_at=v_now
     FROM picked p,batcave.commands c
     WHERE c.id=p.id AND c.action='oracle_model_generate_v1'
       AND g.job_id=c.id AND g.consumed_at IS NULL
       AND g.request_nonce=c.payload->>'nonce'
       AND g.expires_at>v_now
     RETURNING g.job_id
   )
   UPDATE batcave.commands c
   SET status='leased',
     lease_until=v_now+pg_catalog.make_interval(mins=>CASE
        WHEN c.action='oracle_model_generate_v1' THEN 8 ELSE 3 END),
     attempt_count=attempt_count+1
   FROM picked p WHERE c.id=p.id
     AND (c.action<>'oracle_model_generate_v1' OR EXISTS (
       SELECT 1 FROM consumed_model_grant g WHERE g.job_id=c.id
     ))
   RETURNING c.id,c.payload,c.expires_at INTO v_job;
   IF NOT FOUND THEN
     RETURN pg_catalog.jsonb_build_object('ok',true,'scope','oracle_runtime_inventory_v1','pending',false);
   END IF;
   INSERT INTO batcave.command_events(command_id,event_type,details)
   VALUES(v_job.id,
       CASE WHEN v_job.payload->>'operation'='model_generate_and_verify_v1' THEN 'oracle_model_lease'
            WHEN v_job.payload->>'operation'='disposable_project_build_v1' THEN 'oracle_build_lease'
            ELSE 'oracle_inventory_lease' END,
       pg_catalog.jsonb_build_object('device','Oracle'));
   RETURN pg_catalog.jsonb_build_object(
     'ok',true,'scope','oracle_runtime_inventory_v1','pending',true,
     'job',pg_catalog.jsonb_build_object(
       'id',v_job.id,'nonce',v_job.payload->>'nonce',
       'operation',v_job.payload->>'operation','expires_at',v_job.expires_at));
 ELSIF p_op='receipt' THEN
   IF p_command_id IS NULL OR p_nonce IS NULL
      OR p_nonce !~ '^[a-f0-9]{32}$'
      OR p_result IS NULL OR pg_catalog.jsonb_typeof(p_result)<>'object'
      OR pg_catalog.length(p_result::text)>5000 THEN
     RETURN pg_catalog.jsonb_build_object('ok',false,'http_status',422);
   END IF;
   SELECT c.payload,c.status,c.action INTO v_job FROM batcave.commands c
   WHERE c.id=p_command_id AND c.device_id=v_device
      AND c.action IN ('oracle_runtime_inventory_v1','oracle_disposable_build_v1','oracle_model_generate_v1')
   FOR UPDATE;
   IF NOT FOUND OR v_job.payload->>'nonce' IS DISTINCT FROM p_nonce
     OR v_job.payload->>'schema' IS DISTINCT FROM 'batcave.oracle.job.v1'
     OR NOT (
       (v_job.action='oracle_runtime_inventory_v1' AND v_job.payload->>'operation'='runtime_inventory')
       OR (v_job.action='oracle_disposable_build_v1' AND v_job.payload->>'operation'='disposable_project_build_v1')
       OR (v_job.action='oracle_model_generate_v1' AND v_job.payload->>'operation'='model_generate_and_verify_v1'
           AND v_job.payload->>'fixture'='fixed_clamp_score_v1')
     ) THEN
     RETURN pg_catalog.jsonb_build_object('ok',false,'http_status',409);
   END IF;
   IF v_job.status IN ('succeeded','failed') THEN
     RETURN pg_catalog.jsonb_build_object('ok',true,'scope','oracle_runtime_inventory_v1','receipt','already_recorded');
   END IF;
   IF v_job.status<>'leased' THEN
     RETURN pg_catalog.jsonb_build_object('ok',false,'http_status',409);
   END IF;
   IF p_result->>'schema' IS DISTINCT FROM 'batcave.linux.receipt.v1'
      OR p_result->>'job_id' IS DISTINCT FROM p_command_id::text
      OR p_result->>'operation' IS DISTINCT FROM v_job.payload->>'operation'
      OR p_result->>'target' IS DISTINCT FROM 'BatcaveUbuntu'
      OR p_result->>'outcome' IS DISTINCT FROM 'success'
      OR p_result->>'completed_at' IS NULL
      OR coalesce((p_result->>'receipt_hmac_sha256') !~ '^[a-f0-9]{64}$',true)
      OR pg_catalog.jsonb_typeof(p_result->'result')<>'object'
      THEN RETURN pg_catalog.jsonb_build_object('ok',false,'http_status',422);
   END IF;
   IF v_job.payload->>'operation'='disposable_project_build_v1' AND (
      p_result->'result' IS NULL
      OR (p_result->'result'->>'tests_passed') IS DISTINCT FROM 'true'
      OR (p_result->'result'->>'tests_run') IS DISTINCT FROM '6'
      OR coalesce((p_result->'result'->>'artifact_sha256') !~ '^[a-f0-9]{64}$',true)
      OR (p_result->'result'->>'workspace') IS DISTINCT FROM ('lab-projects/' || p_command_id::text)
      OR (p_result->'result'->>'artifact') IS DISTINCT FROM 'src/retry_policy.py'
      OR coalesce((p_result->'result'->>'artifact_bytes') !~ '^[1-9][0-9]*$',true)
   ) THEN RETURN pg_catalog.jsonb_build_object('ok',false,'http_status',422); END IF;
   IF v_job.action='oracle_model_generate_v1' AND NOT EXISTS (
      SELECT 1 FROM batcave.oracle_lab_review_grants_v1 g
      WHERE g.job_id=p_command_id
        AND g.request_nonce=p_nonce
        AND g.consumed_at IS NOT NULL
        AND g.reviewer_key_sha256='4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b'
        AND g.operation='model_generate_and_verify_v1'
        AND g.scope='disposable_lab_only'
        AND g.fixture='fixed_clamp_score_v1'
   ) THEN RETURN pg_catalog.jsonb_build_object('ok',false,'http_status',409); END IF;
   IF v_job.payload->>'operation'='model_generate_and_verify_v1' AND (
      p_result->'result' IS NULL
      OR (p_result->'result'->>'tests_passed') IS DISTINCT FROM 'true'
      OR (p_result->'result'->>'tests_run') IS DISTINCT FROM '8'
      OR coalesce((p_result->'result'->>'artifact_sha256') !~ '^[a-f0-9]{64}$',true)
      OR (p_result->'result'->>'workspace') IS DISTINCT FROM ('lab-projects/' || p_command_id::text)
      OR (p_result->'result'->>'artifact') IS DISTINCT FROM 'src/model_generated.py'
      OR (p_result->'result'->>'model') IS DISTINCT FROM 'qwen2.5-coder:1.5b'
      OR coalesce((p_result->'result'->>'local_run_id') !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',true)
      OR coalesce((p_result->'result'->>'artifact_bytes') !~ '^([2-9][0-9]|[1-9][0-9]{2}|1[0-9]{3}|20[0-3][0-9]|204[0-9])$',true)
   ) THEN RETURN pg_catalog.jsonb_build_object('ok',false,'http_status',422); END IF;
   INSERT INTO batcave.device_receipts(command_id,device_id,outcome,finished_at,result)
   VALUES(p_command_id,v_device,'succeeded',v_now,p_result)
   ON CONFLICT(command_id) DO NOTHING;
   UPDATE batcave.commands SET status='succeeded',
       completed_at=v_now,result=p_result,lease_until=NULL
   WHERE id=p_command_id AND status='leased';
   INSERT INTO batcave.command_events(command_id,event_type,details)
   VALUES(p_command_id,
       CASE WHEN v_job.payload->>'operation'='model_generate_and_verify_v1' THEN 'oracle_model_receipt'
            WHEN v_job.payload->>'operation'='disposable_project_build_v1' THEN 'oracle_build_receipt'
            ELSE 'oracle_inventory_receipt' END,
       pg_catalog.jsonb_build_object('device','Oracle','result','succeeded'));
   RETURN pg_catalog.jsonb_build_object('ok',true,'scope','oracle_runtime_inventory_v1','receipt','recorded');
 END IF;
 RETURN pg_catalog.jsonb_build_object('ok',false,'http_status',422);
EXCEPTION WHEN OTHERS THEN
 RETURN pg_catalog.jsonb_build_object('ok',false,'http_status',503);
END
$function$;
