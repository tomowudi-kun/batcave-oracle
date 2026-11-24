-- STAGED. Invoker/EXECUTE permissions remain unchanged. This is not a grant writer.
-- The authenticated caller must still enforce owner and independent review scope.
DO $guard$
DECLARE item record; actual text; acl text; elevated boolean;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('batcave.claim_next_command(uuid,integer)','614f09064ac5d6e7f5100e448505b6e7'),
  ('batcave.complete_command(uuid,uuid,jsonb,boolean)','1e2cd65cb19b7c29ba13f9c75e145b88'),
  ('batcave.start_command(uuid,uuid)','2dacbda0f79a5ff3407dea276c59ba24')
 ) expected(signature,body_md5) LOOP
  SELECT pg_catalog.md5(p.prosrc),p.proacl::text,p.prosecdef INTO actual,acl,elevated
  FROM pg_catalog.pg_proc p WHERE p.oid=pg_catalog.to_regprocedure(item.signature);
  IF actual IS DISTINCT FROM item.body_md5 OR acl IS DISTINCT FROM '{postgres=X/postgres}'
     OR elevated IS DISTINCT FROM false THEN
   RAISE EXCEPTION 'STAGED recovery preflight mismatch: %',item.signature;
  END IF;
 END LOOP;
END $guard$;

CREATE OR REPLACE FUNCTION batcave.start_command(p_command_id uuid, p_device_id uuid)
RETURNS boolean LANGUAGE plpgsql SET search_path TO '' AS $function$
DECLARE c batcave.commands%ROWTYPE; stamp jsonb; n integer; observed timestamptz;
BEGIN
 SELECT * INTO c FROM batcave.commands
 WHERE id=p_command_id AND device_id=p_device_id FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 observed:=pg_catalog.clock_timestamp();
 IF c.status IS DISTINCT FROM 'leased' OR c.lease_until IS NULL OR c.expires_at IS NULL
    OR c.lease_until<observed OR c.expires_at<=observed OR c.attempt_count<1
    THEN RETURN false; END IF;
 stamp:=pg_catalog.jsonb_build_object('schema','batcave.command.start.v1',
   'attempt',c.attempt_count,'lease_epoch',EXTRACT(epoch FROM c.lease_until)::text);
 INSERT INTO batcave.device_receipts(command_id,device_id,outcome,result)
 VALUES(c.id,c.device_id,'started',stamp)
 ON CONFLICT(command_id) DO NOTHING;
 GET DIAGNOSTICS n=ROW_COUNT;
 RETURN n=1;
END $function$;

CREATE OR REPLACE FUNCTION batcave.complete_command(
 p_command_id uuid,p_device_id uuid,p_result jsonb,p_success boolean)
RETURNS boolean LANGUAGE plpgsql SET search_path TO '' AS $function$
DECLARE c batcave.commands%ROWTYPE; r batcave.device_receipts%ROWTYPE;
 wanted text; bound boolean; observed timestamptz;
BEGIN
 IF p_success IS NULL OR p_result IS NULL
    OR pg_catalog.jsonb_typeof(p_result) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
 wanted:=CASE WHEN p_success THEN 'succeeded' ELSE 'failed' END;
 SELECT * INTO c FROM batcave.commands
 WHERE id=p_command_id AND device_id=p_device_id FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO r FROM batcave.device_receipts
 WHERE command_id=c.id AND device_id=c.device_id FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 -- A retry acknowledges only the same already-persisted outcome; no overwrite/event.
 IF c.status IN ('succeeded','failed') THEN
   RETURN COALESCE(c.status=wanted AND c.result=p_result
      AND r.outcome=wanted AND r.result=p_result AND r.finished_at IS NOT NULL,false);
 END IF;
 IF c.status IS DISTINCT FROM 'leased' OR r.outcome IS DISTINCT FROM 'started'
    OR c.lease_until IS NULL THEN RETURN false; END IF;
 observed:=pg_catalog.clock_timestamp();
 bound:=COALESCE(r.result->>'schema'='batcave.command.start.v1'
   AND r.result->>'attempt'=c.attempt_count::text
   AND r.result->>'lease_epoch'=EXTRACT(epoch FROM c.lease_until)::text,false);
 -- Legacy unbound starts keep their old live-lease behavior. Never infer a late
 -- execution identity for old receipts; they remain held for explicit reconciliation.
 IF NOT bound AND NOT(r.result IS NULL AND c.lease_until>=observed) THEN RETURN false; END IF;
 UPDATE batcave.device_receipts SET outcome=wanted,finished_at=observed,result=p_result
 WHERE command_id=c.id AND device_id=c.device_id;
 UPDATE batcave.commands SET status=wanted,result=p_result,completed_at=observed,lease_until=NULL
 WHERE id=c.id AND device_id=c.device_id;
 INSERT INTO batcave.command_events(command_id,event_type,details)
 VALUES(c.id,wanted,p_result);
 RETURN true;
END $function$;

-- claim_next_command is deliberately unchanged: a started receipt prevents replay.
-- No SECURITY DEFINER, GRANT, new action, device credential or approval modification.
