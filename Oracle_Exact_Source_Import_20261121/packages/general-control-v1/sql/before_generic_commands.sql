-- Read-only production definition snapshot, 2026-11-22. No credentials.
-- Invoker functions; live EXECUTE ACL was postgres only.
CREATE OR REPLACE FUNCTION batcave.claim_next_command(p_device_id uuid, p_lease_seconds integer DEFAULT 60)
 RETURNS TABLE(command_id uuid, action text, payload jsonb, lease_until timestamp with time zone, attempt_count integer)
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
begin
 if p_lease_seconds < 10 or p_lease_seconds > 300 then raise exception 'Invalid lease duration'; end if;
 return query
 with candidate as (
  select c.id from batcave.commands c
  join batcave.devices d on d.id=c.device_id
  where c.device_id=p_device_id and d.state='active'
    and c.expires_at>now() and c.attempt_count<3
    and not exists (select 1 from batcave.device_receipts r where r.command_id=c.id)
    and (c.status='pending' or (c.status='leased' and c.lease_until<now()))
  order by c.created_at,c.id for update of c skip locked limit 1
 ), claimed as (
  update batcave.commands c
  set status='leased', lease_until=now()+make_interval(secs=>p_lease_seconds),
      attempt_count=c.attempt_count+1
  from candidate where c.id=candidate.id
  returning c.id,c.action,c.payload,c.lease_until,c.attempt_count
 )
 select claimed.id,claimed.action,claimed.payload,claimed.lease_until,claimed.attempt_count from claimed;
end $function$;

CREATE OR REPLACE FUNCTION batcave.complete_command(p_command_id uuid, p_device_id uuid, p_result jsonb, p_success boolean)
 RETURNS boolean
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
declare updated_count integer;
begin
 update batcave.commands c set
   status=case when p_success then 'succeeded' else 'failed' end,
   result=p_result, completed_at=now(),lease_until=null
 where c.id=p_command_id and c.device_id=p_device_id and c.status='leased'
   and c.lease_until>=now();
 get diagnostics updated_count=row_count;
 if updated_count=1 then
  insert into batcave.command_events(command_id,event_type,details)
   values(p_command_id,case when p_success then 'succeeded' else 'failed' end,coalesce(p_result,'{}'::jsonb));
 end if;
 return updated_count=1;
end $function$;

CREATE OR REPLACE FUNCTION batcave.start_command(p_command_id uuid, p_device_id uuid)
 RETURNS boolean
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
declare n integer;
begin
 insert into batcave.device_receipts(command_id,device_id,outcome)
 select c.id,c.device_id,'started' from batcave.commands c
 where c.id=p_command_id and c.device_id=p_device_id
 and c.status='leased' and c.lease_until>=now()
 on conflict (command_id) do nothing;
 get diagnostics n=row_count;
 return n=1;
end $function$;

