import {digest} from './notification_core.mjs';
export function phoneRepository(sql,generateKeys){
 return {
 ownerExists:async id=>(await sql`SELECT owner_user_id FROM batcave.linux_owner_keys_v1 WHERE owner_user_id=${id}::uuid AND revoked_at IS NULL`).length===1,
 ensureConfig:async()=>sql.begin(async tx=>{
  await tx`SELECT pg_advisory_xact_lock(hashtextextended('batcave.owner_phone_config_v1',0))`;
  let r=(await tx`SELECT * FROM batcave.owner_phone_config_v1 WHERE slot=1`)[0];if(r)return r;
  const keys=generateKeys(),dispatchToken=Array.from(crypto.getRandomValues(new Uint8Array(32)),x=>x.toString(16).padStart(2,'0')).join('');
  const privateData=JSON.stringify({privateKey:keys.privateKey,dispatchToken});
  const secret=(await tx`SELECT vault.create_secret(${privateData},'batcave_owner_phone_push_v1','Phone notification publisher only; never an owner/reviewer signing key') AS id`)[0].id;
  r=(await tx`INSERT INTO batcave.owner_phone_config_v1(slot,public_key,secret_id,dispatch_hash) VALUES(1,${keys.publicKey},${secret}::uuid,${await digest(dispatchToken)}) RETURNING *`)[0];return r;
 }),
 config:async()=>(await sql`SELECT * FROM batcave.owner_phone_config_v1 WHERE slot=1`)[0],
 secret:async id=>JSON.parse((await sql`SELECT decrypted_secret FROM vault.decrypted_secrets WHERE id=${id}::uuid`)[0].decrypted_secret),
 subscribe:async(id,s,hash)=>sql.begin(async tx=>{
  await tx`SELECT pg_advisory_xact_lock(hashtextextended(${id},20261122))`;
  const old=(await tx`SELECT * FROM batcave.owner_phone_subscriptions_v1 WHERE endpoint_sha256=${hash}`)[0];
  if(old&&old.owner_user_id!==id)throw Error('SUBSCRIPTION_OWNER_MISMATCH');
  if((!old||old.disabled_at)&&Number((await tx`SELECT count(*) AS n FROM batcave.owner_phone_subscriptions_v1 WHERE owner_user_id=${id}::uuid AND disabled_at IS NULL`)[0].n)>=4)throw Error('PHONE_LIMIT');
  return (await tx`INSERT INTO batcave.owner_phone_subscriptions_v1(owner_user_id,endpoint_sha256,endpoint,p256dh,auth) VALUES(${id}::uuid,${hash},${s.endpoint},${s.keys.p256dh},${s.keys.auth}) ON CONFLICT(endpoint_sha256) DO UPDATE SET disabled_at=NULL,p256dh=EXCLUDED.p256dh,auth=EXCLUDED.auth WHERE owner_phone_subscriptions_v1.owner_user_id=EXCLUDED.owner_user_id RETURNING id`)[0];
 }),
 getSubscription:async(id,sub)=>(await sql`SELECT id,disabled_at FROM batcave.owner_phone_subscriptions_v1 WHERE owner_user_id=${id}::uuid AND id=${sub}::uuid`)[0],
 latestDelivery:async(id,sub)=>(await sql`SELECT id,send_state,shown_at,opened_at FROM batcave.owner_phone_notifications_v1 WHERE owner_user_id=${id}::uuid AND subscription_id=${sub}::uuid ORDER BY created_at DESC LIMIT 1`)[0],
 queue:async(id,kind,sub)=>(await sql`SELECT batcave.queue_owner_phone_alert_v1(${id}::uuid,${kind},${sub}::uuid) AS ids`)[0].ids,
 disable:async(id,sub)=>{await sql`UPDATE batcave.owner_phone_subscriptions_v1 SET disabled_at=COALESCE(disabled_at,clock_timestamp()) WHERE id=${sub}::uuid AND owner_user_id=${id}::uuid`;},
 claim:async(id,hash)=>sql.begin(async tx=>{
  const r=(await tx`UPDATE batcave.owner_phone_notifications_v1 n SET send_state='sending',receipt_hash=${hash} FROM batcave.owner_phone_subscriptions_v1 s WHERE n.id=${id}::uuid AND n.send_state='queued' AND n.expires_at>clock_timestamp() AND s.id=n.subscription_id AND s.owner_user_id=n.owner_user_id AND s.disabled_at IS NULL RETURNING n.*,s.endpoint,s.p256dh,s.auth`)[0];return r;
 }),
 reviewPending:async id=>(await sql`SELECT r.slot FROM batcave.oracle_first_reviewer_v1 r JOIN batcave.linux_owner_keys_v1 k ON k.owner_user_id=${id}::uuid AND k.revoked_at IS NULL AND k.public_key_sha256=r.policy->>'owner_key_sha256' JOIN batcave.change_gate_intents i ON i.intent_key=r.policy->>'release_intent_key' AND i.content_sha256=r.policy->>'release_intent_sha256' AND i.state='held' AND i.valid_until>clock_timestamp() WHERE r.slot=1 AND r.policy->>'owner_user_id'=${id} AND r.registered_at IS NULL AND r.revoked_at IS NULL AND r.owner_declined_at IS NULL AND (r.policy->>'signer_valid_until')::timestamptz>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM batcave.oracle_first_challenges_v1 c WHERE c.kind='first_key' AND c.owner_user_id=${id}::uuid AND c.policy_sha256=r.policy_sha256 AND c.pending_owner_signature_b64url IS NOT NULL AND c.consumed_at IS NULL AND c.expires_at>clock_timestamp())`).length===1,
 finish:async(id,state)=>{await sql`UPDATE batcave.owner_phone_notifications_v1 SET send_state=${state},sent_at=CASE WHEN ${state}='sent' THEN clock_timestamp() ELSE sent_at END WHERE id=${id}::uuid AND send_state='sending'`;},
 receipt:async(id,hash,stage)=>{
  const r=stage==='shown'?await sql`UPDATE batcave.owner_phone_notifications_v1 SET shown_at=COALESCE(shown_at,clock_timestamp()) WHERE id=${id}::uuid AND receipt_hash=${hash} AND send_state IN ('sending','sent','uncertain') AND expires_at>clock_timestamp()-interval '1 day' RETURNING id`:await sql`UPDATE batcave.owner_phone_notifications_v1 SET opened_at=COALESCE(opened_at,clock_timestamp()) WHERE id=${id}::uuid AND receipt_hash=${hash} AND send_state IN ('sending','sent','uncertain') AND expires_at>clock_timestamp()-interval '1 day' RETURNING id`;
  return r.length===1;
 }
 };
}
