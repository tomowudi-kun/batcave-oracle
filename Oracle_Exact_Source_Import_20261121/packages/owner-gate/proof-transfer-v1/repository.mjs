export function proofRepository(sql){return {
 readiness:async()=>(await sql`SELECT
  jsonb_typeof(${sql.json({public_probe:true})}::jsonb)='object' AS store_parameter_object,
  has_schema_privilege(current_user,'batcave','USAGE') AS schema_usage,
  has_table_privilege(current_user,'batcave.oracle_first_public_proofs_v1','SELECT') AND has_table_privilege(current_user,'batcave.oracle_first_public_proofs_v1','INSERT') AS proof_access,
  has_function_privilege(current_user,'batcave.oracle_first_store_public_proof_v1(uuid,text,jsonb,text)','EXECUTE') AS store_execute,
  has_table_privilege(current_user,'batcave.oracle_first_reviewer_v1','SELECT') AND has_table_privilege(current_user,'batcave.oracle_first_reviewer_v1','UPDATE')
  AND has_table_privilege(current_user,'batcave.oracle_first_challenges_v1','SELECT') AND has_table_privilege(current_user,'batcave.oracle_first_challenges_v1','UPDATE')
  AND has_table_privilege(current_user,'batcave.linux_owner_keys_v1','SELECT') AND has_table_privilege(current_user,'batcave.linux_owner_keys_v1','UPDATE')
  AND has_table_privilege(current_user,'batcave.change_gate_intents','SELECT') AND has_table_privilege(current_user,'batcave.change_gate_intents','UPDATE')
  AND has_table_privilege(current_user,'batcave.oracle_release_keys_v1','SELECT') AS gate_access`)[0],
 context:async id=>(await sql`SELECT jsonb_build_object('root',to_jsonb(r),'challenge',to_jsonb(c),'owner',to_jsonb(o),'intent',jsonb_build_object('state',i.state,'content_sha256',i.content_sha256,'valid_until',i.valid_until),'existing_reviewers',(SELECT count(*)::int FROM batcave.oracle_release_keys_v1 WHERE registered AND revoked_at IS NULL)) AS ctx FROM batcave.oracle_first_challenges_v1 c JOIN batcave.oracle_first_reviewer_v1 r ON r.slot=1 JOIN batcave.linux_owner_keys_v1 o ON o.owner_user_id=c.owner_user_id JOIN batcave.change_gate_intents i ON i.intent_key=r.policy->>'release_intent_key' WHERE c.id=${id}::uuid`)[0]?.ctx,
 store:async(id,payloadHash,proof,hash)=>(await sql`SELECT batcave.oracle_first_store_public_proof_v1(${id}::uuid,${payloadHash},${sql.json(proof)}::jsonb,${hash}) AS receipt`)[0].receipt,
 proof:async id=>(await sql`SELECT proof FROM batcave.oracle_first_public_proofs_v1 WHERE challenge_id=${id}::uuid`)[0]?.proof
};}
