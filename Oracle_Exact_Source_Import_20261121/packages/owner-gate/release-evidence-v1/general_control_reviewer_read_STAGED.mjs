/* STAGED / NOT DEPLOYED: actual private PostgreSQL owner/reviewer
 * receipt join. No authorization is inferred from the caller or nonce alone.
 * The independent reviewer must still separately prove its protected
 * identity, attested scoped registration and Ed25519 signature.
 */
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export function makeGeneralControlReviewerReadSTAGED(sql){
 if(typeof sql!=='function')throw Error('PRIVATE_POSTGRES_REQUIRED');
 return async requestId=>{
  if(typeof requestId!=='string'||!UUID.test(requestId))
   throw Error('INVALID_REVIEW_REQUEST_ID');
  const rows=await sql`
   SELECT p.request_json AS request,n.state AS nonce_state,
    o.state AS owner_evidence_state,r.state AS reviewer_evidence_state
   FROM batcave.general_control_prepared_challenges_staged_v1 p
   JOIN batcave.general_control_nonce_ledger_v1 n
     ON n.request_id=p.request_id AND n.owner_user_id=p.owner_user_id
     AND n.nonce=p.nonce AND n.request_sha256=p.request_sha256
     AND n.policy_sha256=p.policy_sha256
   JOIN batcave.general_control_owner_evidence_staged_v1 o
     ON o.request_id=p.request_id AND o.owner_user_id=p.owner_user_id
     AND o.nonce=p.nonce AND o.request_sha256=p.request_sha256
     AND o.policy_sha256=p.policy_sha256
   LEFT JOIN batcave.general_control_reviewer_evidence_staged_v1 r
     ON r.request_id=p.request_id AND r.owner_user_id=p.owner_user_id
     AND r.nonce=p.nonce AND r.policy_sha256=p.policy_sha256
   WHERE p.request_id=${requestId}::uuid
   LIMIT 1`;
  const row=rows[0];
  if(!row || !row.request || row.nonce_state!=='consumed' ||
    row.owner_evidence_state!=='owner_signature_recorded_only')
   return null;
  return Object.freeze({
   request:row.request,
   owner_evidence_state:'owner_signature_recorded_only',
   reviewer_evidence_state:row.reviewer_evidence_state??'unused',
   nonce_state:'consumed_owner_evidence'
  });
 };
}
