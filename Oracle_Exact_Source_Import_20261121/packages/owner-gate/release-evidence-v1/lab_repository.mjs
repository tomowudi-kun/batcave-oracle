/* Existing private lab repository, extracted unchanged except typed JSON binding. */
export function labRepository(labSql){
 // Parameterized private DB queries; do not expose the batcave schema through PostgREST.
 return {
  getOwnerKey:async(id)=>(await labSql`SELECT owner_user_id,public_key_b64url,public_key_sha256,revoked_at FROM batcave.linux_owner_keys_v1 WHERE owner_user_id=${id}::uuid LIMIT 1`)[0]||null,
  issueEnrollmentChallenge:async(a)=>(await labSql`INSERT INTO batcave.oracle_lab_enroll_challenges_v2(owner_user_id,nonce,expires_at) VALUES (${a.owner_user_id}::uuid,${a.nonce},${a.expires_at}::timestamptz) RETURNING challenge_id,owner_user_id,nonce,expires_at,consumed_at`)[0]||null,
  getChallenge:async(challengeId,ownerId)=>(await labSql`SELECT challenge_id,owner_user_id,nonce,expires_at,consumed_at FROM batcave.oracle_lab_enroll_challenges_v2 WHERE challenge_id=${challengeId}::uuid AND owner_user_id=${ownerId}::uuid LIMIT 1`)[0]||null,
  enrollVerifiedReviewer:async(a)=>(await labSql`SELECT public.batcave_oracle_lab_enroll_verified_v2(${a.owner_user_id}::uuid,${a.challenge_id}::uuid,${a.request.nonce},${a.request.expires_at}::timestamptz,${labSql.json(a.public_record)}::jsonb,${a.signature_b64url}) AS result`)[0]?.result||null,
  getEnrolledReviewer:async(key)=>(await labSql`SELECT public_key_sha256,public_record,role,owner_user_id,release_archive_sha256,revoked_at FROM batcave.oracle_lab_reviewer_keys_v1 WHERE public_key_sha256=${key} LIMIT 1`)[0]||null,
  getModelJob:async(id)=>(await labSql`SELECT c.id,c.device_id,c.action,c.status,c.attempt_count,c.payload,c.created_at,c.expires_at,d.device_name FROM batcave.commands c LEFT JOIN batcave.devices d ON d.id=c.device_id WHERE c.id=${id}::uuid LIMIT 1`)[0]||null,
  getModelJobStatus:async(id,owner)=>(await labSql`SELECT c.id,c.action,c.status,c.attempt_count,c.payload,c.expires_at,c.completed_at,c.result,d.device_name,g.owner_user_id,g.request_nonce AS grant_nonce,g.artifact_sha256 AS grant_artifact_sha256,g.reviewer_key_sha256,g.release_archive_sha256,g.scope,g.consumed_at,r.outcome AS receipt_outcome,(r.result IS NOT NULL AND c.result IS NOT DISTINCT FROM r.result AND r.device_id=c.device_id) AS receipt_matches FROM batcave.commands c JOIN batcave.devices d ON d.id=c.device_id JOIN batcave.oracle_lab_review_grants_v1 g ON g.job_id=c.id AND g.owner_user_id=${owner}::uuid LEFT JOIN batcave.device_receipts r ON r.command_id=c.id WHERE c.id=${id}::uuid LIMIT 1`)[0]||null,
  insertVerifiedGrant:async(a)=>(await labSql`SELECT public.batcave_oracle_lab_record_verified_v2(${a.owner_user_id}::uuid,${a.job_id}::uuid,${a.nonce},${a.request_sha256},${a.raw_request_json},${labSql.json(a.signed_receipt)}::jsonb,${a.expires_at}::timestamptz) AS result`)[0]?.result||null
 };
}
