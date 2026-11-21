/* Existing private Postgres.js connection is injected, never a client credential.
 * Use behind the existing confirmed-owner wrapper. No independent trust writer.
 */
import {stableJson} from './release_gate_core.mjs';
function normalized(row){
 if(!row)return null;
 const out={...row};for(const k of ['issued_at','expires_at','valid_until','revoked_at','consumed_at'])if(out[k] instanceof Date)out[k]=out[k].toISOString();
 return out;
}
export function releaseRepository(sql){return {
 getOwner:async id=>normalized((await sql`SELECT owner_user_id,public_key_b64url,public_key_sha256,revoked_at FROM batcave.linux_owner_keys_v1 WHERE owner_user_id=${id}::uuid`)[0]),
 getIntent:async key=>normalized((await sql`SELECT intent_key,state,content_sha256,requested_scope,valid_until FROM batcave.change_gate_intents WHERE intent_key=${key}`)[0]),
 getCustody:async(id,fp)=>normalized((await sql`SELECT * FROM batcave.oracle_release_custody_v1 WHERE owner_user_id=${id}::uuid AND public_key_sha256=${fp}`)[0]),
 getReviewer:async(id,fp)=>normalized((await sql`SELECT * FROM batcave.oracle_release_keys_v1 WHERE owner_user_id=${id}::uuid AND public_key_sha256=${fp}`)[0]),
 getChallenge:async(id,ch)=>normalized((await sql`SELECT * FROM batcave.oracle_release_challenges_v1 WHERE owner_user_id=${id}::uuid AND id=${ch}::uuid`)[0]),
 issueChallenge:async a=>normalized((await sql`INSERT INTO batcave.oracle_release_challenges_v1(kind,owner_user_id,owner_key_sha256,reviewer_key_sha256,attestation_id,nonce,issued_at,expires_at,payload,canonical_payload,candidate) VALUES(${a.kind},${a.owner_user_id}::uuid,${a.owner_key_sha256},${a.reviewer_key_sha256},${a.attestation_id}::uuid,${a.nonce},${a.issued_at}::timestamptz,${a.expires_at}::timestamptz,${sql.json(a.payload)}::jsonb,${stableJson(a.payload)},${a.candidate===null?null:sql.json(a.candidate)}::jsonb) RETURNING *`)[0]),
 enrollVerified:async a=>(await sql`SELECT batcave.oracle_release_finish_v1(${a.challenge.owner_user_id}::uuid,${a.challenge.id}::uuid,${a.challenge.payload_sha256},${a.owner_signature_b64url},NULL) AS result`)[0]?.result,
 recordEvidence:async a=>(await sql`SELECT batcave.oracle_release_finish_v1(${a.challenge.owner_user_id}::uuid,${a.challenge.id}::uuid,${a.challenge.payload_sha256},${a.owner_signature_b64url},${a.nanny_signature_b64url}) AS result`)[0]?.result
};}
