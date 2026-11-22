/* Existing private Postgres.js connection is injected, never a client credential.
 * Use behind the existing confirmed-owner wrapper. No independent trust writer.
 */
import {stableJson} from './release_gate_core.mjs';
import {FIRST_BASIS,FIRST_VERSION} from './first_reviewer_protocol.mjs';
function normalized(row){
 if(!row)return null;
 const out={...row};for(const k of ['issued_at','expires_at','valid_until','revoked_at','consumed_at','registered_at','recorded_at','owner_declined_at','last_owner_declined_at','withdrawn_at'])if(out[k] instanceof Date)out[k]=out[k].toISOString();
 return out;
}
export function releaseRepository(sql){
 async function getFirstChallenge(id,ch){return normalized((await sql`SELECT * FROM batcave.oracle_first_challenges_v1 WHERE owner_user_id=${id}::uuid AND id=${ch}::uuid`)[0]);}
 async function getFirstPolicy(){
  const r=normalized((await sql`SELECT * FROM batcave.oracle_first_reviewer_v1 WHERE slot=1`)[0]);
  if(r?.registration_challenge_id)r.registration_challenge=await getFirstChallenge(r.policy.owner_user_id,r.registration_challenge_id);
  return r;
 }
 async function issueFirstChallenge(a){return {...normalized((await sql`INSERT INTO batcave.oracle_first_challenges_v1(kind,owner_user_id,owner_key_sha256,reviewer_key_sha256,policy_sha256,nonce,issued_at,expires_at,payload,canonical_payload,payload_sha256,candidate) VALUES(${a.kind},${a.owner_user_id}::uuid,${a.owner_key_sha256},${a.reviewer_key_sha256},${a.policy_sha256},${a.nonce},${a.issued_at}::timestamptz,${a.expires_at}::timestamptz,${sql.json(a.payload)}::jsonb,${stableJson(a.payload)},${a.payload_sha256},${a.candidate===null?null:sql.json(a.candidate)}::jsonb) RETURNING *`)[0]),first_root:true};}
 async function finishFirstVerified(a){return (await sql`SELECT batcave.oracle_first_finish_v1(${a.challenge.owner_user_id}::uuid,${a.challenge.id}::uuid,${a.challenge.payload_sha256},${a.owner_signature_b64url},${a.reviewer_signature_b64url}) AS result`)[0]?.result;}
 return {
 getFirstPolicy,getFirstChallenge,issueFirstChallenge,finishFirstVerified,
 declineFirstEnrollment:async(id,h)=>(await sql`SELECT batcave.oracle_first_decline_v1(${id}::uuid,${h}) AS result`)[0]?.result,
 getFirstCandidate:async(id,h)=>(await sql`SELECT candidate FROM batcave.oracle_first_challenges_v1 WHERE kind='first_key' AND owner_user_id=${id}::uuid AND policy_sha256=${h} ORDER BY issued_at DESC LIMIT 1`)[0]?.candidate||null,
 getPendingFirstEndorsement:async(id,h)=>normalized((await sql`SELECT * FROM batcave.oracle_first_challenges_v1 WHERE kind='first_key' AND owner_user_id=${id}::uuid AND policy_sha256=${h} AND pending_owner_signature_b64url IS NOT NULL AND withdrawn_at IS NULL AND consumed_at IS NULL AND expires_at>clock_timestamp() ORDER BY issued_at DESC LIMIT 1`)[0]),
 saveFirstEndorsementVerified:async a=>(await sql`SELECT batcave.oracle_first_save_endorsement_v1(${a.challenge.owner_user_id}::uuid,${a.challenge.id}::uuid,${a.challenge.payload_sha256},${a.owner_signature_b64url}) AS result`)[0]?.result,
 getLatestFirstRelease:async(id,h)=>normalized((await sql`SELECT * FROM batcave.oracle_first_challenges_v1 WHERE kind='release' AND owner_user_id=${id}::uuid AND policy_sha256=${h} ORDER BY issued_at DESC LIMIT 1`)[0]),
 saveReleaseEndorsementVerified:async a=>(await sql`SELECT batcave.oracle_release_save_endorsement_v1(${a.challenge.owner_user_id}::uuid,${a.challenge.id}::uuid,${a.challenge.payload_sha256},${a.owner_signature_b64url}) AS result`)[0]?.result,
 declineRelease:async(id,h)=>(await sql`SELECT batcave.oracle_release_decline_v1(${id}::uuid,${h}) AS result`)[0]?.result,
 getReleaseReview:async(id,ch)=>(await sql`SELECT review FROM batcave.oracle_release_public_reviews_v1 WHERE owner_user_id=${id}::uuid AND challenge_id=${ch}::uuid`)[0]?.review||null,
 countExistingReviewers:async()=>Number((await sql`SELECT count(*) AS n FROM batcave.oracle_release_keys_v1`)[0].n),
 getOwner:async id=>normalized((await sql`SELECT owner_user_id,public_key_b64url,public_key_sha256,revoked_at FROM batcave.linux_owner_keys_v1 WHERE owner_user_id=${id}::uuid`)[0]),
 getIntent:async key=>normalized((await sql`SELECT intent_key,state,content_sha256,requested_scope,valid_until FROM batcave.change_gate_intents WHERE intent_key=${key}`)[0]),
 getCustody:async(id,fp)=>normalized((await sql`SELECT * FROM batcave.oracle_release_custody_v1 WHERE owner_user_id=${id}::uuid AND public_key_sha256=${fp}`)[0]),
 getReviewer:async(id,fp)=>{
  const k=normalized((await sql`SELECT * FROM batcave.oracle_release_keys_v1 WHERE owner_user_id=${id}::uuid AND public_key_sha256=${fp}`)[0]);if(k)return k;
  const r=await getFirstPolicy(),p=r?.policy;
  if(!r?.registered_at||p.owner_user_id!==id||p.reviewer_key_sha256!==fp)return null;
  return {role:'independent_release_reviewer',owner_user_id:id,registered:true,public_key_sha256:fp,public_key_b64url:p.reviewer_public_key_b64url,host_identity_sha256:p.host_identity_sha256,valid_until:p.signer_valid_until,revoked_at:r.revoked_at,independently_attested:false,release_policy_version:FIRST_VERSION,trust_basis:FIRST_BASIS,private_key_custodian:'Cortana separate protected reviewer',owner_bootstrap_record:r};
 },
 getChallenge:async(id,ch)=>{const old=normalized((await sql`SELECT * FROM batcave.oracle_release_challenges_v1 WHERE owner_user_id=${id}::uuid AND id=${ch}::uuid`)[0]);if(old)return old;const c=await getFirstChallenge(id,ch);return c?{...c,first_root:true}:null;},
 issueChallenge:async a=>a.first_root?issueFirstChallenge(a):normalized((await sql`INSERT INTO batcave.oracle_release_challenges_v1(kind,owner_user_id,owner_key_sha256,reviewer_key_sha256,attestation_id,nonce,issued_at,expires_at,payload,canonical_payload,payload_sha256,candidate) VALUES(${a.kind},${a.owner_user_id}::uuid,${a.owner_key_sha256},${a.reviewer_key_sha256},${a.attestation_id}::uuid,${a.nonce},${a.issued_at}::timestamptz,${a.expires_at}::timestamptz,${sql.json(a.payload)}::jsonb,${stableJson(a.payload)},${a.payload_sha256},${a.candidate===null?null:sql.json(a.candidate)}::jsonb) RETURNING *`)[0]),
 enrollVerified:async a=>(await sql`SELECT batcave.oracle_release_finish_v1(${a.challenge.owner_user_id}::uuid,${a.challenge.id}::uuid,${a.challenge.payload_sha256},${a.owner_signature_b64url},NULL) AS result`)[0]?.result,
 recordEvidence:async a=>a.challenge.first_root?finishFirstVerified({...a,reviewer_signature_b64url:a.nanny_signature_b64url}):(await sql`SELECT batcave.oracle_release_finish_v1(${a.challenge.owner_user_id}::uuid,${a.challenge.id}::uuid,${a.challenge.payload_sha256},${a.owner_signature_b64url},${a.nanny_signature_b64url}) AS result`)[0]?.result
};}
