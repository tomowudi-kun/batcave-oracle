/* STAGED only. Parameterized PostgreSQL adapter backed by PRIVATE service
 * credentials; never expose to browser, anon, authenticated or device token.
 * This adapter neither verifies Ed25519 nor qualifies/release-approves keys.
 */
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const H32=/^[a-f0-9]{32}$/,H64=/^[a-f0-9]{64}$/,H128=/^[a-f0-9]{128}$/;
const must=(v,re)=>{if(typeof v!=='string'||!re.test(v))throw Error('INVALID_PRIVATE_CANDIDATE_FIELD');return v;};
export function makeCandidatePossessionPrivateRepoSTAGED(sql){
 if(typeof sql!=='function'||typeof sql.json!=='function')throw Error('PRIVATE_POSTGRES_REQUIRED');
 const repository={
  reserve:async(p,hash)=>{
   must(p?.request_id,UUID);must(p?.draft_id,UUID);must(p?.owner_user_id,UUID);
   must(p?.nonce,H32);must(p?.candidate_key_sha256,H64);must(hash,H64);
   // The private draft is checked again inside the INSERT, not solely by JS.
   const rows=await sql`INSERT INTO batcave.general_control_reviewer_possession_staged_v1
    (request_id,draft_id,owner_user_id,candidate_key_sha256,candidate_public_b64url,
     nonce,payload,signing_sha256,issued_at,expires_at)
    SELECT ${p.request_id}::uuid,${p.draft_id}::uuid,${p.owner_user_id}::uuid,
     ${p.candidate_key_sha256},${p.candidate_public_b64url},
     ${p.nonce},${sql.json(p)}::jsonb,${hash},
     ${p.issued_at}::timestamptz,${p.expires_at}::timestamptz
    FROM batcave.oracle_instruction_drafts_v1 d
    WHERE d.id=${p.draft_id}::uuid AND d.owner_user_id=${p.owner_user_id}::uuid
    AND d.state='draft' AND d.execution_authorized=false
    AND d.interpreted_intent->>'kind'='general_control_public_reviewer_candidate_v1'
    AND d.interpreted_intent->>'public_key_sha256_raw'=${p.candidate_key_sha256}
    AND d.interpreted_intent->>'public_key_b64url_raw'=${p.candidate_public_b64url}
    AND d.interpreted_intent->>'registered'='false'
    AND d.interpreted_intent->>'independently_attested'='false'
    RETURNING request_id,nonce,state`;
   const row=rows[0];return row?{reserved:true,request_id:String(row.request_id),nonce:row.nonce}:{reserved:false};
  },
  getPrepared:async(id,nonce)=>{
   must(id,UUID);must(nonce,H32);
   const rows=await sql`SELECT payload,signing_sha256,state
     FROM batcave.general_control_reviewer_possession_staged_v1
     WHERE request_id=${id}::uuid AND nonce=${nonce} LIMIT 1`;
   return rows[0]??null;
  },
  recordProof:async(p)=>{
   must(p?.request_id,UUID);must(p?.draft_id,UUID);must(p?.owner_user_id,UUID);
   must(p?.nonce,H32);must(p?.candidate_key_sha256,H64);
   must(p?.signing_sha256,H64);must(p?.signature_hex,H128);
   const rows=await sql`SELECT batcave.general_control_record_candidate_possession_staged_v1(
    ${p.request_id}::uuid,${p.draft_id}::uuid,${p.owner_user_id}::uuid,
    ${p.nonce},${p.candidate_key_sha256},${p.signing_sha256},
    ${p.signature_hex}) AS recorded`;
   return rows[0]?.recorded===true?{recorded:true,request_id:p.request_id,
    state:'candidate_possession_recorded_only'}:{recorded:false};
  }
 };
 const getPrivateCandidate=async(id,owner)=>{
  must(id,UUID);must(owner,UUID);
  const rows=await sql`SELECT id,owner_user_id,source,state,execution_authorized,
     interpreted_intent FROM batcave.oracle_instruction_drafts_v1
     WHERE id=${id}::uuid AND owner_user_id=${owner}::uuid LIMIT 1`;
  const d=rows[0];if(!d||d.state!=='draft'||d.execution_authorized!==false)return null;
  const i=d.interpreted_intent;
  return {id:String(d.id),owner_user_id:String(d.owner_user_id),kind:i?.kind,
   registered:i?.registered===false,independently_attested:i?.independently_attested===false,
   production_release_authorized:i?.production_release_authorized===false,
   execution_authorized:i?.execution_authorized===false,host:i?.device,account:i?.account,
   sid:i?.sid_from_owner_screenshot,public_key_sha256_raw:i?.public_key_sha256_raw,
   public_key_b64url_raw:i?.public_key_b64url_raw};
 };
 return Object.freeze({repository,getPrivateCandidate});
}
