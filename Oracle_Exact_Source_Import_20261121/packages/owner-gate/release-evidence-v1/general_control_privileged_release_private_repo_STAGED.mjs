/* STAGED, NOT DEPLOYED: private Postgres@3.4.5 adapter for independent
 * privileged release signature receipt. Does not authenticate reviewer,
 * create signatures, qualify keys, or grant authority. It MUST only be called
 * after the independently attested protected-session verifier succeeds.
 */
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const H32=/^[0-9a-f]{32}$/,H40=/^[0-9a-f]{40}$/,H64=/^[0-9a-f]{64}$/,H128=/^[0-9a-f]{128}$/;
const exact=(x,k)=>x&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).length===k.length&&k.every(y=>Object.hasOwn(x,y));
const must=(s,regex)=>{if(typeof s!=='string'||!regex.test(s))throw Error('INVALID_PRIVATE_RELEASE_FIELD');return s};
const FIELDS=['request_id','nonce','reviewer_identity_id','reviewer_key_hex','source_commit',
 'policy_digest','intent_sha256','request_sha256','signature_hex','signing_sha256'];
export function makePrivilegedReleasePrivateRepoSTAGED(sql){
 if(typeof sql!=='function'||typeof sql.json!=='function')throw Error('PRIVATE_SERVER_POSTGRES_REQUIRED');
 return Object.freeze({
  reserve:async(p,hash)=>{
   must(p?.request_id,UUID);must(p.owner_user_id,UUID);
   must(p.reviewer_identity_id,UUID);must(p.nonce,H32);
   must(p.source_commit,H40);must(p.policy_digest,H64);
   must(p.intent_sha256,H64);must(p.request_sha256,H64);
   must(hash,H64);
   if(p.owner_user_id===p.reviewer_identity_id)throw Error('OWNER_CANNOT_ATTEST');
   const rows=await sql`
    INSERT INTO batcave.general_control_privileged_release_review_staged_v1(
     request_id,owner_user_id,nonce,reviewer_identity_id,reviewer_key_hex,
     source_commit,policy_sha256,intent_key,intent_sha256,request_sha256,
     signing_sha256,payload,issued_at,expires_at)
    VALUES(${p.request_id}::uuid,${p.owner_user_id}::uuid,${p.nonce},
     ${p.reviewer_identity_id}::uuid,${p.reviewer_key_hex},
     ${p.source_commit},${p.policy_digest},${p.intent_key},
     ${p.intent_sha256},${p.request_sha256},${hash},
     ${sql.json(p)}::jsonb,${p.issued_at}::timestamptz,${p.expires_at}::timestamptz)
    RETURNING request_id,nonce,state`;
   const row=rows[0];
   return row?{reserved:true,request_id:String(row.request_id),nonce:row.nonce,status:row.state}:{reserved:false};
  },
  getPrepared:async(requestId,nonce)=>{
   must(requestId,UUID);must(nonce,H32);
   const rows=await sql`
    SELECT payload,signing_sha256,state AS status
    FROM batcave.general_control_privileged_release_review_staged_v1
    WHERE request_id=${requestId}::uuid AND nonce=${nonce} LIMIT 1`;
   return rows[0]??null;
  },
  recordSignature:async(row)=>{
   if(!exact(row,FIELDS))throw Error('INVALID_SIGNATURE_INPUT');
   must(row.request_id,UUID);must(row.nonce,H32);
   must(row.reviewer_identity_id,UUID);must(row.reviewer_key_hex,H64);
   must(row.source_commit,H40);must(row.policy_digest,H64);
   must(row.intent_sha256,H64);must(row.request_sha256,H64);
   must(row.signing_sha256,H64);must(row.signature_hex,H128);
   const rows=await sql`
    SELECT batcave.general_control_record_privileged_release_staged_v1(
     ${row.request_id}::uuid,${row.nonce},${row.reviewer_identity_id}::uuid,
     ${row.reviewer_key_hex},${row.source_commit},${row.policy_digest},
     ${row.intent_sha256},${row.request_sha256},
     ${row.signing_sha256},${row.signature_hex}) AS recorded`;
   return rows[0]?.recorded===true?{
    recorded:true,request_id:row.request_id,
    status:'privileged_release_signature_recorded_only'}:{recorded:false};
  },
 });
}
