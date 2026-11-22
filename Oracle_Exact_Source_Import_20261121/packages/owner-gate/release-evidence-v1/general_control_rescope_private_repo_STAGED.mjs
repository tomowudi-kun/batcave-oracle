/* STAGED, NOT MOUNTED. Private postgres@3.4.5 root-key re-scope repository.
 * Independently authenticated release/source policies and the legacy root
 * key are injected by SERVER-ONLY resolvers. This has NO route from a browser
 * to batcave private SQL tables, no new privileges, active key or grants.
 */
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const checkId=id=>{
 if(typeof id!=='string'||!UUID.test(id))throw Error('BAD_SERVER_OWNER_OR_CHALLENGE');
 return id;
};
export function makeGeneralControlRootRescopePrivateRepoSTAGED(sql,{
 getTrustedExistingRoot, getTrustedSourcePolicy,
}={}){
 if(typeof sql!=='function'||typeof sql.json!=='function'||
  typeof getTrustedExistingRoot!=='function'||typeof getTrustedSourcePolicy!=='function')
  throw Error('PRIVATE_POSTGRES_AND_TRUSTED_RESOLVERS_REQUIRED');
 return Object.freeze({
  getRoot:async owner=>getTrustedExistingRoot(checkId(owner)),
  getTrustedScopePolicy:async owner=>getTrustedSourcePolicy(checkId(owner)),
  reserve:async ch=>{
   checkId(ch?.owner_user_id);checkId(ch?.challenge_id);
   const result=await sql`
    INSERT INTO batcave.general_control_owner_rescope_challenges_staged_v1(
     challenge_id,owner_user_id,nonce,root_key_sha256,scope_public_key_hex,
     source_commit,policy_digest,issued_at,expires_at,payload)
    VALUES(${ch.challenge_id}::uuid,${ch.owner_user_id}::uuid,
     ${ch.nonce},${ch.root_key_sha256},${ch.scope_public_key_hex},
     ${ch.source_commit},${ch.policy_digest},
     ${ch.issued_at}::timestamptz,${ch.expires_at}::timestamptz,
     ${sql.json(ch)}::jsonb)
    RETURNING challenge_id,nonce,state`;
   const row=result[0];
   return row?{reserved:true,challenge_id:String(row.challenge_id),
    nonce:row.nonce,state:row.state}:{reserved:false};
  },
  getPrepared:async(owner,challenge)=>{
   checkId(owner);checkId(challenge);
   const rows=await sql`
    SELECT payload AS challenge,state FROM
     batcave.general_control_owner_rescope_challenges_staged_v1
    WHERE owner_user_id=${owner}::uuid AND challenge_id=${challenge}::uuid
    LIMIT 1`;
   return rows[0]??null;
  },
  recordPending:async row=>{
   checkId(row?.owner_user_id);checkId(row?.challenge_id);
   const result=await sql`
    SELECT batcave.general_control_record_root_rescope_staged_v1(
     ${row.owner_user_id}::uuid,${row.challenge_id}::uuid,
     ${row.nonce},${row.root_key_sha256},
     ${row.key_hex},${row.source_commit},
     ${row.policy_digest},${row.signature_hex}) AS recorded`;
   return result[0]?.recorded===true?
    {recorded:true,challenge_id:row.challenge_id,state:'pending_independent_review'}:
    {recorded:false};
  },
  decline:async row=>{
   checkId(row?.owner_user_id);checkId(row?.challenge_id);
   const result=await sql`
    UPDATE batcave.general_control_owner_rescope_challenges_staged_v1
    SET state='declined'
    WHERE owner_user_id=${row.owner_user_id}::uuid
      AND challenge_id=${row.challenge_id}::uuid AND nonce=${row.nonce}
      AND state='unused' AND expires_at>clock_timestamp()
    RETURNING challenge_id`;
   return result.length===1?
    {declined:true,challenge_id:String(result[0].challenge_id)}:
    {declined:false};
  },
 });
}
