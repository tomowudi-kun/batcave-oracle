/* STAGED, NOT MOUNTED: private reviewer evidence repository.
 * SQL is SECURITY INVOKER. This adapter never verifies signatures, grants,
 * releases or executes. Independent reviewer admission must run first.
 */
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const H32=/^[a-f0-9]{32}$/, H40=/^[a-f0-9]{40}$/, H64=/^[a-f0-9]{64}$/, H128=/^[a-f0-9]{128}$/;
const fail=()=>{throw Error('INVALID_PRIVATE_REVIEWER_EVIDENCE');};
const check=(v,re)=>typeof v==='string'&&re.test(v)?v:fail();
const KEYS=['request_id','owner_user_id','nonce','policy_digest','source_commit','reviewer_identity_id','reviewer_key_hex','signature_hex'];
export function makeGeneralControlReviewerPrivateRepoSTAGED(sql,{getTrustedPreparedReview}={}){
 if(typeof sql!=='function'||typeof getTrustedPreparedReview!=='function')throw Error('PRIVATE_CONNECTION_AND_TRUSTED_RESOLVER_REQUIRED');
 return Object.freeze({
  getPreparedReview:async id=>getTrustedPreparedReview(check(id,UUID)),
  appendReviewerEvidence:async e=>{
   if(!e||typeof e!=='object'||Array.isArray(e)||
     Object.keys(e).sort().join(',')!==[...KEYS].sort().join(','))fail();
   const id=check(e.request_id,UUID),owner=check(e.owner_user_id,UUID);
   const nonce=check(e.nonce,H32),policy=check(e.policy_digest,H64);
   const source=check(e.source_commit,H40),reviewer=check(e.reviewer_identity_id,UUID);
   if(reviewer===owner)fail();
   const key=check(e.reviewer_key_hex,H64),sig=check(e.signature_hex,H128);
   const rows=await sql`SELECT batcave.general_control_append_reviewer_evidence_staged_v1(
     ${id}::uuid,${owner}::uuid,${nonce},${policy},${source},
     ${reviewer}::uuid,${key},${sig}) AS recorded`;
   return rows.length===1&&rows[0].recorded===true
    ?Object.freeze({inserted:true,request_id:id,state:'reviewer_signature_recorded_only'})
    :Object.freeze({inserted:false});
  },
 });
}
