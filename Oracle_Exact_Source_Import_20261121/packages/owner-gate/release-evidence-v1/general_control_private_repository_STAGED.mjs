/* STAGED / NOT MOUNTED. Private DB adapter for the typed owner Yes/No API.
 *
 * sql must be a SERVER-ONLY postgres@3.4.5 tagged-template client with
 * private-schema access; no PostgREST exposure, client token, or public RPC.
 * Trusted scope and scoped owner-key resolvers are mandatory independent
 * dependencies. They must use authenticated server policy/identity records;
 * they must NEVER be constructed from the client's requested scope.
 *
 * All writes are parameterized through the private SECURITY INVOKER SQL
 * functions, which atomically reserve/consume or decline one nonce.
 * This module cannot enroll a key, approve an independent reviewer, issue a
 * grant, lease, or dispatch a device/browser command.
 */
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
function requireId(value) {
 if(typeof value!=='string'||!UUID.test(value))throw Error('INVALID_SERVER_OWNER_OR_REQUEST_ID');
 return value;
}
function mustFunction(fn,name) {
 if(typeof fn!=='function')throw Error('TRUSTED_'+name+'_REQUIRED');
 return fn;
}
export function createGeneralControlPrivateRepositorySTAGED(sql, {
 getTrustedPendingScope, getTrustedCurrentScope, getRegisteredOwnerKey,
}={}) {
 if(typeof sql!=='function'||typeof sql.json!=='function')throw Error('PRIVATE_POSTGRES_CLIENT_REQUIRED');
 const pending=mustFunction(getTrustedPendingScope,'PENDING_SCOPE');
 const current=mustFunction(getTrustedCurrentScope,'CURRENT_SCOPE');
 const ownerKey=mustFunction(getRegisteredOwnerKey,'OWNER_KEY');
 return Object.freeze({
  getPendingScope: async ownerId=>pending(requireId(ownerId)),
  getCurrentScope: async (ownerId,requestId)=>current(requireId(ownerId),requireId(requestId)),
  getScopeRegistration: async ownerId=>ownerKey(requireId(ownerId)),
  reservePreparedChallenge: async row=>{
   requireId(row?.owner_user_id);requireId(row?.request_id);
   const out=await sql`
     SELECT batcave.general_control_reserve_prepared_staged_v1(
       ${row.owner_user_id}::uuid,${row.request_id}::uuid,
       ${row.nonce},${row.request_sha256},${row.policy_sha256},
       ${row.expires_at}::timestamptz,
       ${sql.json(row.request)}::jsonb,${sql.json(row.scope)}::jsonb
     ) AS receipt`;
   return out[0]?.receipt??null;
  },
  getPreparedChallenge: async (ownerId,requestId)=>{
   requireId(ownerId);requireId(requestId);
   const out=await sql`
     SELECT p.request_json AS request,p.request_sha256,
       n.state AS nonce_state
     FROM batcave.general_control_prepared_challenges_staged_v1 p
     JOIN batcave.general_control_nonce_ledger_v1 n
       ON n.request_id=p.request_id AND n.owner_user_id=p.owner_user_id
       AND n.nonce=p.nonce AND n.request_sha256=p.request_sha256
       AND n.policy_sha256=p.policy_sha256
     WHERE p.owner_user_id=${ownerId}::uuid AND p.request_id=${requestId}::uuid
     LIMIT 1`;
   return out[0]??null;
  },
  recordSignedOwnerEvidence: async row=>{
   requireId(row?.owner_user_id);requireId(row?.request_id);
   const out=await sql`
     SELECT batcave.general_control_record_owner_evidence_staged_v1(
       ${row.request_id}::uuid,${row.owner_user_id}::uuid,
       ${row.nonce},${row.request_sha256},${row.policy_sha256},
       ${row.signature_hex}) AS recorded`;
   return out[0]?.recorded===true ? {
     recorded:true,request_id:row.request_id,nonce:row.nonce,
     state:'owner_signature_recorded_only',
   } : {recorded:false};
  },
  declinePreparedChallenge: async row=>{
   requireId(row?.owner_user_id);requireId(row?.request_id);
   const out=await sql`
     SELECT batcave.general_control_decline_nonce_staged_v1(
       ${row.request_id}::uuid,${row.owner_user_id}::uuid,${row.nonce}
     ) AS declined`;
   return out[0]?.declined===true ? {
     declined:true,request_id:row.request_id,nonce:row.nonce,state:'declined',
   } : {declined:false};
  },
 });
}
