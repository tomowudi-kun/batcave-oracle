/* STAGED READ-ONLY. Query actual Batcave release, owner and device records.
 * Used only by the authenticated original-owner endpoint. No service writes,
 * enrollments, private keys, leases, policy changes or capability grants.
 * A 'source checks' result is NEVER a cryptographic release signature.
 */
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{40}$/;
const INTENT='batcave.general_control.pr3.owner_release_request.20261122';
const NEED=['Oracle','Cortana'];
function frozen(v) {return Object.freeze(v);}
export async function inspectGeneralControlLivePreflightSTAGED(sql, ownerId, sourceCommit) {
 if(typeof sql!=='function'||typeof ownerId!=='string'||!UUID.test(ownerId) ||
    typeof sourceCommit!=='string'||!SHA.test(sourceCommit))
   throw Error('TRUSTED_OWNER_AND_SOURCE_REQUIRED');
 // The DB session must be private. This function is forbidden from using
 // client Supabase/PostgREST credentials or accepting a caller-owned scope.
 const [intentRows,ruleRows,rootRows,reviewerRows,deviceRows]=await Promise.all([
  sql`SELECT state,owner_auth_state,nanny_review_state,valid_until,
    requested_scope FROM batcave.change_gate_intents
    WHERE intent_key=${INTENT} AND category='project_release' LIMIT 1`,
  sql`SELECT gate_mode,strict_nanny_required,batcave_identity_required,
    signed_scope_required FROM batcave.change_gate_rules
    WHERE category='project_release' LIMIT 1`,
  sql`SELECT count(*)::int AS active
    FROM batcave.linux_owner_keys_v1 WHERE owner_user_id=${ownerId}::uuid
    AND revoked_at IS NULL`,
  sql`SELECT count(*)::int AS qualified
    FROM batcave.oracle_release_keys_v1 WHERE owner_user_id=${ownerId}::uuid
    AND registered=true AND independently_attested=true
    AND production_release_authorized=true AND revoked_at IS NULL
    AND valid_until>clock_timestamp()`,
  sql`SELECT device_name,state,last_seen_at
    FROM batcave.devices WHERE device_name IN ('Oracle','Cortana')`,
 ]);
 const intent=intentRows?.[0]??null,rule=ruleRows?.[0]??null;
 const devices=Array.isArray(deviceRows)?deviceRows:[];
 const reasons=[];
 if(!intent)reasons.push('RELEASE_INTENT_MISSING');
 else {
  if(intent.state!=='released')reasons.push('RELEASE_NOT_SIGNED');
  if(intent.owner_auth_state!=='signed')reasons.push('OWNER_RELEASE_SIGNATURE_MISSING');
  if(intent.nanny_review_state!=='signed')reasons.push('INDEPENDENT_RELEASE_SIGNATURE_MISSING');
  if(Date.parse(intent.valid_until)<=Date.now())reasons.push('RELEASE_INTENT_EXPIRED');
  if(intent.requested_scope?.source_commit!==sourceCommit)
   reasons.push('EXACT_SOURCE_PIN_MISMATCH');
  if(intent.requested_scope?.deployment_authorized!==true)
   reasons.push('RELEASE_DEPLOYMENT_NOT_AUTHORIZED');
 }
 if(!rule || rule.gate_mode!=='enforce' || rule.strict_nanny_required!==true ||
    rule.batcave_identity_required!==true || rule.signed_scope_required!==true)
  reasons.push('PROJECT_RELEASE_GATE_NOT_ENFORCED');
 if(Number(rootRows?.[0]?.active)!==1)reasons.push('EXISTING_OWNER_KEY_UNAVAILABLE');
 if(Number(reviewerRows?.[0]?.qualified)<1)reasons.push('QUALIFIED_INDEPENDENT_SIGNER_MISSING');
 for(const device of NEED) {
  if(!devices.some(x=>x.device_name===device&&x.state==='active'))
    reasons.push(device.toUpperCase()+'_NOT_REGISTERED_ACTIVE');
 }
 // No session check or general_control_owner_v1 registration can be inferred
 // from this snapshot. Its sole role is to explain BLOCKED gates on phone.
 return frozen({
  schema:'batcave.general_control.preflight.readonly.v1',
  state:'SOURCE_FACTS_ONLY',
  blockers:frozen(reasons),
  device_registry:NEED.map(name=>frozen({
   device:name,registered_active:devices.some(x=>x.device_name===name&&x.state==='active'),
  })),
  existing_root_key_present:Number(rootRows?.[0]?.active)===1,
  registered_general_control_key_confirmed:false,
  signed_in_browser_session_confirmed:false,
  owner_signature_verified:false,independent_signature_verified:false,
  deployment_authorized:false,execution_authorized:false,grant_issued:false,
 });
}
