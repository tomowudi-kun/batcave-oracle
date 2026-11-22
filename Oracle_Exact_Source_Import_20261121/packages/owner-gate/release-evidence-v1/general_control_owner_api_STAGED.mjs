/* STAGED, NOT MOUNTED. Authenticated server-side owner Yes/No route.
 * Integrators MUST provide private, parameterized repository operations.
 * Never exposes private batcave tables, grants, leases or model dispatch.
 * A verified owner signature is only owner evidence; independent reviewer
 * attestation and a separate capability-specific gate are still required.
 */
import {
  GENERAL_CONTROL_REQUEST_SCHEMA,
  validateGeneralControlOwnerRequestV1,
} from '../src/general_control_owner_request_v1.mjs';
import {
  GENERAL_CONTROL_OWNER_CHALLENGE_SCHEMA,
  GENERAL_CONTROL_OWNER_SIGNATURE_SCHEMA,
  GENERAL_CONTROL_OWNER_SIGNING_DOMAIN,
} from './general_control_owner_signing_v1.mjs';

const ORIGIN = 'https://batcave-linux-approval.vercel.app';
const HEX128 = /^[0-9a-f]{128}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SCOPE_KEYS = ['device','capability','target_origin','target_session_id',
  'command_digest','source_commit','policy_digest','rollback_ref'];
const OWNER_KEY_KEYS = ['owner_user_id','key_scope','key_state','key_hex','revoked_at'];
const EVIDENCE_KEYS = ['schema','owner_user_id','request_id','nonce','signature_hex',
  'execution_authorized','deployment_authorized'];
const ACTIONS = Object.freeze({
  prepare:'general_control_prepare_owner_v1',
  record:'general_control_record_owner_v1',
  decline:'general_control_decline_owner_v1',
});
function keys(x,k) {
  return x!==null && typeof x==='object' && !Array.isArray(x) &&
    Object.keys(x).length===k.length && k.every(a=>Object.hasOwn(x,a));
}
function deny(code,status=403) {
  return Object.freeze({status,body:{error:'GENERAL_CONTROL_'+code,
    execution_authorized:false,deployment_authorized:false}});
}
function goodOwner(ctx) {
  return ctx?.owner_authenticated===true &&
    typeof ctx.owner_user_id==='string' && UUID.test(ctx.owner_user_id) &&
    ctx.origin===ORIGIN;
}
function validRegistration(key,ownerId) {
  return keys(key,OWNER_KEY_KEYS) &&
    key.owner_user_id===ownerId && key.key_scope==='general_control_owner_v1' &&
    key.key_state==='active' && key.revoked_at===null && HEX64.test(key.key_hex);
}
function binding(ownerId,scope) {
  return {owner_user_id:ownerId,device:scope.device,target_origin:scope.target_origin,
    target_session_id:scope.target_session_id,command_digest:scope.command_digest,
    source_commit:scope.source_commit,policy_digest:scope.policy_digest};
}
function sameScope(request,scope) {
  return keys(scope,SCOPE_KEYS) && SCOPE_KEYS.every(k=>request[k]===scope[k]);
}
const bytesToHex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
async function sha256(text) {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256',
    new TextEncoder().encode(text))));
}
async function verifyOwnerSignature(keyHex,signatureHex,message) {
  if(!HEX64.test(keyHex)||typeof signatureHex!=='string'||!HEX128.test(signatureHex))
    return false;
  try {
    const key=await crypto.subtle.importKey('raw',
      Uint8Array.from(keyHex.match(/.{2}/g),v=>parseInt(v,16)),
      {name:'Ed25519'},false,['verify']);
    return await crypto.subtle.verify('Ed25519',key,
      Uint8Array.from(signatureHex.match(/.{2}/g),v=>parseInt(v,16)),
      new TextEncoder().encode(GENERAL_CONTROL_OWNER_SIGNING_DOMAIN+message));
  } catch { return false; }
}
/** Service-only repo contract (NOT an implementation or deployed route):
 * getPendingScope(ownerId) -> exact trusted scope, current policy/session.
 * getScopeRegistration(ownerId) -> separately enrolled general_control_owner_v1 key.
 * reservePreparedChallenge(row) -> atomic reservation of request + digest
 *   and unused nonce, with a one-active-request-per-owner policy.
 * getPreparedChallenge(ownerId,requestId) -> exact persisted request, hash,
 *   nonce_state and expiry; never reconstruct from client data.
 * getCurrentScope(ownerId,requestId) -> fresh server-authoritative scope.
 * recordSignedOwnerEvidence(row) -> atomically consume reserved unused nonce
 *   AND append signed owner-evidence receipt in same transaction.
 * declinePreparedChallenge(row) -> atomically decline matching unused nonce.
 * These operations must be private, invoker/least-privilege and fail closed.
 */
export async function handleGeneralControlOwnerApiV1(body,ctx,repo,now=Date.now()) {
  if(!goodOwner(ctx)) return deny('AUTHENTICATED_ORIGINAL_OWNER_REQUIRED',401);
  if(!Number.isSafeInteger(now)||now<0 || !body || typeof body!=='object' ||
     Array.isArray(body) || typeof body.action!=='string') return deny('INVALID_REQUEST',422);
  if(!repo || typeof repo!=='object') return deny('PRIVATE_REPOSITORY_REQUIRED',503);
  const ownerId=ctx.owner_user_id;
  if(body.action===ACTIONS.prepare) {
    if(!keys(body,['action']))return deny('BAD_PREPARE_SHAPE',422);
    if(['getPendingScope','getScopeRegistration','reservePreparedChallenge']
      .some(method=>typeof repo[method]!=='function'))return deny('PRIVATE_REPOSITORY_REQUIRED',503);
    try {
      const scope=await repo.getPendingScope(ownerId);
      const reg=await repo.getScopeRegistration(ownerId);
      if(!keys(scope,SCOPE_KEYS) || !validRegistration(reg,ownerId))
        return deny('PENDING_SCOPE_OR_KEY_REQUIRED');
      const request={
        schema:GENERAL_CONTROL_REQUEST_SCHEMA,owner_user_id:ownerId,
        request_id:crypto.randomUUID(),device:scope.device,capability:scope.capability,
        target_origin:scope.target_origin,target_session_id:scope.target_session_id,
        command_digest:scope.command_digest,source_commit:scope.source_commit,
        policy_digest:scope.policy_digest,
        nonce:bytesToHex(crypto.getRandomValues(new Uint8Array(16))),
        issued_at:new Date(now).toISOString(),
        expires_at:new Date(now+180000).toISOString(),rollback_ref:scope.rollback_ref,
      };
      const trustedBinding=binding(ownerId,scope);
      const check=validateGeneralControlOwnerRequestV1(request,trustedBinding,now);
      const requestHash=await sha256(check.signing_message);
      const row={owner_user_id:ownerId,request_id:request.request_id,
        nonce:request.nonce,request_sha256:requestHash,policy_sha256:request.policy_digest,
        expires_at:request.expires_at,request,scope,nonce_state:'unused'};
      const reserved=await repo.reservePreparedChallenge(row);
      if(!reserved || reserved.inserted!==true ||
        reserved.request_id!==request.request_id ||
        reserved.nonce!==request.nonce ||
        reserved.request_sha256!==requestHash ||
        reserved.nonce_state!=='unused')return deny('CHALLENGE_RESERVATION_FAILED',409);
      return {status:200,body:Object.freeze({
        schema:GENERAL_CONTROL_OWNER_CHALLENGE_SCHEMA,request,
        signing_message:check.signing_message,trusted_binding:trustedBinding,
        scope_registration:reg,nonce_state:'unused',
        execution_authorized:false,deployment_authorized:false,
      })};
    } catch { return deny('CHALLENGE_NOT_PREPARED',409); }
  }
  if(body.action===ACTIONS.record || body.action===ACTIONS.decline) {
    if(['getPreparedChallenge','getCurrentScope','getScopeRegistration']
      .some(method=>typeof repo[method]!=='function'))return deny('PRIVATE_REPOSITORY_REQUIRED',503);
    let requestId,nonce,signatureHex;
    if(body.action===ACTIONS.record) {
      if(!keys(body,['action','evidence'])||!keys(body.evidence,EVIDENCE_KEYS))
        return deny('BAD_OWNER_EVIDENCE',422);
      const ev=body.evidence;
      if(ev.schema!==GENERAL_CONTROL_OWNER_SIGNATURE_SCHEMA ||
        ev.execution_authorized!==false || ev.deployment_authorized!==false ||
        ev.owner_user_id!==ownerId || !UUID.test(ev.request_id) ||
        !HEX32.test(ev.nonce) || !HEX128.test(ev.signature_hex))
        return deny('BAD_OWNER_EVIDENCE',422);
      requestId=ev.request_id;nonce=ev.nonce;signatureHex=ev.signature_hex;
      if(typeof repo.recordSignedOwnerEvidence!=='function')
        return deny('PRIVATE_REPOSITORY_REQUIRED',503);
    } else {
      if(!keys(body,['action','owner_user_id','request_id','nonce']) ||
        body.owner_user_id!==ownerId || !UUID.test(body.request_id) || !HEX32.test(body.nonce))
        return deny('BAD_DECLINE',422);
      requestId=body.request_id;nonce=body.nonce;
      if(typeof repo.declinePreparedChallenge!=='function')
        return deny('PRIVATE_REPOSITORY_REQUIRED',503);
    }
    try {
      const saved=await repo.getPreparedChallenge(ownerId,requestId);
      if(!saved || saved.nonce_state!=='unused' || saved.request?.owner_user_id!==ownerId ||
        saved.request.request_id!==requestId || saved.request.nonce!==nonce ||
        !HEX64.test(saved.request_sha256))return deny('STALE_OR_UNKNOWN_CHALLENGE',409);
      const scope=await repo.getCurrentScope(ownerId,requestId);
      if(!sameScope(saved.request,scope))return deny('POLICY_OR_SESSION_CHANGED',409);
      const checked=validateGeneralControlOwnerRequestV1(saved.request,binding(ownerId,scope),now);
      const digest=await sha256(checked.signing_message);
      if(digest!==saved.request_sha256)return deny('CHALLENGE_HASH_MISMATCH',409);
      const reg=await repo.getScopeRegistration(ownerId);
      if(!validRegistration(reg,ownerId))return deny('OWNER_SCOPE_KEY_REVOKED',403);
      if(body.action===ACTIONS.record) {
        if(!await verifyOwnerSignature(reg.key_hex,signatureHex,checked.signing_message))
          return deny('INVALID_OWNER_SIGNATURE');
        const recorded=await repo.recordSignedOwnerEvidence({
          owner_user_id:ownerId,request_id:requestId,nonce,
          request_sha256:digest,policy_sha256:saved.request.policy_digest,
          signature_hex:signatureHex,expires_at:saved.request.expires_at,
        });
        if(!recorded || recorded.recorded!==true ||
           recorded.request_id!==requestId || recorded.nonce!==nonce ||
           recorded.state!=='owner_signature_recorded_only')
          return deny('OWNER_EVIDENCE_NOT_RECORDED',409);
        return {status:200,body:{
          schema:'batcave.general_control.owner_evidence_receipt.v1',
          owner_user_id:ownerId,request_id:requestId,nonce,
          state:'owner_signature_recorded_only',
          execution_authorized:false,deployment_authorized:false,
        }};
      }
      const declined=await repo.declinePreparedChallenge({
        owner_user_id:ownerId,request_id:requestId,nonce,
        request_sha256:digest,policy_sha256:saved.request.policy_digest,
      });
      if(!declined || declined.declined!==true || declined.request_id!==requestId ||
        declined.nonce!==nonce || declined.state!=='declined')
        return deny('DECLINE_NOT_RECORDED',409);
      return {status:200,body:{
        schema:'batcave.general_control.owner_decline_receipt.v1',
        owner_user_id:ownerId,request_id:requestId,nonce,state:'declined',
        execution_authorized:false,deployment_authorized:false,
      }};
    } catch {return deny('OWNER_EVIDENCE_OR_DECLINE_NOT_CONFIRMED',409);}
  }
  return deny('UNSUPPORTED_ACTION',400);
}
