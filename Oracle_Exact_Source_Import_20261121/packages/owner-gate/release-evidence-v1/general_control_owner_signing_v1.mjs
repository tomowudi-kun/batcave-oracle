/* STAGED ONLY. Owner-side browser signing adapter for a future authenticated,
 * one-use general-control approval route on the ORIGINAL owner-key origin.
 * The server, not this UI, must independently bind the authenticated owner,
 * active scope registration, current policy, command and durable unused nonce.
 * No creation, export, enrollment, authority grant, queueing or dispatch here.
 */
import {validateGeneralControlOwnerRequestV1} from '../src/general_control_owner_request_v1.mjs';

export const GENERAL_CONTROL_OWNER_CHALLENGE_SCHEMA = 'batcave.general_control.owner_challenge.v1';
export const GENERAL_CONTROL_OWNER_SIGNATURE_SCHEMA = 'batcave.general_control.owner_signature.v1';
export const GENERAL_CONTROL_OWNER_SIGNING_DOMAIN = 'BATCAVE_OWNER_GENERAL_CONTROL_V1\n';
const ORIGINAL_ORIGIN = 'https://batcave-linux-approval.vercel.app';
const HEX64 = /^[a-f0-9]{64}$/;
const B64URL = /^[A-Za-z0-9_-]{43}$/;
const CHALLENGE_KEYS = [
  'schema','request','signing_message','trusted_binding','scope_registration',
  'nonce_state','execution_authorized','deployment_authorized',
];
const REGISTRATION_KEYS = ['owner_user_id','key_scope','key_state','key_hex','revoked_at'];
function reject(code) { throw new Error('GENERAL_CONTROL_OWNER_SIGN_' + code); }
function exactKeys(obj, expected) {
  return obj !== null && typeof obj === 'object' && !Array.isArray(obj) &&
    Object.keys(obj).length === expected.length && expected.every(k => Object.hasOwn(obj,k));
}
function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2,'0')).join('');
}
function base64urlToBytes(input) {
  if(typeof input !== 'string' || !B64URL.test(input)) reject('INVALID_LOCAL_PUBLIC_KEY');
  const base64=input.replace(/-/g,'+').replace(/_/g,'/')+'=';
  let raw;
  try { raw=Uint8Array.from(atob(base64), c => c.charCodeAt(0)); }
  catch { reject('INVALID_LOCAL_PUBLIC_KEY'); }
  if(raw.length!==32) reject('INVALID_LOCAL_PUBLIC_KEY');
  // Require canonical, unpadded base64url encoding of exactly 32 bytes.
  if(btoa(String.fromCharCode(...raw)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')!==input)
    reject('INVALID_LOCAL_PUBLIC_KEY');
  return raw;
}
/** Read-only inspection. This object is NOT a user approval or a signed grant.
 * challenge must originate from the existing authenticated owner endpoint.
 */
export function inspectGeneralControlOwnerChallengeV1(challenge, ownerUserId, now=Date.now(), origin=ORIGINAL_ORIGIN) {
  if(origin!==ORIGINAL_ORIGIN) reject('WRONG_OWNER_ORIGIN');
  if(!exactKeys(challenge,CHALLENGE_KEYS) ||
     challenge.schema!==GENERAL_CONTROL_OWNER_CHALLENGE_SCHEMA ||
     challenge.execution_authorized!==false || challenge.deployment_authorized!==false)
    reject('INVALID_CHALLENGE_SHAPE');
  if(typeof ownerUserId!=='string' || challenge.request?.owner_user_id!==ownerUserId)
    reject('OWNER_MISMATCH');
  const reg=challenge.scope_registration;
  if(!exactKeys(reg,REGISTRATION_KEYS) || reg.owner_user_id!==ownerUserId ||
     reg.key_scope!=='general_control_owner_v1' || reg.key_state!=='active' ||
     !HEX64.test(reg.key_hex) || reg.revoked_at!==null)
    reject('GENERAL_SCOPE_KEY_NOT_REGISTERED');
  if(challenge.nonce_state!=='unused') reject('NONCE_NOT_AVAILABLE');
  let verified;
  try { verified=validateGeneralControlOwnerRequestV1(challenge.request,challenge.trusted_binding,now); }
  catch { reject('INVALID_SCOPE_OR_WINDOW'); }
  if(challenge.signing_message!==verified.signing_message) reject('SIGNING_BYTES_MISMATCH');
  const r=challenge.request;
  return Object.freeze({
    schema:r.schema,owner_user_id:r.owner_user_id,request_id:r.request_id,
    device:r.device,capability:r.capability,target_origin:r.target_origin,
    target_session_id:r.target_session_id,command_digest:r.command_digest,
    source_commit:r.source_commit,policy_digest:r.policy_digest,
    rollback_ref:r.rollback_ref,expires_at:r.expires_at,
    status:'REQUIRES_EXPLICIT_OWNER_CLICK',execution_authorized:false,deployment_authorized:false,
  });
}
/** Invoke only from an actual, explicit owner button interaction after showing
 * inspectGeneralControlOwnerChallengeV1's fields. consent must be true.
 * getOwnerKey may return an EXISTING non-exportable key, but only when the
 * authenticated backend has registered its public key for this NEW scope.
 * Final server verification must use its own registry and atomically consume
 * the nonce; this client cannot assert permission from a signature alone.
 */
export async function signGeneralControlOwnerChallengeV1({
  challenge, ownerUserId, getOwnerKey, consent=false, now=Date.now(), origin=ORIGINAL_ORIGIN,
}) {
  if(consent!==true) reject('OWNER_CLICK_REQUIRED');
  const preview=inspectGeneralControlOwnerChallengeV1(challenge,ownerUserId,now,origin);
  if(typeof getOwnerKey!=='function') reject('LOCAL_KEY_PROVIDER_REQUIRED');
  const saved=await getOwnerKey();
  const privateKey=saved?.privateKey;
  if(privateKey?.type!=='private' || privateKey.extractable!==false ||
     privateKey.algorithm?.name!=='Ed25519' || !privateKey.usages?.includes('sign'))
    reject('NONEXPORTABLE_KEY_REQUIRED');
  const publicKey=base64urlToBytes(saved.publicKeyB64);
  if(bytesToHex(publicKey)!==challenge.scope_registration.key_hex)
    reject('SCOPE_REGISTERED_PUBLIC_KEY_MISMATCH');
  const msg=GENERAL_CONTROL_OWNER_SIGNING_DOMAIN+challenge.signing_message;
  const signature=await crypto.subtle.sign('Ed25519',privateKey,new TextEncoder().encode(msg));
  return Object.freeze({
    schema:GENERAL_CONTROL_OWNER_SIGNATURE_SCHEMA,
    owner_user_id:ownerUserId, request_id:preview.request_id,
    nonce:challenge.request.nonce, signature_hex:bytesToHex(new Uint8Array(signature)),
    execution_authorized:false,deployment_authorized:false,
  });
}
