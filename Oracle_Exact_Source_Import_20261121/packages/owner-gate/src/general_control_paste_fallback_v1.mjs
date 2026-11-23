// STAGED: read-only human paste fallback for an already validated typed request.
// Never interprets pasted text as shell, grants or signatures. Transport only.
import { validateGeneralControlOwnerRequestV1 } from './general_control_owner_request_v1.mjs';
const PREFIX = 'BATCAVE_GENERAL_CONTROL_REQUEST_V1 ';
const fields = ['schema','owner_user_id','request_id','device','capability','target_origin','target_session_id','command_digest','source_commit','policy_digest','nonce','issued_at','expires_at','rollback_ref'];
function base64url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}
function decode(text) {
  if(typeof text !== 'string' || text.length > 4096 || !text.startsWith(PREFIX)) throw Error('INVALID_PASTE_ENVELOPE');
  const b64 = text.slice(PREFIX.length);
  if(!/^[A-Za-z0-9_-]+$/.test(b64)) throw Error('INVALID_PASTE_ENVELOPE');
  const bytes = Buffer.from(b64,'base64url');
  if(base64url(bytes) !== b64) throw Error('NONCANONICAL_PASTE');
  const json = new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  const data = JSON.parse(json);
  if(!data || typeof data!=='object' || Array.isArray(data) || Object.keys(data).length!==fields.length || !fields.every(k=>Object.hasOwn(data,k))) throw Error('INVALID_REQUEST_FIELDS');
  return data;
}
export function createGeneralControlPasteFallbackV1(request, trustedBinding, now) {
  const checked = validateGeneralControlOwnerRequestV1(request,trustedBinding,now);
  const payload = JSON.parse(checked.signing_message.slice(checked.signing_message.indexOf('\n')+1));
  const paste = PREFIX + base64url(Buffer.from(JSON.stringify(payload),'utf8'));
  return Object.freeze({
    paste,
    instruction:'Paste this exact request into the existing authenticated Batcave owner-review inbox. Do not run it in a terminal. Review the device, browser origin, action and rollback; genuine owner and independent reviewer signatures are still required.',
    execution_authorized:false,
    signature_verified:false,
  });
}
export function parseGeneralControlPasteFallbackV1(paste, trustedBinding, now) {
  const payload = decode(paste);
  const checked = validateGeneralControlOwnerRequestV1(payload,trustedBinding,now);
  return Object.freeze({request:Object.freeze(payload),signing_message:checked.signing_message,execution_authorized:false,signature_verified:false});
}
