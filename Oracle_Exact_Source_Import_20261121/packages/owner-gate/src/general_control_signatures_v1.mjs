/* Pure, non-authorizing Ed25519 evidence verifier.
 * Caller MUST obtain trustedContext from authenticated owner session, server
 * registry, current policy and durable nonce ledger, never from the request.
 * No grants, leases, nonce consumption or production release here.
 */
import {createPublicKey, verify as verifySignature} from 'node:crypto';
import {validateGeneralControlOwnerRequestV1} from './general_control_owner_request_v1.mjs';

const HEX128 = /^[0-9a-f]{128}$/;
const SPKI_PREFIX = '302a300506032b6570032100';
function deny(reason) { return Object.freeze({status:'DENY',reason,execution_authorized:false}); }
function validKey(key) {
  if (typeof key !== 'string' || !/^[a-f0-9]{64}$/.test(key)) return null;
  try {
    return createPublicKey({key:Buffer.from(SPKI_PREFIX + key,'hex'),format:'der',type:'spki'});
  } catch { return null; }
}
function verifyDetached(keyHex, signatureHex, message) {
  const key = validKey(keyHex);
  if (!key || typeof signatureHex !== 'string' || !HEX128.test(signatureHex)) return false;
  try { return verifySignature(null,Buffer.from(message,'utf8'),key,Buffer.from(signatureHex,'hex')); }
  catch { return false; }
}
/** Checks signatures and independently supplied evidence, but cannot issue authority.
 * The request binding and reviewer identity/policy are *server-side* facts.
 * Both signatures cover the same canonical request, with distinct role domains.
 */
export function checkGeneralControlSignaturesV1(request, trustedContext, signatures, now=Date.now()) {
  if (!trustedContext || typeof trustedContext !== 'object' ||
      !trustedContext.binding || !trustedContext.owner || !trustedContext.reviewer ||
      !trustedContext.ledger || !trustedContext.policy) return deny('TRUSTED_CONTEXT_REQUIRED');
  let candidate;
  try { candidate=validateGeneralControlOwnerRequestV1(request,trustedContext.binding,now); }
  catch { return deny('INVALID_REQUEST_OR_BINDING'); }
  if (!signatures || typeof signatures !== 'object' || Array.isArray(signatures) ||
      Object.keys(signatures).sort().join(',') !== 'owner,reviewer') return deny('SIGNATURES_REQUIRED');
  const owner=trustedContext.owner, reviewer=trustedContext.reviewer;
  if (owner.authenticated !== true || owner.owner_user_id !== request.owner_user_id ||
      owner.key_scope !== 'general_control_owner_v1' || owner.key_state !== 'active') return deny('OWNER_NOT_ENROLLED_FOR_SCOPE');
  if (reviewer.independently_attested !== true || reviewer.key_state !== 'active' ||
      reviewer.key_scope !== 'general_control_privileged_reviewer_v1' ||
      reviewer.identity_id === owner.identity_id ||
      reviewer.key_hex === owner.key_hex) return deny('INDEPENDENT_REVIEWER_REQUIRED');
  if (trustedContext.policy.current !== true || trustedContext.policy.digest !== request.policy_digest ||
      trustedContext.policy.source_commit !== request.source_commit ||
      trustedContext.policy.capability_allowed !== true) return deny('POLICY_NOT_APPROVED');
  if (trustedContext.ledger.nonce_state !== 'unused' ||
      trustedContext.ledger.request_id !== request.request_id ||
      trustedContext.ledger.nonce !== request.nonce) return deny('NONCE_NOT_UNUSED');
  const payload=candidate.signing_message;
  if (!verifyDetached(owner.key_hex,signatures.owner,'BATCAVE_OWNER_GENERAL_CONTROL_V1\n'+payload)) return deny('INVALID_OWNER_SIGNATURE');
  if (!verifyDetached(reviewer.key_hex,signatures.reviewer,'BATCAVE_NANNY_GENERAL_CONTROL_V1\n'+payload)) return deny('INVALID_INDEPENDENT_SIGNATURE');
  return Object.freeze({status:'SIGNATURES_VALID_ONLY',reason:'REQUIRES_ATOMIC_NONCE_CONSUMPTION_AND_DEVICE_POLICY_GATE',
    request_id:request.request_id,execution_authorized:false,deployment_authorized:false});
}
