/* Non-authorizing, pure typed-request validator for future owner signing.
 * IMPORTANT: binding MUST come from server-side authenticated and policy-verified
 * state, never from caller-supplied request data. No grant/lease/dispatch here.
 */
export const GENERAL_CONTROL_REQUEST_SCHEMA = 'batcave.general_control.owner_request.v1';
const KEYS = Object.freeze([
  'schema', 'owner_user_id', 'request_id', 'device', 'capability',
  'target_origin', 'target_session_id', 'command_digest', 'source_commit',
  'policy_digest', 'nonce', 'issued_at', 'expires_at', 'rollback_ref',
]);
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HEX64 = /^[a-f0-9]{64}$/;
const HEX40 = /^[a-f0-9]{40}$/;
const HEX32 = /^[a-f0-9]{32}$/;
const SESSION = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const CAPS = new Set(['host.read', 'host.write_reversible', 'browser.observe', 'browser.click', 'browser.type']);
const WRITE_CAPS = new Set(['host.write_reversible', 'browser.click', 'browser.type']);
const BINDINGS = Object.freeze([
  'owner_user_id', 'device', 'target_origin', 'target_session_id',
  'command_digest', 'source_commit', 'policy_digest',
]);
const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
function fail(code) { throw new Error('GENERAL_CONTROL_REQUEST_' + code); }
function plainRecord(x) {
  return x !== null && typeof x === 'object' && !Array.isArray(x) &&
    (Object.getPrototypeOf(x) === Object.prototype || Object.getPrototypeOf(x) === null);
}
function exactKeys(x, keys) {
  return plainRecord(x) && Object.keys(x).length === keys.length &&
    keys.every(key => Object.hasOwn(x, key));
}
function timestamp(x) {
  if (typeof x !== 'string' || !ISO.test(x)) fail('BAD_TIMESTAMP');
  const ms = Date.parse(x);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== x) fail('BAD_TIMESTAMP');
  return ms;
}
function validOrigin(x) {
  if (typeof x !== 'string' || x.length > 250 || !x.startsWith('https://')) return false;
  try {
    const u = new URL(x);
    return u.protocol === 'https:' && u.origin === x && !u.username && !u.password &&
      u.pathname === '/' && !u.search && !u.hash && !x.includes('*');
  } catch { return false; }
}
/** Validates immutable request against a trusted, independently supplied binding.
 * Returns exact bytes for a FUTURE signing operation but authorizes nothing.
 */
export function validateGeneralControlOwnerRequestV1(request, binding, now = Date.now()) {
  if (!exactKeys(request, KEYS)) fail('BAD_REQUEST_SHAPE');
  if (!exactKeys(binding, BINDINGS)) fail('TRUSTED_BINDING_REQUIRED');
  if (!Number.isSafeInteger(now) || now < 0) fail('INVALID_CLOCK');
  if (request.schema !== GENERAL_CONTROL_REQUEST_SCHEMA) fail('BAD_SCHEMA');
  if (!UUID.test(request.owner_user_id) || !UUID.test(request.request_id)) fail('BAD_OWNER_OR_REQUEST_ID');
  if (request.device !== 'Oracle' && request.device !== 'Cortana') fail('UNSUPPORTED_DEVICE');
  if (!CAPS.has(request.capability)) fail('UNSUPPORTED_CAPABILITY');
  if (!SESSION.test(request.target_session_id)) fail('INVALID_SESSION');
  if (!HEX64.test(request.command_digest) || !HEX64.test(request.policy_digest) ||
      !HEX40.test(request.source_commit) || !HEX32.test(request.nonce)) fail('BAD_DIGEST_OR_NONCE');
  const browser = request.capability.startsWith('browser.');
  if (browser ? !validOrigin(request.target_origin) : request.target_origin !== null) {
    fail('INVALID_TARGET_ORIGIN');
  }
  if (WRITE_CAPS.has(request.capability)) {
    if (typeof request.rollback_ref !== 'string' || !/^rollback:[a-f0-9]{64}$/.test(request.rollback_ref)) {
      fail('ROLLBACK_REQUIRED');
    }
  } else if (request.rollback_ref !== 'none') fail('UNEXPECTED_ROLLBACK');
  const issued = timestamp(request.issued_at);
  const expires = timestamp(request.expires_at);
  if (issued > now + 30000 || issued < now - 300000 || expires <= now ||
      expires <= issued || expires - issued > 300000) fail('EXPIRED_OR_INVALID_WINDOW');
  // This binding is not allowed to be supplied by the request submitter. Its
  // values must be derived from authenticated owner and server target/policy.
  for (const key of BINDINGS) {
    if (request[key] !== binding[key]) fail('TRUSTED_BINDING_MISMATCH');
  }
  const canonicalJson = JSON.stringify(Object.fromEntries(KEYS.map(key => [key, request[key]])));
  const signingMessage = GENERAL_CONTROL_REQUEST_SCHEMA + '\n' + canonicalJson;
  return Object.freeze({
    signing_message: signingMessage,
    signing_bytes: new TextEncoder().encode(signingMessage),
    execution_authorized: false,
    deployment_authorized: false,
    signature_verified: false,
  });
}
