/**
 * STAGED, verification-only component for Oracle's existing owner/change gate.
 * This module does NOT enroll keys, authorize execution, or dispatch/deploy anything.
 * Trusted key records and replay state MUST come from the existing private gate,
 * never from an approval packet. No private keys are handled here.
 */
export const PIN = Object.freeze({
  intent_key: 'batcave.oracle.lab_v031.release_request.20261121',
  intent_sha256: 'ff41a4a74e25fd31bf9a466d1566100ba9e98cc5d8769fd01fe12c9c653c4e80',
  owner_gate_zip_sha256: '69ab19be8ec2e11e902716da59c2dda8693a3d3c78a16d8bdc1ded25a8d16851',
  worker_zip_sha256: '4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2',
  pr_head_sha: '33b62fae6ccb2224f04cce43443510b71c051297',
  target_device: 'Oracle',
  operation: 'model_generate_and_verify_v1',
  fixture: 'fixed_clamp_score_v1',
  scope: 'disposable_lab_only',
});
export const SCHEMA = 'batcave.oracle.pinned.release.v1';
export const OWNER_DOMAIN = 'batcave.oracle.owner.release.signature.v1\n';
export const NANNY_DOMAIN = 'batcave.oracle.independent_nanny.release.signature.v1\n';
const FIELDS = [
  'expires_at', 'fixture', 'intent_key', 'intent_sha256', 'issued_at', 'nonce',
  'operation', 'owner_gate_zip_sha256', 'owner_user_id', 'pr_head_sha',
  'schema', 'scope', 'target_device', 'worker_zip_sha256'
];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const encoder = new TextEncoder();
const keys = x => x && typeof x === 'object' && !Array.isArray(x) ? Object.keys(x).sort().join('|') : '';
const expectedKeys = FIELDS.join('|');
function deny(reason){throw new Error(reason);}
function b64bytes(value, expectedLength) {
  if(typeof value !== 'string' || !B64URL.test(value) || value.includes('=') || value.length !== expectedLength) deny('INVALID_BASE64URL');
  const arr = Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-value.length%4)%4)), x=>x.charCodeAt(0));
  if((expectedLength===43 && arr.length!==32) || (expectedLength===86 && arr.length!==64))deny('BAD_KEY_OR_SIGNATURE_SIZE');
  return arr;
}
function canonicalISO(s){
  if(typeof s!=='string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(s))return false;
  const d=Date.parse(s); return Number.isFinite(d)&&new Date(d).toISOString()===s;
}
function hex(bytes){return Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');}
async function fingerprint(raw){return hex(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)));}
function validatePayload(p, {authenticated_owner_id, now}) {
  if(keys(p)!==expectedKeys || Object.values(p).some(v=>typeof v!=='string')) deny('INVALID_PAYLOAD_SHAPE');
  if(p.schema!==SCHEMA)deny('WRONG_SCHEMA');
  for(const [k,v] of Object.entries(PIN))if(p[k]!==v) deny('WRONG_PIN_'+k);
  if(!UUID.test(authenticated_owner_id)||p.owner_user_id!==authenticated_owner_id)deny('OWNER_MISMATCH');
  if(!HEX32.test(p.nonce) || !HEX64.test(p.intent_sha256))deny('INVALID_NONCE_OR_HASH');
  if(!canonicalISO(p.issued_at)||!canonicalISO(p.expires_at))deny('INVALID_TIME');
  const begin=Date.parse(p.issued_at),end=Date.parse(p.expires_at);
  if(begin>now+30000||begin<now-10*60000||end<=now||end<=begin||end>begin+10*60000)deny('EXPIRED_OR_OVERSIZED_WINDOW');
}
function validateTrustedKey(key, expectedRole, owner, now){
  if(!key || key.role!==expectedRole || key.revoked_at!==null || key.registered!==true || key.owner_user_id!==owner)deny('UNTRUSTED_SIGNER');
  if(!HEX64.test(key.public_key_sha256)||typeof key.public_key_b64url!=='string')deny('BAD_SIGNER_KEY');
  if(key.valid_until !== null && (!canonicalISO(key.valid_until) || Date.parse(key.valid_until)<=now))deny('SIGNER_KEY_EXPIRED');
}
async function verifyOne(domain, signature, payloadText, trustedKey){
  const raw=b64bytes(trustedKey.public_key_b64url,43);
  if(await fingerprint(raw)!==trustedKey.public_key_sha256) deny('SIGNER_KEY_FINGERPRINT_MISMATCH');
  let ok=false;
  try{
    const key=await crypto.subtle.importKey('raw',raw,{name:'Ed25519'},false,['verify']);
    ok=await crypto.subtle.verify('Ed25519',key,b64bytes(signature,86),encoder.encode(domain+payloadText));
  } catch { deny('SIGNATURE_INVALID'); }
  if(!ok)deny('SIGNATURE_INVALID');
}
/**
 * Returns a cryptographic evidence verdict, NOT an executable grant.
 * The caller must independently verify its immutable origin, current exact artifact
 * bytes/hashes, one-use challenge, protected environment, separate release policy,
 * backup, staged rollout, postflight and rollback BEFORE any privileged release.
 */
export async function verifyReleaseEvidence({
  payload, owner_signature_b64url, nanny_signature_b64url,
  authenticated_owner_id, trusted_owner_key, trusted_nanny_key,
  nonce_issued_by_gate=false, nonce_consumed=false, now=Date.now()
}) {
  validatePayload(payload,{authenticated_owner_id,now});
  if(nonce_issued_by_gate!==true || nonce_consumed!==false)deny('NONCE_NOT_FRESH');
  validateTrustedKey(trusted_owner_key,'owner',authenticated_owner_id,now);
  validateTrustedKey(trusted_nanny_key,'independent_release_reviewer',authenticated_owner_id,now);
  if(trusted_nanny_key.public_key_sha256===trusted_owner_key.public_key_sha256)deny('SIGNER_NOT_INDEPENDENT');
  // The existing CORTANA LAB reviewer must never be promoted to production signer.
  if(trusted_nanny_key.public_key_sha256==='4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b')deny('LAB_KEY_CANNOT_SIGN_RELEASE');
  if(trusted_nanny_key.independently_attested!==true || trusted_nanny_key.release_policy_version!=='strict_nanny.release.v1')deny('MISSING_INDEPENDENT_ATTESTATION');
  if(trusted_nanny_key.private_key_custodian==='oracle_model' || trusted_nanny_key.private_key_custodian==='chatgpt')deny('MODEL_CANNOT_BE_SIGNER');
  if(typeof trusted_nanny_key.private_key_custodian!=='string'||!trusted_nanny_key.private_key_custodian.trim())deny('MISSING_REVIEWER_CUSTODIAN');
  const text=FIELDS.map(k=>k+'='+payload[k]).join('\n');
  await verifyOne(OWNER_DOMAIN,owner_signature_b64url,text,trusted_owner_key);
  await verifyOne(NANNY_DOMAIN,nanny_signature_b64url,text,trusted_nanny_key);
  return Object.freeze({
    cryptographic_evidence_valid:true,
    intent_key:payload.intent_key, nonce:payload.nonce,
    artifact_pair:[payload.owner_gate_zip_sha256,payload.worker_zip_sha256],
    independent_reviewer_key_sha256:trusted_nanny_key.public_key_sha256,
    owner_key_sha256:trusted_owner_key.public_key_sha256,
    expires_at:payload.expires_at,
    deployment_authorized:false, execution_authorized:false, grant_issued:false
  });
}
export function canonicalReleaseText(payload){
  if(keys(payload)!==expectedKeys)deny('INVALID_PAYLOAD_SHAPE');
  return FIELDS.map(k=>k+'='+payload[k]).join('\n');
}
