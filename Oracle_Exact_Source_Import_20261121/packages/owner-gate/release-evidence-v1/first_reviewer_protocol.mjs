/* One-time owner-root enrollment. Trusted policy comes from the private gate,
 * never from a request. No live operator identifiers or keys in public source.
 * Possession is NOT independent custody attestation or release permission.
 */
export const FIRST_BASIS='owner_signed_first_reviewer_bootstrap';
export const FIRST_VERSION='strict_nanny.owner_first_key.v1';
export const FIRST_SCHEMA='batcave.oracle.first_reviewer.enrollment.v1';
export const FIRST_OWNER_DOMAIN='batcave.oracle.first_reviewer.owner.signature.v1\n';
export const FIRST_PROOF_DOMAIN='batcave.oracle.first_reviewer.possession.signature.v1\n';
const POLICY_SCHEMA='batcave.oracle.owner_first_reviewer.policy.v1';
const SCOPE='first_reviewer_enrollment_only';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const H64=/^[a-f0-9]{64}$/;
const TE=new TextEncoder();
const POLICY_FIELDS='candidate_sha256|custody_evidence_sha256|host_identity_sha256|owner_key_sha256|owner_user_id|release_intent_key|release_intent_sha256|reviewer_key_sha256|reviewer_public_key_b64url|reviewer_sid|schema|scope|signer_valid_until|trust_basis';
const PAYLOAD_FIELDS='candidate_sha256|custody_evidence_sha256|expires_at|host_identity_sha256|issued_at|nonce|owner_key_sha256|owner_user_id|policy_sha256|reviewer_key_sha256|reviewer_sid|schema|scope|signer_valid_until|trust_basis';
const LAB_FINGERPRINTS=new Set(['4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b','61dde7b2e70af2d47746b75f401d87d57e41e123aeba185cc8ca6b7e1b05b664']);
const LAB_RAW='PkCiAsi_f6Cv2UkYCYZbE3z8L5pgUi339QB-yLVvKCo';
function must(v,s){if(!v)throw Error(s);}
function shape(v,keys){return v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join('|')===keys;}
export function firstStable(x){if(Array.isArray(x))return '['+x.map(firstStable).join(',')+']';if(x&&typeof x==='object')return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+firstStable(x[k])).join(',')+'}';return JSON.stringify(x);}
export function firstISO(s){return typeof s==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(s)&&Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s;}
function decode(s,size){must(typeof s==='string'&&new RegExp('^[A-Za-z0-9_-]{'+(size===32?43:86)+'}$').test(s),'FIRST_BAD_ENCODING');const b=Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),x=>x.charCodeAt(0));must(b.length===size&&btoa(String.fromCharCode(...b)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')===s,'FIRST_BAD_ENCODING');return b;}
export async function firstHash(s){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',typeof s==='string'?TE.encode(s):s)),b=>b.toString(16).padStart(2,'0')).join('');}
async function publicKey(k){const raw=decode(k.public_key_b64url,32);must(H64.test(k.public_key_sha256)&&await firstHash(raw)===k.public_key_sha256,'FIRST_KEY_HASH_MISMATCH');return crypto.subtle.importKey('raw',raw,{name:'Ed25519'},false,['verify']);}
export async function firstVerifySignature(k,text,sig){must(await crypto.subtle.verify('Ed25519',await publicKey(k),decode(sig,64),TE.encode(text)),'FIRST_SIGNATURE_INVALID');}
export async function validateFirstPolicy(record,{owner,now=Date.now(),requireUnused=false}={}){
 const p=record?.policy;
 must(shape(p,POLICY_FIELDS)&&Object.values(p).every(v=>typeof v==='string'),'FIRST_POLICY_REQUIRED');
 must(p.schema===POLICY_SCHEMA&&p.scope===SCOPE&&p.trust_basis===FIRST_BASIS,'FIRST_POLICY_SCOPE');
 must(p.release_intent_key==='batcave.oracle.lab_v031.release_request.20261121'&&p.release_intent_sha256==='ff41a4a74e25fd31bf9a466d1566100ba9e98cc5d8769fd01fe12c9c653c4e80','FIRST_POLICY_RELEASE_SCOPE');
 must(UUID.test(p.owner_user_id)&&H64.test(p.owner_key_sha256)&&['reviewer_key_sha256','candidate_sha256','host_identity_sha256','custody_evidence_sha256'].every(k=>H64.test(p[k])),'FIRST_POLICY_FIELDS');
 must(/^S-1-5-21-\d+-\d+-\d+-\d+$/.test(p.reviewer_sid)&&!LAB_FINGERPRINTS.has(p.reviewer_key_sha256)&&p.reviewer_public_key_b64url!==LAB_RAW&&p.reviewer_key_sha256!==p.owner_key_sha256,'FIRST_KEY_NOT_SEPARATE');
 await publicKey({public_key_b64url:p.reviewer_public_key_b64url,public_key_sha256:p.reviewer_key_sha256});
 must(record.revoked_at===null&&record.policy_sha256===await firstHash(firstStable(p)),'FIRST_POLICY_NOT_CURRENT');
 must(firstISO(p.signer_valid_until)&&Date.parse(p.signer_valid_until)>now,'FIRST_POLICY_EXPIRED');
 if(owner)must(owner.revoked_at===null&&owner.owner_user_id===p.owner_user_id&&owner.public_key_sha256===p.owner_key_sha256,'FIRST_OWNER_KEY_CHANGED');
 if(requireUnused)must(record.registered_at===null,'FIRST_ALREADY_REGISTERED');
 return p;
}
export async function validateFirstPayload(payload,record,owner,now=Date.now()){
 const policy=await validateFirstPolicy(record,{owner,now});
 must(shape(payload,PAYLOAD_FIELDS)&&Object.values(payload).every(v=>typeof v==='string')&&payload.schema===FIRST_SCHEMA,'FIRST_BAD_PAYLOAD');
 for(const k of ['owner_user_id','owner_key_sha256','reviewer_key_sha256','candidate_sha256','host_identity_sha256','reviewer_sid','custody_evidence_sha256','scope','trust_basis','signer_valid_until'])must(payload[k]===policy[k],'FIRST_POLICY_BINDING');
 must(payload.policy_sha256===record.policy_sha256&&/^[a-f0-9]{32}$/.test(payload.nonce),'FIRST_NONCE_OR_POLICY');
 const begin=Date.parse(payload.issued_at),end=Date.parse(payload.expires_at);
 must(firstISO(payload.issued_at)&&firstISO(payload.expires_at)&&begin<=now+30000&&begin>=now-600000&&end>now&&end>begin&&end<=begin+600000&&end<=Date.parse(policy.signer_valid_until),'FIRST_EXPIRED_CHALLENGE');
 return policy;
}
export function canonicalFirstText(p){must(shape(p,PAYLOAD_FIELDS),'FIRST_BAD_PAYLOAD');return firstStable(p);}
export async function verifyFirstOwner({payload,record,owner,owner_signature_b64url,now=Date.now()}){
 await validateFirstPayload(payload,record,owner,now);
 await firstVerifySignature(owner,FIRST_OWNER_DOMAIN+canonicalFirstText(payload),owner_signature_b64url);
 return payload;
}
export async function verifyFirstPair(args){
 await verifyFirstOwner(args);
 const p=args.record.policy;
 await firstVerifySignature({public_key_b64url:p.reviewer_public_key_b64url,public_key_sha256:p.reviewer_key_sha256},FIRST_PROOF_DOMAIN+canonicalFirstText(args.payload),args.proof_signature_b64url);
 return Object.freeze({enrollment_evidence_valid:true,trust_basis:FIRST_BASIS,independently_attested:false,deployment_authorized:false,execution_authorized:false,grant_issued:false});
}
export async function verifyRegisteredFirstReviewer({key,owner,record,now=Date.now()}){
 const p=await validateFirstPolicy(record,{owner,now}),c=record.registration_challenge;
 must(key?.trust_basis===FIRST_BASIS&&key.independently_attested===false&&key.release_policy_version===FIRST_VERSION&&key.public_key_sha256===p.reviewer_key_sha256&&key.public_key_b64url===p.reviewer_public_key_b64url,'FIRST_TRUST_RECORD_MISMATCH');
 must(firstISO(record.registered_at)&&Date.parse(record.registered_at)<=now&&record.registration_challenge_id===c?.id&&c?.kind==='first_key'&&c.owner_user_id===p.owner_user_id&&c.consumed_at===record.registered_at&&c.recorded_at===record.registered_at,'FIRST_REGISTRATION_RECEIPT_REQUIRED');
 must(c.payload_sha256===await firstHash(firstStable(c.payload))&&c.policy_sha256===record.policy_sha256&&c.nonce===c.payload.nonce&&c.owner_key_sha256===p.owner_key_sha256&&c.reviewer_key_sha256===p.reviewer_key_sha256&&c.issued_at===c.payload.issued_at&&c.expires_at===c.payload.expires_at,'FIRST_RECEIPT_BINDING');
 await verifyFirstPair({payload:c.payload,record,owner,owner_signature_b64url:c.owner_signature_b64url,proof_signature_b64url:c.reviewer_signature_b64url,now:Date.parse(c.recorded_at)});
 return p;
}
