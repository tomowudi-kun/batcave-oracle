/* Exact owner signature for lab-only Cortana reviewer enrollment.
 * Pure verification. Never signs, deploys, or grants a production release.
 */
export const DOMAIN='batcave.oracle.lab.reviewer.enroll.v2';
export const REVIEWER_KEY='4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b';
// COMPATIBILITY ONLY: this is the lab fixture token embedded in Cortana's installed reviewer.
// Despite sharing the older v0.3 ZIP digest, it is NOT a valid release-artifact authorization.
export const FIXTURE_TOKEN='4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f';
// Distinct audited release archive; old v0.3 ZIP must never authorize installation.
export const RELEASE_SHA='4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HEX32=/^[a-f0-9]{32}$/;
const TE=new TextEncoder();
function fail(s){throw Error(s);}
function bytes(s){if(typeof s!=='string'|| !/^[A-Za-z0-9_-]+$/.test(s)) fail('BAD_B64');return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));}
export function canonicalEnrollmentMessage(o){
 return [DOMAIN,o.owner_user_id,'CORTANA','S-1-5-19',REVIEWER_KEY,'lab_reviewer_only',FIXTURE_TOKEN,RELEASE_SHA,o.nonce,o.expires_at].join('\n');
}
export async function verifyOwnerEnrollmentV2({request,signature_b64url,ownerKey,authenticatedOwnerId,challenge,now=Date.now()}){
 const keys='expires_at|fixture_token|host|nonce|owner_user_id|release_archive_sha256|reviewer_key_sha256|reviewer_sid|role|schema';
 if(!request||Object.keys(request).sort().join('|')!==keys)fail('BAD_ENROLLMENT_SHAPE');
 if(request.schema!==DOMAIN||request.host!=='CORTANA'||request.reviewer_sid!=='S-1-5-19'||request.role!=='lab_reviewer_only'||request.reviewer_key_sha256!==REVIEWER_KEY||request.fixture_token!==FIXTURE_TOKEN||request.release_archive_sha256!==RELEASE_SHA)fail('WRONG_SCOPE');
 if(request.owner_user_id!==authenticatedOwnerId||!UUID.test(authenticatedOwnerId)||!HEX32.test(request.nonce))fail('WRONG_OWNER');
 if(!challenge||challenge.owner_user_id!==authenticatedOwnerId||challenge.nonce!==request.nonce||new Date(challenge.expires_at).toISOString()!==request.expires_at||challenge.consumed_at!==null)fail('WRONG_CHALLENGE');
 const expiry=Date.parse(request.expires_at);
 if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(request.expires_at)||!Number.isFinite(expiry)||expiry<=now||expiry>now+10*60000)fail('EXPIRED_CHALLENGE');
 if(!ownerKey||ownerKey.revoked_at!==null||ownerKey.owner_user_id!==authenticatedOwnerId||typeof ownerKey.public_key_b64url!=='string'||ownerKey.public_key_b64url.length!==43)fail('NO_OWNER_KEY');
 if(typeof signature_b64url!=='string'||signature_b64url.length!==86)fail('BAD_OWNER_SIGNATURE');
 let valid=false;
 try{
  const pub=await crypto.subtle.importKey('raw',bytes(ownerKey.public_key_b64url),{name:'Ed25519'},false,['verify']);
  valid=await crypto.subtle.verify('Ed25519',pub,bytes(signature_b64url),TE.encode(canonicalEnrollmentMessage(request)));
 }catch{fail('BAD_OWNER_SIGNATURE');}
 if(!valid)fail('BAD_OWNER_SIGNATURE');
 return Object.freeze({eligible:true,owner_user_id:authenticatedOwnerId,reviewer_key_sha256:REVIEWER_KEY,fixture_token:FIXTURE_TOKEN,release_archive_sha256:RELEASE_SHA,nonce:request.nonce,expires_at:request.expires_at,production_authorized:false});
}
