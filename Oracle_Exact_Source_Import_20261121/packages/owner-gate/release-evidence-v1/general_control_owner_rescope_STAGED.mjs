/* STAGED ONLY, NEVER MOUNTED FOR PRODUCTION.
 * Reuses the EXISTING non-extractable original-origin owner signing key with
 * an explicitly domain-separated signature to ENDORSE a new limited scope.
 * It never implicitly upgrades the old lab key or activates general control.
 * The server must store a prepared challenge and atomically record the signed
 * endorsement in a private repository, with its state kept PENDING until an
 * independent, attested privileged reviewer approves the SAME exact scope.
 */
export const RESCOPE_SCHEMA='batcave.general_control.owner_rescope_challenge.v1';
export const RESCOPE_SIGNATURE_SCHEMA='batcave.general_control.owner_rescope_signature.v1';
export const RESCOPE_DOMAIN='BATCAVE_ROOT_TO_GENERAL_CONTROL_SCOPE_V1\n';
const ORIGIN='https://batcave-linux-approval.vercel.app';
const KEYS=['schema','owner_user_id','challenge_id','nonce','root_key_sha256',
 'scope_public_key_hex','source_commit','policy_digest','issued_at','expires_at',
 'execution_authorized','deployment_authorized'];
const EVIDENCE_KEYS=['schema','owner_user_id','challenge_id','nonce','signature_hex',
 'execution_authorized','deployment_authorized'];
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const H64=/^[0-9a-f]{64}$/;
const H40=/^[0-9a-f]{40}$/;
const H32=/^[0-9a-f]{32}$/;
const H128=/^[0-9a-f]{128}$/;
const B64=/^[A-Za-z0-9_-]{43}$/;
function fail(reason){throw Error('GENERAL_CONTROL_RESCOPE_'+reason);}
function exact(x,k){
 return x&&typeof x==='object'&&!Array.isArray(x)&&
  Object.keys(x).length===k.length&&k.every(y=>Object.hasOwn(x,y));
}
function toHex(x){return Array.from(x,b=>b.toString(16).padStart(2,'0')).join('');}
function fromB64(s){
 if(typeof s!=='string'||!B64.test(s))fail('BAD_ROOT_KEY');
 const bytes=Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='),c=>c.charCodeAt(0));
 if(bytes.length!==32||btoa(String.fromCharCode(...bytes)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')!==s)
   fail('BAD_ROOT_KEY');
 return bytes;
}
function iso(s){
 return typeof s==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(s)&&
  Number.isFinite(Date.parse(s))&&new Date(Date.parse(s)).toISOString()===s;
}
function canonical(payload){
 if(!exact(payload,KEYS))fail('BAD_SHAPE');
 return JSON.stringify(Object.fromEntries(KEYS.map(k=>[k,payload[k]])));
}
/** The supplied root and policy must have been read by the AUTHENTICATED
 * server from its own database, never derived from browser input.
 */
export async function validateOwnerRescopeChallengeSTAGED(payload,server,now=Date.now()){
 if(!server||server.origin!==ORIGIN||server.authenticated!==true||
    !UUID.test(server.owner_user_id)||!UUID.test(payload?.owner_user_id)||
    server.owner_user_id!==payload.owner_user_id)fail('AUTHENTICATION_REQUIRED');
 const json=canonical(payload);
 if(payload.schema!==RESCOPE_SCHEMA||payload.execution_authorized!==false||
    payload.deployment_authorized!==false||!UUID.test(payload.challenge_id)||
    !H32.test(payload.nonce)||!H64.test(payload.root_key_sha256)||
    !H64.test(payload.scope_public_key_hex)||!H40.test(payload.source_commit)||
    !H64.test(payload.policy_digest))fail('BAD_SCOPE_OR_FIELDS');
 if(!iso(payload.issued_at)||!iso(payload.expires_at)||!Number.isSafeInteger(now)||
    Date.parse(payload.issued_at)>now+30000||Date.parse(payload.issued_at)<now-300000||
    Date.parse(payload.expires_at)<=now||
    Date.parse(payload.expires_at)-Date.parse(payload.issued_at)>300000)
    fail('STALE_CHALLENGE');
 if(server.source_commit!==payload.source_commit||
    server.policy_digest!==payload.policy_digest)fail('SOURCE_OR_POLICY_CHANGED');
 const root=server.root;
 if(root?.owner_user_id!==payload.owner_user_id||root?.revoked_at!==null||
    !H64.test(root?.public_key_sha256)||typeof root?.public_key_b64url!=='string')
    fail('ENROLLED_ROOT_REQUIRED');
 const publicKey=fromB64(root.public_key_b64url);
 const keyHash=toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',publicKey)));
 if(keyHash!==root.public_key_sha256||keyHash!==payload.root_key_sha256||
    toHex(publicKey)!==payload.scope_public_key_hex)fail('ROOT_OR_SCOPE_KEY_MISMATCH');
 return Object.freeze({text:RESCOPE_DOMAIN+json,owner_user_id:payload.owner_user_id,
  challenge_id:payload.challenge_id,nonce:payload.nonce,
  key_hex:payload.scope_public_key_hex,source_commit:payload.source_commit,
  policy_digest:payload.policy_digest,execution_authorized:false,deployment_authorized:false});
}
/** Invoke exclusively from an actual owner Yes button click after displaying
 * challenge information. No key creation, export, reuse of old lab signatures,
 * silent enrollment, grant or auto-approval.
 */
export async function signOwnerRescopeOnClickSTAGED({
 challenge,server,getOwnerKey,consent=false,origin=ORIGIN,now=Date.now()
}={}){
 if(consent!==true)fail('EXPLICIT_OWNER_CLICK_REQUIRED');
 if(origin!==ORIGIN)fail('WRONG_ORIGIN');
 const valid=await validateOwnerRescopeChallengeSTAGED(challenge,server,now);
 if(typeof getOwnerKey!=='function')fail('LOCAL_OWNER_KEY_REQUIRED');
 const existing=await getOwnerKey();
 const privateKey=existing?.privateKey;
 if(privateKey?.type!=='private'||privateKey.extractable!==false||
    privateKey.algorithm?.name!=='Ed25519'||!privateKey.usages?.includes('sign'))
   fail('NONEXPORTABLE_OWNER_KEY_REQUIRED');
 if(toHex(fromB64(existing.publicKeyB64))!==valid.key_hex)
   fail('DIFFERENT_BROWSER_PROFILE_KEY');
 const signed=await crypto.subtle.sign('Ed25519',privateKey,new TextEncoder().encode(valid.text));
 return Object.freeze({schema:RESCOPE_SIGNATURE_SCHEMA,
  owner_user_id:valid.owner_user_id,challenge_id:valid.challenge_id,nonce:valid.nonce,
  signature_hex:toHex(new Uint8Array(signed)),
  execution_authorized:false,deployment_authorized:false});
}
/** Server-only admission. Repository getPrepared and recordPending must be
 * private and atomic, with nonce/request-key equality and one-use enforcement.
 * Recording endorsement MUST NOT set an active scope key or change gate rules.
 */
export async function recordOwnerRescopePendingSTAGED(evidence,server,repository,now=Date.now()){
 if(!exact(evidence,EVIDENCE_KEYS)||evidence.schema!==RESCOPE_SIGNATURE_SCHEMA||
    evidence.execution_authorized!==false||evidence.deployment_authorized!==false||
    !UUID.test(evidence.challenge_id)||!H32.test(evidence.nonce)||
    !H128.test(evidence.signature_hex)||
    evidence.owner_user_id!==server?.owner_user_id)
   return Object.freeze({status:'DENY',reason:'BAD_OWNER_EVIDENCE',execution_authorized:false});
 if(server?.authenticated!==true||server?.origin!==ORIGIN||
    typeof repository?.getPrepared!=='function'||typeof repository?.recordPending!=='function')
   return Object.freeze({status:'DENY',reason:'PRIVATE_AUTHENTICATED_ROUTE_REQUIRED',execution_authorized:false});
 try{
  const stored=await repository.getPrepared(server.owner_user_id,evidence.challenge_id);
  if(!stored||stored.state!=='unused'||stored.challenge?.challenge_id!==evidence.challenge_id||
     stored.challenge.nonce!==evidence.nonce)
    throw Error('UNUSED_CHALLENGE_REQUIRED');
  const checked=await validateOwnerRescopeChallengeSTAGED(stored.challenge,server,now);
  const publicKey=await crypto.subtle.importKey('raw',fromB64(server.root.public_key_b64url),
   {name:'Ed25519'},false,['verify']);
  const sig=Uint8Array.from(evidence.signature_hex.match(/.{2}/g),x=>parseInt(x,16));
  if(!await crypto.subtle.verify('Ed25519',publicKey,sig,new TextEncoder().encode(checked.text)))
    throw Error('BAD_SIGNATURE');
  const receipt=await repository.recordPending({
   owner_user_id:checked.owner_user_id,challenge_id:checked.challenge_id,
   nonce:checked.nonce,key_hex:checked.key_hex,
   root_key_sha256:stored.challenge.root_key_sha256,
   policy_digest:checked.policy_digest,source_commit:checked.source_commit,
   signature_hex:evidence.signature_hex,
  });
  if(receipt?.recorded!==true||receipt.challenge_id!==checked.challenge_id||
     receipt.state!=='pending_independent_review')throw Error('RECEIPT_NOT_CONFIRMED');
  return Object.freeze({status:'OWNER_SCOPE_ENDORSED_PENDING_INDEPENDENT',
   challenge_id:checked.challenge_id,key_state:'pending_independent_review',
   owner_signature_recorded:true,independent_signature_recorded:false,
   execution_authorized:false,deployment_authorized:false,grant_issued:false});
 }catch{
  return Object.freeze({status:'DENY',reason:'OWNER_RESCOPE_NOT_RECORDED',
   execution_authorized:false,deployment_authorized:false,grant_issued:false});
 }
}
