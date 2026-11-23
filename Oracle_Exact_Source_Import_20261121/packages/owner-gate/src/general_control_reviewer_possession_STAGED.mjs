/* STAGED ONLY: server-issued, nonce-bound proof of control of an existing
 * Ed25519 public candidate. This is NOT custody attestation, key enrollment,
 * privileged reviewer qualification, release, deployment, or a host grant.
 * Services/repository must be private server-resolved, NEVER from client claims.
 */
import {createHash,createPublicKey,randomBytes,randomUUID,verify} from 'node:crypto';
export const POP_SCHEMA='batcave.general_control.reviewer_possession_challenge.v1';
export const POP_DOMAIN='BATCAVE_GENERAL_CONTROL_CANDIDATE_POSSESSION_ONLY_V1\n';
const PROOF_SCHEMA='batcave.general_control.reviewer_possession_proof.v1';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const H32=/^[a-f0-9]{32}$/,H64=/^[a-f0-9]{64}$/,H128=/^[a-f0-9]{128}$/;
const RAW=/^[A-Za-z0-9_-]{43}$/;
const SPKI='302a300506032b6570032100';
const KEYS=['schema','purpose','request_id','draft_id','owner_user_id','candidate_key_sha256','candidate_public_b64url','host','account','sid','nonce','issued_at','expires_at','execution_authorized','deployment_authorized','grant_issued'];
const PROOF_KEYS=['schema','request_id','nonce','signature_hex'];
const exact=(x,keys)=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const sha=x=>createHash('sha256').update(x).digest('hex');
const denied=reason=>Object.freeze({status:'DENY',reason,execution_authorized:false,deployment_authorized:false,grant_issued:false});
function iso(s){return typeof s==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(s)&&Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s;}
export function candidatePublicBytes(p){
 if(typeof p!=='string'||!RAW.test(p))throw Error('INVALID_PUBLIC_KEY');
 const b=Buffer.from(p,'base64url');
 if(b.length!==32||b.toString('base64url')!==p)throw Error('INVALID_PUBLIC_KEY');
 return b;
}
export function possessionMessage(challenge,now=Date.now()){
 if(!exact(challenge,KEYS)||challenge.schema!==POP_SCHEMA||
 challenge.purpose!=='candidate_key_possession_only'||
 !UUID.test(challenge.request_id)||!UUID.test(challenge.draft_id)||
 !UUID.test(challenge.owner_user_id)||!H64.test(challenge.candidate_key_sha256)||
 challenge.host!=='Cortana'||challenge.account!=='StrictNannyRelease'||
 challenge.sid!=='S-1-5-21-349890097-2052580754-4142396749-1004'||
 !H32.test(challenge.nonce)||
 !iso(challenge.issued_at)||!iso(challenge.expires_at)||
 !Number.isSafeInteger(now)||Date.parse(challenge.issued_at)>now+30000||
 Date.parse(challenge.issued_at)<now-300000||
 Date.parse(challenge.expires_at)<=now||
 Date.parse(challenge.expires_at)-Date.parse(challenge.issued_at)>300000||
 challenge.execution_authorized!==false||challenge.deployment_authorized!==false||
 challenge.grant_issued!==false)throw Error('INVALID_OR_EXPIRED_CANDIDATE_CHALLENGE');
 const pub=candidatePublicBytes(challenge.candidate_public_b64url);
 if(sha(pub)!==challenge.candidate_key_sha256)throw Error('PUBLIC_KEY_FINGERPRINT_MISMATCH');
 return POP_DOMAIN+JSON.stringify(Object.fromEntries(KEYS.map(k=>[k,challenge[k]])));
}
function candidateValid(c,owner,draft){
 return c?.id===draft&&c?.owner_user_id===owner&&
 c?.kind==='general_control_public_reviewer_candidate_v1'&&
 c?.registered===false&&c?.independently_attested===false&&
 c?.production_release_authorized===false&&
 c?.execution_authorized===false&&c?.host==='Cortana'&&
 c?.account==='CORTANA\\StrictNannyRelease'&&
 c?.sid==='S-1-5-21-349890097-2052580754-4142396749-1004'&&
 H64.test(c.public_key_sha256_raw)&&
 sha(candidatePublicBytes(c.public_key_b64url_raw))===c.public_key_sha256_raw;
}
export async function issuePossessionChallengeSTAGED(input,session,services,now=Date.now()){
 if(!exact(input,['draft_id'])||!UUID.test(input.draft_id)||
 !session||session.authenticated_owner!==true||!UUID.test(session.owner_user_id)||
 !services||typeof services.getPrivateCandidate!=='function'||
 !services.repository||typeof services.repository.reserve!=='function')return denied('PRIVATE_OWNER_SESSION_REQUIRED');
 try{
  const c=await services.getPrivateCandidate(input.draft_id,session.owner_user_id);
  if(!candidateValid(c,session.owner_user_id,input.draft_id))return denied('ELIGIBLE_CANDIDATE_REQUIRED');
  const payload={schema:POP_SCHEMA,purpose:'candidate_key_possession_only',
   request_id:randomUUID(),draft_id:input.draft_id,owner_user_id:session.owner_user_id,
   candidate_key_sha256:c.public_key_sha256_raw,candidate_public_b64url:c.public_key_b64url_raw,
   host:'Cortana',account:'StrictNannyRelease',
   sid:'S-1-5-21-349890097-2052580754-4142396749-1004',
   nonce:randomBytes(16).toString('hex'),issued_at:new Date(now).toISOString(),
   expires_at:new Date(now+300000).toISOString(),
   execution_authorized:false,deployment_authorized:false,grant_issued:false};
  const text=possessionMessage(payload,now);
  const stored=await services.repository.reserve(payload,sha(text));
  if(stored?.reserved!==true||stored.request_id!==payload.request_id||
      stored.nonce!==payload.nonce)return denied('PRIVATE_NONCE_RESERVATION_REQUIRED');
  return Object.freeze({status:'AWAIT_EXPLICIT_KEY_POSSESSION_PROOF',
   challenge:payload,execution_authorized:false,deployment_authorized:false,grant_issued:false});
 }catch{return denied('CHALLENGE_NOT_ISSUED');}
}
export async function recordPossessionProofSTAGED(proof,services,now=Date.now()){
 if(!exact(proof,PROOF_KEYS)||proof.schema!==PROOF_SCHEMA||
 !UUID.test(proof.request_id)||!H32.test(proof.nonce)||!H128.test(proof.signature_hex)||
 !services?.repository||typeof services.repository.getPrepared!=='function'||
 typeof services.repository.recordProof!=='function'||
 typeof services.getPrivateCandidate!=='function')return denied('INVALID_PRIVATE_PROOF');
 try{
  const stored=await services.repository.getPrepared(proof.request_id,proof.nonce);
  if(stored?.state!=='unused'||!stored.payload)return denied('UNUSED_ISSUED_CHALLENGE_REQUIRED');
  const msg=possessionMessage(stored.payload,now);
  if(stored.signing_sha256!==sha(msg)||
    stored.payload.request_id!==proof.request_id||
    stored.payload.nonce!==proof.nonce)return denied('CHALLENGE_MODIFIED');
  const c=await services.getPrivateCandidate(stored.payload.draft_id,stored.payload.owner_user_id);
  if(!candidateValid(c,stored.payload.owner_user_id,stored.payload.draft_id)||
  c.public_key_sha256_raw!==stored.payload.candidate_key_sha256||
  c.public_key_b64url_raw!==stored.payload.candidate_public_b64url)return denied('CANDIDATE_CHANGED');
  // Rebuild the Ed25519 SPKI public key from the validated 32-byte raw key.
  const actual=createPublicKey({key:Buffer.concat([Buffer.from(SPKI,'hex'),candidatePublicBytes(c.public_key_b64url_raw)]),format:'der',type:'spki'});
  if(!verify(null,Buffer.from(msg),actual,Buffer.from(proof.signature_hex,'hex')))
    return denied('INVALID_CANDIDATE_SIGNATURE');
  const receipt=await services.repository.recordProof({
   request_id:proof.request_id,nonce:proof.nonce,draft_id:stored.payload.draft_id,
   owner_user_id:stored.payload.owner_user_id,candidate_key_sha256:stored.payload.candidate_key_sha256,
   signing_sha256:stored.signing_sha256,signature_hex:proof.signature_hex,
  });
  if(receipt?.recorded!==true||receipt.request_id!==proof.request_id||
    receipt.state!=='candidate_possession_recorded_only')return denied('NO_DURABLE_ONE_USE_RECEIPT');
  return Object.freeze({status:'CANDIDATE_POSSESSION_RECORDED_ONLY',
   request_id:proof.request_id,proof_of_possession_verified:true,
   independently_attested:false,registered:false,production_release_authorized:false,
   execution_authorized:false,deployment_authorized:false,grant_issued:false});
 }catch{return denied('PROOF_NOT_RECORDED');}
}
