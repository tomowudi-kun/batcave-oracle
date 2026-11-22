/* STAGED addition to the EXISTING owner portal, on its original key origin.
 * Reuses injected authenticated API and IndexedDB lookup. Never creates/exports keys.
 * Preparing does not sign; signing requires a separate explicit local button.
 */
import {PIN,SCHEMA,OWNER_DOMAIN,canonicalReleaseText} from './verify_release_approval_v1.mjs';
import {ENROLL_DOMAIN,canonicalEnrollmentText} from './release_gate_core.mjs';
import {FIRST_BASIS,FIRST_OWNER_DOMAIN,FIRST_PROOF_DOMAIN,firstStable,firstHash,canonicalFirstText,validateFirstPayload,firstVerifySignature} from './first_reviewer_protocol.mjs';
export function releaseOwnerActions({api,getOwnerId,getOwnerKey,origin,getTrustedOwner,now=Date.now}){
 if(origin!=='https://batcave-linux-approval.vercel.app')throw Error('Use the original Batcave owner-key origin.');
 function validate(ch,kind){
  const p=ch?.payload;
  if(!p||p.owner_user_id!==getOwnerId()||typeof ch.challenge_id!=='string'||!/^[a-f0-9]{32}$/.test(p.nonce)||!Number.isFinite(Date.parse(p.issued_at))||!Number.isFinite(Date.parse(p.expires_at))||Date.parse(p.issued_at)>now()+30000||Date.parse(p.expires_at)<=now()||Date.parse(p.expires_at)>Date.parse(p.issued_at)+600000)throw Error('Invalid or expired owner challenge.');
  if(kind==='release'){
   if(p.schema!==SCHEMA||Object.entries(PIN).some(([k,v])=>p[k]!==v))throw Error('Release scope differs from the reviewed Oracle artifacts.');
  }else if(kind!=='first'&&p.schema!=='batcave.oracle.release.enrollment.v1')throw Error('Wrong enrollment challenge.');
  const message=kind==='first'?FIRST_OWNER_DOMAIN+canonicalFirstText(p):kind==='release'?OWNER_DOMAIN+canonicalReleaseText(p):ENROLL_DOMAIN+canonicalEnrollmentText(p);
  if(message!==ch.signing_message)throw Error('Server signing text differs from the local pinned scope.');
  return message;
 }
 async function sign(ch,kind){
  const message=validate(ch,kind),saved=await getOwnerKey();
  if(saved?.privateKey?.type!=='private'||saved.privateKey.extractable!==false||saved.privateKey.algorithm?.name!=='Ed25519')throw Error('Use the browser profile holding the existing non-exportable owner key.');
  const bytes=new Uint8Array(await crypto.subtle.sign('Ed25519',saved.privateKey,new TextEncoder().encode(message)));
  return btoa(String.fromCharCode(...bytes)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
 }
 async function checkFirst(ch,allowTrustedOwner=false){
  if(allowTrustedOwner&&getTrustedOwner){const owner=await getTrustedOwner();await validateFirstPayload(ch.payload,{policy:ch.policy,policy_sha256:ch.policy_sha256,registered_at:null,revoked_at:null},owner,now());validate(ch,'first');return owner;}
  const saved=await getOwnerKey();
  if(!saved?.publicKeyB64)throw Error('Existing owner public key is required.');
  const raw=Uint8Array.from(atob(saved.publicKeyB64.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-saved.publicKeyB64.length%4)%4)),x=>x.charCodeAt(0));
  const owner={owner_user_id:getOwnerId(),public_key_b64url:saved.publicKeyB64,public_key_sha256:await firstHash(raw),revoked_at:null};
  const record={policy:ch.policy,policy_sha256:ch.policy_sha256,registered_at:null,revoked_at:null};
  await validateFirstPayload(ch.payload,record,owner,now());
  validate(ch,'first');return owner;
 }
 return {
  prepareFirstEnrollment:async candidate=>{
   if(candidate?.schema!=='batcave.nanny.release.public_key.v1'||candidate.role!=='independent_release_reviewer_CANDIDATE'||candidate.registered!==false||candidate.independently_attested!==false||candidate.production_release_authorized!==false||Object.keys(candidate).some(k=>/private|cipher|passphrase/i.test(k)))throw Error('Choose only public.unenrolled.json.');
   const ch=await api({action:'oracle_first_reviewer_challenge_v1',candidate});
   const r={policy:ch.policy,policy_sha256:ch.policy_sha256,registered_at:null,revoked_at:null};
   await validateFirstPayload(ch.payload,r,undefined,now());validate(ch,'first');
   if(await firstHash(firstStable(candidate))!==ch.payload.candidate_sha256||await firstHash(firstStable(candidate.host_identity))!==ch.payload.host_identity_sha256||candidate.public_key_sha256!==ch.policy.reviewer_key_sha256||candidate.public_key_b64url!==ch.policy.reviewer_public_key_b64url)throw Error('First-key candidate differs from the pinned record.');
   return ch;
  },
  signFirstEnrollment:async ch=>{await checkFirst(ch);return {schema:'batcave.oracle.first_reviewer.owner_endorsement.v1',issuer:'batcave-control',challenge_id:ch.challenge_id,policy:ch.policy,policy_sha256:ch.policy_sha256,payload:ch.payload,owner_signature_b64url:await sign(ch,'first')};},
  registerFirstEnrollment:async(e,proof)=>{
   const ch={...e,signing_message:FIRST_OWNER_DOMAIN+canonicalFirstText(e.payload)},owner=await checkFirst(ch,true);
   await firstVerifySignature(owner,ch.signing_message,e.owner_signature_b64url);
   if(proof?.schema!=='batcave.nanny.first_key.possession.v1'||proof.challenge_id!==e.challenge_id||proof.nonce!==e.payload.nonce||proof.policy_sha256!==e.policy_sha256||proof.reviewer_public_key_sha256!==e.policy.reviewer_key_sha256||proof.independently_attested!==false||proof.deployment_authorized!==false||proof.execution_authorized!==false||proof.grant_issued!==false)throw Error('Possession proof differs from the owner endorsement.');
   await firstVerifySignature({public_key_b64url:e.policy.reviewer_public_key_b64url,public_key_sha256:e.policy.reviewer_key_sha256},FIRST_PROOF_DOMAIN+canonicalFirstText(e.payload),proof.proof_signature_b64url);
   return api({action:'oracle_first_reviewer_register_v1',challenge_id:e.challenge_id,owner_signature_b64url:e.owner_signature_b64url,proof_signature_b64url:proof.proof_signature_b64url});
  },
  prepareEnrollment:async candidate=>{
   if(candidate?.schema!=='batcave.nanny.release.public_key.v1'||candidate.role!=='independent_release_reviewer_CANDIDATE'||candidate.registered!==false||candidate.independently_attested!==false||candidate.production_release_authorized!==false||Object.keys(candidate).some(k=>/private|cipher|passphrase/i.test(k)))throw Error('Choose only public.unenrolled.json.');
   const ch=await api({action:'oracle_release_enrollment_challenge_v1',candidate});validate(ch,'enrollment');
   if(ch.payload.reviewer_key_sha256!==candidate.public_key_sha256)throw Error('Candidate fingerprint changed.');
   return ch;
  },
  signEnrollment:async ch=>api({action:'oracle_release_enroll_reviewer_v1',challenge_id:ch.challenge_id,owner_signature_b64url:await sign(ch,'enrollment')}),
  prepareRelease:async fp=>{const ch=await api({action:'oracle_release_challenge_v1',reviewer_public_key_sha256:fp});validate(ch,'release');return ch;},
  signRelease:async ch=>({schema:'batcave.oracle.gate.release.challenge.v1',issuer:'batcave-control',challenge_id:ch.challenge_id,payload:ch.payload,owner_signature_b64url:await sign(ch,'release')}),
  recordReview:async(envelope,receipt,fp)=>{
   if(receipt?.schema!=='batcave.nanny.local.review.evidence.v1'||receipt.intent_key!==PIN.intent_key||receipt.nonce!==envelope.payload.nonce||receipt.reviewer_public_key_sha256!==fp||receipt.deployment_authorized!==false||receipt.execution_authorized!==false)throw Error('Reviewer receipt does not match this exact release challenge.');
   return api({action:'oracle_release_record_evidence_v1',challenge_id:envelope.challenge_id,owner_signature_b64url:envelope.owner_signature_b64url,nanny_signature_b64url:receipt.signature_b64url});
  }
 };
}
export function mountReleasePanel(options){
 const actions=releaseOwnerActions(options),root=document.createElement('section');
 root.id='oracle-release-evidence';
 root.innerHTML='<h2>Oracle release review</h2><p>Use the existing owner key and the separate Cortana reviewer. Recording signatures leaves deployment held.</p><label>Public reviewer record <input data-public type="file" accept="application/json,.json"></label><p><button data-prepare-first>Prepare approved first-key enrollment</button><button data-sign-first disabled>Sign and save first-key endorsement</button></p><label>Local first-key public proof <input data-first-proof type="file" accept="application/json,.json"></label><button data-register-first disabled>Register first key with both signatures</button><p>First-key enrollment records owner trust and possession; independent custody remains unattested.</p><button data-prepare-enroll>Prepare enrollment</button><button data-sign-enroll disabled>Sign displayed enrollment</button><p><button data-prepare-release disabled>Prepare pinned Oracle release</button><button data-sign-release disabled>Sign and save displayed challenge</button></p><label>Local reviewer receipt <input data-review type="file" accept="application/json,.json"></label><button data-record disabled>Record reviewed signatures</button><pre data-status></pre>';
 document.body.append(root);
 const find=s=>root.querySelector(s),show=x=>{find('[data-status]').textContent=typeof x==='string'?x:JSON.stringify(x,null,2);};
 let candidate,enrollment,release,envelope,firstChallenge,firstEndorsement;
 const load=async s=>{const f=find(s).files[0];if(!f||f.size>16000)throw Error('Choose the matching public JSON file (under 16 KB).');return JSON.parse(await f.text());};
 const on=(s,fn)=>{find(s).onclick=async()=>{try{await fn();}catch(e){show(e.message);}};};
 const save=(value,name)=>{const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)+'\n'],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
 on('[data-prepare-first]',async()=>{candidate=await load('[data-public]');firstChallenge=await actions.prepareFirstEnrollment(candidate);show(firstChallenge.payload);find('[data-sign-first]').disabled=false;});
 on('[data-sign-first]',async()=>{if(!firstChallenge)throw Error('Prepare first-key enrollment first.');if(!confirm('Sign one-time owner-root enrollment ONLY for '+candidate.public_key_sha256+'? Independent custody remains unattested. Deployment stays held.'))return;firstEndorsement=await actions.signFirstEnrollment(firstChallenge);save(firstEndorsement,'owner_signed_first_key_endorsement.json');find('[data-sign-first]').disabled=true;find('[data-register-first]').disabled=false;show('Owner endorsement saved. Prove possession locally with the existing encrypted reviewer key before expiry.');});
 on('[data-register-first]',async()=>{if(!firstEndorsement)throw Error('Sign the displayed first-key endorsement first.');show(await actions.registerFirstEnrollment(firstEndorsement,await load('[data-first-proof]')));find('[data-register-first]').disabled=true;find('[data-prepare-release]').disabled=false;});
 on('[data-prepare-enroll]',async()=>{candidate=await load('[data-public]');enrollment=await actions.prepareEnrollment(candidate);show(enrollment.payload);find('[data-sign-enroll]').disabled=false;});
 on('[data-sign-enroll]',async()=>{if(!enrollment)throw Error('Prepare enrollment first.');if(!confirm('Sign enrollment for reviewer '+candidate.public_key_sha256+' and the displayed isolated identity?'))return;show(await actions.signEnrollment(enrollment));find('[data-sign-enroll]').disabled=true;find('[data-prepare-release]').disabled=false;});
 on('[data-prepare-release]',async()=>{release=await actions.prepareRelease(candidate.public_key_sha256);show(release.payload);find('[data-sign-release]').disabled=false;});
 on('[data-sign-release]',async()=>{
  if(!release)throw Error('Prepare a release challenge first.');if(!confirm('Sign only the displayed Oracle fixed fixture, artifact hashes and nonce?'))return;
  envelope=await actions.signRelease(release);const url=URL.createObjectURL(new Blob([JSON.stringify(envelope,null,2)+'\n'],{type:'application/json'}));
  const a=document.createElement('a');a.href=url;a.download='owner_signed_gate_challenge.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  show('Owner challenge saved. Review it locally under the isolated Cortana account before it expires.');find('[data-record]').disabled=false;
 });
 on('[data-record]',async()=>{if(!envelope)throw Error('Sign the displayed challenge first.');show(await actions.recordReview(envelope,await load('[data-review]'),candidate.public_key_sha256));});
 return root;
}
