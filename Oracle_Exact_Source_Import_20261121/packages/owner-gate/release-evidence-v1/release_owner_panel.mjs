/* STAGED addition to the EXISTING owner portal, on its original key origin.
 * Reuses injected authenticated API and IndexedDB lookup. Never creates/exports keys.
 * Preparing does not sign; signing requires a separate explicit local button.
 */
import {PIN,SCHEMA,OWNER_DOMAIN,canonicalReleaseText} from './verify_release_approval_v1.mjs';
import {ENROLL_DOMAIN,canonicalEnrollmentText} from './release_gate_core.mjs';
export function releaseOwnerActions({api,getOwnerId,getOwnerKey,origin,now=Date.now}){
 if(origin!=='https://batcave-linux-approval.vercel.app')throw Error('Use the original Batcave owner-key origin.');
 function validate(ch,kind){
  const p=ch?.payload;
  if(!p||p.owner_user_id!==getOwnerId()||typeof ch.challenge_id!=='string'||!/^[a-f0-9]{32}$/.test(p.nonce)||!Number.isFinite(Date.parse(p.issued_at))||!Number.isFinite(Date.parse(p.expires_at))||Date.parse(p.issued_at)>now()+30000||Date.parse(p.expires_at)<=now()||Date.parse(p.expires_at)>Date.parse(p.issued_at)+600000)throw Error('Invalid or expired owner challenge.');
  if(kind==='release'){
   if(p.schema!==SCHEMA||Object.entries(PIN).some(([k,v])=>p[k]!==v))throw Error('Release scope differs from the reviewed Oracle artifacts.');
  }else if(p.schema!=='batcave.oracle.release.enrollment.v1')throw Error('Wrong enrollment challenge.');
  const message=kind==='release'?OWNER_DOMAIN+canonicalReleaseText(p):ENROLL_DOMAIN+canonicalEnrollmentText(p);
  if(message!==ch.signing_message)throw Error('Server signing text differs from the local pinned scope.');
  return message;
 }
 async function sign(ch,kind){
  const message=validate(ch,kind),saved=await getOwnerKey();
  if(saved?.privateKey?.type!=='private'||saved.privateKey.extractable!==false||saved.privateKey.algorithm?.name!=='Ed25519')throw Error('Use the browser profile holding the existing non-exportable owner key.');
  const bytes=new Uint8Array(await crypto.subtle.sign('Ed25519',saved.privateKey,new TextEncoder().encode(message)));
  return btoa(String.fromCharCode(...bytes)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
 }
 return {
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
 root.innerHTML='<h2>Oracle release review</h2><p>Use the existing owner key and the separate Cortana reviewer. Recording signatures leaves deployment held.</p><label>Public reviewer record <input data-public type="file" accept="application/json,.json"></label><button data-prepare-enroll>Prepare enrollment</button><button data-sign-enroll disabled>Sign displayed enrollment</button><p><button data-prepare-release disabled>Prepare pinned Oracle release</button><button data-sign-release disabled>Sign and save displayed challenge</button></p><label>Local reviewer receipt <input data-review type="file" accept="application/json,.json"></label><button data-record disabled>Record reviewed signatures</button><pre data-status></pre>';
 document.body.append(root);
 const find=s=>root.querySelector(s),show=x=>{find('[data-status]').textContent=typeof x==='string'?x:JSON.stringify(x,null,2);};
 let candidate,enrollment,release,envelope;
 const load=async s=>{const f=find(s).files[0];if(!f||f.size>16000)throw Error('Choose the matching public JSON file (under 16 KB).');return JSON.parse(await f.text());};
 const on=(s,fn)=>{find(s).onclick=async()=>{try{await fn();}catch(e){show(e.message);}};};
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
