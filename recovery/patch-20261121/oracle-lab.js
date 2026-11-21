'use strict';
// Standalone static client extension for the EXISTING owner-portal origin.
// It reads the existing, non-exportable IndexedDB Ed25519 owner key; it never
// generates, exports or replaces an owner key, nor signs production releases.
const LAB_ORIGIN='https://batcave-linux-approval.vercel.app';
const LAB_BASE='https://wizflveeptzeajsdybzs.supabase.co';
const LAB_GATE=LAB_BASE+'/functions/v1/batcave-change-gate-v1';
const LAB_APIKEY='sb_publishable_WUpPRJuKpeR8E4eRboGKhA_mhY20UoW';
const LAB_DOMAIN='batcave.oracle.lab.reviewer.enroll.v2';
const LAB_KEY='4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b';
const LAB_FIXTURE='4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f';
const LAB_RELEASE='4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2';
const LAB_PUBLIC={schema:'batcave.nanny.public_key.request.v1',host:'CORTANA',reviewer_sid:'S-1-5-19',role:'lab_reviewer_only',
 public_key_pem:'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPkCiAsi/f6Cv2UkYCYZbE3z8L5pgUi339QB+yLVvKCo=\n-----END PUBLIC KEY-----\n',
 public_key_sha256:LAB_KEY,production_release_authorized:false,cloud_enrolled:false};
const dom=id=>document.getElementById(id);
function say(message,obj){dom('status').textContent=message;dom('output').textContent=obj?JSON.stringify(obj,null,2):'';}
function b64url(bytes){let s='';for(const b of bytes)s+=String.fromCharCode(b);return btoa(s).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');}
function exact(o,expected){return o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join('|')===expected.slice().sort().join('|');}
function ownerMessage(r){return [LAB_DOMAIN,r.owner_user_id,'CORTANA','S-1-5-19',LAB_KEY,'lab_reviewer_only',LAB_FIXTURE,LAB_RELEASE,r.nonce,r.expires_at].join('\n');}
function verifyChallenge(c,uid){
 if(!c||c.schema!=='batcave.oracle.lab.enroll.challenge.v2'||typeof c.signing_message!=='string'||typeof c.challenge_id!=='string')throw Error('Unexpected gate challenge');
 const r=c.request;
 if(!exact(r,['schema','owner_user_id','host','reviewer_sid','reviewer_key_sha256','role','fixture_token','release_archive_sha256','nonce','expires_at']))throw Error('Unexpected challenge fields');
 if(r.schema!==LAB_DOMAIN||r.owner_user_id!==uid||r.host!=='CORTANA'||r.reviewer_sid!=='S-1-5-19'||r.reviewer_key_sha256!==LAB_KEY||r.role!=='lab_reviewer_only'||r.fixture_token!==LAB_FIXTURE||r.release_archive_sha256!==LAB_RELEASE)throw Error('Challenge scope mismatch');
 if(!/^[a-f0-9]{32}$/.test(r.nonce)||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(r.expires_at))throw Error('Invalid challenge nonce or expiry');
 const ttl=Date.parse(r.expires_at)-Date.now();if(ttl<=0||ttl>600000)throw Error('Expired or excessive challenge TTL');
 const expected=ownerMessage(r);if(c.signing_message!==expected)throw Error('Wrong signing message');return expected;
}
function session(){
 const raw=sessionStorage.getItem('batcave_linux_session_v1');const x=raw?JSON.parse(raw):null;
 if(!x?.access_token||!x?.user?.id)throw Error('Sign in through the original owner portal in this same tab first');return x;
}
function existingKey(uid){return new Promise((resolve,reject)=>{
 const open=indexedDB.open('batcave_linux_signer_v1',1);
 open.onupgradeneeded=()=>{open.transaction.abort();reject(Error('No enrolled signing key in this browser profile — enrollment must not create another key'));};
 open.onerror=()=>reject(open.error);
 open.onsuccess=()=>{
  const db=open.result;
  if(!db.objectStoreNames.contains('keys')){db.close();reject(Error('No owner key store'));return;}
  const tx=db.transaction('keys','readonly'),get=tx.objectStore('keys').get(uid);
  get.onsuccess=()=>{const stored=get.result;db.close();const key=stored?.type==='private'?stored:stored?.privateKey;
   if(!key||key.type!=='private'||key.algorithm?.name!=='Ed25519'||key.extractable!==false)
     reject(Error('Existing non-exportable Ed25519 owner key is unavailable in this Chrome profile'));
   else resolve(key);};
  get.onerror=()=>{db.close();reject(get.error);};
 };
});}
async function callGate(body,token){
 const result=await fetch(LAB_GATE,{method:'POST',cache:'no-store',headers:{'content-type':'application/json','apikey':LAB_APIKEY,'authorization':'Bearer '+token},body:JSON.stringify(body)});
 const x=await result.json().catch(()=>null);
 if(!result.ok)throw Error((x?.error||'Gate endpoint unavailable')+' (HTTP '+result.status+')');
 return x;
}
async function publicKeyMatches(){
 const b64=LAB_PUBLIC.public_key_pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g,'');
 const bytes=Uint8Array.from(atob(b64),c=>c.charCodeAt(0));
 const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');
 if(hash!==LAB_KEY)throw Error('Cortana public-key fingerprint mismatch');
 return true;
}
async function enroll(){
 if(location.origin!==LAB_ORIGIN)throw Error('Preview mode: owner signing is disabled on other origins.');
 if(!dom('scopeConsent').checked)throw Error('Confirm the exact lab-only scope first');
 await publicKeyMatches();
 const x=session();const key=await existingKey(x.user.id);
 const c=await callGate({action:'oracle_lab_enroll_challenge_v2'},x.access_token);
 const message=verifyChallenge(c,x.user.id);
 // Direct user click plus local non-exportable Ed25519 signing; never export private key.
 const signature=b64url(new Uint8Array(await crypto.subtle.sign('Ed25519',key,new TextEncoder().encode(message))));
 const enrolled=await callGate({action:'oracle_lab_enroll_reviewer_v2',challenge_id:c.challenge_id,request:c.request,public_record:LAB_PUBLIC,signature_b64url:signature},x.access_token);
 if(enrolled?.enrollment_recorded!==true||enrolled?.execution_authorized!==false||enrolled?.deployment_authorized!==false)throw Error('Unexpected gate response');
 say('Owner signature verified; LAB-ONLY reviewer enrollment recorded.',{reviewer_key_sha256:LAB_KEY,lab_only:true,execution_authorized:false,deployment_authorized:false});
}
async function selfTest(){
 await publicKeyMatches();
 const n='a'.repeat(32),exp=new Date(Date.now()+120000).toISOString();
 const request={schema:LAB_DOMAIN,owner_user_id:'123e4567-e89b-42d3-a456-426614174000',host:'CORTANA',reviewer_sid:'S-1-5-19',reviewer_key_sha256:LAB_KEY,role:'lab_reviewer_only',fixture_token:LAB_FIXTURE,release_archive_sha256:LAB_RELEASE,nonce:n,expires_at:exp};
 const challenge={schema:'batcave.oracle.lab.enroll.challenge.v2',challenge_id:'123e4567-e89b-42d3-a456-426614174555',request,signing_message:ownerMessage(request)};
 verifyChallenge(challenge,request.owner_user_id);
 let rejected=false;try{verifyChallenge({...challenge,signing_message:'bad'},request.owner_user_id);}catch{rejected=true;}if(!rejected)throw Error('Altered challenge accepted');
 // Ephemeral test keys never touch IndexedDB or the server.
 const pair=await crypto.subtle.generateKey('Ed25519',false,['sign','verify']);const message=verifyChallenge(challenge,request.owner_user_id);
 const sig=await crypto.subtle.sign('Ed25519',pair.privateKey,new TextEncoder().encode(message));
 if(!await crypto.subtle.verify('Ed25519',pair.publicKey,sig,new TextEncoder().encode(message)))throw Error('Ed25519 test failed');
 say('Offline UI self-test: LAB_PASS',{key_fingerprint_verified:true,canonical_scope_verified:true,tamper_rejected:true,webcrypto_ed25519:true,owner_key_used:false,cloud_mutations:false});
}
dom('enrollButton').disabled=location.origin!==LAB_ORIGIN;
if(location.origin!==LAB_ORIGIN)say('PREVIEW MODE — signing blocked on this origin. Run offline self-test only.');
else say('Ready to enroll only after the reviewed cloud gate extension is deployed. Existing owner key required.');
dom('enrollButton').addEventListener('click',()=>enroll().catch(e=>say(e?.message||'Enrollment failed; no permissions changed.')));
dom('selfTest').addEventListener('click',()=>selfTest().catch(e=>say('Self-test failed: '+(e?.message||'unknown'))));