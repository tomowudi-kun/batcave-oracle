#!/usr/bin/env node
/* STAGED offline candidate possession proof, run ONLY as
 * CORTANA\StrictNannyRelease, with interactive human confirmation.
 * NO network, reviewer enrollment, attestation, release or execution grants.
 * Uses existing encrypted private.encrypted.json; never generates a new key.
 * Caller supplies exact server-issued, one-use challenge JSON path.
 */
import {readFileSync,writeFileSync,existsSync,lstatSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {hostname,platform,userInfo} from 'node:os';
import {stdin,stdout,stderr,argv,env} from 'node:process';
import {execFileSync} from 'node:child_process';
import {createHash,createPrivateKey,createPublicKey,createDecipheriv,scryptSync,sign,verify} from 'node:crypto';
import {possessionMessage,candidatePublicBytes} from '../src/general_control_reviewer_possession_STAGED.mjs';
const SID='S-1-5-21-349890097-2052580754-4142396749-1004';
const PROFILE='C:\\Users\\StrictNannyRelease';
const DIR='Batcave-GeneralControl-Privileged-Reviewer-Key';
const H64=/^[a-f0-9]{64}$/;
const sha=b=>createHash('sha256').update(b).digest('hex');
const fail=code=>{throw Error(code)};
const readJson=p=>{
 const st=lstatSync(p);
 if(!st.isFile()||st.isSymbolicLink()||st.size<=0||st.size>8192)fail('INVALID_FILE_SIZE_OR_TYPE');
 return JSON.parse(readFileSync(p,'utf8'));
};
export function rawKeyFromEncryptedRecord(rec,pass){
 if(rec?.schema!=='batcave.nanny.local.encrypted_key.v1'||
 rec.kdf!=='scrypt-32768-8-1'||rec.cipher!=='aes-256-gcm'||
 typeof pass!=='string'||pass.length<16||pass.length>4096)fail('BAD_ENCRYPTED_FORMAT');
 const salt=Buffer.from(rec.salt,'base64url'),iv=Buffer.from(rec.iv,'base64url'),
 tag=Buffer.from(rec.tag,'base64url');
 if(salt.length!==32||iv.length!==12||tag.length!==16)fail('BAD_CRYPTO_PARAMETERS');
 const key=scryptSync(pass,salt,32,{N:32768,r:8,p:1,maxmem:96*1024*1024});
 let der;
 try{
  const cipher=createDecipheriv('aes-256-gcm',key,iv);cipher.setAuthTag(tag);
  der=Buffer.concat([cipher.update(Buffer.from(rec.ciphertext,'base64url')),cipher.final()]);
  return createPrivateKey({key:der,format:'der',type:'pkcs8'});
 }finally{key.fill(0);if(der)der.fill(0);}
}
export function signCandidatePossessionV1(challenge,privateKey,expectedPublic,now=Date.now()){
 const raw=candidatePublicBytes(expectedPublic.public_key_b64url);
 if(sha(raw)!==expectedPublic.public_key_sha256||challenge.candidate_key_sha256!==expectedPublic.public_key_sha256||
 challenge.candidate_public_b64url!==expectedPublic.public_key_b64url)
 fail('CHALLENGE_NOT_OWN_KEY');
 const derived=createPublicKey(privateKey).export({format:'der',type:'spki'}).subarray(-32);
 if(!derived.equals(raw))fail('PRIVATE_KEY_NOT_MATCHED');
 const msg=possessionMessage(challenge,now);
 const signature=sign(null,Buffer.from(msg),privateKey);
 if(!verify(null,Buffer.from(msg),createPublicKey(privateKey),signature))fail('SIGN_SELFTEST_FAILED');
 return Object.freeze({schema:'batcave.general_control.reviewer_possession_proof.v1',
  request_id:challenge.request_id,nonce:challenge.nonce,signature_hex:signature.toString('hex')});
}
function verifyLocal(){
 if(platform()!=='win32'||hostname().toUpperCase()!=='CORTANA'||
  userInfo().username.toLowerCase()!=='strictnannyrelease'||
  env.USERPROFILE?.toLowerCase()!==PROFILE.toLowerCase())fail('WRONG_PROTECTED_ACCOUNT');
 const ident=execFileSync('whoami.exe',['/user','/fo','csv','/nh'],{encoding:'utf8',windowsHide:true,timeout:8000});
 if(!ident.includes(SID))fail('WRONG_CORTANA_REVIEWER_SID');
 if(!stdin.isTTY||!stdout.isTTY||typeof stdin.setRawMode!=='function')fail('LOCAL_INTERACTIVE_TTY_REQUIRED');
 const dir=join(PROFILE,DIR),acl=execFileSync('icacls.exe',[dir],{encoding:'utf8',windowsHide:true,timeout:8000});
 if(/Everyone:|BUILTIN\\Users:|Authenticated Users:|StrictNannyReviewer:|BatcaveRunner:/i.test(acl))fail('KEY_DIR_TOO_BROAD');
 if(!acl.includes(SID)&&!acl.toLowerCase().includes('strictnannyrelease'))fail('KEY_DIR_OWNER_NOT_VERIFIED');
 return dir;
}
function ask(label,{hidden=false}={}){
 stdout.write(label);const chars=[];
 return new Promise((res,rej)=>{
  const cleanup=()=>{stdin.off('data',feed);stdin.setRawMode(false);stdin.pause();stdout.write('\n');};
  function feed(bytes){for(const b of bytes){
   if(b===3){cleanup();rej(Error('OWNER_CANCELLED'));return;}
   if(b===13||b===10){cleanup();res(Buffer.from(chars).toString('utf8'));return;}
   if(b===8||b===127){chars.pop();if(!hidden)stdout.write('\b \b');continue;}
   if(chars.length<4096*4){chars.push(b);if(!hidden)stdout.write(String.fromCharCode(b));}
  }}
  stdin.setRawMode(true);stdin.resume();stdin.on('data',feed);
 });
}
async function main(){
 if(argv.length!==3||!argv[2].toLowerCase().endsWith('.json'))fail('USAGE: node general_control_candidate_sign_possession_STAGED.mjs <server_challenge.json>');
 const dir=verifyLocal();
 const pub=readJson(join(dir,'public.unenrolled.json'));
 if(pub.schema!=='batcave.nanny.release.public_key.v1'||
  pub.role!=='independent_release_reviewer_CANDIDATE'||
  pub.registered!==false||pub.independently_attested!==false||
  pub.production_release_authorized!==false||
  pub.host_identity?.host!=='Cortana'||pub.host_identity?.os!=='win32'||
  pub.host_identity?.user!=='StrictNannyRelease'||!H64.test(pub.public_key_sha256))
  fail('CANDIDATE_NOT_UNENROLLED_OR_CUSTODY_MISMATCH');
 const challenge=readJson(resolve(argv[2]));
 possessionMessage(challenge);
 if(challenge.candidate_public_b64url!==pub.public_key_b64url||
   challenge.candidate_key_sha256!==pub.public_key_sha256)
  fail('CHALLENGE_MISMATCHES_LOCAL_PUBLIC_KEY');
 stdout.write('ONE-TIME CANDIDATE KEY POSSESSION PROOF ONLY. No release, registry, grant or deployment.\n');
 stdout.write('Public fingerprint: '+pub.public_key_sha256+'\nRequest: '+challenge.request_id+'\n');
 const confirmation=await ask('Type PROVE CANDIDATE KEY ONLY: ');
 if(confirmation!=='PROVE CANDIDATE KEY ONLY')fail('HUMAN_NOT_CONFIRMED');
 const pass=await ask('Local key passphrase (hidden): ',{hidden:true});
 let key;
 try{key=rawKeyFromEncryptedRecord(readJson(join(dir,'private.encrypted.json')),pass);}catch{fail('PRIVATE_KEY_DECRYPTION_FAILED');}
 const proof=signCandidatePossessionV1(challenge,key,pub);
 const out=join(dir,'possession-proof-'+challenge.nonce+'.json');
 if(existsSync(out))fail('PROOF_ALREADY_EXISTS_NO_OVERWRITE');
 writeFileSync(out,JSON.stringify(proof,null,2)+'\n',{flag:'wx',mode:0o600});
 stdout.write('PUBLIC_PROOF_JSON_START\n'+JSON.stringify(proof,null,2)+'\nPUBLIC_PROOF_JSON_END\n');
 stdout.write('POSSESSION_SIGNATURE_CREATED_LOCAL_ONLY — transfer public proof to private server verifier before challenge expires.\n');
}
if(argv[1]&&argv[1].endsWith('general_control_candidate_sign_possession_STAGED.mjs'))
 main().catch(e=>{stderr.write('DENIED: '+(e?.message||'UNKNOWN')+'\n');process.exitCode=1;});
