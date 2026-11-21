#!/usr/bin/env node
/**
 * REVIEW-ONLY / no cloud writes / no privileges. Runs locally under a dedicated
 * Windows account separate from the Oracle worker and the existing lab reviewer.
 * Owner must independently enroll the PUBLIC key through an approved gate.
 * ChatGPT never has access to a live key or the passphrase.
 * Requires Node 22+ and an interactive TTY for ALL private-key operations.
 */
import {
  generateKeyPairSync,createHash,randomBytes,scryptSync,createCipheriv,
  createDecipheriv,createPrivateKey,sign,verify,createPublicKey
} from 'node:crypto';
import {readFileSync,writeFileSync,existsSync,mkdirSync,statSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {platform, userInfo, hostname} from 'node:os';
import {execFileSync} from 'node:child_process';
import {stdin,stdout,stderr} from 'node:process';
import {canonicalReleaseText,NANNY_DOMAIN,OWNER_DOMAIN,PIN,SCHEMA} from './verify_release_approval_v1.mjs';

const KEYFILE='private.encrypted.json';
const PUBFILE='public.unenrolled.json';
const SIGFILE='review.signature.json';
const MAX_PASSWORD=4096;
const MAX_FILE=1024*1024;
// Public registered owner key from batcave.linux_owner_keys_v1 (2026-11-21).
// A changed owner key requires a new independent review of this local signer.
const OWNER_PUB_B64URL='YBkEbULiJaOD-j_RAGIgXHi61mecWuUqd8DuLvevlGM';
const OWNER_PUB_SHA256='20c240ee4ef8817faf7036867756991132ca6f8a559ea26aab7337f3c14395ef';
function die(message) { throw new Error(message); }
function sha(bytes) {return createHash('sha256').update(bytes).digest('hex');}
function loadJson(path){const st=statSync(path);if(st.size<=0||st.size>MAX_FILE)die('INPUT_FILE_SIZE');return JSON.parse(readFileSync(path,'utf8'));}
function saveNew(path,data){writeFileSync(path,JSON.stringify(data,null,2)+'\n',{encoding:'utf8',flag:'wx',mode:0o600});}
function ownerIdentity(){return {host:hostname(),os:platform(),user:userInfo().username};}
function ensureTTY(){if(!stdin.isTTY||!stdout.isTTY||!stdin.setRawMode)die('HUMAN_INTERACTIVE_TTY_REQUIRED');}
async function promptSecret(label){
  ensureTTY();stdout.write(label);
  const bytes=[];
  return await new Promise((resolve,reject)=>{
    const cleanup=()=>{stdin.removeListener('data',onData);stdin.setRawMode(false);stdin.pause();stdout.write('\n');};
    function onData(d){for(const b of d){if(b===3){cleanup();reject(Error('USER_CANCELLED'));return;}
      if(b===13||b===10){cleanup();const s=Buffer.from(bytes).toString('utf8');if(s.length<16||s.length>MAX_PASSWORD){reject(Error('PASSPHRASE_LENGTH_16_TO_4096'));return;}resolve(s);return;}
      if(b===8||b===127){bytes.pop();continue;}
      if(bytes.length<MAX_PASSWORD*4)bytes.push(b);
    }}
    stdin.setRawMode(true);stdin.resume();stdin.on('data',onData);
  });
}
async function promptExplicit(label, phrase){ensureTTY();stdout.write(`${label}\nType exactly: ${phrase}\n> `);
  const buf=[];return await new Promise((resolve,reject)=>{
    const cleanup=()=>{stdin.removeListener('data',onData);stdin.setRawMode(false);stdin.pause();stdout.write('\n');};
    function onData(d){for(const b of d){if(b===3){cleanup();reject(Error('USER_CANCELLED'));return;}
       if(b===13||b===10){cleanup();resolve(Buffer.from(buf).toString('utf8')===phrase);return;}
       if(b===8||b===127){buf.pop();stdout.write('\b \b');continue;}
       if(buf.length<128){buf.push(b);stdout.write(String.fromCharCode(b));}
    }}
    stdin.setRawMode(true);stdin.resume();stdin.on('data',onData);
  });
}
function encryptPkcs8(privatePkcs8,pass){
 const salt=randomBytes(32),iv=randomBytes(12),key=scryptSync(pass,salt,32,{N:32768,r:8,p:1,maxmem:96*1024*1024});
 try {const cipher=createCipheriv('aes-256-gcm',key,iv);const ct=Buffer.concat([cipher.update(privatePkcs8),cipher.final()]);
 return {schema:'batcave.nanny.local.encrypted_key.v1',kdf:'scrypt-32768-8-1',cipher:'aes-256-gcm',salt:salt.toString('base64url'),iv:iv.toString('base64url'),tag:cipher.getAuthTag().toString('base64url'),ciphertext:ct.toString('base64url')};}
 finally{key.fill(0);privatePkcs8.fill(0);}
}
function decryptPkcs8(record,pass){
 if(record?.schema!=='batcave.nanny.local.encrypted_key.v1'||record?.kdf!=='scrypt-32768-8-1'||record?.cipher!=='aes-256-gcm')die('BAD_LOCAL_KEY_FORMAT');
 const salt=Buffer.from(record.salt,'base64url'),iv=Buffer.from(record.iv,'base64url'),tag=Buffer.from(record.tag,'base64url');
 if(salt.length!==32||iv.length!==12||tag.length!==16)die('BAD_LOCAL_KEY_PARAMETERS');
 const key=scryptSync(pass,salt,32,{N:32768,r:8,p:1,maxmem:96*1024*1024});
 try {const dec=createDecipheriv('aes-256-gcm',key,iv);dec.setAuthTag(tag);return Buffer.concat([dec.update(Buffer.from(record.ciphertext,'base64url')),dec.final()]);}
 finally{key.fill(0);}
}
function validateEnvelope(e,now=Date.now()){
 const p=e?.payload;
 if(!p||e.schema!=='batcave.oracle.gate.release.challenge.v1'||e.issuer!=='batcave-control')die('MISSING_GATE_ISSUER_EVIDENCE');
 // The cloud alone cannot confer reviewer consent. We require the Pixel owner's
 // Ed25519 signature first. The server must also verify nonce issuance/one-use.
 if(p.schema!==SCHEMA)die('INVALID_RELEASE_SCHEMA');
 for(const [k,v] of Object.entries(PIN))if(p[k]!==v)die('WRONG_PIN_'+k);
 const fields=['expires_at','fixture','intent_key','intent_sha256','issued_at','nonce','operation','owner_gate_zip_sha256','owner_user_id','pr_head_sha','schema','scope','target_device','worker_zip_sha256'];
 if(Object.keys(p).sort().join('|')!==fields.join('|'))die('BAD_RELEASE_FIELDS');
 if(!/^[0-9a-f]{32}$/.test(p.nonce))die('BAD_NONCE');
 if(!/^[0-9a-f-]{36}$/.test(p.owner_user_id))die('BAD_OWNER');
 const issued=Date.parse(p.issued_at),expires=Date.parse(p.expires_at);
 if(!Number.isFinite(issued)||!Number.isFinite(expires)||issued>now+30000||issued<now-600000||expires<=now||expires>issued+600000)die('EXPIRED_OR_INVALID_CHALLENGE');
 if(typeof e.owner_signature_b64url!=='string'||!(/^[A-Za-z0-9_-]{86}$/.test(e.owner_signature_b64url)))die('OWNER_SIGNATURE_MISSING');
 const ownerRaw=Buffer.from(OWNER_PUB_B64URL,'base64url');
 if(sha(ownerRaw)!==OWNER_PUB_SHA256||ownerRaw.length!==32)die('OWNER_PUBLIC_KEY_PIN_MISMATCH');
 const ownerKey=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),ownerRaw]),format:'der',type:'spki'});
 if(!verify(null,Buffer.from(OWNER_DOMAIN+canonicalReleaseText(p)),ownerKey,Buffer.from(e.owner_signature_b64url,'base64url')))die('OWNER_SIGNATURE_INVALID');
 return p;
}
function digestFile(path){const st=statSync(path);if(!st.isFile()||st.size>256*1024*1024)die('BAD_ARCHIVE_SIZE');return sha(readFileSync(path));}
function checkArtifacts(p,gateArchive,workerArchive,repoPath){
 const gate=digestFile(gateArchive),worker=digestFile(workerArchive);
 if(gate!==p.owner_gate_zip_sha256)die('OWNER_GATE_ARCHIVE_HASH_MISMATCH');
 if(worker!==p.worker_zip_sha256)die('ORACLE_WORKER_ARCHIVE_HASH_MISMATCH');
 // Independently inspect the exact checked-out source commit; refuse dirty trees.
 if(!repoPath)die('SOURCE_CHECKOUT_REQUIRED');
 const head=execFileSync('git',['-C',repoPath,'rev-parse','HEAD'],{encoding:'utf8',timeout:15000}).trim();
 const dirty=execFileSync('git',['-C',repoPath,'status','--porcelain'],{encoding:'utf8',timeout:15000}).trim();
 if(head!==p.pr_head_sha||dirty)die('SOURCE_COMMIT_OR_DIRTY_WORKTREE');
 return {gate_sha256:gate,worker_sha256:worker,source_commit:head};
}
async function init(dir){ensureTTY();mkdirSync(dir,{recursive:true,mode:0o700});
 if(existsSync(join(dir,KEYFILE))||existsSync(join(dir,PUBFILE)))die('IDENTITY_EXISTS_NO_OVERWRITE');
 const ident=ownerIdentity();
 stdout.write(`Signer host: ${ident.host} / ${ident.os} / local account ${ident.user}\nUse a DEDICATED OS ACCOUNT isolated from the Oracle worker and Cortana lab reviewer.\n`);
 if(!await promptExplicit('The key is local; public enrollment is a separate, independently reviewed step.',`CREATE ISOLATED ${ident.host}`))die('NOT_CONFIRMED');
 const pass=await promptSecret('New local encryption passphrase (hidden, >=16 chars): ');
 const pass2=await promptSecret('Repeat passphrase (hidden): ');
 if(pass!==pass2)die('PASSPHRASE_MISMATCH');
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');
 const pubRaw=publicKey.export({format:'der',type:'spki'}).subarray(-32);
 const keyRecord=encryptPkcs8(Buffer.from(privateKey.export({format:'der',type:'pkcs8'})),pass);
 const publicRecord={schema:'batcave.nanny.release.public_key.v1',role:'independent_release_reviewer_CANDIDATE',registered:false,independently_attested:false,production_release_authorized:false,host_identity:ident,public_key_b64url:pubRaw.toString('base64url'),public_key_sha256:sha(pubRaw),created_at:new Date().toISOString()};
 saveNew(join(dir,KEYFILE),keyRecord);saveNew(join(dir,PUBFILE),publicRecord);
 stdout.write(`CANDIDATE public fingerprint: ${publicRecord.public_key_sha256}\nPRIVATE key remains local. Status: UNENROLLED, NOT AUTHORIZED.\n`);
}
async function review(dir,challengePath,gateArchive,workerArchive,repoPath){
 ensureTTY(); const ident=ownerIdentity();const pub=loadJson(join(dir,PUBFILE));
 if(pub.host_identity?.host!==ident.host||pub.host_identity?.user!==ident.user)die('DIFFERENT_HOST_OR_ACCOUNT');
 const p=validateEnvelope(loadJson(challengePath));
 const h=checkArtifacts(p,gateArchive,workerArchive,repoPath);
 stdout.write(`\nINDEPENDENT NANNY REVIEW — ${ident.host} (${ident.user})\n`);
 stdout.write(`Owner: ${p.owner_user_id}\nTarget: ${p.target_device} / ${p.operation} / ${p.fixture}\n`);
 stdout.write(`Intent: ${p.intent_key}\nPR pinned head: ${p.pr_head_sha}\nNonce: ${p.nonce}\nExpires: ${p.expires_at}\n`);
 stdout.write(`Owner gate ZIP: ${h.gate_sha256}\nWorker ZIP: ${h.worker_sha256}\n`);
 stdout.write('No general shell, no production task permission; signature is evidence only.\n');
 const code='REVIEW '+p.nonce.slice(-8);
 if(!await promptExplicit('After independently checking code, policy, recovery and hardware identity:',code))die('REVIEW_NOT_APPROVED');
 const pass=await promptSecret('Local reviewer passphrase (hidden): ');
 const pkcs8=decryptPkcs8(loadJson(join(dir,KEYFILE)),pass);
 let privateKey;
 try{privateKey=createPrivateKey({key:pkcs8,format:'der',type:'pkcs8'});}finally{pkcs8.fill(0);}
 const pubRaw=createPublicKey(privateKey).export({format:'der',type:'spki'}).subarray(-32);
 if(sha(pubRaw)!==pub.public_key_sha256)die('WRONG_PRIVATE_KEY');
 const text=canonicalReleaseText(p),signature_b64url=sign(null,Buffer.from(NANNY_DOMAIN+text),privateKey).toString('base64url');
 if(!verify(null,Buffer.from(NANNY_DOMAIN+text),createPublicKey(privateKey),Buffer.from(signature_b64url,'base64url')))die('SELF_CHECK_FAILED');
 const receipt={schema:'batcave.nanny.local.review.evidence.v1',status:'NOT_ENROLLED_BY_THIS_COMMAND',intent_key:p.intent_key,nonce:p.nonce,expires_at:p.expires_at,reviewer_public_key_sha256:pub.public_key_sha256,signature_b64url,reviewer_host_identity:ident,local_file_hashes:h,reviewed_at:new Date().toISOString(),deployment_authorized:false,execution_authorized:false};
 saveNew(join(dir,`review-${p.nonce}.json`),receipt);
 stdout.write(`Local signature saved: ${join(dir,`review-${p.nonce}.json`)}\nServer must verify registered custody and consume nonce. No deployment occurred.\n`);
}
// Array.map supplies (value, index, array); path.resolve must receive only the path.
function resolveReviewPaths(args){return args.map(value=>resolve(value));}
export {encryptPkcs8,decryptPkcs8,validateEnvelope,checkArtifacts,resolveReviewPaths};
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const [cmd,...args]=process.argv.slice(2);
 try{
 if(cmd==='init'&&args.length===1)await init(resolve(args[0]));
 else if(cmd==='review'&&args.length===5)await review(...resolveReviewPaths(args));
 else die('USAGE: node cortana_independent_reviewer.mjs init <private_directory> OR review <private_directory> <gate_challenge.json> <owner_gate.zip> <oracle_worker.zip> <reviewed_source_git_checkout>');
 }catch(e){stderr.write('DENIED: '+(e?.message||'UNKNOWN')+'\n');process.exitCode=1;}
}
