import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes,scryptSync,createCipheriv,createHash,verify} from 'node:crypto';
import {rawKeyFromEncryptedRecord,signCandidatePossessionV1}
 from './general_control_candidate_sign_possession_STAGED.mjs';
import {possessionMessage,POP_SCHEMA} from '../src/general_control_reviewer_possession_STAGED.mjs';
const pair=generateKeyPairSync('ed25519'),other=generateKeyPairSync('ed25519');
const raw=pair.publicKey.export({format:'der',type:'spki'}).subarray(-32);
const pub={public_key_b64url:raw.toString('base64url'),
 public_key_sha256:createHash('sha256').update(raw).digest('hex')};
const now=Date.parse('2026-11-23T21:32:00.000Z');
const ch={schema:POP_SCHEMA,purpose:'candidate_key_possession_only',
 request_id:'5cf31be0-4a90-40dd-8ba0-ae1027c75361',
 draft_id:'50920aad-09e6-4895-aea1-a29410edd435',
 owner_user_id:'ff189123-b5c3-4ee0-9267-06d4f20fb44f',
 candidate_key_sha256:pub.public_key_sha256,
 candidate_public_b64url:pub.public_key_b64url,host:'Cortana',
 account:'StrictNannyRelease',sid:'S-1-5-21-349890097-2052580754-4142396749-1004',
 nonce:'a'.repeat(32),issued_at:new Date(now-1000).toISOString(),
 expires_at:new Date(now+180000).toISOString(),
 execution_authorized:false,deployment_authorized:false,grant_issued:false};
function encryptedRecord(pass){
 const salt=randomBytes(32),iv=randomBytes(12),key=scryptSync(pass,salt,32,{N:32768,r:8,p:1,maxmem:96*1024*1024});
 const der=pair.privateKey.export({type:'pkcs8',format:'der'});
 try{
 const e=createCipheriv('aes-256-gcm',key,iv);
 const ciphertext=Buffer.concat([e.update(der),e.final()]);
 return {schema:'batcave.nanny.local.encrypted_key.v1',kdf:'scrypt-32768-8-1',cipher:'aes-256-gcm',
  salt:salt.toString('base64url'),iv:iv.toString('base64url'),tag:e.getAuthTag().toString('base64url'),
  ciphertext:ciphertext.toString('base64url')};
 }finally{key.fill(0);der.fill(0);}
}
test('decrypt exact initializer key format and create publicly verifiable one-use proof',()=>{
 const pass='test-passphrase-at-least-16',rec=encryptedRecord(pass);
 const privateKey=rawKeyFromEncryptedRecord(rec,pass);
 const proof=signCandidatePossessionV1(ch,privateKey,pub,now);
 assert.deepEqual(Object.keys(proof),['schema','request_id','nonce','signature_hex']);
 assert.equal(proof.signature_hex.length,128);
 assert.equal(verify(null,Buffer.from(possessionMessage(ch,now)),pair.publicKey,Buffer.from(proof.signature_hex,'hex')),true);
 assert.equal(verify(null,Buffer.from(possessionMessage({...ch,nonce:'b'.repeat(32)},now)),pair.publicKey,Buffer.from(proof.signature_hex,'hex')),false);
});
test('wrong local passphrase, incorrect key, changed candidate and stale challenge all deny',()=>{
 const rec=encryptedRecord('test-passphrase-at-least-16');
 assert.throws(()=>rawKeyFromEncryptedRecord(rec,'wrong-passphrase-more-than-16'));
 assert.throws(()=>signCandidatePossessionV1(ch,other.privateKey,pub,now));
 assert.throws(()=>signCandidatePossessionV1({...ch,candidate_key_sha256:'b'.repeat(64)},pair.privateKey,pub,now));
 assert.throws(()=>signCandidatePossessionV1(ch,pair.privateKey,pub,now+301000));
});
test('private key ciphertext cannot be accepted as public proof',()=>{
 const rec=encryptedRecord('test-passphrase-at-least-16');
 assert.throws(()=>signCandidatePossessionV1({...ch,secret:rec},pair.privateKey,pub,now));
});
