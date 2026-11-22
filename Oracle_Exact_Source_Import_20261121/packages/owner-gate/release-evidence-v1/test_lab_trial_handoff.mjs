import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {buildLabRequestCommand,parseTrialRequest,checkLabReceipt} from './lab_trial_handoff.mjs';
import {verifyOracleLabReview,sortedJson} from '../src/verify_lab_grant.mjs';
const now=Date.parse('2026-11-22T06:30:00Z');
const req={schema:'batcave.nanny.lab.request.v1',request_id:'f26d9f50-45b9-48cf-bd66-5f2338031cba',device:'Oracle',operation:'oracle_model_fixture_v1',scope:'disposable_lab_only',artifact_sha256:'4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f',nonce:'f'.repeat(32),created_at:'2026-11-22T06:30:00Z',expires_at:'2026-11-22T06:40:00Z'};
test('public request remains compatible with the existing cloud verifier using an explicitly synthetic signer',async()=>{
 const raw=JSON.stringify(req);assert.deepEqual(parseTrialRequest(raw,now),req);
 const pair=generateKeyPairSync('ed25519'),pem=pair.publicKey.export({type:'spki',format:'pem'}),fp=createHash('sha256').update(pair.publicKey.export({type:'spki',format:'der'})).digest('hex');
 const payload={schema:'batcave.nanny.lab.receipt.v1',request_id:req.request_id,request_sha256:createHash('sha256').update(raw).digest('hex'),host:'CORTANA',reviewer_sid:'S-1-5-19',decision:'LAB_ALLOW',reason:'allowlisted_disposable_lab_only',reviewed_at:'2026-11-22T06:30:01.000Z',execution_authorized:false,deployment_authorized:false,production_release_authorized:false};
 const checked=await verifyOracleLabReview({requestJson:raw,receipt:{payload,signature_b64url:sign(null,Buffer.from('batcave.nanny.lab.review.v1\n'+sortedJson(payload)),pair.privateKey).toString('base64url')},publicRecord:{schema:'batcave.nanny.public_key.request.v1',host:'CORTANA',reviewer_sid:'S-1-5-19',role:'lab_reviewer_only',public_key_pem:pem,public_key_sha256:fp,production_release_authorized:false,cloud_enrolled:false},trust:{role:'lab_reviewer_only',enrollment_verified:true,revoked_at:null,public_key_sha256:fp},job:{id:req.request_id,nonce:req.nonce,schema:'batcave.oracle.job.v1',action:'oracle_model_generate_v1',operation:'model_generate_and_verify_v1',fixture:'fixed_clamp_score_v1',artifact_sha256:req.artifact_sha256},now:now+1000,expectedPublicFingerprint:fp});
 assert.equal(checked.review_valid,true);assert.equal(checked.production_deployment_authorized,false);
});
test('PowerShell transports identical request bytes, without a private key or shell payload',()=>{
 const raw=JSON.stringify(req),script=buildLabRequestCommand(raw,now),b64=script.match(/FromBase64String\("([A-Za-z0-9+/=]+)"\)/)[1];
 assert.equal(Buffer.from(b64,'base64').toString(),raw);assert.ok(script.includes('Move-Item -LiteralPath $temp -Destination $request'));assert.ok(script.includes('LAB_REVIEW_READY='));assert.doesNotMatch(script,/private_key|private\.encrypted|Read-Host|Invoke-Expression|Invoke-RestMethod|Start-Process|Set-Clipboard|--serve/);
});
test('generated public inbox handoff parses in real PowerShell without executing it',t=>{
 const encoded=Buffer.from(buildLabRequestCommand(JSON.stringify(req),now)).toString('base64');
 const parser="$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+encoded+"'));$tokens=$null;$errors=$null;[System.Management.Automation.Language.Parser]::ParseInput($s,[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count){$errors|ForEach-Object {$_.Message};exit 1}";
 const r=spawnSync('pwsh',['-NoLogo','-NoProfile','-NonInteractive','-Command',parser],{encoding:'utf8'});
 if(r.error?.code==='ENOENT'&&!process.env.CI){t.skip('Real PowerShell parser is required in GitHub CI');return;}
 assert.equal(r.status,0,r.stdout+r.stderr);
});
test('expired and extended windows and unreviewed capabilities fail before file publication',()=>{
 for(const r of [{...req,expires_at:'2026-11-22T06:41:00Z'},{...req,scope:'computer_control'},{...req,operation:'shell'},{...req,nonce:'invalid'},{...req,extra:'field'},{...req,created_at:'2026-11-22T06:30:00.000Z'}])assert.throws(()=>buildLabRequestCommand(JSON.stringify(r),now));
 assert.throws(()=>buildLabRequestCommand(JSON.stringify(req),now+600000));
});
test('malformed, wrong-job and tampered public receipts are rejected',async()=>{
 const raw=JSON.stringify(req),p={schema:'batcave.nanny.lab.receipt.v1',request_id:req.request_id,request_sha256:createHash('sha256').update(raw).digest('hex'),host:'CORTANA',reviewer_sid:'S-1-5-19',decision:'LAB_ALLOW',reason:'allowlisted_disposable_lab_only',reviewed_at:'2026-11-22T06:30:01.000Z',execution_authorized:false,deployment_authorized:false,production_release_authorized:false};
 await assert.rejects(checkLabReceipt(raw,{payload:p,signature_b64url:'A'.repeat(86)},now+1000),/signature verification failed/);
 for(const patch of [{request_id:'f26d9f50-45b9-48cf-bd66-5f2338031cbb'},{request_sha256:'0'.repeat(64)},{execution_authorized:true},{reviewer_sid:'S-1-5-18'},{reviewed_at:'2026-11-22T06:29:59.000Z'}])await assert.rejects(checkLabReceipt(raw,{payload:{...p,...patch},signature_b64url:'A'.repeat(86)},now+1000));
});
