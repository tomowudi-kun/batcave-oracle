/* Owner-authenticated historical status. No signing, dispatch or grant writes. */
import {REVIEWER_KEY,FIXTURE_TOKEN,RELEASE_SHA} from './verify_owner_enrollment_v2.mjs';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HEX32=/^[a-f0-9]{32}$/, HEX64=/^[a-f0-9]{64}$/;
const deny=(error,status)=>({status,body:{error,read_only:true,execution_authorized:false,deployment_authorized:false}});
export async function readLabJobStatus(body,ctx,repo,now=Date.now()){
 if(ctx?.owner_authenticated!==true||!UUID.test(ctx?.owner_user_id||''))return deny('OWNER_AUTH_REQUIRED',401);
 if(!body||Object.keys(body).sort().join('|')!=='action|job_id|nonce'||body.action!=='oracle_lab_job_status_v1'||!UUID.test(body.job_id||'')||!HEX32.test(body.nonce||''))return deny('BAD_BODY',422);
 const j=await repo.getModelJobStatus(body.job_id,ctx.owner_user_id);
 if(!j||j.id!==body.job_id||j.owner_user_id!==ctx.owner_user_id||j.grant_nonce!==body.nonce||j.payload?.nonce!==body.nonce||j.device_name!=='Oracle'||j.action!=='oracle_model_generate_v1'||j.payload?.schema!=='batcave.oracle.job.v1'||j.payload?.operation!=='model_generate_and_verify_v1'||j.payload?.fixture!=='fixed_clamp_score_v1'||j.payload?.artifact_sha256!==FIXTURE_TOKEN||j.grant_artifact_sha256!==FIXTURE_TOKEN||j.reviewer_key_sha256!==REVIEWER_KEY||j.release_archive_sha256!==RELEASE_SHA||j.scope!=='disposable_lab_only')return deny('JOB_NOT_FOUND',404);
 const result={schema:'batcave.oracle.lab.status.v1',read_only:true,job_id:j.id,nonce:body.nonce,state:'needs_attention',completion_verified:false,attempt_count:j.attempt_count,execution_authorized:false,deployment_authorized:false};
 const p=j.result, r=p?.result;
 if(j.status==='succeeded'){
  const verified=j.receipt_matches===true&&j.receipt_outcome==='succeeded'&&!!j.consumed_at&&j.attempt_count===1&&p?.schema==='batcave.linux.receipt.v1'&&p.job_id===j.id&&p.operation==='model_generate_and_verify_v1'&&p.target==='BatcaveUbuntu'&&p.outcome==='success'&&r?.tests_passed===true&&r.tests_run===8&&r.model==='qwen2.5-coder:1.5b'&&HEX64.test(r.artifact_sha256||'')&&Number.isInteger(r.artifact_bytes)&&r.artifact_bytes>0&&Number.isFinite(Date.parse(j.completed_at))&&Date.parse(j.completed_at)<=now+30000;
  if(verified)Object.assign(result,{state:'succeeded',completion_verified:true,tests_run:8,tests_passed:true,model:r.model,artifact_sha256:r.artifact_sha256,completed_at:j.completed_at});
 }else if(j.status==='failed'){
  if(j.receipt_matches===true&&j.receipt_outcome==='failed'&&!!j.consumed_at)result.state='failed';
 }else if(j.status==='pending'){
  if(Number.isFinite(Date.parse(j.expires_at)))result.state=Date.parse(j.expires_at)>now?'queued':'expired';
 }else if(j.status==='leased'){
  if(Number.isFinite(Date.parse(j.expires_at))&&Date.parse(j.expires_at)>now)result.state='running';
 }else if(j.status==='expired')result.state='expired';
 return {status:200,body:result};
}
