// STAGED ONLY: independent release EVIDENCE, never deploy without independent review.
// Existing batcave-change-gate-v1 GET and LAB paths preserved.
// POST contains only owner-authenticated LAB-only enroll/review, never deploy/shell.
import { withSupabase } from 'npm:@supabase/server';
import postgres from 'npm:postgres@3.4.5';
const labSql=postgres(Deno.env.get('SUPABASE_DB_URL')!,{prepare:false,max:1,connect_timeout:5,idle_timeout:4});
// @ts-ignore: imported local JS verifier is bundled as a separate deployment file.
import { handleOracleLabOwnerRequest } from './owner_gate_core.mjs';

import { handleReleaseGate } from './release_gate_core.mjs';
import { releaseRepository } from './release_repository.mjs';
const releaseActions = new Set(['oracle_release_enrollment_challenge_v1','oracle_release_enroll_reviewer_v1','oracle_release_challenge_v1','oracle_release_record_evidence_v1']);
const allowedOrigins = new Set([
 'https://batcave-cloud-control.vercel.app',
 'https://batcave-linux-approval.vercel.app'
]);
const allowedOwners = new Set(['tomo@wordsrweapons.com','mike.albanese@gmail.com']);
function respond(body: unknown,status=200,origin='') {
 const headers:Record<string,string>={
  'content-type':'application/json; charset=utf-8',
  'cache-control':'no-store, max-age=0',
  'x-content-type-options':'nosniff','vary':'Origin'
 };
 if(allowedOrigins.has(origin))headers['access-control-allow-origin']=origin;
 return new Response(JSON.stringify(body),{status,headers});
}
function repository(_admin:any){
 // Parameterized private DB queries; do not expose the batcave schema through PostgREST.
 return {
  getOwnerKey:async(id:string)=>(await labSql`SELECT owner_user_id,public_key_b64url,public_key_sha256,revoked_at FROM batcave.linux_owner_keys_v1 WHERE owner_user_id=${id}::uuid LIMIT 1`)[0]||null,
  issueEnrollmentChallenge:async(a:any)=>(await labSql`INSERT INTO batcave.oracle_lab_enroll_challenges_v2(owner_user_id,nonce,expires_at) VALUES (${a.owner_user_id}::uuid,${a.nonce},${a.expires_at}::timestamptz) RETURNING challenge_id,owner_user_id,nonce,expires_at,consumed_at`)[0]||null,
  getChallenge:async(challengeId:string,ownerId:string)=>(await labSql`SELECT challenge_id,owner_user_id,nonce,expires_at,consumed_at FROM batcave.oracle_lab_enroll_challenges_v2 WHERE challenge_id=${challengeId}::uuid AND owner_user_id=${ownerId}::uuid LIMIT 1`)[0]||null,
  enrollVerifiedReviewer:async(a:any)=>(await labSql`SELECT public.batcave_oracle_lab_enroll_verified_v2(${a.owner_user_id}::uuid,${a.challenge_id}::uuid,${a.request.nonce},${a.request.expires_at}::timestamptz,${labSql.json(a.public_record)}::jsonb,${a.signature_b64url}) AS result`)[0]?.result||null,
  getEnrolledReviewer:async(key:string)=>(await labSql`SELECT public_key_sha256,public_record,role,owner_user_id,release_archive_sha256,revoked_at FROM batcave.oracle_lab_reviewer_keys_v1 WHERE public_key_sha256=${key} LIMIT 1`)[0]||null,
  getModelJob:async(id:string)=>(await labSql`SELECT c.id,c.device_id,c.action,c.status,c.attempt_count,c.payload,c.created_at,c.expires_at,d.device_name FROM batcave.commands c LEFT JOIN batcave.devices d ON d.id=c.device_id WHERE c.id=${id}::uuid LIMIT 1`)[0]||null,
  insertVerifiedGrant:async(a:any)=>(await labSql`SELECT public.batcave_oracle_lab_record_verified_v2(${a.owner_user_id}::uuid,${a.job_id}::uuid,${a.nonce},${a.request_sha256},${a.raw_request_json},${JSON.stringify(a.signed_receipt)}::jsonb,${a.expires_at}::timestamptz) AS result`)[0]?.result||null
 };
}
export default {
 fetch:withSupabase({auth:'user'},async(req:any,ctx:any)=>{
  const origin=req.headers.get('origin')||'';
  if(req.method==='OPTIONS'){
   if(!allowedOrigins.has(origin))return respond({error:'origin_denied'},403,origin);
   return new Response(null,{status:204,headers:{
    'access-control-allow-origin':origin,'access-control-allow-methods':'GET, POST, OPTIONS',
    'access-control-allow-headers':'authorization, apikey, content-type',
    'access-control-max-age':'180','cache-control':'no-store','vary':'Origin'
   }});
  }
  if(req.method!=='GET'&&req.method!=='POST')return respond({error:'method_not_allowed'},405,origin);
  if(!ctx.userClaims?.id)return respond({error:'unauthenticated'},401,origin);
  const {data,error}=await ctx.supabaseAdmin.auth.admin.getUserById(ctx.userClaims.id);
  const account=data?.user;
  if(error||!account?.email_confirmed_at||!allowedOwners.has((account.email||'').toLowerCase()))
   return respond({error:'forbidden'},403,origin);
  const endpoint=new URL(req.url).pathname.split('/').filter(Boolean).pop();
  if(endpoint!=='batcave-change-gate-v1')return respond({error:'not_found'},404,origin);
  const db=ctx.supabaseAdmin.schema('batcave');
  if(req.method==='GET'){
   // EXACT original shadow-only provider snapshot contract, no new production powers.
   const [r1,r2,r3]=await Promise.all([
    db.from('change_gate_rules').select('category,gate_mode,strict_nanny_required,batcave_identity_required,signed_scope_required,max_delegation_minutes').order('category'),
    db.from('change_gate_intents').select('intent_key,category,target_resource,summary,content_sha256,state,owner_auth_state,nanny_review_state,created_at,valid_until').order('created_at',{ascending:false}).limit(50),
    db.from('maintenance_release_candidates').select('release_key,operation,stage,signed_by_independent_reviewer,deployed_to_cortana,created_at').order('created_at',{ascending:false}).limit(50)
   ]);
   if(r1.error||r2.error||r3.error)return respond({error:'database_unavailable'},503,origin);
   return respond({schema:'batcave.change_gate.snapshot.v1',mode:'shadow',owner_authenticated:true,
    passkey_enrolled:false,passkey_enrollment_enabled:false,deployment_authorized:false,
    permits_mutations:false,observed_at:new Date().toISOString(),rules:r1.data||[],
    intents:r2.data||[],staged_releases:r3.data||[]},200,origin);
  }
  // The existing production GET flags remain false. The POST is LAB ONLY.
  if(origin&& !allowedOrigins.has(origin))return respond({error:'origin_denied',deployment_authorized:false},403,origin);
  if(!req.headers.get('content-type')?.toLowerCase().startsWith('application/json'))return respond({error:'bad_content_type'},415,origin);
  let body;
  try{const raw=await req.text();if(raw.length>8500)return respond({error:'payload_too_large'},413,origin);body=JSON.parse(raw);}
  catch{return respond({error:'bad_json'},400,origin);}
  try{
   const ownerContext={owner_user_id:ctx.userClaims.id,owner_authenticated:true};
   const result=releaseActions.has(body?.action)
     ? await handleReleaseGate(body,ownerContext,releaseRepository(labSql))
     : await handleOracleLabOwnerRequest(body,ownerContext,repository(ctx.supabaseAdmin));
   return respond(result.body,result.status,origin);
  }catch{return respond({error:'lab_gate_unavailable',execution_authorized:false,deployment_authorized:false},503,origin);}
 })
};

