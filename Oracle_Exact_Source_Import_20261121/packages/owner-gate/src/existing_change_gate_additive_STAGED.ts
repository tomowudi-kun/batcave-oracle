// STAGED / NOT DEPLOYED. Existing batcave-change-gate-v1 GET preserved.
// POST contains only owner-authenticated LAB-only enroll/review, never deploy/shell.
import { withSupabase } from 'npm:@supabase/server';
// @ts-ignore: imported local JS verifier is bundled as a separate deployment file.
import { handleOracleLabOwnerRequest } from './owner_gate_core.mjs';

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
function repository(admin:any){
 const db=admin.schema('batcave');
 const requireData=async(q:any)=>{const {data,error}=await q;if(error)throw Error('GATE_DB_UNAVAILABLE');return data;};
 return {
  getOwnerKey:async(id:string)=>await requireData(db.from('linux_owner_keys_v1').select('owner_user_id,public_key_b64url,public_key_sha256,revoked_at').eq('owner_user_id',id).maybeSingle()),
  issueEnrollmentChallenge:async(a:any)=>await requireData(db.from('oracle_lab_enroll_challenges_v2').insert(a).select('challenge_id,owner_user_id,nonce,expires_at,consumed_at').single()),
  getChallenge:async(challengeId:string,ownerId:string)=>await requireData(db.from('oracle_lab_enroll_challenges_v2').select('challenge_id,owner_user_id,nonce,expires_at,consumed_at').eq('challenge_id',challengeId).eq('owner_user_id',ownerId).maybeSingle()),
  enrollVerifiedReviewer:async(a:any)=>{
   const {data,error}=await admin.rpc('batcave_oracle_lab_enroll_verified_v2',{
    p_owner_user_id:a.owner_user_id,p_challenge_id:a.challenge_id,
    p_nonce:a.request.nonce,p_expires_at:a.request.expires_at,
    p_public_record:a.public_record,p_owner_signature_b64url:a.signature_b64url
   });
   if(error)throw Error('GATE_ATOMIC_ENROLLMENT_UNAVAILABLE');return data;
  },
  getEnrolledReviewer:async(key:string)=>await requireData(db.from('oracle_lab_reviewer_keys_v1')
     .select('public_key_sha256,public_record,role,owner_user_id,release_archive_sha256,revoked_at')
     .eq('public_key_sha256',key).maybeSingle()),
  getModelJob:async(id:string)=>{
   const job=await requireData(db.from('commands').select('id,device_id,action,status,attempt_count,payload,created_at,expires_at').eq('id',id).maybeSingle());
   if(!job)return null;
   const device=await requireData(db.from('devices').select('device_name').eq('id',job.device_id).maybeSingle());
   return {...job,device_name:device?.device_name||''};
  },
  insertVerifiedGrant:async(a:any)=>{
   const {data,error}=await admin.rpc('batcave_oracle_lab_record_verified_v2',{
     p_owner_user_id:a.owner_user_id,p_job_id:a.job_id,p_nonce:a.nonce,
     p_request_sha256:a.request_sha256,p_raw_request_json:a.raw_request_json,
     p_signed_receipt:a.signed_receipt,p_expires_at:a.expires_at
   });
   if(error)throw Error('GATE_ATOMIC_GRANT_UNAVAILABLE');return data;
  }
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
   const result=await handleOracleLabOwnerRequest(body,{owner_user_id:ctx.userClaims.id,owner_authenticated:true},repository(ctx.supabaseAdmin));
   return respond(result.body,result.status,origin);
  }catch{return respond({error:'lab_gate_unavailable',execution_authorized:false,deployment_authorized:false},503,origin);}
 })
};
