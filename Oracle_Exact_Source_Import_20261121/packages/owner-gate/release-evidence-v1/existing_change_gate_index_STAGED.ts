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
import { labRepository } from './lab_repository.mjs';
const releaseActions = new Set(['oracle_first_reviewer_decline_v1','oracle_first_reviewer_status_v1','oracle_first_reviewer_endorse_v1','oracle_first_reviewer_challenge_v1','oracle_first_reviewer_register_v1','oracle_release_enrollment_challenge_v1','oracle_release_enroll_reviewer_v1','oracle_release_challenge_v1','oracle_release_record_evidence_v1']);
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
const repository=(_admin:any)=>labRepository(labSql);

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

