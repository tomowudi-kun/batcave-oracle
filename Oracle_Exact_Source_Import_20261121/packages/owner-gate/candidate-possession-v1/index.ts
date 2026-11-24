/* STAGED ONLY — independent review required before deploying this NEW endpoint.
 * Never replace batcave-change-gate-v1 or batcave-first-proof-v1.
 * Deploy with verify_jwt:true. No privileged release or general host control.
 */
import {withSupabase} from 'npm:@supabase/server@1.9.2';
import postgres from 'npm:postgres@3.4.5';
import {handleCandidatePossessionOnlySTAGED,OWNER_ID}
 from './handler_STAGED.mjs';
import {makeCandidatePossessionPrivateRepoSTAGED}
 from '../release-evidence-v1/general_control_candidate_possession_private_repo_STAGED.mjs';
const ORIGIN='https://batcave-linux-approval.vercel.app';
const DB_URL=Deno.env.get('SUPABASE_DB_URL');
const db=DB_URL?postgres(DB_URL,{prepare:false,max:1,connect_timeout:5,idle_timeout:4}):null;
const services=db?makeCandidatePossessionPrivateRepoSTAGED(db):null;
const flags={registered:false,independently_attested:false,
 production_release_authorized:false,execution_authorized:false,
 deployment_authorized:false,grant_issued:false};
const reply=(body:Record<string,unknown>,status=200)=>
 new Response(JSON.stringify({...body,...flags}),{
  status,headers:{'content-type':'application/json; charset=utf-8',
   'cache-control':'no-store','x-content-type-options':'nosniff',
   'access-control-allow-origin':ORIGIN,'vary':'Origin'}});
const ownerHandler=withSupabase({auth:'user'},async(req:Request,ctx:any)=>{
 try{
  if(ctx.userClaims?.id!==OWNER_ID||!services)
   return reply({status:'DENY',reason:'OWNER_OR_DATABASE_UNAVAILABLE'},403);
  const {data,error}=await ctx.supabaseAdmin.auth.admin.getUserById(OWNER_ID);
  const user=data?.user;
  if(error||user?.id!==OWNER_ID||!user.email_confirmed_at||
   !['tomo@wordsrweapons.com','mike.albanese@gmail.com'].includes((user.email||'').toLowerCase()))
   return reply({status:'DENY',reason:'OWNER_NOT_VERIFIED'},403);
  const raw=await req.text();
  if(raw.length>3000)return reply({status:'DENY',reason:'REQUEST_TOO_LARGE'},400);
  const input=JSON.parse(raw);
  const result=await handleCandidatePossessionOnlySTAGED(input,{
   authenticated_owner:true,owner_user_id:OWNER_ID},services,Date.now());
  return reply(result,result.status==='DENY'?403:200);
 }catch{return reply({status:'DENY',reason:'INVALID_OR_UNAVAILABLE'},403);}
});
export default {fetch:(req:Request)=>{
 const origin=req.headers.get('origin');
 if(origin!==ORIGIN)return reply({status:'DENY',reason:'ORIGIN_DENIED'},403);
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers:{
  'access-control-allow-origin':ORIGIN,'vary':'Origin',
  'access-control-allow-methods':'POST, OPTIONS',
  'access-control-allow-headers':'authorization,apikey,content-type',
  'access-control-max-age':'180','cache-control':'no-store'}});
 if(req.method!=='POST'||!req.headers.get('content-type')?.startsWith('application/json'))
  return reply({status:'DENY',reason:'POST_JSON_REQUIRED'},405);
 return ownerHandler(req);
}};
