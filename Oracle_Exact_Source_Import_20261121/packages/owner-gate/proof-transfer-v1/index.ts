/* Separate evidence-only endpoint. Existing owner release gate/JWT remains unchanged. */
import {withSupabase} from 'npm:@supabase/server';
import postgres from 'npm:postgres@3.4.5';
import {submitPublicProof,ownerProofStatus,FLAGS} from './proof_transfer_core.mjs';
import {proofRepository} from './repository.mjs';
const sql=postgres(Deno.env.get('SUPABASE_DB_URL')!,{prepare:false,max:1,connect_timeout:5,idle_timeout:4}),repo=proofRepository(sql);
const ORIGIN='https://batcave-linux-approval.vercel.app';
const headers=(origin:string)=>({'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff',...(origin===ORIGIN?{'access-control-allow-origin':origin,'vary':'Origin'}:{})});
const reply=(v:unknown,status:number,origin='')=>new Response(JSON.stringify(v),{status,headers:headers(origin)});
const ownerHandler=withSupabase({auth:'user'},async(req:any,ctx:any)=>{
 const origin=req.headers.get('origin')||'';
 if(!ctx.userClaims?.id)return reply({...FLAGS,error:'UNAUTHORIZED'},401,origin);
 const {data,error}=await ctx.supabaseAdmin.auth.admin.getUserById(ctx.userClaims.id),u=data?.user;
 if(error||!u?.email_confirmed_at||!['tomo@wordsrweapons.com','mike.albanese@gmail.com'].includes((u.email||'').toLowerCase()))return reply({...FLAGS,error:'UNAUTHORIZED'},401,origin);
 const r=await ownerProofStatus(await req.json(),{authenticated:true,id:u.id},repo);return reply(r.body,r.status,origin);
});
export default {fetch:async(req:Request)=>{
 const origin=req.headers.get('origin')||'';
 if(req.method==='GET'&&new URL(req.url).pathname.endsWith('/health'))return reply({...FLAGS,public_proof_transfer_ready:true},200,origin);
 if(origin&&origin!==ORIGIN)return reply({...FLAGS,error:'ORIGIN_DENIED'},403);
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers:{...headers(origin),'access-control-allow-methods':'POST, OPTIONS','access-control-allow-headers':'authorization,apikey,content-type'}});
 if(req.method!=='POST'||!req.headers.get('content-type')?.startsWith('application/json'))return reply({...FLAGS,error:'BAD_REQUEST'},400,origin);
 let raw:string,body:any;try{raw=await req.text();if(raw.length>7000)throw Error();body=JSON.parse(raw);}catch{return reply({...FLAGS,error:'BAD_REQUEST'},400,origin);}
 try{
  // Submission authenticates both genuine signatures over the private gate's exact current challenge.
  // It stores public evidence only; it cannot activate a reviewer or change any gate.
  if(body?.op==='submit'){const r=await submitPublicProof(body,repo);return reply(r.body,r.status,origin);}
  if(body?.op!=='status')return reply({...FLAGS,error:'UNSUPPORTED_ACTION'},403,origin);
  const r=await ownerHandler(new Request(req.url,{method:'POST',headers:req.headers,body:raw}));
  const h=new Headers(r.headers);for(const[k,v]of Object.entries(headers(origin)))h.set(k,v);return new Response(r.body,{status:r.status,headers:h});
 }catch{return reply({...FLAGS,error:'PROOF_UNAVAILABLE'},503,origin);}
}};
