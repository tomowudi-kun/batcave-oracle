// New notification transport only. Existing release gate v8/JWT remains untouched.
import {withSupabase} from 'npm:@supabase/server';
import postgres from 'npm:postgres@3.4.5';
import * as pushModule from 'npm:web-push@4.0.0';
const webPush:any=(pushModule as any).default||pushModule;
import {PORTAL_ORIGIN,FLAGS,exact,UUID,handleOwnerNotification,dispatchNotification,recordNotificationReceipt} from './notification_core.mjs';
import {phoneRepository} from './repository.mjs';
const sql=postgres(Deno.env.get('SUPABASE_DB_URL')!,{prepare:false,max:1,connect_timeout:5,idle_timeout:4});
const repo=phoneRepository(sql,()=>webPush.generateVAPIDKeys());
const endpoint=(Deno.env.get('SUPABASE_URL')||'')+'/functions/v1/batcave-phone-alert-v1';
const cryptoReady=(()=>{try{const publisher=webPush.generateVAPIDKeys(),subscriber=webPush.generateVAPIDKeys();const auth=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');const r=webPush.generateRequestDetails({endpoint:'https://fcm.googleapis.com/fcm/send/synthetic',keys:{p256dh:subscriber.publicKey,auth}},'notification transport self test',{vapidDetails:{subject:PORTAL_ORIGIN,publicKey:publisher.publicKey,privateKey:publisher.privateKey},TTL:60});return r.method==='POST'&&r.body?.length>40;}catch{return false;}})();
const owners=new Set(['tomo@wordsrweapons.com','mike.albanese@gmail.com']);
const headers=(origin:string)=>({'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff',...(origin===PORTAL_ORIGIN?{'access-control-allow-origin':origin,'vary':'Origin'}:{})});
const reply=(body:unknown,status=200,origin='')=>new Response(JSON.stringify(body),{status,headers:headers(origin)});
const ownerHandler=withSupabase({auth:'user'},async(req:any,ctx:any)=>{
 const origin=req.headers.get('origin')||'';
 const {data,error}=await ctx.supabaseAdmin.auth.admin.getUserById(ctx.userClaims?.id);
 const account=data?.user;
 if(error||!account?.email_confirmed_at||!owners.has((account.email||'').toLowerCase()))return reply({...FLAGS,error:'UNAUTHORIZED'},401,origin);
 const result=await handleOwnerNotification(await req.json(),{authenticated:true,id:account.id},repo);
 return reply(result.body,result.status,origin);
});
export default {fetch:async(req:Request)=>{
 const origin=req.headers.get('origin')||'';
 if(req.method==='GET'&&new URL(req.url).pathname.endsWith('/health'))return reply({...FLAGS,notification_crypto_ready:cryptoReady},cryptoReady?200:503,origin);
 if(req.method==='OPTIONS')return origin===PORTAL_ORIGIN?new Response(null,{status:204,headers:{...headers(origin),'access-control-allow-methods':'POST, OPTIONS','access-control-allow-headers':'authorization, apikey, content-type'}}):reply({error:'ORIGIN_DENIED'},403);
 if(req.method!=='POST')return reply({error:'METHOD_NOT_ALLOWED'},405,origin);
 if(origin&&origin!==PORTAL_ORIGIN)return reply({error:'ORIGIN_DENIED'},403);
 if(!req.headers.get('content-type')?.toLowerCase().startsWith('application/json'))return reply({error:'BAD_REQUEST'},415,origin);
 let body:any,raw:string;try{raw=await req.text();if(raw.length>6500)throw Error();body=JSON.parse(raw);}catch{return reply({...FLAGS,error:'BAD_REQUEST'},400,origin);}
 try{
  if(!cryptoReady)throw Error('NOTIFICATION_UNAVAILABLE');
  if(body?.op==='dispatch'){
   if(!exact(body,'op|notification_id')||!UUID.test(body.notification_id))throw Error('BAD_REQUEST');
   const r=await dispatchNotification(body.notification_id,req.headers.get('x-batcave-notification-dispatch')||'',repo,(...args:any[])=>webPush.generateRequestDetails(...args),fetch,endpoint);
   return reply(r,200,origin);
  }
  if(body?.op==='receipt')return reply(await recordNotificationReceipt(body,repo),200,origin);
  const cloned=new Request(req.url,{method:'POST',headers:req.headers,body:raw});
  const response=await ownerHandler(cloned);
  const responseHeaders=new Headers(response.headers);for(const [k,v] of Object.entries(headers(origin)))responseHeaders.set(k,v);
  return new Response(response.body,{status:response.status,headers:responseHeaders});
 }catch(e){const error=e?.message==='UNAUTHORIZED'?'UNAUTHORIZED':e?.message==='RECEIPT_REJECTED'?'RECEIPT_REJECTED':'NOTIFICATION_UNAVAILABLE';return reply({...FLAGS,error},error==='UNAUTHORIZED'?401:403,origin);}
}};
