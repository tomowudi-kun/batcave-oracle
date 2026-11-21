
"use strict";
const BASE="https://wizflveeptzeajsdybzs.supabase.co";
const APIKEY="sb_publishable_WUpPRJuKpeR8E4eRboGKhA_mhY20UoW";
const OWNER=BASE+"/functions/v1/batcave-linux-owner-v1";
const NANNY=BASE+"/functions/v1/batcave-linux-nanny-review-v1";
const $=id=>document.getElementById(id);
let session=null;
const te=new TextEncoder();
function print(message,data){$("status").textContent=message;$("output").textContent=data?JSON.stringify(data,null,2):""}
function b64(data){let s="";for(let i=0;i<data.length;i++)s+=String.fromCharCode(data[i]);return btoa(s).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");}
function val(id){return $(id).value.trim();}
async function authReq(path,body){
 const resp=await fetch(BASE+"/auth/v1/"+path,{method:"POST",headers:{"content-type":"application/json","apikey":APIKEY},body:JSON.stringify(body),cache:"no-store"});
 const data=await resp.json().catch(()=>({}));
 if(!resp.ok)throw Error("Authentication error: "+(data.msg||data.error_description||data.message||String(resp.status)));
 return data;
}
async function api(url,body){
 if(!session?.access_token)throw Error("Sign in first");
 const res=await fetch(url,{method:"POST",headers:{"content-type":"application/json","apikey":APIKEY,"authorization":"Bearer "+session.access_token},cache:"no-store",body:JSON.stringify(body)});
 const x=await res.json().catch(()=>({}));
 if(!res.ok)throw Error(x.error||"Server rejected request ("+res.status+")");
 return x;
}
function saveSession(data){
 if(!data.access_token||!data.user?.id)throw Error("Supabase returned no authenticated user session");
 session={access_token:data.access_token,refresh_token:data.refresh_token,user:data.user};
 sessionStorage.setItem("batcave_linux_session_v1",JSON.stringify(session));
 print("Signed in as "+(session.user.email||"owner"),{owner_id:session.user.id,execution_enabled:false});
 $("password").value="";
 $("code").value="";
}
async function refresh(){
 if(!session?.refresh_token)throw Error("Sign in first");
 const data=await authReq("token?grant_type=refresh_token",{refresh_token:session.refresh_token});
 saveSession(data);
}
async function withSession(fn){
 try{
   if(!session)throw Error("Sign in first");
   if(session.access_token){
     try{return await fn();}catch(e){
       if(/invalid.*jwt|token.*expired|unauthorized|401/i.test(String(e.message))&&session.refresh_token){await refresh();return fn();}
       throw e;
     }
   }
 }catch(e){print(e.message||"Request failed");}
}
function database(){
 return new Promise((resolve,reject)=>{
   const r=indexedDB.open("batcave_linux_signer_v1",1);
   r.onupgradeneeded=()=>r.result.createObjectStore("keys");
   r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);
 });
}
async function putKey(id,key){
 const db=await database();
 await new Promise((resolve,reject)=>{
   const tx=db.transaction("keys","readwrite");
   tx.objectStore("keys").put(key,id);
   tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error);
 });
 db.close();
}
async function getKey(id){
 const db=await database();
 const key=await new Promise((resolve,reject)=>{
   const tx=db.transaction("keys","readonly");
   const r=tx.objectStore("keys").get(id);
   r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);
 });
 db.close();return key;
}
async function signed(key,message){return b64(new Uint8Array(await crypto.subtle.sign("Ed25519",key,te.encode(message))))}
$("sendCode").onclick=async()=>{
 try{const e=val("email");if(!e)throw Error("Enter your confirmed owner email");await authReq("otp?redirect_to="+encodeURIComponent(location.origin+"/"),{email:e,create_user:false});print("Check your email for the Magic Link. Open it in this same Chrome profile. A code can be entered below only if the email contains one. If the link returns to a different page, the Supabase Auth redirect URL still needs approval.")}catch(e){print(e.message)}
};
$("sendOracleCode").onclick=async()=>{
 try{
  const e=val("email");if(!e)throw Error("Enter the existing owner email first");
  await authReq("otp?redirect_to="+encodeURIComponent(location.origin+"/"),{email:e,create_user:false});
  localStorage.setItem("batcave_oracle_login_handoff_v1",String(Date.now()));
  print("Fresh Oracle sign-in link requested. Open the newest email link in this same Chrome profile. On success, the portal will continue to Oracle lab enrollment. Do not reuse an earlier link.");
 }catch(e){print("Oracle sign-in request failed: "+(e.message||e));}
};
function finishOracleLoginHandoff(){
 const when=Number(localStorage.getItem("batcave_oracle_login_handoff_v1")||0);
 if(when&&Date.now()-when<15*60*1000){localStorage.removeItem("batcave_oracle_login_handoff_v1");location.replace("/oracle-lab.html");}
 else if(when)localStorage.removeItem("batcave_oracle_login_handoff_v1");
}
$("verifyCode").onclick=async()=>{
 try{const data=await authReq("verify",{email:val("email"),token:val("code"),type:"email"});saveSession(data);finishOracleLoginHandoff()}catch(e){print(e.message)}
};
$("signInPassword").onclick=async()=>{
 try{const data=await authReq("token?grant_type=password",{email:val("email"),password:$("password").value});saveSession(data)}catch(e){print(e.message)}
};
$("logout").onclick=()=>{session=null;sessionStorage.removeItem("batcave_linux_session_v1");print("Signed out. Your non-exportable browser key was not removed.")};
$("checkStatus").onclick=()=>withSession(async()=>{const r=await api(OWNER,{action:"status"});print("Owner key status",r)});
$("enroll").onclick=()=>withSession(async()=>{
 const s=await api(OWNER,{action:"status"});
 if(s.key_enrolled)throw Error("An owner key is already enrolled; replacement requires a separate approved recovery process.");
 let saved=await getKey(session.user.id);
 const challenge=await api(OWNER,{action:"enrollment_challenge"});
 if(!saved){
   const pair=await crypto.subtle.generateKey({name:"Ed25519"},false,["sign","verify"]);
   const pub=b64(new Uint8Array(await crypto.subtle.exportKey("raw",pair.publicKey)));
   saved={privateKey:pair.privateKey,publicKeyB64:pub};
   await putKey(session.user.id,saved);
 }
 if(!saved?.privateKey||!saved?.publicKeyB64)throw Error("Local signing key is incomplete; request a reviewed enrollment recovery.");
 const sig=await signed(saved.privateKey,challenge.message);
 const result=await api(OWNER,{action:"enroll",challenge_id:challenge.challenge_id,public_key_b64url:saved.publicKeyB64,signature_b64url:sig});
 print("Owner key enrolled; command execution remains disabled",result);
});
$("signReview").onclick=()=>withSession(async()=>{
 const key=await getKey(session.user.id);
 if(!key)throw Error("No signing key in this browser profile; enroll first or use the enrolled browser.");
 const proposal=await api(OWNER,{action:"create_intent"});
 const signature=await signed(key.privateKey,proposal.signing_message);
 const signedResult=await api(OWNER,{action:"sign_intent",intent_id:proposal.intent_id,signature_b64url:signature});
 if(!signedResult.owner_signature_verified)throw Error("Owner signature was not verified");
 const review=await api(NANNY,{intent_id:proposal.intent_id});
 print(review.verdict==="valid_but_held"?"Independent signature and scope review passed — execution still disabled":"Independent review denied",review);
});
try{const saved=JSON.parse(sessionStorage.getItem("batcave_linux_session_v1")||"null");if(saved?.access_token&&saved.user?.id){session=saved;print("Existing browser session recovered. Use Check enrollment to verify.")}}catch{}

async function consumeMagicLinkCallback(){
 const fragment=window.location.hash.startsWith("#")?window.location.hash.substring(1):"";
 const p=new URLSearchParams(fragment);
 if(!p.has("access_token")&&!p.has("error")&&!p.has("error_code"))return;
 const access=p.get("access_token"),refreshToken=p.get("refresh_token");
 const err=p.get("error"),errorCode=p.get("error_code");
 history.replaceState(null,"",window.location.pathname);
 if(err||errorCode){
    print("Email sign-in link failed. Request a fresh link.",{error:err||errorCode,description:p.get("error_description")||""});
    return;
 }
 if(!access||!refreshToken){print("Email link did not return a complete session. Request a new link.");return;}
 try{
    const result=await fetch(BASE+"/auth/v1/user",{
      headers:{"apikey":APIKEY,"authorization":"Bearer "+access},
      cache:"no-store"
    });
    if(!result.ok)throw Error("Session verification failed ("+result.status+")");
    const user=await result.json();
    if(!user?.id)throw Error("No user identity returned");
    saveSession({access_token:access,refresh_token:refreshToken,user});
    finishOracleLoginHandoff();
 }catch(e){print("Email link could not complete sign-in: "+e.message);}
}
consumeMagicLinkCallback().catch(e=>print("Magic link callback error: "+e.message));
