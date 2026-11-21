"use strict";
const ORIGIN="https://batcave-linux-approval.vercel.app";
const SUPABASE="https://wizflveeptzeajsdybzs.supabase.co";
const KEY="sb_publishable_WUpPRJuKpeR8E4eRboGKhA_mhY20UoW";
const EVIDENCE=SUPABASE+"/functions/v1/batcave-linux-evidence-v1";
const VERIFY="https://batcave-nanny-verifier.vercel.app/api/verify";
function out(message,value){
 document.getElementById("status").textContent=message;
 document.getElementById("output").textContent=value?JSON.stringify(value,null,2):"";
}
document.getElementById("verify").onclick=async()=>{
 try{
  if(location.origin!==ORIGIN)throw Error("Preview mode: real owner verification is disabled until the reviewed build is promoted.");
  const raw=sessionStorage.getItem("batcave_linux_session_v1");
  const session=raw?JSON.parse(raw):null;
  if(!session||typeof session.access_token!=="string"||!session.user?.id)throw Error("No authenticated session in this tab. Return to the owner approval portal and sign in here.");
  out("Checking signed receipt through Supabase...");
  const result=await fetch(EVIDENCE,{method:"POST",cache:"no-store",headers:{"content-type":"application/json",
    "apikey":KEY,"authorization":"Bearer "+session.access_token},body:JSON.stringify({action:"latest_signed_evidence"})});
  const bundle=await result.json().catch(()=>null);
  if(!result.ok)throw Error("Signed evidence request rejected: "+(bundle?.error||result.status));
  if(bundle?.schema!=="batcave.linux.evidence.v1")throw Error("Unexpected evidence format");
  out("Independently checking Ed25519 signature and scope on Vercel...");
  const verified=await fetch(VERIFY,{method:"POST",cache:"no-store",headers:{"content-type":"application/json"},body:JSON.stringify(bundle)});
  const check=await verified.json().catch(()=>null);
  if(!verified.ok)throw Error("Verifier rejected request: "+(check?.error||verified.status));
  if(check?.execution_authorized!==false||check?.can_release!==false)throw Error("Unsafe verifier response: execution permission must be false");
  out(check.independently_verified?
     (check.unexpired?"Signature and scope verified. Execution remains DISABLED.":"Historical signature verified. Proposal expired; execution remains DISABLED."):
     "Verification failed. No execution permitted.",{
       independent_signature_valid:check.owner_signature_valid,
       request_digest_valid:check.request_digest_valid,
       key_fingerprint_valid:check.owner_key_fingerprint_valid,
       exact_scope_valid:check.scope_valid,
       within_original_time_window:check.within_window,
       unexpired:check.unexpired,
       verdict:check.reason,
       execution_authorized:false
     });
 }catch(e){out(e.message||"Unable to verify receipt. No execution permitted.");}
};