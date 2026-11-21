import { withSupabase } from "npm:@supabase/server";

const allowedOrigins = new Set(["https://batcave-cloud-control.vercel.app"]);
const allowedOwners = new Set(["tomo@wordsrweapons.com", "mike.albanese@gmail.com"]);

function respond(body: unknown, status=200, origin="") {
  const headers: Record<string,string> = {
    "content-type":"application/json; charset=utf-8",
    "cache-control":"no-store, max-age=0",
    "x-content-type-options":"nosniff",
    "vary":"Origin"
  };
  if (allowedOrigins.has(origin)) headers["access-control-allow-origin"] = origin;
  return new Response(JSON.stringify(body),{status,headers});
}

export default {
  fetch: withSupabase({auth:"user"},async(req,ctx)=>{
    const origin=req.headers.get("origin")||"";
    if (req.method==="OPTIONS") {
      if (!allowedOrigins.has(origin)) return respond({error:"origin_denied"},403,origin);
      return new Response(null,{status:204,headers:{
        "access-control-allow-origin":origin,
        "access-control-allow-methods":"GET, OPTIONS",
        "access-control-allow-headers":"authorization, apikey, content-type",
        "access-control-max-age":"180", "cache-control":"no-store","vary":"Origin"
      }});
    }
    if(req.method!=="GET") return respond({error:"method_not_allowed"},405,origin);
    if(!ctx.userClaims?.id) return respond({error:"unauthenticated"},401,origin);
    const {data,error}=await ctx.supabaseAdmin.auth.admin.getUserById(ctx.userClaims.id);
    const account=data?.user;
    if(error||!account?.email_confirmed_at||!allowedOwners.has((account.email||"").toLowerCase())) {
       return respond({error:"forbidden"},403,origin);
    }
    const endpoint=new URL(req.url).pathname.split("/").filter(Boolean).pop();
    if (endpoint!=="batcave-change-gate-v1") return respond({error:"not_found"},404,origin);
    const db=ctx.supabaseAdmin.schema("batcave");
    const [r1,r2,r3]=await Promise.all([
      db.from("change_gate_rules").select("category,gate_mode,strict_nanny_required,batcave_identity_required,signed_scope_required,max_delegation_minutes").order("category"),
      db.from("change_gate_intents").select("intent_key,category,target_resource,summary,content_sha256,state,owner_auth_state,nanny_review_state,created_at,valid_until").order("created_at",{ascending:false}).limit(50),
      db.from("maintenance_release_candidates").select("release_key,operation,stage,signed_by_independent_reviewer,deployed_to_cortana,created_at").order("created_at",{ascending:false}).limit(50)
    ]);
    if(r1.error||r2.error||r3.error) return respond({error:"database_unavailable"},503,origin);
    return respond({
       schema:"batcave.change_gate.snapshot.v1",
       mode:"shadow",
       owner_authenticated:true,
       passkey_enrolled:false,
       passkey_enrollment_enabled:false,
       deployment_authorized:false,
       permits_mutations:false,
       observed_at:new Date().toISOString(),
       rules:r1.data||[],
       intents:r2.data||[],
       staged_releases:r3.data||[]
    },200,origin);
  })
};