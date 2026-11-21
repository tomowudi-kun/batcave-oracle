// Batcave Oracle: outbound-only, typed runtime_inventory, fixed build and fixed model fixture adapter.
// STAGED: no shell jobs, no cloud-supplied prompts, no arbitrary targets.
const base=(Deno.env.get('SUPABASE_URL')||'').replace(/\/$/,'');
const role=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')||'';
const headers={'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff'};
const reply=(status:number,obj:unknown)=>new Response(JSON.stringify(obj),{status,headers});
const deny=(status:number)=>reply(status,{ok:false,scope:'oracle_runtime_inventory_v1'});
async function parseLimited(req:Request){
 if(!req.body)throw Error('missing_body');
 const reader=req.body.getReader(), chunks:Uint8Array[]=[]; let size=0;
 while(true){const {value,done}=await reader.read();if(done)break;size+=value.length;
 if(size>7200)throw Error('too_large');chunks.push(value);}
 const bytes=new Uint8Array(size);let offset=0;
 for(const part of chunks){bytes.set(part,offset);offset+=part.length;}
 return JSON.parse(new TextDecoder().decode(bytes));
}
Deno.serve(async(req:Request)=>{
 if(req.method!=='POST')return deny(405);
 if(!base||!role)return deny(503);
 const token=req.headers.get('x-batcave-device-token')||'';
 if(!/^[a-f0-9]{64}$/.test(token))return deny(401);
 let m:any;
 try{m=await parseLimited(req);}catch(e){return deny(String(e).includes('large')?413:400);}
 if(!m||typeof m!=='object'||Array.isArray(m))return deny(422);
 const keys=Object.keys(m).sort().join('|');
 if(m.op==='poll'||m.op==='status'||m.op==='poll_build'||m.op==='poll_model'||m.op==='capabilities'){
  if(keys!=='op')return deny(422);
 }else if(m.op==='receipt'){
  if(keys!=='command_id|nonce|op|result' ||
     !/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(m.command_id||'') ||
     !/^[a-f0-9]{32}$/.test(m.nonce||'') ||
     !m.result||typeof m.result!=='object'||Array.isArray(m.result) ||
     JSON.stringify(m.result).length>5000)return deny(422);
 }else return deny(422);
 try{
  const hashBytes=new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token)));
  const tokenHash=Array.from(hashBytes).map(x=>x.toString(16).padStart(2,'0')).join('');
  const resp=await fetch(base+'/rest/v1/rpc/batcave_oracle_bridge_v1',{
    method:'POST',headers:{'apikey':role,'authorization':'Bearer '+role,'content-type':'application/json'},
    body:JSON.stringify({
      p_token_hash:tokenHash,p_op:m.op,
      p_command_id:m.op==='receipt'?m.command_id:null,
      p_nonce:m.op==='receipt'?m.nonce:null,
      p_result:m.op==='receipt'?m.result:null
    })
  });
  if(!resp.ok)return deny(503);
  const result=await resp.json();
  if(result?.ok!==true)
    return deny([401,409,422].includes(result?.http_status)?result.http_status:503);
  if(result?.scope!=='oracle_runtime_inventory_v1')return deny(503);
  const encoded=JSON.stringify(result);
  if(encoded.length>7500)return deny(503);
  return reply(200,result);
 }catch{return deny(503);}
});
