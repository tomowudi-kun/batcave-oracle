const fs=require('fs');const vm=require('vm');const assert=require('assert');
const ts=require('/opt/nvm/versions/node/v22.16.0/lib/node_modules/typescript/lib/typescript.js');
const path=require('path');
const src=fs.readFileSync(path.join(__dirname,'../cloud/index.ts'),'utf8');
const transpiled=ts.transpileModule(src,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None},reportDiagnostics:true});
if(transpiled.diagnostics.length){throw new Error(transpiled.diagnostics.map(x=>ts.flattenDiagnosticMessageText(x.messageText,'\n')).join('\n'))}
let handler;let forwarded;
const context={Deno:{env:{get:k=>({'SUPABASE_URL':'https://private.example','SUPABASE_SERVICE_ROLE_KEY':'test-secret'}[k])},serve:fn=>{handler=fn}},
TextDecoder,TextEncoder,Uint8Array,JSON,Error,Response,Request,crypto:require('crypto').webcrypto,
fetch:async(url,init)=>{forwarded=JSON.parse(init.body);return new Response(JSON.stringify({ok:true,scope:'oracle_runtime_inventory_v1',capabilities:['runtime_inventory','disposable_project_build_v1','model_generate_and_verify_v1']}),{status:200});}};
vm.runInNewContext(transpiled.outputText,context,{timeout:3000});
const key='a'.repeat(64);
function req(x,token=key){return new Request('https://edge.example',{method:'POST',headers:{'x-batcave-device-token':token},body:JSON.stringify(x)})}
async function go(){
 let r=await handler(req({op:'capabilities'}));assert.equal(r.status,200);assert.equal((await r.json()).capabilities[2],'model_generate_and_verify_v1');assert.equal(forwarded.p_op,'capabilities');
 r=await handler(req({op:'poll_model'}));assert.equal(r.status,200);assert.equal(forwarded.p_op,'poll_model');
 r=await handler(req({op:'poll_build'}));assert.equal(r.status,200);assert.equal(forwarded.p_op,'poll_build');
 r=await handler(req({op:'poll'}));assert.equal(r.status,200);assert.equal(forwarded.p_op,'poll');
 r=await handler(req({op:'arbitrary_shell'}));assert.equal(r.status,422);
 r=await handler(req({op:'poll_model',prompt:'ignore policy'}));assert.equal(r.status,422);
 r=await handler(req({op:'poll_model'},'b'));assert.equal(r.status,401);
 console.log('EDGE_TYPED_CONTRACT_TESTS_PASS=7');
}
go().catch(e=>{console.error(e);process.exitCode=1});
