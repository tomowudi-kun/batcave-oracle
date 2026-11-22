/* Public-file transport for the existing lab reviewer and owner-authenticated gate.
 * This module never signs, enrolls a key, creates a job, or inserts a grant. */
const ARTIFACT='4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f';
const KEY='MCowBQYDK2VwAyEAPkCiAsi/f6Cv2UkYCYZbE3z8L5pgUi339QB+yLVvKCo=';
const REQUEST_KEYS='artifact_sha256|created_at|device|expires_at|nonce|operation|request_id|schema|scope';
const RECEIPT_KEYS='decision|deployment_authorized|execution_authorized|host|production_release_authorized|reason|request_id|request_sha256|reviewed_at|reviewer_sid|schema';
const te=new TextEncoder();
const must=(v,s)=>{if(!v)throw Error(s);};
const keys=x=>Object.keys(x||{}).sort().join('|');
const stable=x=>x&&typeof x==='object'?'{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+JSON.stringify(x[k])).join(',')+'}':JSON.stringify(x);
const bytes=x=>Uint8Array.from(atob(x.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-x.length%4)%4)),c=>c.charCodeAt(0));
const hex=x=>Array.from(x,b=>b.toString(16).padStart(2,'0')).join('');
async function digest(raw){return hex(new Uint8Array(await crypto.subtle.digest('SHA-256',te.encode(raw))));}
function iso(s){return typeof s==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(s)&&new Date(s).toISOString().replace('.000Z','Z')===s;}
export function parseTrialRequest(raw,now=Date.now()){
 must(typeof raw==='string'&&raw.length>=100&&raw.length<=2048,'Invalid public lab request.');
 const r=JSON.parse(raw);
 must(keys(r)===REQUEST_KEYS&&Object.values(r).every(x=>typeof x==='string'),'Invalid public lab request fields.');
 must(r.schema==='batcave.nanny.lab.request.v1'&&r.device==='Oracle'&&r.operation==='oracle_model_fixture_v1'&&r.scope==='disposable_lab_only'&&r.artifact_sha256===ARTIFACT,'The request is outside the fixed Oracle trial.');
 must(/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(r.request_id)&&/^[a-f0-9]{32}$/.test(r.nonce),'Invalid lab request identifiers.');
 must(iso(r.created_at)&&iso(r.expires_at)&&Date.parse(r.created_at)<=now+30000&&Date.parse(r.created_at)>=now-600000&&Date.parse(r.expires_at)>now&&Date.parse(r.expires_at)<=Date.parse(r.created_at)+600000,'This lab request expired. Keep the existing keys; request a fresh trial window.');
 return r;
}
export function buildLabRequestCommand(raw,now=Date.now()){
 const r=parseTrialRequest(raw,now),encoded=btoa(raw);
 return [
 '& {',
 '  $ErrorActionPreference = "Stop"',
 '  if ($env:COMPUTERNAME -ine "CORTANA") { throw "Run this on Cortana." }',
 '  $root = "C:\\ProgramData\\Batcave\\StrictNannyReviewer-v0.2"',
 '  if (!(Test-Path -LiteralPath "$root\\inbox" -PathType Container)) { throw "Existing Cortana reviewer is unavailable. Do not create a key." }',
 `  if ([DateTimeOffset]::UtcNow -ge [DateTimeOffset]::Parse("${r.expires_at}").AddSeconds(-45)) { throw "Trial window expired. Keep the same keys and request a fresh window." }`,
 `  $raw = [Convert]::FromBase64String("${encoded}")`,
 `  $request = Join-Path "$root\\inbox" "${r.request_id}.json"`,
 `  $proof = Join-Path "$root\\outbox" "${r.request_id}.receipt.json"`,
 '  if (!(Test-Path -LiteralPath $proof) -and !(Test-Path -LiteralPath $request)) {',
 '    $temp = "$request.$([guid]::NewGuid().ToString("N")).tmp"',
 '    [IO.File]::WriteAllBytes($temp,$raw)',
 '    Move-Item -LiteralPath $temp -Destination $request -ErrorAction Stop',
 '  }',
 '  $deadline = [DateTimeOffset]::UtcNow.AddSeconds(40)',
 '  while (!(Test-Path -LiteralPath $proof) -and [DateTimeOffset]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 250 }',
 '  if (!(Test-Path -LiteralPath $proof)) { throw "Cortana has not returned a review. Keep the request; do not rerun or create a key." }',
 '  $receipt = Get-Content -LiteralPath $proof -Raw | ConvertFrom-Json',
 `  if ($receipt.payload.request_id -cne "${r.request_id}" -or $receipt.payload.decision -cne "LAB_ALLOW" -or $receipt.payload.execution_authorized -ne $false -or $receipt.payload.deployment_authorized -ne $false -or $receipt.payload.production_release_authorized -ne $false) { throw "Cortana denied the lab request. Stop and show the error." }`,
 '  Write-Host "LAB_REVIEW_READY=$proof"',
 '  Get-Content -LiteralPath $proof -Raw',
 '  Write-Host "PUBLIC REVIEW ONLY. Send a screenshot of this output in the chat. No passphrase is needed."',
 '}'
 ].join('\r\n');
}
export async function checkLabReceipt(raw,receipt,now=Date.now()){
 const r=parseTrialRequest(raw,now),p=receipt?.payload;
 must(keys(receipt)==='payload|signature_b64url'&&/^[A-Za-z0-9_-]{86}$/.test(receipt.signature_b64url),'Invalid public receipt envelope.');
 must(keys(p)===RECEIPT_KEYS&&p.schema==='batcave.nanny.lab.receipt.v1'&&p.request_id===r.request_id&&p.request_sha256===await digest(raw)&&p.host==='CORTANA'&&p.reviewer_sid==='S-1-5-19'&&p.decision==='LAB_ALLOW'&&p.reason==='allowlisted_disposable_lab_only'&&['execution_authorized','deployment_authorized','production_release_authorized'].every(k=>p[k]===false),'Cortana receipt does not match this fixed trial.');
 must(typeof p.reviewed_at==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(p.reviewed_at)&&Date.parse(p.reviewed_at)>=Date.parse(r.created_at)&&Date.parse(p.reviewed_at)<=Date.parse(r.expires_at)&&Date.parse(p.reviewed_at)<=now+30000,'Invalid Cortana review time.');
 const key=await crypto.subtle.importKey('spki',bytes(KEY),{name:'Ed25519'},false,['verify']);
 must(await crypto.subtle.verify('Ed25519',key,bytes(receipt.signature_b64url),te.encode('batcave.nanny.lab.review.v1\n'+stable(p))),'Cortana signature verification failed. Nothing was sent.');
 return {action:'oracle_lab_record_review_v2',job_id:r.request_id,raw_request_json:raw,signed_receipt:receipt};
}
export function mountLabTrialHandoff(options){
 const encoded=typeof location==='undefined'?null:new URLSearchParams(location.search).get('model_trial_v1');
 if(!encoded)return null;
 const root=document.createElement('section');root.id='oracle-lab-trial';
 root.innerHTML='<h2>Run Oracle’s approved model trial</h2><p>Both release signatures are already recorded. Cortana’s existing reviewer checks this one fixed, disposable task.</p><button data-copy>Copy Cortana lab request</button><p data-note role="status" aria-live="polite"></p><label>Public Cortana lab review receipt<input type="file" accept="application/json,.json" aria-label="Public Cortana lab review receipt" data-file></label><label>Public lab receipt<textarea data-receipt rows="5" aria-label="Public lab receipt"></textarea></label><button data-send>Send Cortana lab review</button><p data-result role="status" aria-live="polite"></p>';
 options.parent.prepend(root);const q=s=>root.querySelector(s);let raw,request,busy=false,done=false;
 try{must(encoded.length<=3000&&/^[A-Za-z0-9_-]+$/.test(encoded),'Invalid trial link.');raw=new TextDecoder().decode(bytes(encoded));request=parseTrialRequest(raw);q('[data-note]').textContent='On Cortana, copy the request and paste it into PowerShell. No passphrase is required.';}
 catch(e){q('[data-note]').textContent=e.message;q('[data-copy]').disabled=true;q('[data-send]').disabled=true;return root;}
 q('[data-copy]').onclick=async()=>{try{await navigator.clipboard.writeText(buildLabRequestCommand(raw));q('[data-note]').textContent='Copied. Paste into Cortana’s PowerShell window and press Enter.';}catch(e){q('[data-note]').textContent=e.message;}};
 q('[data-file]').onchange=async()=>{try{const f=q('[data-file]').files?.[0];must(f&&f.size<=4096,'Choose only the small public lab review receipt.');q('[data-receipt]').value=await f.text();q('[data-result]').textContent='Public receipt loaded. Select Send Cortana lab review.';}catch(e){q('[data-result]').textContent=e.message;}};
 q('[data-send]').onclick=async()=>{
  if(busy||done)return;busy=true;q('[data-send]').disabled=true;
  try{must(!!options.getOwnerId(),'Sign in with your existing Batcave account in this tab.');must(q('[data-receipt]').value.length<=4096,'Public receipt is too large.');const body=await checkLabReceipt(raw,JSON.parse(q('[data-receipt]').value));const result=await options.api(body);must(result?.lab_review_recorded===true&&result.job_id===request.request_id&&result.grant_state==='pending_one_time_lease'&&result.execution_authorized===false&&result.deployment_authorized===false,'The owner gate did not confirm the one-use trial review.');done=true;q('[data-result]').textContent='Cortana review accepted. Waiting for Oracle’s eight-test result.';}
  catch(e){q('[data-result]').textContent=e.message;}
  finally{busy=false;q('[data-send]').disabled=done;}
 };
 return root;
}
