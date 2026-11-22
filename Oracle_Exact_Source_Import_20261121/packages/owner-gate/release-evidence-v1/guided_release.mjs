/* Same owner origin and existing keys. Explicit Yes signs one fixed release;
 * Cortana supplies the distinct local review. No activation or task grants. */
import {releaseOwnerActions} from './release_owner_panel.mjs';
import {PIN,OWNER_DOMAIN,NANNY_DOMAIN,canonicalReleaseText} from './verify_release_approval_v1.mjs';
import {firstVerifySignature,firstStable,firstHash,firstISO} from './first_reviewer_protocol.mjs';
import {LOCAL_TOOLS} from './guided_first_key.mjs';
import {mountLabTrialHandoff} from './lab_trial_handoff.mjs';
const must=(v,s)=>{if(!v)throw Error(s);};
const noAuthority=r=>r&&['deployment_authorized','execution_authorized','grant_issued'].every(k=>r[k]===false);
function checkEnvelope(e,id,now){
 const p=e?.payload;
 must(e?.schema==='batcave.oracle.gate.release.challenge.v1'&&e.issuer==='batcave-control'&&/^[a-f0-9-]{36}$/.test(e.challenge_id)&&p?.owner_user_id===id&&Object.entries(PIN).every(([k,v])=>p[k]===v),'Release details changed. Stop and refresh.');
 must(firstISO(p.issued_at)&&firstISO(p.expires_at)&&Date.parse(p.issued_at)<=now+30000&&Date.parse(p.issued_at)>=now-600000&&Date.parse(p.expires_at)>now&&Date.parse(p.expires_at)<=Date.parse(p.issued_at)+600000,'The release approval expired. Approve again when Cortana is ready.');
 return canonicalReleaseText(p);
}
export function guidedReleaseActions(options){
 let state=null;
 const now=options.now||Date.now,actions=releaseOwnerActions(options);
 async function refresh(){
  if(!options.getOwnerId()){state=null;return null;}
  const r=await options.api({action:'oracle_release_status_v1'});
  must(noAuthority(r)&&r.reviewer_registered===true&&r.owner?.owner_user_id===options.getOwnerId()&&/^[a-f0-9]{64}$/.test(r.reviewer_public_key_sha256),'Release status could not be verified.');
  if(r.envelope){
   const text=checkEnvelope(r.envelope,options.getOwnerId(),now());
   await firstVerifySignature(r.owner,OWNER_DOMAIN+text,r.envelope.owner_signature_b64url);
   if(r.review){
    const p=r.review;
    must(p.schema==='batcave.nanny.local.review.evidence.v1'&&p.nonce===r.envelope.payload.nonce&&p.intent_key===PIN.intent_key&&p.expires_at===r.envelope.payload.expires_at&&p.reviewer_public_key_sha256===r.reviewer_public_key_sha256&&p.deployment_authorized===false&&p.execution_authorized===false&&p.local_file_hashes?.gate_sha256===PIN.owner_gate_zip_sha256&&p.local_file_hashes?.worker_sha256===PIN.worker_zip_sha256&&p.local_file_hashes?.source_commit===PIN.pr_head_sha,'Cortana review differs from this release.');
    await firstVerifySignature({public_key_b64url:r.reviewer_public_key_b64url,public_key_sha256:r.reviewer_public_key_sha256},NANNY_DOMAIN+text,p.signature_b64url);
   }
  }else must(!r.review,'Cortana review has no current phone approval.');
  state=r;return r;
 }
 return {
  refresh,
  approve:async()=>{
   await refresh();must(!state.release_review_recorded,'Release signatures are already recorded.');
   const ch=await actions.prepareRelease(state.reviewer_public_key_sha256),e=await actions.signRelease(ch);
   const r=await options.api({action:'oracle_release_endorse_v1',challenge_id:e.challenge_id,owner_signature_b64url:e.owner_signature_b64url});
   must(noAuthority(r)&&r.owner_endorsement_saved===true,'The phone approval was not saved.');return refresh();
  },
  decline:async()=>{
   const r=await options.api({action:'oracle_release_decline_v1'});must(noAuthority(r)&&r.owner_declined===true,'The No decision was not saved.');await refresh();return r;
  },
  command:async()=>{await refresh();must(state?.envelope,'Approve on your phone after Cortana is ready.');return buildReleaseCommand(state.envelope,state.reviewer_public_key_sha256,now());},
  finish:async()=>{
   await refresh();must(state?.envelope&&state.review,'Waiting for the current Cortana review.');
   const r=await actions.recordReview(state.envelope,state.review,state.reviewer_public_key_sha256);
   must(noAuthority(r)&&r.evidence_recorded===true&&r.cryptographic_evidence_valid===true,'Release signatures were not recorded.');return refresh();
  }
 };
}
export async function buildReleaseCommand(e,fp,now=Date.now()){
 checkEnvelope(e,e.payload.owner_user_id,now);
 must(/^[a-f0-9]{64}$/.test(fp)&&/^[a-f0-9]{32}$/.test(e.payload.nonce),'Invalid reviewer or nonce.');
 const text=firstStable(e),hash=await firstHash(text),encoded=btoa(String.fromCharCode(...new TextEncoder().encode(text))),nonce=e.payload.nonce;
 return [
 '& {','  $ErrorActionPreference = "Stop"',
 '  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()',
 '  if ($identity.Name -ine "CORTANA\\StrictNannyReviewer") { throw "Use the black StrictNannyReviewer window." }',
 '  $ready = Get-Content -LiteralPath (Join-Path $env:USERPROFILE "Batcave-FirstKey-Tools-Ready.json") -Raw | ConvertFrom-Json',
 '  if ($ready.codeCommit -ne "c53b91d7eaa8e45ac63314f4e12aa8ed0731d0ac") { throw "Wrong signing tools." }',
 '  $files = @{',...Object.entries(LOCAL_TOOLS).map(([name,sha])=>'    "'+name+'" = "'+sha+'"'),'  }',
 '  foreach ($name in $files.Keys) { if ((Get-FileHash -LiteralPath (Join-Path $ready.runtime $name) -Algorithm SHA256).Hash -ine $files[$name]) { throw "Signing-tool hash mismatch." } }',
 '  $reviewFiles = Get-Content -LiteralPath (Join-Path $env:USERPROFILE "Batcave-Oracle-Release-Review-Ready.json") -Raw | ConvertFrom-Json',
 '  if ($reviewFiles.schema -cne "batcave.oracle.release.review.files.v1" -or $reviewFiles.source_commit -cne "'+PIN.pr_head_sha+'") { throw "Prepare the release files first." }',
 '  if ([DateTimeOffset]::UtcNow -ge [DateTimeOffset]::Parse("'+e.payload.expires_at+'")) { throw "Release approval expired. Keep the existing key; approve again on your phone." }',
 '  $packet = Join-Path $ready.runtime "release-owner-'+nonce+'.json"',
 '  [IO.File]::WriteAllBytes($packet,[Convert]::FromBase64String("'+encoded+'"))',
 '  if ((Get-FileHash -LiteralPath $packet -Algorithm SHA256).Hash -ine "'+hash+'") { throw "Release packet hash mismatch." }',
 '  $keyDir = Join-Path $env:USERPROFILE "Batcave-Strict-Nanny-Release-Key"',
 '  $receipt = Join-Path $keyDir "review-'+nonce+'.json"',
 '  if (!(Test-Path -LiteralPath $receipt)) {',
 '    $oldReviewPath = $env:Path',
 '    try {',
 '      if ($reviewFiles.git_exe -ne "git") { $env:Path = (Split-Path -Parent $reviewFiles.git_exe) + ";" + $oldReviewPath }',
 '      & "C:\\Program Files\\nodejs\\node.exe" (Join-Path $ready.runtime "cortana_independent_reviewer.mjs") review $keyDir $packet $reviewFiles.gate_archive $reviewFiles.worker_archive $reviewFiles.repo_path',
 '      if ($LASTEXITCODE -ne 0) { throw "Review did not complete. Keep the existing key and show the error." }',
 '    } finally { $env:Path = $oldReviewPath }',
 '  }',
 '  $review = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json',
 '  if ($review.schema -cne "batcave.nanny.local.review.evidence.v1" -or $review.nonce -cne "'+nonce+'" -or $review.reviewer_public_key_sha256 -cne "'+fp+'" -or $review.signature_b64url -cnotmatch "^[A-Za-z0-9_-]{86}$" -or $review.deployment_authorized -ne $false -or $review.execution_authorized -ne $false) { throw "Wrong public review. Nothing sent." }',
 '  $safeReview = [ordered]@{ schema = $review.schema; status = $review.status; intent_key = $review.intent_key; nonce = $review.nonce; expires_at = $review.expires_at; reviewer_public_key_sha256 = $review.reviewer_public_key_sha256; signature_b64url = $review.signature_b64url; reviewer_host_identity = $review.reviewer_host_identity; local_file_hashes = $review.local_file_hashes; reviewed_at = $review.reviewed_at; deployment_authorized = $false; execution_authorized = $false }',
 '  $body = @{ op = "submit_release"; challenge_id = "'+e.challenge_id+'"; review = $safeReview } | ConvertTo-Json -Depth 6 -Compress',
 '  try {',
 '    $sent = Invoke-RestMethod -Method Post -Uri "https://wizflveeptzeajsdybzs.supabase.co/functions/v1/batcave-first-proof-v1" -ContentType "application/json" -Body $body -TimeoutSec 20',
 '  } catch {',
 '    if ($_.ErrorDetails.Message) { Write-Host $_.ErrorDetails.Message }',
 '    throw "Public review transfer failed. Keep this review; do not sign again. Show the error."',
 '  }',
 '  if ($sent.review_received -ne $true -or $sent.deployment_authorized -ne $false -or $sent.execution_authorized -ne $false -or $sent.grant_issued -ne $false) { throw "Review transfer was not verified." }',
 '  Write-Host "RELEASE REVIEW SENT. The open Batcave page will record both signatures. No files or clipboard needed."','}'
 ].join('\n');
}
export function mountGuidedRelease(options){
 const actions=guidedReleaseActions(options),root=document.createElement('section');root.id='guided-release';
 root.innerHTML='<h2>Allow Oracle’s first local AI trial?</h2><p>Oracle will generate and test one fixed sample in a disposable workspace. This request does not permit general computer control.</p><div data-release-phone><button data-release-yes>Yes</button><button data-release-no>No</button></div><p data-release-result role="status" aria-live="polite"></p><div data-release-cortana hidden><p>Use the black StrictNannyReviewer window to review the prepared release files with your existing key.</p><textarea data-release-command readonly rows="5" aria-label="Cortana release review command"></textarea><button data-release-copy>Copy release review command</button></div><button data-release-refresh>Refresh release status</button><p data-release-error role="status" aria-live="polite"></p>';
 options.parent.append(root);mountLabTrialHandoff(options);const q=s=>root.querySelector(s);let state,busy=false,disposed=false,commandNonce=null;
 let phone=window.matchMedia('(max-width: 700px)').matches;
 function paint(){
  const pending=!!state?.envelope,done=state?.release_review_recorded===true;
  q('[data-release-phone]').hidden=!phone||done;q('[data-release-cortana]').hidden=phone||!pending||done;
  q('[data-release-yes]').disabled=busy||!state||pending;q('[data-release-no]').disabled=busy||!state;
  q('[data-release-copy]').disabled=busy||!pending;
  q('[data-release-result]').textContent=done?'Both release signatures are recorded. Deployment remains held until the release gate accepts the rollout.':state?.owner_declined?'You chose No. Oracle stays held. This request was for the fixed local-model trial in a disposable workspace.':pending?'Phone approval saved. Waiting for Cortana’s independent release review.':'Cortana’s reviewer is enrolled. Choose Yes or No when the release files are ready.';
  if(!pending){q('[data-release-command]').value='';commandNonce=null;}
 }
 async function refresh(){
  if(busy||disposed)return;
  try{
   state=await actions.refresh();if(state?.release_review_recorded)q('[data-release-error]').textContent='';paint();
   if(state?.envelope&&!phone&&commandNonce!==state.envelope.payload.nonce){q('[data-release-command]').value=await actions.command();commandNonce=state.envelope.payload.nonce;}
   if(state?.envelope&&state.review){busy=true;paint();try{state=await actions.finish();}finally{busy=false;}paint();}
  }catch(e){q('[data-release-error]').textContent=e.message;}
 }
 async function act(fn){busy=true;paint();try{await fn();q('[data-release-error]').textContent='';root.dispatchEvent(new CustomEvent('batcave-owner-decision',{bubbles:true}));}catch(e){q('[data-release-error]').textContent=e.message;}finally{busy=false;await refresh();}}
 const deviceMode=event=>{phone=event.detail?.mode==='phone';paint();};options.parent.addEventListener('batcave-device-mode',deviceMode);
 q('[data-release-yes]').onclick=()=>act(async()=>{state=await actions.approve();});
 q('[data-release-no]').onclick=()=>act(async()=>{await actions.decline();});
 q('[data-release-copy]').onclick=()=>act(async()=>{const c=await actions.command();q('[data-release-command]').value=c;await navigator.clipboard.writeText(c);q('[data-release-result]').textContent='Copied. Paste into the black reviewer window.';});
 q('[data-release-refresh]').onclick=refresh;paint();refresh();const poll=setInterval(()=>{if(document.visibilityState==='visible'&&!state?.release_review_recorded)refresh();},5000);
 root.dispose=()=>{disposed=true;clearInterval(poll);options.parent.removeEventListener('batcave-device-mode',deviceMode);};return root;
}
