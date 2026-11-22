/* Existing owner portal only. Public signatures sync through the same owner-auth
 * gate; no private-key transfer, new credential, worker grant or relaxed expiry.
 */
import {releaseOwnerActions} from './release_owner_panel.mjs';
import {firstStable,firstHash,firstISO,verifyFirstOwner,verifyFirstPair} from './first_reviewer_protocol.mjs';
export const LOCAL_TOOLS=Object.freeze({
 'cortana_independent_reviewer.mjs':'301af9993ecf1d1f285355b2ded1c78a3faae2a9f4a48981d7a6be1f2c01a97d',
 'verify_release_approval_v1.mjs':'2ed25049f10169de7af4c1f69be2d1a2dacf72fb6fbd2edf9e79d156dc413886',
 'first_reviewer_protocol.mjs':'c8e94dfa3f8325a218e1a0906a68ed37eaaa182145869332a0a9f058313543c8'
});
export function guidedFirstKeyActions(options){
 let status=null;
 const actions=releaseOwnerActions({...options,getTrustedOwner:async()=>{if(!status?.owner)throw Error('Refresh the approval first.');return status.owner;}});
 async function refresh(){
  if(!options.getOwnerId()){status=null;return null;}
  const value=await options.api({action:'oracle_first_reviewer_status_v1'});
  if(value?.owner?.owner_user_id!==options.getOwnerId()||value.owner.revoked_at!==null||value.deployment_authorized!==false||value.execution_authorized!==false||value.grant_issued!==false)throw Error('The gate returned an invalid owner status.');
  if(value.endorsement)await verifyFirstOwner({payload:value.endorsement.payload,record:{policy:value.endorsement.policy,policy_sha256:value.endorsement.policy_sha256,registered_at:null,revoked_at:null},owner:value.owner,owner_signature_b64url:value.endorsement.owner_signature_b64url,now:options.now?.()??Date.now()});
  status=value;return value;
 }
 return {
  refresh,
  decline:async()=>{const r=await options.api({action:'oracle_first_reviewer_decline_v1'});if(r?.owner_declined!==true)throw Error('The decline was not recorded.');await refresh();return r;},
  approve:async()=>{
   await refresh();if(!status?.candidate)throw Error('The saved Cortana reviewer record is missing. Stop here; keep the existing key.');
   if(status.reviewer_registered)throw Error('The reviewer is already enrolled.');
   const ch=await actions.prepareFirstEnrollment(status.candidate),e=await actions.signFirstEnrollment(ch);
   const r=await options.api({action:'oracle_first_reviewer_endorse_v1',challenge_id:e.challenge_id,owner_signature_b64url:e.owner_signature_b64url});
   if(r?.owner_endorsement_saved!==true||r.reviewer_registered!==false)throw Error('Phone approval was not saved.');
   return refresh();
  },
  received:async()=>{
   if(!status?.endorsement||!options.proofApi)return null;
   const e=status.endorsement,r=await options.proofApi({op:'status',challenge_id:e.challenge_id});
   if(!r?.proof)return null;
   const p=r.proof;
   if(r.reviewer_registered!==false||r.deployment_authorized!==false||r.execution_authorized!==false||r.grant_issued!==false||p.challenge_id!==e.challenge_id||p.nonce!==e.payload.nonce||p.policy_sha256!==e.policy_sha256||p.reviewer_public_key_sha256!==e.policy.reviewer_key_sha256||['independently_attested','deployment_authorized','execution_authorized','grant_issued'].some(k=>p[k]!==false))throw Error('Invalid public confirmation transfer.');
   await verifyFirstPair({payload:e.payload,record:{policy:e.policy,policy_sha256:e.policy_sha256,registered_at:null,revoked_at:null},owner:status.owner,owner_signature_b64url:e.owner_signature_b64url,proof_signature_b64url:p.proof_signature_b64url,now:options.now?.()??Date.now()});
   return p;
  },
  command:async()=>{await refresh();if(!status?.endorsement)throw Error('Approve on your phone first.');return buildCortanaCommand(status.endorsement);},
  finish:async input=>{
   await refresh();if(!status?.endorsement)throw Error('The phone approval expired. Approve again on your phone, then copy a fresh Cortana command.');
   if(typeof input!=='string'||input.length>16000)throw Error('Paste only the public confirmation copied by Cortana.');
   let proof;try{proof=JSON.parse(input);}catch{throw Error('The confirmation must be the public JSON copied by Cortana.');}
   const r=await actions.registerFirstEnrollment(status.endorsement,proof);
   if(r?.reviewer_registered!==true||r.independently_attested!==false)throw Error('The gate did not confirm enrollment.');
   return refresh();
  }
 };
}
export async function buildCortanaCommand(e){
 const text=firstStable(e),hash=await firstHash(text),bytes=new TextEncoder().encode(text);
 const encoded=btoa(String.fromCharCode(...bytes)),nonce=e.payload.nonce;
 if(!/^[a-f0-9]{32}$/.test(nonce)||!/^S-1-5-21-\d+-\d+-\d+-\d+$/.test(e.policy.reviewer_sid)||!firstISO(e.payload.expires_at))throw Error('Invalid Cortana approval.');
 const lines=[
 '& {',
 '  $ErrorActionPreference = "Stop"',
 '  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()',
 '  if ($identity.Name -ine "CORTANA\\StrictNannyReviewer" -or $identity.User.Value -ne "'+e.policy.reviewer_sid+'") { throw "Use the black StrictNannyReviewer PowerShell window." }',
 '  $readyPath = Join-Path $env:USERPROFILE "Batcave-FirstKey-Tools-Ready.json"',
 '  if (!(Test-Path -LiteralPath $readyPath)) { throw "Cortana tools are not prepared yet. Keep the existing key and stop here." }',
 '  $ready = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json',
 '  if ($ready.codeCommit -ne "c53b91d7eaa8e45ac63314f4e12aa8ed0731d0ac") { throw "Wrong signing-tool version." }',
 '  $files = @{',
 ...Object.entries(LOCAL_TOOLS).map(([name,sha])=>'    "'+name+'" = "'+sha+'"'),
 '  }',
 '  foreach ($name in $files.Keys) { if ((Get-FileHash -LiteralPath (Join-Path $ready.runtime $name) -Algorithm SHA256).Hash -ine $files[$name]) { throw "Signing-tool hash mismatch: $name" } }',
 '  if ([DateTimeOffset]::UtcNow -ge [DateTimeOffset]::Parse("'+e.payload.expires_at+'")) { Write-Host "APPROVAL EXPIRED. Approve again on your phone and copy a fresh command. Keep the same keys."; return }',
 '  $packet = Join-Path $ready.runtime "owner-'+nonce+'.json"',
 '  [IO.File]::WriteAllBytes($packet,[Convert]::FromBase64String("'+encoded+'"))',
 '  if ((Get-FileHash -LiteralPath $packet -Algorithm SHA256).Hash -ine "'+hash+'") { throw "Approval file hash mismatch." }',
 '  $keyDir = Join-Path $env:USERPROFILE "Batcave-Strict-Nanny-Release-Key"',
 '  $proof = Join-Path $keyDir "first-key-proof-'+nonce+'.json"',
 '  if (!(Test-Path -LiteralPath $proof)) {',
 '    & "C:\\Program Files\\nodejs\\node.exe" (Join-Path $ready.runtime "cortana_independent_reviewer.mjs") prove-first-key $keyDir $packet',
 '    if ($LASTEXITCODE -ne 0) { throw "Confirmation was not created. Keep the key and show the error." }',
 '  }',
 '  $publicProof = Get-Content -LiteralPath $proof -Raw | ConvertFrom-Json',
 '  if ($publicProof.schema -cne "batcave.nanny.first_key.possession.v1" -or $publicProof.challenge_id -cne "'+e.challenge_id+'" -or $publicProof.nonce -cne "'+nonce+'" -or $publicProof.policy_sha256 -cne "'+e.policy_sha256+'" -or $publicProof.reviewer_public_key_sha256 -cne "'+e.policy.reviewer_key_sha256+'" -or $publicProof.proof_signature_b64url -cnotmatch "^[A-Za-z0-9_-]{86}$") { throw "Wrong public confirmation file. Nothing was sent." }',
 '  foreach ($flag in @("independently_attested","deployment_authorized","execution_authorized","grant_issued")) { if ($publicProof.$flag -ne $false) { throw "Unexpected authority in public confirmation. Nothing was sent." } }',
 '  $safeProof = [ordered]@{ schema = $publicProof.schema; challenge_id = $publicProof.challenge_id; nonce = $publicProof.nonce; policy_sha256 = $publicProof.policy_sha256; reviewer_public_key_sha256 = $publicProof.reviewer_public_key_sha256; proof_signature_b64url = $publicProof.proof_signature_b64url; independently_attested = $false; deployment_authorized = $false; execution_authorized = $false; grant_issued = $false }',
 '  $body = @{ op = "submit"; proof = $safeProof } | ConvertTo-Json -Depth 8 -Compress',
 '  $sent = Invoke-RestMethod -Method Post -Uri "https://wizflveeptzeajsdybzs.supabase.co/functions/v1/batcave-first-proof-v1" -ContentType "application/json" -Body $body -TimeoutSec 20',
 '  if ($sent.proof_received -ne $true -or $sent.reviewer_registered -ne $false -or $sent.deployment_authorized -ne $false -or $sent.execution_authorized -ne $false -or $sent.grant_issued -ne $false) { throw "Confirmation transfer was not verified. Keep the public proof file." }',
 '  Write-Host "CONFIRMATION SENT. Return to the Cortana page and select Finish enrollment. No JSON or clipboard is needed."',
 '}'
 ];return lines.join('\n');
}
const friendly=e=>{
 const s=String(e?.message||e);
 if(/OWNER_KEY_REQUIRED/.test(s))return 'Sign in with the same Batcave account you used on your phone.';
 if(/401|JWT|token.*expired|Sign in first/i.test(s))return 'Sign in above with your existing Batcave account.';
 if(/FIRST_ALREADY_REGISTERED/.test(s))return 'The reviewer is already enrolled. Refresh this page.';
 if(/EXPIRED|NOT_FRESH|STALE/.test(s))return 'The phone approval expired. Approve again on your phone, then copy a fresh command on Cortana.';
 return s;
};
export function mountGuidedFirstKey(options){
 const actions=guidedFirstKeyActions(options),root=document.createElement('section');root.id='guided-first-key';
 root.innerHTML='<h1>Connect Cortana’s reviewer</h1><p>Your phone approves. Cortana confirms with its existing key.</p><p data-account></p><button data-account-controls>Show sign-in</button><div class="device-switch"><button data-phone-mode>Phone</button><button data-cortana-mode>Cortana computer</button></div><p data-message role="status" aria-live="polite"></p><div data-phone><h2>Allow your existing Cortana reviewer to join Batcave?</h2><p>Have this same page open on Cortana and sign in there with the same Batcave account. Your existing keys stay on their devices.</p><p data-reviewer></p><button data-approve>Yes</button><button data-decline>No</button><p data-phone-result></p></div><div data-cortana hidden><h2>On Cortana: confirm</h2><p data-wait>Approve on your phone first. The approval appears here automatically.</p><div data-confirm hidden><ol><li>Select <strong>Copy confirmation command</strong>.</li><li>Paste it into the black <strong>StrictNannyReviewer PowerShell</strong> window. Follow its confirmation prompt and enter your existing signing passphrase there.</li><li>Your public confirmation returns here automatically. Then select Finish enrollment.</li></ol><button data-copy>Copy confirmation command</button><details><summary>Show the command</summary><textarea data-command readonly rows="8" aria-label="Cortana confirmation command"></textarea></details><details><summary>Public confirmation details</summary><textarea data-proof readonly rows="5" aria-label="Received public confirmation"></textarea></details><p data-transfer-wait>Waiting for Cortana’s confirmation.</p><button data-finish>Finish enrollment</button><p data-expiry></p></div></div><div data-done hidden><h2>Reviewer enrolled</h2><p>This setup is complete. Oracle’s release remains held for its separate release review.</p></div><p class="held-note">This page enrolls the reviewer only. It does not release Oracle or grant task execution.</p><button data-refresh>Refresh status</button>';
 const main=document.querySelector('main'),auth=main?.querySelector('section');
 if(main){
  const oldTitle=main.querySelector('h1');if(oldTitle)oldTitle.textContent='Batcave';
  const oldNotice=main.querySelector('p.notice');if(oldNotice)oldNotice.hidden=true;
  const legacy=document.createElement('details');legacy.className='earlier-tools';const title=document.createElement('summary');title.textContent='Earlier lab tools — not needed for this setup';legacy.append(title);
  for(const child of Array.from(main.children))if(child!==auth&&child!==oldTitle&&child!==oldNotice)legacy.append(child);
  main.append(root,legacy);
 }else document.body.append(root);
 const unrelated=document.getElementById('sendOracleCode');if(unrelated)unrelated.hidden=true;
 const css=document.createElement('link');css.rel='stylesheet';css.href='/release-evidence-v1/guided_first_key.css';document.head.append(css);
 const q=s=>root.querySelector(s);let mode=window.matchMedia('(max-width: 700px)').matches?'phone':'cortana',state=null,busy=false,lastCommandNonce=null,lastProofNonce=null,disposed=false,showAuth=false;
 const message=s=>{q('[data-message]').textContent=s;};
 function paint(){
  const done=state?.reviewer_registered===true;
  q('[data-account]').textContent=options.getOwnerId()?'Signed in'+(options.getOwnerEmail?.()?' as '+options.getOwnerEmail():''):'Sign in above with your existing Batcave account.';
  if(auth)auth.hidden=!!options.getOwnerId()&&!showAuth;
  q('[data-phone]').hidden=done||mode!=='phone';q('[data-cortana]').hidden=done||mode!=='cortana';q('[data-done]').hidden=!done;
  q('[data-phone-mode]').setAttribute('aria-pressed',String(mode==='phone'));q('[data-cortana-mode]').setAttribute('aria-pressed',String(mode==='cortana'));
  const pending=state?.endorsement;
  q('[data-confirm]').hidden=!pending;q('[data-wait]').hidden=!!pending;
  q('[data-approve]').disabled=busy||!state?.candidate||!!pending;q('[data-decline]').disabled=busy||!state||done;
  q('[data-phone-result]').textContent=pending?'Phone approval saved. Continue on Cortana’s page; no files to download.':state?.owner_declined?'You chose No. Enrollment is stopped. We asked because Batcave needs to recognize the separate Cortana reviewer before Oracle can be released.':'';
  q('[data-reviewer]').textContent=state?.candidate?'Existing reviewer: Cortana / '+state.candidate.host_identity.user+'. Key ending '+state.candidate.public_key_sha256.slice(-8)+'.':'';
  q('[data-expiry]').textContent=pending?'Approval valid until '+new Date(pending.payload.expires_at).toLocaleTimeString()+'. Keep this page open while confirming.':'';
  q('[data-finish]').disabled=busy||!pending||lastProofNonce!==pending.payload.nonce;q('[data-copy]').disabled=busy||!pending;
  if(!pending){q('[data-command]').value='';q('[data-proof]').value='';lastCommandNonce=null;lastProofNonce=null;q('[data-wait]').textContent='Approve on your phone when Cortana is ready, then copy the new confirmation command.';}
  q('[data-transfer-wait]').textContent=pending&&lastProofNonce===pending.payload.nonce?'Cortana’s public confirmation arrived. Select Finish enrollment.':'Waiting for Cortana’s confirmation.';
 }
 async function refresh(){if(busy||disposed)return;try{state=await actions.refresh();paint();if(state?.endorsement&&lastCommandNonce!==state.endorsement.payload.nonce){q('[data-command]').value=await actions.command();lastCommandNonce=state.endorsement.payload.nonce;}if(state?.endorsement&&lastProofNonce!==state.endorsement.payload.nonce){const proof=await actions.received();if(proof){q('[data-proof]').value=JSON.stringify(proof);lastProofNonce=state.endorsement.payload.nonce;paint();}}}catch(e){if(/401|JWT|token|sign in/i.test(String(e.message)))showAuth=true;paint();message(friendly(e));}}
 async function act(fn){busy=true;paint();try{await fn();message('');}catch(e){message(friendly(e));}finally{busy=false;await refresh();paint();}}
 q('[data-account-controls]').onclick=()=>{showAuth=!showAuth;paint();};
 q('[data-phone-mode]').onclick=()=>{mode='phone';paint();};q('[data-cortana-mode]').onclick=()=>{mode='cortana';paint();};
 q('[data-decline]').onclick=()=>act(async()=>{const r=await actions.decline();state=await actions.refresh();q('[data-phone-result]').textContent=r.explanation;root.dispatchEvent(new CustomEvent('batcave-owner-decision'));});
 q('[data-approve]').onclick=()=>act(async()=>{state=await actions.approve();root.dispatchEvent(new CustomEvent('batcave-owner-decision'));});
 q('[data-copy]').onclick=()=>act(async()=>{const text=await actions.command();q('[data-command]').value=text;await navigator.clipboard.writeText(text);q('[data-wait]').textContent='Command copied. Use the black reviewer PowerShell window.';});
 q('[data-finish]').onclick=()=>act(async()=>{state=await actions.finish(q('[data-proof]').value);q('[data-proof]').value='';});
 q('[data-refresh]').onclick=refresh;
 paint();refresh();const poll=setInterval(()=>{if(document.visibilityState==='visible'&&!state?.reviewer_registered)refresh();},5000);
 root.dispose=()=>{disposed=true;clearInterval(poll);};return root;
}
