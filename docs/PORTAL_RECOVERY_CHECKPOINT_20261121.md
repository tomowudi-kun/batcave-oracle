# Portal recovery checkpoint — 2026-11-21

Status: BLOCKED — complete original portal source retrieval; no portal redeployment authorized from partial source.

## Verified
- Vercel team: team_8jN6JqYw9Wg5GMMsLfPhixME; project: prj_ROdGP7ftETecOlKtfsVXlXM65fm1.
- Deployed candidate: dpl_3S2YG5WDdvNH8Zd5XwE8ph7rcxnk, READY, assigned alias batcave-linux-approval.vercel.app.
- Eight files: src/app.js, src/index.html, src/nanny-verifier.html, src/nanny-verifier.js, src/oracle-lab.html, src/oracle-lab.js, src/style.css, src/vercel.json.
- Supabase gate version 2 ACTIVE, three lab tables and two RPCs present, eight existing shadow rules preserved.
- Original portal reports existing owner key; Oracle page fails retrieval of private key. Supabase shows one unrevoked public owner key, zero Oracle reviewer keys, zero enrollment challenges.
- Magic-link redirects to login page without establishing usable session; likely callback/session handling defect, not yet conclusively code-verified.

## Errors and fixes
1. GitHub CI worker test referred to /mnt/data absolute path. Removed unused reference; GitHub run #12 succeeded.
2. Oracle tab sessionStorage mismatch. Same-tab navigation progressed to private-key lookup; authentication persistence still defective.
3. Vercel deployment source connector truncates src/app.js and even index.html to ~2014 base64 characters. Repeating equivalent reads did not recover full bytes. Do not deploy partial source.
4. GitHub repository search for batcave-linux-approval found no separately named source repository.

## Recovery strategy
- Recover exact eight source files through a materially different authorized source/host route; preserve byte hashes and copy under version control.
- Fix magic-link callback, session restoration, and IndexedDB record-format mismatch in a test branch. Never export, regenerate, or replace owner private key.
- Preview deploy; test auth callback, refresh, tab navigation, invalid tokens, key lookup, and signing without production mutation.
- Assign production alias only after acceptance. Rollback by reassigning alias to dpl_297NvEEqDTb31JgoQ6kKnd6LxrbP (prior production) or the verified pre-change candidate as appropriate.
- Owner clicks lab enrollment once; verify Supabase reviewer row. Worker release remains separately gated.

## Secrets
Do not copy or record magic-link tokens, browser sessions, private keys, or API bearer tokens in this repository.

## 2026-11-21 09:52 EST — live browser/connector correction (append-only)
- AUTHENTICATION VERIFIED IN ONE TAB: original portal tab ID 388113049 reports signed in as owner and `execution_enabled:false`. Earlier hypothesis that magic-link auth is entirely broken is disproved; sessions vary by tab.
- Another portal tab ID 388113045 reports `For security purposes, you can only request this after 56 seconds.` This confirms Supabase sign-in throttling, not ChatGPT model usage throttling. No new magic link required in authenticated tab.
- Supabase registry at 2026-11-21T14:51:33Z: Cortana `active`, latest heartbeat 14:48:13Z (age 200s), Oracle `active`, latest heartbeat 14:51:27Z (age 6s). Heartbeats do not establish present command execution rights.
- Desktop Commander device registry reports Cortana offline despite independent Batcave active status. Historical record says DC monthly usage exhausted; current quota itself was not verified.
- Prior Cortana executor V2 read-only receipts include success (job af9ba7b1-1698-44a7-8ae4-3cfb91ef1d0a). Old leased/unreconciled job f81910db-7214-4a30-bc32-cad6ef49da55 must not be replayed.
- Direct HTTP source retrieval from container failed DNS. Web page asset access failed. Google Drive connector search failed due to missing eligible linked account. No evidence original source absent.
- Safest acceptance step: in the already authenticated portal tab, click `Check enrollment` exactly once. Inspect returned result with read-only Browser connector; do not click `Enroll key`, clear site data, or request another magic link.
- No live deployment, DB permissions, owner key, or device changes in this diagnostic.

## Addendum 2026-11-21 ~14:55 UTC — same-origin diagnostic deployed
- Browser-linked read shows one original approval tab **signed in**, and another has a Supabase email-OTP cooldown of 56 seconds. Previous blanket claim that no portal tab was authenticated is corrected. Do not request new links in a loop.
- Cortana Supabase heartbeat **2026-11-21T14:48:13.588817Z**, state active. Desktop Commander separately reports offline; not proof of Batcave connection failure. The cloud executor previously completed PowerShell jobs on 2026-11-20; a **new** executable job has not been submitted or verified today. Usage-limit hypothesis only **confirmed for Supabase OTP cooldown**, not Cortana cloud executor.
- Vercel source reads truncated to ~2014 base64 chars; recovered deployment **exact blob references** (not plaintext source) through Vercel list_deployment_files, allowing non-destructive file reuse.
- First preview dpl_F82obfDY2uMmg3XR416SX9fcVmyf was READY but paths accidentally double-prefixed as src/src/*; **not promoted**. Fix: create-deployment accepts relative basenames rather than src/ paths.
- Corrected preview **dpl_9EiWqCCMxXC7xebyT61W6qhGEsA9** READY. All eight files **same paths and content UIDs** as original dpl_3S2YG5WDdvNH8Zd5XwE8ph7rcxnk; one added file src/oracle-recovery.html from recovery/owner-key-readonly-diagnostic.html, committed at 86953dc.
- Owner's existing scoped instruction to combine Cortana, Vercel, GitHub and isolated diagnostic was used to attach the alias batcave-linux-approval.vercel.app to the corrected deployment. **Vercel alias readback confirmed** new deployment now owns alias and original does not. No other alias, Supabase schema, signing key, or Strict Nanny gate modified.
- **Rollback**: reassign batcave-linux-approval.vercel.app to dpl_3S2YG5WDdvNH8Zd5XwE8ph7rcxnk through Vercel assign_alias; verify original alias ownership. File UIDs from both deployments are identical for the eight originals.
- **Next acceptance test**: in normal Chrome profile open https://batcave-linux-approval.vercel.app/oracle-recovery.html and click 'Inspect local browser key storage'. Browser output exposes only database names, record field names and CryptoKey types, never private-key bytes. A browser key missing would require approved recovery; do not generate or export owner private key.
- **Status**: same-origin recovery diagnostic DEPLOYED; key retrieval diagnosis UNKNOWN until browser test; original portal auth already signed-in in one tab; Oracle reviewer enrollment remains BLOCKED/UNKNOWN.

## 2026-11-21 portal repair release v0.3 — HTTP VERIFIED; owner enrollment pending (append-only)
- Review input: Claude's "Batcave Linux PoC — Independent Review.docx" (uploaded 2026-11-21) highlights an unresolved *device enforcement* risk: deny-only cloud gate does not prove legacy Cortana generic PowerShell is blocked. It proposes a device-side pinned-key signed scope verifier and durable write-ahead journal, tested in lab only. No worker-device enforcement or Linux install is claimed from this portal release. No competing Decision Master created.
- Source recovery: isolated Vercel sandbox fetched complete public assets from live approval origin. Source hashes (SHA-256): app.js e310f6900ac6266e538c10858f40af1bddc30bb691c1b68d382b8d5d43a2c350; oracle-lab.js 9deb36af0092f8713662c2739fb3e6f404be24731239a5e08d060520e16e4777. Original app.js, HTML, CSS, Nanny files, and Vercel security headers backed up under recovery/original-live/2026-11-21/; Oracle lab source matches original import except trailing newline.
- Root cause verified by direct source comparison: original app.js writes owner CryptoKey directly to IndexedDB keys[uid]; Oracle lab previously expected keys[uid].privateKey. Patch accepts the direct non-exportable Ed25519 CryptoKey (and legacy wrapped form), never exports or regenerates keys.
- New login route: root portal now has "Send new Oracle sign-in link", reuses original OTP endpoint and allowed root redirect, stores only a 15-minute nonsecret localStorage handoff marker, then existing magic-link callback validates session and navigates same browser tab to /oracle-lab.html. Session tokens remain in tab-scoped sessionStorage, not localStorage.
- Concurrent-work reconciliation: alias batcave-linux-approval.vercel.app was pointing at dpl_9EiWqCCMxXC7xebyT61W6qhGEsA9 (NINE files), not earlier dpl_3S2YG5WDdvNH8Zd5XwE8ph7rcxnk (EIGHT files). Extra oracle-recovery.html was preserved; inline script failed existing script-src self CSP and was split into oracle-recovery.js, with raw-CryptoKey-aware metadata. CSP was not weakened.
- Tests: both patched app.js and oracle-lab.js pass Node vm.Script syntax validation; existingKey passes 4 synthetic cases (direct CryptoKey, wrapped record, absent, nonexportable constraint) and Ed25519 sign/verify; 3 login-handoff scenarios pass (fresh, expired, absent); diagnostic JS passes static validation. Tests did not use user's real private key.
- Error/fix: create_deployment with target=preview returned HTTP 400; omit target for preview. First created preview inadvertently used src/src/*; discarded it and redeployed with root file names to preserve src/* packaging. These attempts never moved the production alias.
- Correct candidate deployment: dpl_Q2RW4bRCRZeHDJvcmUxHuB3ykNC2, READY, exactly 10 files under src/* including original Nanny verifier and CSP config. Prior production alias dpl_9EiWqCCMxXC7xebyT61W6qhGEsA9 recorded as immediate rollback target.
- Production alias switched to dpl_Q2RW4bRCRZeHDJvcmUxHuB3ykNC2 and read back. Independent HTTP checks: index.html, app.js, oracle-lab.html/js, oracle-recovery.html/js, nanny-verifier.js and style.css all returned HTTP 200; expected patched markers present. Nanny JS sha256 remained 633b7d51e825d8279aa7578f6abc8f4a8bd65ecd8a6ebecb480710f0ed514261. CSP script-src self, no-store, nosniff remained intact. **Status: PRODUCTION_VERIFIED for public asset delivery; UNKNOWN for fresh user login and local owner-key access.**
- After switch, read-only Supabase counts: owner public keys 1; Oracle lab reviewer keys 0, issued Oracle challenges 0, Oracle lab review grants 0. Owner signature/enrollment has NOT happened. Worker production release remains HELD. No live Windows disk, device, credentials, Supabase gate or SSH changes.
- Rollback: if portal login fails due to this update, reassign alias batcave-linux-approval.vercel.app to dpl_9EiWqCCMxXC7xebyT61W6qhGEsA9 then independently verify get_alias and HTTP. Do NOT revoke owner key or disable CSP.
- Next acceptance step: owner opens https://batcave-linux-approval.vercel.app/ in the same established Chrome profile, enters existing owner email, clicks "Send new Oracle sign-in link" once, uses newest emailed link without copying it to chat; after redirect to Oracle page, confirms scope and submits lab enrollment. Then query Supabase reviewer table for independent receipt. If local key absent, use repaired read-only /oracle-recovery.html and stop before any key reset.
