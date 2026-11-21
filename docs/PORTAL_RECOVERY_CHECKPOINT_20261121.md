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
