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
