# Enrollment-only live deployment receipt — 2026-11-21

**VERIFIED: enrollment plumbing deployed. BLOCKED: genuine owner endorsement,
local candidate possession proof and subsequent Oracle release signatures.**

The owner explicitly approved the tested gate/owner-page rollout while preserving
all Oracle release holds. No PR was merged and no worker/model was deployed.

- Existing `batcave-change-gate-v1` is now **v7**, JWT verification remains true.
  Independent readback matched all eight expected deployed source files exactly.
  Existing GET/owner authentication/lab paths were preserved.
- Both reviewed private evidence migrations applied. Six tables have RLS;
  anon/authenticated clients have no direct read/write/finalizer execution access.
  The exact private first-key policy is installed with registered_at NULL,
  independently_attested=false and production_release_authorized=false.
- Original owner-key origin `https://batcave-linux-approval.vercel.app/` now serves
  deployment `dpl_2t47vg5NkrXwERDNf3nNNuT1VbWh`. All original assets are preserved;
  app.js has only the reviewed extension appended, plus four reviewed modules.
  Preview and canonical-origin HTTP bytes match. A real browser rendered the
  first-key enrollment controls and truthful unattested-custody text.
- Original owner key remains unchanged/unrevoked. Original intent remains HELD,
  owner_auth_state unconfigured and Nanny pending. Zero model grants, eight
  SHADOW rules, zero first-key challenges/registrations/release receipts.
- Authenticated owner signing end-to-end remains UNKNOWN until the actual owner
  uses the existing nonexportable key. It was not simulated through admin SQL.
  Existing encrypted Cortana key and installed local signer files are untouched.
- Local `prove-first-key` runtime update remains a separate local preparation
  before possession proof; the gate/page deployment did not install host code.

## Rollback and errors

Before changes, captured gate v6 and prior portal deployment
`dpl_Q2RW4bRCRZeHDJvcmUxHuB3ykNC2`; all ten original source bytes matched deployed
SHA-1 UIDs. Restore that captured gate/JWT and portal origin to roll back serving.
Preserve private evidence and permanently revoke any future registered root;
never reset its once-ever slot or reinitialize private key files.

The source-file API truncated base64 at 2000 characters. Detected invalid bytes,
stopped partial extraction, recovered complete served assets using the existing
Vercel HTTP capability and matched all ten UIDs before any deployment. Durable
private before/after captures and operator policy are recorded in the Decision
Master; actual SID/policy/operator evidence remains out of this public repository.

Code commit `c53b91d7eaa8e45ac63314f4e12aa8ed0731d0ac` remains the deployed reviewed
implementation. CI [44961173314](https://github.com/tomowudi-kun/batcave-oracle/actions/runs/44961173314)
passed 80 signing and 21 actual PostgreSQL tests plus prior gate/worker suites.
No implementation changes were made for this deployment receipt.

Next: in the original browser/profile holding the existing owner key, select the
saved public candidate and Prepare approved first-key enrollment. Genuine local
owner endorsement and candidate possession proof remain required before registration.

## Historical source-stage receipt (superseded deployment status)

# Oracle signer continuation receipt — 2026-11-21

Status: STAGED / LAB_PASS_80_NODE_21_POSTGRESQL / LIVE_RELEASE_BLOCKED.

The Decision Master is authoritative. This is a code/test receipt.

The owner approved one-time first-reviewer enrollment using the existing owner
Ed25519 signature and actual candidate-key possession instead of independently
attested custody for the first key only. The actual candidate/account/ACL/source
receipts already exist privately; initialization is complete and must not repeat.
The first-root trust basis is explicit and independently_attested remains false.

The existing PR #2 now contains a generic, privately configured extension of the
existing gate and same-origin owner portal. No actual SID, candidate configuration,
or private operator evidence is added to public source. GitHub reports this
repository PUBLIC; prior references to it as private were incorrect.

- First-root policy is a singleton, immutable after installation; registration is
  once-ever, including after revocation. Root enrollment requires zero existing
  privileged reviewers and two real domain-separated signatures.
- Every later release re-verifies the stored historical registration pair and
  still requires two NEW owner/reviewer release signatures over the fixed scope.
- Local prove-first-key reuses the encrypted key; human TTY, actual Windows SID,
  existing owner signature and hidden passphrase are required. Only a public proof
  file is written. It neither enrolls nor deploys.
- Private PostgreSQL writes serialize root registration and recheck owner/policy,
  held intent, expiry, nonce and revocation under locks. All authority flags false.
- 80/80 local Node tests pass (62 original plus 18 first-root tests). PostgreSQL CI
  passed 9 new real database tests alongside all 12 original tests.
- No live migration, policy seed, gate/portal deployment, signer registration,
  merge, model grant or release-hold change. PR #1 pins are unchanged.
- Rollback of STAGED code: return PR #2 to its previous head. Preserve real key
  files. A later live rollback must revoke a registered root permanently, never
  reset its once-ever slot or delete signed receipts.

## Verified first-root CI receipt

- Code commit: `c53b91d7eaa8e45ac63314f4e12aa8ed0731d0ac`.
- [GitHub Actions run 44961173314](https://github.com/tomowudi-kun/batcave-oracle/actions/runs/44961173314): SUCCESS.
- Source job `137020089374`: 80 signing/portal/first-root tests PASS, plus
  existing 20 owner-gate Node, 8 owner-gate contract and 35 worker tests PASS.
- PostgreSQL job `137020089553`: original 12 and first-root 9 tests PASS;
  completed 2026-11-21 23:19:23Z. Both actual job logs independently read.
- Concurrent distinct first-key challenges produced one registration; revoked
  roots cannot rebootstrap; private client access denied; intent remains held.
- Fresh live readback: owner key unchanged/unrevoked; original intent HELD,
  owner_auth_state unconfigured and nanny_review_state pending; zero model
  grants; eight SHADOW rules; new privileged tables absent; deployed change
  gate still v6 and owner gate v4. This is STAGED/LAB_PASS, not live enrollment.

## Historical receipt (superseded status; retain evidence)

# Oracle signer continuation receipt — 2026-11-21

Status: STAGED / LAB_PASS_62_NODE / LIVE_RELEASE_BLOCKED.

The existing private Decision Master remains authoritative. This is a source and
testing receipt, not a second master or an approval.

- PR #1 remains pinned at 33b62fae6ccb2224f04cce43443510b71c051297.
- Continuation uses existing draft PR #2; no merge or deployment.
- Fixed signer CLI; staged enrollment, owner portal extension, challenge
  issuance, dual verification and transactional evidence/nonce ledger.
- Local Node: 62/62 PASS on v24.22.3; CI also tests Node 22.
- Actual PostgreSQL atomicity CI: 12/12 PASS, run 44954029074, job 136998038622, completed 2026-11-21 21:55:51Z.
- Successful Cortana browser receipt returned zero accessible Batcave tabs.
  Protected Windows account/TTY access has not been established.
- Actual independent key custody/registration remains BLOCKED. Actual owner
  and reviewer release signatures, controlled deployment and real fixture
  receipt are UNKNOWN/NOT VERIFIED. No live model grants were created.
- Next local action remains init under the real isolated Cortana reviewer
  account. Return only public.unenrolled.json, never the private key/passphrase.
- Rollback: revert the source continuation; no live change to undo.

Correction receipt: first CI source job passed, PostgreSQL setup rejected a generated hash due to STABLE convert_to. The checked-digest fix and raw/SPKI lab-key alias denial are in the next code commit; final corrected code commit a7edf39f82224a80c5fa350437e95d420fdac367 passed GitHub run 44954029074. Source job 136998038345 passed 62 Node signing tests plus the existing 20 owner-gate Node, 8 owner-gate contract and 35 worker tests. Both jobs independently read back SUCCESS. This receipt update changes documentation only.
