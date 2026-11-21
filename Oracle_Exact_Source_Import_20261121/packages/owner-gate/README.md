# Batcave / Oracle lab-only owner enrollment and Cortana grant writer v0.2

**Current state: STAGED / LAB_PASS. NOT DEPLOYED OR PRODUCTION-AUTHORIZED.**

This package implements the missing, owner-authenticated lab-enrollment flow **inside the existing** `batcave-change-gate-v1` Edge Function (a proposed source replacement retaining the original shadow-only GET). It does not add a scheduler or independent executor and does not modify the existing Cortana reviewer or Oracle worker.

## Exact trust boundaries

- **Existing owner identity:** Supabase authenticated, email-confirmed owner claim, verified server-side by the current gate's owner allowlist. Actual owner's **already enrolled** Ed25519 public key from `batcave.linux_owner_keys_v1` verifies a fresh five-minute challenge. The private owner key must remain wherever the existing owner-approved signing client stores it. No key is generated, exported or signed by ChatGPT.
- **Cortana reviewer:** Only the on-host verified `LOCAL SERVICE` lab reviewer; Ed25519 SPKI public-key SHA-256 `4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b`. The public certificate is matched to the earlier independently verified owner-uploaded public evidence ZIP. No reviewer private key is included.
- **Lab fixture compatibility token:** `4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f` is currently embedded in Cortana's running reviewer and the Oracle v0.3.1 model job payload. It happens to equal the *older* v0.3 ZIP digest but is **not** a release authorization for that older ZIP; it is treated only as a compatibility pin for the fixed, disposable clamp-score lab workflow.
- **Current source release:** the separate versioned **v0.3.1** Oracle worker integration ZIP SHA-256 is `4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2`. This value is independently bound into the *owner's enrollment signature*, stored key, and approved lab-grant record. Older v0.3 must not be deployed.
- **Scope:** fixed `Oracle` device, `model_generate_and_verify_v1`, `fixed_clamp_score_v1` fixture, `disposable_lab_only`, a single exact command UUID + nonce and an expiry no later than the original Cortana-reviewed expiry. All signed review receipts remain `execution_authorized=false`, `deployment_authorized=false`, and `production_release_authorized=false`. No shell commands, arbitrary user prompts, paths, or production repair.

## Code and actions (proposed for the EXISTING gate)

- `src/existing_change_gate_additive_STAGED.ts`: preserves existing owner-authenticated GET snapshot including `mode=shadow`, `permits_mutations=false`, and `deployment_authorized=false`. Adds only a guarded owner-authenticated POST dispatcher, denying unknown origin, body shape or account.
- `src/owner_gate_core.mjs`: three exact actions:
  1. `oracle_lab_enroll_challenge_v2` (no arguments): an existing enrolled owner key is required; server stores a fresh five-minute nonce/challenge and returns a canonical Ed25519 message.
  2. `oracle_lab_enroll_reviewer_v2`: validates the owner signature and challenge, matches Cortana's public SPKI hash and lab-only record; one atomic private function consumes the challenge and stores only the pinned **public** reviewer key and signature evidence. A duplicate/expired challenge cannot enroll.
  3. `oracle_lab_record_review_v2`: for an already **pending**, single-attempt Oracle model job, verifies the fresh original **raw** Cortana request bytes, signed `LAB_ALLOW` Ed25519 receipt, UUID, nonce, expiry, fixed fixture and enrolled key. Atomic private RPC records one reviewed grant; duplicates or stale jobs fail closed. It **does not** lease, execute or deploy anything.
- `src/verify_owner_enrollment_v2.mjs`: pure owner challenge signature verification, including both distinct fixture and v0.3.1 archive pins.
- `src/verify_lab_grant.mjs`: unchanged previously tested pure Cortana verifier. It enforces exact JSON byte SHA-256, domain-separated signature, required fields, and job-ID/nonces. Old receipts without their original request bytes **cannot** authorize a new job.
- `sql/lab_only_enrollment_additive_STAGED.sql`: three private RLS-protected tables, two *service_role-only*, `SECURITY INVOKER` atomic enrollment/grant functions, unique-nonce replay guards, strict lab-only CHECK constraints, no anon/authenticated EXECUTE. **Never apply to production without the existing independent release approval.**

### Deployment prerequisites (NOT yet met)

1. Independently review and authorize this exact additive gate release. The existing `batcave.change_gate_rules` remain shadow-only; the prior HELD public-key intent is evidence, not approval. ChatGPT must not create its own Nanny approval.
2. Back up live `batcave-change-gate-v1` Edge source/version and existing `public.batcave_oracle_bridge_v1` RPC, then **only after release approval**, apply the reviewed additive tables/RPCs and update that existing gate's code. This package does not change Oracle's RPC or worker. `sql/` does not automatically run.
3. Extend the **existing owner signing UI** to sign the new canonical challenge with the already enrolled owner private key under its existing origin. Do not upload or transmit private owner key data. A verbal owner authorization in chat is not a cryptographic signature.
4. Complete and verify enrollment with a fresh, owner-signed challenge. Then deploy the exact **v0.3.1** Oracle-only RPC, Edge and worker through separate signed release review, with backups and rollback; a lab-only enrollment **does not** release the worker.
5. Create exactly one typed, pending Oracle model command through an approved owner route. Send its exact request to Cortana's running lab reviewer (no manual key access), retrieve the original raw JSON plus its signed receipt, POST to the new gate for verification, and observe the grant become one-time eligible. Only then can `poll_model` atomically consume that grant and lease the job. Confirm eight fixed tests and one server `device_receipts` row.

## Verification in this authoring turn

- 17 new Node integration tests pass: authenticated owner, fresh signature, exact pins, tampering, expiry, replay, lab review job checks, and no production grant.
- 21 inherited pure verifier tests pass; together **38/38 Node tests**.
- 7 static security/contract tests pass (original shadow-only GET, service role/operation pinning, no general executor).
- `tsc --noEmit` passes for the additive TypeScript code with local module stubs; this is **not** a Deno production compilation.
- Live PostgreSQL **temporary schema** test passes for owner challenge, reviewer key, review grants, RLS, window and production-deny constraints; transaction rolled back and temporary relations removed. **The complete production function migration has not been applied or independently compiled in production.**
- No production gate change, Oracle install, new reviewer key, fresh owner signature, model task, or receipt was created by this package.

## Rollback and logs

No changes to roll back for this staged package. Once authorized to deploy, back up and restore the prior version of the existing gate's Edge source/version first if verification fails. Preserve private grant/review rows as audit history until separately reviewed cleanup; do not delete them casually. The previous gate's GET must still show all eight shadow-only rules. Existing Cortana/Oracle services, backups and protected Windows remain untouched. See `checkpoints/ERROR_FIX_LOG.md` and the append-only owner-private Decision Master for continuity.

## v0.2.1 - actual owner portal recovered + CORS fix (2026-11-21 UTC)
- **Exact original Vercel project recovered:** batcave-linux-approval, project `prj_ROdGP7ftETecOlKtfsVXlXM65fm1`; original production deployment `dpl_297NvEEqDTb31JgoQ6kKnd6LxrbP` still READY with production alias `batcave-linux-approval.vercel.app`. Existing Ed25519 owner key stays non-exportable in IndexedDB `batcave_linux_signer_v1` under that origin, and session in `sessionStorage` key `batcave_linux_session_v1`. No replacement key is required.
- **Discovered backend integration defect:** v0.2 staged Edge allowlisted only `batcave-cloud-control.vercel.app`, so the actual owner's existing signer portal would encounter `origin_denied` for POST. Staged `src/existing_change_gate_additive_STAGED.ts` now allowlists those **two exact** HTTPS origins. No wildcard and no production-gate permission change.
- **Additive portal page:** `portal/oracle-lab.html` + `portal/oracle-lab.js`; it displays exact Cortana lab signer/public key and v0.3.1 release pin, checks server's challenge against these immutable fields before owner-key signing, reads the non-exportable existing owner key in read-only IndexedDB mode, refuses to generate/export/replace owner key, and never requests execution/deployment authority. In preview, origin mismatch disables signing and an offline self-test requires no network or user key.
- **VERCEL PREVIEW READY** deployment ID `dpl_3S2YG5WDdvNH8Zd5XwE8ph7rcxnk`, URL `https://batcave-linux-approval-628d6b80r-mikealbanese-4675.vercel.app/oracle-lab.html`; target none (preview), aliases empty, 8 expected source files in root, READY. Protected by Vercel SSO: unauthenticated public fetch returned `login_required`, so browser rendering/route access was not independently demonstrated. This is NOT production. Original production alias and deployment verified unchanged after preview.
- **Vercel error/fix:** initial SHA1 reuse failed `missing_files`, then invalid explicit `target=preview` (must omit for preview), then a READY preview incorrectly nested files under `src/src` because of a root override. Next candidate with root override and root-level file names errored: logs `Root Directory src does not exist`. Final upload omitted rootDirectory entirely; READY with paths `src/*` as original, no aliases. Do not promote earlier previews.
- **Independent release blocker still present:** current Supabase `batcave-change-gate-v1` POST is not deployed, all eight existing rules shadow, no valid separate reviewer release signature, so this package is **LAB_PASS/STAGED**, NOT execution-authorized. It must be independently reviewed, then deployed with original gate backup and rollback. User's plain-chat authorization is not a cryptographic owner signature. The lab Cortana key cannot approve its own promotion.
