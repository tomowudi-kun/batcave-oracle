# Oracle release signing: existing gate extension (STAGED)

**Current: STAGED / 80 local signing tests PASS / new PostgreSQL CI pending / LIVE RELEASE BLOCKED.**

The owner approved a one-time first-key policy amendment. The recorded real
Cortana candidate already exists: **do not run init again or overwrite key files.**
See `FIRST_REVIEWER_OWNER_ROOT_STAGE.md` for the implemented first-key branch.
The independent-attestation enrollment path below remains mandatory for later
keys. The new owner-root branch truthfully records independently_attested=false,
requires real owner endorsement plus candidate possession proof, and grants no
execution or deployment. Policy approval alone did not authorize rollout.

This continues draft PR #2. PR #1, its pinned commit and release archive hashes,
the existing held intent, eight SHADOW gates and production worker are unchanged.

## Original independent-attestation continuation (preserved)

1. For a genuinely new identity only, locally run `node cortana_independent_reviewer.mjs init <private_directory>`
   under the real dedicated protected Cortana Windows reviewer account. Local
   TTY confirmation and a hidden passphrase are mandatory. Return only
   `public.unenrolled.json`; never upload the encrypted private key or passphrase.
2. An independent registrar must inspect actual host/account/ACL separation,
   custody and recovery, then register the nonsecret attestation in the private
   gate. There is **no application endpoint that writes custody attestations**
   and SQL seeds none. Client booleans cannot fill this boundary. Actual key
   custody/registration remains BLOCKED, not assumed from this source.
3. `release_gate_core.mjs` verifies the existing owner key signature over a
   server-issued enrollment challenge binding candidate fingerprint and host
   identity to the independently stored custody record. The nonce is single-use.
4. Only that registered reviewer and the exact current HELD intent can obtain
   the fixed release challenge (maximum ten minutes). `release_owner_panel.mjs`
   extends the EXISTING original-origin owner portal, reusing its login and
   IndexedDB key. Preparation never signs; a separate local button signs the
   locally re-derived pinned message. Missing/exportable keys are rejected;
   there is no key replacement, export or automatic signing.
5. The local `review` command checks the actual owner signature, exact ZIP
   bytes and clean pinned Git HEAD, then requires nonce-specific local human
   review before signing with the separate encrypted reviewer key.
6. The gate verifies both signatures over its immutable stored payload.
   `release_repository.mjs` calls the private atomic SQL finalizer, which locks
   and rechecks owner/reviewer/custody revocation, pinned intent and wall-clock
   expiry, then records one receipt and consumes the nonce in one transaction.
   Every response retains deployment_authorized=false, execution_authorized=false
   and grant_issued=false. Evidence alone cannot deploy or execute anything.

## Integration and verification

- `existing_change_gate_index_STAGED.ts` is the complete extension of live Edge
  v6, preserving confirmed-owner auth, JWT/CORS, original GET and lab paths.
  Include the new core/repository/verifier beside the existing lab modules.
- `release_evidence_schema_STAGED.sql` adds only private evidence tables and a
  SECURITY INVOKER atomic finalizer; no client grants, trust seed, policy flip,
  worker change or existing-intent update. **Not applied to production.**
- `owner_portal_extension_STAGED.js` is appended to existing portal app.js only
  after independent review. Serve panel modules under `/release-evidence-v1/`
  on the original `https://batcave-linux-approval.vercel.app` key origin. The
  extension is **not deployed or browser-verified**.
- The SQL finalizer is callable only through the private DB connection, after
  authenticated JavaScript verifies signatures. Public/anon/authenticated
  roles cannot access it. No credentials are added to source.
- Node command: `node --test test_release_approval_v1.mjs test_signer_bootstrap.mjs test_release_gate.mjs test_release_owner_panel.mjs` — 62/62 local PASS.
- `test_release_ledger.py` permits only localhost database `release_gate_test`;
  it tests real PostgreSQL concurrency/replay/revocation and public-role denials.
  Local PostgreSQL is unavailable. Final CI receipt is in the repository receipt.

## Error/fix continuation and rollback

- ERR-SIGNER-PATH-005: `args.map(path.resolve)` forwarded numeric map indexes,
  breaking review before its TTY check. Fixed with a unary resolver and actual
  CLI regression. Original ZIP `init` still works; use corrected source for review.
- ERR-SIGNER-EXPIRY-006: malformed key expiry escaped comparison through NaN.
  Fixed canonical ISO validation and explicit reviewer custody; regressions pass.
- ERR-SIGNING-LEDGER-007: enrollment/challenge/atomic consumption existed only as
  requirements. The implementation above is now STAGED, not a live trust claim.
- ERR-CONTINUATION-SQL-008: read-only metadata query ordered by an omitted
  ordinal_position field. Corrected projection; read succeeded.
- No production changes occurred. Revert this PR #2 continuation to roll back
  source only; preserve PR #1, original ZIP and historic logs. Never delete real
  keys or live evidence as a source rollback. Before any later deployment,
  independently review actual custody, old Edge/portal/RPC rollback captures,
  owner/reviewer release signatures and worker-side enforcement/postflight.

- ERR-LAB-FINGERPRINT-009: the lab registry hashes SPKI while release keys hash raw Ed25519 bytes. The same lab key could evade a hash-only denylist after re-fingerprinting. Fixed by rejecting its actual key bytes and both fingerprints in enrollment/verifier/finalizer; regressions pass.

## Prior verifier-only baseline (historical)

**State:** DRAFT / LOCAL_TESTS_PASS / NO SIGNER ENROLLED / NO PRODUCTION AUTHORIZATION.

## Scope
These pure verification components extend the existing release review; they do not create a new Nanny service, change live Supabase policy, deploy an Oracle worker, queue a task or grant execution. Source is pinned to the current draft PR head `33b62fae6ccb2224f04cce43443510b71c051297`, the release intent content SHA-256, and the two exact source archives. A changed head or archive requires a new review and re-signing, not an automatic pin update.

## Required independent custody
- Existing owner Ed25519 key remains on the Pixel owner portal under the original origin; no private key is exported, regenerated or sent to this verifier.
- A **separate, owner-controlled Strict Nanny privileged release signer** must be created in an isolated host identity/security boundary, not the Cortana LOCAL SERVICE lab-only reviewer and not a model/ChatGPT-accessible secret. Its public key must be bound to an independently attested, revocable registration in the existing private gate. No key is enrolled by this stage.
- Both actual signers must sign the **same** immutable, fresh, server-issued release envelope, under two distinct domain strings. Chat consent, lab signatures, GitHub workflow green, and values supplied by a client do not equal that evidence.
- Before any protected release, the existing gate must independently check current intent state/expiry, exact source archive bytes and hashes, trusted signer registrations and custody, owner identity, immutable signed scope, unique issuance and atomic nonce consumption, backup/rollback, and an enforceable job-claim policy. The pure verifier alone never authorizes deployment.

## Tests
`node --test test_release_approval_v1.mjs` — 19 tests pass locally on Node 22. Synthetic test keys are ephemeral and not enrollment evidence. Negative tests cover expired/reused nonce, wrong hash/head/scope, revoked or missing reviewer, model-controlled custody, signer confusion, fake signatures and replacement of the lab reviewer.

## Rollback
No live changes to undo. The staged source can be dropped without touching PR #1 or production. Preserve historical error/fix ledger and the held release intent. Update the Decision Master only with verified receipts.
