# Oracle independent release-signature evidence (STAGED)

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