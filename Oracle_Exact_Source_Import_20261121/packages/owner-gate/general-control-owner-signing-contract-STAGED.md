# General-control owner-signing boundary — staged contract v0.1

Status: STAGED / NON-AUTHORIZING. This document is not a signature, grant, release, or permission to dispatch.

## Existing boundary (verified at PR #3 head e8e9723c9c4e077d4bb3cfdb04f6c4a9d846fcd6)
`packages/owner-gate/src/owner_gate_core.mjs` only recognizes fixed lab enrollment, lab review, and read-only fixed-trial status. Its default is UNSUPPORTED_ACTION. Do not repurpose the pinned `FIXTURE_TOKEN`, `RELEASE_SHA`, or Cortana `lab_reviewer_only` key for general control.

## New typed request (proposal; not wired)
`batcave.general_control.owner_request.v1`: exact owner_user_id, request_id, device (Oracle|Cortana), capability (host.read|host.write_reversible|browser.observe|browser.click|browser.type), target_origin for browser operations, target_session_id, command_digest, source_commit, policy_digest, nonce, issued_at, expires_at, rollback_ref. Canonical serialization is versioned and deterministic. Reject extra keys, wildcards, cross-device scope, missing session binding, expired nonce, mismatched owner, and privileged operations. No arbitrary shell, credential access, browser-cookie extraction, protected OS changes, or permission escalation under this contract.

## Proposed two independent checks
1. Existing authenticated owner origin presents the complete human-readable request, including host, browser origin/session, side effects and rollback. The owner signs exact canonical bytes with a separately enrolled owner-bound key, short expiry and single-use nonce. A click or conversational approval is not a signature.
2. Strict Nanny independently evaluates the *same digest* against current Decision Master and live policy. A separate eligible reviewer signs the exact scope. Lab-only reviewer identities are not eligible for production release. Store append-only attestations; do not insert grants directly.

Only after both signatures are verified server-side, and a fresh capability-specific policy check passes, may the existing queue atomically issue a single typed lease. The executor must bind device/session, enforce an allowlist, and write a durable result receipt. Ambiguous execution stays NEEDS_ATTENTION rather than replaying effects.

## Required negative acceptance tests before any deployment
- Owner authenticated but unsigned -> DENY; signed but wrong device/session/origin/command digest -> DENY.
- Reused nonce, expired signature, changed source/policy hash -> DENY.
- Owner signature without independently eligible reviewer signature -> HELD.
- Lab-only Cortana reviewer signature -> DENY for privilege expansion.
- Reviewer signature for another request or stale policy -> DENY.
- Missing browser signed-in session or unknown active tab -> DENY rather than claim completion.
- Interrupted execution with terminal receipt -> reconcile once; conflicting late receipt -> DENY; unknown side effect -> NEEDS_ATTENTION.
- Phone UI shows Yes/No with precise scope, result and attention; paste fallback produces the *same* typed request and still requires both gates.

## Deployment separation / rollback
Keep PR #3 generic receipt reconciliation and read-only status separate from this privileged route. Preserve live gate-v9 diagnostics and current deployed functions. Stage source, unit/DB tests, signed independent review and exact rollback snapshot before any rollout. Rollback disables the new typed route without deleting receipts, resetting attempts, or weakening existing holds.

## Immediate next code target
Implement a pure `validateGeneralControlOwnerRequestV1` parser with deterministic canonical bytes and negative tests. No queue or grants in that first commit. Independently review its exact source before wiring owner signatures.
