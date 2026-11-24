# General control integration — STAGED

Goal: reuse Batcave's existing host and browser transports for useful owner-controlled work, including a copy/paste fallback. No new executor, credential, grant or release authority is created by this package.

## Concrete recovery defect and fix

The generic SQL path writes a `started` receipt, which prevents re-claim, but its old completion function rejects results after lease expiry. The staged replacement records the original lease/attempt when a task starts, permits that same started execution to finish late, atomically records the terminal command and receipt, and acknowledges an identical duplicate without another event. A conflicting result is refused. The claim function is unchanged, so a started task is never blindly replayed.

The replacement locks the command before checking/writing its start receipt. Expired requests cannot start. Receipt delivery may finish after expiry because it records already-started work. Historical unbound starts retain live-lease compatibility; expired historical starts remain unresolved and require explicit reconciliation. The fix cannot retroactively invent execution identity.

The functions remain invokers with the original postgres-only EXECUTE ACL. They are not a device-authentication or owner-approval boundary. The actual authenticated executor still requires independent review before broad jobs can use it. The Cortana executor-v2 and browser-v1 RPCs are separate paths with their own retry semantics; this fix does not claim to repair those paths or the Oracle model bridge.

## Validation and deployment

`tests/test_command_recovery.py` runs actual PostgreSQL concurrency, expiry, replay, rollback and ACL tests. It refuses any DSN except localhost/127.0.0.1 database `release_gate_test`. Fixtures are synthetic; no real command is dispatched.

The existing GitHub source-review CI runs these tests in its disposable PostgreSQL 17 service. No new paid provider or scheduler is required.

Live deployment is HELD pending independent review of the exact diff and applicable owner authorization. The staged SQL checks the exact previous function bodies and private ACLs before replacement; a changed deployment fails preflight. If approved, apply the complete SQL in a single migration transaction, verify the function bodies/ACLs and perform a separately approved noncritical host acceptance test. Never report these database tests as physical-host or browser recovery.

## Rollback

`sql/before_generic_commands.sql` is the exact read-only definition snapshot. Before rollback, stop new generic dispatch through its authorized control surface and retain all command/receipt/event records. Restoring the old functions restores the old late-result limitation; do not delete `started` receipts, reset attempts or replay side effects to clear a task. Keep ambiguous work held and reconcile actual host state.

## Remaining acceptance

Full browser control in the correct existing signed-in session, a useful reversible host repair, interrupted result-delivery recovery, accurate phone state, and the same task through a readable paste fallback must all be proven separately. Browser tab visibility alone is not full browser control. No broad release is implied by source CI.
