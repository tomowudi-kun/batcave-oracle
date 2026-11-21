# Batcave / Oracle — typed local-model worker integration v0.3.1 (lab gate hardened)

**STATUS: STAGED FOR INDEPENDENT REVIEW — NOT INSTALLED OR CLOUD-RELEASED.**

## Scope and provenance

Built from the **actual owner-supplied Oracle source snapshot**, archive SHA-256 `f2a9ec7f7682d197ef890b87fb9130f43458c728f0f28ba942a4afa622c36907`.

| Installed source | Source SHA-256 (exact prerequisite) |
|---|---|
| `~/.local/share/batcave-worker/batcave_linux_worker.py` | `3f66ab1b9d123f6d448ecfef99ad116f863aa0d4cb7adc7d2f440662f6cda556` |
| `~/.local/share/batcave-worker/oracle_cloud_bridge.py` | `2841fa2a9fde645721fc4e6e0c74dd7ba8f92d5b8c909a48c210f1cd4da30d5f` |

The package extends existing Oracle components, not a second worker or scheduler. It retains `runtime_inventory` and `disposable_project_build_v1` and adds only `model_generate_and_verify_v1`. The new operation uses the local reviewed agent `~/Downloads/Oracle_Local_AI_POC_v0.1/agent.py`, pinned to SHA-256 `e60ec797966fd0055cc9c4e2cde2638599695539c8bd681b6def73ff4ab7020a`, and `qwen2.5-coder:1.5b` via the localhost Ollama endpoint. No prompt, target path, source file or shell command can be supplied by the cloud job. The only model task is a fixed 8-test `clamp_score` Python function fixture. It is not real production service repair.

The worker still authenticates the local job HMAC, writes an exclusive local receipt, and passes it through the existing cloud bridge. The adapter maintains durable job claims: a crash after claiming a job leaves it `UNCERTAIN` rather than blindly reexecuting the model. The bridge verifies model, fixed artifact path, local artifact hash and size, eight tests, and a signed receipt before upload. A single server-side receipt is required for acceptance.

## Package contents

- `patch/batcave_linux_worker.py` and `patch/oracle_cloud_bridge.py`: exact-source patches preserving both existing operations.
- `patch/model_capability.py`: reviewed fixed-task adapter, without cloud polling or general remote tools.
- `cloud/oracle_bridge_rpc_v03.sql`: **proposed** modification to the existing Oracle-only RPC. Retains device-token authentication, existing service-role permissions, old poll/receipt paths; adds `poll_model` and read-only `capabilities` **only with one-time lab-grant enforcement**. PostgreSQL atomic-lease predicate tested in a transaction using temporary tables (inventory/build success, no-grant model denied, fresh grant consumed once, model replay denied); transaction rolled back. The full production RPC remains uninstalled and was not executed.
- `cloud/index.ts`: proposed version of existing `batcave-oracle-bridge-v1` Edge Function with `poll_model` and `capabilities` allowlisted. JavaScript harness tests passed with mock RPC.
- `install-on-oracle.sh`: owner-operated, cloud-capability-gated installer. `--check` is default and read-only except local `.pyc` compilation; `--install` backs up originals and restarts **only** the two existing Oracle user services. No sudo, Windows changes, shared key changes or credential resets.
- `rollback-on-oracle.sh`: saved into the timestamped rollback directory during install, refuses unsafe restore if current files drift or work is outstanding.
- `tests/`: Python regression and negative tests plus Edge request-shape tests.

## Safe release order — do not skip

1. Have Strict Nanny / independent owner reviewer check **this exact package digest**, the cloud diff and the previous current function/Edge source. Record authorization; the staged shadow change-gate rules do not constitute authorization. Capture separate pre-release copies of the current RPC definition (`pg_get_functiondef`) and active Edge source/version so cloud changes are reversible.
2. **Prerequisite**: independently review and deploy the **existing-gate lab-only enrollment/receipt verifier**, its private `batcave.oracle_lab_reviewer_keys_v1` and `batcave.oracle_lab_review_grants_v1` schema, and an authenticated guarded grant-writer. No key may be enrolled solely from a HELD request. The device RPC is not an approval mechanism. Only then apply reviewed `cloud/oracle_bridge_rpc_v03.sql` to the **existing private RPC** and update the **existing** Edge Function `batcave-oracle-bridge-v1` from `cloud/index.ts`. Verify the existing `service_role`/`postgres`-only EXECUTE grants and check `status`, old `poll_build`, and new read-only `capabilities`. Do NOT queue any model job before the worker install.
3. On Oracle (under `tomo`, never root), transfer the verified ZIP and extract into a new user-owned directory. Run `bash install-on-oracle.sh --check` first. It must print `CLOUD_TYPED_MODEL_CAPABILITY=READY` and `PREDEPLOY_PREFLIGHT_PASS`. Only then run `bash install-on-oracle.sh --install` under the authorized change window. It refuses to overwrite unexpected files or restart during pending/claimed work. It creates a timestamped rollback directory before writes.
4. Read back both service states and file hashes independently. Then **one** approved, scoped cloud test command: action `oracle_model_generate_v1`, payload schema `batcave.oracle.job.v1`, operation `model_generate_and_verify_v1`, fixture `fixed_clamp_score_v1`, **payload artifact_sha256 `4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f`**, 32-character lowercase-hex nonce, expiration safely in the future and NO LATER THAN a fresh Cortana grant, Oracle device ID. Create exactly one pending command, obtain a fresh signed `LAB_ALLOW` for that exact command UUID+nonce through the authenticated gate, and only then allow a `poll_model` lease. The cloud response intentionally strips fixture/source/prompt—Oracle chooses its fixed local procedure.
5. Acceptance: **one** job row `succeeded`, exactly **one** `batcave.device_receipts` row tied to that command ID, exactly one model lease/receipt event pair, `tests_run=8`, `tests_passed=true`, `model=qwen2.5-coder:1.5b`, SHA-256 of the actual local generated source equals the returned digest. No repeat/retry of an ambiguous leased job. Independent owner/Strict Nanny review before expanding to any real-service repair.
6. Event-driven next-ready chaining and real Cortana incident intake are **not** implemented by this package. They must be tested separately after the cloud model task is proven, using the same worker and ledger.

## Rollback and known gaps

Oracle rollback: exact script copied to `~/.local/share/batcave-worker/rollback-model-v0.3-<UTC>/restore-v0.3.sh` (path is reported by installer). It restores original worker and bridge modules and removes only the new adapter, provided file hashes and in-flight state are safe. Cloud rollback: restore the saved pre-release RPC definition and previous Edge version; never assume rolling back the worker alone reverts server semantics. Existing `poll_build` remains supported throughout staging to protect old clients.

**Error/fix history:**

- Previous exporter v0.2 failed closed on three ambiguous worker candidates; v0.2.1 resolved the running service source and captured exactly two files. No services changed.
- First Oracle Ollama installer checksum-manifest parsing failed closed; fixed in model lab v0.1.1 with verified pinned release digest. Local Qwen model produced `model_generated.py` and 8/8 tests (`LAB_PASS`), not yet a cloud receipt.
- A cloud static test initially incorrectly flagged the word “GRANT” in a comment as an executable SQL grant; corrected the test to remove SQL comments. No database change occurred.
- New integration is version `v0.3`, independently tested against copied actual source and mocked model/HTTP; Oracle and server production deployment remain **STAGED**.

## Current proof boundary

Python `unittest` and Node Edge tests use simulated local-model results where applicable. The earlier first Oracle model LAB_PASS is **real and preserved**; the new **cloud-to-model-to-receipt** acceptance is not yet tested, and schema/SQL runtime verification remains pending. Do not claim autonomous task chaining or production self-repair until independently demonstrated.

## Critical v0.3.1 security fix (do not deploy v0.3.0)

The preceding v0.3.0 proposed RPC contained a lab-gate bypass: `poll_model` could lease a queued fixed-model job **without** an independent Cortana review. The v0.3.1 SQL closes that gap at the device token-authenticated RPC, not merely in client/UI code:

- Every new model lease requires a signed-review **grant row previously validated by the separate authenticated gate**, bound to the exact job ID, nonce, v0.3 artifact digest, `fixed_clamp_score_v1`, trusted unrevoked Cortana reviewer key and current expiry. `LAB_ALLOW` is required; production/execution flags remain false in the signed reviewer receipt.
- The grant's `consumed_at` is updated with the job lease **atomically in one SQL statement**. There is no model re-lease after a crash/ambiguous attempt. The server's model receipt path also rejects a command lacking a consumed grant. Any restart/recovery requires a fresh independently signed review, not automatic replay.
- Old `poll` inventory and `poll_build` deterministic jobs retain their existing contract and retry handling. `poll_model` cannot lease a model task while the grant ledger is absent/empty.
- This patch does **not** enroll a key or implement the grant-writer itself. In particular, the HELD Cortana public-key intent is only an evidence record. Deploying SQL without the private reviewed-grant tables will not work; do not bypass that prerequisite by creating grants manually.
- No new schedulers, general shell, cross-device execution, credential changes, or production release authority.

**Live testing:** PostgreSQL temporary tables and `pg_temp.test_lab_poll` processed a legacy inventory and build job, denied an ungranted model job, accepted and consumed one test model grant, and denied a second model lease. The test ran inside `BEGIN … ROLLBACK` with independent final temp cleanup. It checks SQL predicate semantics but **does not** establish full production RPC compilation, signature validation in PostgreSQL, on-device Oracle installation, or a cloud model receipt. Local source tests pass. Old v0.3.0 is preserved only for historical error/fix audit; this v0.3.1 supersedes it as the current staged integration candidate.
