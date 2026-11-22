# Batcave / Oracle — independent release signer bootstrap v1

**State: STAGED / LAB_PASS (28/28 Node 22 tests) / NO LIVE INDEPENDENT KEY / PRODUCTION RELEASE HELD.**

Purpose: make it possible for the owner to create a genuinely separate Strict Nanny reviewer signing identity on **Cortana**. The existing Pixel owner key remains on the owner portal; the existing Cortana `LOCAL SERVICE S-1-5-19` lab-reviewer key remains LAB ONLY. Never reclassify either as the new privileged reviewer.

## What is implemented

- `cortana_independent_reviewer.mjs`: offline, human-interactive Ed25519 reviewer candidate key generator, encrypted at rest with scrypt + AES-256-GCM, local public-key candidate record, explicit review of an **owner-signed** release envelope, immutable pinned hashes and clean checked-out Git commit, independent local Nanny signature output. It refuses noninteractive signing. No network calls, account changes or cloud writes.
- `verify_release_approval_v1.mjs`: existing standalone dual-key cryptographic verifier; emits **evidence only** with `deployment_authorized=false`, `execution_authorized=false` and `grant_issued=false`.
- `test_*`: 28 synthetic/failure-path tests; no production key or authentication secret was created or accessed by ChatGPT.
- The live `batcave.change_gate_intents` entry remains HELD, all eight gate rules SHADOW, and existing Oracle PR #1 and verification PR #2 remain unmerged.

## Isolation and prerequisite

Run locally on Cortana, in a **dedicated protected Windows account/profile** whose files and private key cannot be read by Oracle's worker, ChatGPT, the Cortana lab reviewer or the generic executor. This code cannot create or independently attest that OS boundary for you. Do not run `init` in the Oracle model/executor account. Verify security and backup/rotation plan first.

Must have Node 22+, Git, original exact owner-gate ZIP `69ab19be8ec2e11e902716da59c2dda8693a3d3c78a16d8bdc1ded25a8d16851`, Oracle worker ZIP `4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2`, and the **clean** checked-out reviewed commit `33b62fae6ccb2224f04cce43443510b71c051297`. The local signer refuses to sign if any of these differ.

## One-time setup on the isolated Cortana account

From an interactive local console (not a remote AI executor), in the extracted folder:

```powershell
node .\cortana_independent_reviewer.mjs init "$env:USERPROFILE\Batcave-Strict-Nanny-Release-Key"
```

The command asks for explicit local confirmation and a hidden passphrase. It writes `private.encrypted.json` and `public.unenrolled.json`; it **does not register a privileged signer**. Never upload the private file, store it in Git, or copy it into ChatGPT/cloud. The public record can be submitted to an independently controlled gate-registration flow **only after** owner approval and host/custody review.

## After independent key registration exists

The existing gate must generate a fresh nonce (10 minutes maximum) against the exact pinned **HELD** intent and obtain the real Pixel owner's Ed25519 signature over `OWNER_DOMAIN+canonicalReleaseText(payload)`. A user-asserted JSON `issuer` field is not sufficient: private gate must verify issuance, current intent state, and one-time consumption. Then the Cortana reviewer may run locally:

```powershell
node .\cortana_independent_reviewer.mjs review "<private_directory>" "<owner_signed_gate_challenge.json>" "<owner_gate_v021.zip>" "<oracle_worker_v031.zip>" "<clean_git_checkout_path>"
```

This verifies the enrolled owner's public key pinned from `batcave.linux_owner_keys_v1`, owner signature, scope, archive hashes, local Git HEAD, and clean Git worktree; displays exact information; requires a human to type a nonce-specific confirmation; then signs using the separate Nanny private key. **Local receipt is not authorization.** Existing server gate must still verify independently enrolled/attested reviewer status, both signatures, nonce provenance/consumption, immutable artifact bytes, backups, rollback, and actual worker-side enforcement.

## Remaining blocker

The independently controlled, on-device privileged reviewer key has **not** been created or registered; the owner-signed release challenge issuance/atomic consumption is not deployed in the private gate. The current connected Desktop Commander route reports both devices offline and zero remaining remote calls. The existing cloud bridge exposes only typed inventory/disposable build; it cannot legitimately bootstrap a privileged host identity. Do not switch to the generic PowerShell executor, manually insert grants, change shadow rules, self-approve, or merge the PRs to bypass this.

**Next actionable owner step:** On Cortana, under a dedicated isolated local Windows reviewer account, run the `init` command above. Return only the generated **public.unenrolled.json** and the nonsecret OS identity/ACL evidence needed for independent custody review. Do not return the encrypted private file or passphrase.

## Error/fix and rollback

- `ERR-IDENTITY-001`: Existing `lab_reviewer_only` key was erroneously treated as a possible production signer. **Fix:** separate owner/reviewer key roles and deny the lab key's exact fingerprint.
- `ERR-IDENTITY-002`: `issuer_verified: true` in a JSON object could be forged. **Fix:** require actual Pixel owner Ed25519 signature, immutable owner-public-key fingerprint, and server-side nonce verification; never trust a client assertion as enrollment.
- `ERR-IDENTITY-003`: Local script entrypoint URL equality differed on Windows vs POSIX. **Fix:** `pathToFileURL(resolve(process.argv[1]))`.
- `ERR-IDENTITY-004`: External source-review claims were optional. **Fix:** require a clean Git checkout matching the pinned PR #1 commit; original exact archive bytes are independently SHA-256 verified.
- `NOT DONE`: Real host key creation, key custody attestation, independent registration, challenge issuer, cloud integration and end-to-end fixture remain blocked. No production rollback required because nothing was installed/deployed.

Rollback: delete the **candidate bootstrap** and any locally generated *unenrolled* candidate only after owner confirms backup/key custody; never delete already registered keys without a separately verified revocation and recovery procedure. Original PRs, cloud gate, Oracle worker and historical logs remain intact.