# Batcave Oracle v0.3.1 — append-only correction log

## Prior acceptance retained
- Oracle native Xubuntu, user worker and cloud bridge; deterministic builder and server receipt were previously verified.
- Local Qwen2.5-Coder 1.5B independently generated `model_generated.py` with 8/8 tests on Oracle (LAB_PASS), not yet via cloud.
- Cortana Lab Strict Nanny installed as LOCAL SERVICE S-1-5-19; one signed LAB_ALLOW and one signed DENY were independently verified off host. Its key is `lab_reviewer_only`, not a production release key.

## 2026-11-20/21 — issue: model lease bypass in unreleased v0.3 RPC
**Failure:** Staged v0.3 `poll_model` SQL could select a typed model task without requiring Cortana's lab signature/grant. Deploying this version would allow a properly credentialed cloud writer to queue a model task without the intended separate review. **This code had not been deployed.**

**Fix:** v0.3.1 integrates a private `oracle_lab_review_grants_v1` check at the existing token-authenticated RPC lease boundary. Review must be signed, fresh, exact job/nonce/fixture/artifact, unrevoked lab key, ≤10-minute validity and no production permission. Lease + `consumed_at` occur in one PostgreSQL CTE statement. There is no automatic re-lease for an ambiguous model run; model receipts must correspond to consumed grants. The old inventory and deterministic build routes retain their existing behavior.

**Regression receipt:** 35/35 Python tests and 7/7 existing Edge contract tests pass; a zero-persistent-effect PostgreSQL transaction over temporary tables tested legacy inventory/build, no-grant model rejection, single valid grant claim and replay refusal. Explicit ROLLBACK performed and temporary tables removed. No Oracle/Edge/RPC/Windows production changes occurred.

**Known limitation:** The authenticated owner-enrollment and fresh Cortana signed-review grant-writer are not yet deployed. The HELD key-evidence intent is not an enrolled key or executable grant. Do not manually insert grants or deploy the SQL without the independently reviewed trust writer and approved release path. Owner private key remains on the owner device; Cortana lab private key stays on Cortana. Current production gate remains shadow-only.

## 2026-11-20/21 — packaging repair
Original v0.3.1 test copied into a new package referenced its old standalone SQL location and produced an import-time FileNotFoundError. Repointed test to `cloud/oracle_bridge_rpc_v03.sql` within the candidate package; all 35 tests passed. No runtime component changed.

## Rollback and release status
- Source rollback: `rollback-on-oracle.sh` in v0.3.1, only after safe exact file/hash and no in-flight job checks.
- Cloud rollback: restore captured pre-release `pg_get_functiondef()` RPC and existing Edge Function version. Do not assume the local rollback reverts cloud.
- **Status: STAGED / LAB_PASS; NO PRODUCTION RELEASE OR SERVER MODEL RECEIPT.** The owner-private Decision Master remains authoritative.
