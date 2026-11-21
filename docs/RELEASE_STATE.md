# Oracle release state — 2026-11-21 UTC

**Status: STAGED / LAB_PASS; production release BLOCKED.**

## Known working

- GitHub private repository exists with owner admin/write permissions.
- Authenticated Supabase administration tool can inspect the project.
- Oracle cloud executor can complete nonprivileged read-only jobs with signed receipt.
- Lab owner enrollment gate v0.2.1 passed 20 Node tests and 8 Python tests in the most recent verification.

## Not verified or not deployed

- GitHub Actions secrets, Supabase production deployment credentials, and branch protection.
- Existing production gate backup for this release.
- Owner challenge signature for this exact release.
- Independent Strict Nanny release approval.
- Production owner-enrollment POST and Oracle v0.3.1 model worker.

## Release conditions

1. Review exact source artifacts and identify their SHA-256 digests.
2. Back up existing Edge function source/version and relevant RPC definitions.
3. Verify owner-signed authorization and required independent review, or explicitly establish a separately approved emergency administrative process.
4. Apply only reviewed migration and Edge changes; verify existing shadow GET remains unchanged.
5. Verify one fresh owner challenge, one signed lab grant, replay denial, and rollback path.
6. Independently confirm live receipt and mark production only after acceptance tests.

## Rollback

Restore the previously captured Edge function and RPC definitions if acceptance fails. Preserve security audit records. Never disable unrelated gates or overwrite protected Windows/Cortana services.
