# Batcave Oracle

Owner-controlled repository for Oracle worker integration, release evidence, and emergency recovery.

## Verified baseline (2026-11-21 UTC)

- Supabase project: `batcave-control` (`wizflveeptzeajsdybzs`).
- Existing `batcave-change-gate-v1`: active, read-only shadow GET; no deployed owner-enrollment POST.
- Eight gate categories remain shadow mode and require signed scope and Strict Nanny review.
- Oracle is a separate registered Linux executor; a read-only inventory command succeeded with a device receipt.
- Oracle worker v0.3.1 archive SHA-256: `4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2` (STAGED, not installed).
- Owner lab enrollment gate v0.2.1 archive SHA-256: `69ab19be8ec2e11e902716da59c2dda8693a3d3c78a16d8bdc1ded25a8d16851` (LAB_PASS, not deployed).
- Release request `batcave.oracle.lab_v031.release_request.20261121`: HELD; owner auth unconfigured; Nanny review pending.

## Safety and deployment

Never commit owner private keys, Supabase service-role credentials, Cortana reviewer private keys, or tokens. No workflow in this repository currently has production deployment authority. Deployments require a separately verified authorization record and reversible change set. A successful CI test is not a production release.

## Immediate next step

Import the exact reviewed v0.2.1 and v0.3.1 source archives on a review branch, run tests, capture baseline backups, and configure a protected owner-controlled deployment environment. Do not deploy v0.3.0 (known unsafe lease behavior).

See `docs/RELEASE_STATE.md` and `docs/ERROR_FIX_LOG.md`.
