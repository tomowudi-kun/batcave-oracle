# Exact source import (pending)

Do not use the older v0.3 worker package. Import only the pinned archives:

- Owner gate v0.2.1 SHA-256: `69ab19be8ec2e11e902716da59c2dda8693a3d3c78a16d8bdc1ded25a8d16851` into `packages/owner-gate/` (strip the single archive root).
- Oracle worker v0.3.1 SHA-256: `4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2` into `packages/oracle-worker/` (strip the single archive root).

The archives are available in the ChatGPT execution container but have not been copied into this GitHub branch. The review workflow deliberately reports this as NOT TESTED until the source is imported. No release or CI success may be inferred from a skipped test.

No secrets or private signing keys belong in this repository. The production workflow is a deliberate failing placeholder until the protected GitHub environment, credentials, signed approval verification, backups and rollback are implemented and reviewed.
