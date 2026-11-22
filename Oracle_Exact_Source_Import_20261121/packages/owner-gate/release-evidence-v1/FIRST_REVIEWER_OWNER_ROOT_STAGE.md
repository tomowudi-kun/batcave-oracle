# Approved first-reviewer policy — implementation STAGED

This changes the first-key trust bootstrap only. It does not independently attest
custody. Deployment, execution and grant flags stay false. The real reviewer key
already exists; never initialize or overwrite it again.

## Private configuration

`first_reviewer_schema_STAGED.sql` installs two private tables and a private
SECURITY INVOKER finalizer after the existing staged release-evidence migration.
It seeds nothing. A separately reviewed, private operator policy pins the actual
owner identity/key, candidate canonical hash/public key, Windows SID, host hash,
custody-evidence digest, original release intent and signer expiration.
No request can supply or amend that trusted policy. No live operator config belongs
in this public repository. Missing/revoked/expired policy fails closed.

The singleton's policy cannot change or be deleted. Its first successful
registration consumes the slot permanently; revocation cannot enable a new
bootstrap. Ordinary future reviewer enrollment retains independent attestation.

## Owner and local reviewer flow

1. On the original owner-key portal, select the existing public candidate and
   prepare a first-key challenge. This does not sign. The gate privately checks
   its exact configured candidate and absence of any privileged reviewer.
2. A separate owner click signs the locally verified canonical policy/challenge
   with the existing nonexportable Ed25519 key. Save the public endorsement.
3. Under the existing isolated Cortana reviewer account, with updated reviewed
   runtime files in the admin-owned code directory, run:

   ```powershell
   & 'C:\Program Files\nodejs\node.exe' `
     'C:\ProgramData\Batcave\StrictNanny-Signer-v1\cortana_independent_reviewer.mjs' `
     prove-first-key "$env:USERPROFILE\Batcave-Strict-Nanny-Release-Key" `
     '<downloaded-owner-endorsement.json>'
   ```

   The CLI verifies the actual owner signature, candidate/host/SID and expiration,
   asks for the exact nonce-specific confirmation, and reads the existing hidden
   local passphrase. It writes only `first-key-proof-<nonce>.json`. No key export,
   key initialization, remote write or release review occurs.
4. Upload only that public proof to the same owner portal. Submission re-verifies
   both signatures on server-held challenge data, then atomically records the
   signature pair and consumes the single root slot/nonce. Registered means
   owner-root trusted with possession proved; independently_attested remains false.
5. Later exact Oracle release evidence still needs a fresh challenge and separate
   genuine owner and reviewer RELEASE signatures. Possession proof is not reusable
   as a release verdict. Original artifact pins, held intent and SHADOW gates stay.

## Acceptance and rollout boundary

Source tests use ephemeral synthetic keys. Database tests use only a disposable
localhost PostgreSQL service; they cannot connect to production. Green tests are
LAB_PASS, not live enrollment or production acceptance. GitHub PR #2 remains
unmerged. Rollout needs a separately authorized, exact reviewed code revision,
private policy installation and same-origin portal integration, with rollback
captures and read-back. No persistent worker or model job is activated here.
