# Append-only error and fix log

## 2026-11-21 — Bootstrap deadlock

- **Observed:** Oracle release held; owner auth unconfigured; Nanny review pending; production gate supports read-only GET but no enrollment POST.
- **Cause:** Deployment process depends on an authorization mechanism not yet installed.
- **Attempted:** Direct Supabase administrative route verified technically reachable, but not accepted as independent authorization for protected gate replacement.
- **Fix/progress:** Established dedicated private GitHub repository to separate versioned source, review, and future owner-controlled deployment.
- **Verification:** Repository appeared in connected GitHub list with admin/write permissions.
- **Remaining:** No production deployment, signing flow, or worker model task verified.

## 2026-11-21 — Existing v0.3 worker lease issue

- **Observed:** Prior v0.3 unsafe lease bug.
- **Fix:** Use pinned v0.3.1 archive only; never deploy older v0.3.
- **Verification:** v0.3.1 digest recorded in release state; production installation remains unverified.

## 2026-11-21 — Release signer continuation

- **Observed:** Review CLI forwarded numeric map indexes to path.resolve; invalid signer expiry escaped through NaN. Enrollment/release ledger implementation was missing.
- **Fix:** Unary CLI resolver, canonical expiry and custody checks; staged authenticated enrollment, existing-portal signing panel, fixed challenge issuance, dual verification and atomic SQL receipt/nonce ledger.
- **Validation:** 60 local Node tests PASS. Actual PostgreSQL race/revocation tests added to CI; final receipt is `docs/RELEASE_SIGNING_STAGE_20261121.md`.
- **Transport receipt:** Browser job caf2752d-ea62-484f-8b84-9c7b0ae70076 succeeded once at 2026-11-21 21:39:25Z; zero accessible Batcave tabs. Both direct remote devices offline. No protected reviewer account access established.
- **Live boundary:** Existing intent HELD, no privileged registry deployed, zero lab model grants, all eight gates SHADOW. No host/cloud/portal/policy deployment or model job.
- **Remaining:** Actual isolated reviewer key/custody and independent registration, real owner/reviewer signatures, controlled release/postflight.
- **Rollback:** Revert source continuation only; no production rollback needed.

## 2026-11-21 — PostgreSQL generated expression

- **Observed:** CI 44953793317 source review passed, but the real PostgreSQL ledger setup rejected a generated digest column: generation expression is not immutable.
- **Cause:** PostgreSQL classifies convert_to as STABLE; independently confirmed in live read-only pg_proc metadata.
- **Fix:** Store a NOT NULL digest with a database CHECK that recomputes the exact UTF-8 byte hash; update repository insert and synthetic DB fixtures. No false IMMUTABLE wrapper or weaker hash assertion.
- **Status:** Source fix awaiting new CI. No production DDL was attempted.


## 2026-11-21 — Lab key fingerprint alias

- **Observed:** Lab registry fingerprint hashes SPKI; new release records hash raw Ed25519 bytes. Hash-only denial missed an alternate representation of the same lab key.
- **Fix:** Deny actual pinned lab public key bytes plus both SPKI/raw fingerprints in verifier, candidate enrollment and SQL finalizer. Two added cryptographic regressions pass; local Node total is now 62/62. No lab key promotion occurred.
- **Additional regression:** DB must reject a supplied digest that differs from the actual canonical payload bytes; CI suite now has 12 PostgreSQL tests.

## 2026-11-21 — Corrected source acceptance receipt

- **Verified:** GitHub Actions run 44954029074 on code commit a7edf39f82224a80c5fa350437e95d420fdac367 SUCCESS. Source job 136998038345 passed 62 signing tests plus existing gate/worker checks. PostgreSQL job 136998038622 passed all 12 real database tests, including concurrent single-use consumption, revocation, rotation, digest constraints and client privilege denial. Both job logs independently read.
- **Boundary:** LAB_PASS/STAGED only. No real independent key/attestation, owner/reviewer release signature, protected deployment or production fixture receipt is established.


## 2026-11-21 — First-root dependency and visibility corrections

- Observed: no privileged release reviewer exists, but the staged enrollment path
  required an already independent custody attestation. The live lab-only route
  cannot enroll the new candidate. Advisory referral alone cannot fill the gap.
- Decision: owner explicitly approved a one-time owner-root trust rule using the
  existing owner signature plus actual candidate possession. No independent
  attestation is asserted. Real local initialization/ACL evidence is complete.
- Implementation: generic private singleton policy, domain-separated endorsement
  and proof, once-ever atomic registration, historical pair re-verification,
  separate later release signatures, and existing-portal/local-key integration.
- Correction: GitHub reports this repository PUBLIC. Actual candidate SID/policy
  and operator evidence remain private; no visibility change was made.
- Test discovery: mixed-case WRONG_PIN field labels were hidden as generic outage
  errors by the gate's uppercase error filter. Fixed verifier error codes to use
  uppercase field labels; the expanded-scope regression now gives a clear denial.
- Verification: 80 local Node tests PASS. New actual PostgreSQL tests await CI.
- Boundary: policy amendment is approved; rollout, signing and enrollment have
  not occurred. No claims of production completion or model grants.
- Rollback: staged source only. Preserve encrypted reviewer identity and held
  intent; once registered, root-slot revocation is permanent and cannot rebootstrap.
