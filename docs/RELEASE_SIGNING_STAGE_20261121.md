# Oracle signer continuation receipt — 2026-11-21

Status: STAGED / 80 local Node tests PASS / first-root PostgreSQL CI pending / LIVE_RELEASE_BLOCKED.

The Decision Master is authoritative. This is a code/test receipt.

The owner approved one-time first-reviewer enrollment using the existing owner
Ed25519 signature and actual candidate-key possession instead of independently
attested custody for the first key only. The actual candidate/account/ACL/source
receipts already exist privately; initialization is complete and must not repeat.
The first-root trust basis is explicit and independently_attested remains false.

The existing PR #2 now contains a generic, privately configured extension of the
existing gate and same-origin owner portal. No actual SID, candidate configuration,
or private operator evidence is added to public source. GitHub reports this
repository PUBLIC; prior references to it as private were incorrect.

- First-root policy is a singleton, immutable after installation; registration is
  once-ever, including after revocation. Root enrollment requires zero existing
  privileged reviewers and two real domain-separated signatures.
- Every later release re-verifies the stored historical registration pair and
  still requires two NEW owner/reviewer release signatures over the fixed scope.
- Local prove-first-key reuses the encrypted key; human TTY, actual Windows SID,
  existing owner signature and hidden passphrase are required. Only a public proof
  file is written. It neither enrolls nor deploys.
- Private PostgreSQL writes serialize root registration and recheck owner/policy,
  held intent, expiry, nonce and revocation under locks. All authority flags false.
- 80/80 local Node tests pass (62 original plus 18 first-root tests). PostgreSQL CI
  adds 9 new real database tests alongside the 12 original tests; receipt pending.
- No live migration, policy seed, gate/portal deployment, signer registration,
  merge, model grant or release-hold change. PR #1 pins are unchanged.
- Rollback of STAGED code: return PR #2 to its previous head. Preserve real key
  files. A later live rollback must revoke a registered root permanently, never
  reset its once-ever slot or delete signed receipts.

## Historical receipt (superseded status; retain evidence)

# Oracle signer continuation receipt — 2026-11-21

Status: STAGED / LAB_PASS_62_NODE / LIVE_RELEASE_BLOCKED.

The existing private Decision Master remains authoritative. This is a source and
testing receipt, not a second master or an approval.

- PR #1 remains pinned at 33b62fae6ccb2224f04cce43443510b71c051297.
- Continuation uses existing draft PR #2; no merge or deployment.
- Fixed signer CLI; staged enrollment, owner portal extension, challenge
  issuance, dual verification and transactional evidence/nonce ledger.
- Local Node: 62/62 PASS on v24.22.3; CI also tests Node 22.
- Actual PostgreSQL atomicity CI: 12/12 PASS, run 44954029074, job 136998038622, completed 2026-11-21 21:55:51Z.
- Successful Cortana browser receipt returned zero accessible Batcave tabs.
  Protected Windows account/TTY access has not been established.
- Actual independent key custody/registration remains BLOCKED. Actual owner
  and reviewer release signatures, controlled deployment and real fixture
  receipt are UNKNOWN/NOT VERIFIED. No live model grants were created.
- Next local action remains init under the real isolated Cortana reviewer
  account. Return only public.unenrolled.json, never the private key/passphrase.
- Rollback: revert the source continuation; no live change to undo.

Correction receipt: first CI source job passed, PostgreSQL setup rejected a generated hash due to STABLE convert_to. The checked-digest fix and raw/SPKI lab-key alias denial are in the next code commit; final corrected code commit a7edf39f82224a80c5fa350437e95d420fdac367 passed GitHub run 44954029074. Source job 136998038345 passed 62 Node signing tests plus the existing 20 owner-gate Node, 8 owner-gate contract and 35 worker tests. Both jobs independently read back SUCCESS. This receipt update changes documentation only.
