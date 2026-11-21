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
