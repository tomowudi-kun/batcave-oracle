# Oracle lab owner gate v0.2 — append-only error/fix log

1. **Earlier v0.3 staged RPC had an unguarded model-lease path.** Corrected in v0.3.1 proposal: atomic one-time Cortana reviewer grant consumption. No earlier unsafe version was deployed.
2. **Old Cortana reviewer pins original v0.3 package hash as its fixture token.** This token is required for compatibility with the installed reviewer but MUST NOT authorize deploying v0.3; implemented a distinct v0.3.1 release-archive hash included in canonical owner enrollment signature and stored grant scope.
3. **Owner challenge database timestamps can be returned as `+00:00`, not JavaScript `.000Z`.** Compare exact instants after converting to ISO strings, while retaining a strict canonical owner-signature timestamp.
4. **First integration static-test run had two mistaken test assertions.** Test harness incorrectly expected the core module to duplicate pins imported from constants and mistyped a wrapper function name (`response` vs `respond`). Corrected assertions; all tests passed afterward, no app change required.
5. **Review grant could outlive reviewer's requested authorization window.** Added core pre-insert check that reviewer-signed request expiry is no earlier than the cloud job expiry; receipt review time also must lie after job creation and before expiry. Added negative regression test.
6. **PostgreSQL check across transient schema.** Used temporary equivalents in a BEGIN/ROLLBACK transaction, tested invalid production flags/window, and read back complete rollback. Temp tables cannot reference permanent tables; staged migration retains foreign key to actual `batcave.commands`.
7. **SQL NULL-safe comparisons and missing job.** Changed sensitive field comparisons to `IS DISTINCT FROM` and separated missing `SELECT ... FOR UPDATE` result before dereferencing record. Not released.

## Current fixed state

Lab-only owner-authenticated enrollment + signed-grant writer source is STAGED. Existing Supabase gate, Cortana reviewer, Oracle Qwen model and legacy workers untouched. The previous HELD public-key intent remains nonauthorizing. The next blocker is actual independent approved release of the existing gate extension and owner-key signing UI compatibility—not another worker/model setup.

## 2026-11-21 — Existing owner portal integration and preview deployment

- **Discovered** actual owner portal project `batcave-linux-approval` in Vercel, protected existing browser signing key in IndexedDB `batcave_linux_signer_v1` and Supabase session in `sessionStorage`. Prior work had assumed the source could not be recovered. **Fix**: verified six-file source tree through Vercel and recovered live JS/CSS/form markup from public deployment without accessing private keys.
- **Found** staged gate POST CORS only allowlisted `https://batcave-cloud-control.vercel.app`; actual owner portal `https://batcave-linux-approval.vercel.app` would have received `origin_denied`. **Fix**: exact two-origin allowlist, no wildcard, owner JWT/signature requirements and production deny unchanged; static regression added.
- **Preview attempt A**: API rejected deployment with `missing_files` because previous deployment SHA1 file objects were not reusable. **Fix**: upload all eight source files in full, preview-only.
- **Preview attempt B**: API rejected explicit `target=preview` as invalid; Vercel requires omitting target for preview. **Fix**: omit `target`.
- **Preview attempt C**: READY but source tree `src/src/*`, wrong nested layout. **Fix**: remove duplicate `src/` path prefix.
- **Preview attempt D**: ERROR, log `Root Directory "src" does not exist`. **Fix**: remove incorrect rootDirectory override and use root-relative source files.
- **Preview attempt E**: deployment `dpl_3S2YG5WDdvNH8Zd5XwE8ph7rcxnk` READY, no aliases, correct original eight-file tree under `src/*`. Original production `dpl_297NvEEqDTb31JgoQ6kKnd6LxrbP` remains READY and continues to own both original aliases. New asset UIDs SHA1 match exact local `portal/oracle-lab.js` and HTML after removing one trailing newline each. No production mutation or key enrollment.
- **Incomplete acceptance**: Vercel Preview SSO means unauthenticated website check returned `login_required`; no authenticated browser rendering/click verification performed. The client signs only on existing production origin after a separately reviewed cloud gate release. Current live gate remains shadow-only.
- **Package test-path correction:** copied portal UI tests referred to old repo-relative `../oracle-lab.js`; in combined release package the path is `../portal/oracle-lab.js`. Corrected only test fixture path. No browser code or permissions changed.
