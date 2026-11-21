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
