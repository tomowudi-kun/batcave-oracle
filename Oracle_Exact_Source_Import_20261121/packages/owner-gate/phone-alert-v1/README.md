# Phone notification transport — notification only

Adds opt-in Chrome Web Push to the existing owner approval origin. A Dr. Doom notification opens the current Yes/No question. The notification, delivery callback, and subscription cannot sign, enroll, approve a release, issue a grant, or execute a device command. The original owner key remains nonexportable in its original browser origin and the existing release gate remains unchanged.

The owner taps Enable phone alerts once and allows Chrome notifications. The browser registers the root service worker and sends its push subscription through confirmed-owner authentication. Up to four active phones per owner are supported. The new function authenticates the owner with the existing Supabase user wrapper and live confirmed-account lookup; a registered, unrevoked owner key is also required. Owner subscriptions are private. Only the owner can test or disable their own subscription.

The new `batcave-phone-alert-v1` function implements its own authentication because it also accepts a narrowly scoped database webhook and display receipts. The existing release function keeps JWT enforcement enabled. A notification-only random dispatch credential and VAPID publisher key are generated in the function on the first authenticated owner request and stored in Supabase Vault. No owner or reviewer private signing key is stored there. Subscription endpoints are restricted to Chrome's Google push host; redirects are prohibited.

The private SQL queue checks the current held intent, immutable policy, owner key pin, expiry, and unresolved owner question. A fresh saved Yes, recorded No, revoked key, completed registration, or expired intent suppresses the question. Queued rows invoke the fixed notification endpoint through pg_net; the atomic claim sends at most once. Ambiguous sends are not automatically retried. Display/open receipts are capability-limited and never represent consent. A test can be requested again after the cooldown.

`phone-alert-sw.js` has no cache/fetch interception and no access to browser signing keys. Its only click action opens/focuses the original approval origin. There are no background Yes/No buttons. Existing page decisions still use the existing authenticated signing flow. The phone may require sign-in if no session remains; session persistence has not changed. A successful Yes or No closes the displayed notification.

## Validation

- `node --test test_notification_core.mjs test_service_worker.mjs`
- `BATCAVE_TEST_DATABASE_URL=postgresql://...@localhost:5432/release_gate_test python3 test_notification_ledger.py`

The PostgreSQL suite rejects non-local/test databases and uses local Vault/net stubs to verify real constraints, role isolation, deduplication, and concurrent claims without outbound requests. The Edge `/health` endpoint also exercises real Web Push encryption using ephemeral synthetic keys and performs no send or persistent write.

Source tests and deployment health are LAB_PASS. Phone delivery remains UNKNOWN until the owner's actual browser opts in and a real `shown_at` callback is received. Provider acceptance alone is insufficient. The publisher does not restore the separate native phone bridge, ADB, device control, or release permissions. Current automatic requests cover the existing first-reviewer question; other task kinds require their own reviewed producer and question binding.

## Deployment and rollback

Deploy the new private schema and separate Edge function before publishing the new module/service worker on the existing portal origin. Preserve original auth storage and old static assets. No changes to the release gate function or release holds are required. The Doom icon is the existing owner-provided personal asset, served on the same origin, rather than part of this source package.

Rollback: restore the previously recorded portal deployment alias, apply `rollback_STAGED.sql`, and deploy an inert notification function if needed. Retain notification rows as receipts. Publisher keys remain in Vault for controlled cleanup; they never become owner credentials. A push already accepted by the provider can still arrive until its ten-minute expiry. The worker rejects expired alerts.

Error/fix log: initial local file commands used an incorrect working directory; source operations now use the workspace root. Stable SQL timestamps avoid expiry-check microsecond drift. Subscription/owner composite keys prevent cross-owner outbox rows. Fresh saved consent suppresses redundant questions. None of these changes promote a signer or release Oracle.
