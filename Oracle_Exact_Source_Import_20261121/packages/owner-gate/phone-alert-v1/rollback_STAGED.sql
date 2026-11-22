BEGIN;
ALTER TABLE batcave.owner_phone_notifications_v1 DISABLE TRIGGER owner_phone_dispatch;
UPDATE batcave.owner_phone_subscriptions_v1 SET disabled_at=COALESCE(disabled_at,clock_timestamp());
UPDATE batcave.owner_phone_notifications_v1 SET send_state='cancelled' WHERE send_state='queued';
COMMIT;
